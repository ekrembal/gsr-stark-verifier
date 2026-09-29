//! Liveness-aware GSR lowering. Proof values affect witness bytes, never code.
use crate::{
    bitcoin_system::{BitcoinSystemRef, Element, TraceEntry},
    stack::Stack,
};
use anyhow::{ensure, Result};
use std::collections::BTreeMap;

pub struct Program {
    pub script: Vec<u8>,
    pub witness: Vec<Vec<u8>>,
    pub functions: Vec<(u8, Vec<u8>, usize)>,
    pub spans: Vec<(usize, usize, usize)>,
    pub labeled_constants: Vec<(usize, Vec<String>)>,
    pub hint_traces: Vec<usize>,
    pub hint_labels: Vec<Vec<String>>,
    pub diagnostic_checks: usize,
    pub sections: Vec<(String, usize, usize)>,
    pub hint_layout: Vec<(usize, usize, usize, bool)>,
}

pub fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    match bytes {
        [] => out.push(0),
        [x] if (1..=16).contains(x) => out.push(0x50 + x),
        _ => {
            match bytes.len() {
                n @ 0..=75 => out.push(n as u8),
                n @ 76..=255 => out.extend([0x4c, n as u8]),
                n @ 256..=65535 => {
                    out.push(0x4d);
                    out.extend((n as u16).to_le_bytes());
                }
                n => {
                    out.push(0x4e);
                    out.extend((n as u32).to_le_bytes());
                }
            }
            out.extend(bytes);
        }
    }
}
pub fn push_num(out: &mut Vec<u8>, n: usize) {
    let mut bytes = (n as u64).to_le_bytes().to_vec();
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    // OP_1NEGATE is not an arithmetic constant in GSR; avoid its old minimal-push encoding.
    if bytes == [0x81] {
        bytes.push(0);
    }
    push_bytes(out, &bytes);
}
fn fetch(out: &mut Vec<u8>, distance: usize, roll: bool) {
    match (roll, distance) {
        (true, 0) => {}
        (true, 1) => out.push(0x7c),
        (true, 2) => out.push(0x7b),
        (false, 0) => out.push(0x76),
        (false, 1) => out.push(0x78),
        _ => {
            push_num(out, distance);
            out.push(if roll { 0x7a } else { 0x79 });
        }
    }
}

pub fn compile(cs: BitcoinSystemRef) -> Result<Program> {
    compile_inner(cs, false)
}
/// Test-only oracle checks; never used by the deployable profile.
pub fn compile_differential(cs: BitcoinSystemRef) -> Result<Program> {
    compile_inner(cs, true)
}
fn compile_inner(cs: BitcoinSystemRef, differential: bool) -> Result<Program> {
    ensure!(
        crate::gsr::enabled(),
        "compile within a GSR capture session"
    );
    let cs = cs.0.borrow();
    ensure!(
        cs.num_inputs == Some(0),
        "GSR bundle has no independent program-input stack"
    );
    let mut last = vec![None; cs.memory_last_idx];
    for (t, entry) in cs.trace.iter().enumerate() {
        if let TraceEntry::InsertScript(_, inputs, _) = entry {
            for i in inputs {
                last[*i] = Some(t);
            }
        }
    }
    let mut witness = Vec::<Vec<u8>>::new();
    let mut hint_layout = Vec::new();
    let mut hint_traces = Vec::new();
    let mut hint_labels = Vec::new();
    let section_starts = crate::gsr::sections();
    let mut sections: Vec<(String, usize, usize)> = vec![];
    let mut new_section = false;
    for (t, entry) in cs.trace.iter().enumerate() {
        if let Some((_, name)) = section_starts.iter().find(|(start, _)| *start == t) {
            if let Some(last) = sections.last_mut() {
                last.2 = witness.len() - last.1;
            }
            sections.push((name.clone(), witness.len(), 0));
            new_section = true;
        }
        if let TraceEntry::RequestHint(i) = entry {
            ensure!(last[*i].is_some(), "unused proof hint at trace {}", t);
            hint_traces.push(t);
            hint_labels.push(crate::gsr::labels(*i));
            let (data, numeric) = match &cs.memory[i] {
                Element::Num(n) => {
                    ensure!(
                        *n >= 0 && (*n as u32) < crate::gsr::P,
                        "non-field numeric hint"
                    );
                    (((*n as u32).to_le_bytes()).to_vec(), true)
                }
                Element::Str(s) => (s.clone(), false),
            };
            if new_section
                || witness.is_empty()
                || witness.last().unwrap().len() + data.len() > 4096
            {
                witness.push(vec![]);
                new_section = false;
            }
            let chunk = witness.len() - 1;
            let offset = witness[chunk].len();
            witness[chunk].extend(&data);
            hint_layout.push((chunk, offset, data.len(), numeric));
        }
    }
    if let Some(last) = sections.last_mut() {
        last.2 = witness.len() - last.1;
    }
    // Fragments, rather than a monolithic byte string, preserve gadget boundaries
    // for safe function sharing. No guessed byte-level pattern substitution.
    let mut fragments: Vec<(Vec<u8>, bool, usize)> = vec![];
    let mut stack = Stack::new(cs.memory_last_idx);
    let mut hint_index = 0;
    let mut active_chunk = None;
    for (t, entry) in cs.trace.iter().enumerate() {
        let mut bytes = vec![];
        match entry {
            TraceEntry::InsertScript(generator, inputs, options) => {
                for (n, i) in inputs.iter().enumerate() {
                    let distance = stack.get_relative_position(*i)? + n;
                    let roll = last[*i] == Some(t) && !inputs[n + 1..].contains(i);
                    if roll {
                        stack.pull(*i)?;
                    }
                    fetch(&mut bytes, distance, roll);
                }
                fragments.push((bytes, true, t));
                let body = generator.run(&mut stack, options)?.to_bytes();
                fragments.push((body, true, t));
                continue;
            }
            TraceEntry::DeclareConstant(i) => {
                stack.push_to_stack(*i)?;
                match &cs.memory[i] {
                    Element::Num(n) => {
                        ensure!(*n >= 0, "negative GSR constant");
                        push_num(&mut bytes, *n as usize);
                        if *n == 129 {
                            bytes.extend([0, 0x93]);
                        }
                    }
                    Element::Str(s) => push_bytes(&mut bytes, s),
                }
            }
            TraceEntry::DeclareOutput(i) => {
                stack.push_to_stack(*i)?;
                if differential
                    && !matches!(cs.trace.get(t + 1), Some(TraceEntry::DeclareOutput(_)))
                {
                    let mut j = t;
                    loop {
                        if let TraceEntry::DeclareOutput(id) = &cs.trace[j] {
                            fetch(&mut bytes, t - j, false);
                            match &cs.memory[id] {
                                Element::Num(n) => {
                                    push_num(&mut bytes, *n as usize);
                                    if *n == 129 {
                                        bytes.extend([0, 0x93]);
                                    }
                                }
                                Element::Str(v) => push_bytes(&mut bytes, v),
                            }
                            bytes.push(0x88);
                        } else {
                            break;
                        }
                        if j == 0 {
                            break;
                        }
                        j -= 1;
                    }
                }
            }
            TraceEntry::RequestHint(i) => {
                let (chunk, _offset, len, numeric) = hint_layout[hint_index];
                if active_chunk != Some(chunk) {
                    if active_chunk.is_some() {
                        bytes.extend([0x6c, 0x75]);
                    }
                    // Future witness chunks sit below all live symbolic values.
                    bytes.extend([0x74, 0x8c, 0x7a, 0x82]);
                    push_num(&mut bytes, witness[chunk].len());
                    bytes.extend([0x88, 0x6b]);
                    active_chunk = Some(chunk);
                }
                fragments.push((bytes, false, t));
                // Consume the next fixed-size value; section size was checked on entry.
                let mut reader = vec![0x6c, 0x76];
                push_num(&mut reader, len);
                reader.push(0x80);
                reader.push(0x7c);
                push_num(&mut reader, len);
                push_num(&mut reader, 4096);
                reader.extend([0x7f, 0x6b]);
                if numeric {
                    reader.extend([0, 0x93, 0x76]);
                    push_num(&mut reader, crate::gsr::P as usize);
                    reader.extend([0x9f, 0x69]);
                }
                fragments.push((reader, true, t));
                stack.push_to_stack(*i)?;
                hint_index += 1;
                continue;
            }
            TraceEntry::SystemOutput(_) => {
                anyhow::bail!("unexpected system output in complete verifier")
            }
        }
        fragments.push((bytes, false, t));
    }
    let mut tail = vec![];
    if active_chunk.is_some() {
        tail.extend([0x6c, 0x75]);
    }
    let remaining = stack.get_num_elements_in_stack()?;
    tail.extend(std::iter::repeat(0x6d).take(remaining / 2));
    if remaining % 2 != 0 {
        tail.push(0x75);
    }
    tail.extend([0x74, 0, 0x88, 0x51]); // No surplus witness; exactly true remains.
    fragments.push((tail, false, cs.trace.len()));
    let mut counts = BTreeMap::<Vec<u8>, usize>::new();
    for (body, share, _) in &fragments {
        if *share && body.len() >= 4 {
            *counts.entry(body.clone()).or_default() += 1;
        }
    }
    let mut candidates: Vec<_> = counts
        .into_iter()
        .filter(|(b, n)| *n >= 3 && b.len() * n > b.len() + n * 3 + 5)
        .collect();
    candidates.sort_by_key(|(b, n)| std::cmp::Reverse(b.len() * n - b.len() - n * 3 - 5));
    candidates.truncate(128);
    let mut functions = vec![];
    let mut ids = BTreeMap::new();
    let mut script = vec![];
    for (id, (body, n)) in candidates.into_iter().enumerate() {
        push_bytes(&mut script, &body);
        push_num(&mut script, id);
        script.push(0xbb);
        ids.insert(body.clone(), id as u8);
        functions.push((id as u8, body, n));
    }
    let mut spans = vec![];
    for (body, share, trace) in fragments {
        let start = script.len();
        if let Some(id) = if share { ids.get(&body) } else { None } {
            push_num(&mut script, *id as usize);
            script.push(0xbc);
        } else {
            script.extend(body);
        }
        if script.len() != start {
            spans.push((start, script.len(), trace));
        }
    }
    // RequestHint removes the deepest witness chunk first.
    Ok(Program {
        script,
        witness,
        functions,
        spans,
        hint_layout,
        sections,
        hint_traces,
        hint_labels,
        labeled_constants: cs
            .trace
            .iter()
            .enumerate()
            .filter_map(|(t, e)| {
                if let TraceEntry::DeclareConstant(id) = e {
                    let names = crate::gsr::labels(*id);
                    if names.is_empty() {
                        None
                    } else {
                        Some((t, names))
                    }
                } else {
                    None
                }
            })
            .collect(),
        diagnostic_checks: if differential {
            cs.trace
                .iter()
                .filter(|e| matches!(e, TraceEntry::DeclareOutput(_)))
                .count()
        } else {
            0
        },
    })
}
