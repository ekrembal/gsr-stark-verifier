const WASM_URL = "pr-sdk-wasm.wasm";
const $ = (id) => document.getElementById(id);
const worker = new Worker("worker.js", { type: "module" });
let nextId = 0;
const pending = new Map();

worker.onmessage = (ev) => {
  const m = ev.data;
  const p = pending.get(m.id);
  if (!p) return;
  if (m.log !== undefined) { log(m.log); return; }
  pending.delete(m.id);
  p(m);
};

function run(args, files) {
  return new Promise((resolve) => {
    const id = nextId++;
    pending.set(id, resolve);
    worker.postMessage({ id, url: WASM_URL, args, files });
  });
}

function log(line) {
  const el = $("log");
  el.textContent += line + "\n";
  el.scrollTop = el.scrollHeight;
}

async function device() {
  const d = {
    user_agent: navigator.userAgent,
    platform: navigator.platform,
    hardware_concurrency: navigator.hardwareConcurrency ?? null,
    device_memory_gb: navigator.deviceMemory ?? null,
    screen: `${screen.width}x${screen.height}@${devicePixelRatio}`,
    cross_origin_isolated: self.crossOriginIsolated,
    js_heap_limit_bytes: performance.memory ? performance.memory.jsHeapSizeLimit : null,
  };
  if (navigator.userAgentData) {
    d.ua_mobile = navigator.userAgentData.mobile;
    d.ua_platform = navigator.userAgentData.platform;
    try {
      const h = await navigator.userAgentData.getHighEntropyValues(["model", "platformVersion", "architecture", "fullVersionList"]);
      Object.assign(d, { ua_model: h.model, ua_platform_version: h.platformVersion, ua_architecture: h.architecture,
        ua_browsers: (h.fullVersionList || []).map((b) => `${b.brand} ${b.version}`).join(", ") });
    } catch (_) { /* not granted */ }
  }
  return d;
}

function table(el, rows) {
  el.innerHTML = rows.map(([k, v]) => `<tr><th>${k}</th><td>${v ?? "–"}</td></tr>`).join("");
}

function stageRow(name, ok, detail, seconds) {
  const tr = document.createElement("tr");
  tr.innerHTML = `<td>${name}</td><td class="${ok ? "ok" : "fail"}">${detail}</td>` +
    `<td class="n">${seconds == null ? "–" : seconds.toFixed(3)}</td>`;
  $("stages").appendChild(tr);
}

async function json(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return new Uint8Array(await r.arrayBuffer());
}

function parseLast(stdout) {
  for (let i = stdout.length - 1; i >= 0; i--) {
    try { return JSON.parse(stdout[i]); } catch (_) { /* not JSON */ }
  }
  return null;
}

async function benchmark() {
  $("run").disabled = true;
  $("download").disabled = true;
  $("stages").innerHTML = "<tr><th>Stage</th><th>Result</th><th>Seconds</th></tr>";
  $("log").textContent = "";
  const mode = $("mode").value, po2 = $("po2").value, n = $("segments").value;
  const result = { version: 1, mode, segment_po2: Number(po2), requested_segments: mode === "profile" ? Number(n) : null,
    started: new Date().toISOString(), device: await device(), stages: {}, ok: false };
  const finish = async () => {
    result.finished = new Date().toISOString();
    $("json").textContent = JSON.stringify(result, null, 2);
    $("download").disabled = false;
    $("download").onclick = () => {
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([JSON.stringify(result, null, 2)], { type: "application/json" }));
      a.download = `pr-sdk-wasm-benchmark-${Date.now()}.json`;
      a.click();
    };
    if ($("report").checked) {
      try {
        const r = await fetch("v1/benchmarks", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(result) });
        log(`posted result: HTTP ${r.status}`);
      } catch (e) { log(`posting result failed: ${e}`); }
      history();
    }
    $("state").textContent = result.ok ? "done" : "failed";
    $("run").disabled = false;
  };
  try {
    $("state").textContent = "building the witness…";
    let status;
    try { status = await json("v1/status"); result.status_source = "batcher /v1/status"; }
    catch (_) { status = await json("sample/status.json"); result.status_source = "sample/status.json"; }
    const funding = await json("sample/funding.json");
    const seed = Array.from(crypto.getRandomValues(new Uint8Array(32)), (b) => b.toString(16).padStart(2, "0")).join("");
    const w = await run(["deposit", seed, "/work/status.json", "/work/funding.json", "1000", "/work"],
      { "status.json": status, "funding.json": funding });
    result.wasm_compile_seconds = w.compile_ms != null ? w.compile_ms / 1000 : null;
    if (w.compile_ms != null) stageRow("compile wasm module", true, "WebAssembly.compileStreaming", w.compile_ms / 1000);
    const wOut = parseLast(w.stdout);
    result.stages.witness = { exit: w.exit, trap: w.trap, wall_seconds: w.wall_ms / 1000, output: wOut, memory_bytes: w.memory_bytes };
    if (w.exit !== 0 || !wOut) { stageRow("build deposit witness", false, w.trap || `exit ${w.exit}`, w.wall_ms / 1000); return; }
    stageRow("build deposit witness", true, `deposit ${wOut.deposit_sats} sats`, wOut.witness_build_seconds);

    $("state").textContent = mode === "profile" ? `proving ${n} segment(s)…` : "proving the full receipt…";
    const args = mode === "profile"
      ? ["profile", "/work/witness.json", po2, n]
      : ["prove", "/work/witness.json", "/work/external.json", po2, "/work"];
    const p = await run(args, { "witness.json": w.files["witness.json"], "external.json": w.files["external.json"] });
    const pOut = parseLast(p.stdout);
    result.stages.prove = { exit: p.exit, trap: p.trap, wall_seconds: p.wall_ms / 1000, output: pOut, memory_bytes: p.memory_bytes };
    result.wasm_memory_bytes = p.memory_bytes ?? null;
    if (p.exit !== 0 || !pOut) {
      stageRow(mode === "profile" ? "execute + prove segments" : "prove receipt", false, p.trap || `exit ${p.exit}`, p.wall_ms / 1000);
      return;
    }
    const s = pOut.stats;
    stageRow("check witness", true, "circuit constraints", s.witness_check_seconds);
    stageRow("execute guest", true, `${s.cycles_total} cycles, ${s.segments} segments`, s.execute_seconds);
    stageRow("prove segments", true, `${s.segments_proven} of ${s.segments}`, s.segment_proving_seconds);
    stageRow("lift + join", true, `${s.segments_proven} lifts`, s.lift_join_seconds);
    if (mode === "prove") {
      stageRow("identity_zk (zero-knowledge wrap)", true, `${s.seal_words} seal words`, s.identity_zk_seconds);
      stageRow("verify receipt", true, `${s.receipt_bytes} bytes`, s.verify_seconds);
      result.receipt_bytes = s.receipt_bytes;
    }
    stageRow("total (worker wall clock)", true, `wasm memory ${(p.memory_bytes / 2 ** 20).toFixed(0)} MiB`, p.wall_ms / 1000);
    result.ok = true;
  } catch (e) {
    result.error = String(e);
    stageRow("benchmark", false, String(e), null);
  } finally {
    await finish();
  }
}

async function history() {
  try {
    const r = await fetch("v1/benchmarks");
    if (!r.ok) return;
    const rows = await r.json();
    $("history").innerHTML = "<tr><th>When</th><th>Device</th><th>Mode</th><th>po2</th><th>Segments</th><th>Prove s</th><th>Memory MiB</th><th>OK</th></tr>" +
      rows.slice(-20).reverse().map((x) => {
        const s = x.stages?.prove?.output?.stats;
        return `<tr><td>${x.finished ?? ""}</td><td>${x.device?.ua_model || x.device?.platform || ""}</td><td>${x.mode}</td>` +
          `<td>${x.segment_po2}</td><td>${s ? `${s.segments_proven}/${s.segments}` : "–"}</td>` +
          `<td class="n">${x.stages?.prove ? x.stages.prove.wall_seconds.toFixed(1) : "–"}</td>` +
          `<td class="n">${x.wasm_memory_bytes ? (x.wasm_memory_bytes / 2 ** 20).toFixed(0) : "–"}</td><td>${x.ok ? "yes" : "no"}</td></tr>`;
      }).join("");
  } catch (_) { /* served without the batcher */ }
}

(async () => {
  const d = await device();
  table($("device"), Object.entries(d));
  $("state").textContent = "ready";
  $("run").onclick = benchmark;
  history();
})();
