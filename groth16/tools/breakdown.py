#!/usr/bin/env python3
"""Attribute committed macro Script bytes and witness payload to verifier stages."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from cost import anchor_script, decode_macros, instructions, read_compact
from pairing_script import build_pairing_script

OP_MACRO, OP_CALLMACRO = 0xD0, 0xD1


def parse_definitions(code: bytes):
    definitions = []
    offset = 0
    while offset < len(code) and code[offset] == OP_MACRO:
        start = offset
        offset += 1
        size, offset = read_compact(code, offset)
        end = offset + size
        if end > len(code):
            raise ValueError("truncated macro definition")
        definitions.append({
            "body": code[offset:end],
            "encoded_bytes": end - start,
        })
        offset = end
    return definitions, offset


def split_amount(amount: int, weights: Counter, stage_names: list[str]) -> Counter:
    total = sum(weights.values())
    if not total:
        raise ValueError("cannot attribute bytes without stage weight")
    shares = Counter()
    remainders = []
    for stage in stage_names:
        quotient, remainder = divmod(amount * weights[stage], total)
        shares[stage] = quotient
        remainders.append((remainder, stage))
    remaining = amount - sum(shares.values())
    for _, stage in sorted(remainders, key=lambda item: (-item[0], stage_names.index(item[1])))[:remaining]:
        shares[stage] += 1
    return shares


def stage_weights(start: int, end: int, ranges: list[tuple[str, int, int]]) -> Counter:
    weights = Counter()
    for name, range_start, range_end in ranges:
        overlap = max(0, min(end, range_end) - max(start, range_start))
        if overlap:
            weights[name] += overlap
    if end > start and not weights:
        raise ValueError(f"unattributed unrolled bytes [{start}, {end})")
    return weights


def compressed_stage_bytes(code: bytes, unrolled: bytes, ranges):
    definitions, main_start = parse_definitions(code)
    macro_instructions = [instructions(item["body"]) for item in definitions]

    @lru_cache(maxsize=None)
    def expanded_length(index: int) -> int:
        total = 0
        for ins in macro_instructions[index]:
            total += (
                expanded_length(ins.call)
                if ins.call is not None
                else ins.end - ins.start
            )
        return total

    definition_use_weights = [Counter() for _ in definitions]

    def record_expansion(index: int, start: int) -> int:
        end = start + expanded_length(index)
        definition_use_weights[index].update(stage_weights(start, end, ranges))
        cursor = start
        for ins in macro_instructions[index]:
            if ins.call is None:
                cursor += ins.end - ins.start
            else:
                cursor = record_expansion(ins.call, cursor)
        if cursor != end:
            raise ValueError("macro expansion length accounting failed")
        return end

    main_body_bytes = Counter()
    cursor = 0
    for ins in instructions(code[main_start:]):
        encoded_size = ins.end - ins.start
        if ins.call is None:
            weights = stage_weights(cursor, cursor + encoded_size, ranges)
            main_body_bytes.update(split_amount(encoded_size, weights, [r[0] for r in ranges]))
            cursor += encoded_size
        else:
            expansion_size = expanded_length(ins.call)
            weights = stage_weights(cursor, cursor + expansion_size, ranges)
            main_body_bytes.update(split_amount(encoded_size, weights, [r[0] for r in ranges]))
            cursor = record_expansion(ins.call, cursor)
    if cursor != len(unrolled):
        raise ValueError(f"macro expansion covers {cursor} of {len(unrolled)} unrolled bytes")

    macro_definition_bytes = Counter()
    for index, definition in enumerate(definitions):
        shares = split_amount(
            definition["encoded_bytes"],
            definition_use_weights[index],
            [r[0] for r in ranges],
        )
        macro_definition_bytes.update(shares)

    total_compressed = len(code)
    if sum(main_body_bytes.values()) + sum(macro_definition_bytes.values()) != total_compressed:
        raise ValueError("committed-byte attribution does not sum to compressed Script size")
    stages = {}
    for name, _, _ in ranges:
        definitions_size = macro_definition_bytes[name]
        calls_size = main_body_bytes[name]
        stages[name] = {
            "macro_definition_bytes": definitions_size,
            "main_body_call_site_bytes": calls_size,
            "committed_bytes": definitions_size + calls_size,
        }
    return stages


def witness_categories(witness):
    layout = witness.layout

    def indices(groups):
        return [index for group in groups for index in group]

    categories = {
        "proof_points": indices(
            [coordinate for name in ("A", "B", "C") for coordinate in layout[name]]
        ),
        "slopes": indices(
            layout["slopes"] + layout["shamir_slopes"] + layout["subgroup_slopes"]
        ),
        "line_coefficients_plus_binding": indices(layout["line_constants"]),
        "residue_values": indices([layout[name] for name in ("c", "c_inv", "wi")]),
        "shamir_bits": indices(layout["bits"][0] + layout["bits"][1]),
    }
    used = set()
    result = {}
    for name, item_indices in categories.items():
        if len(item_indices) != len(set(item_indices)) or used.intersection(item_indices):
            raise ValueError(f"overlapping witness category: {name}")
        used.update(item_indices)
        result[name] = {
            "items": len(item_indices),
            "bytes": sum(len(witness.stack[index]) for index in item_indices),
        }
    remainder = set(range(len(witness.stack))) - used
    result["everything_else"] = {
        "items": len(remainder),
        "bytes": sum(len(witness.stack[index]) for index in remainder),
    }
    if sum(item["bytes"] for item in result.values()) != sum(map(len, witness.stack)):
        raise ValueError("witness byte categories do not sum to witness payload")
    result["binding_witness_bytes"] = 0
    result["binding_script_constant_bytes"] = 2 * len(witness.layout["line_hash"])
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--claim", choices=("fixed", "witness"), default="fixed")
    parser.add_argument("--bundle")
    args = parser.parse_args()
    bundle_path = Path(args.bundle) if args.bundle else ROOT / f"build/{args.claim}.json"
    bundle = json.loads(bundle_path.read_text())
    fixture = json.loads((ROOT / "fixtures/receipt.json").read_text())
    script, witness = build_pairing_script(fixture, args.claim)
    if [item.hex() for item in witness.stack] != bundle["witness"]:
        raise ValueError("bundle witness does not match the Python twin")

    compressed = bytes.fromhex(bundle["script"])
    anchor_depth = bundle["info"]["compression"]["anchor"]["min_depth"]
    unrolled, _, _ = decode_macros(compressed)
    anchored, ranges = anchor_script(
        script.code, witness.stack, anchor_depth, witness.stage_ranges
    )
    if unrolled != anchored:
        raise ValueError("compressed Script does not unroll to the anchored Script")
    report = {
        "claim_mode": args.claim,
        "compressed_script_bytes": len(compressed),
        "stage_script_bytes": compressed_stage_bytes(compressed, unrolled, ranges),
        "witness_items": len(witness.stack),
        "witness_bytes": sum(map(len, witness.stack)),
        "witness_categories": witness_categories(witness),
        "definition_attribution": (
            "Each macro declaration's encoded bytes are apportioned by the "
            "expanded-byte stage distribution of its invocations. Main-body "
            "bytes, including call sites, are apportioned by their expansion spans."
        ),
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
