"""Independent, positional W/header/slot/bias/permutation comparison.

This file is a NEW diagnostic (it does not modify probe.py,
transport_reference.py or initialization_reference.py).  It compares three
artifacts position by position:

  1. the pre-Rust reference JSON        diagnostics/initialization-reference.json
  2. a fresh re-derivation from the pinned source text (initialize.py logic
     transcribed from initOnce.txt/initB.txt/initC.txt/boot.txt/make.txt)
  3. the Rust output artifact            ../target.metadata.txt + *.bin

No Lua/Luau, VM, coroutine, executor or recovered program function runs.  The
only evaluation is bounded integer/struct arithmetic.  Absent W positions are
compared explicitly: a "None" on one side and a value on the other is a
mismatch, and the full 142045-position index set must be present in the Rust
metadata.

Exact equality of the 7022 populated words is initialization fidelity only.
It is NOT devirtualization: 135023 positions are legitimately absent and the
program instructions are not certified by this audit.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import initialization_audit as ia

ROOT = Path(__file__).resolve().parent.parent
DIAG = ROOT / "diagnostics"
WORD_SLOTS = ia.WORD_SLOTS  # 142045 (word indices 0..142044)


def main() -> None:
    # (1) fresh source re-derivation
    payload = ia.decode_transport(ia.source_fragments())
    assert hashlib.sha256(payload).hexdigest() == ia.TRANSPORT_SHA256
    fresh = ia.initialize(payload)

    # (2) pre-Rust reference and (3) Rust artifact
    reference = json.loads((DIAG / "initialization-reference.json").read_text())
    metadata = ia.parse_metadata(ROOT / "target.metadata.txt")

    checks: dict[str, bool] = {}
    mismatches: list[dict] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks[name] = bool(ok)
        if not ok:
            mismatches.append({"check": name, "detail": detail})

    # pinned source and transport
    src = (ROOT / "target.original.lua").read_bytes()
    check("source_sha256_pinned",
          hashlib.sha256(src).hexdigest() == ia.SOURCE_SHA256
          and metadata["Source"].strip('Some("').rstrip('")') == ia.SOURCE_SHA256)
    rust_transport = (ROOT / "target.transport.bin").read_bytes()
    ref_transport = (DIAG / "reference.transport.bin").read_bytes()
    check("transport_sha256",
          hashlib.sha256(rust_transport).hexdigest() == ia.TRANSPORT_SHA256)
    check("transport_bytes_equal_reference", rust_transport == ref_transport == payload)
    check("transport_word_count", len(rust_transport) // 4 == ia.RAW_WORDS)

    # scalar header / key / float / zero counts / range
    check("argument", int(metadata["Argument"]) == reference["argument"] == 110391195)
    header = [int(x) for x in metadata["Header"].strip("[]").split(",")]
    check("header_words_1_4", header == fresh["header"] == reference["header"],
          f"rust={header} fresh={fresh['header']} ref={reference['header']}")
    check("master_key_K0", int(metadata["K0"]) == fresh["master"] == reference["master_key"])
    # The pre-Rust JSON stores float bits as raw little-endian byte hex, while
    # Rust prints the u64 value; reinterpret the reference bytes the same way.
    ref_float_u64 = int.from_bytes(bytes.fromhex(reference["float_bits"]), "little")
    check("float_bits", int(metadata["Float"], 16) == fresh["float_bits"] == ref_float_u64,
          f"rust={metadata['Float']} fresh={fresh['float_bits']:016x} ref_bytes={reference['float_bits']} ref_u64={ref_float_u64:016x}")
    check("zero_counts", int(metadata["Zero counts"]) == fresh["zero_counts"] == reference["zero_counts"])
    rlo, rhi = (int(x) for x in metadata["Range"].strip("()").split(","))
    check("decoded_range", [rlo, rhi] == fresh["range"] == reference["range"],
          f"rust={[rlo,rhi]} fresh={fresh['range']} ref={reference['range']}")

    # all 1734 slots + biases (65 including the placeholder index 0)
    rust_slots = json.loads(metadata["Slots"])
    check("slots_all_1734", rust_slots == fresh["slots"] == reference["slots"],
          f"lens rust={len(rust_slots)} fresh={len(fresh['slots'])} ref={len(reference['slots'])}")
    check("slot_count", len(rust_slots) - 1 == reference["slot_count"] == 1734)
    check("slot_distinct_71", len(set(rust_slots[1:])) == reference["distinct_slots"] == 71)
    check("slot_max_71", max(rust_slots) == reference["max_slot"] == 71)
    rust_biases = json.loads(metadata["Biases"])
    check("biases_all_65", rust_biases == fresh["biases"] == reference["biases"])
    check("bias_count", len(rust_biases) == 65)

    # permutations: 16384 u16 words each, byte-for-byte and by digest
    for name, values in (("A", fresh["a"]), ("B", fresh["b"]), ("C", fresh["c"])):
        rust_bytes = (ROOT / f"permutation-{name}.bin").read_bytes()
        ref_bytes = (DIAG / f"reference.permutation-{name}.bin").read_bytes()
        own_bytes = b"".join(int(v).to_bytes(2, "little") for v in values)
        check(f"permutation_{name}_bytes", rust_bytes == ref_bytes == own_bytes,
              f"rust={len(rust_bytes)} ref={len(ref_bytes)} own={len(own_bytes)}")
        check(f"permutation_{name}_digest",
              ia.permutation_digest(values) == reference["permutation_hashes"][ord(name) - 65])
    check("permutations_injective", len(set(fresh["a"])) == 16384 and len(set(fresh["b"])) == 16384)

    # EVERY W position including absent ones, three-way
    rust_words = metadata["words"]
    missing_indices = sorted(set(range(WORD_SLOTS)) - set(rust_words))
    check("rust_w_index_set_complete", not missing_indices,
          f"missing {len(missing_indices)} first={missing_indices[:5]}")
    value_mismatch: list[dict] = []
    absence_mismatch: list[dict] = []
    for i in range(WORD_SLOTS):
        rv = rust_words.get(i, "MISSING")
        fv = fresh["words"][i]
        pv = reference["words"][i]
        if not (rv == fv == pv):
            value_mismatch.append({"index": i, "rust": rv, "fresh": fv, "reference": pv})
        if (rv is None) != (fv is None) or (fv is None) != (pv is None):
            absence_mismatch.append({"index": i, "rust": rv, "fresh": fv, "reference": pv})
    check("w_all_142045_positions_three_way", not value_mismatch,
          f"{len(value_mismatch)} mismatches first={value_mismatch[:5]}")
    check("w_absence_agrees", not absence_mismatch,
          f"{len(absence_mismatch)} disagreements first={absence_mismatch[:5]}")

    populated = sum(v is not None for v in fresh["words"])
    check("w_populated_7022", populated == reference["populated_words"] == 7022,
          f"fresh={populated} ref={reference['populated_words']}")
    check("w_absent_count", WORD_SLOTS - populated == 135023)
    check("w_range_fully_populated",
          all(fresh["words"][i] is not None for i in range(rlo, rhi + 1)))
    check("w_outside_range_absent",
          all(fresh["words"][i] is None
              for i in list(range(0, 1)) + list(range(5, rlo))))

    # root descriptor cross-check with the Rust prototype block
    proto = metadata["prototype"]
    root = fresh["root"]
    field_checks = {
        "word": (proto["word"], root["word"], 134628),
        "byte_offset": (proto["byte_offset"], (root["word"] - 1) * 4, 538508),
        "encoded_reference": (proto["encoded_reference"], root["word"] ^ 266632, 400492),
        "entry_pc": (proto["entry_pc"], root["entry"], 138920),
        "initial_decode_state": (proto["initial_decode_state"], root["key"], 4225420928),
        "dispatch_token": (proto["dispatch_token"], root["token"], 4515),
        "frame_capacity": (proto["frame_capacity"], root["frame"], 71),
        "bank_base": (proto["bank_base"], root["bank"], 40),
        "prototype_salt": (proto["prototype_salt"], root["salt"], 53417),
    }
    for field, (rust_value, own, expected) in field_checks.items():
        check(f"root_descriptor_{field}", rust_value == own == expected,
              f"rust={rust_value} own={own} expected={expected}")
    check("root_fixed_false", proto["fixed_parameter_mode"] is False and root["fixed"] == 0)
    check("root_no_captures", proto["captures"] == [] and root["captures"] == 0)
    check("root_no_parameters", proto["parameter_operands"] == [] and root["arity"] == 0)
    check("root_zero_lazy_extent", root["code_start"] == 0 and root["code_length"] == 0)

    # certified control-slot roles
    roles = [("KD", 15), ("SH", 3), ("SB2", 7), ("AP", 9), ("RN", 17), ("PS", 18),
             ("RBS", 33), ("RB", 21), ("SB1", 6), ("IP", 29), ("RBE", 24), ("RV", 2),
             ("ST", 23), ("STOP", 5), ("EXIT", 12)]
    controls = reference["control_slots"]
    check("control_slots_identity", all(controls[n] == fresh["slots"][i] for n, i in roles))
    check("control_slots_distinct", len(set(controls.values())) == 15)
    check("control_slots_in_range", all(1 <= v <= 71 for v in controls.values()))

    report = {
        "source_sha256": ia.SOURCE_SHA256,
        "transport_sha256": ia.TRANSPORT_SHA256,
        "word_positions_compared": WORD_SLOTS,
        "w_populated": populated,
        "w_absent": WORD_SLOTS - populated,
        "slots_compared": len(rust_slots) - 1,
        "biases_compared": len(rust_biases),
        "permutation_words_each": 16384,
        "checks": checks,
        "checks_total": len(checks),
        "checks_passed": sum(checks.values()),
        "mismatches": mismatches,
        "control_slots": controls,
        "devirtualization_claim": False,
        "executed": False,
    }
    (DIAG / "w-evidence.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k not in {"mismatches", "control_slots", "checks"}}, indent=2))
    if mismatches:
        print("MISMATCHES:", json.dumps(mismatches[:10], indent=2))
        raise SystemExit(1)
    print(f"PASS: {len(checks)}/{len(checks)} checks; all {WORD_SLOTS} W positions agree.")


if __name__ == "__main__":
    main()
