"""Independent descriptor + AF lazy-code cipher derivation (static only).

Transcribed from make.txt, boot.txt, wrapper.tokens.txt (the AF factory body,
lines ~2429-2448).  No Lua/Luau, VM, coroutine, executor or recovered program
function runs; this is pure integer/struct math.

What is proved here:

  * the root descriptor (mask 0) from the pinned W table,
  * `activatedK1` derived DIRECTLY from the certified root-entry formula with
    NO child value supplied by any report: boot derives root entry 138920 and
    est, U(270,...) gives st = est + 67311, and _dr_2880 lines 92-94 derive
    _cs and K1 from the root-entry W words.  The mask then follows as
    `activatedK1 ^ SALT`,
  * the first child descriptor decoded independently with that mask (entry
    136924, bank 94, fixed 1, captures 0, lazy code 136680+559),
  * the make/AF double-XOR round trip for code start, length and hash key,
  * the AF lazy-code cipher seed, LCG, rotate/xor mixing and XOR writeback for
    all 559 words, plus a digest of the decoded code words.

No Rust report value (in particular no child entry) is used as an input to
the activation derivation.  The child decode is a downstream check, not the
source of the key.
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import initialization_audit as ia

ROOT = Path(__file__).resolve().parent.parent
DIAG = ROOT / "diagnostics"
MASK32 = 0xFFFFFFFF
SALT = 43122
K1_INITIAL = 1030971814 ^ 355957541


def u32(v: int) -> int:
    return v & MASK32


def rotl(v: int, n: int) -> int:
    v = u32(v)
    return u32((v << n) | (v >> (32 - n)))


def clz(v: int) -> int:
    return 32 - u32(v).bit_length()


def crz(v: int) -> int:
    v = u32(v)
    return 32 if v == 0 else (v & -v).bit_length() - 1


def descriptor(W: list, p: int, key: int) -> dict:
    """boot.txt:14-19 / make.txt:6-13 field decode.

    Capture halves use the HIGH word half as the parent-bank source offset and
    the LOW half as the child-bank destination operand (helper 19 reads high;
    boot/make read low).
    """
    w = lambda i: W[p + i]
    est = w(0) ^ 2305819396 ^ key
    entry = w(2) ^ 3146221740 ^ key
    aa = w(3) ^ 1312544370 ^ key
    bb = w(4) ^ 3129404073 ^ key
    token = w(5) ^ 3545062758 ^ key
    code_start = w(6) ^ 3330028092 ^ key
    code_length = w(1) ^ 322097349 ^ key
    out = {
        "word": p, "est": est, "entry": entry, "token": token,
        "code_start": code_start, "code_length": code_length,
        "fixed": aa & 1, "bank": (aa >> 1) & 131071,
        "arity": (aa >> 29) & 7, "captures": (aa >> 19) & 1023,
        "frame": (bb >> 18) & 8191, "salt": bb & 65535,
        "packed_a": aa, "packed_b": bb,
    }
    aw = (out["arity"] + 1) // 2 if out["fixed"] else 0
    params = []
    for i in range(aw):
        value = w(7 + i) ^ 431712049 ^ key
        params.extend([value & 65535, value >> 16])
    params = params[:out["arity"]] if out["fixed"] else []
    caps = []
    for i in range(out["captures"]):
        value = w(7 + aw + i) ^ 1434732467 ^ key
        caps.append({"destination_low": value & 65535, "source_high": (value >> 16) & 65535})
    out["parameter_operands"] = params
    out["captures_low_dest_high_source"] = caps
    return out


def valid(d: dict, lo: int, hi: int) -> tuple[bool, list[str]]:
    reasons = []
    if not (lo <= d["entry"] <= hi):
        reasons.append("entry outside decoded range")
    if d["arity"] > 4 or d["frame"] == 0:
        reasons.append("bad arity/frame")
    if not (lo <= d["code_start"] < hi):
        reasons.append("code_start outside range")
    if not (0 < d["code_length"] <= hi - lo + 1):
        reasons.append("code_length outside range")
    return (not reasons), reasons


def main() -> None:
    reference = json.loads((DIAG / "initialization-reference.json").read_text())
    W = reference["words"]
    K0 = reference["master_key"]
    lo, hi = reference["range"]

    checks: dict[str, bool] = {}
    def check(name: str, ok: bool, detail: str = "") -> None:
        checks[name] = bool(ok)
        if not ok:
            print(f"FAIL {name}: {detail}")

    root = descriptor(W, 134628, K0)
    check("root_entry", root["entry"] == 138920, str(root["entry"]))
    check("root_fields", (root["bank"], root["frame"], root["salt"], root["token"])
          == (40, 71, 53417, 4515), str(root))
    check("root_no_code_extent", root["code_start"] == 0 and root["code_length"] == 0)

    # Direct activation derivation, with NO child value supplied by any report.
    # boot.txt:10-19:  hw = tk ^ 266632 = 134628 (root descriptor word),
    #                  entry = W[hw+2] ^ 3146221740 ^ K0 = 138920 (mask 0),
    #                  est   = W[hw+0] ^ 2305819396 ^ K0.
    # U(270,...).third = TM["nil"] + SALT = 24189 + 43122 = 67311
    #   (U.txt:51, initOnce.txt:75 TM table, initB.txt:53 salt),
    #   so boot.txt:67 sets st = (est + 67311) % 2^32.
    # _dr_2880.txt:92-94 (entry helper; lift.rs:1418-1454 matches this body):
    #   _cs = (W[ip+4] + st) % 2^32
    #   K1  = ((W[ip+1] + st) % 2^32) ^ K0 ^ ps ^ st ^ _cs
    # with ip = boot-derived root entry and ps = root descriptor low half.
    boot_root_word = 134628
    boot_root_entry = 138920
    root_est = u32(W[boot_root_word] ^ 2305819396 ^ K0)
    st = u32(root_est + 67311)
    ps = root["salt"]                    # bext(mtB,0,16) of root = 53417
    ip = boot_root_entry
    entry_cs = u32(W[ip + 4] + st)       # source `_cs` (not the AF code start)
    activated = u32(u32(W[ip + 1] + st) ^ K0 ^ ps ^ st ^ entry_cs)
    derived_mask = u32(activated ^ SALT)
    # Auxiliary entry-probe fields from the same certified root words.
    stride = u32(W[ip + 2] ^ st)         # source `_ls`
    rotor = u32(u32(W[ip + 5] + st) | 1) # source `_sr` (odd)
    a0 = u32(W[ip + 3] + st)             # source `_a0`
    check("root_entry_boot_derived", boot_root_entry == 138920)
    check("root_est_from_W", root_est == 4225420928, f"{root_est}")
    check("entry_probe_st", st == 4225488239, f"{st}")
    check("entry_probe_cs", entry_cs == 156857040, f"{entry_cs}")
    check("derived_activated_K1_direct", activated == 1648390755, f"{activated}")
    check("derived_mask", derived_mask == u32(1648390755 ^ SALT), f"{derived_mask}")
    check("entry_probe_stride_18", stride == 18, f"{stride}")
    check("entry_probe_rotor_odd", rotor & 1 == 1, f"{rotor}")
    check("entry_probe_a0", a0 == 0, f"{a0}")

    candidates = {"initial_K1": u32(K1_INITIAL ^ SALT), "activated_K1": derived_mask}
    trials = {}
    for name, mask in candidates.items():
        d = descriptor(W, 140545, u32(K0 ^ mask))
        ok, reasons = valid(d, lo, hi)
        trials[name] = {"mask": mask, "key": u32(K0 ^ mask), "valid": ok,
                        "reasons": reasons, "descriptor": d}
    check("initial_mask_rejected", not trials["initial_K1"]["valid"])
    check("activated_mask_accepted", trials["activated_K1"]["valid"])

    child = trials["activated_K1"]["descriptor"]
    check("child_entry", child["entry"] == 136924, str(child["entry"]))
    check("child_bank", child["bank"] == 94, str(child["bank"]))
    check("child_fixed", child["fixed"] == 1, str(child["fixed"]))
    check("child_captures_zero", child["captures"] == 0, str(child["captures"]))
    check("child_frame", child["frame"] == 71, str(child["frame"]))
    check("child_code_extent", (child["code_start"], child["code_length"]) == (136680, 559),
          str((child["code_start"], child["code_length"])))
    check("child_arity_one", child["arity"] == 1, str(child["arity"]))
    check("child_est", child["est"] == 1528981884, str(child["est"]))

    # make.txt:29 / wrapper.tokens.txt:2432 double-XOR round trip.
    key = u32(K0 ^ derived_mask)          # make _hk
    K1 = activated
    pcs = u32(child["code_start"] ^ (K1 & 65535))
    pcl = u32(child["code_length"] ^ ((K1 >> 8) & 65535))
    phk = u32(key ^ K1)
    cs = u32(pcs ^ (K1 & 65535))
    cl = u32(pcl ^ ((K1 >> 8) & 65535))
    hk0 = u32(phk ^ K1)
    check("make_AF_code_start_roundtrip", cs == child["code_start"])
    check("make_AF_code_length_roundtrip", cl == child["code_length"])
    check("make_AF_hashkey_roundtrip", hk0 == key)

    # AF lazy code cipher: wrapper.tokens.txt:2435-2447.
    af_ps, af_est = child["salt"], child["est"]   # do not shadow root `ps`
    seed = u32(u32(u32(hk0 ^ u32(af_ps * 65537)) ^ af_est ^ 546595050)
               ^ u32(clz(af_est) + crz(af_ps) * 257))
    state = seed
    keystream = []
    for _ in range(cl):
        state = u32(u32(state * 6405) + 483291509)
        state = u32(rotl(state, 6) ^ (state >> 13))
        keystream.append(state)
    decoded = [u32(W[cs + i] ^ keystream[i]) for i in range(cl)]
    digest = hashlib.sha256(b"".join(struct.pack("<I", v) for v in decoded)).hexdigest()
    check("code_extent_in_range", lo <= cs and cs + cl <= hi + 1)

    report = {
        "source_sha256": ia.SOURCE_SHA256,
        "constants": {
            "K0": K0, "SALT": SALT, "K1_initial": K1_INITIAL,
            "activated_K1_direct_root_entry_formula": activated,
            "derived_mask": derived_mask, "decode_key": key,
        },
        "root_entry_activation": {
            "boot_root_word": boot_root_word,
            "boot_root_entry": boot_root_entry,
            "root_est": root_est,
            "tg_from_U270": 67311,
            "st": st, "ps": ps, "ip": ip,
            "words": {"ip+1": W[ip + 1], "ip+2": W[ip + 2], "ip+3": W[ip + 3],
                      "ip+4": W[ip + 4], "ip+5": W[ip + 5]},
            "entry_cs": entry_cs, "stride": stride, "rotor": rotor, "a0": a0,
            "formula": "K1 = ((W[ip+1]+st)%2^32) ^ K0 ^ ps ^ st ^ ((W[ip+4]+st)%2^32)",
        },
        "root": {k: root[k] for k in ("word", "entry", "bank", "frame", "salt", "token",
                                      "code_start", "code_length")},
        "mask_trials": {name: {"mask": t["mask"], "key": t["key"], "valid": t["valid"],
                               "reasons": t["reasons"]} for name, t in trials.items()},
        "first_child": child,
        "make_AF_roundtrip": {"pcs": pcs, "pcl": pcl, "phk": phk,
                              "cs": cs, "cl": cl, "hk0": hk0},
        "af_lazy_cipher": {
            "seed": seed, "ps": af_ps, "est": af_est,
            "lcg": "state = (state*6405 + 483291509) % 2^32",
            "mix": "state = bxor(lrot(state,6), rshift(state,13))",
            "writeback": "W[cs+i] = bxor(W[cs+i], keystream[i])",
            "rounds": cl,
            "first_8_keystream": keystream[:8],
            "last_4_keystream": keystream[-4:],
            "first_8_decoded_words": decoded[:8],
            "decoded_words_sha256": digest,
        },
        "capture_half_rule": "low 16 bits = child-bank destination operand; high 16 bits = parent-bank source offset",
        "checks": checks,
        "checks_total": len(checks),
        "checks_passed": sum(checks.values()),
        "derivation_note": "activatedK1 is derived from the certified root-entry formula only; no Rust report child entry is an input. The child descriptor decode is a downstream check.",
        "executed": False,
        "devirtualization_claim": False,
    }
    (DIAG / "prototype-reference.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items()
                      if k not in {"first_child", "checks", "root"}}, indent=2))
    print(f"PASS: {sum(checks.values())}/{len(checks)} prototype/AF checks.")
    if not all(checks.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
