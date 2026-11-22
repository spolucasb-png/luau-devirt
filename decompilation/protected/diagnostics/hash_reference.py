"""Independent 320-round constant hash reference for the protected target.

The implementation below is transcribed BY HAND from the certified source
text in _h_8.txt / _h_9.txt / _h_28.txt (lines 22-73 of each).  Their 320-round
core is byte-for-byte identical; only the register-update/return tails differ.
It is NOT copied from Rust.  A second function (`rust_control_hash`) is a
separate transcription of src/sarp_large/control.rs:355-468 used ONLY as a
cross-check of the known-answer vectors.

The 16-byte scratch is modelled as a real byte buffer:

  * w32 writes at offsets 0,4,8,12 (little-endian u32),
  * wf64 writes 8 bytes at an offset selected by (hr & 1) * 8, which overlaps
    one or two of those u32 words (the f64 scratch overlap),
  * ri16 reads a SIGNED 16-bit word at ((tr >> 3) & 7) * 2 and the source adds
    65536 and takes % 65536, i.e. the unsigned 16-bit value,
  * the xor writeback at (round & 3) * 4 mutates the same buffer.

Every input below is a proved constant from the certified source/reference;
no int32 preimage is searched and no Lua/Luau, VM, coroutine, executor or
recovered program function is invoked.  Pure Python integer/struct math only.

Source -> Rust parameter correspondence (proved, not inferred):

  source _h[8/9/28]        Rust hash_gate        note
  ----------------------   -------------------   -----------------------------
  _x        (int32)        value                subject
  _m32                     mask                 mask
  _sv                      extra                seed
  _st                      state                frame key
  K1 ^ _sbz                pool ^ SALT          the other two w0 terms
  BL_A / BL_B / BL_C       a / b / c            u16 permutations
  KBOX                     bias                 64 u32 biases (index 1..64)
  _pk1 / _pk2              p1 / p2              equality checks
  _kvIp / _kvSh            ip / sh              certified frame offsets
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
SALT = 43122                      # initB.txt:53, initC.txt (SALT), boot.txt
K1_INITIAL = 1030971814 ^ 355957541   # initOnce.txt:171 = 675551875
SMA = 608916103                   # initC.txt:387
SMB = 1981805674                  # initC.txt:387
EK = 2601618823                   # initC.txt:387
ACTIVATED_K1 = 1648390755        # derived from root-entry words; see prototype_reference.py
K0 = 3350847355                  # pre-Rust reference master_key


def u32(v: int) -> int:
    return v & MASK32


def rotl(v: int, n: int) -> int:
    v = u32(v)
    return u32((v << n) | (v >> (32 - n)))


def rotr(v: int, n: int) -> int:
    v = u32(v)
    return u32((v >> n) | (v << (32 - n)))


def bswap(v: int) -> int:
    return int.from_bytes(u32(v).to_bytes(4, "little"), "big")


def clz(v: int) -> int:
    return 32 - u32(v).bit_length()


def crz(v: int) -> int:
    v = u32(v)
    return 32 if v == 0 else (v & -v).bit_length() - 1


# ---------------------------------------------------------------- source core
def hash_gate_source(
    x: int,
    m32: int,
    sv: int,
    st: int,
    ck: int,
    a: list[int],
    b: list[int],
    c: list[int],
    bias: list[int],
    checkpoints: dict | None = None,
) -> tuple[int, int, int, int]:
    """_h[8]/_h[9]/_h[28] lines 22-73, transcribed from the source text.

    `ck` is the source's `_ck = bxor(K1, _sbz, _sv)`; callers supply the proved
    constant triple.  Returns (_pk1, _pk2, _kvIp, _kvSh).
    """
    A = lambda v: a[u32(v) & 16383]
    B = lambda v: b[u32(v) & 16383]
    C = lambda v: c[u32(v) & 16383]

    # lines 22-24: _u = bxor(_x, 0); _w0 = bxor(_u, _m32, _ck)
    w0 = u32(u32(x) ^ u32(m32) ^ u32(ck))
    w1 = u32(w0 ^ (w0 >> 15))                       # line 25
    a1, a2 = A(w1), B(w1 >> 14)                     # lines 26-27
    a3 = C((w1 >> 18) ^ a1 ^ a2)                    # line 28
    h1 = u32(w1 * 85131 + rotl(w0, 19) + a1 * 65537 + a2 + st) ^ rotl(a3, 12)   # 29
    t2 = u32(h1 ^ rotl(h1, 9) ^ m32)                # line 30
    b1, b2 = A(t2), B(t2 >> 14)                     # lines 31-32
    b3 = C(t2 ^ b1 ^ b2)                            # line 33
    h2 = u32(t2 * 109467 + b1 * 65537 + b2 * 257 + b3 + st) ^ rotr(h1, 19)      # 34
    t3 = u32(h2 ^ h1 ^ rotl(w0, 12))                # line 35
    c1, c2 = A(t3), B(t3 >> 14)                     # lines 36-37
    c3 = C(h2 ^ c1 ^ c2)                            # line 38
    h3 = u32(t3 * 121053 + c1 * 65537 + c2 * 257 + c3 + clz(w0) * 131 + crz(h1) * 17) ^ bswap(h2)  # 39
    t4 = u32(h3 ^ rotl(h2, 19) ^ m32)               # line 40
    d1, d2 = A(t4), B(t4 >> 14)                     # lines 41-42
    d3 = C(h3 ^ d1 ^ d2)                            # line 43

    if checkpoints is not None:
        checkpoints.update({
            "w0": w0, "w1": w1, "a1": a1, "a2": a2, "a3": a3,
            "h1": h1, "t2": t2, "b1": b1, "b2": b2, "b3": b3,
            "h2": h2, "t3": t3, "c1": c1, "c2": c2, "c3": c3,
            "h3": h3, "t4": t4, "d1": d1, "d2": d2, "d3": d3,
        })

    # lines 44-49: buffer creation and the four seed u32 words
    scratch = bytearray(16)
    for off, word in ((0, w0), (4, h1), (8, h2), (12, t3)):
        struct.pack_into("<I", scratch, off, u32(word))

    hr, tr = h3, t4
    round_log = []
    for jr in range(1, 321):                        # line 50: while _jr <= 320
        # line 51-52: _doff = band(_hr,1)*8; wf64(_jfb,_doff, tr + hr/1024 + jr)
        doff = (hr & 1) * 8
        f64value = tr + hr * 0.0009765625 + jr      # 0.0009765625 == 1/1024
        bits = struct.unpack("<Q", struct.pack("<d", float(f64value)))[0]
        struct.pack_into("<Q", scratch, doff, bits)
        # line 53: _jlo, _jhi = r32(_jfb,_doff), r32(_jfb,_doff+4)
        jlo = struct.unpack_from("<I", scratch, doff)[0]
        jhi = struct.unpack_from("<I", scratch, doff + 4)[0]
        # line 54: _i16 = (ri16(_jfb, band(rshift(_tr,3),7)*2) + 65536) % 65536
        ioff = ((tr >> 3) & 7) * 2
        i16 = (struct.unpack_from("<h", scratch, ioff)[0] + 65536) % 65536
        # line 55: _kw = KBOX[1 + band(bxor(_hr,_jr),63)]
        kw = bias[1 + ((hr ^ jr) & 63)]
        # lines 56-58: BL_A/BL_C table lookups with 14-bit masking
        s1 = A(tr ^ jlo ^ i16)
        s2 = B((tr >> 14) ^ jhi)
        s3 = C(hr ^ s1 ^ s2 ^ kw)
        # line 59: _nh = bxor((...)%2^32, lrot(_hr,12), bswap(_s3), _jlo)
        nh = u32(
            tr * 85131 + hr + s1 * 65537 + s2 * 257 + s3 + kw
            + i16 * 13 + clz(tr) * 29 + crz(hr) * 19 + jr * 997
        ) ^ rotl(hr, 12) ^ bswap(s3) ^ jlo
        # line 60: _tr = bxor(_nh, rrot(_tr,9), _m32, _st, _jhi)
        tr = u32(nh ^ rotr(tr, 9) ^ m32 ^ st ^ jhi)
        # lines 61-62: _woff = band(_jr,3)*4; w32(_jfb,_woff, xor(r32(...),_nh))
        woff = (jr & 3) * 4
        old = struct.unpack_from("<I", scratch, woff)[0]
        struct.pack_into("<I", scratch, woff, u32(old ^ nh))
        hr = nh                                    # line 63
        if checkpoints is not None and jr in (1, 2, 3, 4, 64, 160, 319, 320):
            round_log.append({
                "round": jr, "doff": doff, "f64_bits": f"{bits:016x}",
                "jlo": jlo, "jhi": jhi, "i16_offset": ioff, "i16": i16,
                "kw": kw, "s1": s1, "s2": s2, "s3": s3, "nh": nh, "hr": hr, "tr": tr,
            })

    # lines 67-68: _pk1 / _pk2
    pk1 = u32(hr * 121053 + d1 * 65537 + d3 + m32) ^ rotl(d2, 9) ^ rotr(h1, 12) ^ tr
    pk2 = u32(tr * 85131 + hr + d2 * 65537 + d1 + st) ^ rotl(d3, 19) ^ rotr(b3, 9) ^ h3
    # lines 71-72: _kvIp / _kvSh (only used when pk1/pk2 match the expected pair)
    kv_ip = u32(u32(hr ^ d3 ^ rotl(c1, 13)) + b2 * 65537)
    kv_sh = u32(u32(tr ^ d1 ^ rotr(c2, 11)) + b1 * 65537)
    if checkpoints is not None:
        checkpoints.update({
            "final_hr": hr, "final_tr": tr,
            "scratch_le_hex": scratch.hex(),
            "round_log": round_log,
        })
    return pk1, pk2, kv_ip, kv_sh


def source_via_rust_params(value, mask, extra, state, pool, a, b, c, bias, checkpoints=None):
    """Feed the source core with Rust's parameter names.

    Source `_ck = K1 ^ _sbz ^ _sv`; Rust folds `K1 ^ _sbz` into `pool ^ SALT`
    and passes `_sv` as `extra`, so `_ck = pool ^ SALT ^ extra`.
    """
    ck = u32(pool ^ SALT ^ extra)
    if checkpoints is not None:
        checkpoints["ck"] = ck
        checkpoints["w0_terms"] = [value, mask, pool, SALT, extra]
    return hash_gate_source(value, mask, extra, state, ck, a, b, c, bias, checkpoints)


# --------------------------------------------------------------- Rust crosscheck
def rust_control_hash(value, mask, extra, state, pool, a, b, c, bias, checkpoints=None):
    """Independent transcription of src/sarp_large/control.rs:355-468, for
    agreement checking only (the reference above is the source transcription).
    """
    lookup = lambda table, at: table[at & 16383]
    w0 = value ^ mask ^ pool ^ SALT ^ extra
    w1 = w0 ^ (w0 >> 15)
    a1 = lookup(a, w1)
    a2 = lookup(b, w1 >> 14)
    a3 = lookup(c, (w1 >> 18) ^ a1 ^ a2)
    h1 = u32((w1 * 85131 + rotl(w0, 19) + u32(a1 * 65537) + a2 + state)) ^ rotl(a3, 12)
    t2 = h1 ^ rotl(h1, 9) ^ mask
    b1 = lookup(a, t2)
    b2 = lookup(b, t2 >> 14)
    b3 = lookup(c, t2 ^ b1 ^ b2)
    h2 = u32(t2 * 109467 + u32(b1 * 65537) + u32(b2 * 257) + b3 + state) ^ rotr(h1, 19)
    t3 = h2 ^ h1 ^ rotl(w0, 12)
    c1 = lookup(a, t3)
    c2 = lookup(b, t3 >> 14)
    c3 = lookup(c, h2 ^ c1 ^ c2)
    h3 = u32(t3 * 121053 + u32(c1 * 65537) + u32(c2 * 257) + c3 + clz(w0) * 131 + crz(h1) * 17) ^ bswap(h2)
    t4 = h3 ^ rotl(h2, 19) ^ mask
    d1 = lookup(a, t4)
    d2 = lookup(b, t4 >> 14)
    d3 = lookup(c, h3 ^ d1 ^ d2)
    hr, tr = h3, t4
    scratch = bytearray(16)
    for i, word in enumerate([w0, h1, h2, t3]):
        struct.pack_into("<I", scratch, i * 4, word)
    for jr in range(1, 321):
        off = (hr & 1) * 8
        bits = struct.unpack("<Q", struct.pack("<d", float(tr + hr * 0.0009765625 + jr)))[0]
        struct.pack_into("<Q", scratch, off, bits)
        lo = bits & MASK32
        hi = bits >> 32
        idx = ((tr >> 3) & 7) * 2
        i16 = struct.unpack_from("<H", scratch, idx)[0]
        kw = bias[1 + ((hr ^ jr) & 63)]
        s1 = lookup(a, tr ^ lo ^ i16)
        s2 = lookup(b, (tr >> 14) ^ hi)
        s3 = lookup(c, hr ^ s1 ^ s2 ^ kw)
        nh = u32(tr * 85131 + hr + u32(s1 * 65537) + u32(s2 * 257) + s3 + kw
                 + i16 * 13 + clz(tr) * 29 + crz(hr) * 19 + jr * 997) ^ rotl(hr, 12) ^ bswap(s3) ^ lo
        tr = u32(nh ^ rotr(tr, 9) ^ mask ^ state ^ hi)
        woff = (jr & 3) * 4
        old = struct.unpack_from("<I", scratch, woff)[0]
        struct.pack_into("<I", scratch, woff, u32(old ^ nh))
        hr = nh
    p1 = u32(hr * 121053 + u32(d1 * 65537) + d3 + mask) ^ rotl(d2, 9) ^ rotr(h1, 12) ^ tr
    p2 = u32(tr * 85131 + hr + u32(d2 * 65537) + d1 + state) ^ rotl(d3, 19) ^ rotr(b3, 9) ^ h3
    ip = u32(u32(hr ^ d3 ^ rotl(c1, 13)) + u32(b2 * 65537))
    sh = u32(u32(tr ^ d1 ^ rotr(c2, 11)) + u32(b1 * 65537))
    if checkpoints is not None:
        checkpoints.update({"final_hr": hr, "final_tr": tr, "scratch_le_hex": scratch.hex()})
    return p1, p2, ip, sh


# ------------------------------------------------------------------- known answers
def main() -> None:
    reference = json.loads((DIAG / "initialization-reference.json").read_text())
    a, b, c = ia.permutations()
    bias = reference["biases"]           # 65 entries; index 0 unused placeholder

    child_key = u32(K0 ^ u32(ACTIVATED_K1 ^ SALT))   # make/factory decode key

    # Every input is a proved constant: source constants, the pinned master
    # key, source-derived descriptor fields, and small int32 subjects.
    vectors = [
        {"name": "K1-mask/root-key/int32-138920",
         "value": 138920, "mask": u32(K1_INITIAL ^ SALT), "extra": SALT,
         "state": 4225420928, "pool": K1_INITIAL,
         "provenance": "value=root entry_pc; mask=make cookie K1^SALT; extra=SALT; state=reference root descriptor key; pool=initial K1"},
        {"name": "activated-mask/child-key/int32-136924",
         "value": 136924, "mask": u32(ACTIVATED_K1 ^ SALT), "extra": SMA,
         "state": child_key, "pool": ACTIVATED_K1,
         "provenance": "value=first child entry; mask=activatedK1^SALT; extra=_sma; state=source-derived make key; pool=activated K1"},
        {"name": "zero-subject/root-key",
         "value": 0, "mask": u32(K1_INITIAL ^ SALT), "extra": 0,
         "state": 4225420928, "pool": K1_INITIAL,
         "provenance": "value=int32 0; extra=0; all others certified constants"},
        {"name": "one-subject/activated-mask",
         "value": 1, "mask": u32(ACTIVATED_K1 ^ SALT), "extra": SMB,
         "state": child_key, "pool": ACTIVATED_K1,
         "provenance": "value=int32 1; extra=_smb; all others certified constants"},
        {"name": "salt-subject/root-key/ek-seed",
         "value": SALT, "mask": u32(K1_INITIAL ^ SALT), "extra": EK,
         "state": u32(K0 ^ K1_INITIAL), "pool": K1_INITIAL,
         "provenance": "value=SALT int32; extra=_ek; state=K0^initial K1"},
        {"name": "band-subject/activated-mask",
         "value": 16383, "mask": u32(ACTIVATED_K1 ^ SALT), "extra": SALT,
         "state": u32(K0 ^ ACTIVATED_K1), "pool": ACTIVATED_K1,
         "provenance": "value=14-bit mask int32; state=K0^activated K1"},
    ]

    rows = []
    for vec in vectors:
        args = (vec["value"], vec["mask"], vec["extra"], vec["state"], vec["pool"])
        src_cp: dict = {}
        rust_cp: dict = {}
        got_src = source_via_rust_params(*args, a, b, c, bias, src_cp)
        got_rust = rust_control_hash(*args, a, b, c, bias, rust_cp)
        assert got_src == got_rust, (vec["name"], got_src, got_rust)
        assert src_cp["final_hr"] == rust_cp["final_hr"]
        assert src_cp["final_tr"] == rust_cp["final_tr"]
        assert src_cp["scratch_le_hex"] == rust_cp["scratch_le_hex"]
        rows.append({
            "name": vec["name"], "provenance": vec["provenance"],
            "inputs": {"value": vec["value"], "mask": vec["mask"], "extra": vec["extra"],
                       "state": vec["state"], "pool": vec["pool"]},
            "ck": src_cp["ck"], "w0_terms": src_cp["w0_terms"],
            "checkpoints": {k: v for k, v in src_cp.items()
                            if k not in {"w0_terms", "ck", "round_log", "scratch_le_hex"}},
            "scratch_le_hex": src_cp["scratch_le_hex"],
            "round_log": src_cp["round_log"],
            "source_result": {"pk1": got_src[0], "pk2": got_src[1],
                              "kv_ip": got_src[2], "kv_sh": got_src[3]},
            "rust_result": {"pk1": got_rust[0], "pk2": got_rust[1],
                            "kv_ip": got_rust[2], "kv_sh": got_rust[3]},
            "source_equals_rust": True,
        })

    report = {
        "source": "decompilation/protected/diagnostics/_h_8.txt,_h_9.txt,_h_28.txt (lines 22-73)",
        "rust_crosscheck": "src/sarp_large/control.rs:355-468",
        "source_sha256": ia.SOURCE_SHA256,
        "constants": {"SALT": SALT, "K1_initial": K1_INITIAL, "activated_K1": ACTIVATED_K1,
                      "K0": K0, "SMA": SMA, "SMB": SMB, "EK": EK,
                      "child_decode_key": child_key,
                      "mask_initial": u32(K1_INITIAL ^ SALT),
                      "mask_activated": u32(ACTIVATED_K1 ^ SALT)},
        "rounds": 320,
        "scratch_bytes": 16,
        "signed16_read": "struct.unpack('<h') then +65536 %65536",
        "kbox_index": "bias[1 + ((hr ^ round) & 63)]",
        "xor_writeback": "scratch[(round & 3)*4] ^= nh (little-endian u32)",
        "vectors": rows,
        "preimage_search": False,
        "executed": False,
        "devirtualization_claim": False,
    }
    (DIAG / "hash-reference-results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {len(rows)} known-answer vectors; source-transcribed core == Rust cross-check on all.")
    for r in rows:
        print(r["name"], "->", json.dumps(r["source_result"]))


if __name__ == "__main__":
    main()
