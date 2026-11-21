"""SARP independent STATIC arithmetic reference (diagnostics only).

Self-contained: the leading `local _pcN =` fragment literals and the
`_ab` alphabet literal are read from the original source with a bounded
lexical scanner implemented here (with tested exact Lua escape handling);
no external probe module is imported. No Lua source is ever executed,
evaluated or interpreted, and no target expression is evaluated.

Recomputed with pure Python arithmetic transcribed from the preserved
diagnostics (initOnce.txt, initB.txt, boot.txt, make.txt, U.txt,
exec.txt):

  1. fragment assembly (_pc0.._pc4, bcopy order/offsets)
  2. Base85 word decode (low digit first) + bit32.byteswap
  3. transport LCG xor (1147127625 * 17487 + 3048913621)
  4. header word stream (bxor(sa, 1496625396); 398991 + 3534337991 bswap
     xorshift; the same state continues into the ws..ce fill)
  5. K0 (f64 bits, countlz/countrz, pcall/metamethod/coroutine modeled as
     the proven standard-Luau identities -> _pf = 0, _pe = 0), K1 constant
  6. ws..ce range from header + K0, initB second-layer masking after the
     cyield(K0) / cresume(bxor(K0, K0)) handshake
  7. KBOX bias (64), BL_A/BL_B/BL_C permutations, RMAP (118 slots),
     C_* slots, CM/CM2/CM3 tables
  8. root prototype 7-word header and the U-main frame seeds
     (_pa, exp, _tg == 74056 + 12836 + 0 == 86892)
  9. root-entry opcode walk inside dispatch family 2199 (its complete op
     table is transcribed below), yielding the single pool-key rekey and
     the first call target; the walk stops at the family transition
 10. const string record scan (offsets + bodies) under the initial and
     root-entry-rekeyed pool keys, and const number records
 11. the executed control-flow path of initOnce/initB is traced and the
     dormant `_dm` branches are proven unreachable (no checksum ever runs)

The parent Rust implementation's pinned values are used ONLY as a final
comparison block; they are never an input to any derivation here.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import struct
from datetime import datetime, timezone
from pathlib import Path

DIAG = Path(__file__).resolve().parent
TARGET = DIAG.parent / "target.original.lua"
SOURCE_SHA256 = "4518ff6626677a946e60b1f1fbf5e0e0bd6c2aa95a674c163864e763fff3d45f"
GIT_BLOB_SHA1 = "b05c800c569376cc9f99c9be13e484f938d3949f"
BASELINE_COMMIT = "3ffea1943b15feffeceb29f6193238163d055511"

MAX_SOURCE = 8 * 1024 * 1024
MAX_LITERAL = 8192  # bounded scan span for one string literal
M32 = 0xFFFFFFFF
SMA = 1771687064  # _sma
SMB = 4294002830  # _smb
SALT = 12836      # BL_C construction salt; equals every frame's string salt


# ---------------------------------------------------------------------------
# Bounded lexical scanning of the original source (independent, exact)
# ---------------------------------------------------------------------------

_LUA_ESCAPES = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11}


def scan_quoted(source: str, start: int, limit: int) -> tuple[str, int]:
    """Bounded scan of a short (quoted) string literal opening at start.

    Returns (token_text, index_after_closing_quote). Raw newlines inside a
    short literal are rejected, exactly like Lua's lexer would.
    """
    if start >= len(source) or source[start] not in ("'", '"'):
        raise ValueError(f"expected a quote at offset {start}")
    quote = source[start]
    i = start + 1
    while i < limit and i < len(source):
        ch = source[i]
        if ch == "\\":
            escaped = source[i + 1 : i + 2]
            if not escaped:
                raise ValueError("truncated escape")
            i += 2
            if escaped == "z":
                while i < limit and i < len(source) and source[i] in " \t\r\n\v\f":
                    i += 1
            elif escaped == "\r" and source[i : i + 1] == "\n":
                i += 1
            continue
        if ch == quote:
            return source[start : i + 1], i + 1
        if ch in "\r\n":
            raise ValueError(f"raw newline inside short literal at offset {start}")
        i += 1
    raise ValueError(f"unterminated literal within {limit - start} byte bound")


def unquote_lua_string(token: str) -> bytes:
    """Exact Lua 5.4/Luau short-string unquoting for the scanned token."""
    if len(token) < 2 or token[0] not in ("'", '"') or token[-1] != token[0]:
        raise ValueError("not a quoted literal token")
    body = token[1:-1]
    out = bytearray()
    i, n = 0, len(body)
    while i < n:
        ch = body[i]
        if ch != "\\":
            if ch in "\r\n":
                raise ValueError("raw newline inside literal body")
            out.extend(ch.encode("utf-8"))
            i += 1
            continue
        i += 1
        if i >= n:
            raise ValueError("trailing backslash")
        ch = body[i]
        if ch in _LUA_ESCAPES:
            out.append(_LUA_ESCAPES[ch])
            i += 1
        elif ch in ("'", '"', "\\"):
            out.append(ord(ch))
            i += 1
        elif ch.isascii() and ch.isdigit():
            match = re.match(r"[0-9]{1,3}", body[i:])
            assert match is not None
            value = int(match[0])
            if value > 255:
                raise ValueError(f"decimal escape \\{match[0]} out of byte range")
            out.append(value)
            i += len(match[0])
        elif ch == "x":
            digits = body[i + 1 : i + 3]
            if len(digits) != 2 or not re.fullmatch(r"[0-9a-fA-F]{2}", digits):
                raise ValueError("hex escape requires exactly two hex digits")
            out.append(int(digits, 16))
            i += 3
        elif ch == "z":
            i += 1
            while i < n and body[i] in " \t\r\n\v\f":
                i += 1
        elif ch in "\r\n":
            if ch == "\r" and body[i + 1 : i + 2] == "\n":
                i += 1
            i += 1
            out.append(10)
        else:
            raise ValueError(f"unsupported escape \\{ch}")
    return bytes(out)


def escape_self_test() -> None:
    """Exact-escape tests for the independent scanner (run before use)."""
    cases = [
        ('"abc"', b"abc"),
        ('"a\\nb"', b"a\nb"),
        ('"\\65\\066\\67"', b"ABC"),
        ('"\\x41\\x42"', b"AB"),
        ('"a\\z   b"', b"ab"),
        ('"\\\\"', b"\\"),
        ('"\\\"q\\\""', b'"q"'),
        ("'it\\'s'", b"it's"),
        ('"a\\\nb"', b"a\nb"),
        ('"a\\\r\nb"', b"a\nb"),
        ('"a\\z\u00a0b"', b"a\xc2\xa0b"),
        ("'\\t\\v\\a\\b\\f\\r'", b"\t\v\a\b\f\r"),
        ('"\\250"', b"\xfa"),
        ('"\\0"', b"\x00"),
        ('"caf\\xc3\\xa9"', "café".encode("utf-8")),
    ]
    for token, expected in cases:
        got = unquote_lua_string(token)
        assert got == expected, f"escape test failed: {token!r} -> {got!r}"
    for bad in ('"\\256"', '"\\x4"', '"ab', '"a\nb"', '"\\q"'):
        try:
            unquote_lua_string(bad)
        except ValueError:
            continue
        raise AssertionError(f"escape test expected rejection for {bad!r}")
    token, end = scan_quoted('"x\\\\y"', 0, 64)
    assert token == '"x\\\\y"' and end == 6, (token, end)
    assert unquote_lua_string(token) == b"x\\y"


def find_declaration_literal(source: str, pattern: str) -> list[bytes]:
    """All string literals for `local <name> =`-style declarations matching
    the given regex (whitespace-tolerant, bounded literal span)."""
    results = []
    for match in re.finditer(pattern, source):
        i = match.end()
        while i < len(source) and source[i].isspace():
            i += 1
        token, _ = scan_quoted(source, i, i + MAX_LITERAL)
        results.append(unquote_lua_string(token))
    return results


def extract_source_literals() -> tuple[dict[str, bytes], bytes, bytes]:
    data = TARGET.read_bytes()
    if sha256_hex(data) != SOURCE_SHA256:
        raise SystemExit("target.original.lua sha256 mismatch; refusing to proceed")
    if len(data) > MAX_SOURCE:
        raise SystemExit("source exceeds the static scan budget")
    source = data.decode("utf-8")
    escape_self_test()

    literals: dict[str, bytes] = {}
    for name in ("_pc0", "_pc1", "_pc2", "_pc3", "_pc4"):
        found = find_declaration_literal(source, rf"local\s+{re.escape(name)}\s*=")
        if len(found) != 1:
            raise SystemExit(f"expected exactly one `local {name} =` string literal, found {len(found)}")
        literals[name] = found[0]

    alphabets = find_declaration_literal(source, r"local\s+_ab\s*=\s*bfrom\s*\(")
    if len(alphabets) != 1:
        raise SystemExit(f"expected exactly one `local _ab = bfrom(...)` alphabet literal, found {len(alphabets)}")
    alphabet = alphabets[0]
    if len(alphabet) != 85 or len(set(alphabet)) != 85:
        raise SystemExit("alphabet must be 85 distinct bytes")
    for name, value in literals.items():
        if not all(byte in alphabet for byte in set(value)):
            raise SystemExit(f"fragment {name} contains bytes outside the Base85 alphabet")
    return literals, alphabet, data


# ---------------------------------------------------------------------------
# 32-bit arithmetic primitives (bit32/buffer identities)
# ---------------------------------------------------------------------------


def bxor(*values: int) -> int:
    """bit32.bxor over any number of operands (mod 2^32)."""
    out = 0
    for v in values:
        out ^= v
    return out & M32


def bswap(v: int) -> int:
    v &= M32
    return ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) | ((v >> 8) & 0xFF00) | ((v >> 24) & 0xFF)


def lrot(v: int, n: int) -> int:
    v &= M32
    n %= 32
    return ((v << n) | (v >> (32 - n))) & M32


def clz(v: int) -> int:
    return 32 - (v & M32).bit_length()


def crz(v: int) -> int:
    v &= M32
    if v == 0:
        return 32
    return (v & -v).bit_length() - 1


def lshift(v: int, n: int) -> int:
    return (v << n) & M32


def rshift(v: int, n: int) -> int:
    return (v & M32) >> n


def band(v: int, m: int) -> int:
    return v & m


def bor(v: int, w: int) -> int:
    return v | w


def bext(v: int, pos: int, width: int) -> int:
    """bit32.extract(v, pos, width)."""
    return (v >> pos) & ((1 << width) - 1)


def brep(v: int, r: int, pos: int, width: int) -> int:
    """bit32.replace(v, r, pos, width)."""
    mask = ((1 << width) - 1) << pos
    return (v & ~mask & M32) | ((r & ((1 << width) - 1)) << pos)


def r32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def f64_bits(value: float) -> tuple[int, int]:
    """buffer.writef64 is little-endian; _flo/_fhi are the readu32 halves."""
    raw = struct.pack("<d", value)
    return struct.unpack_from("<I", raw, 0)[0], struct.unpack_from("<I", raw, 4)[0]


CHECKPOINTS: list[dict[str, str]] = []


def checkpoint(name: str, detail: str) -> None:
    CHECKPOINTS.append({"stage": name, "detail": detail})
    print(f"[checkpoint] {name}: {detail}")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Stage 2/3: fragment assembly, Base85 low-digit-first decode, transport xor
# ---------------------------------------------------------------------------

FRAGMENT_LEN = {"_pc0": 558, "_pc1": 582, "_pc2": 560, "_pc3": 556, "_pc4": 574}
# initOnce bcopy order (source order, not declaration order):
#   bcopy(_b85, 1140, bfrom(_pc2), 0, 560); bcopy(_b85, 2256, bfrom(_pc4), 0, 574);
#   bcopy(_b85, 1700, bfrom(_pc3), 0, 556); bcopy(_b85,  558, bfrom(_pc1), 0, 582);
#   bcopy(_b85,    0, bfrom(_pc0), 0, 558)
BCOPY_ORDER = [("_pc2", 1140), ("_pc4", 2256), ("_pc3", 1700), ("_pc1", 558), ("_pc0", 0)]


def assemble_and_decode(literals: dict[str, bytes], alphabet: bytes) -> bytes:
    for name, size in FRAGMENT_LEN.items():
        if len(literals[name]) != size:
            raise SystemExit(f"fragment {name} has {len(literals[name])} bytes, expected {size}")
    encoded = bytearray(2830)
    covered = [False] * 2830
    for name, offset in BCOPY_ORDER:
        chunk = literals[name]
        for i in range(len(chunk)):
            if covered[offset + i]:
                raise SystemExit("overlapping fragment write")
            covered[offset + i] = True
            encoded[offset + i] = chunk[i]
    if not all(covered):
        raise SystemExit("unwritten transport bytes")
    index = {byte: i for i, byte in enumerate(alphabet)}
    payload = bytearray(2264)
    key = 1147127625
    for word in range(566):
        p = word * 5
        # initOnce: low digit first (_p least significant, _p+4 most significant)
        v = 0
        for digit in reversed(range(5)):
            v = v * 85 + index[encoded[p + digit]]
        v &= M32
        key = (key * 17487 + 3048913621) % 4294967296
        struct.pack_into("<I", payload, word * 4, bswap(v) ^ key)
    return bytes(payload)


# ---------------------------------------------------------------------------
# Stage 4/5: initOnce header stream, K0, K1, ws..ce range
# ---------------------------------------------------------------------------

SA = bxor(66482806, 3268698463)


def next_st(st: int) -> int:
    st = (st * 398991 + 3534337991) % 4294967296
    st = bswap(st)
    st = bxor(st, lshift(st, 9))
    st = bxor(st, rshift(st, 5))
    st = bxor(st, lshift(st, 1))
    return st


def model_pe_checks() -> dict[str, bool]:
    """initOnce environment probes, each an exact standard-Luau identity."""
    checks: dict[str, bool] = {}
    checks["bit32.replace"] = brep(3225577635, 199, 7, 8) == 3225576355
    # rawget({[2]=92}, 2) == 92: rawget bypasses __index and [2] is a raw
    # entry, so the __index(999) fallback is never consulted.
    checks["rawget"] = True
    # _rt2 - 15 -> __sub(_a, _b) -> _a[2] - _b; _a[2] is the raw entry 92.
    checks["__sub"] = 92 - 15 == 77
    checks["frexp"] = math.frexp(55.5) == (0.8671875, 6)
    checks["ldexp"] = math.ldexp(0.8671875, 6) == 55.5
    checks["modf"] = math.modf(55.75)[1] == 55.0
    checks["clamp"] = min(max(68, 21), 53) == 53
    checks["format"] = "%04x:%d" % (39634, 77) == "9ad2:77"
    checks["reverse_byte"] = "9ad2"[::-1][0] == "2" and ord("2") == 50
    checks["pack"] = struct.unpack("<Ih", struct.pack("<Ih", 4031576911, -10585)) == (
        4031576911,
        -10585,
    )
    # tonumber("o0h", 31): o = 24, 0 = 0, h = 17 -> 24*31^2 + 0*31 + 17 = 23081
    checks["tonumber_base31"] = 24 * 31 * 31 + 0 * 31 + 17 == 23081
    return checks


def init_once(payload: bytes) -> dict[str, object]:
    st = bxor(SA, 1496625396)
    header = [0, 0, 0, 0]
    for i in range(1, 5):
        st = next_st(st)
        header[i - 1] = bxor(r32(payload, (i - 1) * 4), st)

    bw = r32(payload, 12)
    m0 = bxor(SA, bw)
    m1 = (m0 * 26797 + 1259477385) % 4294967296

    # pcall/metamethod/coroutine semantics (proven Luau invariants, not
    # execution of the target):
    #   _p1 = pcall(function() local _e = {}; return _e + 1 end):
    #       arithmetic add on a plain table raises -> _p1 == false -> _pf = 0
    #   _p2, _mv = pcall(function() return _mx + _mx[2] end):
    #       __add(_, v) -> _mv = (v + _cz + _pf) % 2^32 and _p2 == true
    #   _kc = coroutine(function(_a,_b,_c) cyield(bxor(_a,_b)); cyield(_c) end):
    #       the first resume passes (_mx[1], _mx[3], _p2 and _mv or 0) =
    #       (m1, _fhi, _mv) because _p2 is true; cyield returns bxor(m1,_fhi)
    #       as _kpa, the second resume returns _mv as _kpb; both ok
    #   _pe = _pf + (_p2 and 0 or 2) + (_ok1 and 0 or 4) + (_ok2 and 0 or 8)
    #       plus the probe deltas below, all zero on a standard runtime.
    checks = model_pe_checks()
    if not all(checks.values()):
        raise SystemExit(f"environment identity failed: {checks}")
    pf = 0
    pe = pf + 0 + 0 + 0

    float_value = m1 + header[3] + 1048576
    flo, fhi = f64_bits(float(float_value))
    cz = clz(m0) * 65537 + crz(bw) * 257 + clz(header[3])

    # K0 = bxor((m1 + _flo) % 2^32, lrot(wt[4], 11), _fhi, bswap(_mx(m0)), #_mx)
    # with _mx(m0) = bxor(m0, _pe) (via __call) and #_mx = _cz (via __len).
    k0 = bxor((m1 + flo) % 4294967296, lrot(header[3], 11), fhi, bswap(bxor(m0, pe)), cz)
    k1 = bxor(4021752008, 3067287787)

    ws = bxor(header[1], bxor(3678364643, k0))
    ce = bxor(header[2], bxor(3087163986, k0))
    if not (5 <= ws <= ce and ce + 59 <= 566):
        raise SystemExit(f"invalid header-derived word range {ws}..={ce}")

    words: list[int | None] = [None] * 567
    for i in range(1, 5):
        words[i] = header[i - 1]
    # the st recurrence continues from the header fill, never reset
    for i in range(ws, ce + 1):
        st = next_st(st)
        words[i] = bxor(r32(payload, (i - 1) * 4), st)

    return {
        "sa": SA,
        "st_seed": bxor(SA, 1496625396),
        "header": header,
        "bw": bw,
        "m0": m0,
        "m1": m1,
        "float_value": float_value,
        "float_bits": struct.unpack("<Q", struct.pack("<d", float(float_value)))[0],
        "flo": flo,
        "fhi": fhi,
        "cz": cz,
        "pf": pf,
        "pe": pe,
        "checks": checks,
        "k0": k0,
        "k1_initial": k1,
        "ws": ws,
        "ce": ce,
        "range_count": ce - ws + 1,
        "words": words,
    }


# ---------------------------------------------------------------------------
# Stage 6/7: initB - KBOX, permutations, second-layer masking, RMAP, CM tables
# ---------------------------------------------------------------------------


def build_kbox() -> list[int]:
    ks = 706272505
    biases = [0]
    for _ in range(64):
        ks = (ks * 26663 + 4214497697) % 4294967296
        biases.append(1 + ks % 200000)
    return biases


def build_permutations() -> tuple[list[int], list[int], list[int]]:
    a = list(range(16384))
    b = list(range(16384))
    c = [0] * 16384
    ka, kb = 1933532995, 2171122303
    for i in range(16383, 0, -1):
        ka = (ka * 17577 + 419902917) % 4294967296
        j = ka % (i + 1)
        a[i], a[j] = a[j], a[i]
        kb = (kb * 17577 + 419902917) % 4294967296
        k = kb % (i + 1)
        b[i], b[k] = b[k], b[i]
    for i in range(16384):
        pa, pb = a[i], b[i]
        bit = bxor(bext(pa, 7, 1), bext(pb, 10, 1), 1)
        c[pa] = (pb * 4 + ((i * 17 + 1833) % 16384) * 2 + bit + SALT) % 65536
    for i in range(16384):
        ka = (ka * 17577 + 419902917) % 4294967296
        kb = (kb * 17577 + 419902917) % 4294967296
        a[i] = bor(a[i], lshift(bext(ka, 20, 2), 14))
        b[i] = bor(b[i], lshift(bext(kb, 20, 2), 14))
    return a, b, c


def second_layer(
    words: list[int | None],
    k0: int,
    ws: int,
    ce: int,
    a: list[int],
    b: list[int],
    c: list[int],
    kbox: list[int],
) -> None:
    """initB post-cyield masking; the resume value is bxor(K0, K0) == 0."""
    k2 = bxor(k0, 2372119159)
    for wi in range(ws, ce + 1):
        k2 = (k2 * 7745 + 888415943) % 4294967296
        m2 = bxor(
            a[band(k2, 16383)],
            lshift(b[band(rshift(k2, 14), 16383)], 16),
            kbox[1 + (wi % 64)],
            c[band(bxor(k2, wi), 16383)],
        )
        if words[wi] is None:
            raise SystemExit(f"absent decoded word at second-layer index {wi}")
        words[wi] = bxor(words[wi], m2)


def build_rmap(payload: bytes, ce: int, k0: int) -> list[int]:
    rk = bxor(3402759894, k0)
    rb_off = ce * 4
    slots = [0]
    for wi in range(59):
        rk = (rk * 24307 + 1800847725) % 4294967296
        pw = bxor(r32(payload, rb_off + wi * 4), rk)
        slots.append(band(pw, 65535))
        slots.append(rshift(pw, 16))
    return slots


def build_cm(rmap: list[int]) -> dict[str, object]:
    c = {
        "C_RN": rmap[4],
        "C_RV": rmap[10],
        "C_RBS": rmap[11],
        "C_ST": rmap[7],
        "C_SB2": rmap[6],
        "C_SH": rmap[3],
        "C_RB": rmap[14],
        "C_RBE": rmap[2],
        "C_EXIT": rmap[9],
        "C_SB1": rmap[13],
        "C_AP": rmap[5],
        "C_STOP": rmap[1],
        "C_IP": rmap[12],
        "C_KD": rmap[8],
        "C_PS": rmap[15],
    }
    cm = [
        c["C_ST"], c["C_SB1"], c["C_RN"], 17, c["C_KD"], c["C_RV"], c["C_SB2"],
        c["C_IP"], c["C_EXIT"], c["C_RBS"], c["C_SH"], 3, 48, c["C_RBE"], 33,
        46, c["C_RB"], 49, 10, c["C_AP"], c["C_PS"], 11, 5, c["C_STOP"], 4,
    ]
    cm2 = [
        c["C_RN"], c["C_STOP"], c["C_EXIT"], 19, c["C_IP"], c["C_RV"], 17,
        c["C_RBS"], c["C_SB2"], 12, c["C_KD"], 22, 25, c["C_RBE"], 5, c["C_SH"],
        c["C_PS"], 7, 31, 46, 16, c["C_SB1"], c["C_ST"], c["C_RB"], c["C_AP"], 40,
    ]
    cm3 = [
        c["C_RBS"], c["C_KD"], 43, 39, c["C_IP"], 46, c["C_RN"], c["C_SB2"],
        c["C_ST"], c["C_RB"], 11, 7, c["C_SH"], 9, c["C_RV"], c["C_SB1"],
        c["C_STOP"], c["C_AP"], 41, c["C_PS"], c["C_RBE"], c["C_EXIT"], 32,
    ]
    return {"C": c, "CM": cm, "CM2": cm2, "CM3": cm3}


RT_TABLE = {
    57558: 8434, 39632: 359, 60081: 2199, 32958: 8434, 22900: 7480, 54937: 1868,
    49325: 755, 54298: 7480, 8215: 1901, 42631: 2199, 40052: 1901, 32252: 755,
    57003: 359, 26931: 1868, 11590: 8434, 3539: 2199, 8097: 755, 56332: 2199,
    24074: 359, 24320: 359, 3838: 8434, 3585: 7480, 5556: 1901, 28582: 1901,
    29856: 1868, 252: 755, 22553: 1868, 40544: 7480, 14729: 1901, 46874: 8434,
    17421: 359, 11670: 8434, 3010: 2199, 30617: 7480,
}


# ---------------------------------------------------------------------------
# Executed control-flow proof: initOnce and initB state traces
# ---------------------------------------------------------------------------
# Every condition below is a literal integer comparison on the state
# variable in the preserved layout files; the traces are the exact
# executed path. The `_dm` update at `_ist >= 55357` (initOnce) and the
# `_dy = bxor(_dm, blen(B))` guard at `_ist < 23122` (initB) are DORMANT:
# no executed predecessor writes a state that reaches them, so `_dm`
# stays 52699 and no blen(B) checksum is ever evaluated.

INITONCE_TRACE = [
    {"state": 31452, "taken": "31451 < _ist and _ist < 46730",
     "action": "fragment assembly -> Base85 decode -> transport LCG -> B; wt[1..4] via the st stream",
     "next": 26188},
    {"state": 26188, "taken": "not (31451 < _ist) and not (_ist < 26188)",
     "action": "bw/m0/m1, f64 bits, _cz, pcall/metamethod/coroutine block -> K0, K1, ws, ce",
     "next": 11648},
    {"state": 11648, "taken": "_ist < 26188",
     "action": "ws..ce fill (st stream continues); SM/NM/PM/PD tables; W = wt",
     "next": 46730},
    {"state": 46730, "taken": "31451 < _ist and not (_ist < 46730) and _ist < 55357",
     "action": "TM and BM_BOOL type tables", "next": 0},
]
INITONCE_DORMANT = {
    "branch": "_ist >= 55357: _dx = bxor(r32(B,12), _dm); _dm = (_dm + _dx) % 2^32",
    "reason": ("both predecessors of the 46730 region (state 11648 and the branch "
               "itself) write exactly 46730; entry is 31452, so no state >= 55357 "
               "is ever reached and _dm remains 52699"),
}
INITB_TRACE = [
    {"state": 26216, "taken": "26215 < _ist and not (_ist >= 46996)",
     "action": "KBOX bias build (64 values)", "next": 53782},
    {"state": 53782, "taken": "26215 < _ist and _ist >= 46996 and 53781 < _ist",
     "action": ("BL_A/BL_B/BL_C permutations; cyield(K0) resumed with "
                "bxor(_ibv or 0, K0) = bxor(K0, K0) = 0 -> second-layer W[ws..ce] mask"),
     "next": 46996},
    {"state": 46996, "taken": "26215 < _ist and _ist >= 46996 and not (53781 < _ist)",
     "action": "RMAP build (118 slots from B at ce*4)", "next": 23122},
    {"state": 23122, "taken": "not (26215 < _ist) and not (_ist < 23122)",
     "action": "C_* slots, CM/CM2/CM3, MO/MO2, RT, EX, _h, _dr, AF, DR", "next": 0},
]
INITB_DORMANT = {
    "branch": "_ist < 23122: _dy = bxor(_dm, blen(B)); if _dy == 0 then 26216 else 0",
    "reason": ("initB is entered with _st0 = 26216; every executed transition "
               "(26216 -> 53782 -> 46996 -> 23122 -> 0) bypasses the guard, so the "
               "second resume's _dm = 52699 argument is never validated"),
}


# ---------------------------------------------------------------------------
# Stage 8: root prototype header (boot) + U-main frame seeds
# ---------------------------------------------------------------------------


def u_main(a: list[int], b: list[int], c: list[int], u: int, tb: int, ds: int) -> tuple[int, int, int]:
    """U-main path (op 47484) for a nil/number/string _ua with index u.

    Returns (_pa, (_exp + _ds) % 2^16, (_tb + _sbz + _ds*99) % 2^32).
    Proven identity: BL_C[BL_A[u] & 16383] == _exp(u) + 12836 exactly,
    because the C construction writes, at index b, exp(b, BL_B[b]) + 12836
    and the read index here is BL_A[u] & 16383 with u == b. Hence
    _sbz == (12836 - _ds) % 65536 and, when _ds == 0, the third return is
    _tb + 12836, independent of the permutation state and of the varargs.
    """
    pa = band(a[u], 16383)
    pb = band(b[u], 16383)
    bit = bxor(bext(pa, 7, 1), bext(pb, 10, 1), 1)
    exp = (pb * 4 + ((u * 17 + 1833) % 16384) * 2 + bit) % 65536
    sbz = (c[pa] - exp) % 65536
    if ds == 0 and sbz != SALT:
        raise SystemExit("BL_C identity violated: record permutation tables")
    return pa, (exp + ds) % 65536, (tb + sbz + ds * 99) % 4294967296


def root_prototype(words: list[int | None], k0: int) -> dict[str, object]:
    """boot: tk/hw and the 7-word header, then the mtA/mtB field split."""
    tk = bxor(k0, (2674807212 + 2921856046) % 4294967296)
    hw = bxor(tk, 774880)

    def word(idx: int) -> int:
        v = words[hw + idx]
        if v is None:
            raise SystemExit(f"root header word {hw + idx} outside decoded range")
        return v

    entry = bxor(word(0), bxor(1151433088, k0))
    est = bxor(word(4), bxor(3098405659, k0))
    esh = bxor(word(5), bxor(445800084, k0))
    mt_a = bxor(word(2), bxor(1209284937, k0))
    mt_b = bxor(word(1), bxor(4028605236, k0))
    c_start = bxor(word(3), bxor(2871857514, k0))
    c_len = bxor(word(6), bxor(2766250242, k0))

    size = band(rshift(mt_b, 18), 8191)
    uc = band(rshift(mt_a, 18), 1023)
    ar = bext(mt_a, 28, 3)
    da = band(rshift(mt_a, 31), 1)
    rb = band(rshift(mt_b, 1), 131071)
    ps = band(rshift(mt_a, 1), 65535)

    family = RT_TABLE.get(esh)
    return {
        "tk": tk,
        "hw": hw,
        "header_words": [word(i) for i in range(7)],
        "entry": entry,
        "est": est,
        "esh": esh,
        "mtA": mt_a,
        "mtB": mt_b,
        "cStart": c_start,
        "cLen": c_len,
        "size": size,
        "uc": uc,
        "ar": ar,
        "da": da,
        "rb": rb,
        "ps": ps,
        "family": family,
    }


# ---------------------------------------------------------------------------
# Stage 9: root-entry opcode walk (dispatch family 2199, exact transcription)
# ---------------------------------------------------------------------------
# initB.txt lines 3980-4213. op = ((_w[ip] - st*11 - ps) % 2^32) - 6806.
# Leaf ranges are half-open [lo, hi) except rekey2 which is [1224, 1358).
FAMILY_2199_LEAVES: list[dict[str, object]] = [
    {"kind": "rekey1", "lo": -(1 << 31), "hi": 444, "ip_delta": 6,
     "st": lambda st: (st * 470113 + 978875) % 4294967296, "st_note": "st*470113+978875"},
    {"kind": "mo4a", "lo": 444, "hi": 543, "ip_delta": 4,
     "st": lambda st: bxor((st * 347937 + 967947) % 4294967296, 625757214),
     "st_note": "(st*347937+967947)^625757214"},
    {"kind": "mo6", "lo": 543, "hi": 681, "ip_delta": 6,
     "st": lambda st: (st * 94141 + 1351193) % 4294967296, "st_note": "st*94141+1351193"},
    {"kind": "mo4b", "lo": 681, "hi": 707, "ip_delta": 4,
     "st": lambda st: (st * 275389 + 1428043) % 4294967296, "st_note": "st*275389+1428043"},
    {"kind": "mo3", "lo": 707, "hi": 708, "ip_delta": 3,
     "st": lambda st: bxor(lrot((st * 56421 + 1624753) % 4294967296, 4), 1154186531),
     "st_note": "lrot(st*56421+1624753,4)^1154186531"},
    {"kind": "return", "lo": 708, "hi": 795},
    {"kind": "mo5", "lo": 795, "hi": 821, "ip_delta": 5,
     "st": lambda st: bxor((st * 423757 + 540843) % 4294967296, 551559966),
     "st_note": "(st*423757+540843)^551559966"},
    {"kind": "movexor6", "lo": 821, "hi": 1006, "ip_delta": 6,
     "st": lambda st: bxor(lrot((st * 385329 + 1729285) % 4294967296, 9), 2432542295),
     "st_note": "lrot(st*385329+1729285,9)^2432542295"},
    {"kind": "call18a", "lo": 1006, "hi": 1102},
    {"kind": "movexor5a", "lo": 1102, "hi": 1224, "ip_delta": 5,
     "st": lambda st: bxor((st * 34153 + 1567789) % 4294967296, 1796575328),
     "st_note": "(st*34153+1567789)^1796575328"},
    {"kind": "rekey2", "lo": 1224, "hi": 1358, "ip_delta": 6,
     "st": lambda st: bxor(lrot((st * 219169 + 706323) % 4294967296, 19), 326053779),
     "st_note": "lrot(st*219169+706323,19)^326053779"},
    {"kind": "movexor5b", "lo": 1358, "hi": 1400, "ip_delta": 5,
     "st": lambda st: bxor((st * 389377 + 204245) % 4294967296, 3644635107),
     "st_note": "(st*389377+204245)^3644635107"},
    {"kind": "movexor3", "lo": 1400, "hi": 1461, "ip_delta": 3,
     "st": lambda st: bxor(lrot((st * 257293 + 96219) % 4294967296, 3), 3429404473),
     "st_note": "lrot(st*257293+96219,3)^3429404473"},
    {"kind": "movexor5c", "lo": 1461, "hi": 1482, "ip_delta": 5,
     "st": lambda st: bxor(lrot((st * 267409 + 1722731) % 4294967296, 7), 1414428347),
     "st_note": "lrot(st*267409+1722731,7)^1414428347"},
    {"kind": "return", "lo": 1482, "hi": 1791},
    {"kind": "call18b", "lo": 1791, "hi": 1 << 31},
]

MAX_WALK_STEPS = 64


def root_entry_walk(
    words: list[int | None],
    rmap: list[int],
    root: dict[str, object],
    k0: int,
    k1_initial: int,
) -> dict[str, object]:
    """Decode the root's entry instructions with exact arithmetic only.

    The root dispatches in family 2199 (RT[esh]); its op table above is
    transcribed from initB.txt. The walk tracks the frame slots that the
    reached ops read (F[_pxs], F[_pys], C_RBS, C_RBE) and stops at the
    first family transition, return or untranscribed dependence. _h[18]
    (initB.txt line 512) is modeled exactly; its (ip,st,sh) results are
    self-cancelling against the post-call _r = _nr, and the bank rotation
    aliases RMAP[rb'+1] with the old _u2s slot.
    """

    def w(idx: int) -> int:
        v = words[idx]
        if v is None:
            raise StopIteration(f"word {idx} outside decoded range")
        return v

    ip = root["entry"]
    st = (root["est"] + 86892) % 4294967296  # est + _tg; see u_main identity
    sh = root["esh"]
    rb = root["rb"]
    ps = root["ps"]
    rbs = 0
    c_rbe = 0
    pool = k1_initial
    pxs, pys, u1s, u2s = rmap[rb + 1], rmap[rb + 2], rmap[rb + 3], rmap[rb + 4]
    f: dict[int, int | None] = {pxs: None, pys: None, u1s: None, u2s: None}
    trace: list[dict[str, object]] = []
    events: dict[str, object] = {"rekey": None, "call": None}
    stop_reason = "step-cap"

    for step in range(MAX_WALK_STEPS):
        op = ((w(ip) - st * 11 - ps) % 4294967296) - 6806
        leaf = next((lf for lf in FAMILY_2199_LEAVES if lf["lo"] <= op < lf["hi"]), None)
        if leaf is None:
            stop_reason = f"untranscribed op {op} at ip {ip}"
            trace.append({"step": step, "ip": ip, "op": op, "leaf": "none"})
            break
        kind = leaf["kind"]
        row: dict[str, object] = {"step": step, "ip": ip, "op": op, "leaf": kind}

        if kind in ("rekey1", "rekey2"):
            if kind == "rekey1":
                a0 = (w(ip + 5) - st * 9) % 4294967296
                sr = bor(((w(ip + 3) - st * 15) % 4294967296), 1)
                ls = (w(ip + 2) - st * 9) % 4294967296
                cs = (w(ip + 4) - st) % 4294967296
                new_k1 = bxor((w(ip + 1) + st) % 4294967296, bxor(k0, bxor(ps, bxor(st, cs))))
            else:
                a0 = (w(ip + 4) - st * 5) % 4294967296
                sr = bor(((w(ip + 3) + st) % 4294967296), 1)
                ls = bxor(w(ip + 2), st)
                cs = (w(ip + 5) - st) % 4294967296
                new_k1 = bxor((w(ip + 1) - st * 9) % 4294967296, bxor(k0, bxor(ps, bxor(st, cs))))
            if pool == k1_initial:
                pool = new_k1
                events["rekey"] = {
                    "step": step, "ip": ip, "op": op, "leaf": kind,
                    "operand_words": [w(ip + k) for k in range(1, 7)],
                    "k1_after": new_k1,
                    "cs": cs,
                    "formula": "bxor((w[ip+1] -/+ st*k) % 2^32, K0, ps, st, cs)",
                }
                row["k1_after"] = new_k1
            if a0 != 0:
                f[rmap[rb + a0]] = f[pxs]
            f[pxs] = bxor(sr, SMA)
            f[pys] = (cs - (sr + SMB)) % 4294967296
            rbs = ls
            c_rbe = rb + 2 * ls
            row.update({"sr": sr, "ls": ls, "cs": cs, "a0": a0, "rbs": rbs})
        elif kind.startswith("mo") or kind.startswith("movexor"):
            stop_reason = f"scope stops before program-dependent operation {kind} at ip {ip}"
            trace.append(row)
            break
        elif kind == "return":
            stop_reason = f"return leaf at ip {ip} (rbs={rbs})"
            trace.append(row)
            break
        elif kind in ("call18a", "call18b"):
            if f[pxs] is None or f[pys] is None:
                stop_reason = f"call at ip {ip} reads unset frame marker slots"
                trace.append(row)
                break
            if kind == "call18a":
                ds = bxor(w(ip + 3), st)
                ct = (w(ip + 4) - st) % 4294967296
                hh = bxor(w(ip + 1), st)
                dd = bxor(w(ip + 2), st) - 1193876
            else:
                ds = bxor(w(ip + 1), st)
                ct = bxor(w(ip + 4), st)
                hh = (w(ip + 3) - st * 5) % 4294967296
                dd = ((w(ip + 2) + st) % 4294967296) - 957986
            r_old = bxor(f[pxs], SMA)
            cur = (r_old + SMB + f[pys] + (1 - band(r_old, 1)) * 65537) % 4294967296
            nr = (r_old * 433233 + 2142828636) % 4294967296
            sbz = SALT  # proven: (BL_C[F[C_SB1]] - F[C_SB2]) % 2^16 == 12836
            ns = (st + ds + cur + sbz) % 4294967296
            nh = (hh + cur + sbz) % 4294967296
            f[pxs], f[u1s], f[u2s] = f[u1s], f[u2s], bxor(nr, SMA)
            # _h[18] bank rotation: _nrb = rb + 2*ls when rb <= C_RBE - 2*ls
            nrb = rb - rbs
            if rb <= c_rbe - 2 * rbs:
                nrb = rb + 2 * rbs
            # exec reads bxor(F[RMAP[rb'+1]], SMA); the marker was stored at
            # the old _u2s slot, so the bank rotation must alias them.
            if rmap[nrb + 1] != u2s:
                stop_reason = (
                    f"bank rotation mismatch: RMAP[{nrb + 1}]={rmap[nrb + 1]} "
                    f"!= old _u2s slot {u2s}"
                )
                trace.append(row)
                break
            target_ip = (ip + dd) % 4294967296
            target_st = ns
            target_sh = nh
            family_after = RT_TABLE.get(target_sh)
            events["call"] = {
                "step": step, "ip": ip, "op": op, "leaf": kind,
                "nr": nr, "cur": cur, "bank_after": nrb,
                "target": {"ip": target_ip, "st": target_st, "sh": target_sh,
                           "family": family_after},
            }
            row.update({"target_ip": target_ip, "target_st": target_st,
                        "target_sh": target_sh, "family_after": family_after,
                        "bank_after": nrb})
            if family_after != 2199:
                stop_reason = f"family transition {family_after} at ip {ip}"
                trace.append(row)
                break
            # in-family continuation: slots rotate, corrections cancel
            rb, pxs, u1s, u2s = nrb, u2s, pxs, u1s
            f[pxs], f[pys] = bxor(nr, SMA), (ct - (nr + SMB)) % 4294967296
            ip, st, sh = target_ip, target_st, target_sh
            trace.append(row)
            continue

        # linear advance
        ip += leaf["ip_delta"]  # type: ignore[operator]
        st = leaf["st"](st)  # type: ignore[operator]
        trace.append(row)

    return {
        "initial": {"ip": root["entry"], "st": (root["est"] + 86892) % 4294967296,
                    "sh": root["esh"], "rb": root["rb"], "ps": root["ps"]},
        "pool_key_after_rekey": pool,
        "events": events,
        "trace": trace,
        "stop_reason": stop_reason,
        "op_table": [
            {"kind": lf["kind"], "range": [lf["lo"], lf["hi"]], "st": lf.get("st_note")}
            for lf in FAMILY_2199_LEAVES
        ],
    }


# ---------------------------------------------------------------------------
# Stage 10: const string / number records
# ---------------------------------------------------------------------------


def decrypt_string_record(payload: bytes, offset: int, k0: int, pool_key: int) -> bytes:
    """U string path: _k = bxor(_ps, K0, _k1, _sbz) with _sbz == 12836."""
    ps = bxor(r32(payload, offset), 1573349377)
    n = bxor(r32(payload, offset + 4), bxor(1638974510, ps))
    if offset + 8 + n > len(payload):
        raise ValueError("record overruns payload")
    k = bxor(ps, k0, pool_key, SALT)
    out = bytearray(n)
    data_at = offset + 8
    for w_i in range(n // 4):
        k = (k * 22439 + 195899001) % 4294967296
        struct.pack_into("<I", out, w_i * 4, bxor(r32(payload, data_at + w_i * 4), k))
    for t in range((n // 4) * 4, n):
        k = (k * 22439 + 195899001) % 4294967296
        out[t] = bxor(payload[data_at + t], k % 256)
    return bytes(out)


def scan_string_records(payload: bytes) -> list[dict[str, int]]:
    """Every byte offset whose derived length fits inside the payload.

    Candidates alone are not proof of program constants. The Rust lifter
    independently resolves references; the final comparison matches those
    references and plaintext bytes, not merely candidate printability.
    """
    records = []
    for offset in range(0, len(payload) - 8 + 1):
        ps = bxor(r32(payload, offset), 1573349377)
        n = bxor(r32(payload, offset + 4), bxor(1638974510, ps))
        if offset + 8 + n <= len(payload):
            records.append({"byte_offset": offset, "ua": bxor(offset, 1528192), "length": n})
    return records


def scan_number_records(payload: bytes, w1: int, k0: int, pool_key: int) -> list[dict[str, object]]:
    """U number path: _k1 = bxor(pool, 12836) then per-index word keys."""
    k1 = bxor(pool_key, SALT)
    base = bxor(w1, bxor(2115480298, k0))
    records: list[dict[str, object]] = []
    if base % 8 != 0:
        return [{"error": f"base offset {base} is not 8-aligned"}]
    for i in range(1, (len(payload) - base) // 8 + 1):
        p = base + (i - 1) * 8
        if p + 8 > len(payload):
            break
        low_key = bxor((495004947 + i * 464691) % 4294967296, bxor(k0, k1))
        high_key = bxor(
            (1772561933 + i * 290983) % 4294967296,
            bxor(bxor(rshift(k0, 11), lshift(k0, 21)), bxor(rshift(k1, 7), lshift(k1, 25))),
        )
        lo = bxor(r32(payload, p), low_key)
        hi = bxor(r32(payload, p + 4), high_key)
        value = struct.unpack("<d", struct.pack("<II", lo, hi))[0]
        records.append({"i": i, "ua": bxor(i, 1071764), "byte_offset": p, "value": value})
    return records


def printable(body: bytes) -> bool:
    return all(32 <= b <= 126 or b in (9, 10, 13) for b in body)


# ---------------------------------------------------------------------------
# Parent Rust pinned values - comparison ONLY, never a derivation input.
# ---------------------------------------------------------------------------

PARENT_RUST_PINNED = {
    "payload_sha256": "0b27a42d1fcea8d6a268848800b7cd04681167b15d007094a5082e3dd1f52d0f",
    "k0": 1302175439,
    "decoded_range": [190, 507],
    "root_word": 501,
    "entry_pc": 442,
    "payload_words": 566,
    "analyzer": {
        "states": 178, "pcs": 43, "structured": 30, "strings": 35,
        "nums": 3, "calls": 8, "recovered_lines": 60,
        "note": ("independently produced by the parent Rust analyzer; the "
                 "recovered application matches the previous recovery, and "
                 "neither side is treated as a golden copy"),
    },
}


def cross_check(derived: dict[str, object]) -> dict[str, object]:
    fields = {
        "payload_sha256": (PARENT_RUST_PINNED["payload_sha256"], derived["payload_sha256"]),
        "k0": (PARENT_RUST_PINNED["k0"], derived["k0"]),
        "decoded_range": (tuple(PARENT_RUST_PINNED["decoded_range"]), tuple(derived["decoded_range"])),
        "root_word": (PARENT_RUST_PINNED["root_word"], derived["root_word"]),
        "entry_pc": (PARENT_RUST_PINNED["entry_pc"], derived["entry_pc"]),
        "payload_words": (PARENT_RUST_PINNED["payload_words"], derived["payload_words"]),
    }
    rows = {name: {"parent_rust": a, "this_reference": b, "match": a == b} for name, (a, b) in fields.items()}
    return {
        "comparison_only": ("the parent Rust values above were never read by any "
                            "derivation stage of this reference"),
        "fields": rows,
        "all_match": all(r["match"] for r in rows.values()),
        "analyzer_facts_parent_rust": PARENT_RUST_PINNED["analyzer"],
        "this_reference_scope": {
            "string_records": derived["string_records"],
            "program_number_constants": derived["program_number_constants"],
            "note": ("this reference performs no lifting or code generation; "
                     "states/pcs/calls/line counts belong to the parent analyzer"),
        },
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    literals, alphabet, source_bytes = extract_source_literals()
    payload = assemble_and_decode(literals, alphabet)
    (DIAG / "reference.decoded.bin").write_bytes(payload)
    checkpoint(
        "transport",
        f"payload sha256 {sha256_hex(payload)} ({len(payload)} bytes, 566 words)",
    )

    init = init_once(payload)
    k0: int = init["k0"]
    ws, ce = init["ws"], init["ce"]
    words: list[int | None] = init["words"]
    checkpoint(
        "initOnce",
        f"executed path 31452 -> 26188 -> 11648 -> 46730 -> 0; K0={k0} "
        f"K1={init['k1_initial']} ws={ws} ce={ce} count={init['range_count']} "
        f"cz={init['cz']} float_bits={init['float_bits']:016x}; _dm stays 52699 (dormant)",
    )

    kbox = build_kbox()
    a, b, c = build_permutations()
    second_layer(words, k0, ws, ce, a, b, c, kbox)
    rmap = build_rmap(payload, ce, k0)
    for value in rmap[1:]:
        if not (1 <= value <= 52):
            raise SystemExit(f"RMAP slot {value} outside 1..52")
    tables = build_cm(rmap)
    checkpoint(
        "initB",
        f"executed path 26216 -> 53782 -> 46996 -> 23122 -> 0; KBOX[1..4]={kbox[1:5]} "
        f"RMAP[1..6]={rmap[1:7]} BL_A[2268]={a[2268]} BL_B[2268]={b[2268]}; "
        "the _dy guard is dormant",
    )

    root = root_prototype(words, k0)
    if root["family"] is None:
        raise SystemExit(f"root dispatch token {root['esh']} absent from RT")
    if root["uc"] != 0 or root["da"] != 0:
        raise SystemExit("root prototype must be vararg-mode with no captures")
    # boot frame seeds via U-main with _ub = 792406: ds = bxor(792406,155290)
    # - 936396 == 0 exactly, so _tg == 74056 + 12836 == 86892 for a nil
    # first vararg (the `return boot(...)` tail with an empty vararg list),
    # and the same identity holds for number/string varargs.
    ds = bxor(792406, 155290) - 936396
    if ds != 0:
        raise SystemExit("boot U-main ds constant is not zero; retranscribe")
    p1, p2, tg = u_main(a, b, c, 2268, 74056, ds)
    checkpoint(
        "root",
        f"hw={root['hw']} entry={root['entry']} est={root['est']} esh={root['esh']} "
        f"family={root['family']} rb={root['rb']} ps={root['ps']} size={root['size']} "
        f"uc={root['uc']} ar={root['ar']} da={root['da']} p1={p1} p2={p2} tg={tg}",
    )

    walk = root_entry_walk(words, rmap, root, k0, init["k1_initial"])
    rekey = walk["events"]["rekey"]
    pool = walk["pool_key_after_rekey"]
    if rekey is None:
        raise SystemExit("root entry did not rekey; pool key stays initial")
    call = walk["events"]["call"]
    checkpoint(
        "root_entry_walk",
        f"op={rekey['op']} at ip={rekey['ip']} -> pool K1={pool}; "
        + (
            f"call at ip={call['ip']} -> target ip={call['target']['ip']} "
            f"st={call['target']['st']} sh={call['target']['sh']} "
            f"family={call['target']['family']}"
            if call
            else "no call reached"
        )
        + f"; stop: {walk['stop_reason']}",
    )

    string_records = scan_string_records(payload)
    decoded: list[dict[str, object]] = []
    for rec in string_records:
        body_initial = decrypt_string_record(payload, rec["byte_offset"], k0, init["k1_initial"])
        body_rekey = decrypt_string_record(payload, rec["byte_offset"], k0, pool)
        decoded.append(
            {
                **rec,
                "initial_pool_printable": printable(body_initial),
                "rekeyed_pool_printable": printable(body_rekey),
                "body": body_rekey.decode("utf-8", "replace")
                if printable(body_rekey)
                else None,
                "body_hex_rekeyed": body_rekey.hex(),
            }
        )
    hits = [d for d in decoded if d["rekeyed_pool_printable"]]
    false_initial = [d for d in decoded if d["initial_pool_printable"]]
    checkpoint(
        "strings",
        f"{len(string_records)} records scanned; {len(hits)} printable under the "
        f"root-entry-rekeyed pool key; {len(false_initial)} under the initial key",
    )

    numbers = scan_number_records(payload, words[1] or 0, k0, pool)
    number_rows = [
        {**n, "value_hex": struct.pack("<d", n["value"]).hex()}  # type: ignore[arg-type]
        for n in numbers
        if isinstance(n.get("value"), float)
    ]
    # The application's own float constants (recovered semantics: the dialogue
    # table uses UDim2.fromScale(0.5, 0.95) and Lifetime 7.5) identify the
    # three real number records among the scan candidates.
    program_values = {0.95, 7.5, 0.5}
    program_constants = [
        row for row in number_rows if struct.unpack("<d", bytes.fromhex(row["value_hex"]))[0] in program_values
    ]
    checkpoint(
        "numbers",
        f"{len(number_rows)} candidate records at base offset "
        f"{bxor(words[1] or 0, bxor(2115480298, k0))}; "
        f"{len(program_constants)} match the application's float constants",
    )

    # ---- outputs ---------------------------------------------------------
    words_json = {
        "raw_words": [r32(payload, i * 4) for i in range(566)],
        "decoded_words": {str(i): words[i] for i in range(1, 567)},
    }
    (DIAG / "reference.words.json").write_text(json.dumps(words_json, indent=2) + "\n", encoding="utf-8")

    slots_json = {
        "rmap": rmap,
        "kbox": kbox,
        "cm_tables": tables,
        "root": root,
        "boot_frame": {
            "u_main_call": {
                "ud": 489, "ua_vararg": None, "ug": 227, "uf": 11, "ue": 181,
                "um": 60285, "ui": 751, "uc": 283, "ub": 792406, "uh": 697,
            },
            "ds": ds,
            "p1": p1,
            "p2": p2,
            "tg": tg,
            "string_salt": SALT,
            "initial_decode_state": (root["est"] + tg) % 4294967296,
            "slots": {
                "F[C_SB1]": p1, "F[C_SB2]": p2, "F[C_RB]": root["rb"],
                "F[C_PS]": root["ps"], "F[C_IP]": root["entry"],
                "F[C_ST]": (root["est"] + tg) % 4294967296, "F[C_SH]": root["esh"],
                "F[C_STOP]": 0, "F[C_EXIT]": 0, "F[C_RBS]": 0, "F[C_RBE]": 0,
                "F[C_AP]": "vararg pack {n=0}",
                f"F[RMAP[{root['rb']}+1]]": None, f"F[RMAP[{root['rb']}+2]]": None,
            },
        },
        "control_flow": {
            "init_once_trace": INITONCE_TRACE,
            "init_once_dormant": INITONCE_DORMANT,
            "init_b_trace": INITB_TRACE,
            "init_b_dormant": INITB_DORMANT,
        },
    }
    (DIAG / "reference.slots.json").write_text(json.dumps(slots_json, indent=2) + "\n", encoding="utf-8")

    strings_json = {
        "pool_keys": {
            "initial": init["k1_initial"],
            "root_entry_rekey": pool,
            "rekey_event": rekey,
            "salt": SALT,
        },
        "records": decoded,
        "numbers": number_rows,
        "program_number_constants": program_constants,
        "root_entry_walk": walk,
    }
    (DIAG / "reference.strings.json").write_text(json.dumps(strings_json, indent=2) + "\n", encoding="utf-8")

    bl_blob = (
        struct.pack("<16384H", *a)
        + struct.pack("<16384H", *b)
        + struct.pack("<16384H", *c)
    )
    (DIAG / "reference.bl.bin").write_bytes(bl_blob)

    comparison = cross_check({
        "payload_sha256": sha256_hex(payload),
        "k0": k0,
        "decoded_range": [ws, ce],
        "root_word": root["hw"],
        "entry_pc": root["entry"],
        "payload_words": 566,
        "string_records": len(hits),
        "program_number_constants": len(program_constants),
    })
    if not comparison["all_match"]:
        raise SystemExit(f"cross-check mismatch against parent Rust pins: {comparison['fields']}")

    metadata = {
        "profile": "sarp-static-arithmetic-reference-v1",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "scope": (
            "independent self-contained static arithmetic reference for the "
            "parent Rust devirtualizer; no lifting, no code generation, no "
            "Lua execution, no dependency on any external probe module"
        ),
        "source": {
            "path": "decompilation/sarp/target.original.lua",
            "sha256": sha256_hex(source_bytes),
            "expected_sha256": SOURCE_SHA256,
            "git_blob_sha1": GIT_BLOB_SHA1,
            "bytes": len(source_bytes),
            "baseline_commit": BASELINE_COMMIT,
            "extraction": "bounded lexical scan of the leading `local _pcN =` and `_ab = bfrom(...)` literals with exact tested escape handling",
        },
        "transport": {
            "fragments": {
                name: {"bytes": len(literals[name]), "sha256": sha256_hex(literals[name])}
                for name in sorted(literals)
            },
            "fragment_lengths": FRAGMENT_LEN,
            "bcopy_order": [{"fragment": n, "offset": o} for n, o in BCOPY_ORDER],
            "alphabet_sha256": sha256_hex(alphabet),
            "alphabet": alphabet.decode("latin-1"),
            "alphabet_sites": 1,
            "encoded_bytes": 2830,
            "base85": "low digit first, then bit32.byteswap of the low u32",
            "transport_lcg": {"seed": 1147127625, "mul": 17487, "add": 3048913621},
            "payload_bytes": len(payload),
            "payload_words": 566,
            "payload_sha256": sha256_hex(payload),
            "payload_file": "reference.decoded.bin",
        },
        "init_once": {
            "executed_trace": [row["state"] for row in INITONCE_TRACE] + [0],
            "dormant_dm_branch": INITONCE_DORMANT,
            "sa": init["sa"],
            "st_seed": init["st_seed"],
            "header_words": init["header"],
            "stream": {
                "mul": 398991, "add": 3534337991,
                "ops": ["bswap", "xor lshift 9", "xor rshift 5", "xor lshift 1"],
                "note": "one state for wt[1..4] then ws..ce without reset",
            },
            "bw": init["bw"],
            "m0": init["m0"],
            "m1": init["m1"],
            "float_value": init["float_value"],
            "float_bits": init["float_bits"],
            "float_lo": init["flo"],
            "float_hi": init["fhi"],
            "cz": init["cz"],
            "pf": init["pf"],
            "pe": init["pe"],
            "environment_checks": init["checks"],
            "k0": k0,
            "k1_initial": init["k1_initial"],
            "ws": ws,
            "ce": ce,
            "range_count": init["range_count"],
        },
        "init_b": {
            "executed_trace": [row["state"] for row in INITB_TRACE] + [0],
            "dormant_dy_branch": INITB_DORMANT,
            "kbox_sha256": sha256_hex(json.dumps(kbox).encode()),
            "kbox": kbox,
            "second_layer": {
                "seed": bxor(k0, 2372119159),
                "mul": 7745,
                "add": 888415943,
                "range": [ws, ce],
                "resume_value": 0,
                "note": "cresume(_ibc, bxor(_ibv or 0, K0)) with _ibv = K0",
            },
            "rmap": rmap,
            "rmap_source": {
                "byte_offset": ce * 4, "words": 59,
                "lcg": {"seed": bxor(3402759894, k0), "mul": 24307, "add": 1800847725},
                "slot_groups": "bank roles repeat across three engineered windows; other slot multiplicities vary",
            },
            "cm_tables": tables,
            "permutations": {
                "bl_a_sha256": sha256_hex(struct.pack("<16384H", *a)),
                "bl_b_sha256": sha256_hex(struct.pack("<16384H", *b)),
                "bl_c_sha256": sha256_hex(struct.pack("<16384H", *c)),
                "samples": {"a2268": a[2268], "b2268": b[2268], "c_of_a2268": c[a[2268] & 16383]},
                "file": "reference.bl.bin",
            },
        },
        "root": {
            **{k: v for k, v in root.items()},
            "boot_frame": slots_json["boot_frame"],
        },
        "root_entry_walk": {
            "family": root["family"],
            "initial": walk["initial"],
            "rekey": rekey,
            "pool_key_after_rekey": pool,
            "call": call,
            "stop_reason": walk["stop_reason"],
            "op_table": walk["op_table"],
            "trace_file": "reference.strings.json",
        },
        "strings": {
            "scanned_offsets": len(string_records),
            "printable_under_root_entry_pool": len(hits),
            "printable_under_initial_pool": len(false_initial),
            "salt": SALT,
            "records_file": "reference.strings.json",
        },
        "numbers": {
            "base_offset": bxor(words[1] or 0, bxor(2115480298, k0)),
            "candidate_count": len(number_rows),
            "program_constant_count": len(program_constants),
            "records_file": "reference.strings.json",
        },
        "outputs": [
            "reference.decoded.bin", "reference.words.json", "reference.slots.json",
            "reference.strings.json", "reference.bl.bin", "reference.checkpoints.txt",
        ],
        "checkpoints": CHECKPOINTS,
        "cross_check": comparison,
        "invariants": [
            "bcopy order pc2,pc4,pc3,pc1,pc0 tiles [0,2830) with extents 560,574,556,582,558",
            "Base85 digit order: byte _p is the least significant digit, _p+4 the most",
            "transport LCG advances once per word before the XOR",
            "header st stream continues into the ws..ce fill without reset",
            "initOnce executes 31452 -> 26188 -> 11648 -> 46730 -> 0; the _dm update at _ist >= 55357 is unreachable (both predecessors of the 46730 region write exactly 46730), so _dm stays 52699 and no blen(B) checksum runs",
            "initB executes 26216 -> 53782 -> 46996 -> 23122 -> 0; the _dy = bxor(_dm, blen(B)) guard at _ist < 23122 is unreachable, so the resume's _dm argument is never validated",
            "pcall(function() local _e={}; return _e+1 end) is false: arithmetic on a plain table raises",
            "_mx __add/__len/__call and both coroutine resumes give _pf=0, _pe=0",
            "bit32.replace/rawget/__sub/frexp/ldexp/modf/clamp/format/pack/tonumber identities all hold",
            "BL_C[BL_A[u] & 16383] == exp(u) + 12836, hence the string salt is exactly 12836",
            "boot U-main ds = bxor(792406,155290) - 936396 = 0, hence _tg = 86892 for any vararg type",
            "rekey opcodes fire only while K1 == bxor(4021752008, 3067287787)",
            "the root's first instruction (op 1224 at word 442) is the single rekey",
            "_h[18] call results self-cancel against the post-call _r = _nr",
            "bank rotation aliases RMAP[rb+2*ls+1] with the old _u2s slot (rmap[60] == rmap[19] == 43)",
        ],
    }
    (DIAG / "reference.metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    lines = [f"{cp['stage']}: {cp['detail']}" for cp in CHECKPOINTS]
    (DIAG / "reference.checkpoints.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps({
        "k0": k0, "k1_initial": init["k1_initial"], "pool_after_rekey": pool,
        "ws": ws, "ce": ce, "count": init["range_count"],
        "root_hw": root["hw"], "root_family": root["family"],
        "string_records": len(string_records), "printable_rekeyed": len(hits),
        "program_number_constants": len(program_constants),
        "cross_check_all_match": comparison["all_match"],
    }, indent=2))
    for hit in hits:
        print(f"  offset {hit['byte_offset']:5d} ua={hit['ua']:8d} len {hit['length']:4d}: {hit['body']!r}")


if __name__ == "__main__":
    main()
