"""Independent large-SARP initialization audit (static, numeric only).

Re-derives the transport buffer, W table, register map, biases, header,
permutations and root descriptor from the inert source text, then compares
them position-by-position with the Rust artifacts:

  * diagnostics/initialization-reference.json   (reference derived pre-Rust)
  * target.metadata.txt                         (Rust output)
  * target.transport.bin / permutation-*.bin    (Rust output)
  * diagnostics/reference.*                     (reference binaries)

No Lua/Luau, VM, coroutine, executor or recovered function is invoked.  The
only evaluation is bounded integer/struct arithmetic transcribed from
initOnce.txt, initB.txt, initC.txt, boot.txt and make.txt.

Exact equality of the 7022 populated W words is initialization fidelity.  It
is NOT devirtualization: 135022 positions are legitimately absent and the
program instructions themselves are not certified by this audit.
"""
from __future__ import annotations

import hashlib
import json
import re
import struct
from pathlib import Path

from probe import tokens, unquote

ROOT = Path(__file__).resolve().parent.parent
DIAG = ROOT / "diagnostics"
MOD = 2**32
MASK = MOD - 1
SALT = 43122
SOURCE_SHA256 = "1496f231da48222f5aa52d84829e9ad4ef5481eb237f56c6be1b9645dd7136fe"
TRANSPORT_SHA256 = "b56b453499598f203dc50ffc04d515dd907fd30ec79f23610cc740c17832f69a"
LENGTHS = (177562, 177551, 177559, 177548)
OFFSETS = (0, 177562, 355113, 532672)
ALPHABET = b"XzO+#ig=Jk[1qYc:@K)yuaH;~jew6srV7b<n3ptMBdUF$NECQ]foZ,^mT4.!>&52(G09D_hPRW%lI8?SLAxv|"
RAW_WORDS = 142044
WORD_SLOTS = RAW_WORDS + 1


def rotl(value: int, amount: int) -> int:
    return ((value << amount) | (value >> (32 - amount))) & MASK


def byteswap(value: int) -> int:
    return int.from_bytes(value.to_bytes(4, "little"), "big")


def clz(value: int) -> int:
    """bit32.countlz on a 32-bit word."""
    return 32 - (value & MASK).bit_length()


def crz(value: int) -> int:
    """bit32.countrz on a 32-bit word; 0 => 32."""
    value &= MASK
    if value == 0:
        return 32
    return (value & -value).bit_length() - 1


def stream(state: int) -> int:
    state = rotl((state * 411395 + 479499883) % MOD, 11)
    state ^= (state << 9) & MASK
    state ^= state >> 5
    state ^= (state << 1) & MASK
    return state & MASK


# ---------------------------------------------------------------- transport
def source_fragments() -> list[bytes]:
    raw = (ROOT / "target.original.lua").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SOURCE_SHA256
    ts = tokens(raw.decode())
    fragments = []
    for number, size in enumerate(LENGTHS):
        name = "_pc" + str(number)
        at = [
            i + 3
            for i in range(len(ts) - 3)
            if [t.text for t in ts[i : i + 3]] == ["local", name, "="]
        ]
        assert len(at) == 1, name
        fragment = unquote(ts[at[0]].text)
        assert len(fragment) == size, (name, len(fragment))
        fragments.append(fragment)
    at = [
        i + 4
        for i in range(len(ts) - 4)
        if [t.text for t in ts[i : i + 4]] == ["_ab", "=", "bfrom", "("]
    ]
    assert len(at) == 1
    assert unquote(ts[at[0]].text) == ALPHABET
    return fragments


def decode_transport(fragments: list[bytes]) -> bytes:
    encoded = bytearray(710220)
    covered = bytearray(710220)
    # Certified copy order from initOnce: _pc2, _pc1, _pc3, _pc0.
    for number in (2, 1, 3, 0):
        start, length = OFFSETS[number], LENGTHS[number]
        assert not any(covered[start : start + length])
        encoded[start : start + length] = fragments[number]
        covered[start : start + length] = b"\x01" * length
    assert all(covered)

    digits = {byte: index for index, byte in enumerate(ALPHABET)}
    assert len(digits) == 85
    weights = (1, 85, 85 * 85, 85**3, 85**4)
    state = 577177045
    words = []
    for at in range(0, len(encoded), 5):
        value = 0
        for position in range(5):
            value += digits[encoded[at + position]] * weights[position]
        value %= MOD
        state = (state * 15577 + 3425539465) % MOD
        words.append(byteswap(value) ^ state)
    return b"".join(struct.pack("<I", word) for word in words)


# ------------------------------------------------------------ permutations
def permutations():
    a = list(range(16384))
    b = list(range(16384))
    c = [0] * 16384
    ka, kb = 1074033615, 2285263105
    for index in range(16383, 0, -1):
        ka = (ka * 29983 + 3162639897) % MOD
        kb = (kb * 29983 + 3162639897) % MOD
        ja, jb = ka % (index + 1), kb % (index + 1)
        a[index], a[ja] = a[ja], a[index]
        b[index], b[jb] = b[jb], b[index]
    for b_index in range(16384):
        pa, pb = a[b_index], b[b_index]
        parity = ((pa >> 7) & 1) ^ ((pb >> 2) & 1) ^ 1
        c[pa] = (pb * 4 + ((b_index * 17 + 13025) % 16384) * 2 + parity + SALT) % 65536
    for index in range(16384):
        ka = (ka * 29983 + 3162639897) % MOD
        kb = (kb * 29983 + 3162639897) % MOD
        a[index] |= ((ka >> 20) & 3) << 14
        b[index] |= ((kb >> 20) & 3) << 14
    return a, b, c


# ---------------------------------------------------------- initializer
def initialize(payload: bytes, argument: int = 110391195):
    raw = struct.unpack("<" + "I" * (len(payload) // 4), payload)
    assert len(raw) == RAW_WORDS
    words: list[int | None] = [None] * WORD_SLOTS

    state = argument ^ 192128608
    for index in range(1, 5):
        state = stream(state)
        words[index] = raw[index - 1] ^ state
    header = [words[1], words[2], words[3], words[4]]

    bw = raw[2]
    m0 = argument ^ bw
    m1 = (m0 * 29955 + 504689345) % MOD
    bits = struct.pack("<d", float(m1) + float(words[3]) + 1048576.0)
    lo, hi = struct.unpack("<II", bits)
    zero_counts = clz(m0) * 65537 + crz(bw) * 257 + clz(words[3])
    master = (
        ((m1 + lo) % MOD)
        ^ rotl(words[3], 11)
        ^ hi
        ^ byteswap(m0)
        ^ zero_counts
    ) & MASK
    low = (words[2] ^ 2659961469 ^ master) & MASK
    high = (words[4] ^ 4067770469 ^ master) & MASK
    assert 4 < low <= high < RAW_WORDS

    for index in range(low, high + 1):
        state = stream(state)
        words[index] = raw[index - 1] ^ state

    biases = [0]
    key = 299753647
    for _ in range(64):
        key = (key * 13003 + 3750079167) % MOD
        biases.append(1 + key % 200000)

    a, b, c = permutations()
    key = master ^ 1836873615
    for index in range(low, high + 1):
        key = (key * 32625 + 2288117495) % MOD
        assert words[index] is not None
        words[index] ^= (
            a[key & 16383]
            ^ (b[(key >> 14) & 16383] << 16)
            ^ biases[1 + index % 64]
            ^ c[(key ^ index) & 16383]
        )

    slots = [0]
    key = 3662345728 ^ master
    for index in range(867):
        key = (key * 16973 + 1663117091) % MOD
        value = raw[high + index] ^ key
        slots.extend((value & 65535, value >> 16))

    root_word = master ^ ((595533583 + 2755699720) % MOD) ^ 266632
    descriptor = {
        "word": root_word,
        "key": words[root_word] ^ 2305819396 ^ master,
        "code_length": words[root_word + 1] ^ 322097349 ^ master,
        "entry": words[root_word + 2] ^ 3146221740 ^ master,
        "packed_a": words[root_word + 3] ^ 1312544370 ^ master,
        "packed_b": words[root_word + 4] ^ 3129404073 ^ master,
        "token": words[root_word + 5] ^ 3545062758 ^ master,
        "code_start": words[root_word + 6] ^ 3330028092 ^ master,
    }
    aa, bb = descriptor["packed_a"], descriptor["packed_b"]
    descriptor.update(
        {
            "fixed": aa & 1,
            "bank": (aa >> 1) & 131071,
            "arity": (aa >> 29) & 7,
            "captures": (aa >> 19) & 1023,
            "frame": (bb >> 18) & 8191,
            "salt": bb & 65535,
        }
    )
    return {
        "words": words,
        "header": header,
        "master": master,
        "float_bits": int.from_bytes(bits, "little"),
        "zero_counts": zero_counts,
        "range": [low, high],
        "slots": slots,
        "biases": biases,
        "a": a,
        "b": b,
        "c": c,
        "root": descriptor,
        "initial_pool_key": 1030971814 ^ 355957541,
    }


# ------------------------------------------------------------- comparison
def permutation_digest(values) -> str:
    return hashlib.sha256(b"".join(struct.pack("<H", v) for v in values)).hexdigest()


def parse_metadata(path: Path):
    text = path.read_text(encoding="utf-8")
    out = {}
    for name in ("Profile", "Source", "Argument", "K0", "Header", "Float", "Zero counts", "Range", "Slots", "Biases"):
        match = re.search(rf"^{re.escape(name)}: (.*)$", text, re.MULTILINE)
        assert match, name
        out[name] = match.group(1)
    words = {}
    for match in re.finditer(r"^W\[(\d+)\] = (None|Some\((\d+)\))$", text, re.MULTILINE):
        index = int(match.group(1))
        words[index] = None if match.group(2) == "None" else int(match.group(3))
    out["words"] = words
    proto = text.find("Prototypes: [")
    end = text.find("W[0] =", proto)
    assert proto >= 0 and end > proto
    block = text[proto:end]
    fields = {}
    for field in ("word", "byte_offset", "encoded_reference", "entry_pc", "initial_decode_state",
                  "dispatch_token", "frame_capacity", "bank_base", "prototype_salt"):
        match = re.search(rf"{field}: (\d+)", block)
        assert match, field
        fields[field] = int(match.group(1))
    fields["fixed_parameter_mode"] = bool(re.search(r"fixed_parameter_mode: true", block))
    fields["fixed_parameter_count"] = None
    count = re.search(r"fixed_parameter_count: Some\((\d+)\)", block)
    if count:
        fields["fixed_parameter_count"] = int(count.group(1))
    fields["parameter_operands"] = []
    fields["captures"] = []
    out["prototype"] = fields
    return out


def collect_mismatches(mine: dict, reference: dict, metadata: dict) -> dict:
    report: dict = {"checks": {}, "mismatches": [], "notes": []}

    def check(name: str, ok: bool, detail: str = "") -> None:
        report["checks"][name] = ok
        if not ok:
            report["mismatches"].append({"check": name, "detail": detail})

    # 1. transport and source
    rust_transport = (ROOT / "target.transport.bin").read_bytes()
    ref_transport = (DIAG / "reference.transport.bin").read_bytes()
    check("transport_sha256", hashlib.sha256(rust_transport).hexdigest() == TRANSPORT_SHA256,
          hashlib.sha256(rust_transport).hexdigest())
    check("transport_bytes_equal_reference", rust_transport == ref_transport)
    check("transport_sha_matches_reference_json",
          hashlib.sha256(ref_transport).hexdigest() ==
          json.loads((DIAG / "transport-reference.json").read_text())["transport_sha256"])
    check("transport_words", len(rust_transport) // 4 == RAW_WORDS)
    check("source_sha256_pinned", metadata["Source"].strip('Some("').rstrip('")') == SOURCE_SHA256)

    # 2. argument/header/float/zero/range/master/slots/biases
    check("argument", mine["header"] is not None and int(metadata["Argument"]) == 110391195)
    header = [int(x) for x in metadata["Header"].strip("[]").split(",")]
    check("header", header == mine["header"] and header == reference["header"],
          f"rust={header} mine={mine['header']} ref={reference['header']}")
    check("master_key", int(metadata["K0"]) == mine["master"] == reference["master_key"],
          f"rust={metadata['K0']} mine={mine['master']} ref={reference['master_key']}")
    check("float_bits", int(metadata["Float"], 16) == mine["float_bits"] == reference["float_bits"],
          f"rust={metadata['Float']} mine={mine['float_bits']:016x} ref={reference['float_bits']}")
    check("zero_counts", int(metadata["Zero counts"]) == mine["zero_counts"] == reference["zero_counts"])
    rust_range = tuple(int(x) for x in metadata["Range"].strip("()").split(","))
    check("range", list(rust_range) == mine["range"] == reference["range"],
          f"rust={rust_range} mine={mine['range']} ref={reference['range']}")
    rust_slots = json.loads(metadata["Slots"])
    check("slots", rust_slots == mine["slots"] == reference["slots"],
          f"lens rust={len(rust_slots)} mine={len(mine['slots'])} ref={len(reference['slots'])}")
    check("slot_count", len(rust_slots) - 1 == reference["slot_count"] == 1734)
    check("distinct_slots", len(set(rust_slots[1:])) == reference["distinct_slots"] == 71)
    check("max_slot", max(rust_slots) == reference["max_slot"] == 71)
    rust_biases = json.loads(metadata["Biases"])
    check("biases", rust_biases == mine["biases"] == reference["biases"])
    check("bias_count", len(rust_biases) == 65)

    # 3. permutation binaries and digests
    for name, values in (("A", mine["a"]), ("B", mine["b"]), ("C", mine["c"])):
        rust_bytes = (ROOT / f"permutation-{name}.bin").read_bytes()
        ref_bytes = (DIAG / f"reference.permutation-{name}.bin").read_bytes()
        mine_bytes = b"".join(struct.pack("<H", v) for v in values)
        check(f"permutation_{name}_bytes",
              rust_bytes == ref_bytes == mine_bytes,
              f"rust={len(rust_bytes)} ref={len(ref_bytes)} mine={len(mine_bytes)}")
        check(f"permutation_{name}_sha", permutation_digest(values) == reference["permutation_hashes"][ord(name) - 65])
    check("permutation_injective", len(set(mine["a"])) == 16384 and len(set(mine["b"])) == 16384)

    # 4. every W position, including absent
    rust_words = metadata["words"]
    check("w_length", len(rust_words) == WORD_SLOTS == len(mine["words"]) == len(reference["words"]),
          f"rust={len(rust_words)} mine={len(mine['words'])} ref={len(reference['words'])}")
    missing_rust = sorted(set(range(WORD_SLOTS)) - set(rust_words))
    check("w_indices_complete", not missing_rust, f"missing {len(missing_rust)}")
    word_mismatch = []
    absent_mismatch = []
    for index in range(WORD_SLOTS):
        rust_value = rust_words.get(index, "missing")
        mine_value = mine["words"][index]
        ref_value = reference["words"][index]
        if rust_value != mine_value:
            word_mismatch.append({"index": index, "rust": rust_value, "mine": mine_value, "ref": ref_value})
        if ref_value != mine_value:
            word_mismatch.append({"index": index, "reference": ref_value, "mine": mine_value})
        if rust_value is None or mine_value is None:
            if rust_value is not None or mine_value is not None:
                absent_mismatch.append({"index": index, "rust": rust_value, "mine": mine_value})
    check("w_all_positions", not word_mismatch, f"{len(word_mismatch)} mismatches, first={word_mismatch[:3]}")
    check("w_absence_agrees", not absent_mismatch, f"{len(absent_mismatch)} absent/present disagreements")
    populated = sum(value is not None for value in mine["words"])
    check("w_populated", populated == reference["populated_words"] == 7022)
    check("w_range_populated",
          all(mine["words"][i] is not None for i in range(mine["range"][0], mine["range"][1] + 1)))
    check("w_outside_heads_absent",
          all(mine["words"][i] is None for i in list(range(0, 1)) + list(range(5, mine["range"][0]))))
    report["notes"].append(
        f"{populated} populated words of {WORD_SLOTS} positions "
        f"({WORD_SLOTS - populated} absent, {mine['range'][0]}..{mine['range'][1]} populated range)"
    )

    # 5. root descriptor vs metadata prototype
    proto = metadata["prototype"]
    root = mine["root"]
    check("prototype_word", proto["word"] == root["word"] == 134628)
    check("prototype_byte_offset", proto["byte_offset"] == (root["word"] - 1) * 4 == 538508)
    check("prototype_encoded_reference", proto["encoded_reference"] == (root["word"] ^ 266632) == 400492)
    check("prototype_entry_pc", proto["entry_pc"] == root["entry"] == 138920)
    check("prototype_initial_decode_state", proto["initial_decode_state"] == root["key"] == 4225420928)
    check("prototype_dispatch_token", proto["dispatch_token"] == root["token"] == 4515)
    check("prototype_frame_capacity", proto["frame_capacity"] == root["frame"] == 71)
    check("prototype_bank_base", proto["bank_base"] == root["bank"] == 40)
    check("prototype_salt", proto["prototype_salt"] == root["salt"] == 53417)
    check("prototype_fixed", proto["fixed_parameter_mode"] == bool(root["fixed"]) is False)
    check("prototype_no_captures", proto["captures"] == [] and root["captures"] == 0)
    check("prototype_no_parameters", proto["parameter_operands"] == [] and root["arity"] == 0)
    check("root_code_extent_is_root_relative",
          root["code_start"] == 0 and root["code_length"] == 0,
          "root has no lazy code extent; child descriptors carry the extent")

    # 6. control-slot identity used by the certified frame roles
    controls = reference["control_slots"]
    roles = [("KD", 15), ("SH", 3), ("SB2", 7), ("AP", 9), ("RN", 17), ("PS", 18),
             ("RBS", 33), ("RB", 21), ("SB1", 6), ("IP", 29), ("RBE", 24), ("RV", 2),
             ("ST", 23), ("STOP", 5), ("EXIT", 12)]
    check("control_slots",
          all(controls[name] == mine["slots"][index] for name, index in roles))
    check("control_slots_distinct", len(set(controls.values())) == 15)
    check("control_slot_bounds", all(1 <= v <= 71 for v in controls.values()))
    report["notes"].append(
        "Root descriptor word ordering est/len/entry/A/B/token/start is shared with "
        "make.txt:6-13; only the root has a zero lazy-code extent."
    )
    return report


def main() -> None:
    fragments = source_fragments()
    payload = decode_transport(fragments)
    assert hashlib.sha256(payload).hexdigest() == TRANSPORT_SHA256
    mine = initialize(payload)
    reference = json.loads((DIAG / "initialization-reference.json").read_text())
    metadata = parse_metadata(ROOT / "target.metadata.txt")
    report = collect_mismatches(mine, reference, metadata)

    output = {
        "source_sha256": SOURCE_SHA256,
        "transport_sha256": TRANSPORT_SHA256,
        "profile": metadata["Profile"],
        "argument": 110391195,
        "header": mine["header"],
        "master_key": mine["master"],
        "float_bits": f"{mine['float_bits']:016x}",
        "zero_counts": mine["zero_counts"],
        "range": mine["range"],
        "populated_words": sum(v is not None for v in mine["words"]),
        "absent_words": WORD_SLOTS - sum(v is not None for v in mine["words"]),
        "slots": len(mine["slots"]) - 1,
        "distinct_slots": len(set(mine["slots"][1:])),
        "max_slot": max(mine["slots"]),
        "permutation_hashes": [permutation_digest(v) for v in (mine["a"], mine["b"], mine["c"])],
        "root": mine["root"],
        "control_slots": reference["control_slots"],
        **report,
        "devirtualization_claim": False,
        "executed": False,
    }
    (DIAG / "initialization-audit.json").write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps({k: v for k, v in output.items()
                      if k not in {"mismatches", "control_slots"}}, indent=2))
    if report["mismatches"]:
        print("MISMATCHES:", json.dumps(report["mismatches"][:10], indent=2))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
