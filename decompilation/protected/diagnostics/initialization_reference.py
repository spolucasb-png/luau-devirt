"""Independent static initializer/permutation/descriptor arithmetic.

Transcribed from initOnce.txt/initB.txt/initC.txt/boot.txt/make.txt. No handler,
VM, coroutine, metamethod, or recovered program function is invoked. Library
checks are proved identities; only bounded cipher math is evaluated.
"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MOD = 2**32
MASK = MOD - 1
SALT = 43122

def rot(value, amount):
    return ((value << amount) | (value >> (32 - amount))) & MASK

def swap(value):
    return int.from_bytes(value.to_bytes(4, "little"), "big")

def stream(state):
    state = rot((state * 411395 + 479499883) % MOD, 11)
    state = state ^ ((state << 9) & MASK)
    state = state ^ (state >> 5)
    return state ^ ((state << 1) & MASK)

def clz(value):
    return 32 - value.bit_length()

def crz(value):
    return 32 if value == 0 else (value & -value).bit_length() - 1

def main():
    data = (ROOT / "diagnostics/reference.transport.bin").read_bytes()
    raw = struct.unpack("<" + "I" * (len(data) // 4), data)
    words = [None] * (len(raw) + 1)
    argument = 263838302 ^ 153990597
    state = argument ^ 192128608
    for index in range(1, 5):
        state = stream(state)
        words[index] = raw[index - 1] ^ state
    m0 = argument ^ raw[2]
    m1 = (m0 * 29955 + 504689345) % MOD
    bits = struct.pack("<d", float(m1) + float(words[3]) + 1048576.0)
    lo, hi = struct.unpack("<II", bits)
    zero_counts = clz(m0) * 65537 + crz(raw[2]) * 257 + clz(words[3])
    master = ((m1 + lo) % MOD) ^ rot(words[3], 11) ^ hi ^ swap(m0) ^ zero_counts
    low = words[2] ^ 2659961469 ^ master
    high = words[4] ^ 4067770469 ^ master
    assert 4 < low <= high and high + 867 <= len(raw), (low, high)
    for index in range(low, high + 1):
        state = stream(state)
        words[index] = raw[index - 1] ^ state
    key, biases = 299753647, [0]
    for _ in range(64):
        key = (key * 13003 + 3750079167) % MOD
        biases.append(1 + key % 200000)
    a, b, c = list(range(16384)), list(range(16384)), [0] * 16384
    ka, kb = 1074033615, 2285263105
    for index in range(16383, 0, -1):
        ka = (ka * 29983 + 3162639897) % MOD
        kb = (kb * 29983 + 3162639897) % MOD
        ja, jb = ka % (index + 1), kb % (index + 1)
        a[index], a[ja] = a[ja], a[index]
        b[index], b[jb] = b[jb], b[index]
    for index, (pa, pb) in enumerate(zip(a, b)):
        parity = ((pa >> 7) & 1) ^ ((pb >> 2) & 1) ^ 1
        c[pa] = (4 * pb + 2 * ((index * 17 + 13025) % 16384) + parity + SALT) % 65536
    for index in range(16384):
        ka = (ka * 29983 + 3162639897) % MOD
        kb = (kb * 29983 + 3162639897) % MOD
        a[index] |= ((ka >> 20) & 3) * 16384
        b[index] |= ((kb >> 20) & 3) * 16384
    key = master ^ 1836873615
    for index in range(low, high + 1):
        key = (key * 32625 + 2288117495) % MOD
        words[index] ^= a[key % 16384] ^ (b[(key >> 14) % 16384] << 16) ^ biases[1 + index % 64] ^ c[(key ^ index) % 16384]
    slots, key = [0], 3662345728 ^ master
    for index in range(867):
        key = (key * 16973 + 1663117091) % MOD
        word = raw[high + index] ^ key
        slots.extend((word % 65536, word // 65536))
    assert len(slots) == 1735
    root = master ^ ((595533583 + 2755699720) % MOD) ^ 266632
    assert low <= root <= high - 6
    descriptor = {
        "word": root,
        "key": words[root] ^ 2305819396 ^ master,
        "code_length": words[root + 1] ^ 322097349 ^ master,
        "entry": words[root + 2] ^ 3146221740 ^ master,
        "packed_a": words[root + 3] ^ 1312544370 ^ master,
        "packed_b": words[root + 4] ^ 3129404073 ^ master,
        "token": words[root + 5] ^ 3545062758 ^ master,
        "code_start": words[root + 6] ^ 3330028092 ^ master,
    }
    aa, bb = descriptor["packed_a"], descriptor["packed_b"]
    descriptor.update({"fixed": aa & 1, "bank": (aa >> 1) & 131071, "arity": (aa >> 29) & 7,
                       "captures": (aa >> 19) & 1023, "frame": (bb >> 18) & 8191, "salt": bb & 65535})
    buffer_hash = lambda values: hashlib.sha256(b"".join(struct.pack("<H", v) for v in values)).hexdigest()
    control = {name: slots[index] for name, index in [
        ("KD", 15), ("SH", 3), ("SB2", 7), ("AP", 9), ("RN", 17), ("PS", 18), ("RBS", 33),
        ("RB", 21), ("SB1", 6), ("IP", 29), ("RBE", 24), ("RV", 2), ("ST", 23), ("STOP", 5), ("EXIT", 12)]}
    report = {
        "argument": argument, "header": words[1:5], "master_key": master,
        "initial_pool_key": 1030971814 ^ 355957541, "float_bits": bits.hex(),
        "zero_counts": zero_counts, "range": [low, high],
        "populated_words": sum(w is not None for w in words),
        "slots": slots, "slot_count": len(slots) - 1, "distinct_slots": len(set(slots[1:])),
        "max_slot": max(slots), "control_slots": control,
        "biases": biases, "permutation_hashes": [buffer_hash(v) for v in (a, b, c)],
        "root": descriptor,
        "boot_tag": 24189 + SALT,
        "boot_witness_displacement": (763676 ^ 1040301) - 293041,
        "words": words, "executed": False,
    }
    (ROOT / "diagnostics/initialization-reference.json").write_text(json.dumps(report, indent=2) + "\n")
    for name, values in [("A", a), ("B", b), ("C", c)]:
        (ROOT / f"diagnostics/reference.permutation-{name}.bin").write_bytes(b"".join(struct.pack("<H", v) for v in values))
    print(json.dumps({k: v for k, v in report.items() if k not in {"slots", "biases", "words"}}, indent=2))

if __name__ == "__main__":
    main()
