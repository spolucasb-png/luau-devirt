"""Independent large-SARP transport arithmetic, derived before Rust changes.

Uses explicit positional digit weights rather than Rust's Horner loop. Byte
swapping is an endian reinterpretation. Never executes source or VM code.
"""
import hashlib
import json
import struct
from pathlib import Path
from probe import tokens, unquote

ROOT = Path(__file__).resolve().parent.parent
SOURCE_SHA256 = "1496f231da48222f5aa52d84829e9ad4ef5481eb237f56c6be1b9645dd7136fe"
ALPHABET = b"XzO+#ig=Jk[1qYc:@K)yuaH;~jew6srV7b<n3ptMBdUF$NECQ]foZ,^mT4.!>&52(G09D_hPRW%lI8?SLAxv|"
LENGTHS = (177562, 177551, 177559, 177548)
OFFSETS = (0, 177562, 355113, 532672)
FIRST = (0xe747ff55, 0x162cbeb3, 0xd51d7a23, 0xc6c2a9ca,
         0xbcdda2dd, 0x77fc4197, 0x5e3d7d16, 0x88503b0b)
MODULUS = 2**32

def decode(encoded, alphabet):
    if len(alphabet) != 85 or len(set(alphabet)) != 85:
        raise ValueError("duplicate or invalid alphabet")
    if not encoded or len(encoded) % 5:
        raise ValueError("invalid encoded extent")
    digits = {character: position for position, character in enumerate(alphabet)}
    weights = (1, 85, 85**2, 85**3, 85**4)
    words, state = [], 577177045
    for position in range(0, len(encoded), 5):
        value = sum(digits[encoded[position + i]] * weights[i] for i in range(5)) % MODULUS
        # write the mathematical low-u32 big-endian, then read little-endian:
        swapped = struct.unpack("<I", struct.pack(">I", value))[0]
        state = (state * 15577 + 3425539465) % MODULUS
        words.append(swapped ^ state)
    return b"".join(struct.pack("<I", word) for word in words)

def main():
    raw = (ROOT / "target.original.lua").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SOURCE_SHA256
    ts = tokens(raw.decode())
    fragments = []
    for number, size in enumerate(LENGTHS):
        name = "_pc" + str(number)
        indices = [i + 3 for i in range(len(ts) - 3)
                   if [t.text for t in ts[i:i + 3]] == ["local", name, "="]]
        assert len(indices) == 1
        fragment = unquote(ts[indices[0]].text)
        assert len(fragment) == size
        fragments.append(fragment)
    indices = [i + 4 for i in range(len(ts) - 4)
               if [t.text for t in ts[i:i + 4]] == ["_ab", "=", "bfrom", "("]]
    assert len(indices) == 1 and unquote(ts[indices[0]].text) == ALPHABET
    assembled = bytearray(710220)
    occupied = bytearray(710220)
    # Use the source's actual copy order, distinct from declaration order.
    for number in (2, 1, 3, 0):
        start, end = OFFSETS[number], OFFSETS[number] + LENGTHS[number]
        assert not any(occupied[start:end])
        assembled[start:end] = fragments[number]
        occupied[start:end] = b"\1" * LENGTHS[number]
    assert all(occupied)
    decoded = decode(assembled, ALPHABET)
    assert len(decoded) == 568176
    assert struct.unpack("<8I", decoded[:32]) == FIRST
    (ROOT / "diagnostics/reference.transport.bin").write_bytes(decoded)
    report = {"source_sha256": SOURCE_SHA256, "fragments": [
        {"name": "_pc" + str(i), "length": LENGTHS[i], "offset": OFFSETS[i]} for i in range(4)],
        "alphabet": ALPHABET.decode(), "encoded_bytes": len(assembled),
        "decoded_bytes": len(decoded), "word_count": len(decoded) // 4,
        "transport_sha256": hashlib.sha256(decoded).hexdigest(),
        "first_eight_words": [f"{x:08x}" for x in FIRST], "executed": False}
    (ROOT / "diagnostics/transport-reference.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
