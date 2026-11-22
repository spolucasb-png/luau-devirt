"""Check generated inert artifacts only; never compile or execute Lua/Luau.

The LVDW presence flags are independently compared with every initializer
position. These checks do not validate complete program semantics.
"""
import hashlib
import json
import struct
from pathlib import Path

import initialization_audit as ia

ROOT = Path(__file__).resolve().parent.parent


def sparse_words(image):
    if len(image) < 12 or image[:8] != b"LVDW\x01\0\0\0":
        raise ValueError("invalid sparse image header")
    count, = struct.unpack_from("<I", image, 8)
    if count != 142045:
        raise ValueError("invalid sparse image word count")
    words, at = [], 12
    for _ in range(count):
        if at >= len(image) or image[at] not in (0, 1):
            raise ValueError("invalid/truncated presence flag")
        present = image[at]
        at += 1
        value = None
        if present:
            if at + 4 > len(image):
                raise ValueError("truncated present word")
            value, = struct.unpack_from("<I", image, at)
            at += 4
        words.append(value)
    if at != len(image):
        raise ValueError("trailing sparse image bytes")
    return words


def main():
    original = (ROOT / "target.original.lua").read_bytes()
    assert hashlib.sha256(original).hexdigest() == ia.SOURCE_SHA256
    fixture = ROOT.parent.parent / "tests/fixtures/protected.luau"
    fixture_compared = fixture.is_file()
    if fixture_compared:
        assert original == fixture.read_bytes()
    reference = json.loads((ROOT / "diagnostics/initialization-reference.json").read_text())
    image = (ROOT / "target.vm.bin").read_bytes()
    words = sparse_words(image)
    metadata = ia.parse_metadata(ROOT / "target.metadata.txt")
    assert words == reference["words"]
    assert words == [metadata["words"][i] for i in range(len(words))]
    assert sum(w is not None for w in words) == 7022
    assert (ROOT / "target.transport.bin").read_bytes() == (ROOT / "diagnostics/reference.transport.bin").read_bytes()
    malformed = [image[:11], image[:-1], image + b"\0", image[:12] + b"\2" + image[13:]]
    for data in malformed:
        try:
            sparse_words(data)
        except ValueError:
            pass
        else:
            raise AssertionError("malformed sparse image was accepted")
    status = (ROOT / "target.status.txt").read_text()
    trace = (ROOT / "target.partial-bytecode.txt").read_text()
    assert "INCOMPLETE" in status and "unavailable" in status
    assert "unsupported helper 25 generic iteration" in trace
    assert "Hash proofs:" in trace and "Factory requests:" in trace
    report = {
        "source_sha256": ia.SOURCE_SHA256,
        "fixture_bytes_compared": fixture_compared,
        "sparse_word_positions_compared": len(words),
        "sparse_image_bytes": len(image),
        "present_words": 7022,
        "absent_words": len(words) - 7022,
        "malformed_images_rejected": len(malformed),
        "transport_bytes_match": True,
        "incomplete_status_verified": True,
        "executed_lua": False,
        "devirtualization_claim": False,
    }
    (ROOT / "diagnostics/artifact-check.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
