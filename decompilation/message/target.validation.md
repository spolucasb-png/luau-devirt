# Validation of the recovered Luau

All validation is static. The original wrapper, its VM, and the recovered
program were never executed. Compilation used `luau-compile --null` only.

Final reproduction completed successfully: formatting check, full Cargo test
suite, release build, artifact generation, CLI inspection/emission, cleaned
reference emission, official Luau compilation and official Luau analysis all
returned exit code **0**. Cargo reported **112 tests passed**; one preexisting
optional local-parser test internally reported its unavailable-tool skip, so
111 checks ran and that one optional check was not performed. Official compiler
and analyzer checks were performed. The original-profile regression suite is
included in those results.

## Evidence and checks

- Original source fingerprint matches the supplied SHA-256 exactly:
  `0e4d2588aaa6f118dcdfe9999ccb84c0115ad058b3f3c61bca5ced500757edd0`.
  The original attachment, untouched copy, working copy and fixture are checked.
- Rust and independent arithmetic decoding agree on all 2,248 payload bytes,
  the 562 little-endian words, header/key derivation, range, 111 register-map
  entries, 64 biases and the root descriptor. Payload SHA-256:
  `1450c06c547092e6f75b662180fde0b1ecc364942e063fffdc804db24ba63b1a`.
- Every encoded character is validated. Invalid characters, duplicate/short
  alphabets, source mutations, source/payload truncations and size mismatches
  are covered by regression tests; no malformed input is silently skipped.
- Raw symbolic coverage is 162 states and 42 instruction addresses. No Raw or
  unresolved instruction is present. Successor states target decoded words.
  Full evidence is in `target.bytecode.txt` and `target.ir.txt`.
- Control specialization proves initialized nonescaping integer successors;
  it rejects unknown facts, nontermination and state-budget overflow. Liveness
  retains potentially observable calls and table reads/writes. Structured IR
  has 29 blocks. The two scratch values remain distinct under all six bank
  transitions. Permutation identity/equality proofs include negative int32.
- 35 string constants and three used f64 constants are recovered. The latter
  retain their exact binary representations. Integer arguments such as 255,
  45 and markup indices come from the decoded biased immediates.
- Original return handling is checked: `stop/exit` remain zero, the reachable
  terminator returns dispatcher code 93375, and `boot` therefore returns no
  values. Dormant alternative return forms are documented, not fabricated.
- The final source has eight external call sites, each emitted once, with the
  original short-circuit branches and property/call/write order. Private scalar
  call packets collapse only under a one-use immediate-projection proof.
- The generated script passes official Luau **0.747** compile-only checking
  and strict static analysis, both exit code 0. This checks syntax, balanced
  blocks, local bindings, function/call syntax and static types; it is not a
  runtime equivalence test.
- Original-profile regressions still check all 109 dispatcher states and the
  211-token readable baseline. New tests cover this profile and synthetic
  scalar/captured-environment dataflow. `cargo fmt --check`, full Cargo tests
  and `cargo build --release --locked` are reproduced by the validation runner.
- CLI and library/example output must match byte-for-byte. Output/payload and
  all requested deliverable hashes are recorded in `SHA256SUMS.txt`.
- The later `cleaned.lua` reference has exact noncomment-token equality with
  the original and must produce byte-identical recovered output. The renamed
  abacktools reference retains identical payload/alphabet literals; its altered
  wrapper is not treated as a correctness oracle.

Final commands, stdout, stderr, timings and exit codes are saved in
`logs/final-results.json` and `logs/final-*.{stdout,stderr,exit}.txt`. A preexisting
optional local `luau-decompiler` parser is not installed, so its legacy optional
test reports a skip. Official Luau compilation and analysis are available and
run on the recovered output. No input fixture is passed to either compiler.

## Remaining limits

This recovers the reachable logic under the certified wrapper and ordinary
Luau library semantics. It does not recover original identifier spellings,
comments, formatting, or the preferred original syntax for equivalent table
construction. The generated names describe proved roles.

It does not claim support for unrelated Base85 VM variants or arbitrary changes
to this wrapper. The adapter rejects unsupported captures, fixed-parameter
roots, new wrapper formulas, unknown helpers and unsupported structures. The
payload has no original integrity checksum; its provenance is the supplied
source hash, independently matched transport and structural/semantic checks.

Decoded words 242, 259 and 506 have no instruction fetch or operand use in the
recovered state graph. They remain in the preserved payload and are explicitly
listed in `target.coverage.txt`. No placeholder source was invented for them.

No behavioral test was run in Roblox or a Lua/Luau interpreter, and none is
needed to reproduce these static results. The external game objects and APIs
are runtime dependencies of the original program, not supplied implementations.
