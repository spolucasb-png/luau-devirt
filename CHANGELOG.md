# Changelog

## 0.2.0 — 2026-11-21

- Added independently certified SARP fragment/byteswap/dual-stream support in
  `src/sarp.rs`, including seven-word root descriptors and tagged permutations.
- Replaced `_b85` identifier-based routing with complete token certification and
  an explicit decoded profile tag.
- Added bounded SARP handler parsing/lifting, source-proved bank renaming,
  on-demand constants and constant-only double-hash predicate analysis.
- Preserved both 0.1.0 profile outputs byte-for-byte; no old golden was changed.
- Added independent arithmetic reference, fixture/decoder/VM regression tests,
  CLI metadata/help updates and `recover_sarp` artifact generation.
- Aggregate verification now checks all three profiles; packaging includes
  SARP recovery artifacts through an explicit allowlist.

The certified specimen has zero unresolved instructions. Unknown hash subjects,
new operation helpers, capture bindings, fixed roots and incompatible wrapper
formulas remain explicit unsupported cases; this is not universal SARP support.

## 0.1.0 — 2026-11-21

- Standalone, std-only Rust static devirtualizer for the checked VM profile.
- Literal parsing, active Adler integrity bindings, wrapping word/key decoding.
- Prototype, register-map, string, and exact f64 recovery.
- Symbolic CFG across dynamic keys, banks, tokens, phases, and salts.
- Guarded instruction lifting and structured strictly typed Luau output.
- Explicit packed-tuple and dispatch-halt semantics.
- Alias noninterference, loop-effect, boolean-snapshot, and tuple-arity guards.
- Portable regression fixtures and CLI smoke tests.
- `--version`, metadata-only `--inspect`, safer output creation and `--force`.
- Allowlisted source/binary release packaging and SHA-256 checksums.
- Added the certified Base85 / rotated-key / three-bank VM profile.
- Bounded control specialization and captured-environment Luau reconstruction.
- Memoized register-type inference to avoid repeated exponential traversal.
- Additional transport, bank-role, scalar-call, alias and branch regressions.
- Reviewed recovery examples and reports included through an explicit allowlist;
  diagnostic logs, external uploads and local tooling remain excluded.
