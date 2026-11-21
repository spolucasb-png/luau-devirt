# Release project

- Static-only devirtualization: never run `tests/fixtures/sample.lua` or other
  untrusted Lua/Luau inputs, including through an executor or an interpreter.
- Preserve explicit unsupported-profile/instruction errors. Do not fabricate
  clean output, register bindings, tuple arities, or source metadata.
- Contracts live in `src/ir.rs`. Packed tuples retain explicit `.n` counts.
- Alias proofs include live/live and destination/live-out interference.
- Fixtures are bundled under `tests/fixtures`; no private files are required.
- Run `cargo fmt --check`, `cargo test -- --nocapture`, `cargo build --release`.
- Only generated readable output may be compiled with `luau-compile --null`
  or statically analyzed with `luau-analyze`.
- `tools/verify.ps1` is the aggregate check; external tools are optional unless
  requested through `-RequireExternalTools`.
- `tools/package.ps1` creates an allowlisted release, excluding build caches,
  executor tools, credentials, private paths, and runtime-client details.
