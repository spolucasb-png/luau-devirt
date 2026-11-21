# Validation

## Verified specimen

- Payload: 2,276 Adler-32-verified bytes.
- Decoded words: 490 populated; absent positions retained as absent.
- Physical slot map: 120 entries, 46 distinct specimen slots.
- Descriptors: words 24 and 505; entries 388 and 413.
- Constants: `table`, `concat`, `,`; exact f64 records
  `-131`, `757`, `-650/7`, `289`.
- CFG: 55 addresses and all seven fields of all 109 states match the static
  reference.
- Reachable IR: no unresolved Raw instructions.
- Output: all 211 normalized tokens match the readable golden result.

The earlier working build passed 85 automated tests and, at an explicit user
request, 543 bounded Real differential cases of **readable generated code**
against the readable baseline. Of those, 277 carried explicit expected
results; seven intentional error cases matched.

The original VM specimen was never executed. No private executor installation,
client/account identifier, credentials, or game deployment is part of this
release.

## Release reproduction

```text
cargo fmt --check
cargo test --locked -- --nocapture
cargo build --release --locked
```

The release adds packaging/fixture checks and safer CLI behavior to the working
build. **88 automated tests passed** in the clean release tree, with all
external checks enabled and no skips. All fixture inputs are in the source
archive. Optional external checks compile/analyze generated output only.

On Windows:

```powershell
.\tools\install_luau.ps1
.\tools\verify.ps1 -RequireExternalTools
.\tools\package.ps1
```

See `README.md` and `VM_FORMAT.md` for the supported profile and limitations.

## Additional Base85 specimen

The source tree now includes static recovery of `base85-rotor.lua` (source
SHA-256 `0e4d2588aaa6f118dcdfe9999ccb84c0115ad058b3f3c61bca5ced500757edd0`).
The decoded payload is 2,248 bytes / 562 words, independently matched byte for
byte. The full raw trace has 162 states, 42 addresses and no Raw instructions.
The reachable program has one root prototype and eight external call sites;
its readable 60-line reconstruction passes official Luau compile-only and
strict static analysis. Neither original nor recovered code was executed.

`tests/base85_profile.rs`, `tests/captured_dataflow.rs`, and synthetic tests in
`src/base85.rs` cover transport errors, source mutations, bounds, permutation
inversion, bank-role preservation, control specialization, alias identity,
scalar call counts, nil/false branches, and explicit unsupported cases. The
original 109-state and 211-token profile checks are retained. Exact commands,
logs, exit codes, remaining limits and deliverable hashes are recorded under
`decompilation/message`.

## 0.2.0 SARP extension

Baseline was exact commit `3ffea1943b15feffeceb29f6193238163d055511`.
Both prior emitted outputs remain byte-identical to their existing examples.
The SARP fixture is 118,433 bytes, source SHA-256
`4518ff6626677a946e60b1f1fbf5e0e0bd6c2aa95a674c163864e763fff3d45f`.
Independent arithmetic and Rust agree on 2,264 payload bytes (SHA-256
`0b27a42d1fcea8d6a268848800b7cd04681167b15d007094a5082e3dd1f52d0f`),
all decoded word positions, map/bias entries, root and entry rekey.

The new profile lifts 43 addresses / 178 states, then proves 30 structured
data blocks. It has one reachable function, 35 strings, three referenced f64
records and zero unresolved instructions. Generated Luau passes compile-only
and strict analysis; no original/recovered program was executed.

`tests/sarp_profile.rs` covers transport vectors/wrapping, source certification,
fragment ordering, corruption, all reached families, state/control targets,
limits and mandatory old-output equality. Synthetic unit tests pin standard
key-check identities, tagged permutations and both bank directions.
`tools/verify.ps1` checks all three profiles. Exact final commands/results,
test count and remaining limits are in `decompilation/sarp/target.validation.md`.
