# Validation

The latest branch state is an **unreleased 0.2.0 development preview**. Historical
results below describe the three complete profiles; the large fourth specimen
remains incomplete. Its current results and explicit unavailable stages are
recorded under `decompilation/protected/target.validation.md`.

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

## Optional pretty-output extension (unreleased)

`--pretty` and `CodegenOptions::pretty` operate on the recovered statement tree.
The bundled SARP and Base85 dialogue outputs independently match
`tests/fixtures/sarp.pretty.luau`: 39 lines, SHA-256
`e8e4d0f2e1228c50394f202bd1e7433b01d4c617937c44050cfc660dde8b594d`.
All three default outputs and protected input/artifact hashes remain unchanged.

Verification performed for this extension:

- `cargo fmt --check`, `cargo test --locked -- --nocapture`, and
  `cargo build --release --locked` passed.
- Cargo reported **147 passing tests, zero failures**. The preexisting optional
  local-decompiler parser check was explicitly skipped because that optional
  executable is unavailable; it is not a performed parser validation.
- `tools/verify.ps1 -RequireExternalTools` passed official Luau 0.747
  compile-only (`--null`) and static analysis for all three defaults and all
  four pretty/comment/strict flag combinations (15 CLI outputs each).
- Real's **static `check-script` tool** reported zero errors and zero warnings
  for the exact generated pretty dialogue. No executor/client was invoked.

The added regressions cover lookup/call order, predicate identity, multiple
live branch results, nil/false distinctions, aliases/self-reference, duplicate
and invalid keys, allocation/escape/read barriers, scalar arity, packed `.n`
counts, expression precedence, source comments, and cleanup depth limits.
Pretty cleanup does not reinterpret unknown operations or conceal errors.
Compilation and static checking are not runtime-equivalence proofs.
Neither protected inputs nor generated Lua/Luau were executed in these checks.

## Large four-fragment SARP preview (incomplete)

The independent `VmProfile::SarpLarge` adapter certifies the full executable
token skeleton with only four payload literals masked. The bundled source
SHA-256 is `1496f231da48222f5aa52d84829e9ad4ef5481eb237f56c6be1b9645dd7136fe`.
Transport agrees on every one of 568176 bytes. Independent diagnostics pass
46/46 initializer checks, 26/26 root/first-child cipher checks and six hash
vectors; the sparse artifact reader matches all 142045 positions.

Partial lowering completes 666 states, with 62 pending, before rejecting
helper 25 generic iteration at prototype 140804, PC 140992. Complete linked IR,
default Luau and pretty Luau are unavailable. `--inspect` exits 1 with a clearly
labeled incomplete report; no output file is replaced, even with `--force`.

The full aggregate passed formatting, locked Cargo tests/build, official Luau
0.747 compile-only/static analysis on 15 old-profile CLI outputs and 20
synthetic manual-IR outputs, and the expected fourth-profile rejection.
Cargo reported 179 successful test results and no failures; the optional local
decompiler parser check explicitly skipped. Five saved emitted baselines and
38 old protected input/artifact/manifest/profile-source hashes remain identical.
No program, VM, interpreter, executor or client was run in this pass.

These are preview regression checks, not a completion or runtime-equivalence
proof. Cargo remains 0.2.0; no new release is published. See the protected
analysis/validation reports for exact reproduction commands and required loop
contracts.
