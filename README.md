# luau-devirt

**A standalone, static-only Luau VM deobfuscator and devirtualizer.**

Release **0.1.0** supports the checked Adler-32 / LCG / five-word-prototype VM
and the certified Base85 / rotated-key / three-bank VM profiles represented by
the bundled specimens. It extracts protected bytecode,
recovers constants and register slots, explores symbolic dispatcher states,
and emits readable `--!strict` Luau where the instruction semantics and control
flow are supported.

**The input is never executed.** The CLI has no Python, Lua runtime, executor,
network service, or Cargo dependency.

## Windows binary

Extract `luau-devirt-0.1.0-windows-x86_64.zip`, open a terminal in that folder:

```powershell
.\luau-devirt.exe --version
.\luau-devirt.exe input.lua -o recovered.luau
.\luau-devirt.exe input.lua --inspect
```

The binary is unsigned. Verify its archive against the accompanying
`luau-devirt-0.1.0-SHA256SUMS.txt`, or build it yourself from the source archive.

## Build from source

Requires Rust **1.83 or newer**; the release was tested with Rust 1.95.

```text
cargo build --release --locked
cargo test --locked
```

On Windows:

```powershell
.\target\release\luau-devirt.exe tests\fixtures\sample.lua -o recovered.luau
```

On Linux/macOS, use `./target/release/luau-devirt`. Source portability does not
imply that this release includes prebuilt binaries for those platforms.

## CLI

```text
luau-devirt <input.lua> [options]

  -o, --output <path>  Save the result; otherwise write to stdout
  --force             Safely replace an existing output
  --inspect           Decode metadata only, without lifting/emission
  --comments          Include source-address comments
  --no-strict         Omit the --!strict directive
  -V, --version       Print version
  -h, --help          Print help
  --                  Accept an input filename beginning with "-"
```

Existing output files are preserved unless `--force` is explicit. The input
itself cannot be selected as the output. Forced replacement stages a new file
instead of writing through an existing symlink or hard link.

Exit status: `0` success, `1` decoding/emission/I/O failure, `2` invalid usage.

## Supported format

- Leading literal table with length and Adler-32 integrity records.
- Escaped binary payload, parsed with a real quoted-string lexer—not by
  splitting on `};`.
- Flattened initializer/key math, wrapping 32-bit decryption, 120-entry
  physical register map, string and f64 constant records.
- Five-word prototype descriptors and symbolic state tracking across
  PC/key/bank/dispatch/phase/bank-sum/salt changes.
- Implemented comparison-tree leaves for the substantive handler families
  6094, 1173, and 6965; explicit dispatch-halt representation for 8258/4270.
- Structured loops/branches, guarded constant propagation, proven
  bank-alias normalization, explicit packed tuple counts.

See [VM_FORMAT.md](VM_FORMAT.md) for the profile and [VALIDATION.md](VALIDATION.md)
for verified results.

### Honest limits

This is **not a universal VM decompiler**. A related wrapper with different
cipher formulas, unsupported leaf semantics, or an unproved control-flow
structure fails explicitly. Formula changes are not silently treated as the
old profile. Nonempty closure capture binding and reachable dispatch halts
requiring wrapper return-tag analysis are not yet emitted; neither occurs in
the bundled specimen.

The current source-model matcher expects formatted handler comparison trees.
Minified/reordered wrapper variants are not certified by this release; use a
trusted source formatter first, without executing the input.

The high-level scanner style is derived from a complete matched IR/statement
tree. The CLI never reads or copies the golden output fixture.

## Tests and verification

All specimen, metadata, state, and readable-output fixtures are bundled under
`tests/fixtures`. Input Lua/Luau is never executed by Cargo tests.

```text
cargo fmt --check
cargo test --locked -- --nocapture
```

Optional output compilation/type checking uses official Luau tools:

```powershell
.\tools\install_luau.ps1
.\tools\verify.ps1 -RequireExternalTools
```

Only generated readable output is passed to `luau-compile --null` and
`luau-analyze`; no generated chunk runs. The optional local decompiler parser
check can be enabled with `LUAU_DEVIRT_VALIDATOR`.

Other overrides: `LUAU_DEVIRT_SAMPLE`, `LUAU_DEVIRT_ANALYSIS_DIR`,
`LUAU_DEVIRT_BASELINE_OUTPUT`, `LUAU_DEVIRT_COMPILER`, `LUAU_DEVIRT_ANALYZER`.
An explicit invalid override fails rather than being treated as a skip.

## Release packaging

```powershell
.\tools\package.ps1
```

Creates source and Windows x86-64 ZIPs plus SHA-256 checksums under `dist/`.
Packaging uses an allowlist: no build caches, PDBs, logs, Real installations,
credentials, deployment files, or local-account paths are included.

Reviewed Base85 recovery examples and reports are included under
`decompilation/message`. Original protected sources are inert analysis inputs;
do not execute them. The readable examples were compiled and analyzed only.

## Additional checked Base85 profile

This source tree also supports the certified `base85-rotor-3bank-v1` wrapper
in `tests/fixtures/base85-rotor.lua`. The existing CLI automatically selects
the isolated Rust profile; its older Adler-32 profile and regressions remain
available. The new profile lifts reachable instructions into the shared IR
and emits readable Luau while preserving captured-environment lookups and
external call order. Changed wrapper formulas fail explicitly.

```powershell
cargo run --release --locked --example recover_base85 -- tests\fixtures\base85-rotor.lua decompilation\message --emit
```

The detailed recovery, all 33 transition helpers, raw instruction/state listing,
static validation, and reproducibility commands are under
`decompilation/message/target.analysis.md` and `target.validation.md`.

## Project layout

```text
src/decoder.rs     Literal/integrity/profile and protected-buffer decoder
src/cfg.rs         Bounded symbolic dispatcher traversal
src/lifter.rs      Comparison-tree and variable-length instruction lifting
src/ir.rs          Shared typed IR and explicit tuple/return semantics
src/aliases.rs     Bank-register liveness/noninterference proofs
src/optimizer.rs   Proven silent-control-region simplification
src/specialize.rs  Guarded boolean dispatch specialization
src/codegen.rs     Structured Luau reconstruction and emission
tests/            Portable regression, state, CLI, and output checks
tools/            Verification, official-tool installer, packaging
```

MIT license; see [LICENSE](LICENSE).
