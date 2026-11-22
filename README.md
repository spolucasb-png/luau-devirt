# luau-devirt

**A standalone, static-only Luau VM deobfuscator and devirtualizer.**

This branch is an **unreleased 0.2.0 development preview**, not a 0.3.0 release.
The fourth, large SARP specimen is **not completely devirtualized**; see below.
No new release or replacement of previously published archives is implied.

The complete profiles support the checked Adler-32 / LCG / five-word-prototype VM,
the certified Base85 / rotated-key / three-bank VM, and an independently
certified SARP fragment / dual-stream / seven-word VM profile represented by
the bundled specimens. It extracts protected bytecode,
recovers constants and register slots, explores symbolic dispatcher states,
and emits readable `--!strict` Luau where the instruction semantics and control
flow are supported.

**The input is never executed.** The CLI has no Python, Lua runtime, executor,
network service, or Cargo dependency.

## Windows binary

Build locally, or extract a clearly labeled
`luau-devirt-0.2.0-development-preview-windows-x86_64.zip`:

```powershell
.\luau-devirt.exe --version
.\luau-devirt.exe input.lua -o recovered.luau
.\luau-devirt.exe input.lua --pretty -o readable.luau
.\luau-devirt.exe input.lua --inspect
```

The binary is unsigned. Verify its archive against the accompanying
`luau-devirt-0.2.0-development-preview-SHA256SUMS.txt`, or build it yourself.

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
  --inspect           Inspect metadata/profile analysis without Luau emission
  --pretty            Safely simplify recovered code for comfortable reading
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

### Optional pretty output

`--pretty` runs a bounded cleanup on the **recovered IR-derived statement tree**,
not on the obfuscated source. It removes adjacent, single-use lookup/call
temporaries, reconstructs safe table initializers, and turns predicate-carrying
branches into `and`/`or` expressions. Tables get consistent spacing and larger
initializers are split over several lines.

```powershell
.\target\release\luau-devirt.exe tests\fixtures\sarp.lua --pretty -o readable-sarp.luau
```

The bundled dialogue is emitted in 39 lines instead of 60. Both the SARP and
Base85 profiles produce the same pretty result independently. The CLI never
reads the expected-output fixtures.

Cleanup preserves captured-environment lookups, method lookup/call order,
table identity, and nil/false distinctions. It never uses the unsafe
`condition and value or fallback` idiom. A lookup is not moved across another
effect, and scalar calls are not inlined into argument lists. Table folding
stops at a call, read, escape, another allocation, duplicate/dynamic key, or
self-reference.

The optional cleanup currently targets acyclic captured-environment dataflow.
The existing scanner/loop/closure/packed-tuple renderer retains its established
structured output and explicit `.n` counts. Unproved simplifications remain
conservative, and unsupported instructions/unknown arities still fail.
`--comments` and `--no-strict` can be combined with `--pretty`; source comments
act as cleanup barriers so their addresses stay attached to the same operations.
**Default output remains byte-for-byte unchanged.**

For the Rust API:

```rust
let options = luau_devirt::ir::CodegenOptions {
    pretty: true,
    ..Default::default()
};
```

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
requiring wrapper return-tag analysis are not generally supported by the older
renderer. The large specimen's partial traversal must not be confused with a
complete emitted program.

The original Adler source-model matcher expects formatted handler comparison
trees. The Base85 rotor and SARP adapters use the shared tokenizer directly;
their certified minified inputs need no formatter. Reordered/different wrapper
formulas are not automatically accepted.

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
.\tools\package.ps1 -Preview -OutputDirectory target\preview-package
```

Creates development-preview source and Windows x86-64 ZIPs plus SHA-256
checksums in the requested directory. On this incomplete branch, packaging
without `-Preview` is refused. Existing archives/checksums are preserved unless
`-Force` is explicitly requested; do not use it on published archives.
Packaging uses an allowlist: no build caches, PDBs, logs, Real installations,
credentials, deployment files, or local-account paths are included.

Reviewed Base85 recovery examples and reports are included under
`decompilation/message`, and SARP artifacts under `decompilation/sarp`.
Original protected sources are inert analysis inputs;
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

## Certified SARP profile

`sarp-fragment-dualstream-7word-v1` is isolated in `src/sarp.rs`. It certifies
the complete wrapper token skeleton with only five payload fragment literals
excluded. Its transport assembles those fragments by buffer offsets, decodes
low-digit-first Base85, swaps each u32 and applies a separate XOR stream. The
word initializer, tagged permutations, second word cipher, seven-word root,
operation tables and dispatcher state are independently derived.

```powershell
cargo run --release --locked --example recover_sarp -- tests\fixtures\sarp.lua decompilation\sarp
.\target\release\luau-devirt.exe tests\fixtures\sarp.lua --inspect
.\target\release\luau-devirt.exe tests\fixtures\sarp.lua -o recovered-sarp.luau
```

The specimen has 43 instruction addresses / 178 bounded states, one reachable
prototype, 35 strings, three referenced numbers and zero unresolved instructions.
The readable result passes official Luau compile-only and strict analysis.
It reproduces the earlier specimen's dialogue logic without reading its golden
output. The old profile outputs remain unchanged.

Unknown inputs to the 60-round hash gate, capture bindings, fixed-parameter
roots, unsupported operation-table entries and unproved structures fail
explicitly. There is no arbitrary expression interpreter or target execution.
See `decompilation/sarp/target.analysis.md`, `target.handlers.md` and
`target.validation.md` for certification fingerprints, exact math, evidence,
commands and limits.

## Large four-fragment SARP development preview

`sarp-four-fragment-dualstream-large-v1` is an independent adapter in
`src/sarp_large.rs` and `src/sarp_large/`. It does not replace or weaken the
five-fragment certifier. Certification fingerprints all 145,089 tokens while
masking only the four payload literals. Ambiguous profile selection and changed
executable tokens still fail explicitly.

The bundled `tests/fixtures/protected.luau` is pinned to SHA-256
`1496f231da48222f5aa52d84829e9ad4ef5481eb237f56c6be1b9645dd7136fe`.
Its transport recovers all 568,176 bytes. Independent arithmetic agrees on
all 142,045 working-word positions (including absence), maps, biases,
permutations, root activation, the first child descriptor/lazy cipher, and six
320-round hash vectors. These are static cipher/initialization checks, not a
runtime-equivalence or full-program proof.

The bounded lifter currently completes **666 dispatcher states with 62 pending**
and fails at child prototype 140804, PC 140992, helper 25. This helper implements
generic iteration with a packed iterator, reentrant dispatcher calls, saved
stop/exit continuations and changing rotor state. Existing numeric-loop IR
cannot safely substitute for it. **Complete linked IR, default Luau and pretty
Luau are unavailable for this target.** The CLI exits 1 even with `--inspect`;
it prints an incomplete-analysis report to stderr and does not replace output.

```powershell
# Rust static analysis only; the nonzero exit is the current honest result.
cargo run --locked --example recover_protected -- tests\fixtures\protected.luau decompilation\protected
.\target\release\luau-devirt.exe tests\fixtures\protected.luau --inspect
```

Genuine transport, sparse VM image, parsed-handler evidence and the partial
trace are under `decompilation/protected/`, together with reproduction commands
in `target.analysis.md` and `target.validation.md`. `target.status.txt` marks
unavailable stages. Never execute the original source, recovered code or VM;
the independent Python references evaluate only bounded diagnostic arithmetic.

## Project layout

```text
src/decoder.rs     Literal/integrity/profile and protected-buffer decoder
src/sarp.rs        Independently certified SARP decoder/state/lifter
src/sarp_large/    Separate large-SARP partial lifter and source proofs
src/cfg.rs         Bounded symbolic dispatcher traversal
src/lifter.rs      Comparison-tree and variable-length instruction lifting
src/ir.rs          Shared typed IR and explicit tuple/return semantics
src/aliases.rs     Bank-register liveness/noninterference proofs
src/optimizer.rs   Proven silent-control-region simplification
src/specialize.rs  Guarded boolean dispatch specialization
src/codegen.rs     Structured Luau reconstruction and emission
src/codegen/pretty.rs  Optional, proved statement-tree presentation cleanup
tests/            Portable regression, state, CLI, and output checks
tools/            Verification, official-tool installer, packaging
```

MIT license; see [LICENSE](LICENSE).
