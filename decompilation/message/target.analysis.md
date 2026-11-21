# Static recovery of message.txt

Recovery date: November 21, 2026. The Rust devirtualizer is the decompilation
engine. No original or recovered Lua/Luau program was executed.

## Result

`target.deobfuscated.lua` reconstructs the reachable program as a readable
60-line Luau script. It retrieves `ReplicatedStorage`, finds its `Events` child
and `MothDialogueBindable`, checks that the latter is a `BindableEvent`, builds
a dialogue options table, and calls the event's `Fire` method. The payload text
is `hey its me its celestial`; the entrance/exit animations are `horizontal`
and `flash`, lifetime is 7.5, position is `UDim2.fromScale(0.5, 0.95)`, and the
two markups are a red Color3 `(255,45,45)` and `Shaky` with both values 1.

The wrapper has one reachable root prototype and no reachable user closures.
Its `make`, closure factories, return-tag alternatives, and decoy helpers are
wrapper infrastructure, not additional recovered source functions. The root
returns no values and communicates through its calls and table writes.

## Input preservation and fingerprint

| Item | Result |
| --- | --- |
| Original bytes | 83,951 |
| Lines | 13; the last line is 82,038 bytes |
| Original SHA-256 | `0e4d2588aaa6f118dcdfe9999ccb84c0115ad058b3f3c61bca5ced500757edd0` |
| Encoded literal | 2,810 bytes |
| Alphabet | 85 distinct bytes |
| Transport words / bytes | 562 / 2,248 |
| Decoded payload SHA-256 | `1450c06c547092e6f75b662180fde0b1ecc364942e063fffdc804db24ba63b1a` |

The Downloads attachment was copied, not moved. `target.original.lua`,
`target.working.lua`, and `tests/fixtures/base85-rotor.lua` preserve its bytes.
The token layout and extracted wrapper functions in `diagnostics` are analysis
aids, not devirtualized output. A StyLua `--verify` diagnostic rejected its own
AST comparison and left that diagnostic copy unchanged; its output was never
used as a correctness premise. Token-only layout was then checked for exact
token equality.

Two later-supplied failed online outputs were preserved under
`diagnostics/external` and compared as text. `cleaned.lua` (105,844 bytes,
SHA-256 `8e53d161e8e429aa0922d4fbc21a9eeb08ce83a62c92a8bb79a5e498fb412271`)
has exactly the same 35,901 noncomment tokens as the original: it is a faithful
formatting, still containing the whole VM. The 167,745-byte
`abacktools-lua-deobfuscator-helper.lua` (SHA-256
`e92cb44a164ce48a6e0041f66fda6c0a2e5102fd4b861b47c382220bfcb02a76`)
has 35,879 tokens and renamed/changed wrapper syntax; it retains the exact same
decoded 2,810-byte payload literal and 85-byte alphabet. That is corroboration
of input identity, not proof of its full semantic equivalence. Neither online
file was executed or used as the engine's source of recovered logic. The Rust
CLI accepts the token-identical cleaned copy and reproduces the final script.
`diagnostics/external-comparison.json` records the comparisons.

## Existing engine and initial result

The existing project is `luau-devirt` 0.1.0, a dependency-free Rust crate whose
library and CLI share `decode_source -> walk_cfg -> emit_luau`. The documented
command is:

```powershell
cargo build --release --locked
.\target\release\luau-devirt.exe INPUT.lua -o OUTPUT.luau
```

The initial binary was built from the unmodified source and run against the
Downloads original, once for decompilation and once with `--inspect`. Both
returned exit code **1**, empty stdout, and an explicit unsupported-profile
error. Exact stdout, stderr, exit codes, and the baseline test/build logs are
under `logs/baseline-*`. No formatted file was counted as success.

The old decoder certifies `adler32-lcg-5word-v1`. Its assumptions differ at the
transport, key stream, header order, prototype bit layout, register-map size,
constant cipher, handler source model, and symbolic-state transitions. Merely
formatting this input cannot repair these differences. Its prior fixtures and
55-address/109-state baseline remain unchanged and pass their regressions.

## Transport and initialization

The source's alphabet is used byte-for-byte. For each five-byte group, with
digit values `d0..d4`, the word is
`d0 + 85*d1 + 85^2*d2 + 85^3*d3 + 85^4*d4`. Thus the first character is the
least significant digit. The word is written little-endian, with source-faithful
low-u32 conversion. There is no Ascii85 shorthand, padding, ignored character,
or whitespace skipping. All 2,810 characters are checked; there is no overflow
in this specimen. The header copy-out/copy-back leaves the first 16 bytes intact.

| Initialization fact | Recovered value |
| --- | --- |
| `sa` | 1,754,244,686 |
| `K0` | 2,484,975,588 |
| Initial `K1` | 1,109,638,509 |
| `K1` after the entry rekey | 135,918,109 |
| Decoded word range | 194..506 inclusive |
| Populated words | 317: four headers plus 313 range words |
| Register map | 111 entries; physical slots 1..48 |
| Immediate biases | 64 |
| Root descriptor / entry | 194 / 243 |
| Initial key / token / bank / salt | 394,499,739 / 58,811 / 15 / 31,541 |
| Root frame / parameters / captures | 48 / vararg wrapper, no consumed arguments / 0 |

Word-key derivation starts with `sa XOR 3516382929`; each step applies
`*386733+3401468729 mod 2^32`, left rotate 5, then XOR folds at left 9,
right 5, left 1. The key stream continues from header word four into word 194;
it is not reset. `K0` uses raw word three, decoded word three with byte swap,
the `*28595+624331951` LCG, and the source's rotate/shift terms. The slot-map
LCG is `*2185+3437004073`; the bias LCG is `*15449+631628129`.

`diagnostics/decode_payload.py` is an independent arithmetic transcription used
only to cross-check the Rust bytes/metadata. Rust produces `target.decoded.bin`;
the independent output is `diagnostics/reference.decoded.bin`. They match
byte-for-byte. The diagnostic's explicit no-overflow check is specimen-specific;
the Rust decoder implements the actual low-u32 write semantics.

## Dispatcher and handler recovery

`RT` has 15 shape-to-family entries. The three substantive families reached are
3080, 1408, and 1952. Their selectors are respectively:

```text
bxor(W[ip], key, prototype_salt) - 1669
((W[ip] - key*7 - prototype_salt) mod 2^32) - 5536
((W[ip] - key - prototype_salt) mod 2^32) - 19927
```

The source comparison trees select the actual leaf statements; opcode indices
are not used as guesses. Leaf operand expressions are parsed and statically
resolved. Data reads, writes, calls, tables, comparisons and returns become the
existing typed IR. Program function calls are never invoked by Rust.

The 33 `_h` functions are transition helpers, not 33 ordinary program opcodes.
Their complete parameter maps, effects, mask groups, branch polarity, return
forms and decoy classification are documented in `target.handlers.md`. The
helpers used by reachable transitions are 1, 3, 6, 15, 16 and 32; helper 5 is
referenced by stop alternatives but dormant because `stop` is always zero.

The permutation tables prove that both the witness correction and conditional
correction equal **53,112**, independent of runtime input. The entry tag is
therefore 62,760. The normalized phase is
`(rotor + 4044522868 + F[pys]) mod 2^32`. A helper's payload store makes the next
phase exactly its encoded phase operand. Its masked PC/key/token results are
cancelled by the corresponding dispatcher unmask; the raw rotor need not be
enumerated indefinitely. The helper-1 int32 equality check is inverted through
the two proved permutations, including its extra `kv` contribution to all four
successor channels.

Banks cycle through 15, 36 and 57 in stride 21. The four physical role windows
are `{3,46,29,21}`, `{29,46,21,3}`, and `{21,46,3,29}`. The phase slot stays 46.
Each source parallel rotation preserves the values of logical scratch roles
u1/u2 in the corresponding new roles. The adapter checks all four identities
at every transition and maps the two distinct data roles to distinct canonical
IR registers. This is a bijective state-dependent renaming, not a merge of
simultaneously live values. The rotor and phase cells cannot be accessed as
program data. Other physical data slots keep their identities. Leaf-local
snapshot temporaries have separate bounded ranges per instruction address.

## Control flow and readable emission

The bounded symbolic worklist recovers **162 states at 42 instruction
addresses**, with no unresolved Raw instructions. `target.bytecode.txt` records
each state's key, bank, token, salt, phase, window, ceiling and pool key, every
instruction's word span, typed effects and successor states. `target.ir.txt`
preserves the raw typed program.

A separate bounded abstract pass specializes only initialized, nonescaping
integer control facts. It removes the wrapper's counter/flip-flop layer after
proving its exact successors; escaping values and unknown predicates are not
guessed. Dead-copy elimination removes only pure dead definitions. All calls
and potentially effectful user table reads/writes retain their order. This
leaves **29 structured blocks**, written to `target.structured-ir.txt`.

The shared emitter reuses its graph validation and postdominators. Its captured
environment renderer assigns immutable value identities, preserves joins with
explicit phi assignments, and recognizes a scalar result only when a private
one-result packet has exactly one immediate `[1]` projection. It emits each
external call once, preserves nil/false in short-circuit checks, captures
`getfenv()` once, and keeps both separate `math.huge` reads. It does not replace
the captured environment with `_G` or reorder property lookups into a table
constructor. Descriptive names are derived from recovered keys/operations;
original variable spellings and comments are not recoverable.

There are 35 referenced string records and three referenced f64 records (0.5,
0.95 and 7.5). Other byte regions are not promoted to constants without a
reference proof. The 305 words covered by instruction/operand spans and root descriptor
account for the live word regions; words **242, 259 and 506** are neither fetched
instructions nor read operands in any discovered state. They are retained in
the raw payload/listing coverage report as unreferenced words, not replaced
with invented instructions.

## Rust changes and reproducibility

New Rust files:

- `src/base85.rs`: certified transport/initializer profile, bounded leaf parser,
  transition normalization, typed lifting, control specialization, liveness,
  raw trace and synthetic proof tests.
- `examples/recover_base85.rs`: produces payload, listing, raw/structured IR,
  constant and coverage artifacts through the Rust library.
- `tests/base85_profile.rs`: independent transport vectors, fixture metadata,
  mutation/truncation, coverage and legacy-profile compatibility regressions.
- `tests/captured_dataflow.rs`: synthetic captured-environment emission checks.

Modified existing Rust files:

- `src/lib.rs`: registers the isolated profile module.
- `src/decoder.rs`: routes Base85 inputs and shares the existing lexer, quoted
  literal scanner and SHA-256 implementation within the crate.
- `src/cfg.rs`: routes the certified profile to its bounded state model.
- `src/ir.rs`: adds an explicit captured-environment operand.
- `src/codegen.rs`: order-preserving captured-environment rendering, source
  comments, and memoized bounded register-type queries. The old type inference
  had a depth limit but could visit exponentially many repeated definitions;
  memoization preserves its results without that blow-up.
- `src/optimizer.rs`: recognizes the environment operand as register-free.
- `src/main.rs`: reports the actual profile and correct inspection metadata.

The original Adler-32 formulas, handler lifter, alias proofs and fixtures are
retained. There is no unsafe Rust and no new Cargo dependency. The new profile
certifies the complete wrapper token skeleton with only the payload literal
excluded: `3fdbcad7ec61989dadc90cad4226c55434a585d35083244dc4f491a945a90739`.
Formula, handler, alphabet or appended-code changes are rejected, while comments
and whitespace are tolerated. This intentionally supports this checked wrapper,
not arbitrary related VMs. Unsupported roots, capture bindings, instructions,
states, layouts and structures fail explicitly.

From the project root:

```powershell
cargo fmt --check
cargo test --locked -- --nocapture
cargo build --release --locked
cargo run --release --locked --example recover_base85 -- decompilation\message\target.original.lua decompilation\message --emit
.\target\release\luau-devirt.exe decompilation\message\target.original.lua --inspect
.\target\release\luau-devirt.exe decompilation\message\target.original.lua -o decompilation\message\target.cli.luau --force
.\tools\luau-0.747\luau-compile.exe --null decompilation\message\target.deobfuscated.lua
.\tools\luau-0.747\luau-analyze.exe decompilation\message\target.deobfuscated.lua
```

`python decompilation\message\diagnostics\run_validation.py` runs these checks,
records stdout/stderr/exit codes and hashes, compares the CLI/example output
and independent payload, and verifies unchanged originals. Python is only a
diagnostic/test launcher; the Rust engine itself has no Python requirement.
