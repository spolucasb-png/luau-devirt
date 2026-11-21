# Certified SARP recovery

## Proven result and provenance

The source was retrieved from the user-supplied raw GitHub URL with HTTP 200,
no redirects, and valid UTF-8. `acquisition.json` records the URL, UTC retrieval
timestamp, selected response headers, size, line count and fingerprints:

- Source: 118,433 bytes, two lines, longest line 118,399 bytes.
- Source SHA-256: `4518ff6626677a946e60b1f1fbf5e0e0bd6c2aa95a674c163864e763fff3d45f`.
- Git blob SHA-1, independently computed including the `blob LENGTH\0` prefix:
  `b05c800c569376cc9f99c9be13e484f938d3949f`. This matches the supplied blob ID;
  it is not substituted for SHA-256.
- Original and working copies were written separately; neither was edited.

Baseline: `main`, `v0.1.0`, commit
`3ffea1943b15feffeceb29f6193238163d055511`, initially clean. Formatting, locked
Cargo tests and release build were run before implementation; all returned 0.
Cargo reported 112 passing tests, including one internally skipped optional
local-parser check. The official compile/analyze checks and both existing
profile regressions ran. Exact baseline commands/stdout/stderr are retained in
local `logs/baseline.json` and companion files, excluded from release packaging.
Work is isolated on `sarp-profile`; no reset or discarded user work was needed.

The old CLI rejected SARP with exit 1 because it inferred the rotor profile from
the `_b85` identifier. SARP actually allocates `_b85` as a buffer, not the rotor
profile's quoted-string binding. New selection checks each full certified token
skeleton and assigns an explicit `VmProfile` tag. Neither `_b85` alone nor map
length determines the profile. Ambiguous/changed wrappers are rejected. The
older Adler validator and rotor fingerprint/algorithms remain unchanged.

## Certification

Profile: **`sarp-fragment-dualstream-7word-v1`**.

Wrapper token fingerprint:
`e81814ff9d295dc39e3888a8e60b4a484140b627f52ef3b8c3215b17afe92f3b`.
The shared quoted-string lexer/tokenizer produces 52,501 tokens without needing
a formatter. The fingerprint joins token spellings with LF and replaces only
the five `_pcN` fragment literal tokens with `PAYLOAD:_pcN`. The alphabet,
copy offsets, cipher formulas, initializer, helper/operation tables, comparison
trees, and trailing boot call remain certified. Whitespace/comments may change;
new executable code, different alphabets, helpers or formulas cannot pass.

This is a checked wrapper profile, not a universal SARP decompiler. Payload
bytes are decoded from the current literals; output is never copied from an
old golden fixture. The supplied SARP payload happens to recover the same
dialogue program as the earlier rotor specimen, independently through different
keys, descriptors, operand expressions and transitions.

## Source-grounded transport

Declarations are ordered 4, 2, 3, 1, 0. Assembly is defined by actual buffer copy
destinations, not declaration order:

| Fragment | Destination | Exact bytes |
| --- | ---: | ---: |
| `_pc0` | 0 | 558 |
| `_pc1` | 558 | 582 |
| `_pc2` | 1140 | 560 |
| `_pc3` | 1700 | 556 |
| `_pc4` | 2256 | 574 |

Copy execution order is 2, 4, 3, 1, 0. These disjoint regions cover all 2,830
encoded bytes. The `_ab` literal contains 85 distinct bytes; `_d85` maps each
byte to its zero-based alphabet index. No padding, shorthand, ignored invalid
character or whitespace filtering exists.

Each five-character group computes
`d[p] + 85*d[p+1] + 85^2*d[p+2] + 85^3*d[p+3] + 85^4*d[p+4]`.
Thus the first character is the **least significant** digit. The source then
applies `bit32.byteswap` to the low 32 bits and writes little-endian u32. A
second, separate transport stream starts at 1,147,127,625, advances
`*17487 + 3048913621 mod 2^32`, and XORs every decoded word in order.

Resulting `B`: **2,264 bytes / 566 raw words**, SHA-256
`0b27a42d1fcea8d6a268848800b7cd04681167b15d007094a5082e3dd1f52d0f`.
The 16-byte header copy-out/copy-back changes no bytes. This is not the previous
rotor profile's transport.

## Initializer and second word cipher

`boot` passes `66482806 XOR 3268698463 = 3240235817` to `initOnce`. Its
flattened control follows 31452 -> 26188 -> 11648 -> 46730 -> 0, then resumes
`initB` as a coroutine. Each header word advances the stream from
`sa XOR 1496625396` through:

1. `*398991 + 3534337991 mod 2^32`;
2. byte swap;
3. XOR with left shift 9;
4. XOR with right shift 5;
5. XOR with left shift 1.

After four headers the same stream continues over 190..507 inclusive; it is
not reset. Positions 5..189 remain absent, not invented zeros.

Master-key derivation reads **raw `B` word four** at byte 12:

```text
m0 = sa XOR raw_word4
m1 = m0*26797 + 1259477385 mod 2^32
float_bits = f64_bits(m1 + decoded_header4 + 1048576)
lo = low32(float_bits); hi = high32(float_bits)
cz = leading_zeros(m0)*65537 + trailing_zeros(raw_word4)*257
     + leading_zeros(decoded_header4)
K0 = ((m1+lo) mod 2^32) XOR rotate_left(header4,11) XOR hi
     XOR byteswap(m0) XOR cz
```

The source hides these equations behind literal table metamethods, `pcall` and
two coroutine yields. No such Lua operation is executed by the decoder.
Static type/algebra proofs establish that plain `{}` + 1 fails, the literal
metamethod arithmetic succeeds, both yields/resumes succeed, and the standard
bit replacement/rawget/subtraction, frexp/ldexp/modf/clamp, format/sub/reverse,
pack/unpack and base-31 conversion identities hold. Under those certified
ordinary Luau library semantics, `_pe = 0`. Changed library behavior is outside
the profile contract; no environmental execution is used to guess `_pe`.
Some flattened `_dm` anti-tamper alternatives are dormant, not successful
runtime checks. The independent reference documents the live initializer path.

Recovered `K0 = 1302175439` (0x4d9d9ecf), initial
`K1 = 4021752008 XOR 3067287787`. The range is derived from header 2 and header 3
using masks 3678364643 and 3087163986 with K0.

`initB` creates 118 u16 physical map entries after word 507, using
`rk = 3402759894 XOR K0`, then `*24307+1800847725`. All used slots are 1..52.
Its 64 immediate biases use seed 706272505 and `*26663+4214497697`, followed
by `1 + state % 200000`.

BL_A/BL_B are 16,384-entry permutations shuffled with seeds 1933532995 and
2171122303, multiplier 17577 and addend 419902917. BL_C is indexed by the
permuted A value and contains:

```text
(pb*4 + ((index*17+1833)%16384)*2
 + ((pa>>7)&1) XOR-bit-combined with ((pb>>10)&1) and 1
 + 12836) mod 65536
```

The precise expression is
`pb*4 + (...) *2 + (((pa>>7)&1) XOR ((pb>>10)&1) XOR 1) + 12836`.
Afterwards, A/B receive two extra PRNG tag bits in their high u16 bits. Witness
uses mask these tags off; the second word cipher and hash gate use them intact.

`initB` yields K0. `initOnce` resumes it with `(yielded_K0 XOR K0) = 0`, which
enables an additional word decryption over the same inclusive range. Its seed
is `K0 XOR 2372119159`, stream `*7745+888415943`, and XOR mask combines tagged
A, tagged B shifted 16, KBOX indexed by `1 + word_index % 64`, and BL_C. There
are **322 populated words**: four headers and 318 range words.

## Descriptors, constants and factory boundaries

The source-derived root descriptor is **word 501**, not a heuristic candidate:

| Field | Source word/mask | Recovered |
| --- | --- | ---: |
| entry | p+0 XOR 1151433088 XOR K0 | 442 |
| frame/bank bits | p+1 XOR 4028605236 XOR K0 | frame 52, bank 15 |
| arity/captures/salt bits | p+2 XOR 1209284937 XOR K0 | vararg mode, 0 captures, salt 26339 |
| factory code start | p+3 XOR 2871857514 XOR K0 | dormant in root boot path |
| decode key | p+4 XOR 3098405659 XOR K0 | 1234081515 |
| dispatch token | p+5 XOR 445800084 XOR K0 | 56332 -> 2199 |
| factory code length | p+6 XOR 2766250242 XOR K0 | dormant in root boot path |

The parameter/capture records start at p+7, not p+5. Capture destinations are
the high u16, and fixed parameter halves are high then low. The source's
`make`/AF factories support additional lazy code/factory behavior, but none is
called by the certified dispatcher leaves. Only one prototype/user function is
reachable. Unsupported captures/fixed-root modes are explicit errors rather
than empty invented bindings.

`U` has ten scrambled arguments. `_um` is argument 5 and `_ub` is argument 8
(zero-based); its selector XOR mask is 20993. Witness channel 47484 has
`(792406 XOR 155290)-936396 = 0`. The permutation correction is always
12,836, yielding initial entry tag **86,892**. Conditional channel
`(13444 XOR 20993)` similarly has zero displacement. Both facts are proved for
all supported value-type index choices, not guessed from nil alone.

String channel 38746..40598 resolves byte offset `reference XOR 1528192`,
seed `readu32 XOR 1573349377`, length `readu32(offset+4) XOR 1638974510 XOR seed`,
then body stream `*22439+195899001` starting with seed XOR K0 XOR K1 XOR 12836.
Whole words precede separately keyed trailing bytes.

Number channel 40599..56274 resolves index `reference XOR 1071764`,
base `W[1] XOR 2115480298 XOR K0`, and two f64 halves masked with
`495004947+index*464691`, `1772561933+index*290983`, K0 and rotated extra key.
Only referenced records are decoded; there is no speculative record scan.
The entry instruction rewrites K1 once using its decoded operands; it is
tracked as decoding state, not kept at its initializer value.

The reachable program references **35 strings and three f64 constants**
(0.5, 0.95 and 7.5, exact bits retained). It uses biased integer immediates for
markup indices, boolean construction, RGB 255/45/45 and shaky values.

## Dispatch, operations and bounded state

RT has 34 token/family bindings and seven `_dr` definitions. Three substantive
families are reached:

```text
1901: xor(W[ip], key, salt) - 35367
359:  xor(W[ip], rotate_left(key,16), salt*53) - 7411
2199: ((W[ip] - key*11 - salt) mod 2^32) - 6806
```

The token parser selects actual comparison-tree leaves, resolves their operand
expressions, and lowers their effects into the existing typed IR. Keys advance
through the specific leaf's LCG/rotate/XOR expression, not a reused rotor rule.
MO/MO2 dispatch operation functions through different K1-dependent masks.
Their exact source operations are used; unknown operations fail with address,
family and selector. Missing private-table operation functions produce a proved
unchanged destination only where the source guards `if _mv then`.

Thirty-six `_h` functions are transition helpers, not 36 opcodes. The live
transition helpers are 18, 35, 1, 5, 23 and 27. Helper 15 is referenced by
dormant stop alternatives. `target.handlers.md` catalogs the helper formulas,
family-specific masks and decoys.

SARP's normalized phase is
`(rotor + 4294002830 + F[pys] + (1-band(rotor,1))*65537) mod 2^32`.
Every entry forces the rotor odd; its LCG has odd multiplier 433233 and even
addend 2142828636, so oddness is preserved. The correction term therefore
vanishes, by proof. The source writes the next phase as an encoded constant.
Family-specific output masks cancel exactly with dispatcher inverses. Outer
frame masking is additive PC*rotor coefficient 5, key coefficient 61 and shape
coefficient 137, not the old rotor profile's XOR convention.

The bank ring is 15, 37 and 59, stride 22, ceiling 59. The phase role is fixed;
parallel source rotations preserve logical u1/u2 in two distinct canonical
registers. Every edge checks all four physical identities and injectivity.
Other data slots retain their identity; control/rotor cells cannot be used as
program operands. This is state-dependent bijective renaming, not merging live
values using the old seven-field alias graph.

The state key contains PC, decode key, bank, token, prototype salt, normalized
phase, window, bank ceiling, K1, and a finite lattice of proved integer 0/1
register facts. Non-0/1 facts become unknown, never coerced booleans. The
60-round double-hash helper 27 is evaluated only for an int32 subject proved
constant through typed IR facts; unknown subjects fail explicitly. Its two
hash comparisons and separate PC/shape offsets are fully transcribed. No
int32 brute force or arbitrary program-expression execution occurs.

The trace explicitly records which helper ran. Helper 27 is reached in two
analyzed states, both with a proved constant subject. `HashProof` records the
subject, current keys, masks, hash comparisons and offsets.
`diagnostics/hash_reference.py` independently recomputes those fixed 60-round
cipher calculations; it never invokes the source helper or any Lua program.

Limits: 8 MiB source, 1 MiB transport budget, exact certified 2,264-byte layout,
512 states, 8,192 worklist pops, inherited 96 expression/statement depth,
4,096 statements per handler region, 256 operand-offset budget, 64 temporary
registers per address, 4,096 referenced strings and 1 MiB aggregate string
bytes. Permutation and predicate work use fixed loop counts.

## Recovered program and validation boundaries

The raw trace has **178 states and 43 instruction addresses**, no Raw/unresolved
instruction. Initialized nonescaping integer control specialization and pure
dead-copy elimination reduce it to **30 data blocks**. The generic passes are
reused only after their source/IR domain assumptions are met. Potentially
effectful calls and table reads/writes remain. The shared captured-environment
emitter uses explicit snapshots, postdominators, nil/false-preserving joins and
proved scalar packet projections.

The output retrieves `ReplicatedStorage.Events.MothDialogueBindable`, checks
its type, builds dialogue options with horizontal/flash animations, lifetime
7.5, position fromScale(0.5,0.95), empty initial sounds, NoIdle=false, red Color
and Shaky markups, then fires the event. The eight external call sites remain
in order, including both separate `math.huge` lookups. It returns no values:
reachable stop alternatives produce code 135301, which `boot` maps to empty
return. Packed/multivalue return alternatives are dormant, not fabricated.

`target.ir.txt` retains raw typed instructions; `target.structured-ir.txt`
retains transformed data blocks; `target.bytecode.txt` records every analyzed
state, operand span, instruction effect and successor. Generated output
SHA-256 is `e9c1055148831d6bd553fbfebedd4d4fedd19ebc92f6dba54aab6cedbe2fbc7b`.
This equality with the earlier script is a **validation observation**, never
an implementation dependency. Source names/comments/line metadata are not
recovered or invented.

Independent arithmetic evidence, final commands, exact exit codes, test counts
and compiler/analyzer results are recorded in `target.validation.md`.
Neither original nor recovered code was executed; no Roblox client/executor
was used, including for syntax checking.

## Reproduction

```powershell
cargo fmt --check
cargo test --locked -- --nocapture
cargo build --release --locked
python decompilation\sarp\diagnostics\reference.py
cargo run --release --locked --example recover_sarp -- tests\fixtures\sarp.lua decompilation\sarp
python decompilation\sarp\diagnostics\hash_reference.py
.\target\release\luau-devirt.exe decompilation\sarp\target.original.lua --inspect
.\target\release\luau-devirt.exe decompilation\sarp\target.original.lua -o decompilation\sarp\target.deobfuscated.lua --force
.\tools\luau-0.747\luau-compile.exe --null decompilation\sarp\target.deobfuscated.lua
.\tools\luau-0.747\luau-analyze.exe decompilation\sarp\target.deobfuscated.lua
.\tools\verify.ps1 -RequireExternalTools
.\tools\package.ps1 -SkipBuild
```

The Python programs are independent diagnostics, not required by the product
decoder, CLI, or Cargo tests. Only those reviewed source scripts are allowlisted;
their generated logs, scratch dumps and local tools are excluded.

## Exact source changes

New Rust files: `src/sarp.rs`, `examples/recover_sarp.rs`,
`tests/sarp_profile.rs`.

Modified Rust files:

- `src/ir.rs`: explicit `VmProfile` metadata tag; tuple/return/instruction
  contracts are unchanged.
- `src/decoder.rs`: token-certified profile selection and Adler profile tag.
- `src/base85.rs`: rotor profile tag and crate-private access to its existing
  certificate, bounded grammar and IR-only specialization/compaction helpers.
  No rotor cipher formula or certificate bytes were changed.
- `src/cfg.rs`: SARP analysis routing.
- `src/lib.rs`: exports the isolated SARP module.
- `src/main.rs`: accurate profile/help/inspection output.
- `tests/fixtures_present.rs`: requires both additional bundled fixtures.

Additional changes: `Cargo.toml`/`Cargo.lock` version 0.2.0, `.gitignore`,
`.gitattributes` (byte preservation for the new protected input/artifacts),
`AGENTS.md`, `README.md`, `VM_FORMAT.md`, `VALIDATION.md`, `CHANGELOG.md`,
`tools/verify.ps1`, `tools/package.ps1`, and fixture documentation. The untouched
SARP source is bundled as `tests/fixtures/sarp.lua`. Recovery artifacts and
reviewed independent Python references are new allowlisted files.

`src/lifter.rs`, `src/aliases.rs`, `src/optimizer.rs`, `src/specialize.rs`,
`src/codegen.rs`, existing protected specimens and existing readable goldens
were not rewritten.

Post-review guards explicitly check helper context, cache fallback key/channel,
ignored-argument purity, unknown short-circuit RHS effects, plain-arm state
updates, exact integer arithmetic bounds, extraction shifts, and descriptor
offsets. Luau buffer operations are defined little-endian; `to_bits()` produces
logical IEEE-754 bits, so no native-host-endianness guess is required.
