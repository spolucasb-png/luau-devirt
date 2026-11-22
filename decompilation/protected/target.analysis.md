# Protected large SARP — partial static recovery

**Status: INCOMPLETE.** Version 0.2.0 remains an unreleased development
preview. This is not the requested complete program recovery and must not be
described as a fourth fully supported emission profile.

## Pinned input and independent certificate

- Repository: <https://github.com/spolucasb-png/luau-devirt>.
- Source URL: recorded in `acquisition.json`; the bundled bytes are authoritative.
- Input: 1,014,109 bytes; SHA-256
  `1496f231da48222f5aa52d84829e9ad4ef5481eb237f56c6be1b9645dd7136fe`.
- Git blob: `e78c7329b3b98793f79c5268e4ad42abf5a24018`.
- Profile: `sarp-four-fragment-dualstream-large-v1` / `VmProfile::SarpLarge`.
- Executable-token certificate:
  `7dfe43e60fb3b1d70aba68dadebf59c35b88280e436681315eb7ebab67cbd105`.
- 145,089 tokens; only `_pc0`–`_pc3` fragment literal contents are masked.
  Alphabet, fragment destinations/lengths, helper bodies and all other executable
  tokens remain part of the certificate. Comments/whitespace are not evidence.
  The five-fragment SARP certifier remains separate; selection rejects ambiguity.

## Available stages

| Stage | Result | Artifact |
|---|---|---|
| Original input | Pinned, unchanged inert bytes | `target.original.lua` |
| Transport | Complete, independently matched | `target.transport.bin` |
| Initial working-word image | Sparse, independently matched | `target.vm.bin` |
| Initializer/map/bias/root metadata | Derived, not invented | `target.metadata.txt` |
| Permutations | All three 16,384-u16 arrays | `permutation-{A,B,C}.bin` |
| Source model | Seven family trees, 32 helper signatures, operation tables | `target.handlers.parsed.txt` |
| Reachable bytecode lowering | Partial: 666 states, 62 pending | `target.partial-bytecode.txt` |
| Complete linked IR | **Unavailable** | No `target.ir.txt` |
| Default readable Luau | **Unavailable** | No `target.deobfuscated.lua` |
| Pretty readable Luau | **Unavailable** | No `target.pretty.luau` |

Parsed helper signatures are not proof that every helper is lifted. The partial
trace includes states, actual IR instructions, successor states, operation
selections, constant hash proofs and factory requests. It is not a complete
bytecode listing or source reconstruction.

### Transport and initialization

Fragments have lengths 177562/177551/177559/177548, destination offsets
0/177562/355113/532672, and actual copy order 2/1/3/0. The 710,220 encoded
bytes decode to 568,176 bytes / 142,044 u32 words; transport SHA-256 is
`b56b453499598f203dc50ffc04d515dd907fd30ec79f23610cc740c17832f69a`.
The independent reference uses positional Base85 digit weights and endian
reinterpretation, distinct from Rust's transport loop.

Initializer argument 110391195 derives K0 3350847355, initial K1 675551875,
and range `134160..=141177`. There are 7022 present words (four headers plus
7018 range words); 135023 entries are absent in the 142045-position one-based
image including index-zero sentinel. The slot map has 1734 meaningful entries
and 71 distinct slots. Bias/map artifact arrays include index-zero sentinels.

Root descriptor 134628 has entry 138920, bank 40, salt 53417, vararg mode and
zero captures. Root-entry formulas independently yield st 4225488239,
cs 156857040, stride 18, rotor 152047965, spill 0 and activated K1 1648390755.
The first child at descriptor 140545 has entry 136924, bank 94, fixed arity 1,
salt 38408 and lazy-code extent `136680+559`, mask 1648417297. All 559 lazy
decoded words match the independent digest
`75a889db15746511c3fcbfe5bcf159dc7d5f756c067076f02de1ba295837cc63`.

### Sparse artifact format

`target.vm.bin` is **not runnable bytecode**. Format:

1. Eight bytes: `LVDW`, version byte 1, three zero bytes.
2. Little-endian u32 number of positions (142045).
3. For each index, a presence byte: 0 = absent, 1 = present followed by one
   little-endian u32. Absent positions have no invented zero word.
4. No trailing bytes. Current size: 170145 bytes.

`diagnostics/artifact_check.py` independently reads this format, compares every
position with both metadata and the reference, and rejects malformed images.

## Exact semantic blocker

```text
PC 140992 family=2094 selector=1993, prototype=140804
unsupported helper 25 generic iteration: iterator packets, nested dispatcher
stop/exit continuations and changing rotor state require an explicit
structured-loop IR contract
```

The helper's source is preserved in `diagnostics/_h_25.txt`. A numeric
`ForPrep`/`ForLoop`, ordinary `Next`, skipped body or guessed post-loop state
would be incorrect. See `diagnostics/loop-contract-review.md` for the source
evidence and the required contextual CFG/structured-iteration contract.

AF invocation frames are cached, not always fresh. Child reads must follow
a parameter/capture/local write on the same invocation; retained cached cells
are not treated as nil. Captures snapshot parent values at closure creation;
table/cell references retain identity. Lazy layers are applied once per proved
descriptor/key and inconsistent extents/overlaps are explicitly rejected.
None of this proves complete equivalence while the loop remains unsupported.

## Reproduction

From the repository root:

```powershell
cargo run --locked --example recover_protected -- tests\fixtures\protected.luau decompilation\protected
# Expected exit 1: writes genuine partial artifacts, no complete output.
python decompilation\protected\diagnostics\probe.py
python decompilation\protected\diagnostics\transport_reference.py
python decompilation\protected\diagnostics\initialization_reference.py
python decompilation\protected\diagnostics\w_evidence.py
python decompilation\protected\diagnostics\prototype_reference.py
python decompilation\protected\diagnostics\hash_reference.py
python decompilation\protected\diagnostics\artifact_check.py
```

The references are diagnostic-only Python arithmetic/text readers. They never
invoke Lua/Luau, coroutines, the VM, recovered functions, an interpreter,
executor or Roblox client. Hash analysis uses proved constant inputs only;
there is no int32 preimage search. Static compilation/analysis is allowed only
for genuine generated readable output, which this target does not yet have.
