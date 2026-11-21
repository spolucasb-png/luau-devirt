# SARP static arithmetic reference — review

Independent diagnostics-only reference for the SARP wrapper preserved at
`decompilation/sarp/target.original.lua`
(SHA-256 `4518ff6626677a946e60b1f1fbf5e0e0bd6c2aa95a674c163864e763fff3d45f`,
git blob `b05c800c569376cc9f99c9be13e484f938d3949f`,
branch `sarp-profile`, baseline `3ffea19`).

Everything below is produced by `reference.py` — a **self-contained**
Python script (standard library only, no import of any probe module) that
recomputes every pre-dispatch SARP value with hand-transcribed arithmetic.
No Lua source, interpreter, executor or VM is ever invoked; no target
expression is evaluated; no lifting or code generation is performed (that
belongs to the parent Rust devirtualizer, which remains the single product
implementation). The pinned Rust values are used **only** in a final
comparison block and are never an input to any derivation.

## 1. Inputs and transcription sources

| fact | source |
| --- | --- |
| `_pc0.._pc4` literals, `_ab` alphabet | bounded lexical scan of the original source (see §2) |
| fragment `bcopy` order and extents | `diagnostics/initOnce.txt` lines 9–38 |
| Base85 digit order, `bswap`, transport LCG | `initOnce.txt` lines 40–57 |
| header stream `398991 + 3534337991`, salt, range | `initOnce.txt` lines 64–76, 97–105, 182–183 |
| K0/K1 construction, `_pe` probes | `initOnce.txt` lines 114–181 |
| KBOX, BL permutations, second-layer mask, RMAP, CM tables | `initB.txt` lines 6–120 |
| boot root header (7 words), frame seeds | `boot.txt`, `make.txt` |
| U dispatch (`_op`), string/number records, U-main | `U.txt` |
| exec-layer `_r` corrections | `exec.txt`, `initB.txt` 301–348 |
| family-2199 op table, rekey ops, `_h[18]` | `initB.txt` 3955–4213, 512–531 |
| RT dispatch table | `initB.txt` line 121 |

## 2. Self-contained lexical extraction (steering requirement)

`reference.py` implements its own bounded scanner:

* `scan_quoted(source, start, limit)` — bounded short-string literal scan
  (span capped at `MAX_LITERAL = 8192`, raw newlines rejected exactly like
  Lua's lexer);
* `unquote_lua_string(token)` — exact Lua 5.4/Luau escape semantics:
  `\a \b \f \n \r \t \v`, `\\ \' \"`, decimal `\ddd` (≤ 3 digits, ≤ 255),
  `\xXX` (exactly two hex digits), `\z` (skip following whitespace),
  `\<newline>` continuation;
* `escape_self_test()` — runs 15 positive cases and 5 rejection cases
  before any extraction happens (including `\256`, truncated `\x4`,
  unterminated literals, raw newlines, unsupported `\q`).

The independent scanner follows the shared lexer contract: escaped line
endings become LF bytes, and `\z` skips only ASCII Lua whitespace, not arbitrary
Unicode whitespace. The reference rejects absent second-layer words rather than
substituting zero, and its short root-entry verification stops before any
program-value-dependent operation.

The scanner reads the five `local _pcN = "..."` declarations (each must
occur exactly once) and the single `local _ab = bfrom("...")` alphabet
declaration (exactly one such literal exists in the source; the other
`bfrom(` calls take fragment variables). It validates that the alphabet is
85 distinct bytes and that every fragment byte is an alphabet member. The
wrapper token skeleton cert stays with the Rust side; this reference does
not reproduce or depend on it.

## 3. Transport (stages 1–3)

`bcopy` order as written in `initOnce`: `_pc2→1140`, `_pc4→2256`,
`_pc3→1700`, `_pc1→558`, `_pc0→0` with extents 560, 574, 556, 582, 558 —
these tile `[0, 2830)` exactly (558+582=1140, +560=1700, +556=2256,
+574=2830).

Word decode: for word *i*, the five bytes at `i*5..i*5+4` are Base85
digits with **the lowest digit first** (`_p+4` most significant), the
32-bit result is `bit32.byteswap`-ed, then XOR-ed with the transport LCG
state `_tk = (1147127625·17487 + 3048913621)`, which advances **before**
each word's XOR.

Result: `B`, 2264 bytes / 566 words,
SHA-256 `0b27a42d1fcea8d6a268848800b7cd04681167b15d007094a5082e3dd1f52d0f`
→ `reference.decoded.bin`.

## 4. initOnce (stages 4–5)

Executed state path (proven from the literal integer comparisons in
`initOnce.txt`):

```
31452 -> 26188 -> 11648 -> 46730 -> 0
```

* `sa = bxor(66482806, 3268698463)`; stream seed `bxor(sa, 1496625396)`;
  each step: `st = (st·398991 + 3534337991) % 2^32`, `bswap`, `^= st<<9`,
  `^= st>>5`, `^= st<<1` (all bit32-mod-2^32). One continuous state fills
  `wt[1..4]` and later `wt[ws..ce]` — never reset.
* `bw = r32(B,12)`; `m0 = bxor(sa,bw)`; `m1 = (m0·26797 + 1259477385) % 2^32`.
* `_fb` = f64 bits of `m1 + wt[4] + 1048576` (exact: the sum < 2^33 is
  exactly representable), read back as `_flo` (low u32) / `_fhi` (high u32).
* `_cz = clz(m0)·65537 + crz(bw)·257 + clz(wt[4])` with `clz(0)=crz(0)=32`.

**K0 semantics modeling (pcall/metamethod/coroutine).** These are the only
non-arithmetic facts, and each is a proven standard-Luau invariant rather
than an execution:

* `_p1 = pcall(function() local _e = {}; return _e + 1 end)` — arithmetic
  add on a plain table raises, so `_p1 = false` → `_pf = 0`.
* `_p2,_mv = pcall(function() return _mx + _mx[2] end)` — `_mx` has
  `__add`, so `__add(_, v)` returns `(v + _cz + _pf) % 2^32`; `_p2 = true`.
* The coroutine passes `(m1, _fhi, _mv)` on the first resume (`_p2` is
  true), yields `bxor(m1,_fhi)`, then yields `_mv`; both resumes succeed.
* `_pe` probes: `bit32.replace(3225577635,199,7,8)=3225576355`,
  `rawget({[2]=92},2)=92` (raw entry — `__index` never consulted),
  `_rt2-15 = 92-15 = 77` via `__sub` reading the same raw entry,
  `frexp/ldexp(55.5)` exact, `modf(55.75)=55`, `clamp(68,21,53)=53`,
  `"%04x:%d" % (39634,77) = "9ad2:77"`, `string.byte(string.reverse("9ad2"),1)=50`,
  `string.pack/unpack("<I4h")` roundtrip, `tonumber("o0h",31) = 24·31²+17 = 23081`.
  All are computed and asserted in `model_pe_checks()` → `_pe = 0`.

Hence `K0 = (m1 + _flo) ^ lrot(wt[4],11) ^ _fhi ^ bswap(m0) ^ _cz`
(`__call` contributes `bxor(m0, _pe) = m0`; `__len` contributes `_cz`).

**Values:** `K0 = 1302175439`, `K1₀ = bxor(4021752008, 3067287787) =
1499727907`, `ws = 190`, `ce = 507` (inclusive count **318** — the
"317?" in the work order resolves to 318 words at `ce - ws + 1`),
`_cz = 1544`, f64 bits `41d547ed97c00000`.

## 5. initB (stages 6–7)

Executed state path (first resume passes `_st0 = 26216`):

```
26216 -> 53782 -> 46996 -> 23122 -> 0
```

* 26216: KBOX — `ks = 706272505`, `ks = ks·26663 + 4214497697`, 64 values
  `1 + ks % 200000`.
* 53782: BL permutations — identity tables shuffled downward
  (`i = 16383..1`, `ka/kb = ka/kb·17577 + 419902917`, swap at
  `ka % (i+1)`), then `BL_C[pa] = pb·4 + ((i·17+1833)%16384)·2 +
  ((pa>>7&1)^(pb>>10&1)^1) + 12836`, then the top two bits of every
  `BL_A`/`BL_B` entry are set from LCG bits 20–21.
  `cyield(K0)` is resumed with `bxor(_ibv or 0, K0) = bxor(K0,K0) = 0`,
  so `_yn == 0` and the second-layer mask runs:
  `k2 = K0 ^ 2372119159`, per word `k2 = k2·7745 + 888415943`,
  `W[wi] ^= BL_A[k2 & 16383] ^ (BL_B[(k2>>14)&16383] << 16) ^
  KBOX[1 + wi%64] ^ BL_C[(k2^wi) & 16383]` for `wi ∈ [190, 507]`.
* 46996: RMAP — `rk = 3402759894 ^ K0`, per word
  `rk = rk·24307 + 1800847725`, `pw = r32(B, ce·4 + wi·4) ^ rk`, unpacked
   into 118 u16 slots (all in 1..52; engineered role aliases repeat across
   three bank windows, while other slot multiplicities vary).
* 23122: `C_*` slot names from RMAP[1..15], then `CM` (25), `CM2` (26),
  `CM3` (23).

RMAP[1..6] = `[52, 50, 35, 21, 29, 28]`; KBOX[1..4] =
`[105553, 21586, 102585, 4074]`. `reference.slots.json` carries the full
118 slots, 64 biases and the three CM tables; `reference.bl.bin` carries
`BL_A‖BL_B‖BL_C` (98304 bytes) with per-table SHA-256 in the metadata.

### 5.1 Dormant branches (steering: no executed checksum)

* initOnce's `_ist ≥ 55357` branch (`_dx = bxor(r32(B,12), _dm)`;
  `_dm = (_dm + _dx) % 2^32`) is **unreachable**: both predecessors of the
  46730 region (state 11648 and the branch itself) write exactly 46730,
  and entry is 31452. `_dm` stays `52699`.
* initB's `_ist < 23122` branch (`_dy = bxor(_dm, blen(B))`; requires
  `_dm == 2264`) is **unreachable** from the entry state 26216; the
  executed path never validates the second resume's `_dm` argument.

Consequently **no `_dm`-style checksum ever executes on the real path**,
and this reference neither computes one nor treats `_dm` as validated.
Both traces and both dormancy proofs are stored verbatim in
`reference.slots.json` → `control_flow` and in the metadata
(`init_once.executed_trace`, `init_b.executed_trace`, dormant entries).

## 6. Root prototype (stage 8)

`tk = K0 ^ ((2674807212 + 2921856046) % 2^32)`, `hw = tk ^ 774880 = 501`.
The 7 header words at `W[501..507]` decode to:

| field | value |
| --- | --- |
| entry | 442 |
| est | 1234081515 |
| esh (dispatch token) | 56332 → family **2199** |
| mtA / mtB | decoded in metadata |
| cStart / cLen | decoded in metadata (root uses entry, not cStart) |
| size / uc / ar / da | 52 / 0 / 0 / 0 |
| rb (bank) / ps (salt) | 15 / 26339 |

`uc = 0` and `da = 0` match the vararg-mode, capture-free root contract.

**U-main frame seeds** (`boot.txt`'s `U(489, _v0, ..., 60285, ..., 792406, 697)`
with an empty module vararg, `_v0 = nil` → index 2268):

* `_ds = bxor(792406, 155290) − 936396 = 936396 − 936396 = 0` exactly;
* proven identity: the BL_C construction writes, at index `b`,
  `exp(b, BL_B[b]) + 12836`, and U-main reads `BL_C[BL_A[u] & 16383]` with
  `u == b`, so `_sbz = 12836` for **every** U-main-seeded frame,
  independent of the permutation state and of the vararg type;
* therefore `_p1 = BL_A[2268] & 16383 = 15672`, `_p2 = exp(2268) = 28514`,
  and `_tg = 74056 + 12836 + 0 = 86892` — the same `_tg` (and the same
  string salt) holds for number/string varargs too.

Every prototype's initial decode state is `est + 86892 (mod 2^32)`;
for the root: `st₀ = 1234168407`.

## 7. Root-entry opcode walk (stage 9)

The root dispatches in family 2199 — the smallest handler
(`initB.txt` 3955–4213), whose complete op table is transcribed in
`reference.py` (`FAMILY_2199_LEAVES`): five MO metamethod leaves, four
register-move leaves, two return leaves, two `_h[18]` call leaves and the
**two rekey leaves** (op `< 444` and op ∈ `[1224, 1358)`). The rekey fires
only while `K1 == bxor(4021752008, 3067287787)` — i.e. exactly once in a
whole run.

Walk from `(ip=442, st=1234168407, sh=56332, rb=15, ps=26339)`:

1. `op = ((W[442] − st·11 − ps) % 2^32) − 6806 = 1224` → **rekey leaf 2**:
   `cs = (W[447] − st) % 2^32`,
   `K1 = bxor((W[443] − st·9) % 2^32, K0, ps, st, cs) = 2912755157`.
   The same leaf is the loop setup: `_ls = bxor(W[444], st) = 22`,
   `_sr = 871384683`, markers stored into the frame slots, `C_RBS = 22`,
   `C_RBE = 59`, then `ip = 448`, `st = lrot(st·219169+706323,19)^326053779`.
2. `op = 1006` at `ip = 448` → `_h[18]` call leaf: with the statically
   stored markers, `_cur` and `_nr` are exact; the handler's post-call
   `_r = _nr` cancels the `_h[18]` result offsets, so the call target is
   `(ip = 453, st = 1326605459, sh = 40052)` → family **1901** — a family
   transition, where the walk stops by design (family 1901's op table
   belongs to the parent's full analyzer).
   Bank consistency was verified arithmetically: `_h[18]` stores
   `bxor(_nr, SMA)` at the old `_u2s` slot (RMAP[19] = 43) and the
   rotated bank's `_pxs` slot is RMAP[60] = 43 — the RMAP 4-fold slot
   groups make the exec layer's marker read land on the same slot.

**Pool key conclusion:** the string-pool key is `K1 = 2912755157` after
the single root-entry rekey (before it, only the initial
`1499727907` would be in effect, and no string load precedes the rekey).

## 8. Const string records (stage 10)

Record layout in `B` (U string path, `_op = 38746`): at byte offset
`_o = _ua ^ 1528192`, `_ps = word(_o) ^ 1573349377`,
`n = word(_o+4) ^ 1638974510 ^ _ps`, body at `_o+8`, keystream
`_k = _ps ^ K0 ^ pool ^ 12836` then `k = k·22439 + 195899001` per
word/byte.

A **full offset scan** (every byte offset in `B`) accepts a record iff
`_o + 8 + n ≤ 2264`; a random word passes with probability ≈ 5·10⁻⁷, so
the 35 accepted offsets are the true record extents (expected false
positives ≈ 0.001). Under the root-entry pool key **all 35 bodies are
printable** and reproduce the application's constant strings; under the
initial pool key only one 3-byte coincidence (`#%;` at offset 232, which
is `IsA` under the rekeyed key) appears.

The 35 records (offset, `_ua`, body): `game`, `ReplicatedStorage`,
`GetService`, `Events`, `FindFirstChild`, `MothDialogueBindable`, `assert`,
`BindableEvent`, `IsA`, `MothDialogueBindable not found. Run this inside
Nullscape.`, `Text`, `hey its me its celestial`, `EntranceAnimation`,
`horizontal`, `ExitAnimation`, `flash`, `Lifetime`, `Position`, `UDim2`,
`fromScale`, `InitialSounds`, `NoIdle`, `Markups`, `MarkupType`, `Color`,
`StartIndex`, `EndIndex`, `math`, `huge`, `Value1`, `Color3`, `fromRGB`,
`Shaky`, `Value2`, `Fire` — full table with hex bodies in
`reference.strings.json`.

## 9. Const number records (stage 10, U number path)

Base offset `bxor(W[1], 2115480298, K0) = 16`; record *i* at
`16 + (i−1)·8`; note the number path folds the salt into the pool key
first (`_k1 = bxor(pool, 12836)`) before the rotate/shift word keys. The
scan lists 281 candidates; the application's float constants identify the
three real records:

| i | `_ua` | offset | value |
| --- | --- | --- | --- |
| 3 | 1071767 | 32 | 0.95 |
| 4 | 1071760 | 40 | 7.5 |
| 5 | 1071761 | 48 | 0.5 |

(UDim2.fromScale(0.5, 0.95) and Lifetime 7.5 in the recovered
application.) The remaining candidates are payload bytes that no load
instruction references.

## 10. Cross-check against the parent Rust (comparison only)

`reference.metadata.json` → `cross_check` compares, field by field, the
values derived here with the parent Rust pins; **the pins are never read
by any derivation stage**:

| field | parent Rust | this reference | match |
| --- | --- | --- | --- |
| payload SHA-256 | `0b27a42d…d1f52d0f` | `0b27a42d…d1f52d0f` | ✓ |
| K0 | 1302175439 | 1302175439 | ✓ |
| decoded range | 190..507 | 190..507 | ✓ |
| root word | 501 | 501 | ✓ |
| entry pc | 442 | 442 | ✓ |
| payload words | 566 | 566 | ✓ |

Analyzer-level facts recorded for comparison (not reproduced here — no
lifting/codegen in this reference): the parent analyzer reports 178
states, 43 pcs, 30 structured, 35 strings, 3 nums, 8 calls and a
60-line recovery of the same application as the previous run, produced
independently — neither side is treated as a golden copy. This
reference's corresponding independent facts: 35 string records, 3
program number constants.

## 11. Files and metadata schema

| file | contents |
| --- | --- |
| `reference.py` | the self-contained reference (this review's subject) |
| `reference.decoded.bin` | 2264-byte decoded payload `B` |
| `reference.words.json` | 566 raw payload words + 566 decoded `W` words (null outside `1..4 ∪ 190..507`) |
| `reference.slots.json` | RMAP (118), KBOX (64), C_* slots, CM/CM2/CM3, root header, boot frame, control-flow traces with dormancy proofs |
| `reference.strings.json` | pool keys + rekey event, 35 string records (bodies + hex, both pool keys), 281 number candidates, root-entry walk trace/op table |
| `reference.bl.bin` | `BL_A‖BL_B‖BL_C` (98304 bytes) |
| `reference.checkpoints.txt` | the seven checkpoint lines (dumped before integration) |
| `reference.metadata.json` | schema below |

`reference.metadata.json` schema:

```
profile, generated_utc, scope,
source{path, sha256, expected_sha256, git_blob_sha1, bytes, baseline_commit, extraction},
transport{fragments{…sha256}, fragment_lengths, bcopy_order, alphabet_sha256,
          alphabet, alphabet_sites, encoded_bytes, base85, transport_lcg,
          payload_bytes, payload_words, payload_sha256, payload_file},
init_once{executed_trace, dormant_dm_branch, sa, st_seed, header_words, stream,
          bw, m0, m1, float_value, float_bits, float_lo, float_hi, cz, pf, pe,
          environment_checks, k0, k1_initial, ws, ce, range_count},
init_b{executed_trace, dormant_dy_branch, kbox_sha256, kbox, second_layer,
       rmap, rmap_source, cm_tables, permutations{…sha256, samples, file}},
root{tk, hw, header_words, entry, est, esh, mtA, mtB, cStart, cLen,
     size, uc, ar, da, rb, ps, family, boot_frame{…}},
root_entry_walk{family, initial, rekey, pool_key_after_rekey, call,
                stop_reason, op_table, trace_file},
strings{scanned_offsets, printable_under_root_entry_pool,
        printable_under_initial_pool, salt, records_file},
numbers{base_offset, candidate_count, program_constant_count, records_file},
outputs[…], checkpoints[…], cross_check{comparison_only, fields, all_match,
        analyzer_facts_parent_rust, this_reference_scope}, invariants[…]
```

Reproducibility: `python decompilation/sarp/diagnostics/reference.py`
regenerates every output deterministically (pure arithmetic over the
pinned source; the only timestamp is `generated_utc`).

## 12. Integration notes for the parent Rust

Directly comparable artifacts: payload bytes/SHA, `W` words
(`reference.words.json`), KBOX/BL tables (`reference.bl.bin` + SHA-256s),
RMAP/C_* /CM tables, K0/K1/range, root 7-word header and field split,
`_tg = 86892` initial decode state, family-2199 op table, the rekey event
(`K1 = 2912755157` from word 442/447 operands), the first call target
`(453, 1326605459, 40052 → family 1901)`, the string-record extents/bodies
and the three program number constants.

Deliberately out of scope here (owned by the parent): the full
multi-family symbolic walk (families 359/1901/755/7480/8434/1868), prototype
lifting, register-slot binding, codegen, and any certification logic — the
Rust implementation remains the single product implementation; this
reference only cross-checks its inputs.

## 13. Residual notes

* The "317?" word count from the work order resolves to **318**
  (`ce − ws + 1` with `ws = 190`, `ce = 507`).
* The single initial-pool printable hit at offset 232 is a 3-byte
  coincidence; the same offset decrypts to `IsA` under the root-entry key.
* The reference deliberately performs no `_dm`/blen(B) checksum: both
  such branches are proven dormant on the executed path (§5.1).
