# Independent static review — protected/large-SARP target

Scope: source-only, arithmetic-only. No Lua/Luau, VM, coroutine, executor,
Roblox client or recovered program function was run. No preimage was searched.
Nothing here claims devirtualization or full transport recovery. The parsed
helpers are *parsed*, not "understood".

Pinned source: `target.original.lua` SHA-256
`1496f231da48222f5aa52d84829e9ad4ef5481eb237f56c6be1b9645dd7136fe`.
Transport: `b56b453499598f203dc50ffc04d515dd907fd30ec79f23610cc740c17832f69a`,
568176 bytes / 142044 words / 142044 words decoded.

## 1. W / header / slots / biases / permutations — exact comparison

Artifact: `w_evidence.py`, `w-evidence.json`. Three-way comparison of
(a) the pre-Rust `initialization-reference.json`, (b) a fresh re-derivation from
the pinned source (`initialization_audit.initialize`), and (c) the Rust
`target.metadata.txt` + `permutation-*.bin`.

- **46/46 checks pass.** All **142045** W positions compared, including absent
  ones: 7022 populated, 135023 absent; W index set in Rust metadata is complete
  and every present/absent state agrees three ways.
- Header words 1–4 `[1753978936, 1496324374, 2523024251, 902740071]`, `K0 =
  3350847355`, float bits `41eac1f2ec800000`, zero counts, range
  `[134160, 141177]`, all **1734** slots (distinct 71, max 71), all **65**
  biases, and permutations A/B/C (16384 u16 words each) agree byte-for-byte and
  by SHA-256 digest.
- Root descriptor fields and the 15 certified control-slot roles agree.
- Representation caveat handled: the pre-Rust JSON stores `float_bits` as raw
  little-endian byte hex (`000080ecf2c1ea41`); Rust prints the u64 value
  (`41eac1f2ec800000`). They are the same bits reinterpreted, not a mismatch.
- This is **initialization fidelity only**. 135023 absent positions are
  legitimate and the instruction stream is not certified by this comparison.

## 2. 320-round hash reference and known-answer vectors

Artifact: `hash_reference.py`, `hash-reference-results.json`.

`hash_gate_source()` is transcribed by hand from `_h_8.txt` / `_h_9.txt` /
`_h_28.txt`, lines 22–73 (identical core in all three; only the dispatch tails
differ). It models the **16-byte scratch** with real little-endian reads/writes:

- seed words `_w0, _h1, _h2, _t3` at offsets 0/4/8/12,
- `wf64` writes 8 bytes at `(_hr & 1) * 8`, overlapping those words,
- `ri16` reads a **signed** 16-bit word at `((_tr >> 3) & 7) * 2`, then
  `+65536 % 65536` (source line 54),
- `KBOX[1 + ((_hr ^ round) & 63)]` mixing,
- xor writeback at `(round & 3) * 4` (source line 62),
- 320 rounds, then `_pk1/_pk2` and `_kvIp/_kvSh`.

Parameter correspondence proved from source text: source
`_x, _m32, _sv, _st, (K1 ^ _sbz)` ↔ Rust `value, mask, extra, state,
(pool ^ SALT)`; therefore `w0 = value ^ mask ^ pool ^ SALT ^ extra`.

A **separate** transcription of `src/sarp_large/control.rs:355-468`
(`rust_control_hash`) is used only as a cross-check. Six known-answer vectors,
each built only from proved constants (root/child entry PCs, K0, K1, SALT,
`_sma/_smb/_ek`, the make cookie `K1^SALT`, the activated mask, small int32
subjects 0/1/SALT/16383). Source core == Rust transcription on all six,
including final `hr/tr` and the 16-byte scratch hex.

| inputs (value,mask,extra,state,pool) | pk1 | pk2 | kv_ip | kv_sh |
|---|---|---|---|---|
| 138920, 675590897, 43122, 4225420928, 675551875 | 2204169260 | 2982472156 | 3556667885 | 583177525 |
| 136924, 1648417297, 608916103, 2784560490, 1648390755 | 2911021113 | 1868075030 | 2110936601 | 81601156 |
| 0, 675590897, 0, 4225420928, 675551875 | 1393204744 | 4222276010 | 3265043314 | 3891493306 |
| 1, 1648417297, 1981805674, 2784560490, 1648390755 | 282847150 | 1571344452 | 1782690477 | 2697319067 |
| 43122, 675590897, 2601618823, 4026385912, 675551875 | 2603817584 | 2991986275 | 981933046 | 2435227184 |
| 16383, 1648417297, 43122, 2784603416, 1648390755 | 4122545956 | 544180572 | 2232344480 | 1983702062 |

Full checkpoints (h1/h2/h3/t4, d1/d2/d3, rounds 1/2/3/4/64/160/319/320,
scratch hex) are in `hash-reference-results.json`. These are **private control
hash vectors** for the parent to compare against the Rust report's `HashProof`
records. No subject preimage was searched; `_hp1/_hp2` equality is only tested
on proved constant subjects.

## 3. Descriptor layout, capture halves, AF lazy-code cipher

Artifact: `prototype_reference.py`, `prototype-reference.json`. **26/26 checks
pass.**

- Root descriptor at `W[134628]`: entry 138920, bank 40, frame 71, salt 53417,
  token 4515, zero code extent.
- `activatedK1` is derived **directly** from the certified root-entry formula,
  with no child value supplied by any report. `boot.txt:10-19` boots the root
  entry as `138920` and `est = W[134628] ^ 2305819396 ^ K0 = 4225420928`.
  `U(270,...)`'s third return is `TM["nil"] + SALT = 24189 + 43122 = 67311`
  (`U.txt:51`, `initOnce.txt:75`, `initB.txt:53`), so `boot.txt:67` gives
  `st = (est + 67311) % 2^32 = 4225488239`. The `_dr_2880` entry helper
  (`_dr_2880.txt:92-94`) then yields, from root-entry W words at `ip = 138920`
  and `ps = 53417` (root descriptor low half):
  `cs = (W[ip+4] + st) % 2^32 = 156857040`,
  `K1 = ((W[ip+1] + st) % 2^32) ^ K0 ^ ps ^ st ^ cs = 1648390755`.
  Auxiliary probe fields from the same words: `stride = W[ip+2] ^ st = 18`,
  `rotor = ((W[ip+5] + st) % 2^32) | 1 = 152047965`, `a0 = (W[ip+3] + st) %
  2^32 = 0`. The decode mask is then `activatedK1 ^ SALT = 1648417297`. No
  Rust `pool_key` or child entry is an input to this derivation.
- The first child descriptor is then decoded **independently** with that mask
  (a downstream check, not the source of the key). Initial `K1 ^ SALT =
  675590897` yields an invalid descriptor (entry/code extent outside range).
- First child at `W[140545]`: entry **136924**, bank **94**, fixed **1**,
  arity 1, captures **0**, frame 71, est 1528981884, salt 38408, token 48510,
  lazy code **136680 + 559** — matching the certified factory resolution.
- Capture half rule: `low 16 = child-bank destination operand`,
  `high 16 = parent-bank source offset`. `boot.txt:24` / `make.txt:18` read the
  low half; `prototype()` (`sarp_large.rs:316-325`, helper 19) reads the high
  half. Both halves are therefore proved from source, not inferred from one
  consumer.
- AF double-XOR round trip (`make.txt:29` → `wrapper.tokens.txt:2432`):
  `pcs=157579, pcl=16989, phk=3350820617` re-derive `cs=136680, cl=559,
  hk0=2784560490`.
- AF lazy cipher: seed
  `bxor(bxor(hk0, ps*65537, est, 546595050), clz(est) + crz(ps)*257) =
  1212652016`; each of 559 rounds `state = state*6405 + 483291509 (mod 2^32)`
  then `state = rotl(state,6) ^ (state >> 13)`; writeback
  `W[136680+i] ^= keystream[i]`. First 8 keystream words and decoded words and
  the decoded-word SHA-256 are in the JSON.

Corroboration (not a derivation input): the derived entry `cs = 156857040`
equals the `phase` field reported for `PC 138926` in `target.partial-bytecode.txt`;
the make cookie proof is `SALT ^ 3893 == 42823`. No claim is made that the
child descriptor decode produced the activation key.

## 4. Read-only source findings / risks (audit only)

1. **AF frame and decode caching — not every invocation is fresh.**
   `wrapper.tokens.txt:2429-2431` closes over `_dec`: the decode block runs once
   (`if not _dec then _dec = true`). Line 2433 additionally gates on
   `not PD[_ptk]` and marks `PD[_ptk] = 1`, so the lazy-code XOR is applied
   **once per prototype token**. `make.txt:1-3,34-36` caches the factory in
   `FM[tk]`, so repeated `make(tk,...)` returns the *same* factory and the same
   `_dec` upvalue. `wrapper.tokens.txt:2451-2457` reuses a cached frame `_pf`
   (`F = _pf; if F then _pf = nil; F[cm[10]] = nil else F = tcreate(_sz) end`).
   In the protected `CM` array (`initC.txt:41`), `CM[10] = C_KD` (the return-tag /
   key slot), while `CM[14] = C_STOP` and `CM[22] = C_EXIT`; boot zeroes
   `cm[14]` and `cm[22]` (`boot.txt:71-72`). So the reused frame clears
   **C_KD, not the stop slot**, and other frame cells persist. A lifted model
   that re-runs the AF decode per invocation, or assumes a fresh frame, would
   double-XOR the code and mis-model state.
2. **boot double guard and forwarding.** `boot.txt:1-8` calls `initOnce` twice
   guarded (`if not W` and `if _wi == nil`). Arguments are forwarded via
   `_v0.._v3` (line 34) and `tpack(...)` (line 61); return tags select scalar
   counts or `tunpack(_rv1, 1, _rv1.n)` (lines 74-87), so **packed tuples keep
   an explicit `.n`** — do not collapse them to a fixed arity.
3. **Captures are copied at creation, not re-read from parent F per call.**
   `_h[19]` (`initC.txt:1574-1580`) builds a fresh table `cp` at closure
   creation: `cp[i] = F[rm[rb + ps[i]]]` (parent-bank slot values), then
   `make(cp, ...)`. `make.txt:39` returns `_fm(cp)`, and the AF factory
   (`wrapper.tokens.txt:2429`) closes over that `ups = cp`. At invocation,
   `wrapper.tokens.txt:2465-2469` only copies the stored `ups[i]` into the child
   destinations (`F[_us] = ups[i]`); it does **not** re-read parent `F`. Plain
   scalar values are therefore snapshotted at creation, while boxed TABLE/cell
   references retain identity, so later mutations through such a reference are
   observable. `wrapper.tokens.txt:2417-2421` builds `_ups[i] = _rm[rb + us[i]]`
   (child destination slot numbers), which are distinct from `cp`.
4. **Header/key lifecycle.** `initOnce.txt:62-71` derives header words from a
   stream seeded `sa ^ 192128608`; `initOnce.txt:85-92,170` derives K0 from a
   float-bit scratch plus a zero-count fold and metamethod/library proofs with
   accumulated error `_pe` (lines 93-168). K0 is trustworthy only when `_pe ==
   0`. `K1` starts at `bxor(1030971814,355957541)` (line 171) and is replaced
   by an activated value from the root-entry words via the `_dr_2880` entry
   formula (`_dr_2880.txt:92-94`, derived directly in section 3) before frames
   use it as `pool_key` and as the hash `_ck` term.
5. **Three unmask layers, in order.** (a) base85 + byteswap + LCG over the
   transport (`initOnce.txt:41-52`), (b) W decode stream + initB permutation
   unmask over `[ws..ce]` (`initOnce.txt:182-190`, `initB.txt:69-74`), (c) AF
   lazy-code XOR over `cs..cs+cl`. The W table is sparse — only 7022/142045
   words are present; absent words must never be materialized as decoded zero.
6. **Discarded helper-tail risks.** `_h[8]/_h[9]/_h[28]` differ only in their
   tails (different return orders and multipliers, `_h_8:84-87`, `_h_9:84-87`,
   `_h_28:84-87`); the 320-round core must not be conflated with the tail.
   `_dr_2880.txt:65-66` calls a helper `_hc[...]` and discards its results;
   `boot.txt:73` `exec(...)` returns five values selected by `_rk` tags;
   `wrapper.tokens.txt:2424` `U(472,...)` yields three values of which only
   `_kbt` is used. Values computed in these tails cannot be assumed live.

## 5. What is not claimed

- No handler is "understood"; parsing is not comprehension.
- The transport is not "fully recovered": only the certified W/permutation/
  slot layers are reproduced, and the program instruction stream is not
  certified by these diagnostics.
- The Rust private control hash was compared via independently transcribed
  known-answer vectors (section 2); no Rust report file for this target was
  present under `decompilation/protected`, so the parent should match the six
  vectors above against its own `HashProof` records.
