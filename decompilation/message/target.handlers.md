# `base85-rotor` — transition helper & handler semantics (static recovery)

Source: `tests/fixtures/base85-rotor.lua`
SHA-256 `0e4d2588aaa6f118dcdfe9999ccb84c0115ad058b3f3c61bca5ced500757edd0`
(never executed; every formula below was derived by reading the decompiled
wrapper and verified by transcribing constants into arithmetic checks only).

Inputs used: `decompilation/message/diagnostics/`
`_h_1.._h_33.txt`, `_dr_{1408,1952,2517,3080,3424,5521}.txt`, `U.txt`,
`boot.txt`, `make.txt`, `exec.txt`, `initOnce.txt`,
`target.wrapper.tokens.lua`, `reference.metadata.json`,
`reference.decoded.bin` (payload SHA `1450c06c…`, 2248 bytes, 562 words).

Purpose: exact, implementation-ready semantics of the 33 `_h` transition
helpers, the dispatcher "families", the `U` salt/decrypt function, and the
`boot`/`make`/`exec` entry machinery, plus the real-vs-decoy classification
needed so the Rust engine (`src/base85.rs` profile) never guesses.

---

## 1. Frame model

`F` is the frame table (root prototype `size = 48`). Control slots are
addressed through `CM` (from `reference.metadata.json`):

| slot | frame idx | meaning (name in fixtures) |
|------|-----------|------------------------------|
| CM[1]  | 44 | return values (single value or packed table with `.n`) |
| CM[2]  | 11 | return tag (`st ^ 1618725763` at stop) |
| CM[3]  | 35 | window / rotor stride `ls` (0 = rotor off) |
| CM[4]  | 9  | bank base `rb` |
| CM[5]  | 30 | stop ip (`0` for the whole profile) |
| CM[6]  | 36 | varargs (`tpack(...)`) |
| CM[7]  | 23 | rotor state `st` (masked when window active) |
| CM[8]  | 33 | instruction pointer `ip` (masked when window active) |
| CM[9]  | 41 | bank ceiling `rb + 2·ls` (set by the rotor-setup op) |
| CM[10] | 31 | salt anchor `_p1 = BL_A[u]` |
| CM[11] | 32 | return-count key (`band(st,65535)` at stop) |
| CM[12] | 39 | exit ip (`0` for the whole profile) |
| CM[13] | 38 | salt anchor `_p2` |
| CM[14] | 5  | prototype salt `ps` |
| CM[15] | 43 | shape `sh` (masked when window active) |

Register slots are addressed `F[RMAP[rb + k]]` (`RMAP[i] = slots[i]`, 1..111).
At each dispatcher entry the four special slots are derived once:

```
pxs = RMAP[rb+1]   -- masked rotor cell
pys = RMAP[rb+2]   -- rotor payload cell
u1s = RMAP[rb+3]
u2s = RMAP[rb+4]
```

### 1.1 The bank ring (window cycles)

The RMAP middle region is built so the three bank windows alias the same four
frame slots (verified against `reference.metadata.json:slots`):

| window `rb` | pxs | pys | u1s | u2s |
|-------------|-----|-----|-----|-----|
| 15 | 3  | 46 | 29 | 21 |
| 36 | 29 | 46 | 21 | 3  |
| 57 | 21 | 46 | 3  | 29 |

* window stride `ls = 21`, ring `{15, 36, 57}`, ceiling `CM[9] = rb0 + 2·21 = 57`.
* **`pys` is frame slot 46 in every window and is never rotated** by any
  dispatcher; only `pxs/u1s/u2s` rotate (or are re-derived).
* The aliasing makes both the "re-derive from new rb" sites and the "rotate
  locals" sites land the fresh rotor on the next read (proof in
  `diagnostics/transition-review.md` §2).

### 1.2 Boot initialization (root prototype, word 194)

From `reference.metadata.json` + `boot.txt` (K0 = 2484975588, K1 = 1109638509):

```
entry = 243      est = 394436979     token/shape = 58811  (family 3080)
rb    = 15       ps   = 31541         size = 48, fixed=0, arity=0, captures=0
```

`boot` computes `_p1,_p2,_tg = U(956, _v0, 300222, 172, 964, 613, 13411)`
and stores `F[CM[10]], F[CM[13]] = _p1, _p2`; for the usual call
`boot(...)` with no varargs `_v0 = nil` → `_u = 7534`, `_tb = TM["nil"] = 9648`
and (see §4.2) `_ds = 0`, so

```
F[CM[7]]  = est + _tg = 394436979 + 9648 + 53112 = 394499739   -- initial st
F[CM[8]]  = entry = 243                                          -- ip
F[CM[15]] = 58811                                                -- sh
F[CM[4]]  = 15 ; F[CM[14]] = 31541 ; CM[3] = CM[5] = CM[9] = CM[12] = 0
F[CM[6]]  = tpack(...)            -- varargs (root is da=0)
F[pxs]=F[pys]=_v0 (= nil at top level; overwritten by the first rotor-setup op)
```

`exec(204, bxor(K0,326350471), F, 162, bxor(_tg,_bs), 256)` — **the five
arguments other than `F` are ignored decoys**; `exec` reads everything from
the frame.

---

## 2. Families, helpers, decoys — how to tell them apart

`RT` maps a 32-bit shape to a family id; `DR[family]` holds the dispatcher:

```
RT = { 58811:3080, 39012:3080, 53090:3080,      -- real, _dr[3080] exists
       32567:1408, 48861:1408, 3879:1408,       -- real, _dr[1408] exists
       18273:1952, 26325:1952, 48352:1952,      -- real, _dr[1952] exists
       7922:2517, 37911:3424, 22505:5521,       -- decoy dispatchers (no-ops)
       26754:2117, 10900:8358, 34417:1574 }     -- NO dispatcher at all
```

**Real dispatcher** (`_dr[3080|1408|1952]`): reads `rb,ps,stop,exit,ip,st,sh`
from `F` (or from `_eip` args when entered directly by an AF factory), decodes
`op = f(W[ip], st, ps)` (each family has its own `op` formula, §7), executes
data ops that advance `st` by a per-op LCG (`st = st*A+B`), executes
transition ops that call `HC[k]` helpers, and ends with the frame-state
write-back plus `return ip==0 or ip==stop or ip==exit`.

**Decoy dispatcher** (`_dr[2517|3424|5521]`): bounded `_dn < 4` loop, only
`ip = ip+1` or `ip = 0`, **never writes `F`, never calls a helper, always
`return true`**. Reaching one in a trace means a mis-decoded shape.

**Transition helper** (`_h[k] == HC[k]`, `tcreate(33)`): advances the hidden
state `(rotor, bank, st, sh, ip)` and returns masked `(ip, st, sh)` in a
family-specific order. Dispatcher-referenced helpers are exactly
`_h[1], _h[3], _h[5], _h[6], _h[15], _h[16], _h[32]` — of these `_h[5]` is
the stop helper: referenced by every stop op but never executed in this
profile because `stop ≡ 0` (§5.7, trap T8), so the executing rotor-transition
set is `_h[1], _h[3], _h[6], _h[15], _h[16], _h[32]`. Call sites:

| family | unconditional | conditional | stop |
|--------|---------------|-------------|------|
| 3080 (`_dr[3080`) | `_hc[32]` (2 sites) | — | `_hc[5]` (2 sites, dormant) |
| 1408 (`_dr[1408`) | — | `_hc[3]` (2 sites) | `_hc[5]` (2 sites, dormant) |
| 1952 (`_dr[1952`) | `_hc[16]` (7 sites) | `_hc[6]` (2), `_hc[1]` (1), `_hc[15]` (2) | `_hc[5]` (1 site, dormant) |

Everything else in `_h[1..33]` is never called (§8 catalog).

---

## 3. The normalized transition operation (all rotor helpers)

Constants: `_sma = 3501875219`, `_smb = 4044522868`,
LCG `NR = (267593·R + 452471507) mod 2^32`.

Given the frame and the dispatcher's current `(rb, ip, st)`:

```
1. R   = F[pxs] XOR _sma                       -- raw rotor (decoys XOR a wrong salt!)
2. cur = (R + _smb + F[pys]) mod 2^32          -- = (rotor + 4044522868 + payload)
3. NR  = (267593·R + 452471507) mod 2^32
4. ls  = F[CM[3]]                                -- window stride (0 while rotor off)
5. sbz = (BL_C[F[CM[10]]·2 read as u16] - F[CM[13]]) mod 65536   -- == 53112 here
6. v1, v2 = F[u1s], F[u2s]
```

**Bank step (the ± window cycle)** — two forms:

```
down:  nrb = rb - ls ;  if rb <= F[CM[9]] - 2·ls then nrb = rb + 2·ls end
up:    nrb = rb + ls ;  if rb >= F[CM[9]]       then nrb = rb - 2·ls end
```

**Slot rotation** — two forms (note the different assignment targets):

```
keep:  F[pxs], F[u1s], F[u2s], F[CM[4]] = v1, v2, NR XOR _sma, nrb
swap:  F[pxs], F[u2s], F[u1s], F[CM[4]] = v2, v1, NR XOR _sma, nrb
```

Real helpers bind the direction and the rotation together:
`up ⇒ swap`, `down ⇒ keep` (every real branch follows this).

**Payload write (the rotor cancellation).** With the branch operand
`c0` (`_ct`/`_cf`/`_ceq(+_kv)`/`_cne`):

```
F[pys] = (c0 - (NR + _smb)) mod 2^32
```

so the *next* read computes `cur' = NR + _smb + F[pys] = c0` exactly — the
helper subtracts what the next helper adds back. `cur` is therefore always
the previous transition op's payload operand (or the setup op's `_cs`),
never independent hidden state.

**Masked outputs** (three family dialects; `mod 2^32` everywhere):

| group | family | ip mask | st mask | sh mask | return order |
|-------|--------|---------|---------|---------|--------------|
| A | 1952 | `mip = ip + d + 25·NR` | `mst = st + ds + cur + [zb] + sbz + 77·NR` | `msh = (h + cur + sbz) XOR 137·NR` | `mip, msh, mst` |
| X | 3080 | `mip = (ip + d) XOR 27·NR` | `mst = (st + ds + cur + [zb] + sbz) XOR 89·NR` | `msh = (h + cur + sbz) XOR 101·NR` | `mst, mip, msh` |
| M | 1408 | `mip = (ip + d) XOR 23·NR` | `mst = st + ds + cur + [zb] + sbz + 87·NR` | `msh = h + cur + sbz + 147·NR` | `msh, mst, mip` |

`d` = ip delta operand, `ds` = st delta operand, `h` = sh delta operand
(all come from `W[ip+k] ± st − bias` at the call site), `zb = 53112` appears
**only** in the st term and **only** in conditional helpers that call
`U(443, _c, 413384, 330, 774, 862, 43605)` (see §4.2); `sbz = 53112` appears
in both st and sh terms of every transition.

**Dispatcher unmask (inverse pairs).** After the helper returns the
dispatcher refreshes `rb = F[CM[4]]`, obtains the new slot triple, and reads
the new rotor `_r = F[pxs'] XOR _sma` (= NR), then unmasks with the exact
inverse of the group:

```
3080: ip = mip XOR 27·_r ; st = mst XOR 89·_r ; sh = msh XOR 101·_r
1408: ip = mip XOR 23·_r ; st = mst - 87·_r   ; sh = msh - 147·_r
1952: ip = mip - 25·_r   ; st = mst - 77·_r   ; sh = msh XOR 137·_r
```

The new slot triple is either **rotated locally**
(`_pxs,_u1s,_u2s = _u1s,_u2s,_pxs` in 3080; `= _u2s,_pxs,_u1s` in 1952) or
**re-derived** (`_pxs,_u1s,_u2s = RMAP[rb+1], RMAP[rb+3], RMAP[rb+4]`, used by
1408 always and by 1952 after `_hc[6]/_hc[1]/_hc[15]`). Both are ring-consistent
(§1.1). `_pys` is never rotated.

`_go = (RT[sh] == family)` continues the family loop; a family change exits
the while, the write-back block stores masked state, and the outer `exec`
loop re-dispatches on the new shape.

**State masking while the window is active** (`F[CM[3]] ~= 0`, i.e. after the
first rotor-setup op, unless it sets `ls = 0`):

```
entry: _r = F[RMAP[rb+1]] XOR _sma ; ip ^= 31·_r ; st -= 35·_r
exit : F[CM[8]] = ip XOR 31·_r ; F[CM[7]] = st + 35·_r ; F[CM[15]] = sh XOR 199·_r
exec-level shape read: sh = F[CM[15]] XOR 199·_r   (only when _r ~= 0)
```

---

## 4. The `U` function (salt generator + constant decryptor)

`U(_uf, _ua, _ub, _ud, _ue, _uc, _um)` dispatches on `_op = _ua? no —
_op = _um XOR 3300`. Live channels in this profile (all others are decoy
branches):

### 4.1 `_op == 14471` (from `_um = 13411`) — boot/AF salt

Used by `boot` (`U(956, _v0, 300222, 172, 964, 613, 13411)`) and every AF
factory (`U(870, ps, 300222, 771, 237, 26, 13411)`).

```
skv = _ub = 300222
ds  = (skv XOR 845168) - 553422        -- == 0   (verified)
u   = type index: number→band(v,16383), string→band(#v,16383),
                    boolean→11233/11380, nil→7534
pa  = BL_A[u] ; pb = BL_B[u]
exp = (pb*4 + ((u*17+8644) mod 16384)*2 + bit9(pa)) mod 65536
sbz = (BL_C[pa] - exp) mod 65536       -- == 53112 by BL_C construction
tb  = 9648 (number/string) | BM_BOOL[v] (boolean, both 9648) | TM[type]
return pa, (exp + ds) mod 65536, (tb + sbz + 83·ds) mod 2^32
```

So the stored anchors are `F[CM[10]] = BL_A[u]`, `F[CM[13]] = exp`, and the
state salt `_tg = tb + 53112 + 83·ds`. With `ds = 0`:
`_tg = 9648 + 53112 = 62760`.

### 4.2 `_op == 42673` (from `_um = 43605`) — conditional-branch boolean salt

Called by conditional helpers only: `zb = U(443, _c, 413384, 330, 774, 862, 43605)`.

```
zkv = _ub = 413384
dz  = ((zkv XOR 491297) - 78313) * 83   -- == 0   (verified: 413384^491297 = 78313)
-- any type of _c selects only the index u; sbz stays 53112 by construction
return (sbz + dz) mod 2^32              -- == 53112 for EVERY _c
```

`zb = 53112` regardless of the branch — it is a constant folded behind a
data-dependent-looking call. Helpers with `zb`: `_h[3], _h[6], _h[7], _h[15],
_h[22], _h[26]` (all six read the rotor with the correct `_sma`).

### 4.3 `_op == 31151` (from `_um = 30027`) — string constant decrypt (`SM` cache)

```
sbz = 100 + (_ua mod 97) ; corrected to (BL_C[F[CM[10]]] - F[CM[13]]) mod 65536 = 53112
ck  = (sbz XOR 9761 == 59737) and _ub ~= nil       -- == true with frame + K1
o   = _ua XOR 701714                                -- byte offset into B
ps  = r32(B, o) XOR 1656731775
n   = r32(B, o+4) XOR (85451734 XOR ps)
k   = ps XOR K0 XOR (_ub XOR sbz)                   -- _ub = current K1
k   = (k*2151 + 549576011) mod 2^32 per output unit (word, then tail bytes)
plaintext = rstr(bcreate(n) filled by XOR-ing B[o+8 .. o+8+n], 0, n)
if ck: SM[_ua] = plaintext                          -- memoized
```

### 4.4 `_op == 39793` (from `_um = 38805`) — number constant decrypt (`NM` cache)

```
sbz corrected as above (53112); ck likewise
i  = _ua XOR 1329030                    -- 1-based index
o  = W[4] XOR 3139019791 XOR K0         -- == 16 (metadata "number_base")
p  = o + (i-1)*8
lo = r32(B, p)     XOR ((4177466961 + 267459·i) mod 2^32) XOR (K0 XOR (K1 XOR sbz))
hi = r32(B, p+4)   XOR ((1751540260 + 473879·i) mod 2^32)
                       XOR ((K0>>>11 | K0<<<21) XOR ((K1 XOR sbz)>>>7 | (K1 XOR sbz)<<<25))
v  = readf64(lo, hi) ; if ck: NM[_ua] = v
```

`K1` here is the *current* secondary key — see trap T7 (one-shot rewrite).

Decoy `U` branches (never reached with this profile's `_um` values):
`op in [15774, 31151)` rf64-hash branch, `op < 15774` `_mkv` number-salt
branch, `op <= 39792` two-character name builder (`w8 65+band(v,31)`,
`66+bit(v,0..3)`), `op > 42673` `_dz` number-salt branch, plus the dead
`_udm < 0 → return 0` guard.

### 4.5 The `make` / salt-balance check

`make(tk, ups, _ms)` verifies `bxor(bxor(_ms, K1), 9761) == 59737`, i.e.
`_ms == 53112 XOR K1`-style anchor; the same predicate appears inside `U`
as `bxor(sbz, 9761) == 59737` ⟺ `sbz == 53112`. **`make` is never called by
any dispatcher op in this profile** (the payload has a single prototype and
no closure-creation op); it is generic infrastructure, like `JMT` and
`_dexec`, which are also defined but never used.

---

## 5. Deep dives (the live helpers)

### 5.1 `_h[16]` — unconditional transition, family 1952 (group A)

Signature order (shuffled): `(_st, _u1s, _F, _pys, _d, _pxs, _ds, _u2s, _ip,
_rb, _ct, _h)` → semantic roles st, u1s, F, pys, d, pxs, ds, u2s, ip, rb,
ct, h. No condition, no `zb`.

```
R = F[pxs] XOR _sma ; cur = (R + _smb + F[pys]) mod 2^32 ; NR = LCG(R)
ls = F[CM[3]] ; sbz = 53112 ; v1,v2 = F[u1s],F[u2s]
nrb = rb - ls ; if rb <= F[CM[9]] - 2·ls then nrb = rb + 2·ls end   -- DOWN
F[pxs],F[u1s],F[u2s],F[CM[4]] = v1, v2, NR XOR _sma, nrb             -- KEEP
F[pys] = (ct - (NR + _smb)) mod 2^32
mip = ip + d + 25·NR
mst = st + ds + cur + sbz + 77·NR
msh = (h + cur + sbz) XOR 137·NR
return mip, msh, mst
```

Call sites in `_dr[1952]` (operand maps; all `W[...] ± st` are `mod 2^32`):

| site (line in `_dr_1952.txt`) | `_d` (ip delta) | `_ds` (st delta) | `_ct` (payload) | `_h` (sh delta) |
|---|---|---|---|---|
| 37 | `W[ip+5]-st-1162511` | `W[ip+2]-st` | `W[ip+3]+st` | `W[ip+1]-st` |
| 46 | `W[ip+4]+st-1053485` | `W[ip+2]+st` | `W[ip+3]+st` | `W[ip+1]-st` |
| 250 | `W[ip+5]+st-1104781` | `W[ip+6]-st` | `W[ip+4]+st` | `W[ip+3]-st` |
| 560 | `W[ip+4]+st-1052754` | `W[ip+3]-st` | `W[ip+5]-st` | `W[ip+1]-st` |
| 632 | `W[ip+2]+st-1157107` | `W[ip+6]+st` | `W[ip+1]-st` | `W[ip+5]-st` |
| 644 | `W[ip+4]+st-1195077` | `W[ip+1]-st` | `W[ip+2]-st` | `W[ip+3]+st` |
| 728 | `W[ip+4]+st-1190936` | `W[ip+3]-st` | `W[ip+1]+st` | `W[ip+2]+st` |

After each call the dispatcher rotates `_pxs,_u1s,_u2s = _u2s,_pxs,_u1s`
(NR̂ was written to old `u2s`, which becomes the new `pxs`), unmasks
`ip = mip - 25·_r`, `st = mst - 77·_r`, `sh = msh XOR 137·_r`, and re-tests
`_go = RT[sh] == 1952`.

### 5.2 `_h[32]` — unconditional transition, family 3080 (group X)

Signature: `(_u2s, _pxs, _h, _rb, _u1s, _st, _hd0, _ds, _ip, _ct, _pys,
_hd1, _d, _F)` → u2s, pxs, h, rb, u1s, st, *(decoy)*, ds, ip, ct, pys,
*(decoy)*, d, F. Body: UP step + SWAP order, no `zb`:

```
nrb = rb + ls ; if rb >= F[CM[9]] then nrb = rb - 2·ls end           -- UP
F[pxs],F[u2s],F[u1s],F[CM[4]] = v2, v1, NR XOR _sma, nrb             -- SWAP
F[pys] = (ct - (NR + _smb)) mod 2^32
mip = (ip + d) XOR 27·NR ; mst = (st + ds + cur + sbz) XOR 89·NR
msh = (h + cur + sbz) XOR 101·NR ; return mst, mip, msh
```

Call sites in `_dr[3080]`:

| line | `_d` | `_ds` | `_ct` | `_h` |
|---|---|---|---|---|
| 51 | `W[ip+4]+st` | `W[ip+2]+st` | `W[ip+3]+st-1164258` | `333` |
| 79 | `W[ip+2]-st` | `W[ip+4]+st` | `W[ip+3]+st-942380` | `37` |

(`333`/`37` are literal sh-delta operands.) After the call the dispatcher
rotates `_pxs,_u1s,_u2s = _u1s,_u2s,_pxs` (NR̂ was written to old `u1s`)
and unmasks with the X-group inverses.

### 5.3 `_h[3]` — conditional transition (truthiness), family 1408 (group M, `zb`)

Signature: `(_hd0, _sf, _ht, _u2s, _hf, _c, _u1s, _ct, _pys, _hd1, _rb,
_ip, _pxs, _st0, _st, _cf, _dt, _F, _df)` → *(decoy)*, sf, ht, u2s, hf,
**c**, u1s, ct, pys, *(decoy)*, rb, ip, pxs, st0, st, cf, dt, F, df.

```
zb = U(443, c, 413384, ...) = 53112
q = BM1[not c] - 43          -- q == 1  <=>  c is falsy
if q == 1:                                  -- condition HOLDS (c falsy)
    nrb = UP step ; SWAP order
    F[pys] = (ct - (NR + _smb)) mod 2^32
    mip = (ip + dt) XOR 23·NR
    mst = st + st0 + cur + zb + sbz + 87·NR
    msh = ht + cur + sbz + 147·NR
else:                                       -- c truthy
    nrb = DOWN step ; KEEP order
    F[pys] = (cf - (NR + _smb)) mod 2^32
    mip = (ip + df) XOR 23·NR
    mst = st + sf + cur + zb + sbz + 87·NR
    msh = hf + cur + sbz + 147·NR
return msh, mst, mip
```

`BM1 = {[true]=44, [false]=43, [1]=63, [0]=63, ["_"]=68}` — `BM1[not c]` is
44 iff `not c` is true, so the taken branch is exactly `c == nil/false`.
Call sites in `_dr[1408]` (the tested value `_c = _fr0` is a register read;
operands with `-bias` are ip deltas):

| line | taken-set (`dt`, `st0`, `ht`, `ct`) | fallthrough-set (`df`, `sf`, `hf`, `cf`) |
|---|---|---|
| 47 | `W[ip+2]+st-1174652`, `W[ip+6]-st`, `W[ip+4]+st`, `W[ip+8]+st` | `W[ip+1]+st-999137`, `W[ip+3]+st`, `W[ip+7]-st`, `W[ip+5]-st` |
| 229 | `W[ip+8]-st-946004`, `W[ip+10]-st`, `W[ip+9]+st`, `W[ip+5]-st` | `W[ip+4]+st-955000`, `W[ip+2]-st`, `W[ip+6]+st`, `W[ip+11]+st` |

After the call the dispatcher **re-derives**
`_pxs,_u1s,_u2s = RMAP[rb+1], RMAP[rb+3], RMAP[rb+4]` and unmasks
`ip = mip XOR 23·_r`, `st = mst - 87·_r`, `sh = msh - 147·_r`.

### 5.4 `_h[6]` — conditional transition (comparison `<`), family 1952 (group A, `zb`)

Signature: `(_st, _ht, _c, _pxs, _rb, _hf, _F, _st0, _ip, _dt, _pys, _u2s,
_df, _cf, _sf, _hd0, _u1s, _ct)` → st, ht, **c**, pxs, rb, hf, F, st0, ip,
dt, pys, u2s, df, cf, sf, *(decoy)*, u1s, ct.

```
zb = 53112
q = BM2[not c] - 65          -- q == 1  <=>  c is truthy
if q == 1:                                  -- comparison TRUE
    UP step + SWAP order ; payload ct ; deltas dt/st0/ht
else:                                       -- comparison FALSE
    DOWN step + KEEP order ; payload cf ; deltas df/sf/hf
mip = ip + (dt|df) + 25·NR
mst = st + (st0|sf) + cur + zb + sbz + 77·NR
msh = ((ht|hf) + cur + sbz) XOR 137·NR
return mip, msh, mst
```

`BM2 = {[true]=65, [false]=66, ["_"]=112, [1]=103, [0]=68}` — polarity is
inverted relative to `BM1`: here the taken branch is `c` truthy.

Call sites in `_dr[1952]` (condition = register `<` KBOX-biased constant):

| line | `_c` (condition) | taken-set (`dt`,`st0`,`ht`,`ct`) | fallthrough-set (`df`,`sf`,`hf`,`cf`) |
|---|---|---|---|
| 205 | `F[_rl1] < (W[ip+4]-st - KBOX[5] - 524288)` | `W[ip+9]+st-1005325`, `W[ip+1]-st`, `W[ip+7]+st`, `W[ip+8]+st` | `W[ip+2]-st-1191430`, `W[ip+5]-st`, `W[ip+10]-st`, `W[ip+6]+st` |
| 397 | `F[_rl1] < (W[ip+2]-st - KBOX[45] - 524288)` | `W[ip+5]-st-1101726`, `W[ip+1]+st`, `W[ip+7]+st`, `W[ip+10]+st` | `W[ip+9]+st-1132507`, `W[ip+3]+st`, `W[ip+6]-st`, `W[ip+8]+st` |

`KBOX[5] = 142839`, `KBOX[45] = 15743` (metadata `biases`). After the call
the dispatcher re-derives the slots from the new `rb` (not rotation) and
unmasks with the A-group inverses.

### 5.5 `_h[15]` — conditional transition (truthiness), family 1952 (group A, `zb`)

Signature: `(_F, _u2s, _df, _st, _c, _hf, _cf, _sf, _rb, _pys, _pxs, _u1s,
_ip, _dt, _ht, _st0, _ct)` → F, u2s, df, st, **c**, hf, cf, sf, rb, pys,
pxs, u1s, ip, dt, ht, st0, ct.

Same `BM1` polarity as `_h[3]`: taken branch is `_c` **falsy**
(`q = BM1[not c] - 43 == 1`), i.e. the op is `if not <register> then …`.
Branch shapes: taken → UP + SWAP with `dt/st0/ht/ct`; fallthrough →
DOWN + KEEP with `df/sf/hf/cf`; masks and return order identical to `_h[6]`;
`zb = 53112` in st only.

Call sites in `_dr[1952]` (tested value `_c = _fr0`, a register read):

| line | taken-set (`dt`,`st0`,`ht`,`ct`) | fallthrough-set (`df`,`sf`,`hf`,`cf`) |
|---|---|---|
| 550 | `W[ip+1]-st-903378`, `W[ip+6]-st`, `W[ip+7]-st`, `W[ip+8]+st` | `W[ip+3]-st-1032815`, `W[ip+5]+st`, `W[ip+4]+st`, `W[ip+11]-st` |
| 761 | `W[ip+9]-st-1196684`, `W[ip+5]-st`, `W[ip+7]-st`, `W[ip+3]+st` | `W[ip+8]-st-958891`, `W[ip+4]+st`, `W[ip+2]+st`, `W[ip+13]-st` |

Dispatcher after-call behavior identical to `_h[6]` (re-derive + A-unmask).

### 5.6 `_h[1]` — switch/equality transition, family 1952 (group A)

Signature: `(_cne, _ip, _deq, _ceq, _rb, _pxs, _u2s, _F, _seq, _x, _sne,
_hp, _dne, _hd0, _st, _u1s, _pys, _hd1, _m32, _heq, _hne)` →
cne (default payload), ip, deq (case ip delta), ceq (case payload),
rb, pxs, u2s, F, seq (case st delta), **x (runtime switch value)**,
sne (default st delta), **hp (expected packed key)**, dne (default ip delta),
*(decoy)*, st, u1s, pys, *(decoy)*, **m32 (site key mask)**, heq (case sh
delta), hne (default sh delta).

**The permutation equality test** (only for integer `_x` in
`[-2^31, 2^31-1]`; anything else takes the default branch):

```
a1 = BL_A[ x & 16383 ]                    -- 14-bit permutation lookup
a2 = BL_B[ (x >> 14) & 16383 ]            -- 14-bit permutation lookup
pk = (a1 | a2<<14 | (x >> 28) << 28) XOR m32
eq = (pk == hp)
```

Because `BL_A` and `BL_B` are exact permutations of 0..16383 and the top 4
bits pass through, `x -> pk` is a bijection on int32 (verified: both tables
are permutations). So `pk == hp` **iff** `x` equals the case constant the
builder encoded, and equality is proven through the permutation images
without ever storing the constant. The stored pair
`(hp = W[ip+10]+st, m32 = W[ip+11]-st)` binds the case to the site: `m32`
scrambles otherwise-identical packed keys.

When equal, the case tag is recovered from the same permutation data:

```
kv = (BL_C[a1] XOR a2) & 65535
```

and is added to **all four channels** of the taken branch:

```
UP step + SWAP order
F[pys] = ((ceq + kv) - (NR + _smb)) mod 2^32
mip = ip + deq + kv + 25·NR
mst = st + seq + cur + sbz + kv + 77·NR          -- NOTE: no zb (h1 never calls U)
msh = (heq + cur + sbz + kv) XOR 137·NR
```

Default branch: DOWN + KEEP, payload `_cne`, deltas `_dne/_sne/_hne`,
no `kv`. Return order `mip, msh, mst` (A-group). The single call site
(`_dr_1952` line 433) maps operands:

```
_cne = W[ip+9]-st      _deq = W[ip+7]-st-1185885   _ceq = W[ip+8]+st
_seq = W[ip+6]-st      _x   = F[_sl]  (register)    _sne = W[ip+3]+st
_hp  = W[ip+10]+st     _dne = W[ip+4]-st-1003877    _m32 = W[ip+11]-st
_heq = W[ip+2]-st      _hne = W[ip+5]-st            decoys: 231, 479
```

Dispatcher after-call: re-derive slots from new `rb`, A-group unmask.

### 5.7 `_h[5]` — the stop helper (return-tag writer)

Signature: `(_st, _rr, _F, _sh)`; no rotor arithmetic:

```
F[CM[11]] = band(st, 65535)                 -- return-count key (n xor band(st,65535))
F[CM[1]]  = nil                             -- no return values
F[CM[8]]  = (rr·31) mod 2^32               -- ip stored as pure mask => true ip 0
F[CM[7]]  = (st + rr·35) mod 2^32          -- st stored masked
F[CM[15]] = sh XOR (rr·199)                -- sh stored masked
F[CM[2]]  = st XOR 1618725763              -- return tag from the TRUE st
```

`boot`/AF later recover `_fst = F[CM[7]] - rr·35`, check
`F[CM[2]] == _fst XOR 1618725763`, and compute the value count
`n = F[CM[11]] XOR band(_fst, 65535)` — for `_h[5]` that is 0 (no values).
`n == 1` returns `F[CM[1]]`; `n > 1` does `tunpack(F[CM[1]], 1, n)`.

**Profile note (verified):** `stop`/`exit` (`F[CM[5]]`, `F[CM[12]]`) are set
to 0 at boot/factory init and **no op ever writes them again**, so every
stop op in this payload takes the dispatcher's
`if stop == 0 then return true, 93375 end` path and `_h[5]` never actually
executes. Likewise the multi-value return codes (`287782` 1 value,
`328993` 2, `604419` 3, `240743` 4, `769411` packed tuple) are decoded by
`boot`/AF but **never produced** by any dispatcher in this payload — the only
produced code is `93375` (no values), at five sites. The program's effect
comes purely from data-op side effects (calls through `F[...]`, table
writes, `G[...]` access).

---

## 6. Inline rotor-setup op (turns the rotor on)

Present in `_dr[3080]` (op range `948 < op < 1205`) and `_dr[1408]`
(op `>= 1414`); `_dr[1952]` has **no** setup op (it inherits an active
window by entering after a 3080/1408 transition).

`_dr[3080]` layout (word offsets from `ip`):

```
_a0 = W[ip+2]+st   (spill offset; if ~= 0: F[RMAP[rb+_a0]] = F[pxs]  -- old masked rotor)
_sr = W[ip+1]+st   (new rotor value R)
_cs = W[ip+3]-st   (new cur/payload target)
_ls = W[ip+5]-st   (window stride; 0 disables masking again)
one-shot K1 update (see T7): if bxor(K1,432963489) == 1542308556 then
        K1 = (W[ip+4]+st) XOR K0 XOR ps XOR st XOR _cs
F[pxs] = _sr XOR _sma
F[pys] = (_cs - (_sr + _smb)) mod 2^32       -- so the next cur == _cs exactly
F[CM[3]] = _ls ; F[CM[9]] = rb + 2·_ls ; _r = _sr
ip += 6 ; st = (st·23237 + 785669) mod 2^32
```

`_dr[1408]` variant (same semantics, shuffled operands):
`_a0 = W[ip+5]+st`, `_sr = W[ip+2]-st`, `_ls = W[ip+1]+st`,
`_cs = W[ip+4]-st`, K1 word `W[ip+3]-st`, `ip += 6`,
`st = st·338817+969367`.

The setup op does **not** step the bank and does **not** rotate slots.
It anchors: rotor `R = _sr`, payload so that `cur = _cs`, window `ls`,
ceiling `CM[9] = rb + 2·ls` (for the ring invariant the payload uses
`ls = 21`, `rb0 = 15` ⇒ `CM[9] = 57`).

---

## 7. Family `op` decode formulas (for completeness)

Each dispatcher decodes its opcode from `W[ip]`:

```
3080: op = (W[ip] XOR st XOR ps) - 1669
1408: op = (W[ip] - 7·st - ps) mod 2^32 - 5536
1952: op = (W[ip] - st - ps) mod 2^32 - 19927
2517: op = (W[ip] - st - ps) mod 2^32 - 29064   (decoy)
3424: op = (W[ip] XOR st XOR ps) - 13816         (decoy)
5521: op = (W[ip] - st - ps) mod 2^32 - 40011   (decoy)
```

Data ops read operands as `RMAP[rb + (W[ip+k] ± st mod 2^32)]` and advance
`st` by per-op LCG constants; transition ops advance `st` through the helper
output (no extra LCG step). String/number constants come from
`SM[x] or U(rand, x, K1, …, 30027)` and `NM[x] or U(rand, x, K1, …, 38805)`
channels (§4.3/§4.4); `G[...]` (globals, `getfenv()`) resolves names loaded
through the string channel.

---

## 8. Complete catalog of the 33 helpers

Legend — **salt**: value XOR-ed with `F[pxs]` when reading the rotor
(`_sma = 3501875219` is the only correct one). **grp**: mask group
A(25+/77+/137^, ret ip,sh,st) · X(27^/89^/101^, ret st,ip,sh) ·
M(23^/87+/147+, ret sh,st,ip). **step/rot**: bank step and slot order.
**cond**: `–` unconditional; `BM1` taken when `_c` falsy; `BM2` taken when
`_c` truthy; `not _c` / `_c` = literal `if` polarity (same semantics);
`SIB` = step-in-branch, `SUC` = step unconditional (deltas-only conditional).
**zb**: calls `U(443,…)` adding 53112 to st. **live**: call sites.

| # | salt | grp | step/rot | cond | zb | live |
|---|------|-----|----------|------|----|------|
| 1 | _sma | A | eq:up+swap (+kv), ne:down+keep | permutation-key equality | – | `_dr1952` ×1 |
| 2 | 61822809 | A | down+keep | – | – | never |
| 3 | _sma | M | falsy:up+swap, truthy:down+keep | BM1, SIB | yes | `_dr1408` ×2 |
| 4 | 1193034495 | M | up+swap | – | – | never |
| 5 | — (stop helper, no rotor read) | — | — | — | — | all families' stop ops (dormant here, see §5.7) |
| 6 | _sma | A | truthy:up+swap, falsy:down+keep | BM2, SIB | yes | `_dr1952` ×2 |
| 7 | _sma | X | falsy:down+keep, truthy:up+swap | not _c, SIB | yes | never |
| 8 | 3464128947 | A | down+keep | – | – | never |
| 9 | 2956124930 | X | down+keep | – | – | never |
| 10 | 300639441 | M | up+swap always | not _c, SUC | – | never |
| 11 | 4087586464 | A | up+swap | – | – | never |
| 12 | _sma | M | up+swap | – | – | never |
| 13 | 923830726 | M | up+swap always | not _c, SUC | – | never |
| 14 | 2563310485 | A | up+swap | – | – | never |
| 15 | _sma | A | falsy:up+swap, truthy:down+keep | BM1, SIB | yes | `_dr1952` ×2 |
| 16 | _sma | A | down+keep | – | – | `_dr1952` ×7 |
| 17 | 3194925306 | A | up+swap | – | – | never |
| 18 | 539437641 | X | up+swap | – | – | never |
| 19 | 2178919448 | M | down+keep always | not _c, SUC | – | never |
| 20 | 1670653423 | A | up+swap always | not _c, SUC | – | never |
| 21 | 3310182334 | X | down+keep always | not _c, SUC | – | never |
| 22 | _sma | X | truthy:down+keep, falsy:up+swap | if _c, SIB | yes | never |
| 23 | 154815196 | A | up+swap | – | – | never |
| 24 | 3941780643 | X | down+keep | – | – | never |
| 25 | 1286293106 | M | down+keep | – | – | never |
| 26 | _sma | X | truthy:down+keep, falsy:up+swap | if _c, SIB | yes | never |
| 27 | 2417521040 | X | up+swap | – | – | never |
| 28 | 1909517159 | M | down+keep | – | – | never |
| 29 | 3548998966 | A | down+keep always | not _c, SUC | – | never |
| 30 | 3040994949 | X | up+swap always | not _c, SUC | – | never |
| 31 | 393615444 | M | up+swap always | not _c, SUC | – | never |
| 32 | _sma | X | up+swap | – | – | `_dr3080` ×2 |
| 33 | 1525091306 | X | up+swap always | not _c, SUC | – | never |

Signature orders (positional, as defined; `hd0`/`hd1` are never-read decoy
parameters):

```
1  (_cne,_ip,_deq,_ceq,_rb,_pxs,_u2s,_F,_seq,_x,_sne,_hp,_dne,_hd0,_st,_u1s,_pys,_hd1,_m32,_heq,_hne)
2  (_d,_hd0,_h,_pys,_F,_ds,_st,_ip,_u2s,_pxs,_u1s,_ct,_rb)
3  (_hd0,_sf,_ht,_u2s,_hf,_c,_u1s,_ct,_pys,_hd1,_rb,_ip,_pxs,_st0,_st,_cf,_dt,_F,_df)
4  (_hd0,_F,_d,_ip,_ds,_u2s,_pys,_pxs,_hd1,_ct,_h,_rb,_u1s,_st)
5  (_st,_rr,_F,_sh)
6  (_st,_ht,_c,_pxs,_rb,_hf,_F,_st0,_ip,_dt,_pys,_u2s,_df,_cf,_sf,_hd0,_u1s,_ct)
7  (_st,_hd0,_df,_ip,_ht,_ct,_dt,_st0,_c,_rb,_pys,_u1s,_hf,_F,_cf,_pxs,_u2s,_sf)
8  (_ds,_u2s,_ct,_F,_pxs,_h,_u1s,_ip,_rb,_st,_pys,_d)
9  (_u1s,_d,_ip,_ct,_pys,_st,_F,_hd0,_pxs,_ds,_h,_u2s,_rb)
10 (_pys,_cf,_hd0,_st0,_pxs,_dt,_F,_rb,_hf,_u2s,_c,_df,_sf,_ct,_ip,_st,_u1s,_ht)
11 (_u2s,_ct,_st,_u1s,_ip,_rb,_hd0,_ds,_h,_d,_pxs,_F,_pys)
12 (_u1s,_rb,_F,_d,_st,_u2s,_pys,_hd0,_pxs,_ct,_ip,_h,_ds)
13 (_df,_hd0,_ht,_ct,_cf,_F,_st,_pxs,_ip,_u2s,_st0,_sf,_rb,_pys,_hf,_dt,_c,_u1s)
14 (_u1s,_u2s,_hd0,_rb,_h,_d,_ct,_ds,_pys,_F,_pxs,_ip,_st)
15 (_F,_u2s,_df,_st,_c,_hf,_cf,_sf,_rb,_pys,_pxs,_u1s,_ip,_dt,_ht,_st0,_ct)
16 (_st,_u1s,_F,_pys,_d,_pxs,_ds,_u2s,_ip,_rb,_ct,_h)
17 (_d,_F,_ip,_rb,_ct,_u2s,_pys,_u1s,_ds,_st,_hd1,_h,_hd0,_pxs)
18 (_pys,_u2s,_F,_rb,_ct,_d,_h,_ds,_pxs,_ip,_u1s,_hd0,_st)
19 (_pys,_df,_ct,_ht,_pxs,_u2s,_cf,_F,_ip,_hf,_st,_st0,_u1s,_c,_rb,_sf,_dt)
20 (_F,_pxs,_u1s,_cf,_hf,_st,_df,_c,_ct,_sf,_ht,_rb,_u2s,_dt,_ip,_pys,_st0)
21 (_ht,_hf,_st,_hd0,_u2s,_F,_sf,_ct,_dt,_rb,_df,_cf,_c,_u1s,_st0,_ip,_pys,_pxs)
22 (_F,_st,_sf,_rb,_ht,_pxs,_df,_ct,_hf,_cf,_dt,_c,_u1s,_ip,_st0,_pys,_u2s)
23 (_d,_u2s,_st,_h,_u1s,_ip,_pxs,_ct,_F,_pys,_rb,_ds)
24 (_ip,_ct,_pys,_h,_rb,_hd0,_pxs,_d,_hd1,_u2s,_F,_u1s,_st,_ds)
25 (_hd0,_pxs,_pys,_ip,_h,_ct,_u2s,_u1s,_d,_ds,_st,_F,_rb)
26 (_u2s,_sf,_hf,_u1s,_dt,_st0,_ct,_ip,_cf,_pys,_ht,_rb,_st,_df,_pxs,_F,_hd0,_c)
27 (_ct,_ip,_pxs,_pys,_rb,_hd0,_st,_u1s,_h,_u2s,_d,_F,_ds)
28 (_ct,_st,_rb,_u2s,_F,_ds,_d,_hd0,_h,_pxs,_ip,_pys,_u1s)
29 (_sf,_st0,_df,_F,_hf,_pxs,_ht,_dt,_cf,_st,_rb,_ct,_u2s,_c,_pys,_u1s,_ip)
30 (_sf,_u2s,_st,_ht,_F,_pxs,_u1s,_pys,_dt,_ip,_st0,_cf,_df,_c,_ct,_rb,_hf)
31 (_st0,_cf,_F,_u2s,_ip,_dt,_ct,_c,_st,_hf,_df,_ht,_sf,_pxs,_pys,_rb,_u1s)
32 (_u2s,_pxs,_h,_rb,_u1s,_st,_hd0,_ds,_ip,_ct,_pys,_hd1,_d,_F)
33 (_c,_F,_ct,_ip,_st0,_st,_pys,_dt,_u2s,_sf,_df,_u1s,_ht,_cf,_rb,_pxs,_hf)
```

Semantic parameter naming used throughout this document:

```
F     frame            pxs/pys/u1s/u2s  slot ids     rb    bank base
ip    word index       st   rotor state              d/dt/df/deq/dne   ip deltas
ds/st0/sf/seq/sne     st deltas         h/ht/hf/heq/hne   sh deltas
ct/cf/ceq/cne         payload consts    c    condition value
x/hp/m32/kv           switch value / packed key / site mask / case tag
hd0, hd1, _uf, _ud, _ue, _uc, and exec/make/U extra args   (never read)
```

---

## 9. Correctness traps for the Rust engine

* **T1 — per-helper read salts.** Only `_sma = 3501875219` is live. A generic
  body-lifter that honors the literal salt of, e.g., `_h[21]`
  (`3310182334`) or `_h[24]` (`3941780643`) reads a wrong rotor and every
  subsequent `ip/st/sh` unmask derails. Emulate only `_h[1,3,5,6,15,16,32]`
  and hard-fail on references to the other 26.
* **T2 — `sbz` and `zb` are data-computed, here both exactly 53112.**
  `sbz = (BL_C[F[CM[10]]] − F[CM[13]]) mod 65536 = 53112 − _ds` with
  `_ds = (300222 XOR 845168) − 553422 = 0`, and `zb = 53112 + _dz` with
  `_dz = ((413384 XOR 491297) − 78313)·83 = 0`. Hard-coding 53112 is safe
  for this fixture; for generality compute from the anchors. `CM[10]/CM[13]`
  are written once (boot/AF) and never rewritten by any op — but a generic
  engine should still read them from the frame.
* **T3 — BL tables must be built exactly.** `BL_A/BL_B` start as identity
  0..16383 and are Fisher-Yates-shuffled descending `i = 16383..1` with two
  LCGs (`ka = 2147576667`, `kb = 2377930657`, step `·19985 + 4096326383`,
  swap index `ka mod (i+1)`). `BL_C[BL_A[b]] = (BL_B[b]·4 +
  ((b·17+8644) mod 16384)·2 + bit9(BL_A[b]) + 53112) mod 65536` — the 53112
  bias lives here and is what makes `BL_C[BL_A[u]] − exp(u) ≡ 53112` for
  every `u` (the engine may exploit this identity directly).
* **T4 — `pys` never rotates.** Dispatchers rotate or re-derive only
  `(pxs, u1s, u2s)`. It is frame slot 46 in every ring window. Rotating it
  breaks the payload cancellation silently.
* **T5 — slot update style is per-call-site.** `_dr[3080]` after `_hc[32]`
  and `_dr[1952]` after `_hc[16]` rotate locals; `_dr[1408]` after `_hc[3]`
  and `_dr[1952]` after `_hc[6]/_hc[1]/_hc[15]` re-derive from the new `rb`.
  Both are correct only because `up ⇒ swap` writes `NR̂` to `RMAP[rb+3]`
  (= `RMAP[rb+ls+1]` for `ls = 21`) and `down ⇒ keep` writes it to
  `RMAP[rb+4]` (= `RMAP[rb−ls+1]`). Mixing the styles, or the
  `SUC`-decoys' unconditional steps, breaks the ring.
* **T6 — `_h[1]` adds `kv` to all four channels** (ip delta, st base, sh
  base, payload) in the taken branch, and never adds `zb`. Missing the
  payload/`kv` term corrupts the next transition's `cur`.
* **T7 — K1 is mutable state with a one-shot rewrite.** The first inline
  rotor-setup op executed anywhere (guard `bxor(K1,432963489) ==
  1542308556`, true only for the initial `K1 = 1109638509`) sets
  `K1 = W[ip+4]+st XOR K0 XOR ps XOR st XOR _cs` (3080 layout; 1408 uses
  `W[ip+3]−st`). Every later `U(…, K1, …, 30027/38805)` decrypt uses the new
  K1. An engine that keeps K1 constant decrypts garbage after the first
  setup op.
* **T8 — stop/exit are identically 0** in this payload: all frames end via
  `return true, 93375`; `_h[5]`, the return-tag path, and the multi-value
  return codes are live code paths in the wrapper but never execute. Don't
  build control-flow that requires them; do keep them for profile
  completeness (the wrapper shape references them).
* **T9 — decoy dispatchers and phantom families.** `2517/3424/5521` are
  bounded no-op loops (`_dn < 4`, `ip+1` or `ip = 0`, always `return true`,
  no frame writes). RT keys `26754→2117, 10900→8358, 34417→1574` have **no**
  dispatcher — a correct trace never produces these shapes; treat their
  appearance as a decode error, not a fallthrough.
* **T10 — shape keys are a strong self-check.** After every transition the
  unmasked `sh` must be one of the three keys of the current family
  (3080: `58811, 39012, 53090`; 1408: `32567, 48861, 3879`;
  1952: `18273, 26325, 48352`) or a key of a family the next exec iteration
  will dispatch to. Anything else ⇒ wrong operand decode or wrong branch.
* **T11 — transition ops do not run the per-op st LCG.** The helper output
  *is* the next `st`. Applying the data-op `st = st·A+B` after a helper call
  double-advances the rotor chain.
* **T12 — number and string bases.** `number_base = W[4] XOR 3139019791
  XOR K0 = 16`; number `i` lives at `B[16 + (i−1)·8]` for id
  `i = _ua XOR 1329030`. String blobs live at byte offset
  `_ua XOR 701714` (length `_n` from the following word) inside the same
  2248-byte payload buffer; both are XOR-stream decrypted with K0/K1-derived
  LCG keys (`·2151 + 549576011`).
* **T13 — `make`, `JMT`, `_dexec`, `_dr[0]` are dead infrastructure** in this
  profile (never called / never assigned because `CM` is always truthy at
  that point). Don't spend engine effort modeling them beyond recognition.

---

## 10. Live-vs-decoy summary

| component | count | live | decoy/dead |
|-----------|-------|------|------------|
| dispatchers | 6 | 3080, 1408, 1952 | 2517, 3424, 5521 (no-ops); RT also names 2117/8358/1574 (nonexistent) |
| transition helpers | 33 | 1, 3, 5*, 6, 15, 16, 32 | 26 never called (22 wrong-salt: 2,4,8,9,10,11,13,14,17,18,19,20,21,23,24,25,27,28,29,30,31,33; 4 correct-salt: 7, 12, 22, 26) |
| U channels | 8 branches | 14471 (boot/AF salt), 42673 (zb), 31151 (strings), 39793 (numbers) | rf64-hash, `_mkv` salt, 2-char names, `_dz` salt |
| return codes | 6 | 93375 only | 287782/328993/604419/240743/769411 (decoded, never produced) |
| exec args | 6 | F only | 204/871/536/162/40/256/… decoy args |
| `make`/`JMT`/`_dexec` | — | never invoked | entire bodies |

\* `_h[5]` is referenced by the stop ops but never executes because
`stop == 0` always (T8); implement it, but expect zero invocations.
