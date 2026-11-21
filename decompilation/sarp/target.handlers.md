# SARP wrapper handler inventory (static, source-grounded)

Source: `decompilation/sarp/target.original.lua` (118433 bytes,
SHA256 `4518ff6626677a946e60b1f1fbf5e0e0bd6c2aa95a674c163864e763fff3d45f`).
Every fact below is derived from the token layout in `diagnostics/wrapper.tokens.txt`
and the per-function dumps in `diagnostics/` (`boot.txt`, `initOnce.txt`, `make.txt`,
`initC.txt`, `initB.txt`, `_h_1..36.txt`, `_dr_*.txt`, `U.txt`, `exec.txt`).
No Lua/Luau was executed; all arithmetic identities were recomputed as static math.

## 1. Wrapper layout (lexical.json)

```
boot        tokens 435-1444    bytes 4155-6447
initOnce    tokens 1446-3026   bytes 6448-10201
make        tokens 3028-3666    bytes 10202-11603
initC       tokens 3668-3713   bytes 11604-11730   (no-op guard)
initB       tokens 3715-50402  bytes 11731-113412  (contains _h[1..36], _dr[7], EX/AF build)
U           tokens 50404-52108 bytes 113413-117570
exec        tokens 52110-52494 bytes 117571-118416 (top-level decoy; overwritten by initB)
tail:       return boot(...)   bytes 118417-118433
```

The top-level `exec` (3 families only) is dead: `initB` line 399 does
`exec = _exec` where `_exec` dispatches all seven `_dr` families. `boot` never
reads the global `exec`; it calls `EX[30506]` directly.

## 2. Boot chain and keys

`return boot(...)` forwards the chunk varargs. First `boot` call runs
`initOnce(bxor(66482806, 3268698463))` with `sa = 3240235817`.

`initOnce` (state machine, static seeds only):

- Blob `B` (2264 bytes = 566 u32 words): Base85 chunks `_pc0.._pc4`
  (566*5 chars, alphabet `xUvtToqpzV^657!...`, value = little-endian u32,
  `bswap` on store) whitened by LCG `_tk = (_tk*17487 + 3048913621) % 2^32`,
  seed `1147127625`. **B is fully static (no key).**
- `W[1..4]`: `st = bxor(sa, 1496625396) = 2551620573`; per word
  `st = (st*398991 + 3534337991) % 2^32; st = bswap(st);
  st ^= lshift(st,9); st ^= rshift(st,5); st ^= lshift(st,1);
  wt[i] = bxor(r32(B,(i-1)*4), st)`.
- Environment probes accumulate `_pe` (table+1 pcall flag, coroutine flags,
  +512 bit32.replace, +4096 math.frexp/ldexp/modf/clamp, +1024
  string.format/reverse, +64 string.pack/tonumber base 31).
- `m0 = bxor(sa, r32(B,12))`; `m1 = (m0*26797 + 1259477385) % 2^32`;
  `wf64(fb,0, m1 + wt[4] + 1048576)` -> `_flo,_fhi` (low/high u32 of the f64 bits);
  `_cz = clz(m0)*65537 + crz(r32(B,12))*257 + clz(wt[4])`;
  **`K0 = bxor((m1 + _flo) % 2^32, lrot(wt[4],11), _fhi, bswap(bxor(m0,_pe)), _cz)`**
  (environment- and B-dependent; any `_pe != 0` derails everything).
- **`K1 = bxor(4021752008, 3067287787) = 1499727907`** (initial; replaced once
  by the K1-activation opcode, see 5.4).
- `ws = bxor(wt[2], bxor(3678364643, K0))`, `ce = bxor(wt[3], bxor(3087163986, K0))`.
- `initB` runs as a coroutine; handshake: initB `cyield(K0)` (only after
  BL_A/BL_B/BL_C are built), initOnce resumes with `bxor(_ibv or 0, K0) = 0`;
  only then does initB whiten `W[ws..ce]` (see 3).

## 3. initB construction (order of states 26216 -> 53782 -> 46996 -> 23122 -> ...)

1. **KBOX** (static): `kt[i] = 1 + (ks % 200000)`, LCG
   `ks = (ks*26663 + 4214497697) % 2^32`, seed `706272505`, 64 entries.
2. **BL_A/BL_B/BL_C** (static, 16384 u16 each):
   `_ba`/`_bb` start as identity permutations 0..16383; Fisher-Yates with two
   LCGs `_ka = 1933532995`, `_kb = 2171122303` (`*17577 + 419902917`);
   `BL_C[2*pa] = (pb*4 + ((b*17+1833)%16384)*2 + parity(pa,pb)^1 + 12836) % 65536`;
   afterwards BL_A/BL_B entries get random flag bits 14..15
   (`bor(v, lshift(bext(lcg,20,2),14))`) so readers must `band(v,16383)`.
   The `+12836` term is the salt identity (see 7).
3. **W whitening** (after the yield handshake): for `_wi = ws..ce`:
   `_k2 = (_k2*7745 + 888415943) % 2^32`, seed `bxor(K0, 2372119159)`;
   `W[_wi] ^= bxor(BL_A[2*(_k2&16383)], lshift(BL_B[2*((_k2>>14)&16383)],16),
   KBOX[1+(_wi%64)], BL_C[2*((_k2^_wi)&16383)])`. **K0-dependent.**
4. **RMAP** (118 slots, K0-dependent): `rk = bxor(3402759894, K0)`;
   59 words read from `B[ce*4 ..]`; `rk = (rk*24307 + 1800847725) % 2^32` per
   word; `rm[i] = pw & 65535`, `rm[i+1] = pw >> 16`. Slot 1..15 are the
   control cells (see 4), `rb+1..rb+4` are rotor cells, `rb+5..` registers.
5. Guard: `_dm == blen(B)` integrity word chain (`initC` is a no-op stub).
6. **CM/CM2/CM3, BM1/BM2, RT, MO, MO2, JMT, EX, HC(=_h), AF, DR** (see 4-6).
7. `_sma = 1771687064`, `_smb = 4294002830`, `_ek = 462419941`,
   `_bk = bxor(K0, 647117177)` (initB line 289; `_dr_1901`/`_dr_359` re-declare
   the same `_sma/_smb` locally).
8. `JMT[1..3]` = 4-word constant sets `{19030191,966049205,2785401419,2991907552}`
   etc. (bound to a jump-metadata op; no current family references JMT — dead).

## 4. Control-cell aliasing (the "new state tuple")

Control cells live at **absolute ring slots 1..15** (`C_* = RMAP[k]`):

```
C_STOP=rm[1]  C_RBE=rm[2]  C_SH=rm[3]   C_RN=rm[4]   C_AP=rm[5]
C_SB2=rm[6]   C_ST=rm[7]   C_KD=rm[8]   C_EXIT=rm[9] C_RV=rm[10]
C_RBS=rm[11]  C_IP=rm[12]  C_SB1=rm[13] C_RB=rm[14]  C_PS=rm[15]
```

Three per-family views (numbers marked `*` are decoy constants used only by
no-op self-writes `F[cm[k]] = F[cm[k]]`):

```
CM  (2199, exec, boot): 1=C_ST 2=C_SB1 3=C_RN 4=17* 5=C_KD 6=C_RV 7=C_SB2
   8=C_IP 9=C_EXIT 10=C_RBS 11=C_SH 12=3* 13=48* 14=C_RBE 15=33* 16=46*
   17=C_RB 18=49* 19=10* 20=C_AP 21=C_PS 22=11* 23=5* 24=C_STOP 25=4*
CM2 (359): 1=C_RN 2=C_STOP 3=C_EXIT 4=19* 5=C_IP 6=C_RV 7=17* 8=C_RBS
   9=C_SB2 10=12* 11=C_KD 12=22* 13=25* 14=C_RBE 15=5* 16=C_SH 17=C_PS
   18=7* 19=31* 20=46* 21=16* 22=C_SB1 23=C_ST 24=C_RB 25=C_AP 26=40*
CM3 (1901): 1=C_RBS 2=C_KD 3=43* 4=39* 5=C_IP 6=46* 7=C_RN 8=C_SB2
   9=C_ST 10=C_RB 11=11* 12=7* 13=C_SH 14=9* 15=C_RV 16=C_SB1 17=C_STOP
   18=C_AP 19=41* 20=C_PS 21=C_RBE 22=C_EXIT 23=32*
```

Verified aliases: ip cell `CM[8]=CM2[5]=CM3[5]=C_IP`; st `CM[1]=CM2[23]=CM3[9]`;
sh `CM[11]=CM2[16]=CM3[13]`; ring base `CM[17]=CM2[24]=CM3[10]`;
window `CM[10]=CM2[8]=CM3[1]=C_RBS`; ring top `CM[14]=CM2[14]=CM3[21]=C_RBE`;
ps `CM[21]=CM2[17]=CM3[20]`; stop `CM[24]=CM2[2]=CM3[17]`;
exit `CM[9]=CM2[3]=CM3[22]`; salts `CM[2]/CM[7]=CM2[22]/CM2[9]=CM3[16]/CM3[8]`;
arity `CM[3]=CM2[1]=CM3[7]=C_RN`; values `CM[6]=CM2[6]=CM3[15]=C_RV`;
KD `CM[5]=CM2[11]=CM3[2]=C_KD`; argpack `CM[20]=CM2[25]=CM3[18]=C_AP`.

Stored vs. working state (boot/exec layer, rotor `_r = bxor(F[RMAP[rb+1]], _sma)`):

```
ip_cell = ip + _r*5      st_cell = st + _r*61     sh_cell = sh + _r*137
```

The dormant `_h_15` stop alternative writes `F[CM[5]] = bxor(st_exit, _ek)`; boot re-derives
`_fst = F[CM[1]] - _rr*61`; exit valid iff `F[CM[5]] == bxor(_fst, 462419941)`.
Return arity `_n = bxor(F[CM[3]], band(_fst,65535))`.

## 5. Opcode families

### 5.1 Real families (exec-dispatched, masking-aware)

| family | cell view | op decode | operand decode styles |
|---|---|---|---|
| 2199 | CM  | `((W[ip] - st*11 - ps) % 2^32) - 6806` | `(W[k]-st)`, `(W[k]+st)`, `bxor(W[k],st)`, `st*5/7/9/11/13/15` variants |
| 1901 | CM3 | `bxor(W[ip], st, ps) - 35367` | same three styles |
| 359  | CM2 | `bxor(W[ip], lrot(st,16), ps*53) - 7411` | same three styles |

All three enter in "captured factory" mode when `_eip ~= nil`
(`rb,ps,stop,exit,ip,st,sh = _erb,_eps,0,0,_eip,_est,_m`, masking off) and in
frame mode otherwise, applying the 5/61/137 unmask when `F[C_RBS] ~= 0`.
Exit writes back with the same mask. `_hc[15](F,_r,st,sh)` exits a called
closure; `stop==0` exits the root with `return true, 135301`.

Real op groups observed (359 richest): direct two/three-argument calls
(`F[sb](F[s0],F[s1])` or `F[sb](F[s0],F[s1],F[s2])`, results to a slot or discarded), MO unary,
inline `F[d] = bxor((F[s] or 0), band(st,255))`, KBOX numeric loads
(`word - KBOX[i] - 524288`, i in {9,29,32,35,39,40,46,49,51,63}), constant
loads via `SM[k] or U(...,50523,...)` (strings) and `NM[k] or U(...,52374,...)`
(numbers), GETTABLE (`F[rl1][const]`, `F[rl2][F[rl4]]`), SETTABLE
(`F[rl1][F[rl2]] = v`, `_fr0[const] = v`), table constructors (`{}` + keyed
fills), boolean const `(bxor(W[k],st) ~= 0)`, salt refresh
(`U(293, F[sl], ..., 60285, ..., 792406, 51)` -> rewrites the frame salt pair),
arith (`F[rl1] + (W - KBOX[i] - 524288)`), moves, and the five transition ops
(see 8). 1901 adds `_mo(bxor(301, band(K1,1023)), const)` (a MO-keyed unary on
a decoded constant) and two fixed-arg CALL forms; 2199 adds the K1-activation
op (5.4) and jump ops via `_hc[18]`.

### 5.2 Decoy families (never valid on the genuine stream)

`_dr_755` (op `W - st - ps - 41248`), `_dr_1868` (`W - lrot(st,23) - ps*55 - 37038`),
`_dr_8434` (`W - lrot(st,8) - ps*31 - 9594`), `_dr_7480`
(`W - lrot(st,17) - ps*51 - 16098`):

- no rotor unmask on entry, no mask on writeback -> they read masked cells as
  raw and write raw values back, corrupting the tuple whenever masking is on;
- dormant traps `if _hc[17] == nil / _hc[10] == nil / _hc[30] == nil then ip = 0`;
- only junk unary ops and `F[cmN[k]] = F[cmN[k]]` decoy touches;
- RT contains 19 entries pointing at them
  (8434: 57558,32958,11590,3838,46874,11670; 7480: 22900,54298,3585,40544,30617;
  1868: 54937,26931,29856,22553; 755: 49325,32252,8097,252). Reaching one of
  those sh values derails the frame permanently.

Real RT entries: 1901 {8215,40052,5556,28582,14729}; 2199
{60081,42631,3539,56332,3010}; 359 {39632,57003,24074,24320,17421}.

### 5.3 EX (metatable `__index: _exb[bxor(k, 31954)]`)

`EX[30506] -> 3064 = _exec` (7-family dispatcher; used by boot).
`EX[25191] -> 7861 = _exec2` (same, different decoy args; used by AF factories).
`_exb[3907] = _dexec`, `_exb[1377] = _dexec2` are fake loops that never call
`_dr`. Boot passes `_bk = bxor(K0, 647117177)` as arg 2 (only used as a
pass-through decoy in `_exec`).

### 5.4 K1 activation + ring-window op (family 2199, op <444 or 1224..1357)

```
if bxor(K1, 3067287787) == 4021752008 then        -- i.e. K1 == 1499727907 (once)
    K1 = bxor((W[ip+1] +- st), bxor(K0, bxor(ps, bxor(st, _cs))))
end
_sr = bor(((W[ip+3] - st*15) % 2^32), 1)   -- new rotor, forced odd
F[_pxs] = bxor(_sr, _sma);  F[_pys] = _cs - (_sr + _smb)
F[C_RBS] = _ls (stream word);  F[C_RBE] = rb + 2*_ls
-- optionally spills the old rotor to a stack slot first (F[_sl] = F[_pxs])
```

This is the only writer of `F[C_RBS]`/`F[C_RBE]`; until it runs, masking is off
and `_r = 0`. It also fixes `band(K1,1023)` for every MO lookup,
`band(rshift(K1,10),1023)` for the MO index transform,
`band(rshift(K1,5),1023)` for MO2, `band(rshift(K1,20),1023)` for the 359
compare key, and `bxor(K1, _sbz)` (= K1 ^ 12836) for U's const keys.

## 6. Key-dependent function tables

**MO** (unary; `__index`/`__call`: slot `bxor(k, band(rshift(K1,10),1023), 944)`):

```
 1: (num,num) and a-b+70 or nil   [decoy]      13: tcreate(4)
 2: tcreate(4)                                 14: bxor((num a or 110), band(K1,255)) [keyed]
 3: -a                                          15: G[k]            (getglobal)
 4: {n=0} (empty tuple)                         16: bxor((num a or 108), band(K1,255)) [keyed]
 5: {a,n=1}                                    17: a .. b          (concat)
 6: tcreate(4)                                 18: {}
 7: #a                                          19: a // b          (floordiv)
 8: {a,n=1}                                     20: not a
 9: G[k]=v (setglobal)                          21: a ^ b           (pow)
10: (num,num) and a-b+24 or nil [decoy]         22: a == b
11: a~=b and a==b  [compound comparisons]        23: a < b
12: (num,num) and a-b+40 or nil [decoy]
```

**MO2** (binary; slot `bxor(k, band(rshift(K1,5),1023), 504)`):

```
 1,2,14,19: a>b      4,6,10: a>=b     18,21: a<b     7,15,22: a<=b
 3,8: a~=b           13: a==b         12: a<=b and b<=a
 9: (a or 0)-(b or 0)   11: a/b   16: a%b
 5: bxor(band(a or 0,65535), band(b or 0,65535))   17,20: a==b and a~=b
```

The duplicate/decoy slots make the effective op unknowable until activated K1
is known. Family 359's compare uses
`_mo2(bxor(989, band(rshift(K1,20),1023)), a, b)` -> final slot
`989 ^ ((K1>>20)&1023) ^ ((K1>>5)&1023) ^ 504`.
Family call-style `_mo(bxor(301, band(K1,1023)), v)` -> slot
`301 ^ (K1&1023) ^ ((K1>>10)&1023) ^ 944`.

Compound comparisons above are documented literally, not simplified to a
single equality or constant false: arbitrary values may invoke comparison
metamethods. Unsupported entries are rejected if reached.

## 7. Salt identities (all static, proven by canceling constants)

1. **Frame salt** (boot `U(489,_v0,...,60285,...,792406,697)`; AF factory
   `U(464,ps,...,60285,...,792406,720)`; 359 salt-refresh
   `U(293,F[sl],...,60285,...,792406,51)`): `_ds = bxor(792406,155290) - 936396`
   and `bxor(792406,155290) = 936396` exactly -> **`_ds = 0`**. U op-47484
   returns `(_pa, _exp, _tb + _sbz + _ds*99)`; the helpers compute
   `_sbz = (BL_C[2*F[C_SB1]] - F[C_SB2]) % 65536 = (exp+12836) - exp = 12836`.
   **`_sbz = 12836` for every genuine frame, every salt-source type/value.**
2. **Condition channel** (helpers 1,5,19,23,26,32:
   `U(567,_c,618,383,211,13444,351,275,643962,984)`): `_op = bxor(13444,20993)
   = 26245` selects the BL_C single-value branch;
   `_dz = (bxor(643962,177821) - 746983)*99` and `bxor(643962,177821) = 746983`
   exactly -> **`_dz = 0`**, so the channel returns
   `(BL_C[2*pa] - _exp) = 12836` for **every** condition type/value. It is a
   pure constant disguised as data-dependent.
3. **`_h_27` `_z` channel**: `_zb = band(_x,16383)` for int32 `_x`,
   `band(#_x,16383)` for strings, else 0; every index b satisfies
   `BL_C[2*pa_b] = exp_b + 12836`, so **`_z = 12836` for every type of `_x`**
   (including the `_zb = 0` fallback).
4. U's internal gate `bxor(_sbz,48727) == 35955` is `bxor(48727,35955) = 12836`
   -> passes for all genuine frames; it keys constant decode with
   `_k1 = bxor(_ub, _sbz) = K1 ^ 12836` and enables SM/NM caching.
5. In op-47484, `_tb` starts at **74056**. Number and string values bypass
   the TM lookup; boolean values use BM_BOOL, whose entries are also 74056.
   Other supported type names map to 74056. Thus `_tg = 86892` for these
   values/types. Boot and dormant AF factories use `est + 86892`.
   TM["number"] and TM["string"] are not this channel's `_tb`.

U selector math (`_op = bxor(_um, 20993)`): `60285 -> 47484` salt triple,
`50523 -> 38746` SM string const, `52374 -> 40599` NM number const,
`13444 -> 26245` constant 12836. The rf64 box (`_op < 26245`), 2-char tag
(`27902..38745`) and table-box (`_op > 56274`) branches are unused by the
families and boot.

**NM decode** (needs K0, activated K1): index `_i = bxor(_ua,1071764)`;
`_o = bxor(W[1], bxor(2115480298,K0))`; `_p = _o + 8*(_i-1)`;
`w0 = bxor(r32(B,_p), bxor((495004947+_i*464691)%2^32, bxor(K0, K1^12836)))`;
`w1 = bxor(r32(B,_p+4), bxor((1772561933+_i*290983)%2^32,
bxor(bxor(rshift(K0,11),lshift(K0,21)), bxor(rshift(K1^12836,7), lshift(K1^12836,25)))))`;
value = `rf64` of (w0,w1). **SM decode**: `_o = bxor(_ua,1528192)`;
`_ps = bxor(r32(B,_o),1573349377)`; `_n = bxor(r32(B,_o+4), bxor(1638974510,_ps))`;
`_k = bxor(_ps, K0, K1, 12836)`; per word `_k = (_k*22439+195899001)%2^32`.

## 8. The 36 `_h` helpers: classified (none are opcodes)

All 36 are state-transition micro-helpers sharing one skeleton
(`_r = bxor(F[_pxs], SALT_h)`; `_nr = (_r*433233+2142828636)%2^32`;
ring move; rotor-cell shuffle; `F[_pys] = ct - (_nr+_smb)`; masked triple out).
**None of them interprets an opcode**; opcode work happens in the family trees.

| class | count | members |
|---|---|---|
| source-referenced | 7 | 15 (dormant stop leaf), 18 (2199 back), 23 (1901 cond), 1, 5, 27, 35 (359) |
| salt-compatible unused | 4 | 19, 26, 32, 33 (read rotor with `_sma` but never called) |
| hard decoys (unique rotor salt) | 25 | 2,3,4,6,7,8,9,10,11,12,13,14,16,17,20,21,22,24,25,28,29,30,31,34,36 |

Hard-decoy rotor salts (would derail if invoked): h2 484189935, h3 4195661982,
h4 1483682633, h6 2516455339, h7 1932953178, h8 3507034117, h9 2940310196,
h10 244847975, h11 3973115670, h12 1244357057, h13 677640304, h14 2277143075,
h16 3284487837, h17 2703081804, h20 2095535193, h21 3661508104, h22 3094782139,
h24 4118920469, h25 1406678980, h28 1856215761, h29 3438943360, h30 2855442227,
h31 134572514, h34 602733583, h36 528468329.

Masking multiplier sets of the returned triple (`mip, mst, msh`):

```
A-set (21 add, 43 xor, 107 add): h1 h4 h5 h7 h10 h13 h16 h22 h25 h27 h28 h31 h34 h35
B-set (17 add,  95 add, 153 add): h2 h8 h11 h14 h17 h19 h20 h23 h29 h33
C-set (3 xor,   49 add, 177 xor): h3 h6 h9 h12 h18 h21 h24 h26 h30 h32 h36
leaf: h15 (writes the exit tuple directly)
```

Family use: 2199 pairs `_hc[18]` (C-set, back) with caller-side local rotation;
1901 pairs `_hc[23]` (B-set, cond) with reload from the new ring base; 359 pairs
`_hc[1]` (A-set, cond, callee truthy -> fwd), `_hc[5]` (A-set, cond, inverted
polarity), `_hc[27]` (A-set, hash-switch), `_hc[35]` (A-set, fwd) with local
rotation for `_hc[35]` and reload for `_hc[1]/[5]/[27]`. All families reference
`_hc[15]` only in stop alternatives; root stop==0 bypasses it.

See `diagnostics/transition-review.md` for the normalized per-helper formulas,
ring model, and `_h_27` bounded evaluation rules.

## 9. Closure machinery (captured factories)

`make(tk, _mkd1, ups, _mkd2, _ms, _mkd0)`: FM cache check
`_chk = _ms ~= nil and bxor(bxor(_ms,K1),48727) == 35955`; proto header read at
`hw = bxor(tk, 774880)` from W (salted with `bxor(const, bxor(K0,_ms))`):
entry=+0 (1151433088), mtB=+1 (4028605236), mtA=+2 (1209284937), cStart=+3
(2871857514), est=+4 (3098405659), esh=+5 (445800084), cLen=+6 (2766250242);
upvalue slots `us[i] = band(rshift(bxor(W[ub+i-1], bxor(675436679,hk)),16),65535)`;
arg slots wA/wB salted `bxor(372244837,hk)`;
`mtA -> uc=(>>18)&1023, ar=bext(28,3), da=(>>31)&1, ps=(>>1)&65535`;
`mtB -> size=(>>18)&8191, rb=(>>1)&131071`.
`AF[ar](...)` receives `tk, bxor(cStart,band(K1,65535)),
bxor(_chk and cLen or 0, band(rshift(K1,8),65535)), bxor(hk,K1)`.

AF factory (e.g. AF[4], initB 1408-1542):

- frame salt from `ps` via op-47484 (genuine pair, `_sbz = 12836`);
   `_ist0 = est + 86892` (number channel bypasses TM lookup);
- `return function(ups) return function(v0,v1,v2,v3)` — per-closure decode-once
  flag `_dec` and **lazy per-proto W decryption**:
  `_cs = cStart ^ (K1&65535)`, `_cl = cLen ^ ((K1>>8)&65535)`,
   `_hk0 = bxor(_phk,K1) = _hk` (effective prototype key, not its word index);
  keystream seed
  `bxor(bxor(_hk0, ps*65537, est, 3316659204), clz(est) + crz(ps)*257)`, then per
  word `i = 0.._cl-1`: `_lk = (_lk*9635+3540373453)%2^32;
  _lk = bxor(lrot(_lk,11), rshift(_lk,13)); W[_cs+i] ^= _lk`
  (`PD[tk]` once-guard). **User protos' instruction words are encrypted in W and
  only become decodable here — user closures are reachable only after this
  bytecode ref step.**
- frame init: `F[C_RB],F[C_PS],F[C_STOP],F[C_EXIT],F[C_RBS] = rb,ps,0,0,0`;
  salt pair; `F[_pxs],F[_pys] = v0,v0` (placeholder rotor, never read before the
  K1-activation op overwrites it); args to slots (da==1) or `F[C_AP] = tpack`;
  upvalues `F[_ups[i]] = ups[i]`;
- direct entry: `_dr[RT[esh]]` in captured-factory mode
  (359: `(_rb,_ist0,esh,entry,F,208,602,ps)`; 2199:
  `(entry,esh,974,rb,F,_ist0,118,49,43,451,ps)`; 1901:
  `(F,entry,esh,ps,659,_ist0,rb)`), continuing via `EX[25191] = _exec2` when the
  segment ends in a family transition;
- Return codes 57430/884221/135301/96256/600530/371956 are consumed by boot/AF.
  Stop is always zero in this root, so the reachable family terminator returns
  **`true, 135301`**, which boot maps to no values. The `_h_15` tag-check path
  is referenced but dormant, not the reachable root exit.

## 10. Root invocation

Tail: `return boot(...)` — the protected program runs at load time with the
chunk's varargs. Root token `tk_root = bxor(K0, 1301695962)` (from
`(2674807212+2921856046)%2^32`); `hw = bxor(tk_root, 774880)`. Root salt is
taken from `_v0` (chunk vararg #1, typically nil -> entry st `est + 86892`).
The root frame is built by `boot` itself (size >= 52, register window from the
proto header `rb`, upvalue slots, salt pair), then
`EX[30506](88, bxor(K0,647117177), F, 136, bxor(_tg,_bs), 690)` starts the
dispatcher. Anything the program exposes beyond load time must come out of the
decoded W stream (user closures via make/AF).
