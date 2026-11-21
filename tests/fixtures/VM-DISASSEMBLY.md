# T001 pseudo-disassembly

This lists all 55 instruction addresses reached from the two decoded prototype entries under intact VM tables. Every listed address was also observed in Real. `PC` is the one-based word index in the decoded table. `Family/selector` gives the interpreter handler and its normalized discriminator, not a Roblox bytecode opcode. `Source` refers to `beautifully at least.lua`.

`Rn` is physical frame slot `n`. The data registers used by the parser have the same meaning in both of its alternating register banks. The listing elides rolling-key calculations and frame masks except where they explain a transition. `pack` denotes a tuple with a separate result count; `TAG` updates VM bookkeeping, not a parser value.

## Entry prototype (header at word 505, starts at PC 413)

| PC | Family/selector | Pseudo-instruction and successor | Source |
| ---: | --- | --- | ---: |
| 413 | 6965/624 | Initialize decode phase `521943758` and bank sum `33`; no argument copy. Next 418. | 1732 |
| 418 | 6965/825 | Rotate into bank `19`; jump 466. | 1713 |
| 466 | 6965/172 | Advance over three words; next 469. | 1770 |
| 469 | 6965/1692 | `R31 = CLOSURE(651779 XOR 651803 = 24, captures=[])`; next 472. | 1793 |
| 472 | 6965/328 | Return `R31` (the parser). | 1767 |

## Parser prototype (header at word 24, starts at PC 388)

`R21` and `R33` carry the input; `R1` is the index, and `R43` is its current value. `R37` is the parser phase (`0` marker, `1` length, `2` payload, `3` checksum). `R35` is the expected payload length, `R9` counts payload values, and `R31` carries the sum modulo 256. `R4` is the valid count, `R38` the invalid count, and `R22` the accepted-checksum list. `R44`/`R45` are obfuscation-only branch state.

| PC | Family/selector | Pseudo-instruction and successor | Source |
| ---: | --- | --- | ---: |
| 030 | 1173/1282 | `R4 += 1`; append `R31` to `R22`; jump 298. | 1649 |
| 039 | 6094/704 | `R44 = 0`; jump 204. | 1189 |
| 046 | 1173/1520 | `R41 = pack(R4, R38)`; `R18 = env["table"]["concat"]`; `R24 = R22`; `R16 = ","`; next 057. | 1590 |
| 057 | 1173/1484 | `R32 = pack(R18(R24, R16))`; next 061. | 1642 |
| 061 | 1173/1503 | Append packed results `R32` to `R41`; next 065. | 1580 |
| 065 | 1173/231 | Return the packed tuple `R41`. | 1556 |
| 067 | 6094/1040 | `TAG(R10)`; next 069. | 1461 |
| 069 | 6094/429 | Numeric-for test on `R10`: jump 090 if in range, else 046. | 1153 |
| 079 | 6094/1665 | `R26 = R20`; jump 133 if truthy, else 196. | 1251 |
| 090 | 6094/79 | `R1 = R10[1]`; next 094. | 1117 |
| 094 | 6094/1040 | `TAG(R1)`; next 096. | 1461 |
| 096 | 6094/1607 | `R43 = R33[R1]`; `R17 = 0`; `R8 = (R37 == 0)`; next 104. | 1365 |
| 104 | 6094/632 | If `R8` then jump 368; otherwise permutation parity at `R17=0` selects 231. | 1220 |
| 108 | 6094/1651 | Jump 140. | 1345 |
| 113 | 6094/1651 | Jump 285. | 1345 |
| 118 | 6094/976 | Derive one-bit tag `R40` from `R27=2`; evaluates to 0. Next 121. | 1418 |
| 121 | 6094/117 | If `R37 == 3 + R40` then jump 310, else 285. | 1108 |
| 133 | 6094/344 | `R37 = R26`; jump 285. | 1162 |
| 140 | 6094/227 | `R35 = R43`; `R9 = 0`; `R20 = (R43 > 0)`; jump 321 if true, else 079. | 1092 |
| 154 | 6094/691 | If `R44 < 2` then jump 291, else 039. | 1198 |
| 165 | 6094/304 | `R33 = R21`; zero `R44`, `R45`, `R6`, `R37`, `R35`, `R31`, `R9`, `R4`; next 179. | 1171 |
| 179 | 6094/1956 | `R38 = R6`; `R22 = {}`; `R46 = 1`; `R13 = pack(#R21, 1)`; next 187. | 1286 |
| 187 | 6094/1965 | Check numeric-for bounds/step, coerce nonnumbers via `env.tonumber` if needed; `R10 = {R46, R13[1], R13[2]}` with normalized values. Next 191. | 1266 |
| 191 | 6094/251 | Jump 067. | 1132 |
| 196 | 6094/149 | `R26 = 3`; next 199. | 1084 |
| 199 | 6094/251 | Jump 133. | 1132 |
| 204 | 6094/903 | `R37 = 0`; jump 285. | 1448 |
| 231 | 6094/1145 | Derive one-bit tag `R7` from `R17=0`; evaluates to 1. Next 234. | 1376 |
| 234 | 6094/1535 | If `R37 == R7` then jump 108, else 246. | 1357 |
| 246 | 6094/1730 | `R27 = 2`; `R12 = (R37 == 2)`; next 251. | 1324 |
| 251 | 6094/632 | If `R12` then jump 398; otherwise permutation parity at `R27=2` selects 118. | 1220 |
| 255 | 6094/251 | Jump 285. | 1132 |
| 260 | 1173/1822 | `R38 += 1`; jump 298. | 1623 |
| 267 | 6094/704 | `R44 = 0`; jump 329. | 1189 |
| 274 | 6094/691 | If `R44 < 2` then jump 361, else 267. | 1198 |
| 285 | 6094/588 | `R10[1] += R10[3]`; jump 067. | 1208 |
| 291 | 6094/1697 | `R44 += 1`; jump 274. | 1331 |
| 298 | 6094/1802 | `R45 = 1 - R45`; if `R45 == 0` then jump 154, else 274. | 1310 |
| 310 | 6094/101 | If `R43 == R31` then jump 030 (valid), else 260 (invalid). | 1121 |
| 321 | 6094/149 | `R20 = 2`; next 324. | 1084 |
| 324 | 6094/1651 | Jump 079. | 1345 |
| 329 | 6094/1048 | `R37 = 0`; jump 285. | 1474 |
| 351 | 6094/1096 | `R37 = 1`; `R31 = 0`; jump 255. | 1399 |
| 361 | 6094/1697 | `R44 += 1`; jump 154. | 1331 |
| 368 | 6094/927 | `TAG(R43)`; next 370. | 1414 |
| 370 | 6094/1147 | If `R43 == 170` then jump 351, else 255. | 1390 |
| 381 | 6094/903 | `R37 = 3`; jump 113. | 1448 |
| 388 | 6094/791 | Copy argument to `R21` before rekeying; initialize decode phase `463635844` and bank sum `80`; next 393. | 1434 |
| 393 | 6094/1651 | Rotate into bank `56`; jump 165. | 1345 |
| 398 | 6094/1681 | `R31 = (R31 + R43) % 256`; `R9 += 1`; if `R9 >= R35` then jump 381, else 113. | 1236 |

## Reachability and simplification

Allowing all selector-table arms produces 60 addresses. At PC 104, PC 096 has just set the tag operand to `0`, for which `permutation_a[0] & 1 == 1`; the false arm therefore selects tag 18, not tag 17. At PC 251, PC 246 has just set the tag operand to `2`, for which `permutation_a[2] & 1 == 0`; the false arm selects tag 22, not tag 23. This removes PCs `211`, `216`, `219`, `336`, and `339`. `disassemble.py --all-arms` retains them for comparison.

The branches after a completed frame manipulate only `R44` and `R45`, then set phase `R37` back to 0 and continue at the next index. Removing those branches, VM tagging, bank changes, and encoded dispatch recovers the structured four-phase loop in [T001-deobfuscated.luau](../T001-deobfuscated.luau).
