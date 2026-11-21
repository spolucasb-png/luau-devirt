# Static VM regression facts

The integrity check covers 13 initial strings.
The first escaped string parses to the same **2,276 bytes**, with payload SHA-256
`aedd2957ca229f1c1684ebdea85eaa4d5d247cc52a21b8ec47d2a29e932dad91`.

The call argument is `3935408727`; the derived global key `var15` is `2702369233`.
The slot map contains 120 decrypted 16-bit entries and addresses 46 distinct physical frame slots.
The 64 immediate-bias table entries are recorded in `decoded-metadata.json`.

The three reached families are 6094, 1173, and 6965.

```text
9179, 32310, 9024 -> handler 1173
11366, 49540, 33141 -> handler 6094
55358, 53479, 33163 -> handler 6965
57492 -> handler 4270
42961 -> handler 8258
35097 -> handler 5377
16911 -> handler 8487
```

Resolving selector parity reduced this to **55 reachable addresses** (5 entry, 50 parser).
The walk retained **109 combinations** of PC, decode key, bank, dispatch token,
phase, bank sum, and prototype salt. It did not execute Lua or VM instructions.

Prototype header word 24 has entry PC 388 and one fixed parameter.
Prototype header word 505 has entry PC 413 and packed-vararg mode.
String records at byte offsets 48, 64, and 80 decode to `table`, `concat`, and `,`.
The four f64 records are `-131`, `757`, `-650/7`, and `289`.

This file contains only portable regression facts. Local paths, account names,
client identifiers, and executor deployment information are intentionally absent.
