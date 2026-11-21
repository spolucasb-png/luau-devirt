# Supported VM profile

Profile identifier: **`adler32-lcg-5word-v1`**.

This identifier describes a checked implementation profile, not every
obfuscator that happens to use an Adler checksum or a flattened VM.

## Wrapper and extraction

The leading Lua table stores an escaped binary literal and twelve small
type-name literals. Two active tables supply lengths and Adler-32 checksums.
The extractor resolves the actual comparison's table bindings, so an unused
matching checksum table cannot hide a corrupted active table.

Quoted strings support up-to-three-digit decimal escapes, standard escapes,
hex escapes, ASCII-whitespace `\z`, and escaped line endings. Literal UTF-8
bytes are preserved. Raw line endings inside short strings are rejected.

The checked initializer transcribes the word-key stream and master-key
derivation with wrapping 32-bit arithmetic. Payload-specific initialization
arguments, master keys, decoded bounds, and descriptors are derived, not
substituted from the golden sample. Unsupported formula changes are rejected.

## Buffer, slots, and constants

- Raw words are little-endian u32.
- The decoded table is one-based; absent words stay absent.
- The physical slot map has 120 decrypted u16 entries. Repeated entries are
  legitimate register banks/aliases.
- String record headers and their LCG streams recover raw byte strings.
- f64 records preserve their exact 64-bit encodings, including NaNs.
- String-candidate allocation, overlap, count, and work budgets are checked.

The specimen contains 2,276 bytes, 569 raw words, and 490 populated decoded
words (headers 1–4 and range 24–509). These are regression facts, not a general
claim that every payload must have that length.

## Prototypes

An encoded reference XORs to a one-based descriptor word `p`.
Five words at `p + 0..4` encode:

1. Initial dispatch token.
2. Initial operand/decode key.
3. Packed frame capacity, fixed-call mode, and register-bank base.
4. Packed arity, captures, and opcode salt.
5. Entry instruction address.

Parameter/capture records follow the descriptor. Arity and slot windows are
validated before a candidate is accepted.

## Instructions and symbolic CFG

Instructions are custom, variable-length word sequences—not ordinary Roblox
opcode A/B/C words. Register operands resolve through the current slot bank;
immediates include state adjustments and generated bias terms.

The implemented substantive family selectors are:

```text
6094: ((W[pc] - key * 5 - salt) mod 2^32) - 5177
1173: xor(W[pc], key, salt) - 13579
6965: ((W[pc] - key - salt) mod 2^32) - 43880
```

Their source comparison trees identify leaves by ranges, not only one observed
selector value. The worklist tracks:

```text
(pc, key_state, bank_base, dispatch_token, phase, bank_sum, prototype_salt)
```

Selector parity is pruned only from proved register facts. All state variants
at one address must agree modulo bank aliases. Alias merging is permitted only
when full-state liveness and destination/live-out interference checks pass.

The bundled specimen reaches 55 addresses in 109 distinct states.

## Emission and limits

The typed IR separates ordinary arrays, packed tuples, scalar call elements,
tuple splices, language returns, and dispatch halts. A numeric table write does
not imply a tuple `.n` change.

Silent regions are folded only after equal-effect and termination proofs.
Numeric-for promotion cannot consume extra calls or other observable work.
No unsafe `goto` syntax is emitted for Luau.

Nonempty capture binding and post-halt wrapper return-tag evaluation remain
explicit unsupported emission cases. Unknown leaves never become a made-up
successful recovery.

Current bounds include 8 MiB source, 1 MiB payload, 512 dispatcher states, 8,192
worklist pops, bounded handler expression depth, and aggregate string budgets.

## Additional profile: base85-rotor-3bank-v1

`src/base85.rs` implements a separately certified wrapper with a custom
least-significant-digit-first Base85 transport, rotate/xorshift word cipher,
five-word descriptors in a different order, 111-entry register map, three-bank
rotating scratch roles, and state-dependent constant keys. It does not reuse
the older profile's formulas. Source token certification excludes only the
payload literal; unknown formula/handler changes fail closed.

Its bounded symbolic model records PC, key, bank, dispatch token, prototype
salt, normalized phase, window, bank ceiling and constant-pool key. Raw rotor
masks are cancelled by proved source inverses; data is lifted into the shared
IR and is never executed. Distinct scratch roles remain distinct. The detailed
profile and per-helper proofs are in `decompilation/message/target.handlers.md`.

The specimen yields 2,248 payload bytes, 317 populated words, one reachable
prototype, 42 instruction addresses and 162 normalized states. Nonescaping
initialized integer control facts reduce the typed CFG to 29 data blocks. An
order-preserving captured-environment renderer uses the shared CFG validation
and postdominators and emits eight external calls exactly once. Unsupported
captures, roots, operations, loops and structures remain explicit errors.
