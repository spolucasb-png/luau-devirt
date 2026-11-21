# Regression fixtures

`sample.lua` is an inert, VM-protected frame-scanner specimen for the supported
Adler-32 / LCG / five-word prototype profile.

**Never execute the specimen.** Tests parse its literals and perform static
decoder/CFG arithmetic. Compilation checks apply only to generated readable
Luau.

- `decoded-metadata.json`: static decoder reference, including absent words.
- `cfg-states.txt`: all seven fields of the 109 symbolic dispatcher states.
- `VM-DISASSEMBLY.md`: 55 reachable addresses from the static reference.
- `T001-VM-ANALYSIS.md`: portable reference facts used by integration tests.
- `T001-deobfuscated.luau`: readable golden result.

Python is not needed to run these tests. No hub, private game script, account
identifier, Real credential, or deployment file is included.
