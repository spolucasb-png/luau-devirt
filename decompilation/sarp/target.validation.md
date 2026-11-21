# SARP 0.2.0 static validation

Baseline: `3ffea1943b15feffeceb29f6193238163d055511`, `main`, `v0.1.0`, initially clean.
Baseline formatting/tests/release build passed (112 reported tests; one optional parser check skipped).
Dedicated implementation branch: `sarp-profile`. Final version: `0.2.0`.

Final Cargo results: **127 tests reported passing**, zero failures. One preexisting optional local-parser check was unavailable and explicitly skipped; it is **not counted as a performed check**. Official Luau 0.747 compiler and analyzer ran successfully. Aggregate verification covered all three profiles.

| Check | Exact command | Exit | Seconds |
| --- | --- | ---: | ---: |
| fmt | `cargo fmt --check` | 0 | 0.543 |
| tests | `cargo test --locked -- --nocapture` | 0 | 12.927 |
| build | `cargo build --release --locked` | 0 | 67.127 |
| reference | `python decompilation/sarp/diagnostics/reference.py` | 0 | 0.132 |
| recovery | `cargo run --release --locked --example recover_sarp -- tests/fixtures/sarp.lua decompilation/sarp` | 0 | 26.016 |
| hash-reference | `python decompilation/sarp/diagnostics/hash_reference.py` | 0 | 0.149 |
| inspect | `target/release/luau-devirt.exe decompilation/sarp/target.original.lua --inspect` | 0 | 0.034 |
| cli | `target/release/luau-devirt.exe decompilation/sarp/target.original.lua -o decompilation/sarp/target.cli.luau --force` | 0 | 0.037 |
| adler | `target/release/luau-devirt.exe tests/fixtures/sample.lua -o decompilation\sarp\logs\final-adler.luau --force` | 0 | 0.045 |
| rotor | `target/release/luau-devirt.exe tests/fixtures/base85-rotor.lua -o decompilation\sarp\logs\final-rotor.luau --force` | 0 | 0.113 |
| compile | `tools/luau-0.747/luau-compile.exe --null decompilation/sarp/target.deobfuscated.lua` | 0 | 0.008 |
| analyze | `tools/luau-0.747/luau-analyze.exe decompilation/sarp/target.deobfuscated.lua` | 0 | 0.017 |
| aggregate | `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File tools/verify.ps1 -RequireExternalTools` | 0 | 9.53 |

All stdout/stderr and exit-code records are saved in local `logs/final-*` files and `logs/final-results.json`, excluded from source/binary archives.

Packaging command:
`powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File tools/package.ps1 -SkipBuild -Force`
returned **0** (3.202 seconds). Both ZIPs were CRC-checked and inspected against
the explicit allowlists. Build caches, private paths, credentials, executables
used for local diagnostics and unrelated logs are excluded. The three reviewed
Python source diagnostics are included for independent reproduction.

Source SHA-256: `4518ff6626677a946e60b1f1fbf5e0e0bd6c2aa95a674c163864e763fff3d45f`.
Payload SHA-256: `0b27a42d1fcea8d6a268848800b7cd04681167b15d007094a5082e3dd1f52d0f` (2264 bytes / 566 words).
Output SHA-256: `e9c1055148831d6bd553fbfebedd4d4fedd19ebc92f6dba54aab6cedbe2fbc7b`.

The Rust and independent diagnostic agree byte-for-byte on payload, all 566 decoded word positions (including absent entries), 118 physical map entries, 64 biases, 35 string records and all three referenced f64 bit patterns. Both reached constant hash-gate proofs match independently transcribed 60-round arithmetic. Wrapper fingerprint is `e81814ff9d295dc39e3888a8e60b4a484140b627f52ef3b8c3215b17afe92f3b`.

Coverage: one root/function (descriptor 501, entry 442); families 2199/1901/359; 43 raw addresses / 178 bounded states; 30 structured blocks; eight external calls; zero Raw/unresolved instructions and zero dispatch halts. Word spans and successors are preserved in `target.bytecode.txt` / raw and structured IR. Original file, working copy and bundled fixture retain the source hash.

Compatibility: old Adler output hash `27eea9ff7b925253ab09981f4bb7a803e919fdb953c849b01998d483269b56c0`, old rotor output hash `e9c1055148831d6bd553fbfebedd4d4fedd19ebc92f6dba54aab6cedbe2fbc7b`, both compared byte-for-byte to baseline. No old golden file was changed.

Limits: certification covers this token skeleton, not unrelated SARP variants. Fixed/captured roots, lazy captured factories, unsupported MO/MO2 entries, unknown hash subjects and unproved structures fail explicitly. Finite integer facts are 0/1 or unknown; no int32 brute force occurs. Some apparent `_dm` checksum branches are dormant: arbitrary payload changes are not claimed to have checksum protection. No original variable names/comments/line metadata are invented. Compilation/type analysis is not runtime equivalence proof.

Instruction spans cover 310 word positions plus the seven-word descriptor.
Word 336 is unreferenced, not replaced by an invented instruction; it remains
preserved in the original decoded buffer and raw word table. Post-review
arithmetic/shift bounds, cache-channel checks, ignored-argument purity checks
and plain-arm state checks are covered by synthetic regressions. Git attributes
disable line-ending conversion for the preserved SARP input and artifacts.

**Neither original nor recovered source was executed. No Lua/Luau interpreter, VM invocation, executor or Roblox client was used.**
