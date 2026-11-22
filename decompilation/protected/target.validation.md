# Protected large SARP — validation and unavailable stages

Date: 2026-11-22. **Incomplete 0.2.0 development preview.** This report does
not claim complete lifting, readable output or runtime equivalence for the
protected specimen. See `target.analysis.md` and `target.status.txt`.

## Performed checks

| Check | Result |
|---|---|
| `cargo fmt --check` | Passed |
| `cargo check --locked --all-targets` | Passed |
| `cargo test --locked -- --nocapture` | Cargo reported 179 successful test results, zero failures; optional parser check skipped as below |
| `cargo build --release --locked` | Passed; Cargo version remains 0.2.0 |
| `tools/verify.ps1 -RequireExternalTools` | Passed; three complete profiles + expected unsupported fourth-profile inspection |
| Official Luau 0.747 compile-only (`--null`) and analysis | Passed for 15 generated CLI outputs and 20 generated manual-IR outputs |
| Fourth-profile recovery example | Expected exit 1 at helper 25; wrote genuine transport/metadata/partial evidence, no complete output |
| Independent token fingerprint | 145089 tokens, matching complete certificate with four payload literals masked |
| Independent transport | All 568176 bytes equal Rust transport |
| Independent W/header/map/bias/permutations | 46/46 checks; all 142045 positions including absence |
| Independent root activation/first-child lazy cipher | 26/26 checks; all 559 decoded lazy words digest-matched |
| Independent constant hash | Six 320-round vectors match source transcription and Rust unit tests |
| Independent sparse artifact validation | All 142045 positions agree; four malformed images rejected |
| Preserved baselines | 38 old input/artifact/manifest/profile-source hashes unchanged; all five saved default/pretty output baselines byte-identical |
| `git diff --check` | Passed |
| Allowlisted development-preview packaging | Passed in a separate `target/` directory; both archives contain all 83 hash-listed protected artifacts and no cache/runtime-log entries |
| Git byte preservation | All 83 staged artifact blobs match the manifest and working-tree bytes; `.gitattributes` disables text normalization for protected artifacts |
| Extracted preview source ZIP | Full aggregate passed again from a fresh extraction, including locked build/tests and official checks with explicit compiler/analyzer overrides |
| Preview packaging negative checks | Corrupted, duplicate, extra-path and incomplete checksum manifests rejected in an isolated extracted copy; no ZIPs created |
| Preview archive overwrite guard | Invocation without `-Force` rejected; existing archive hashes unchanged |

The aggregate includes the formatting, full Cargo suite and release build; it
does not treat the expected unsupported fourth-profile result as successful
devirtualization. The manual-IR checks cover tuple expansion, fixed-result
truncate/nil-pad contracts, root/child parameter forwarding, captures, actual
returns, and concat precedence. They are synthetic IR tests, not reconstructed
program output or a complete emitter-equivalence proof.

## Skipped / unavailable

- The preexisting optional local `luau-decompiler validate --builtin` parser
  executable was unavailable. Its test printed an explicit `SKIP`; it did not
  perform parser validation. Official compile-only/static checks were performed.
- Complete protected linked IR, default Luau and pretty Luau do not exist.
  Consequently **no official output compilation/analysis for this target** was
  performed. The original protected source was not compiled or analyzed as a
  substitute for generated output.
- No runtime test or differential execution was performed. No Lua/Luau input,
  recovered function, VM, coroutine, executor, interpreter or Roblox client was
  run. No hash preimages were brute-forced.

## Reproduce

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\verify.ps1 -RequireExternalTools
cargo check --locked --all-targets
cargo run --locked --example recover_protected -- tests\fixtures\protected.luau decompilation\protected
# Above recovery currently exits 1, with 666 completed and 62 pending states.
python decompilation\protected\diagnostics\probe.py
python decompilation\protected\diagnostics\transport_reference.py
python decompilation\protected\diagnostics\initialization_reference.py
python decompilation\protected\diagnostics\w_evidence.py
python decompilation\protected\diagnostics\prototype_reference.py
python decompilation\protected\diagnostics\hash_reference.py
python decompilation\protected\diagnostics\artifact_check.py
```

In Windows PowerShell 5, redirecting all native Cargo streams with `*>` inside
the same script can turn ordinary compiler progress on stderr into a
`NativeCommandError` under `ErrorActionPreference=Stop`. The child-process
invocation above passed without that logging wrapper; PowerShell 7 was not
installed in this environment. Neither logging failure was a failed Cargo
semantic test; the successful full run is the validation recorded here.

## Release safety

Work remains on `sarp-large-payload`; no main/tag move, remote push or GitHub
release is part of these checks. Published ZIPs are not overwritten. Preview
packaging requires `-Preview` and separate development-preview archive names;
its allowlist excludes build caches, local logs, credentials, runtime details
and private paths. No 0.3.0 version advancement is justified while helper 25
and complete CFG/emission remain unsupported.
The aggregate and preview packager verify the protected byte manifest. Preview
packaging also requires exact coverage of its artifact allowlist and rejects
extra/duplicate checksum entries. Regenerating diagnostic files may update
line endings; deliberately refresh the checksums after reviewing such changes.
