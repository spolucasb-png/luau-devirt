# Helper 25 — source-grounded structured-iteration requirements

Read-only review by OpenCode Go HY4 Flash Free; checked against the protected
source, not the older five-fragment SARP. No program or VM was executed.
Line references below refer to the lexical extraction `_h_25.txt`.

## Why an ordinary transition or numeric loop is unsound

- Lines 2–9: save `_ostop/_oexit`, derive `_top/_bd/_ex`, fetch an iterator
  packet `_p = _t[1]`, and install stop/exit sentinels in the same frame.
- Lines 10–13 and 85–86: generic iteration over `tunpack(_p,1,_p.n)` has two
  iteration variables, written to `_t[4]`/`_t[5]` on every iteration.
  The iterator function/state/control packet and explicit `.n` must survive.
- Lines 24–58 and 112–146: call the dispatcher on the same frame. These are
  not ordinary recovered function calls with a new invocation frame.
- Lines 62–71 and 150–165: dispatch can leave the local range, call `_exec`
  and return early with a different control triple. Stop/exit are restored.
- Lines 87–106 and 170–194: bank/rotor roles are re-read/recomputed; metadata
  has encoded and raw branches. Loop exit is a computed triple, not `Next`.

Existing `ForPrep`/`ForLoop` carries only a numeric-loop state register and
target. It cannot encode this iterator packet, shared-frame dispatch, saved
continuations, dynamic rotor state or early returns. Keeping explicit
unsupported behavior is required until all these contracts exist.

## Required proof obligations before implementation

1. Typed generic iterator initialization/advance with an explicit packed
   iterator packet; snapshot iteration variables and preserve the table identity.
2. A loop-context stack containing saved stop/exit values, body/exit triples,
   packet identity, and the active frame. Every return/break path restores the
   correct context exactly once.
3. Contextual CFG identity, at least prototype + instruction address + loop
   context. Existing address-only IDs must not merge nested and outer dispatch.
4. Dedicated same-frame dispatch semantics. Prove CM/CM2/CM3 aliases from the
   certified metadata, not from role names. CM[7]/CM2[25] is IP; CM[11]/CM2[12]
   is ST; CM[14]/CM2[15] is STOP; CM[22]/CM2[6] is EXIT; CM[3]/CM2[19] is RB.
   These are map roles, not necessarily identical to their physical indices.
5. Per-iteration rotor/key/bank transitions. Either prove a finite bank cycle
   with every role-injectivity check or provide validated parametric control
   semantics. An unknown runtime bank cannot be replaced with a guessed integer.
6. Preserve iterator evaluation count, nil/false, multi-return expansion,
   changing frame facts, side-effect order, early exits and return packets.
7. Source-derived regressions for empty/multiple iterations, body mutation,
   exit-to-outer-driver, nested loops, stop/exit restoration, and both metadata
   encoding branches. Static generated-output checks do not prove runtime
   equivalence; no target execution is authorized.

This document is a design review, **not implemented IR or a completion claim**.
The current failure is prototype 140804, PC 140992, family 2094, selector 1993.
