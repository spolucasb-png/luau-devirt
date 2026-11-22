//! Symbolic state-machine traversal.
//!
//! [`walk_cfg`] performs a bounded worklist walk over the dispatcher state
//! space, tracking exactly [`VmState`]: program counter, rolling decode key,
//! register-bank base, dispatch token, decode phase, bank sum, and prototype
//! salt. Each visited state is lifted through [`crate::lifter`] into a
//! `DecodedInstruction`; every reachable program counter becomes one
//! `BasicBlock` whose `entry_states` list records the dispatcher-state
//! variants that reached it.
//!
//! The walk runs twice:
//!
//! 1. a discovery pass that keeps every selector-table arm and records, per
//!    instruction, the constants stored into frame registers, the slots
//!    written, and the predecessor edges of the graph;
//! 2. the final pass that uses those records to derive, by a bounded
//!    fixpoint over the graph, the constants provably held by each register
//!    at entry to every instruction. Those constants drive the selector-table
//!    pruning and the folding of inline permutation-parity derives, and the
//!    final pass produces the `LiftedProgram`.
//!
//! Pruning and folding are derived, not assumed: when a register's value
//! cannot be proven, all three selector arms are kept and the parity derive
//! stays a typed expression rather than being guessed.
//!
//! Bounds: at most 512 distinct visited states and 8192 worklist pops, both
//! reported as explicit errors. Decoding is also verified per program
//! counter: all dispatcher states reaching one word must agree on handler
//! family, selector, leaf line range, and successor labels and targets,
//! otherwise the walk fails with `inconsistent decoding at word N`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use crate::aliases::{canonicalize, Variant};
use crate::ir::{BasicBlock, DecodedInstruction, DecodedVm, EdgeLabel, LiftedProgram, VmState};
use crate::lifter::{build_source_model, lift_instruction, LiftOutcome, SourceModel, VALUE_SEED};

/// Hard cap on distinct dispatcher states, matching the reference walk.
const MAX_VISITED_STATES: usize = 512;
/// Hard cap on worklist pops; bounds runaway graphs.
const MAX_WALK_STEPS: usize = 8_192;
/// Hard cap on the constant-propagation fixpoint iterations.
const MAX_PROPAGATION: usize = 1024;

/// Per-pc decoding record: the representative lift plus the signature every
/// other state reaching the same word must agree with.
struct PcRow {
    family: u32,
    selector: i64,
    leaf_lines: (usize, usize),
    edges: Vec<(EdgeLabel, Option<usize>)>,
    decoded: DecodedInstruction,
    effects: BTreeMap<u16, i64>,
    writes: BTreeSet<u16>,
}

/// Everything one walk pass collects.
struct PassData {
    rows: BTreeMap<usize, PcRow>,
    entry_states: BTreeMap<usize, Vec<VmState>>,
    preds: BTreeMap<usize, BTreeSet<usize>>,
    visited: usize,
    variants: HashMap<VmState, Variant>,
    initial_pcs: BTreeSet<usize>,
}

/// Initial dispatcher states: one per decoded prototype, keyed by its entry
/// word, dispatch token, bank base, and prototype salt. The decode key
/// starts from the prototype's initial decode state plus the constant seed
/// the protected source derives from standard value cases.
fn initial_states(vm: &DecodedVm) -> Vec<VmState> {
    vm.prototypes
        .iter()
        .map(|proto| VmState {
            pc: proto.entry_pc,
            key_state: proto.initial_decode_state.wrapping_add(VALUE_SEED),
            dispatch_token: proto.dispatch_token,
            bank_base: proto.bank_base,
            phase: 0,
            bank_sum: 0,
            prototype_salt: proto.prototype_salt,
        })
        .collect()
}

/// One worklist pass over the dispatcher state space.
///
/// Both production passes propagate lifting errors rather than treating an
/// unknown path as an empty-effect dead end. Unsupported leaf semantics stay
/// explicit as Raw instructions and kill all register facts.
fn run_pass(
    vm: &DecodedVm,
    model: &SourceModel,
    const_hints: &BTreeMap<usize, BTreeMap<u16, i64>>,
    strict: bool,
) -> Result<PassData, String> {
    let mut queue: VecDeque<VmState> = initial_states(vm).into();
    let mut visited: HashSet<VmState> = HashSet::new();
    let mut data = PassData {
        rows: BTreeMap::new(),
        entry_states: BTreeMap::new(),
        preds: BTreeMap::new(),
        visited: 0,
        variants: HashMap::new(),
        initial_pcs: vm
            .prototypes
            .iter()
            .map(|prototype| prototype.entry_pc)
            .collect(),
    };
    let mut steps: usize = 0;

    while let Some(state) = queue.pop_front() {
        steps += 1;
        if steps > MAX_WALK_STEPS {
            return Err("CFG walk exceeded the step bound".to_owned());
        }
        if !visited.insert(state.clone()) {
            continue;
        }
        if visited.len() > MAX_VISITED_STATES {
            return Err("CFG walk exceeded the visited-state bound (512)".to_owned());
        }
        data.visited = visited.len();

        let outcome: LiftOutcome = match lift_instruction(vm, model, &state, const_hints) {
            Ok(outcome) => outcome,
            Err(error) => {
                if strict {
                    return Err(format!("failed to lift word {}: {error}", state.pc));
                }
                continue;
            }
        };
        let pc = state.pc;
        let variant_instructions = outcome.decoded.instructions.clone();
        let successors = outcome.decoded.successors.clone();
        let edges: Vec<(EdgeLabel, Option<usize>)> = successors
            .iter()
            .map(|s| (s.label.clone(), s.target_pc))
            .collect();

        match data.rows.get_mut(&pc) {
            Some(row) => {
                if row.family != outcome.decoded.handler_family
                    || row.selector != outcome.decoded.selector
                    || row.leaf_lines != outcome.leaf_lines
                    || row.edges != edges
                {
                    return Err(format!("inconsistent decoding at word {pc}"));
                }
                row.effects
                    .retain(|slot, value| outcome.constant_effects.get(slot) == Some(value));
                row.writes.extend(outcome.writes.iter().copied());
            }
            None => {
                data.rows.insert(
                    pc,
                    PcRow {
                        family: outcome.decoded.handler_family,
                        selector: outcome.decoded.selector,
                        leaf_lines: outcome.leaf_lines,
                        edges,
                        decoded: outcome.decoded,
                        effects: outcome.constant_effects,
                        writes: outcome.writes,
                    },
                );
            }
        }
        data.entry_states.entry(pc).or_default().push(state.clone());
        data.variants.insert(
            state.clone(),
            Variant {
                instructions: variant_instructions,
                successors: successors
                    .iter()
                    .filter_map(|successor| successor.state.clone())
                    .collect(),
            },
        );

        for succ in &successors {
            if let Some(target) = succ.target_pc {
                data.preds.entry(target).or_default().insert(pc);
            }
            if let Some(next) = &succ.state {
                queue.push_back(next.clone());
            }
        }
    }
    Ok(data)
}

/// Derives the constants provably held by each register at entry to every
/// instruction, by a bounded fixpoint over the graph.
///
/// A slot's value survives a block only when no block writes it; otherwise
/// the store kills it. When every predecessor agrees on a surviving value,
/// that value is recorded. This is monotone-growing from the empty set, so
/// every intermediate result is a sound under-approximation.
fn propagate_constants(pass: &PassData) -> BTreeMap<usize, BTreeMap<u16, i64>> {
    let mut entry: BTreeMap<usize, BTreeMap<u16, i64>> = BTreeMap::new();
    for pc in pass.rows.keys() {
        entry.insert(*pc, BTreeMap::new());
    }
    for _ in 0..MAX_PROPAGATION {
        let mut changed = false;
        for pc in pass.rows.keys().copied().collect::<Vec<_>>() {
            // Outgoing constants of each predecessor.
            let mut merged: BTreeMap<u16, i64> = BTreeMap::new();
            let mut first = true;
            let mut any_pred = false;
            // Collect predecessor list.
            let preds: Vec<usize> = pass
                .preds
                .get(&pc)
                .map(|s| s.iter().copied().collect())
                .unwrap_or_default();
            for pred in &preds {
                any_pred = true;
                let Some(pred_row) = pass.rows.get(pred) else {
                    continue;
                };
                let pred_entry = entry.get(pred).cloned().unwrap_or_default();
                // Kill written slots, then apply constant stores.
                let mut out = BTreeMap::new();
                for (slot, value) in &pred_entry {
                    if !pred_row.writes.contains(slot) {
                        out.insert(*slot, *value);
                    }
                }
                for (slot, value) in &pred_row.effects {
                    out.insert(*slot, *value);
                }
                // Merge: keep only unanimous values.
                if first {
                    merged = out;
                    first = false;
                } else {
                    let mut next = BTreeMap::new();
                    for (slot, value) in &merged {
                        if out.get(slot) == Some(value) {
                            next.insert(*slot, *value);
                        }
                    }
                    merged = next;
                }
            }
            // Prototype entries have no predecessors: keep empty.
            if !any_pred || pass.initial_pcs.contains(&pc) {
                merged.clear();
            }
            let current = entry.get(&pc).cloned().unwrap_or_default();
            if merged != current {
                entry.insert(pc, merged);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    entry
}

/// Derives the selector-table pruning hints from the discovery pass: a word
/// whose leaf is a selector-table transition gets the statically known tag
/// operand value when the entry-constant propagation proves it.
fn derive_const_hints(pass: &PassData) -> BTreeMap<usize, BTreeMap<u16, i64>> {
    propagate_constants(pass)
}

/// Assembles the final lifted program from a completed pass.
fn build_program(vm: &DecodedVm, pass: PassData) -> Result<LiftedProgram, String> {
    let PassData {
        rows,
        entry_states,
        visited,
        variants,
        ..
    } = pass;
    let mut blocks = BTreeMap::new();
    for (pc, row) in rows {
        let states = entry_states.get(&pc).cloned().unwrap_or_default();
        blocks.insert(
            pc,
            BasicBlock {
                start_pc: pc,
                end_pc: row.decoded.end_pc,
                handler_family: row.decoded.handler_family,
                entry_states: states,
                instructions: row.decoded.instructions,
                successors: row.decoded.successors,
            },
        );
    }
    canonicalize(&mut blocks, &variants)?;
    let mut entry_points: Vec<usize> = vm.prototypes.iter().map(|p| p.entry_pc).collect();
    entry_points.sort_unstable();
    entry_points.dedup();
    let reachable_pcs: BTreeSet<usize> = blocks.keys().copied().collect();
    Ok(LiftedProgram {
        blocks,
        entry_points,
        reachable_pcs,
        state_variants: visited,
        root_entry: vm
            .prototypes
            .iter()
            .find(|prototype| prototype.word == vm.entry_prototype)
            .map(|prototype| prototype.entry_pc),
        prototype_entries: vm
            .prototypes
            .iter()
            .map(|prototype| (prototype.word, prototype.entry_pc))
            .collect(),
        parameters: vm
            .prototypes
            .iter()
            .map(|prototype| {
                (
                    prototype.entry_pc,
                    prototype.fixed_parameter_count.map(usize::from),
                )
            })
            .collect(),
    })
}

/// Walks the dispatcher state machine symbolically and lifts every reachable
/// instruction into the shared IR.
///
/// The walk starts from the decoded prototype entries, tracks exactly
/// `VmState`, and is bounded by visited-state and step caps. It never
/// executes the payload: all successor states are computed statically from
/// the decoded word tables, the slot map, the immediate biases, the
/// dispatch-family map, the selector-table rows, and the handler source
/// resolved from `DecodedVm::source_text`.
pub fn walk_cfg(vm: &DecodedVm) -> Result<LiftedProgram, String> {
    if vm.profile == crate::ir::VmProfile::SarpLarge {
        return crate::sarp_large::analyze(vm)
            .map(|a| a.program)
            .map_err(|e| e.to_string());
    }
    if vm.profile == crate::ir::VmProfile::Sarp {
        return crate::sarp::walk(vm);
    }
    if crate::base85::is_profile(vm) {
        return crate::base85::walk(vm);
    }
    let model = build_source_model(vm)?;
    // Discovery pass: keep every selector-table arm, and record the constant
    // stores, written slots, and predecessor edges needed to derive the
    // constant propagation.
    let discovery = run_pass(vm, &model, &BTreeMap::new(), true)?;
    let const_hints = derive_const_hints(&discovery);
    // Final pass: prune the selector arms whose tag operand is statically
    // known and build the lifted program.
    let final_pass = run_pass(vm, &model, &const_hints, true)?;
    build_program(vm, final_pass)
}
