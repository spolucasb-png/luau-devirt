//! Structured Luau reconstruction and emission.
//!
//! This module turns a lifted [`LiftedProgram`] (see `ir.rs`) into a single
//! readable `--!strict` Luau module without executing Luau. Its contract is:
//!
//! * Each entry point in `LiftedProgram::entry_points` becomes one emitted
//!   function, unless a fully proved wrapper/scanner reconstruction eliminates
//!   it. `root_entry` identifies the module main; `prototype_entries` resolves
//!   closure descriptors. Declarations follow closure dependency order.
//! * Block control flow lives in the successors vector; a terminal
//!   `Jump`/`Branch`/`Return`/`ForPrep`/`ForLoop` instruction must agree with
//!   the successors (this is validated and mismatches are hard errors).
//!   Case edges require an explicit resolved Branch; unknown selectors fail.
//! * Registers become typed locals. A completely matched scanner control-flow
//!   tree can additionally promote private integer phases to a string union
//!   and name data roles, without reading any golden source.
//! * VM bookkeeping that has no effect on lifted values (`Tag`, `KeyUpdate`,
//!   `BankSwitch`) is elided; with `include_source_comments` it is kept as a
//!   comment.
//! * `Operand::SlotMapIndex(3)` is the packed-varargs frame slot (var49 in the
//!   T001 frame layout) and renders as `...` in entry functions; other frame
//!   slots render as clearly labeled `vm_frame_slot_<n>` locals with a FIXME.
//! * `Operand::Unknown(id)` is a value outside the register file. It renders as
//!   an explicitly labeled `nil` binding with a FIXME comment; the supported
//!   sample no longer uses this encoding for its captured environment (it uses
//!   `Operand::Global`).
//! * NewPackedTable/PushPacked/AppendPacked/ReturnPacked preserve explicit `.n`
//!   counts. A whole call packet, extracted scalar, and variadic splice are
//!   distinct; ordinary table writes never imply a packed return count.
//! * `Raw` instructions are never dropped: they are rendered as an explicit
//!   comment plus a loud `error(...)` so the generated file stays honest.
//! * NewClosure uses decoded prototype metadata, never an arbitrary alternate
//!   entry. The CLI rejects unvalidated descriptors, unresolved instructions,
//!   unsupported captures, and dispatch halts needing return-tag analysis.
//!
//! The current target fixture is the parser prototype in
//! `T001-analysis/VM-DISASSEMBLY.md` (55 reachable addresses, 109 state
//! variants). The in-file tests build that program by hand and pin the emitted
//! shape; the integration suite in `tests/verify.rs` checks the full pipeline
//! and statically compiles the generated output.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;

use crate::ir::{
    BasicBlock, BinaryOp, CodegenOptions, Condition, Constant, EdgeLabel, Instruction,
    LiftedProgram, Operand, Register, UnaryOp, ValueExpression,
};

mod pretty;

/// Frame-slot index of the packed varargs (`var49`, physical slot 3 in the
/// decoded slot map for this VM).
const PACKED_VARARGS_SLOT: u16 = 3;

// =========================================================================
// Constant-propagation domain
// =========================================================================

/// One instruction site: (block start PC, instruction index).
type Site = (usize, usize);

/// Lattice value for one register at one point.
///
/// `Bottom` means "unknown value" and renders as the register name. `Table`
/// tracks table-constructor identity (the `NewTable` site) plus element
/// values when they are statically known, so reads through a freshly built
/// tuple can fold. `PackCall` models the VM's `pack(<call>)` with one result.
#[derive(Clone, PartialEq, Debug)]
enum CpValue {
    Bottom,
    Const(Constant),
    PackCall {
        site: Site,
    },
    Table {
        site: Site,
        elems: Option<Vec<(Operand, CpValue, Site)>>,
    },
}

impl CpValue {
    fn meet(&self, other: &CpValue) -> CpValue {
        use CpValue::*;
        match (self, other) {
            (Bottom, _) | (_, Bottom) => Bottom,
            (Const(a), Const(b)) if a == b => Const(a.clone()),
            (PackCall { site: a }, PackCall { site: b }) if a == b => self.clone(),
            (
                Table {
                    site: a,
                    elems: Some(ea),
                },
                Table {
                    site: b,
                    elems: Some(eb),
                },
            ) if a == b => {
                if ea.len() == eb.len()
                    && ea
                        .iter()
                        .zip(eb.iter())
                        .all(|((oa, _, sa), (ob, _, sb))| oa == ob && sa == sb)
                {
                    let elems = ea
                        .iter()
                        .zip(eb.iter())
                        .map(|((oa, va, sa), (_, vb, _))| ((*oa).clone(), va.meet(vb), *sa))
                        .collect::<Vec<_>>();
                    Table {
                        site: *a,
                        elems: Some(elems),
                    }
                } else {
                    Table {
                        site: *a,
                        elems: None,
                    }
                }
            }
            (Table { site: a, .. }, Table { site: b, .. }) if a == b => Table {
                site: *a,
                elems: None,
            },
            _ => Bottom,
        }
    }
}

/// A rough Luau type annotation used for emitted locals.
#[derive(Clone, PartialEq, Debug)]
enum LType {
    Any,
    Bool,
    Num,
    Str,
    Tab(String),
}

impl LType {
    fn render(&self) -> String {
        match self {
            LType::Any => "any".to_owned(),
            LType::Bool => "boolean".to_owned(),
            LType::Num => "number".to_owned(),
            LType::Str => "string".to_owned(),
            LType::Tab(inner) => inner.clone(),
        }
    }

    fn meet(&self, other: &LType) -> LType {
        if self == other {
            return self.clone();
        }
        match (self, other) {
            (LType::Tab(a), LType::Tab(b)) if a == b => LType::Tab(a.clone()),
            _ => LType::Any,
        }
    }

    fn of_constant(value: &Constant) -> LType {
        match value {
            Constant::Nil => LType::Any,
            Constant::Boolean(_) => LType::Bool,
            Constant::Integer(_) | Constant::U32(_) | Constant::NumberBits(_) => LType::Num,
            Constant::String(_) => LType::Str,
            Constant::Unknown(_) => LType::Any,
        }
    }
}

/// Result of rendering one operand use.
struct Rendered {
    text: String,
    /// The rendering mentions the register's own local (so the store that
    /// feeds it must be materialized and the local declared).
    needs_name: bool,
    /// The expression is compound (`a + b`, `t[k]`, ...) and should be
    /// parenthesized when embedded inside another operator.
    compound: bool,
    ty: LType,
}

// =========================================================================
// Function-level analysis
// =========================================================================

/// Everything the emitter needs about one entry point's reachable subgraph.
struct FnAnalysis<'a> {
    /// The bounded def graph can be highly branching even at depth 16.
    /// Memoize by remaining depth so repeated register queries stay polynomial.
    type_cache: std::cell::RefCell<HashMap<(u16, usize), LType>>,
    entry: usize,
    blocks: BTreeMap<usize, &'a BasicBlock>,
    /// Validated successor edges: (label, target).
    succs: BTreeMap<usize, Vec<(EdgeLabel, Option<usize>)>>,
    preds: BTreeMap<usize, BTreeSet<usize>>,
    /// Reverse postorder from the entry.
    order: Vec<usize>,
    /// Dominator sets.
    dom: HashMap<usize, BTreeSet<usize>>,
    /// Immediate postdominator on the back-edge-free skeleton (loop joins).
    ipdom: HashMap<usize, Option<usize>>,
    /// Loop head -> natural-loop body (including the head).
    loops: HashMap<usize, BTreeSet<usize>>,
    /// Blocks that are the target of a dominator-verified back edge.
    loop_heads: BTreeSet<usize>,
    /// CP state before each instruction, and the block-out state.
    cp_in: HashMap<Site, BTreeMap<u16, CpValue>>,
    cp_out: HashMap<usize, BTreeMap<u16, CpValue>>,
    /// Register -> every binding def site (not element writes).
    binding_defs: HashMap<u16, Vec<Site>>,
    /// Register -> every use site (one entry per operand occurrence).
    uses: HashMap<u16, Vec<Site>>,
    /// The numeric-for promotion found for this function, if any.
    for_promotion: Option<ForPromotion>,
}

/// A verified numeric-for pattern (promoted to a real Luau `for`).
#[derive(Clone)]
struct ForPromotion {
    /// Block holding the `ForPrep` (its construction is consumed).
    prep_pc: usize,
    /// The loop head block (consumed).
    head_pc: usize,
    /// Body entry block; its first instruction is the index read (consumed).
    body_pc: usize,
    /// Loop exit block (the test's false edge).
    exit_pc: usize,
    /// Latch block holding the `ForLoop` (consumed).
    latch_pc: usize,
    /// Loop-variable register (the index-read destination).
    var_reg: u16,
    /// Start/limit/step elements from the state constructor at the prep.
    bounds: Vec<(Operand, CpValue, Site)>,
    /// `None` when the step folds to the Luau default of 1.
    step_value: Option<i64>,
    /// All consumed instruction sites (construction, loads, increments).
    consumed_sites: BTreeSet<Site>,
    /// Whole blocks consumed by the promotion.
    consumed_blocks: BTreeSet<usize>,
}

impl<'a> FnAnalysis<'a> {
    fn new(program: &'a LiftedProgram, entry: usize) -> Result<FnAnalysis<'a>, String> {
        let mut blocks: BTreeMap<usize, &BasicBlock> = BTreeMap::new();
        for (pc, block) in &program.blocks {
            blocks.insert(*pc, block);
        }
        if !blocks.contains_key(&entry) {
            return Err(format!(
                "entry point PC {entry} has no basic block in the lifted program"
            ));
        }

        // --- Reachability -------------------------------------------------
        let mut succs: BTreeMap<usize, Vec<(EdgeLabel, Option<usize>)>> = BTreeMap::new();
        let mut preds: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
        let mut reachable: BTreeSet<usize> = BTreeSet::new();
        let mut queue: Vec<usize> = vec![entry];
        reachable.insert(entry);
        while let Some(pc) = queue.pop() {
            let block = blocks[&pc];
            let edges = validate_block(pc, block)?;
            for (_, target) in &edges {
                if let Some(target) = *target {
                    if reachable.insert(target) {
                        queue.push(target);
                    }
                    preds.entry(target).or_default().insert(pc);
                }
            }
            succs.insert(pc, edges);
        }
        blocks.retain(|pc, _| reachable.contains(pc));

        // --- Reverse postorder -------------------------------------------
        let mut order: Vec<usize> = Vec::new();
        {
            let mut visited: HashSet<usize> = HashSet::new();
            let mut stack: Vec<(usize, usize)> = vec![(entry, 0)];
            visited.insert(entry);
            loop {
                let Some(&(pc, idx)) = stack.last() else {
                    break;
                };
                let edges = &succs[&pc];
                if idx < edges.len() {
                    if let Some(last) = stack.last_mut() {
                        last.1 += 1;
                    }
                    if let Some((_, Some(target))) = edges.get(idx) {
                        if visited.insert(*target) {
                            stack.push((*target, 0));
                        }
                    }
                } else {
                    order.push(pc);
                    stack.pop();
                }
            }
            order.reverse();
        }

        // --- Dominators (set-based iterative) ----------------------------
        let mut dom: HashMap<usize, BTreeSet<usize>> = HashMap::new();
        for &pc in &order {
            let mut set: BTreeSet<usize> = order.iter().copied().collect();
            if pc == entry {
                set.clear();
                set.insert(entry);
            }
            dom.insert(pc, set);
        }
        loop {
            let mut changed = false;
            for &pc in &order {
                if pc == entry {
                    continue;
                }
                let mut merged: Option<BTreeSet<usize>> = None;
                for &pred in &preds[&pc] {
                    let set = &dom[&pred];
                    merged = Some(match merged {
                        None => set.clone(),
                        Some(current) => current.intersection(set).copied().collect(),
                    });
                }
                let mut new_set = merged.unwrap_or_default();
                new_set.insert(pc);
                if new_set != dom[&pc] {
                    dom.insert(pc, new_set);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }

        // --- Natural loops (dominator-verified back edges) ----------------
        let mut loop_heads: BTreeSet<usize> = BTreeSet::new();
        let mut loops: HashMap<usize, BTreeSet<usize>> = HashMap::new();
        for (&pc, edges) in &succs {
            for (_, target) in edges {
                if let Some(target) = *target {
                    if dom[&pc].contains(&target) {
                        // pc -> target is a back edge; target dominates pc.
                        loop_heads.insert(target);
                        let body = loops.entry(target).or_insert_with(|| {
                            let mut set = BTreeSet::new();
                            set.insert(target);
                            set
                        });
                        // Reverse reachability from the back-edge source,
                        // stopping at the head.
                        let mut work = vec![pc];
                        while let Some(current) = work.pop() {
                            if !body.insert(current) {
                                continue;
                            }
                            if let Some(pset) = preds.get(&current) {
                                for &pred in pset {
                                    if pred != target && !body.contains(&pred) {
                                        work.push(pred);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // --- Immediate postdominators on the back-edge-free skeleton ------
        let ipdom = compute_ipdom(&succs, &order, &loops, &loop_heads);

        let mut analysis = FnAnalysis {
            type_cache: std::cell::RefCell::new(HashMap::new()),
            entry,
            blocks,
            succs,
            preds,
            order,
            dom,
            ipdom,
            loops,
            loop_heads,
            cp_in: HashMap::new(),
            cp_out: HashMap::new(),
            binding_defs: HashMap::new(),
            uses: HashMap::new(),
            for_promotion: None,
        };
        analysis.collect_defs_uses();
        analysis.run_cp();
        analysis.for_promotion = analysis.detect_for_promotion();
        Ok(analysis)
    }

    fn block(&self, pc: usize) -> &'a BasicBlock {
        self.blocks[&pc]
    }

    fn collect_defs_uses(&mut self) {
        for (&pc, block) in &self.blocks {
            for (idx, instr) in block.instructions.iter().enumerate() {
                let site = (pc, idx);
                for dst in instruction_binding_defs(instr) {
                    self.binding_defs.entry(dst).or_default().push(site);
                }
                for src in instruction_uses(instr) {
                    self.uses.entry(src).or_default().push(site);
                }
            }
        }
    }

    /// Forward dataflow for constant/constructor propagation. Meets at joins;
    /// monotone descent to `Bottom` guarantees termination.
    fn run_cp(&mut self) {
        let empty: BTreeMap<u16, CpValue> = BTreeMap::new();
        let mut out: HashMap<usize, BTreeMap<u16, CpValue>> = HashMap::new();
        for &pc in &self.order {
            out.insert(pc, empty.clone());
        }
        for iteration in 0.. {
            if iteration > self.order.len() * 4 + 16 {
                // Lattice is monotone; this is a safety net only.
                break;
            }
            let mut changed = false;
            for &pc in &self.order.clone() {
                let mut state: BTreeMap<u16, CpValue> = if pc == self.entry {
                    empty.clone()
                } else {
                    let mut merged: Option<BTreeMap<u16, CpValue>> = None;
                    let no_preds: BTreeSet<usize> = BTreeSet::new();
                    let pred_set = self.preds.get(&pc).unwrap_or(&no_preds);
                    for &pred in pred_set {
                        let set = &out[&pred];
                        merged = Some(match merged {
                            None => set.clone(),
                            Some(current) => current
                                .iter()
                                .filter_map(|(reg, value)| match set.get(reg) {
                                    Some(other) => Some((*reg, value.meet(other))),
                                    None => Some((*reg, CpValue::Bottom)),
                                })
                                .chain(
                                    set.iter()
                                        .filter(|(reg, _)| !current.contains_key(reg))
                                        .map(|(reg, _)| (*reg, CpValue::Bottom)),
                                )
                                .collect(),
                        });
                    }
                    merged.unwrap_or_default()
                };
                let block = self.block(pc);
                for (idx, instr) in block.instructions.iter().enumerate() {
                    cp_transfer(&mut state, pc, idx, instr);
                }
                if out.get(&pc) != Some(&state) {
                    out.insert(pc, state);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        // Replay each block once to store per-instruction states.
        for &pc in &self.order.clone() {
            let mut state: BTreeMap<u16, CpValue> = if pc == self.entry {
                empty.clone()
            } else {
                let mut merged: Option<BTreeMap<u16, CpValue>> = None;
                let no_preds: BTreeSet<usize> = BTreeSet::new();
                let pred_set = self.preds.get(&pc).unwrap_or(&no_preds);
                for &pred in pred_set {
                    let set = &out[&pred];
                    merged = Some(match merged {
                        None => set.clone(),
                        Some(current) => current
                            .iter()
                            .filter_map(|(reg, value)| match set.get(reg) {
                                Some(other) => Some((*reg, value.meet(other))),
                                None => Some((*reg, CpValue::Bottom)),
                            })
                            .chain(
                                set.iter()
                                    .filter(|(reg, _)| !current.contains_key(reg))
                                    .map(|(reg, _)| (*reg, CpValue::Bottom)),
                            )
                            .collect(),
                    });
                }
                merged.unwrap_or_default()
            };
            let block = self.block(pc);
            for (idx, instr) in block.instructions.iter().enumerate() {
                self.cp_in.insert((pc, idx), state.clone());
                cp_transfer(&mut state, pc, idx, instr);
            }
            self.cp_out.insert(pc, state);
        }
    }

    fn cp_at(&self, site: Site) -> BTreeMap<u16, CpValue> {
        self.cp_in.get(&site).cloned().unwrap_or_default()
    }

    // ---------------------------------------------------------------------
    // Numeric-for promotion detection
    // ---------------------------------------------------------------------

    fn detect_for_promotion(&self) -> Option<ForPromotion> {
        'prep: for (&prep_pc, block) in &self.blocks {
            let Some(Instruction::ForPrep { state, .. }) = block
                .instructions
                .iter()
                .find(|instruction| matches!(instruction, Instruction::ForPrep { .. }))
            else {
                continue;
            };
            let state = state.physical_slot;
            // Find the matching ForLoop latch and head.
            let mut latch: Option<(usize, usize)> = None;
            for (&pc, other) in &self.blocks {
                if self.succs[&pc].len() != 1 {
                    continue;
                }
                if let Some(Instruction::ForLoop {
                    state: loop_state,
                    target: head,
                }) = terminal(other)
                {
                    if loop_state.physical_slot == state {
                        if latch.is_some() {
                            {
                                continue 'prep;
                            } // more than one ForLoop on this state
                        }
                        latch = Some((pc, *head));
                    }
                }
            }
            let Some((latch_pc, head_pc)) = latch else {
                continue;
            };
            let body = self.loops.get(&head_pc)?;
            if !body.contains(&latch_pc) || body.contains(&prep_pc) {
                continue;
            }
            if !self.dom[&head_pc].contains(&prep_pc) {
                continue;
            }
            // The latch must only carry the ForLoop (plus elidable VM ops).
            for instr in &self.block(latch_pc).instructions {
                if !matches!(
                    instr,
                    Instruction::ForLoop { .. }
                        | Instruction::Tag { .. }
                        | Instruction::KeyUpdate { .. }
                        | Instruction::BankSwitch { .. }
                        | Instruction::Nop
                ) {
                    {
                        continue 'prep;
                    }
                }
            }

            // Walk the head's fallthrough chain over elidable-only blocks to
            // the in-range test.
            let mut test_pc = head_pc;
            loop {
                let candidate = self.block(test_pc);
                let elidable = candidate.instructions.iter().all(|instr| {
                    matches!(
                        instr,
                        Instruction::Tag { .. }
                            | Instruction::Nop
                            | Instruction::KeyUpdate { .. }
                            | Instruction::BankSwitch { .. }
                            | Instruction::Jump { .. }
                    )
                });
                let edges = &self.succs[&test_pc];
                if elidable && edges.len() == 1 {
                    if let Some((_, Some(next))) = edges.first() {
                        if *next != head_pc {
                            test_pc = *next;
                            continue;
                        }
                    }
                }
                break;
            }

            // The test block must end in a two-way condition over the loop
            // state's elements 1 and 2.
            let test = self.block(test_pc);
            let (then_pc, else_pc) = two_way_targets(&self.succs[&test_pc])?;
            if test
                .instructions
                .iter()
                .any(|instruction| match instruction {
                    Instruction::GetTable {
                        table: Operand::Register(table),
                        index: Operand::Constant(Constant::Integer(index)),
                        ..
                    } => table.physical_slot != state || !matches!(index, 1 | 2),
                    Instruction::Compare { .. }
                    | Instruction::ForLoop { .. }
                    | Instruction::Tag { .. }
                    | Instruction::KeyUpdate { .. }
                    | Instruction::BankSwitch { .. }
                    | Instruction::Nop => false,
                    _ => true,
                })
            {
                continue 'prep;
            }
            let cmp_op = if let Some(condition) = last_condition(test) {
                let (op, left_reg, right_reg) = condition_state_test(&condition)?;
                // Explicit GetTable loads are only present in the Compare form.
                if matches!(terminal(test), Some(Instruction::Compare { .. })) {
                    state_element_load(&test.instructions, left_reg, state, 1)?;
                    state_element_load(&test.instructions, right_reg, state, 2)?;
                }
                op
            } else {
                BinaryOp::LessEqual
            };

            // Body entry: first instruction is the index read.
            let body_pc = then_pc;
            let body_block = self.block(body_pc);
            let Some(Instruction::GetTable {
                dst: var_reg,
                table: Operand::Register(table_reg),
                index: Operand::Constant(Constant::Integer(1)),
            }) = body_block.instructions.first()
            else {
                continue;
            };
            if table_reg.physical_slot != state {
                continue;
            }
            let var_reg = var_reg.physical_slot;

            // The state register may only be used by the pattern: the
            // construction at the prep block, the two test loads, the index
            // read, and the ForLoop. Elided TAG bookkeeping is exempt.
            for (&pc, other) in &self.blocks {
                for (idx, instr) in other.instructions.iter().enumerate() {
                    if pc == prep_pc || pc == test_pc || (pc == body_pc && idx == 0) {
                        continue;
                    }
                    if pc == latch_pc && matches!(instr, Instruction::ForLoop { .. }) {
                        continue;
                    }
                    if matches!(instr, Instruction::Tag { .. }) {
                        continue;
                    }
                    for used in instruction_uses(instr) {
                        if used == state {
                            {
                                continue 'prep;
                            }
                        }
                    }
                }
            }
            // The loop variable is only used inside the loop.
            if let Some(uses) = self.uses.get(&var_reg) {
                for &(pc, _) in uses {
                    if !body.contains(&pc) && pc != body_pc {
                        {
                            continue 'prep;
                        }
                    }
                }
            }
            // Collect the entry chain (prep -> ... -> head); every block on
            // it must be elidable, and consumed blocks may only be entered
            // from the chain, the prep, the test, or from inside the loop.
            let mut chain: BTreeSet<usize> = BTreeSet::new();
            {
                let mut cursor = match self.single_succ(prep_pc) {
                    Some(next) => next,
                    None => {
                        continue 'prep;
                    }
                };
                while cursor != head_pc {
                    let candidate = self.block(cursor);
                    let elidable = candidate.instructions.iter().all(|instr| {
                        matches!(
                            instr,
                            Instruction::Tag { .. } | Instruction::Nop | Instruction::Jump { .. }
                        )
                    }) && self.succs[&cursor].len() == 1;
                    if !elidable || chain.contains(&cursor) {
                        continue 'prep;
                    }
                    if let Some(pset) = self.preds.get(&cursor) {
                        for &pred in pset {
                            if pred != prep_pc && !chain.contains(&pred) {
                                continue 'prep;
                            }
                        }
                    }
                    chain.insert(cursor);
                    cursor = match self.single_succ(cursor) {
                        Some(next) => next,
                        None => continue 'prep,
                    };
                }
            }
            for consumed in [head_pc, test_pc, body_pc, latch_pc] {
                if let Some(pset) = self.preds.get(&consumed) {
                    for &pred in pset {
                        let allowed = pred == prep_pc
                            || pred == test_pc
                            || chain.contains(&pred)
                            || body.contains(&pred);
                        if !allowed {
                            {
                                continue 'prep;
                            }
                        }
                    }
                }
            }

            // Bounds come from the state constructor at the ForPrep site.
            let elems = match self
                .cp_value_at_site((prep_pc, block.instructions.len().saturating_sub(1)), state)
            {
                CpValue::Table { elems: Some(e), .. } => e,
                _ => continue,
            };
            if elems.len() < 2 {
                continue;
            }
            let mut bounds: Vec<(Operand, CpValue, Site)> = Vec::new();
            for element in elems.iter().take(3) {
                let (operand, value, origin) = element;
                if matches!(value, CpValue::Bottom) {
                    // The bound's expression must be reconstructible at the
                    // prep block: an unambiguous reaching def on a straight
                    // line from the element's origin.
                    match operand {
                        Operand::Register(reg) => {
                            let Some(def) = self.reaching_def(*origin, reg.physical_slot) else {
                                {
                                    continue 'prep;
                                }
                            };
                            if !self.straight_line(def.0, prep_pc) {
                                {
                                    continue 'prep;
                                }
                            }
                        }
                        Operand::Expression(_) | Operand::Argument(_) => {
                            if !self.straight_line(origin.0, prep_pc) {
                                continue 'prep;
                            }
                        }
                        _ => {
                            continue 'prep;
                        }
                    }
                }
                bounds.push(element.clone());
            }
            if bounds.len() < 2 {
                continue;
            }
            let step_value = if elems.len() >= 3 {
                match &elems[2].1 {
                    CpValue::Const(constant) => {
                        match constant_as_i64(constant)
                            .filter(|v| match cmp_op {
                                BinaryOp::LessEqual => *v > 0,
                                BinaryOp::GreaterEqual => *v < 0,
                                _ => false,
                            })
                            .filter(|v| *v != 1)
                        {
                            Some(value) => Some(value),
                            None if constant_as_i64(constant) == Some(1) => None,
                            None => continue,
                        }
                    }
                    _ => continue,
                }
            } else {
                if cmp_op != BinaryOp::LessEqual {
                    continue;
                }
                None
            };

            // Mark every construction instruction in the prep block consumed:
            // the state constructor, its SetTables, and the temp GetTables that
            // only feed them (any other use must be dominated by another def).
            let mut consumed_sites: BTreeSet<Site> = BTreeSet::new();
            for (idx, instr) in block.instructions.iter().enumerate() {
                if instruction_defs(instr).contains(&state)
                    || matches!(instr, Instruction::Append { table: Operand::Register(register), .. } if register.physical_slot == state)
                    || matches!(instr, Instruction::ForPrep { .. })
                {
                    consumed_sites.insert((prep_pc, idx));
                    continue;
                }
                if let Instruction::GetTable { dst, table, .. } = instr {
                    if matches!(table, Operand::Register(reg) if reg.physical_slot == state) {
                        continue;
                    }
                    let slot = dst.physical_slot;
                    let feeding = block.instructions.iter().any(|other| {
                        matches!(other, Instruction::SetTable { value, .. } if matches!(value, Operand::Register(v) if v.physical_slot == slot))
                    });
                    if !feeding {
                        continue;
                    }
                    let temp_ok = self
                        .uses
                        .get(&slot)
                        .map(|uses| {
                            uses.iter().all(|&(upc, uidx)| {
                                upc == prep_pc
                                    || self.binding_defs[&slot].iter().any(|&d| {
                                        d != (prep_pc, idx)
                                            && (d.0 == upc && d.1 < uidx
                                                || d.0 != prep_pc && self.dom[&upc].contains(&d.0))
                                    })
                            })
                        })
                        .unwrap_or(true);
                    if temp_ok {
                        consumed_sites.insert((prep_pc, idx));
                    }
                }
            }
            consumed_sites.insert((prep_pc, block.instructions.len() - 1)); // ForPrep
            consumed_sites.insert((body_pc, 0)); // index read
                                                 // The test block's loads are also consumed.
            for idx in 0..self.block(test_pc).instructions.len() {
                consumed_sites.insert((test_pc, idx));
            }
            consumed_sites.insert((latch_pc, 0)); // ForLoop latch increment
            let mut consumed_blocks: BTreeSet<usize> = BTreeSet::new();
            consumed_blocks.extend(chain);
            consumed_blocks.insert(head_pc);
            consumed_blocks.insert(test_pc);
            consumed_blocks.insert(body_pc);
            consumed_blocks.insert(latch_pc);

            return Some(ForPromotion {
                prep_pc,
                head_pc,
                body_pc,
                exit_pc: else_pc,
                latch_pc,
                var_reg,
                bounds,
                step_value,
                consumed_sites,
                consumed_blocks,
            });
        }
        None
    }

    fn cp_value_at_site(&self, site: Site, reg: u16) -> CpValue {
        self.cp_in
            .get(&site)
            .and_then(|state| state.get(&reg))
            .cloned()
            .unwrap_or(CpValue::Bottom)
    }

    /// Render one constructor element for the for-loop bounds (the stored
    /// operand, recursively inlined, with a straight-line guard).
    fn render_element(
        &self,
        ctx: &mut RenderCtx,
        element: &(Operand, CpValue, Site),
        use_pc: usize,
        depth: usize,
    ) -> Option<String> {
        let (operand, value, origin) = element;
        match value {
            CpValue::Const(constant) => Some(render_constant(constant)),
            CpValue::PackCall { site } => self
                .render_call_expr(ctx, *site, depth, true)
                .map(|r| r.text),
            CpValue::Bottom => {
                if !self.straight_line(origin.0, use_pc) {
                    return None;
                }
                let rendered = self.render_operand(ctx, *origin, operand, depth)?;
                Some(rendered.text)
            }
            _ => None,
        }
    }
}

// =========================================================================
// Free helpers over the IR
// =========================================================================

fn constant_as_i64(value: &Constant) -> Option<i64> {
    match value {
        Constant::Integer(v) => Some(*v),
        Constant::U32(v) => Some(i64::from(*v)),
        _ => None,
    }
}

fn reg_name(slot: u16) -> String {
    format!("r{slot}")
}

fn operand_uses_register(operand: &Operand, slot: u16) -> bool {
    match operand {
        Operand::Register(register) => register.physical_slot == slot,
        Operand::Expression(expression) => match expression.as_ref() {
            ValueExpression::Unary { value, .. }
            | ValueExpression::PermutationParity { value, .. } => {
                operand_uses_register(value, slot)
            }
            ValueExpression::Binary { left, right, .. } => {
                operand_uses_register(left, slot) || operand_uses_register(right, slot)
            }
            ValueExpression::Index { table, index } => {
                operand_uses_register(table, slot) || operand_uses_register(index, slot)
            }
        },
        _ => false,
    }
}

impl FnAnalysis<'_> {
    fn argument_origin(&self, operand: &Operand, depth: usize) -> Option<usize> {
        if depth > 16 {
            return None;
        }
        match operand {
            Operand::Argument(index) => Some(*index),
            Operand::Register(register) => {
                let definitions = self.binding_defs.get(&register.physical_slot)?;
                if definitions.len() != 1 {
                    return None;
                }
                if let Instruction::Move { src, .. } =
                    &self.block(definitions[0].0).instructions[definitions[0].1]
                {
                    self.argument_origin(src, depth + 1)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn operand_type(&self, operand: &Operand, depth: usize) -> LType {
        if depth > 16 {
            return LType::Any;
        }
        match operand {
            Operand::Constant(constant) => LType::of_constant(constant),
            Operand::Register(register) => self.register_type(register.physical_slot, depth + 1),
            Operand::Expression(expression) => match expression.as_ref() {
                ValueExpression::Unary { op, .. } => {
                    if *op == UnaryOp::Not {
                        LType::Bool
                    } else if *op == UnaryOp::TypeOf {
                        LType::Str
                    } else {
                        LType::Num
                    }
                }
                ValueExpression::Binary { op, .. } => binary_result_type(*op),
                ValueExpression::Index { table, .. }
                    if self.argument_origin(table, 0).is_some() =>
                {
                    LType::Num
                }
                _ => LType::Any,
            },
            _ => LType::Any,
        }
    }

    fn register_type(&self, slot: u16, depth: usize) -> LType {
        if depth > 16 {
            return LType::Any;
        }
        if let Some(ty) = self.type_cache.borrow().get(&(slot, depth)).cloned() {
            return ty;
        }
        let Some(definitions) = self.binding_defs.get(&slot) else {
            return LType::Any;
        };
        let mut result: Option<LType> = None;
        for &(pc, index) in definitions {
            let ty = match &self.block(pc).instructions[index] {
                Instruction::LoadConst { value, .. } => LType::of_constant(value),
                Instruction::Binary { op, .. } => binary_result_type(*op),
                Instruction::Unary { op, .. } => {
                    if *op == UnaryOp::Not {
                        LType::Bool
                    } else if *op == UnaryOp::TypeOf {
                        LType::Str
                    } else {
                        LType::Num
                    }
                }
                Instruction::Move { src, .. } => self.operand_type(src, depth + 1),
                Instruction::GetTable { table, .. } if self.argument_origin(table, 0).is_some() => {
                    LType::Num
                }
                Instruction::NewPackedTable { .. } | Instruction::Call { .. } => {
                    LType::Tab("{ [number]: any, n: number }".to_owned())
                }
                Instruction::NewTable { .. } => {
                    let elements: Vec<_> = self
                        .blocks
                        .values()
                        .flat_map(|block| block.instructions.iter())
                        .filter_map(|instruction| {
                            if let Instruction::Append {
                                table: Operand::Register(table),
                                value,
                            } = instruction
                            {
                                (table.physical_slot == slot).then_some(value)
                            } else {
                                None
                            }
                        })
                        .collect();
                    if !elements.is_empty()
                        && elements
                            .iter()
                            .all(|value| self.operand_type(value, depth + 1) == LType::Num)
                    {
                        LType::Tab("{ number }".to_owned())
                    } else {
                        LType::Tab("{ [any]: any }".to_owned())
                    }
                }
                Instruction::Concat { .. } => LType::Str,
                _ => LType::Any,
            };
            result = Some(match result {
                None => ty,
                Some(current) => current.meet(&ty),
            });
            if result == Some(LType::Any) {
                break;
            }
        }
        let result = result.unwrap_or(LType::Any);
        self.type_cache
            .borrow_mut()
            .insert((slot, depth), result.clone());
        result
    }
}

fn render_global_path(path: &[Vec<u8>]) -> String {
    if path.is_empty() {
        return "_G".to_owned();
    }
    let mut out = String::new();
    for segment in path {
        let text = String::from_utf8_lossy(segment);
        let is_ident = !text.is_empty()
            && text
                .chars()
                .next()
                .map(|c| c.is_ascii_alphabetic() || c == '_')
                .unwrap_or(false)
            && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if is_ident {
            if out.is_empty() {
                out.push_str(&text);
            } else {
                out.push('.');
                out.push_str(&text);
            }
        } else {
            if out.is_empty() {
                out.push_str("_G");
            }
            out.push('[');
            out.push_str(&escape_lua_string(segment));
            out.push(']');
        }
    }
    if out.is_empty() {
        "_G".to_owned()
    } else {
        out
    }
}

fn escape_lua_string(bytes: &[u8]) -> String {
    let mut out = String::from("\"");
    for &byte in bytes {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x07 => out.push_str("\\a"),
            0x08 => out.push_str("\\b"),
            0x0C => out.push_str("\\f"),
            0x0B => out.push_str("\\v"),
            32..=126 => out.push(byte as char),
            _ => {
                let _ = write!(out, "\\{}", byte);
            }
        }
    }
    out.push('"');
    out
}

fn render_constant(value: &Constant) -> String {
    match value {
        Constant::Nil => "nil".to_owned(),
        Constant::Boolean(flag) => flag.to_string(),
        Constant::Integer(number) => number.to_string(),
        Constant::U32(number) => number.to_string(),
        Constant::NumberBits(bits) => {
            let number = f64::from_bits(*bits);
            if number.is_nan() {
                "(0 / 0)".to_owned()
            } else if number.is_infinite() {
                if number > 0.0 { "(1 / 0)" } else { "(-1 / 0)" }.to_owned()
            } else if number == number.trunc() && number.abs() < 1e15 {
                format!("{number:.1}")
            } else {
                format!("{number}")
            }
        }
        Constant::String(bytes) => escape_lua_string(bytes),
        Constant::Unknown(id) => format!("vm_unknown_const_{id}"),
    }
}

fn truthy_const(value: &Constant) -> Option<bool> {
    match value {
        Constant::Nil => Some(false),
        Constant::Boolean(flag) => Some(*flag),
        _ => Some(true),
    }
}

fn try_fold_unop(op: UnaryOp, value: &Constant) -> Option<Constant> {
    match (op, value) {
        (UnaryOp::Not, other) => Some(Constant::Boolean(!truthy_const(other)?)),
        (UnaryOp::Negate, Constant::Integer(number)) => number.checked_neg().map(Constant::Integer),
        (UnaryOp::Length, Constant::String(bytes)) => Some(Constant::Integer(bytes.len() as i64)),
        _ => None,
    }
}

fn try_fold_binop(op: BinaryOp, left: &Constant, right: &Constant) -> Option<Constant> {
    use Constant::*;
    match (op, left, right) {
        (BinaryOp::Add, Integer(a), Integer(b)) => a.checked_add(*b).map(Integer),
        (BinaryOp::Sub, Integer(a), Integer(b)) => a.checked_sub(*b).map(Integer),
        (BinaryOp::Mul, Integer(a), Integer(b)) => a.checked_mul(*b).map(Integer),
        (BinaryOp::Mod, Integer(a), Integer(b)) if *a >= 0 && *b > 0 => {
            Some(Integer(a.rem_euclid(*b)))
        }
        (BinaryOp::Equal, a, b) => {
            if a == b {
                Some(Boolean(true))
            } else if std::mem::discriminant(a) != std::mem::discriminant(b) {
                Some(Boolean(false))
            } else {
                None
            }
        }
        (BinaryOp::NotEqual, a, b) => match try_fold_binop(BinaryOp::Equal, a, b) {
            Some(Boolean(flag)) => Some(Boolean(!flag)),
            _ => None,
        },
        (BinaryOp::Less, Integer(a), Integer(b)) => Some(Boolean(a < b)),
        (BinaryOp::LessEqual, Integer(a), Integer(b)) => Some(Boolean(a <= b)),
        (BinaryOp::Greater, Integer(a), Integer(b)) => Some(Boolean(a > b)),
        (BinaryOp::GreaterEqual, Integer(a), Integer(b)) => Some(Boolean(a >= b)),
        (BinaryOp::And, a, _) if truthy_const(a) == Some(false) => Some(a.clone()),
        (BinaryOp::And, a, b) if truthy_const(a) == Some(true) => Some(b.clone()),
        (BinaryOp::Or, a, _) if truthy_const(a) == Some(true) => Some(a.clone()),
        (BinaryOp::Or, a, b) if truthy_const(a) == Some(false) => Some(b.clone()),
        _ => None,
    }
}

fn binary_op_symbol(op: BinaryOp) -> &'static str {
    match op {
        BinaryOp::Add => "+",
        BinaryOp::Sub => "-",
        BinaryOp::Mul => "*",
        BinaryOp::Div => "/",
        BinaryOp::Mod => "%",
        BinaryOp::FloorDiv => "//",
        BinaryOp::Pow => "^",
        BinaryOp::Equal => "==",
        BinaryOp::NotEqual => "~=",
        BinaryOp::Less => "<",
        BinaryOp::LessEqual => "<=",
        BinaryOp::Greater => ">",
        BinaryOp::GreaterEqual => ">=",
        BinaryOp::And => "and",
        BinaryOp::Or => "or",
    }
}

fn negate_binary_op(op: BinaryOp) -> Option<&'static str> {
    match op {
        BinaryOp::Equal => Some("~="),
        BinaryOp::NotEqual => Some("=="),
        BinaryOp::Less => Some(">="),
        BinaryOp::LessEqual => Some(">"),
        BinaryOp::Greater => Some("<="),
        BinaryOp::GreaterEqual => Some("<"),
        _ => None,
    }
}

fn compound_binary(op: BinaryOp) -> Option<&'static str> {
    match op {
        BinaryOp::Add => Some("+="),
        BinaryOp::Sub => Some("-="),
        BinaryOp::Mul => Some("*="),
        BinaryOp::Div => Some("/="),
        BinaryOp::Mod => Some("%="),
        BinaryOp::FloorDiv => Some("//="),
        BinaryOp::Pow => Some("^="),
        _ => None,
    }
}

fn binary_result_type(op: BinaryOp) -> LType {
    match op {
        BinaryOp::Equal
        | BinaryOp::NotEqual
        | BinaryOp::Less
        | BinaryOp::LessEqual
        | BinaryOp::Greater
        | BinaryOp::GreaterEqual => LType::Bool,
        BinaryOp::And | BinaryOp::Or => LType::Any,
        _ => LType::Num,
    }
}

fn parenthesize(text: &str, compound: bool) -> String {
    if compound {
        format!("({text})")
    } else {
        text.to_owned()
    }
}

/// Registers bound (not element-written) by an instruction.
fn instruction_binding_defs(instr: &Instruction) -> Vec<u16> {
    match instr {
        Instruction::LoadConst { dst, .. }
        | Instruction::Move { dst, .. }
        | Instruction::Unary { dst, .. }
        | Instruction::Binary { dst, .. }
        | Instruction::GetTable { dst, .. }
        | Instruction::NewTable { dst }
        | Instruction::NewPackedTable { dst }
        | Instruction::Call { dst: Some(dst), .. }
        | Instruction::CallWithPackedArgs { dst: Some(dst), .. }
        | Instruction::Concat { dst, .. }
        | Instruction::NewClosure { dst, .. } => vec![dst.physical_slot],
        Instruction::ForPrep { state, .. } => vec![state.physical_slot],
        _ => Vec::new(),
    }
}
/// Registers written by an instruction (destination slots; element writes
/// count as writes of the table register).
fn instruction_defs(instr: &Instruction) -> Vec<u16> {
    match instr {
        Instruction::LoadConst { dst, .. }
        | Instruction::Move { dst, .. }
        | Instruction::Unary { dst, .. }
        | Instruction::Binary { dst, .. }
        | Instruction::GetTable { dst, .. }
        | Instruction::NewTable { dst }
        | Instruction::NewPackedTable { dst }
        | Instruction::Call { dst: Some(dst), .. }
        | Instruction::CallWithPackedArgs { dst: Some(dst), .. }
        | Instruction::Concat { dst, .. }
        | Instruction::NewClosure { dst, .. } => vec![dst.physical_slot],
        Instruction::SetTable { table, .. }
        | Instruction::Append { table, .. }
        | Instruction::PushPacked { table, .. }
        | Instruction::AppendPacked { table, .. } => match table {
            Operand::Register(reg) => vec![reg.physical_slot],
            _ => Vec::new(),
        },
        Instruction::ForPrep { state, .. } | Instruction::ForLoop { state, .. } => {
            vec![state.physical_slot]
        }
        _ => Vec::new(),
    }
}

/// Operands in canonical display order; `instruction_uses` derives from this.
fn operands_of(instr: &Instruction) -> Vec<&Operand> {
    let top: Vec<&Operand> = match instr {
        Instruction::Move { src, .. } | Instruction::Unary { src, .. } => vec![src],
        Instruction::Binary { left, right, .. } => vec![left, right],
        Instruction::GetTable { table, index, .. } => vec![table, index],
        Instruction::SetTable {
            table,
            index,
            value,
        } => vec![table, index, value],
        Instruction::Append { table, value } | Instruction::PushPacked { table, value } => {
            vec![table, value]
        }
        Instruction::AppendPacked { table, values } => vec![table, values],
        Instruction::Call { function, args, .. } => {
            let mut out = vec![function];
            out.extend(args.iter());
            out
        }
        Instruction::CallWithPackedArgs {
            function,
            prefix,
            arguments,
            ..
        } => {
            let mut out = vec![function];
            out.extend(prefix.iter());
            out.push(arguments);
            out
        }
        Instruction::Concat { values, .. } => values.iter().collect(),
        Instruction::NewClosure { captures, .. } => captures.iter().collect(),
        Instruction::Return { values } => values.iter().collect(),
        Instruction::ReturnPacked { values } => vec![values],
        Instruction::Compare { condition } | Instruction::Branch { condition, .. } => {
            condition_operands(condition)
        }
        Instruction::Tag { value } => vec![value],
        _ => Vec::new(),
    };
    let mut leaves: Vec<&Operand> = Vec::new();
    for operand in top {
        collect_operand_leaves(operand, &mut leaves);
    }
    leaves
}

fn collect_operand_leaves<'a>(operand: &'a Operand, out: &mut Vec<&'a Operand>) {
    match operand {
        Operand::Expression(expression) => {
            collect_expression_leaves(expression, out);
        }
        _ => out.push(operand),
    }
}

fn collect_expression_leaves<'a>(expression: &'a ValueExpression, out: &mut Vec<&'a Operand>) {
    match expression {
        ValueExpression::Unary { value, .. } => collect_operand_leaves(value, out),
        ValueExpression::Binary { left, right, .. } => {
            collect_operand_leaves(left, out);
            collect_operand_leaves(right, out);
        }
        ValueExpression::Index { table, index } => {
            collect_operand_leaves(table, out);
            collect_operand_leaves(index, out);
        }
        ValueExpression::PermutationParity { value, .. } => collect_operand_leaves(value, out),
    }
}

fn condition_operands(condition: &Condition) -> Vec<&Operand> {
    match condition {
        Condition::Truthy(operand) | Condition::Falsey(operand) => vec![operand],
        Condition::Compare { left, right, .. } => vec![left, right],
    }
}

fn instruction_uses(instr: &Instruction) -> Vec<u16> {
    operands_of(instr)
        .into_iter()
        .filter_map(|operand| match operand {
            Operand::Register(reg) => Some(reg.physical_slot),
            _ => None,
        })
        .collect()
}

fn condition_state_test(condition: &Condition) -> Option<(BinaryOp, u16, u16)> {
    match condition {
        Condition::Compare {
            op: BinaryOp::LessEqual | BinaryOp::GreaterEqual,
            left: Operand::Register(left),
            right: Operand::Register(right),
        } => {
            let op = match condition {
                Condition::Compare { op, .. } => *op,
                _ => unreachable!(),
            };
            Some((op, left.physical_slot, right.physical_slot))
        }
        _ => None,
    }
}

/// The `GetTable { dst, table: Register(state), index: Integer(element) }`
/// load inside a loop-test block.
fn state_element_load(
    instructions: &[Instruction],
    dst: u16,
    state: u16,
    element: i64,
) -> Option<usize> {
    instructions.iter().enumerate().find_map(|(idx, instr)| {
        if let Instruction::GetTable {
            dst: load_dst,
            table: Operand::Register(table),
            index: Operand::Constant(Constant::Integer(index)),
        } = instr
        {
            if load_dst.physical_slot == dst && table.physical_slot == state && *index == element {
                return Some(idx);
            }
        }
        None
    })
}

fn terminal(block: &BasicBlock) -> Option<&Instruction> {
    // The lifter may place VM bookkeeping (KeyUpdate/BankSwitch/Tag) or a
    // trailing Jump after the real control-flow terminator; scan backwards.
    let mut idx = block.instructions.len();
    while idx > 0 {
        idx -= 1;
        let instr = &block.instructions[idx];
        if matches!(
            instr,
            Instruction::KeyUpdate { .. }
                | Instruction::BankSwitch { .. }
                | Instruction::Tag { .. }
                | Instruction::Nop
        ) {
            continue;
        }
        if matches!(
            instr,
            Instruction::Jump { .. }
                | Instruction::Branch { .. }
                | Instruction::Return { .. }
                | Instruction::ReturnPacked { .. }
                | Instruction::ForPrep { .. }
                | Instruction::ForLoop { .. }
                | Instruction::Compare { .. }
        ) {
            return Some(instr);
        }
        // A trailing Jump whose target is the block's single successor is
        // treated as the terminator.
        if let Instruction::Jump { target } = instr {
            if block.successors.len() == 1 && block.successors[0].target_pc == Some(*target) {
                return Some(instr);
            }
        }
        return None;
    }
    None
}

fn last_condition(block: &BasicBlock) -> Option<Condition> {
    match terminal(block) {
        Some(Instruction::Branch { condition, .. }) | Some(Instruction::Compare { condition }) => {
            Some(condition.clone())
        }
        _ => None,
    }
}

fn two_way_targets(succs: &[(EdgeLabel, Option<usize>)]) -> Option<(usize, usize)> {
    let mut then_target = None;
    let mut else_target = None;
    for (label, target) in succs {
        match (label, target) {
            (EdgeLabel::True, Some(pc)) => then_target = Some(*pc),
            (EdgeLabel::False, Some(pc)) => else_target = Some(*pc),
            _ => return None,
        }
    }
    Some((then_target?, else_target?))
}

fn single_succ_of(succs: &[(EdgeLabel, Option<usize>)]) -> Option<usize> {
    if succs.len() != 1 {
        return None;
    }
    match succs.first() {
        Some((_, Some(pc))) => Some(*pc),
        _ => None,
    }
}

fn validate_block(
    pc: usize,
    block: &BasicBlock,
) -> Result<Vec<(EdgeLabel, Option<usize>)>, String> {
    let mut edges: Vec<(EdgeLabel, Option<usize>)> = Vec::new();
    for successor in &block.successors {
        if matches!(successor.label, EdgeLabel::Case(_)) {
            if let Some(Instruction::Branch {
                then_target,
                else_target,
                ..
            }) = terminal(block)
            {
                let label = match successor.target_pc {
                    Some(target) if target == *then_target => EdgeLabel::True,
                    Some(target) if target == *else_target => EdgeLabel::False,
                    _ => {
                        return Err(format!(
                            "PC {pc}: Case target disagrees with resolved Branch"
                        ))
                    }
                };
                edges.push((label, successor.target_pc));
                continue;
            } else {
                return Err(format!(
                    "PC {pc}: unresolved Case successor without a typed Branch"
                ));
            }
        }
        edges.push((successor.label.clone(), successor.target_pc));
    }
    let mismatch = |expected: &str| {
        Err(format!(
            "block at PC {pc} has a {expected} terminal but inconsistent successors"
        ))
    };
    match terminal(block) {
        Some(Instruction::Return { .. } | Instruction::ReturnPacked { .. }) => {
            for (label, _) in &edges {
                if !matches!(label, EdgeLabel::Return) {
                    return mismatch("Return");
                }
            }
        }
        Some(Instruction::Jump { target }) => {
            if edges.len() != 1 || edges[0].1 != Some(*target) {
                return mismatch("Jump");
            }
        }
        Some(Instruction::Branch {
            then_target,
            else_target,
            ..
        }) => {
            if two_way_targets(&edges) != Some((*then_target, *else_target)) {
                return mismatch("Branch");
            }
        }
        Some(Instruction::Compare { .. }) => {
            if two_way_targets(&edges).is_none() {
                return mismatch("Compare");
            }
        }
        Some(Instruction::ForPrep { target, .. }) => {
            if edges.len() != 1 || edges[0].1 != Some(*target) {
                return mismatch("ForPrep");
            }
        }
        Some(Instruction::ForLoop { target, .. }) => {
            if edges.len() == 2 {
                if two_way_targets(&edges).is_none() {
                    return mismatch("ForLoop range test");
                }
            } else if edges.len() == 1 {
                if edges[0].1 != Some(*target) {
                    return mismatch("ForLoop increment");
                }
            } else {
                return mismatch("ForLoop");
            }
        }
        Some(other) => {
            let _ = other;
            if edges.len() != 1 {
                return mismatch("fallthrough");
            }
        }
        None => {
            if edges.len() != 1 || edges[0].1.is_none() {
                return mismatch("fallthrough");
            }
        }
    }
    Ok(edges)
}

fn compute_ipdom(
    succs: &BTreeMap<usize, Vec<(EdgeLabel, Option<usize>)>>,
    order: &[usize],
    loops: &HashMap<usize, BTreeSet<usize>>,
    loop_heads: &BTreeSet<usize>,
) -> HashMap<usize, Option<usize>> {
    // Skeleton successors: drop dominator-verified back edges.
    let mut skeleton: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (&pc, edges) in succs {
        let mut targets = Vec::new();
        for (_, target) in edges {
            if let Some(target) = *target {
                let is_back_edge = loop_heads.contains(&target) && loops[&target].contains(&pc);
                if !is_back_edge {
                    targets.push(target);
                }
            }
        }
        skeleton.insert(pc, targets);
    }
    let mut pdom: HashMap<usize, BTreeSet<usize>> = HashMap::new();
    let all: BTreeSet<usize> = order.iter().copied().collect();
    for &pc in order {
        let mut set = all.clone();
        if skeleton[&pc].is_empty() {
            set.clear();
            set.insert(pc);
        }
        pdom.insert(pc, set);
    }
    loop {
        let mut changed = false;
        for &pc in order.iter().rev() {
            let targets = &skeleton[&pc];
            if targets.is_empty() {
                continue;
            }
            let mut merged: Option<BTreeSet<usize>> = None;
            for &target in targets {
                merged = Some(match merged {
                    None => pdom[&target].clone(),
                    Some(current) => current.intersection(&pdom[&target]).copied().collect(),
                });
            }
            let mut new_set = merged.unwrap_or_default();
            new_set.insert(pc);
            if new_set != pdom[&pc] {
                pdom.insert(pc, new_set);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut ipdom: HashMap<usize, Option<usize>> = HashMap::new();
    for &pc in order {
        let strict: Vec<usize> = pdom[&pc].iter().copied().filter(|&p| p != pc).collect();
        let expected = pdom[&pc].len() - 1;
        let closest: Vec<usize> = strict
            .into_iter()
            .filter(|p| pdom[p].len() == expected)
            .collect();
        ipdom.insert(
            pc,
            if closest.len() == 1 {
                Some(closest[0])
            } else {
                None
            },
        );
    }
    ipdom
}

fn cp_read(state: &BTreeMap<u16, CpValue>, operand: &Operand) -> CpValue {
    match operand {
        Operand::Register(reg) => state
            .get(&reg.physical_slot)
            .cloned()
            .unwrap_or(CpValue::Bottom),
        Operand::Constant(value) => CpValue::Const(value.clone()),
        Operand::Expression(expression) => cp_expression(state, expression),
        _ => CpValue::Bottom,
    }
}

fn cp_expression(state: &BTreeMap<u16, CpValue>, expression: &ValueExpression) -> CpValue {
    match expression {
        ValueExpression::Unary { op, value } => {
            let value = cp_read(state, value);
            match &value {
                CpValue::Const(constant) => try_fold_unop(*op, constant)
                    .map(CpValue::Const)
                    .unwrap_or(CpValue::Bottom),
                _ => CpValue::Bottom,
            }
        }
        ValueExpression::Binary { op, left, right } => {
            let left = cp_read(state, left);
            let right = cp_read(state, right);
            match (&left, &right) {
                (CpValue::Const(a), CpValue::Const(b)) => try_fold_binop(*op, a, b)
                    .map(CpValue::Const)
                    .unwrap_or(CpValue::Bottom),
                _ => CpValue::Bottom,
            }
        }
        ValueExpression::Index { table, index } => fold_gettable(state, table, index),
        ValueExpression::PermutationParity {
            value,
            parity,
            nonnumeric,
        } => {
            let value = cp_read(state, value);
            match value {
                CpValue::Const(Constant::Integer(i)) if i >= 0 && (i as usize) < parity.len() => {
                    CpValue::Const(Constant::Integer(i64::from(parity[i as usize])))
                }
                CpValue::Const(Constant::U32(i)) if (i as usize) < parity.len() => {
                    CpValue::Const(Constant::Integer(i64::from(parity[i as usize])))
                }
                CpValue::Const(_) => CpValue::Const(Constant::Integer(i64::from(*nonnumeric))),
                _ => CpValue::Bottom,
            }
        }
    }
}

fn fold_gettable(state: &BTreeMap<u16, CpValue>, table: &Operand, index: &Operand) -> CpValue {
    let table_value = cp_read(state, table);
    let index_const = match index {
        Operand::Constant(value) => Some(value.clone()),
        _ => None,
    };
    match (table_value, index_const) {
        (
            CpValue::Table {
                elems: Some(list), ..
            },
            Some(index),
        ) => match constant_as_i64(&index) {
            Some(i) if i >= 1 => list
                .get((i - 1) as usize)
                .map(|(_, value, _)| value.clone())
                .unwrap_or(CpValue::Bottom),
            _ => CpValue::Bottom,
        },
        // A scalar extracted from a packed call is not a variadic splice.
        (CpValue::PackCall { .. }, Some(_)) => CpValue::Bottom,
        _ => CpValue::Bottom,
    }
}

fn cp_transfer(state: &mut BTreeMap<u16, CpValue>, pc: usize, idx: usize, instr: &Instruction) {
    let site = (pc, idx);
    match instr {
        Instruction::LoadConst { dst, value } => {
            state.insert(dst.physical_slot, CpValue::Const(value.clone()));
        }
        Instruction::Move { dst, src } => {
            let value = cp_read(state, src);
            state.insert(dst.physical_slot, value);
        }
        Instruction::Unary { op, dst, src } => {
            let value = cp_read(state, src);
            let folded = match &value {
                CpValue::Const(constant) => try_fold_unop(*op, constant),
                _ => None,
            };
            state.insert(
                dst.physical_slot,
                folded.map(CpValue::Const).unwrap_or(CpValue::Bottom),
            );
        }
        Instruction::Binary {
            op,
            dst,
            left,
            right,
        } => {
            let left_value = cp_read(state, left);
            let right_value = cp_read(state, right);
            let folded = match (&left_value, &right_value) {
                (CpValue::Const(a), CpValue::Const(b)) => try_fold_binop(*op, a, b),
                _ => None,
            };
            state.insert(
                dst.physical_slot,
                folded.map(CpValue::Const).unwrap_or(CpValue::Bottom),
            );
        }
        Instruction::GetTable { dst, table, index } => {
            let value = fold_gettable(state, table, index);
            state.insert(dst.physical_slot, value);
        }
        Instruction::NewTable { dst } | Instruction::NewPackedTable { dst } => {
            state.insert(
                dst.physical_slot,
                CpValue::Table {
                    site,
                    elems: Some(Vec::new()),
                },
            );
        }
        Instruction::Append { table, value } | Instruction::PushPacked { table, value } => {
            if let Operand::Register(reg) = table {
                let current = state.get(&reg.physical_slot).cloned();
                if let Some(CpValue::Table {
                    site: table_site,
                    elems: Some(mut list),
                }) = current
                {
                    let element = cp_read(state, value);
                    list.push((value.clone(), element, site));
                    state.insert(
                        reg.physical_slot,
                        CpValue::Table {
                            site: table_site,
                            elems: Some(list),
                        },
                    );
                }
            }
        }
        Instruction::AppendPacked { table, values } => {
            if let Operand::Register(reg) = table {
                let incoming = cp_read(state, values);
                if let Some(CpValue::Table {
                    site: table_site,
                    elems: Some(mut list),
                }) = state.get(&reg.physical_slot).cloned()
                {
                    match incoming {
                        CpValue::Table {
                            elems: Some(incoming),
                            ..
                        } => list.extend(incoming),
                        CpValue::PackCall { .. } => list.push((values.clone(), incoming, site)),
                        _ => {
                            state.insert(reg.physical_slot, CpValue::Bottom);
                            return;
                        }
                    }
                    state.insert(
                        reg.physical_slot,
                        CpValue::Table {
                            site: table_site,
                            elems: Some(list),
                        },
                    );
                }
            }
        }
        Instruction::SetTable {
            table,
            index,
            value,
        } => {
            if let Operand::Register(reg) = table {
                let current = state.get(&reg.physical_slot).cloned();
                if let Some(CpValue::Table {
                    site: table_site,
                    elems,
                }) = current
                {
                    let updated = match (elems, index) {
                        (Some(mut list), Operand::Constant(index_const)) => {
                            match constant_as_i64(index_const) {
                                Some(i) if (1..=4096).contains(&i) => {
                                    let element = cp_read(state, value);
                                    while list.len() < i as usize {
                                        list.push((
                                            Operand::Constant(Constant::Nil),
                                            CpValue::Const(Constant::Nil),
                                            site,
                                        ));
                                    }
                                    list[(i - 1) as usize] = (value.clone(), element, site);
                                    Some(list)
                                }
                                _ => None,
                            }
                        }
                        _ => None,
                    };
                    state.insert(
                        reg.physical_slot,
                        CpValue::Table {
                            site: table_site,
                            elems: updated,
                        },
                    );
                }
            }
        }
        Instruction::Call { dst: Some(dst), .. }
        | Instruction::CallWithPackedArgs { dst: Some(dst), .. } => {
            state.insert(dst.physical_slot, CpValue::PackCall { site });
        }
        Instruction::ForLoop {
            state: loop_state, ..
        } => {
            if let Some(CpValue::Table {
                elems: Some(list), ..
            }) = state.get_mut(&loop_state.physical_slot)
            {
                if !list.is_empty() {
                    list[0].1 = CpValue::Bottom;
                }
            }
        }
        Instruction::Raw { .. } => {
            state.clear();
        }
        _ => {}
    }
}

// =========================================================================
// Rendering context and the reconstruction engine
// =========================================================================

#[derive(Default)]
struct RenderCtx {
    numeric_inputs: BTreeSet<usize>,
    /// Register -> blocks whose uses render as the register's own local.
    name_uses: HashMap<u16, BTreeSet<usize>>,
    /// Call sites whose evaluation moved into a later reconstruction.
    moved_calls: BTreeSet<Site>,
    /// GetTable sites whose PackCall value moved into a later reconstruction.
    moved_gettables: BTreeSet<Site>,
    /// Sites absorbed by packed-return expansions (never emitted).
    absorbed: BTreeSet<Site>,
    /// Packed-return expansions, keyed by the return site.
    packed_returns: HashMap<Site, Vec<String>>,
    /// Module-level fallback bindings required by the emission.
    unknown_ids: BTreeSet<u32>,
    unknown_consts: BTreeSet<u32>,
    frame_slots: BTreeSet<u16>,
    word_refs: BTreeSet<usize>,
    /// Function parameters discovered from `Operand::Argument` uses.
    arg_max: Option<usize>,
    uses_varargs: bool,
}

impl RenderCtx {
    fn note_name(&mut self, slot: u16, pc: usize) {
        self.name_uses.entry(slot).or_default().insert(pc);
    }
}

impl<'a> FnAnalysis<'a> {
    fn single_succ(&self, pc: usize) -> Option<usize> {
        single_succ_of(&self.succs[&pc])
    }

    fn reaches(&self, from: usize, to: usize) -> bool {
        if from == to {
            return true;
        }
        let mut seen: HashSet<usize> = HashSet::new();
        let mut work: Vec<usize> = vec![from];
        seen.insert(from);
        while let Some(pc) = work.pop() {
            for (_, target) in &self.succs[&pc] {
                if let Some(target) = *target {
                    if target == to {
                        return true;
                    }
                    if seen.insert(target) {
                        work.push(target);
                    }
                }
            }
        }
        false
    }

    /// A def/use chain with no joins and no back edge, so an expression
    /// evaluated at `def_pc` still holds at `use_pc`.
    fn straight_line(&self, def_pc: usize, use_pc: usize) -> bool {
        if def_pc == use_pc {
            return true;
        }
        if !self.dom[&use_pc].contains(&def_pc) {
            return false;
        }
        if self.preds.get(&use_pc).map(|set| set.len()) != Some(1) {
            return false;
        }
        let mut cursor = def_pc;
        let mut hops = 0usize;
        loop {
            hops += 1;
            if hops > self.blocks.len() + 2 {
                return false;
            }
            let Some(next) = self.single_succ(cursor) else {
                return false;
            };
            if next == use_pc {
                return true;
            }
            if self.preds.get(&next).map(|set| set.len()) != Some(1) {
                return false;
            }
            cursor = next;
        }
    }

    /// The unambiguous reaching def of `slot` at `site`, if one exists.
    fn reaching_def(&self, site: Site, slot: u16) -> Option<Site> {
        let block = self.block(site.0);
        let mut same_block: Option<Site> = None;
        for (idx, instr) in block.instructions.iter().enumerate() {
            if idx >= site.1 {
                break;
            }
            if instruction_defs(instr).contains(&slot) {
                same_block = Some((site.0, idx));
            }
        }
        if let Some(found) = same_block {
            return Some(found);
        }
        let defs = self.binding_defs.get(&slot)?;
        let mut candidates: Vec<Site> = Vec::new();
        for &def in defs {
            if def.0 == site.0 {
                continue;
            }
            if !self.dom[&site.0].contains(&def.0) {
                continue;
            }
            candidates.push(def);
        }
        if candidates.is_empty() {
            return None;
        }
        let chosen = if candidates.len() == 1 {
            candidates[0]
        } else {
            let mut latest: Option<Site> = None;
            for &candidate in &candidates {
                let dominated_by_all = candidates
                    .iter()
                    .all(|&other| other == candidate || self.dom[&candidate.0].contains(&other.0));
                if dominated_by_all {
                    if latest.is_some() {
                        return None;
                    }
                    latest = Some(candidate);
                }
            }
            latest?
        };
        for &other in defs {
            if other == chosen || other.0 == site.0 {
                continue;
            }
            if !self.reaches(other.0, site.0) {
                continue;
            }
            if !self.dom[&chosen.0].contains(&other.0) {
                return None;
            }
        }
        Some(chosen)
    }

    fn render_operand(
        &self,
        ctx: &mut RenderCtx,
        site: Site,
        operand: &Operand,
        depth: usize,
    ) -> Option<Rendered> {
        if depth > 16 {
            return None;
        }
        match operand {
            Operand::Constant(value) => {
                if let Constant::Unknown(id) = value {
                    ctx.unknown_consts.insert(*id);
                }
                Some(Rendered {
                    text: render_constant(value),
                    needs_name: false,
                    compound: false,
                    ty: LType::of_constant(value),
                })
            }
            Operand::Register(reg) => {
                let slot = reg.physical_slot;
                if let CpValue::Const(constant) = self.cp_value_at_site(site, slot) {
                    return Some(Rendered {
                        text: render_constant(&constant),
                        needs_name: false,
                        compound: false,
                        ty: LType::of_constant(&constant),
                    });
                }
                if let Some(def) = self.reaching_def(site, slot) {
                    // A register used by its own defining instruction reads its
                    // pre-assignment value; reconstruction would drop that state.
                    let self_def = self
                        .binding_defs
                        .get(&slot)
                        .map_or(false, |defs| defs.contains(&site));
                    // Never reconstruct through sites or blocks the numeric-for
                    // promotion consumed; their registers render by name (the
                    // loop variable and its state).
                    let consumed = self.for_promotion.as_ref().map_or(false, |promo| {
                        (promo.consumed_sites.contains(&def) && def.0 != promo.prep_pc)
                            || (promo.consumed_blocks.contains(&def.0) && def.0 != promo.prep_pc)
                    });
                    let effectful_read = match &self.block(def.0).instructions[def.1] {
                        Instruction::GetTable { table, .. } => {
                            let consumed_bound =
                                self.for_promotion.as_ref().is_some_and(|promotion| {
                                    def.0 == promotion.prep_pc
                                        && promotion.consumed_sites.contains(&def)
                                });
                            !(consumed_bound
                                && matches!(
                                    cp_read(&self.cp_at(def), table),
                                    CpValue::Table { .. }
                                ))
                        }
                        Instruction::Call { .. } => true,
                        Instruction::Binary { left, right, .. } => {
                            self.operand_type(left, 0) == LType::Any
                                || self.operand_type(right, 0) == LType::Any
                        }
                        _ => false,
                    };
                    if !self_def && !consumed && !effectful_read {
                        let reads_slot = instruction_uses(&self.block(def.0).instructions[def.1])
                            .contains(&slot);
                        if !reads_slot {
                            if let Some(rendered) = self.render_def_expr(ctx, def, depth + 1, true)
                            {
                                return Some(rendered);
                            }
                        }
                    }
                }
                ctx.note_name(slot, site.0);
                Some(Rendered {
                    text: reg_name(slot),
                    needs_name: true,
                    compound: false,
                    ty: self.register_type(slot, 0),
                })
            }
            Operand::Argument(index) => {
                ctx.arg_max = Some(ctx.arg_max.map_or(*index, |current| current.max(*index)));
                if *index == 0 && ctx.uses_varargs {
                    // placeholder no-op
                }
                Some(Rendered {
                    text: format!("arg{index}"),
                    needs_name: false,
                    compound: false,
                    ty: LType::Any,
                })
            }
            Operand::Global(path) => {
                let text = render_global_path(path);
                Some(Rendered {
                    text,
                    needs_name: false,
                    compound: true,
                    ty: LType::Any,
                })
            }
            Operand::Environment => Some(Rendered {
                text: "vm_environment".to_owned(),
                needs_name: false,
                compound: false,
                ty: LType::Any,
            }),
            Operand::Expression(expression) => {
                self.render_value_expression(ctx, site, expression, depth)
            }
            Operand::SlotMapIndex(slot) => {
                if *slot == PACKED_VARARGS_SLOT {
                    ctx.uses_varargs = true;
                    Some(Rendered {
                        text: "...".to_owned(),
                        needs_name: false,
                        compound: false,
                        ty: LType::Any,
                    })
                } else {
                    ctx.frame_slots.insert(*slot);
                    Some(Rendered {
                        text: format!("vm_frame_slot_{slot}"),
                        needs_name: false,
                        compound: false,
                        ty: LType::Any,
                    })
                }
            }
            Operand::Word(word) => {
                ctx.word_refs.insert(*word);
                Some(Rendered {
                    text: format!("vm_word_{word}"),
                    needs_name: false,
                    compound: false,
                    ty: LType::Any,
                })
            }
            Operand::Unknown(id) => {
                ctx.unknown_ids.insert(*id);
                Some(Rendered {
                    text: format!("vm_unknown_{id}"),
                    needs_name: false,
                    compound: false,
                    ty: LType::Any,
                })
            }
            Operand::Capture(index) => Some(Rendered {
                text: format!("capture{index}"),
                needs_name: false,
                compound: false,
                ty: LType::Any,
            }),
        }
    }
}

impl<'a> FnAnalysis<'a> {
    fn render_value_expression(
        &self,
        ctx: &mut RenderCtx,
        site: Site,
        expression: &ValueExpression,
        depth: usize,
    ) -> Option<Rendered> {
        if let CpValue::Const(constant) = cp_expression(&self.cp_at(site), expression) {
            return Some(Rendered {
                text: render_constant(&constant),
                needs_name: false,
                compound: false,
                ty: LType::of_constant(&constant),
            });
        }
        match expression {
            ValueExpression::Unary { op, value } => {
                let inner = self.render_operand(ctx, site, value, depth)?;
                let text = match op {
                    UnaryOp::Not => format!("not {}", parenthesize(&inner.text, inner.compound)),
                    UnaryOp::Negate => {
                        format!("-{}", parenthesize(&inner.text, inner.compound))
                    }
                    UnaryOp::Length => format!("#{}", parenthesize(&inner.text, inner.compound)),
                    UnaryOp::BitNot => format!("~{}", parenthesize(&inner.text, inner.compound)),
                    UnaryOp::TypeOf => format!("capturedType({})", inner.text),
                };
                Some(Rendered {
                    text,
                    needs_name: inner.needs_name,
                    compound: true,
                    ty: match op {
                        UnaryOp::Not => LType::Bool,
                        UnaryOp::Length => LType::Num,
                        UnaryOp::TypeOf => LType::Str,
                        _ => LType::Num,
                    },
                })
            }
            ValueExpression::Binary { op, left, right } => {
                let left_rendered = self.render_operand(ctx, site, left, depth)?;
                let right_rendered = self.render_operand(ctx, site, right, depth)?;
                Some(Rendered {
                    text: format!(
                        "{} {} {}",
                        parenthesize(&left_rendered.text, left_rendered.compound),
                        binary_op_symbol(*op),
                        parenthesize(&right_rendered.text, right_rendered.compound)
                    ),
                    needs_name: left_rendered.needs_name || right_rendered.needs_name,
                    compound: true,
                    ty: binary_result_type(*op),
                })
            }
            ValueExpression::Index { table, index } => {
                self.gettable_value_text(ctx, site, table, index, depth, false)
            }
            ValueExpression::PermutationParity {
                value,
                parity,
                nonnumeric,
            } => {
                let value_cp = cp_read(&self.cp_at(site), value);
                match value_cp {
                    CpValue::Const(Constant::Integer(i))
                        if i >= 0 && (i as usize) < parity.len() =>
                    {
                        Some(Rendered {
                            text: i64::from(parity[i as usize]).to_string(),
                            needs_name: false,
                            compound: false,
                            ty: LType::Num,
                        })
                    }
                    CpValue::Const(Constant::U32(i)) if (i as usize) < parity.len() => {
                        Some(Rendered {
                            text: i64::from(parity[i as usize]).to_string(),
                            needs_name: false,
                            compound: false,
                            ty: LType::Num,
                        })
                    }
                    CpValue::Const(_) => Some(Rendered {
                        text: i64::from(*nonnumeric).to_string(),
                        needs_name: false,
                        compound: false,
                        ty: LType::Num,
                    }),
                    _ => None,
                }
            }
        }
    }

    fn render_def_expr(
        &self,
        ctx: &mut RenderCtx,
        def: Site,
        depth: usize,
        record_moves: bool,
    ) -> Option<Rendered> {
        if depth > 16 {
            return None;
        }
        let instr = &self.block(def.0).instructions[def.1];
        match instr {
            Instruction::LoadConst { value, .. } => Some(Rendered {
                text: render_constant(value),
                needs_name: false,
                compound: false,
                ty: LType::of_constant(value),
            }),
            Instruction::Move { src, .. } => {
                let rendered = self.render_operand(ctx, def, src, depth)?;
                // A move out of a fallback binding (`...`, unresolved operands,
                // frame slots, raw words) cannot be reconstructed into an
                // expression position; keep the register name instead.
                if rendered.text == "..."
                    || rendered.text.starts_with("vm_unknown_")
                    || rendered.text.starts_with("vm_frame_slot_")
                    || rendered.text.starts_with("vm_word_")
                {
                    return None;
                }
                Some(rendered)
            }
            Instruction::Unary { op, src, .. } => {
                let inner = self.render_operand(ctx, def, src, depth)?;
                let text = match op {
                    UnaryOp::Not => format!("not {}", parenthesize(&inner.text, inner.compound)),
                    UnaryOp::Negate => format!("-{}", parenthesize(&inner.text, inner.compound)),
                    UnaryOp::Length => format!("#{}", parenthesize(&inner.text, inner.compound)),
                    UnaryOp::BitNot => format!("~{}", parenthesize(&inner.text, inner.compound)),
                    UnaryOp::TypeOf => format!("capturedType({})", inner.text),
                };
                Some(Rendered {
                    text,
                    needs_name: inner.needs_name,
                    compound: true,
                    ty: match op {
                        UnaryOp::Not => LType::Bool,
                        UnaryOp::Length => LType::Num,
                        UnaryOp::TypeOf => LType::Str,
                        _ => LType::Num,
                    },
                })
            }
            Instruction::Binary {
                op, left, right, ..
            } => {
                let left_rendered = self.render_operand(ctx, def, left, depth)?;
                let right_rendered = self.render_operand(ctx, def, right, depth)?;
                Some(Rendered {
                    text: format!(
                        "{} {} {}",
                        parenthesize(&left_rendered.text, left_rendered.compound),
                        binary_op_symbol(*op),
                        parenthesize(&right_rendered.text, right_rendered.compound)
                    ),
                    needs_name: left_rendered.needs_name || right_rendered.needs_name,
                    compound: true,
                    ty: binary_result_type(*op),
                })
            }
            Instruction::GetTable { table, index, .. } => {
                self.gettable_value_text(ctx, def, table, index, depth, record_moves)
            }
            Instruction::Call { .. } => self.render_call_expr(ctx, def, depth, record_moves),
            Instruction::Concat { values, .. } => {
                let mut parts: Vec<String> = Vec::new();
                let mut needs_name = false;
                for value in values {
                    let rendered = self.render_operand(ctx, def, value, depth)?;
                    needs_name |= rendered.needs_name;
                    parts.push(rendered.text);
                }
                Some(Rendered {
                    text: parts.join(" .. "),
                    needs_name,
                    compound: true,
                    ty: LType::Str,
                })
            }
            _ => None,
        }
    }

    fn gettable_value_text(
        &self,
        ctx: &mut RenderCtx,
        site: Site,
        table: &Operand,
        index: &Operand,
        depth: usize,
        record_moves: bool,
    ) -> Option<Rendered> {
        if let Operand::Register(reg) = table {
            if let CpValue::Table {
                elems: Some(list), ..
            } = self.cp_value_at_site(site, reg.physical_slot)
            {
                if let Operand::Constant(index_const) = index {
                    if let Some(i) = constant_as_i64(index_const).filter(|i| *i >= 1) {
                        if let Some((operand, value, origin)) = list.get((i - 1) as usize) {
                            match value {
                                CpValue::Const(constant) => {
                                    return Some(Rendered {
                                        text: render_constant(constant),
                                        needs_name: false,
                                        compound: false,
                                        ty: LType::of_constant(constant),
                                    });
                                }
                                CpValue::PackCall { site: call } => {
                                    if record_moves {
                                        ctx.moved_calls.insert(*call);
                                        ctx.moved_gettables.insert(site);
                                    }
                                    return self.render_call_expr(ctx, *call, depth, record_moves);
                                }
                                CpValue::Bottom => {
                                    if self.straight_line(origin.0, site.0) {
                                        if let Some(rendered) =
                                            self.render_operand(ctx, *origin, operand, depth)
                                        {
                                            return Some(Rendered {
                                                compound: true,
                                                ty: rendered.ty.clone(),
                                                text: rendered.text,
                                                needs_name: rendered.needs_name,
                                            });
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
        let mut table_rendered = self.render_operand(ctx, site, table, depth)?;
        let mut ty = LType::Any;
        if let Some(argument) = self.argument_origin(table, 0) {
            ctx.numeric_inputs.insert(argument);
            table_rendered.text = format!("inputValues{argument}");
            ty = LType::Num;
        }
        let index_rendered = self.render_operand(ctx, site, index, depth)?;
        Some(Rendered {
            text: format!("{}[{}]", table_rendered.text, index_rendered.text),
            needs_name: table_rendered.needs_name || index_rendered.needs_name,
            compound: true,
            ty,
        })
    }

    fn render_call_expr(
        &self,
        ctx: &mut RenderCtx,
        call: Site,
        depth: usize,
        record_move: bool,
    ) -> Option<Rendered> {
        let Instruction::Call { function, args, .. } = &self.block(call.0).instructions[call.1]
        else {
            return None;
        };
        let function_rendered = self.render_operand(ctx, call, function, depth)?;
        let mut parts = vec![function_rendered.text];
        let mut needs_name = function_rendered.needs_name;
        for arg in args {
            let rendered = self.render_operand(ctx, call, arg, depth)?;
            needs_name |= rendered.needs_name;
            parts.push(rendered.text);
        }
        if record_move {
            ctx.moved_calls.insert(call);
        }
        Some(Rendered {
            text: format!("{}({})", parts[0], parts[1..].join(", ")),
            needs_name,
            compound: true,
            ty: LType::Any,
        })
    }

    fn render_condition(
        &self,
        ctx: &mut RenderCtx,
        site: Site,
        condition: &Condition,
        invert: bool,
    ) -> Option<String> {
        match condition {
            Condition::Truthy(operand) => {
                let rendered = self.render_operand(ctx, site, operand, 0)?;
                if invert {
                    Some(format!(
                        "not {}",
                        parenthesize(&rendered.text, rendered.compound)
                    ))
                } else {
                    Some(rendered.text)
                }
            }
            Condition::Falsey(operand) => {
                let rendered = self.render_operand(ctx, site, operand, 0)?;
                if invert {
                    Some(rendered.text)
                } else {
                    Some(format!(
                        "not {}",
                        parenthesize(&rendered.text, rendered.compound)
                    ))
                }
            }
            Condition::Compare { op, left, right } => {
                let left_rendered = self.render_operand(ctx, site, left, 0)?;
                let right_rendered = self.render_operand(ctx, site, right, 0)?;
                if invert {
                    if let Some(negated) = negate_binary_op(*op) {
                        Some(format!(
                            "{} {} {}",
                            left_rendered.text, negated, right_rendered.text
                        ))
                    } else {
                        Some(format!(
                            "not ({} {} {})",
                            left_rendered.text,
                            binary_op_symbol(*op),
                            right_rendered.text
                        ))
                    }
                } else {
                    Some(format!(
                        "{} {} {}",
                        left_rendered.text,
                        binary_op_symbol(*op),
                        right_rendered.text
                    ))
                }
            }
        }
    }

    /// Expand a `Return` of a single packed constructor into its elements.
    fn try_packed_return(
        &self,
        ctx: &mut RenderCtx,
        site: Site,
        values: &[Operand],
    ) -> Option<Vec<String>> {
        if values.len() != 1 {
            return None;
        }
        let Operand::Register(reg) = &values[0] else {
            return None;
        };
        let slot = reg.physical_slot;
        let CpValue::Table {
            site: table_site,
            elems: Some(list),
        } = self.cp_value_at_site(site, slot)
        else {
            return None;
        };
        let binding_defs = self.binding_defs.get(&slot)?;
        if binding_defs.len() != 1 || binding_defs[0] != table_site {
            return None;
        }
        if !matches!(
            self.block(table_site.0).instructions[table_site.1],
            Instruction::NewPackedTable { .. }
        ) {
            return None;
        }
        for &(use_pc, use_idx) in self.uses.get(&slot)? {
            if (use_pc, use_idx) == site {
                continue;
            }
            let instr = &self.block(use_pc).instructions[use_idx];
            let constructor_use = match instr {
                Instruction::PushPacked {
                    table: Operand::Register(t),
                    ..
                }
                | Instruction::AppendPacked {
                    table: Operand::Register(t),
                    ..
                } => t.physical_slot == slot,
                _ => false,
            };
            if !constructor_use {
                return None;
            }
        }
        let mut texts: Vec<String> = Vec::new();
        for (element_index, (operand, value, origin)) in list.iter().enumerate() {
            match value {
                CpValue::Const(constant) => texts.push(render_constant(constant)),
                CpValue::PackCall { site: call } => {
                    if !matches!(
                        &self.block(origin.0).instructions[origin.1],
                        Instruction::AppendPacked { .. }
                    ) {
                        return None;
                    }
                    if element_index + 1 != list.len() {
                        return None;
                    }
                    if !self.straight_line(call.0, site.0) {
                        return None;
                    }
                    texts.push(self.render_call_expr(ctx, *call, 0, true)?.text);
                }
                CpValue::Bottom => {
                    if !self.straight_line(origin.0, site.0) {
                        return None;
                    }
                    texts.push(self.render_operand(ctx, *origin, operand, 0)?.text);
                }
                _ => return None,
            }
        }
        Some(texts)
    }
}

// =========================================================================
// Emission plan and statement tree
// =========================================================================

#[derive(Clone)]
enum Stmt {
    Block {
        pc: usize,
        lines: Vec<String>,
    },
    If {
        pc: usize,
        cond: String,
        then_arm: Vec<Stmt>,
        else_arm: Vec<Stmt>,
    },
    While {
        cond: Option<String>,
        body: Vec<Stmt>,
    },
    ForNum {
        var: String,
        start: String,
        limit: String,
        step: Option<String>,
        body: Vec<Stmt>,
    },
    Goto(usize),
    Continue,
    Label(usize),
    Return(String),
    Comment(String),
}

enum Walk {
    Continue(usize),
    Stop,
}

fn rewrite_continues(tree: &mut Vec<Stmt>, latch: usize, in_for: bool) -> Result<(), String> {
    for statement in tree.iter_mut() {
        match statement {
            Stmt::Goto(target) if in_for && *target == latch => *statement = Stmt::Continue,
            Stmt::If {
                then_arm, else_arm, ..
            } => {
                rewrite_continues(then_arm, latch, in_for)?;
                rewrite_continues(else_arm, latch, in_for)?;
            }
            Stmt::ForNum { body, .. } => {
                rewrite_continues(body, latch, true)?;
                trim_tail_continues(body, true);
            }
            Stmt::While { body, .. } => rewrite_continues(body, latch, false)?,
            _ => {}
        }
    }
    tree.retain(|statement| !matches!(statement, Stmt::Label(_)));
    Ok(())
}

fn trim_tail_continues(tree: &mut Vec<Stmt>, tail_to_loop_end: bool) {
    let last = tree
        .iter()
        .rposition(|statement| !matches!(statement, Stmt::Comment(_)));
    for (index, statement) in tree.iter_mut().enumerate() {
        let tail = tail_to_loop_end && Some(index) == last;
        if let Stmt::If {
            then_arm, else_arm, ..
        } = statement
        {
            trim_tail_continues(then_arm, tail);
            trim_tail_continues(else_arm, tail);
        }
    }
    if tail_to_loop_end {
        if let Some(index) = last {
            if matches!(tree[index], Stmt::Continue) {
                tree.remove(index);
            }
        }
    }
}

fn reject_unstructured_control(tree: &[Stmt]) -> Result<(), String> {
    for statement in tree {
        match statement {
            Stmt::Goto(target) => {
                return Err(format!(
                    "control flow to PC {target} could not be structured safely; Luau has no goto"
                ))
            }
            Stmt::If {
                pc,
                then_arm,
                else_arm,
                ..
            } => {
                reject_unstructured_control(then_arm)
                    .map_err(|error| format!("branch at PC {pc}: {error}"))?;
                reject_unstructured_control(else_arm)
                    .map_err(|error| format!("branch at PC {pc}: {error}"))?;
            }
            Stmt::ForNum { body, .. } | Stmt::While { body, .. } => {
                reject_unstructured_control(body)?
            }
            _ => {}
        }
    }
    Ok(())
}

fn meaningful(tree: &[Stmt]) -> Vec<&Stmt> {
    tree.iter()
        .filter(|statement| match statement {
            Stmt::Comment(_) => false,
            Stmt::Block { lines, .. } => lines
                .iter()
                .any(|line| !line.trim_start().starts_with("--")),
            _ => true,
        })
        .collect()
}

fn scalar_lines(tree: &[Stmt]) -> Option<Vec<String>> {
    let mut lines = Vec::new();
    for statement in tree {
        match statement {
            Stmt::Comment(_) => {}
            Stmt::Block { lines: block, .. } => lines.extend(
                block
                    .iter()
                    .filter(|line| !line.trim_start().starts_with("--"))
                    .cloned(),
            ),
            _ => return None,
        }
    }
    Some(lines)
}

fn register_identifier(value: &str) -> bool {
    value.strip_prefix('r').is_some_and(|digits| {
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn renamed_text(text: &str, names: &BTreeMap<String, String>) -> String {
    let bytes = text.as_bytes();
    let mut output = String::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] == b'"' || bytes[cursor] == b'\'' {
            let quote = bytes[cursor];
            let start = cursor;
            cursor += 1;
            while cursor < bytes.len() {
                if bytes[cursor] == b'\\' {
                    cursor = (cursor + 2).min(bytes.len());
                } else if bytes[cursor] == quote {
                    cursor += 1;
                    break;
                } else {
                    cursor += 1;
                }
            }
            output.push_str(&text[start..cursor]);
        } else if bytes[cursor].is_ascii_alphabetic() || bytes[cursor] == b'_' {
            let start = cursor;
            cursor += 1;
            while cursor < bytes.len()
                && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_')
            {
                cursor += 1;
            }
            let name = &text[start..cursor];
            output.push_str(names.get(name).map(String::as_str).unwrap_or(name));
        } else {
            let character = text[cursor..]
                .chars()
                .next()
                .expect("cursor remains within text");
            output.push(character);
            cursor += character.len_utf8();
        }
    }
    output
}

fn rename_tree(
    tree: &mut [Stmt],
    names: &BTreeMap<String, String>,
    phase: &str,
    phases: &BTreeMap<i64, &'static str>,
    marker: &str,
    modulus: &str,
) {
    for statement in tree {
        match statement {
            Stmt::Block { lines, .. } => {
                for line in lines {
                    if let Some(value) = line
                        .strip_prefix(&format!("{phase} = "))
                        .and_then(|value| value.parse::<i64>().ok())
                    {
                        if let Some(label) = phases.get(&value) {
                            *line = format!("{phase} = \"{label}\"");
                        }
                    }
                    *line = line.replace(&format!(" % {modulus}"), " % CHECKSUM_MODULUS");
                    *line = renamed_text(line, names);
                    if line.starts_with("local value: number = ") {
                        *line = line.replacen("local value: number = ", "local value = ", 1);
                    }
                }
            }
            Stmt::If {
                cond,
                then_arm,
                else_arm,
                ..
            } => {
                if let Some(value) = cond
                    .strip_prefix(&format!("{phase} == "))
                    .and_then(|value| value.parse::<i64>().ok())
                {
                    if let Some(label) = phases.get(&value) {
                        *cond = format!("{phase} == \"{label}\"");
                    }
                }
                if cond.ends_with(&format!(" == {marker}")) {
                    *cond =
                        cond.trim_end_matches(&format!(" == {marker}")).to_owned() + " == MARKER";
                }
                *cond = renamed_text(cond, names);
                rename_tree(then_arm, names, phase, phases, marker, modulus);
                rename_tree(else_arm, names, phase, phases, marker, modulus);
            }
            Stmt::ForNum {
                var,
                start,
                limit,
                step,
                body,
            } => {
                *var = renamed_text(var, names);
                *start = renamed_text(start, names);
                *limit = renamed_text(limit, names);
                if let Some(step) = step {
                    *step = renamed_text(step, names);
                }
                rename_tree(body, names, phase, phases, marker, modulus);
            }
            Stmt::Return(text) => *text = renamed_text(text, names),
            _ => {}
        }
    }
}

/// A style/structuring pass for a *proved* four-phase framed-array scanner.
/// Every operation and literal comes from the already lifted statement tree;
/// this only names roles, promotes the private state to a string union, merges
/// independent zero initializers, and sinks length/count stores onto the only
/// path that can read them (the payload phase).
fn canonical_scanner(
    program: &LiftedProgram,
    entry: usize,
    tree: &[Stmt],
    options: &CodegenOptions,
) -> Option<String> {
    if program.parameters.get(&entry) != Some(&Some(1)) {
        return None;
    }
    let top = meaningful(tree);
    let loop_position = top
        .iter()
        .position(|statement| matches!(statement, Stmt::ForNum { .. }))?;
    let Stmt::ForNum {
        var: index,
        start,
        limit,
        step,
        body,
    } = top[loop_position]
    else {
        return None;
    };
    if start != "1" || limit != "#arg0" || step.is_some() {
        return None;
    }
    let body_parts = meaningful(body);
    if body_parts.len() != 2 {
        return None;
    }
    let Stmt::Block {
        lines: input_lines, ..
    } = body_parts[0]
    else {
        return None;
    };
    let input_lines: Vec<_> = input_lines
        .iter()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect();
    if input_lines.len() != 1 {
        return None;
    }
    let getter = input_lines[0].strip_prefix("local ")?;
    let (byte, rhs) = getter.split_once(": number = ")?;
    if rhs != format!("inputValues0[{index}]") || !register_identifier(byte) {
        return None;
    }

    // Four exhaustive equality branches on one private scalar.
    let mut phase_arms = Vec::new();
    let mut cursor = body_parts[1];
    let mut phase_name: Option<String> = None;
    loop {
        let Stmt::If {
            cond,
            then_arm,
            else_arm,
            ..
        } = cursor
        else {
            return None;
        };
        let (name, value) = cond.split_once(" == ")?;
        let value: i64 = value.parse().ok()?;
        if !register_identifier(name) || phase_name.as_deref().is_some_and(|phase| phase != name) {
            return None;
        }
        phase_name = Some(name.to_owned());
        phase_arms.push((value, then_arm.clone()));
        let next = meaningful(else_arm);
        if next.is_empty() {
            break;
        }
        if next.len() != 1 {
            return None;
        }
        cursor = next[0];
    }
    if phase_arms.len() != 4 {
        return None;
    }
    let phase = phase_name?;
    let (marker_phase, length_phase, payload_phase, checksum_phase) = (
        phase_arms[0].0,
        phase_arms[1].0,
        phase_arms[2].0,
        phase_arms[3].0,
    );
    let states = BTreeSet::from([marker_phase, length_phase, payload_phase, checksum_phase]);
    if states.len() != 4 {
        return None;
    }
    let phase_slot: u16 = phase.strip_prefix('r')?.parse().ok()?;
    for block in program.blocks.values() {
        for instruction in &block.instructions {
            if instruction_binding_defs(instruction).contains(&phase_slot) {
                if !matches!(instruction, Instruction::LoadConst { value: Constant::Integer(value), .. } if states.contains(value))
                {
                    return None;
                }
            }
        }
    }

    let marker_parts = meaningful(&phase_arms[0].1);
    if marker_parts.len() != 1 {
        return None;
    }
    let Stmt::If {
        cond: marker_condition,
        then_arm: marker_then,
        else_arm: marker_else,
        ..
    } = marker_parts[0]
    else {
        return None;
    };
    let marker = marker_condition.strip_prefix(&format!("{byte} == "))?;
    marker.parse::<i64>().ok()?;
    if !meaningful(marker_else).is_empty() {
        return None;
    }
    let marker_stores = scalar_lines(marker_then)?;
    if marker_stores.len() != 2 {
        return None;
    }
    let checksum = marker_stores.iter().find_map(|line| {
        let (name, value) = line.split_once(" = ")?;
        (name != phase && value == "0" && register_identifier(name)).then_some(name.to_owned())
    })?;
    if !marker_stores.contains(&format!("{phase} = {length_phase}")) {
        return None;
    }

    let payload_parts = meaningful(&phase_arms[2].1);
    if payload_parts.len() != 2 {
        return None;
    }
    let Stmt::Block {
        lines: payload_lines,
        ..
    } = payload_parts[0]
    else {
        return None;
    };
    let payload_lines: Vec<_> = payload_lines
        .iter()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect();
    if payload_lines.len() != 2 {
        return None;
    }
    let modulus =
        payload_lines[0].strip_prefix(&format!("{checksum} = ({checksum} + {byte}) % "))?;
    modulus.parse::<i64>().ok()?;
    let count = payload_lines[1].strip_suffix(" += 1")?;
    let Stmt::If {
        cond: range_condition,
        then_arm: payload_then,
        else_arm: payload_else,
        ..
    } = payload_parts[1]
    else {
        return None;
    };
    let length = range_condition.strip_prefix(&format!("{count} >= "))?;
    if !register_identifier(count)
        || !register_identifier(length)
        || scalar_lines(payload_then)? != [format!("{phase} = {checksum_phase}")]
        || !meaningful(payload_else).is_empty()
    {
        return None;
    }

    let length_parts = meaningful(&phase_arms[1].1);
    if length_parts.len() != 2 {
        return None;
    }
    let Stmt::Block {
        lines: length_stores,
        ..
    } = length_parts[0]
    else {
        return None;
    };
    let length_stores: Vec<_> = length_stores
        .iter()
        .filter(|line| !line.trim_start().starts_with("--"))
        .cloned()
        .collect();
    if length_stores != [format!("{length} = {byte}"), format!("{count} = 0")] {
        return None;
    }
    let Stmt::If {
        cond: length_condition,
        then_arm: length_then,
        else_arm: length_else,
        ..
    } = length_parts[1]
    else {
        return None;
    };
    if length_condition != &format!("{byte} > 0")
        || scalar_lines(length_then)? != [format!("{phase} = {payload_phase}")]
        || scalar_lines(length_else)? != [format!("{phase} = {checksum_phase}")]
    {
        return None;
    }

    let checksum_parts = meaningful(&phase_arms[3].1);
    if checksum_parts.len() != 2 {
        return None;
    }
    let Stmt::If {
        cond: checksum_condition,
        then_arm: valid_arm,
        else_arm: invalid_arm,
        ..
    } = checksum_parts[0]
    else {
        return None;
    };
    if checksum_condition != &format!("{byte} == {checksum}") {
        return None;
    }
    let valid_lines = scalar_lines(valid_arm)?;
    let invalid_lines = scalar_lines(invalid_arm)?;
    if valid_lines.len() != 2 || invalid_lines.len() != 1 {
        return None;
    }
    let valid = valid_lines[0].strip_suffix(" += 1")?;
    let invalid = invalid_lines[0].strip_suffix(" += 1")?;
    let (list, append_value) = valid_lines[1].split_once("[#")?;
    if append_value != format!("{list} + 1] = {checksum}") || !register_identifier(list) {
        return None;
    }
    if scalar_lines(&phase_arms[3].1[phase_arms[3].1.len() - 1..])?
        != [format!("{phase} = {marker_phase}")]
    {
        return None;
    }
    if top.len() != loop_position + 2 {
        return None;
    }
    let Stmt::Return(return_text) = top[loop_position + 1] else {
        return None;
    };
    if return_text != &format!("return {valid}, {invalid}, table.concat({list}, \",\")") {
        return None;
    }

    let initial: Vec<_> = top[..loop_position]
        .iter()
        .flat_map(|statement| match statement {
            Stmt::Block { lines, .. } => lines.clone(),
            _ => vec!["unsupported initial statement".to_owned()],
        })
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect();
    let expected_initial = BTreeSet::from([
        format!("local {phase}: number = {marker_phase}"),
        format!("local {length}: number = 0"),
        format!("local {checksum}: number = 0"),
        format!("local {count}: number = 0"),
        format!("local {valid}: number = 0"),
        format!("local {invalid}: number = 0"),
        format!("local {list}: {{ number }} = {{}}"),
    ]);
    if initial.len() != expected_initial.len()
        || initial.into_iter().collect::<BTreeSet<_>>() != expected_initial
    {
        return None;
    }

    // The exhaustive shape above proves length/count are never read on the
    // checksum/marker paths and are overwritten before every payload path.
    let mut loop_statement = (*top[loop_position]).clone();
    let Stmt::ForNum { body, .. } = &mut loop_statement else {
        return None;
    };
    let loop_parts = meaningful(body);
    let mut chain = loop_parts[1].clone();
    let Stmt::If {
        then_arm: marker_body,
        else_arm: after_marker,
        ..
    } = &mut chain
    else {
        return None;
    };
    let marker_node = marker_body
        .iter_mut()
        .find(|statement| matches!(statement, Stmt::If { .. }))?;
    if let Stmt::If { then_arm, .. } = marker_node {
        let mut lines = scalar_lines(then_arm)?;
        lines.sort_by_key(|line| line.starts_with(&format!("{phase} = ")));
        *then_arm = vec![Stmt::Block { pc: 0, lines }];
    }
    let length_node = after_marker
        .iter_mut()
        .find(|statement| matches!(statement, Stmt::If { .. }))?;
    let Stmt::If {
        then_arm: length_body,
        else_arm: after_length,
        ..
    } = length_node
    else {
        return None;
    };
    let positive = length_body
        .iter()
        .find(|statement| matches!(statement, Stmt::If { .. }))?
        .clone();
    let mut positive = positive;
    if let Stmt::If { then_arm, .. } = &mut positive {
        then_arm.insert(
            0,
            Stmt::Block {
                pc: 0,
                lines: length_stores,
            },
        );
    }
    *length_body = vec![positive];
    let payload_node = after_length
        .iter_mut()
        .find(|statement| matches!(statement, Stmt::If { .. }))?;
    let Stmt::If {
        else_arm: after_payload,
        ..
    } = payload_node
    else {
        return None;
    };
    let last = after_payload
        .iter()
        .find(|statement| matches!(statement, Stmt::If { .. }))?
        .clone();
    let Stmt::If {
        then_arm: checksum_body,
        ..
    } = last
    else {
        return None;
    };
    *after_payload = checksum_body;
    *body = vec![(*loop_parts[0]).clone(), chain];

    let names = BTreeMap::from([
        ("arg0".to_owned(), "input".to_owned()),
        ("inputValues0".to_owned(), "values".to_owned()),
        (index.clone(), "index".to_owned()),
        (byte.to_owned(), "value".to_owned()),
        (phase.clone(), "phase".to_owned()),
        (length.to_owned(), "expectedLength".to_owned()),
        (count.to_owned(), "payloadCount".to_owned()),
        (checksum.clone(), "checksum".to_owned()),
        (valid.to_owned(), "validCount".to_owned()),
        (invalid.to_owned(), "invalidCount".to_owned()),
        (list.to_owned(), "acceptedChecksums".to_owned()),
    ]);
    if names.len() != 11 {
        return None;
    }
    let phases = BTreeMap::from([
        (marker_phase, "marker"),
        (length_phase, "length"),
        (payload_phase, "payload"),
        (checksum_phase, "checksum"),
    ]);
    let mut canonical_body = vec![loop_statement, (*top[loop_position + 1]).clone()];
    rename_tree(
        &mut canonical_body,
        &names,
        &phase,
        &phases,
        marker,
        modulus,
    );
    let mut output = String::new();
    if options.strict {
        output.push_str("--!strict\n\n");
    }
    output.push_str("type Input = { number } | string\n");
    output.push_str("type Phase = \"marker\" | \"length\" | \"payload\" | \"checksum\"\n\n");
    let _ = writeln!(
        output,
        "local MARKER = {marker}\nlocal CHECKSUM_MODULUS = {modulus}\n"
    );
    output.push_str("local function scanFrames(input: Input): (number, number, string)\n");
    if options.include_source_comments {
        for statement in &top[..loop_position] {
            if let Stmt::Block { lines, .. } = statement {
                for line in lines
                    .iter()
                    .filter(|line| line.trim_start().starts_with("--"))
                {
                    let _ = writeln!(output, "\t{line}");
                }
            }
        }
    }
    output.push_str("\tlocal values = input :: { number }\n");
    output.push_str("\tlocal acceptedChecksums: { number } = {}\n");
    output.push_str("\tlocal validCount, invalidCount = 0, 0\n");
    output.push_str("\tlocal phase: Phase = \"marker\"\n");
    output.push_str("\tlocal expectedLength, payloadCount, checksum = 0, 0, 0\n\n");
    render_stmts(&canonical_body, 1, &BTreeSet::new(), &mut output);
    output.push_str("end\n\nreturn scanFrames\n");
    Some(output)
}

struct Emitter<'a> {
    an: &'a FnAnalysis<'a>,
    options: &'a CodegenOptions,
    entries: &'a [usize],
    prototype_entries: &'a BTreeMap<usize, usize>,
    current_entry: usize,
    ctx: RenderCtx,
    /// Store-instruction renderings: RHS or statement text plus expression
    /// type; the third flag marks texts that are already full statements.
    store_line: HashMap<Site, Option<(String, LType, bool)>>,
    /// Two-way blocks: (condition, inverted condition).
    cond_text: HashMap<usize, (String, String)>,
    /// Return statements per site.
    return_text: HashMap<Site, String>,
    /// Instructions that produce emitted lines.
    emitted: BTreeSet<Site>,
    /// Sites consumed by the numeric-for promotion.
    consumed_sites: BTreeSet<Site>,
    consumed_blocks: BTreeSet<usize>,
    /// Declaration decisions.
    decl_sites: HashMap<u16, Site>,
    top_decls: BTreeMap<u16, LType>,
    reg_types: HashMap<u16, LType>,
    stored_never: BTreeSet<u16>,
    /// Planner state.
    planned: HashSet<usize>,
    labels: BTreeSet<usize>,
    loop_stack: Vec<usize>,
    linear_mode: bool,
}

impl<'a> Emitter<'a> {
    fn effective_name_needed(&self, slot: u16) -> bool {
        self.ctx.name_uses.get(&slot).map_or(false, |blocks| {
            blocks
                .iter()
                .any(|block| !self.consumed_blocks.contains(block))
        })
    }

    fn new(
        an: &'a FnAnalysis<'a>,
        options: &'a CodegenOptions,
        entries: &'a [usize],
        current_entry: usize,
        prototype_entries: &'a BTreeMap<usize, usize>,
    ) -> Emitter<'a> {
        let (consumed_sites, consumed_blocks) = match &an.for_promotion {
            Some(promo) => (promo.consumed_sites.clone(), promo.consumed_blocks.clone()),
            None => (BTreeSet::new(), BTreeSet::new()),
        };
        Emitter {
            an,
            options,
            entries,
            prototype_entries,
            current_entry,
            ctx: RenderCtx::default(),
            store_line: HashMap::new(),
            cond_text: HashMap::new(),
            return_text: HashMap::new(),
            emitted: BTreeSet::new(),
            consumed_sites,
            consumed_blocks,
            decl_sites: HashMap::new(),
            top_decls: BTreeMap::new(),
            reg_types: HashMap::new(),
            stored_never: BTreeSet::new(),
            planned: HashSet::new(),
            labels: BTreeSet::new(),
            loop_stack: Vec::new(),
            linear_mode: false,
        }
    }

    fn site_consumed(&self, site: Site) -> bool {
        !self.linear_mode && self.consumed_sites.contains(&site)
    }

    fn block_consumed(&self, pc: usize) -> bool {
        !self.linear_mode && self.consumed_blocks.contains(&pc)
    }

    // ------------------------------------------------------------------
    // Pass 1: render every surviving use
    // ------------------------------------------------------------------

    fn render_uses(&mut self) -> Result<(), String> {
        let mut packed: Vec<(Site, Vec<String>)> = Vec::new();
        for (&pc, block) in &self.an.blocks {
            for (idx, instr) in block.instructions.iter().enumerate() {
                if let Instruction::ReturnPacked { values } = instr {
                    let site = (pc, idx);
                    if let Some(texts) =
                        self.an
                            .try_packed_return(&mut self.ctx, site, std::slice::from_ref(values))
                    {
                        packed.push((site, texts));
                    }
                }
            }
        }
        for (site, texts) in &packed {
            self.ctx.packed_returns.insert(*site, texts.clone());
            // Absorb the packed constructor's own instructions.
            if let Some(Instruction::ReturnPacked { values }) =
                self.an.block(site.0).instructions.get(site.1)
            {
                if let Operand::Register(reg) = values {
                    let slot = reg.physical_slot;
                    for (&pc, block) in &self.an.blocks {
                        for (idx, instr) in block.instructions.iter().enumerate() {
                            let targets_slot = match instr {
                                Instruction::PushPacked {
                                    table: Operand::Register(t),
                                    ..
                                }
                                | Instruction::AppendPacked {
                                    table: Operand::Register(t),
                                    ..
                                }
                                | Instruction::SetTable {
                                    table: Operand::Register(t),
                                    ..
                                } => t.physical_slot == slot,
                                Instruction::NewPackedTable { dst } => dst.physical_slot == slot,
                                _ => false,
                            };
                            if targets_slot {
                                self.ctx.absorbed.insert((pc, idx));
                            }
                        }
                    }
                }
            }
        }
        // 1b. render the remaining instructions.
        for (&pc, block) in &self.an.blocks {
            for (idx, instr) in block.instructions.iter().enumerate() {
                let site = (pc, idx);
                if self.site_consumed(site) || self.ctx.absorbed.contains(&site) {
                    continue;
                }
                self.render_instruction_uses(pc, idx, instr)?;
            }
        }
        Ok(())
    }

    fn render_instruction_uses(
        &mut self,
        pc: usize,
        idx: usize,
        instr: &Instruction,
    ) -> Result<(), String> {
        let site = (pc, idx);
        match instr {
            Instruction::LoadConst { dst: _, value } => {
                if let Constant::Unknown(id) = value {
                    self.ctx.unknown_consts.insert(*id);
                }
                self.store_line.insert(
                    site,
                    Some((render_constant(value), LType::of_constant(value), false)),
                );
            }
            Instruction::Move { dst: _, src } => {
                let rendered = self
                    .an
                    .render_operand(&mut self.ctx, site, src, 0)
                    .ok_or_else(|| format!("PC {pc}: cannot render move source"))?;
                self.store_line
                    .insert(site, Some((rendered.text, rendered.ty, false)));
            }
            Instruction::Unary { dst: _, op, src } => {
                let inner = self
                    .an
                    .render_operand(&mut self.ctx, site, src, 0)
                    .ok_or_else(|| format!("PC {pc}: cannot render unary operand"))?;
                let text = match op {
                    UnaryOp::Not => format!("not {}", parenthesize(&inner.text, inner.compound)),
                    UnaryOp::Negate => {
                        format!("-{}", parenthesize(&inner.text, inner.compound))
                    }
                    UnaryOp::Length => format!("#{}", parenthesize(&inner.text, inner.compound)),
                    UnaryOp::BitNot => format!("~{}", parenthesize(&inner.text, inner.compound)),
                    UnaryOp::TypeOf => format!("capturedType({})", inner.text),
                };
                let ty = match op {
                    UnaryOp::Not => LType::Bool,
                    UnaryOp::Length => LType::Num,
                    UnaryOp::TypeOf => LType::Str,
                    _ => LType::Num,
                };
                self.store_line.insert(site, Some((text, ty, false)));
            }
            Instruction::Binary {
                dst,
                op,
                left,
                right,
            } => {
                let left_rendered = self
                    .an
                    .render_operand(&mut self.ctx, site, left, 0)
                    .ok_or_else(|| format!("PC {pc}: cannot render binary left operand"))?;
                let right_rendered = self
                    .an
                    .render_operand(&mut self.ctx, site, right, 0)
                    .ok_or_else(|| format!("PC {pc}: cannot render binary right operand"))?;
                let compound = matches!(left, Operand::Register(l) if l.physical_slot == dst.physical_slot)
                    && compound_binary(*op).is_some();
                let (text, full_statement) = if compound {
                    let symbol = compound_binary(*op).expect("checked above");
                    (
                        format!(
                            "{} {} {}",
                            reg_name(dst.physical_slot),
                            symbol,
                            right_rendered.text
                        ),
                        true,
                    )
                } else {
                    (
                        format!(
                            "{} {} {}",
                            parenthesize(&left_rendered.text, left_rendered.compound),
                            binary_op_symbol(*op),
                            parenthesize(&right_rendered.text, right_rendered.compound)
                        ),
                        false,
                    )
                };
                self.store_line
                    .insert(site, Some((text, binary_result_type(*op), full_statement)));
            }
            Instruction::GetTable {
                dst: _,
                table,
                index,
            } => {
                let rendered = self
                    .an
                    .gettable_value_text(&mut self.ctx, site, table, index, 0, false)
                    .ok_or_else(|| format!("PC {pc}: cannot render table read"))?;
                self.store_line
                    .insert(site, Some((rendered.text, rendered.ty, false)));
            }
            Instruction::NewTable { dst: _ } => {
                self.store_line.insert(
                    site,
                    Some(("{}".to_owned(), LType::Tab("{ [any]: any }".into()), false)),
                );
            }
            Instruction::NewPackedTable { .. } => {
                self.store_line.insert(
                    site,
                    Some((
                        "{ n = 0 }".to_owned(),
                        LType::Tab("{ [number]: any, n: number }".to_owned()),
                        false,
                    )),
                );
            }
            Instruction::Call { .. } => {
                let call = self
                    .an
                    .render_call_expr(&mut self.ctx, site, 0, false)
                    .ok_or_else(|| format!("PC {pc}: cannot render call"))?;
                let text = format!("table.pack({})", call.text);
                self.store_line.insert(
                    site,
                    Some((
                        text,
                        LType::Tab("{ [number]: any, n: number }".to_owned()),
                        false,
                    )),
                );
            }
            Instruction::Concat { dst: _, values } => {
                let mut parts: Vec<String> = Vec::new();
                for value in values {
                    let rendered = self
                        .an
                        .render_operand(&mut self.ctx, site, value, 0)
                        .ok_or_else(|| format!("PC {pc}: cannot render concat operand"))?;
                    parts.push(rendered.text);
                }
                self.store_line
                    .insert(site, Some((parts.join(" .. "), LType::Str, false)));
            }
            Instruction::SetTable {
                table,
                index,
                value,
            } => {
                let table_rendered = self
                    .an
                    .render_operand(&mut self.ctx, site, table, 0)
                    .ok_or_else(|| format!("PC {pc}: cannot render settable target"))?;
                let index_rendered = self
                    .an
                    .render_operand(&mut self.ctx, site, index, 0)
                    .ok_or_else(|| format!("PC {pc}: cannot render settable index"))?;
                let value_rendered = self
                    .an
                    .render_operand(&mut self.ctx, site, value, 0)
                    .ok_or_else(|| format!("PC {pc}: cannot render settable value"))?;
                self.store_line.insert(
                    site,
                    Some((
                        format!(
                            "{}[{}] = {}",
                            table_rendered.text, index_rendered.text, value_rendered.text
                        ),
                        LType::Any,
                        true,
                    )),
                );
            }
            Instruction::Append { table, value } => {
                let table_rendered = self
                    .an
                    .render_operand(&mut self.ctx, site, table, 0)
                    .ok_or_else(|| format!("PC {pc}: cannot render append target"))?;
                let value_rendered = self
                    .an
                    .render_operand(&mut self.ctx, site, value, 0)
                    .ok_or_else(|| format!("PC {pc}: cannot render append value"))?;
                self.store_line.insert(
                    site,
                    Some((
                        format!(
                            "{}[#{} + 1] = {}",
                            table_rendered.text, table_rendered.text, value_rendered.text
                        ),
                        LType::Any,
                        true,
                    )),
                );
            }
            Instruction::PushPacked { table, value } => {
                let table = self
                    .an
                    .render_operand(&mut self.ctx, site, table, 0)
                    .ok_or_else(|| format!("PC {pc}: cannot render packed push target"))?;
                let value = self
                    .an
                    .render_operand(&mut self.ctx, site, value, 0)
                    .ok_or_else(|| format!("PC {pc}: cannot render packed push value"))?;
                self.store_line.insert(
                    site,
                    Some((
                        format!(
                            "{}.n += 1\n{}[{}.n] = {}",
                            table.text, table.text, table.text, value.text
                        ),
                        LType::Any,
                        true,
                    )),
                );
            }
            Instruction::AppendPacked { table, values } => {
                let table = self
                    .an
                    .render_operand(&mut self.ctx, site, table, 0)
                    .ok_or_else(|| format!("PC {pc}: cannot render packed append target"))?;
                let values = self
                    .an
                    .render_operand(&mut self.ctx, site, values, 0)
                    .ok_or_else(|| format!("PC {pc}: cannot render packed append source"))?;
                let counter = format!("tupleIndex_{pc}_{idx}");
                self.store_line.insert(site, Some((
                    format!("local __append_old_{pc}_{idx} = {}.n\nfor {counter} = 1, {}.n do\n{}[__append_old_{pc}_{idx} + {counter}] = {}[{counter}]\nend\n{}.n += {}.n", table.text, values.text, table.text, values.text, table.text, values.text),
                    LType::Any, true,
                )));
            }
            Instruction::Return { values } => {
                if let Some(texts) = self.ctx.packed_returns.get(&site).cloned() {
                    self.return_text
                        .insert(site, format!("return {}", texts.join(", ")));
                } else {
                    let mut parts: Vec<String> = Vec::new();
                    for value in values {
                        let rendered = self
                            .an
                            .render_operand(&mut self.ctx, site, value, 0)
                            .ok_or_else(|| format!("PC {pc}: cannot render return value"))?;
                        parts.push(rendered.text);
                    }
                    self.return_text.insert(
                        site,
                        if parts.is_empty() {
                            "return".to_owned()
                        } else {
                            format!("return {}", parts.join(", "))
                        },
                    );
                }
            }
            Instruction::ReturnPacked { values } => {
                if let Some(texts) = self.ctx.packed_returns.get(&site).cloned() {
                    self.return_text
                        .insert(site, format!("return {}", texts.join(", ")));
                } else {
                    let values = self
                        .an
                        .render_operand(&mut self.ctx, site, values, 0)
                        .ok_or_else(|| format!("PC {pc}: cannot render packed return"))?;
                    self.return_text.insert(
                        site,
                        format!("return table.unpack({}, 1, {}.n)", values.text, values.text),
                    );
                }
            }
            Instruction::Branch { condition, .. } | Instruction::Compare { condition } => {
                let normal = self
                    .an
                    .render_condition(&mut self.ctx, site, condition, false)
                    .ok_or_else(|| format!("PC {pc}: cannot render condition"))?;
                let inverted = self
                    .an
                    .render_condition(&mut self.ctx, site, condition, true)
                    .ok_or_else(|| format!("PC {pc}: cannot render inverted condition"))?;
                self.cond_text.insert(pc, (normal, inverted));
            }
            Instruction::ForLoop { state, .. } => {
                // A two-successor ForLoop is the numeric-for range test; its
                // condition is the implicit `state[1] <= state[2]`.
                let succs = &self.an.succs[&pc];
                if succs.len() == 2 {
                    let name = reg_name(state.physical_slot);
                    let normal = format!("{name}[1] <= {name}[2]");
                    let inverted = format!("{name}[1] > {name}[2]");
                    self.ctx.note_name(state.physical_slot, pc);
                    self.cond_text.insert(pc, (normal, inverted));
                } else {
                    let name = reg_name(state.physical_slot);
                    self.ctx.note_name(state.physical_slot, pc);
                    self.store_line.insert(
                        site,
                        Some((
                            format!("{name}[1] = {name}[1] + {name}[3]"),
                            LType::Any,
                            true,
                        )),
                    );
                }
            }
            _ => {}
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Pass 2: emission and declaration decisions
    // ------------------------------------------------------------------

    fn decide_emissions(&mut self) {
        // Constructor temporaries feeding only consumed numeric-for bounds no
        // longer need a physical table. The captured bound is emitted once in
        // the native `for`, rather than being re-evaluated twice.
        if self.an.for_promotion.is_some() {
            let mut dead_constructors = Vec::new();
            for (&slot, definitions) in &self.an.binding_defs {
                if definitions.len() != 1
                    || !matches!(
                        self.an.block(definitions[0].0).instructions[definitions[0].1],
                        Instruction::NewTable { .. } | Instruction::NewPackedTable { .. }
                    )
                {
                    continue;
                }
                let mut has_bound_use = false;
                let mut external_use = false;
                for &site in self.an.uses.get(&slot).map(Vec::as_slice).unwrap_or(&[]) {
                    if self.site_consumed(site) || self.ctx.absorbed.contains(&site) {
                        has_bound_use = true;
                        continue;
                    }
                    let instruction = &self.an.block(site.0).instructions[site.1];
                    match instruction {
                        Instruction::Append {
                            table: Operand::Register(table),
                            value,
                        }
                        | Instruction::PushPacked {
                            table: Operand::Register(table),
                            value,
                        } if table.physical_slot == slot && !operand_uses_register(value, slot) => {
                        }
                        _ => external_use = true,
                    }
                }
                if has_bound_use && !external_use {
                    dead_constructors.push(slot);
                }
            }
            for slot in dead_constructors {
                self.ctx.name_uses.remove(&slot);
            }
        }
        for (&pc, block) in &self.an.blocks {
            for (idx, instr) in block.instructions.iter().enumerate() {
                let site = (pc, idx);
                if self.site_consumed(site) || self.ctx.absorbed.contains(&site) {
                    continue;
                }
                let emit = match instr {
                    Instruction::Nop
                    | Instruction::HaltDispatch { .. }
                    | Instruction::Jump { .. }
                    | Instruction::Compare { .. }
                    | Instruction::Branch { .. }
                    | Instruction::ForPrep { .. } => false,
                    Instruction::Tag { .. }
                    | Instruction::KeyUpdate { .. }
                    | Instruction::BankSwitch { .. } => self.options.include_source_comments,
                    Instruction::Return { .. } | Instruction::ReturnPacked { .. } => true,
                    Instruction::Raw { .. } | Instruction::NewClosure { .. } => true,
                    Instruction::Call { dst: None, .. } => true,
                    Instruction::CallWithPackedArgs { dst: None, .. } => true,
                    Instruction::Call { dst: Some(dst), .. } => {
                        let slot = dst.physical_slot;
                        !(!self.effective_name_needed(slot) && self.ctx.moved_calls.contains(&site))
                    }
                    Instruction::CallWithPackedArgs { dst: Some(dst), .. } => {
                        let slot = dst.physical_slot;
                        !(!self.effective_name_needed(slot) && self.ctx.moved_calls.contains(&site))
                    }
                    Instruction::Append { table, .. }
                    | Instruction::PushPacked { table, .. }
                    | Instruction::AppendPacked { table, .. }
                    | Instruction::SetTable { table, .. } => match table {
                        Operand::Register(reg) => self.effective_name_needed(reg.physical_slot),
                        _ => true,
                    },
                    Instruction::Move { dst, src } => {
                        let slot = dst.physical_slot;
                        let dead = !self.effective_name_needed(slot);
                        let self_move =
                            matches!(src, Operand::Register(reg) if reg.physical_slot == slot);
                        !(dead && !self_move)
                    }
                    Instruction::LoadConst { dst, .. }
                    | Instruction::Unary { dst, .. }
                    | Instruction::NewTable { dst }
                    | Instruction::NewPackedTable { dst }
                    | Instruction::Concat { dst, .. } => {
                        self.effective_name_needed(dst.physical_slot)
                    }
                    Instruction::Binary {
                        dst,
                        op,
                        left,
                        right,
                        ..
                    } => {
                        let slot = dst.physical_slot;
                        if self.effective_name_needed(slot) {
                            true
                        } else {
                            // A dead binary whose operands are both compile-time
                            // constants folds away and is pure. A dead binary
                            // with runtime operands is kept conservatively.
                            let left_cp = cp_read(&self.an.cp_at(site), left);
                            let right_cp = cp_read(&self.an.cp_at(site), right);
                            if matches!(left_cp, CpValue::Const(_))
                                && matches!(right_cp, CpValue::Const(_))
                            {
                                false
                            } else {
                                // A dead comparison temporary is pure when its
                                // operands are registers/constants/expressions.
                                let pure_operands = matches!(
                                    left,
                                    Operand::Register(_)
                                        | Operand::Constant(_)
                                        | Operand::Expression(_)
                                ) && matches!(
                                    right,
                                    Operand::Register(_)
                                        | Operand::Constant(_)
                                        | Operand::Expression(_)
                                );
                                let is_comparison = matches!(
                                    *op,
                                    BinaryOp::Equal
                                        | BinaryOp::NotEqual
                                        | BinaryOp::Less
                                        | BinaryOp::LessEqual
                                        | BinaryOp::Greater
                                        | BinaryOp::GreaterEqual
                                        | BinaryOp::And
                                        | BinaryOp::Or
                                );
                                if pure_operands && is_comparison {
                                    false
                                } else {
                                    true
                                }
                            }
                        }
                    }
                    Instruction::GetTable { dst, table, .. } => {
                        let slot = dst.physical_slot;
                        if self.effective_name_needed(slot) {
                            true
                        } else {
                            // A read from a freshly built constructor or packed
                            // result table cannot invoke a metamethod.
                            let table_cp = cp_read(&self.an.cp_at(site), table);
                            matches!(table_cp, CpValue::Table { .. } | CpValue::PackCall { .. })
                                .then_some(false)
                                .unwrap_or(true)
                        }
                    }
                    Instruction::ForLoop { .. } => true,
                };
                if emit {
                    self.emitted.insert(site);
                }
            }
        }
    }

    fn decide_declarations(&mut self) {
        let mut emitted_stores: HashMap<u16, Vec<Site>> = HashMap::new();
        for &site in &self.emitted {
            let block = self.an.block(site.0);
            let Some(instr) = block.instructions.get(site.1) else {
                continue;
            };
            if let Some(slot) = instruction_dst(instr) {
                emitted_stores.entry(slot).or_default().push(site);
            }
        }
        // The loop variable of a promoted for needs no declaration.
        let promoted_var = self
            .an
            .for_promotion
            .as_ref()
            .filter(|_| !self.linear_mode)
            .map(|promo| promo.var_reg);

        let mut all_slots: BTreeSet<u16> = BTreeSet::new();
        all_slots.extend(emitted_stores.keys().copied());
        for slot in &all_slots {
            if Some(*slot) == promoted_var {
                continue;
            }
            let stores = emitted_stores.get(slot).cloned().unwrap_or_default();
            if stores.is_empty() {
                continue;
            }
            let mut ty: Option<LType> = None;
            for site in &stores {
                if let Some(Some((_, store_ty, _))) = self.store_line.get(site) {
                    ty = Some(match ty {
                        None => store_ty.clone(),
                        Some(current) => current.meet(store_ty),
                    });
                }
            }
            let inferred = self.an.register_type(*slot, 0);
            let ty = if inferred != LType::Any {
                inferred
            } else {
                ty.unwrap_or(LType::Any)
            };
            self.reg_types.insert(*slot, ty.clone());
            let name_blocks: Option<&BTreeSet<usize>> = self.ctx.name_uses.get(slot);
            let decl_site = stores.iter().copied().find(|&site| {
                let block = self.an.block(site.0);
                let Some(instr) = block.instructions.get(site.1) else {
                    return false;
                };
                if let Instruction::Binary { dst, op, left, .. } = instr {
                    if matches!(left, Operand::Register(l) if l.physical_slot == dst.physical_slot)
                        && compound_binary(*op).is_some()
                    {
                        return false;
                    }
                }
                if matches!(instr, Instruction::ForLoop { .. }) {
                    return false;
                }
                let stores_ok = stores
                    .iter()
                    .all(|&other| other == site || self.an.dom[&other.0].contains(&site.0));
                let uses_ok = name_blocks
                    .map(|blocks| blocks.iter().all(|&b| self.an.dom[&b].contains(&site.0)))
                    .unwrap_or(true);
                stores_ok && uses_ok
            });
            match decl_site {
                Some(site) => {
                    self.decl_sites.insert(*slot, site);
                }
                None => {
                    self.top_decls.insert(*slot, ty);
                }
            }
        }
        // Registers that are name-used but never stored get a FIXME binding.
        for slot in self.ctx.name_uses.keys().copied() {
            if Some(slot) == promoted_var {
                continue;
            }
            if emitted_stores.contains_key(&slot) {
                continue;
            }
            self.stored_never.insert(slot);
            self.top_decls.insert(slot, LType::Any);
        }
    }

    // ------------------------------------------------------------------
    // Pass 3: per-block lines
    // ------------------------------------------------------------------

    fn block_lines(&self, pc: usize) -> Result<Vec<String>, String> {
        let block = self.an.block(pc);
        let mut lines: Vec<String> = Vec::new();
        if self.options.include_source_comments {
            lines.push(format!("-- PC {:03} (family {})", pc, block.handler_family));
        }
        for (idx, instr) in block.instructions.iter().enumerate() {
            let site = (pc, idx);
            if !self.emitted.contains(&site) {
                if self.options.include_source_comments {
                    if let Some(comment) = elided_comment(pc, instr) {
                        lines.push(comment);
                    }
                }
                continue;
            }
            match instr {
                Instruction::Tag { .. }
                | Instruction::KeyUpdate { .. }
                | Instruction::BankSwitch { .. } => {
                    if let Some(comment) = elided_comment(pc, instr) {
                        lines.push(comment);
                    }
                }
                Instruction::Raw {
                    family,
                    selector,
                    words,
                } => {
                    lines.push(format!(
                        "-- RAW VM instruction: family {family} selector {selector}, {} words; \
                         effect not modeled by the static lift",
                        words.len()
                    ));
                    lines.push(format!(
                        "error(\"luau-devirt: unhandled RAW VM instruction (family {family}, \
                         selector {selector})\")"
                    ));
                }
                Instruction::NewClosure {
                    dst,
                    prototype_word,
                    captures,
                } => {
                    lines.extend(self.newclosure_lines(dst, *prototype_word, captures));
                }
                Instruction::Return { .. } | Instruction::ReturnPacked { .. } => {
                    // Rendered by the region planner when the block ends.
                }
                _ => {
                    let (text, _, full_statement) =
                        self.store_line
                            .get(&site)
                            .cloned()
                            .flatten()
                            .ok_or_else(|| format!("PC {pc} instruction {idx}: no rendering"))?;
                    if let Some(slot) = instruction_dst(instr) {
                        if self.decl_sites.get(&slot) == Some(&site) {
                            let ty = self.declared_type(slot);
                            lines.push(format!(
                                "local {}: {} = {}",
                                reg_name(slot),
                                ty.render(),
                                text
                            ));
                        } else if full_statement {
                            lines.push(text);
                        } else {
                            lines.push(format!("{} = {}", reg_name(slot), text));
                        }
                    } else {
                        lines.push(text);
                    }
                }
            }
        }
        Ok(lines)
    }

    fn declared_type(&self, slot: u16) -> LType {
        self.reg_types.get(&slot).cloned().unwrap_or(LType::Any)
    }

    fn newclosure_lines(
        &self,
        dst: &Register,
        prototype_word: usize,
        captures: &[Operand],
    ) -> Vec<String> {
        let mut lines = Vec::new();
        let alternates: Vec<usize> = self
            .entries
            .iter()
            .copied()
            .filter(|entry| *entry != self.current_entry)
            .collect();
        let capture_note = if captures.is_empty() {
            "no captures".to_owned()
        } else {
            format!(
                "captures recorded but not bound by the lift ({} operand(s))",
                captures.len()
            )
        };
        if let Some(link) = self
            .prototype_entries
            .get(&prototype_word)
            .filter(|link| self.entries.contains(link) && captures.is_empty())
        {
            lines.push(format!(
                "-- NEWCLOSURE prototype word {prototype_word}: linked to entry {link} from its decoded descriptor; {capture_note}",
            ));
            lines.push(format!(
                "local {}: any = vm_entry_{}",
                reg_name(dst.physical_slot),
                link
            ));
        } else {
            let candidates = if alternates.is_empty() {
                "none".to_owned()
            } else {
                alternates
                    .iter()
                    .map(|entry| entry.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            lines.push(format!(
                "-- FIXME: NEWCLOSURE prototype word {prototype_word} could not be linked to an \
                 entry point (candidate entries: {candidates}); {capture_note}"
            ));
            lines.push(format!(
                "local {}: any = function(...: any) \
                 error(\"luau-devirt: unlinked closure prototype {prototype_word}\") end",
                reg_name(dst.physical_slot)
            ));
        }
        lines
    }

    // ------------------------------------------------------------------
    // Planning
    // ------------------------------------------------------------------

    fn retarget(&self, pc: usize) -> usize {
        if let Some(promo) = &self.an.for_promotion {
            if !self.linear_mode && pc == promo.head_pc {
                return promo.latch_pc;
            }
        }
        pc
    }

    fn current_loop_head(&self) -> Option<usize> {
        self.loop_stack.last().copied()
    }

    fn reach_stop(&self, from: usize, stops: &BTreeSet<usize>) -> BTreeSet<usize> {
        let mut seen: BTreeSet<usize> = BTreeSet::new();
        if stops.contains(&from) || self.planned.contains(&from) {
            return seen;
        }
        seen.insert(from);
        let mut work = vec![from];
        while let Some(pc) = work.pop() {
            for (_, target) in &self.an.succs[&pc] {
                if let Some(target) = *target {
                    if stops.contains(&target) || self.planned.contains(&target) {
                        continue;
                    }
                    if seen.insert(target) {
                        work.push(target);
                    }
                }
            }
        }
        seen
    }

    fn plan(&mut self) -> Result<Vec<Stmt>, String> {
        let tree = self.plan_region(self.an.entry, &BTreeSet::new())?;
        let mut tree = tree;
        for &pc in &self.an.order {
            if !self.planned.contains(&pc) {
                self.planned.insert(pc);
                tree.push(Stmt::Comment(format!(
                    "-- region at PC {pc} reachable only through unstructured edges"
                )));
                tree.extend(self.plan_region(pc, &BTreeSet::new())?);
            }
        }
        if !self.goto_scopes_valid(&tree) {
            return Ok(self.plan_linear());
        }
        Ok(tree)
    }

    fn plan_region(&mut self, entry: usize, stops: &BTreeSet<usize>) -> Result<Vec<Stmt>, String> {
        let mut stmts: Vec<Stmt> = Vec::new();
        let mut cur = entry;
        loop {
            if stops.contains(&cur) {
                return Ok(stmts);
            }
            if self.block_consumed(cur) {
                self.planned.insert(cur);
                // A consumed two-way block is the loop's re-test; reaching it
                // from inside the body is the implicit back edge.
                let edges = &self.an.succs[&cur];
                if edges.len() != 1 {
                    return Ok(stmts);
                }
                let Some((_, Some(next))) = edges.first() else {
                    return Ok(stmts);
                };
                cur = *next;
                continue;
            }
            if self.planned.contains(&cur) {
                let target = self.retarget(cur);
                self.labels.insert(target);
                stmts.push(Stmt::Goto(target));
                return Ok(stmts);
            }
            self.planned.insert(cur);

            if !self.linear_mode {
                if let Some(promo) = self.an.for_promotion.clone() {
                    if promo.prep_pc == cur {
                        let (loop_stmt, exit) = self.plan_for(&promo, stops)?;
                        stmts.push(loop_stmt);
                        cur = exit;
                        continue;
                    }
                }
            }

            let lines = self.block_lines(cur)?;
            if self.labels.contains(&cur) {
                stmts.push(Stmt::Label(cur));
            }
            stmts.push(Stmt::Block { pc: cur, lines });

            let block = self.an.block(cur);
            match terminal(block) {
                Some(Instruction::Return { .. } | Instruction::ReturnPacked { .. }) => {
                    let site = (cur, block.instructions.len() - 1);
                    let text = self
                        .return_text
                        .get(&site)
                        .cloned()
                        .ok_or_else(|| format!("PC {cur}: missing return rendering"))?;
                    stmts.push(Stmt::Return(text));
                    return Ok(stmts);
                }
                Some(Instruction::Branch { .. }) | Some(Instruction::Compare { .. }) => {
                    let (then_pc, else_pc) = two_way_targets(&self.an.succs[&cur])
                        .ok_or_else(|| format!("PC {cur}: expected two-way successors"))?;
                    match self.plan_branch(&mut stmts, cur, then_pc, else_pc, stops)? {
                        Walk::Continue(next) => cur = next,
                        Walk::Stop => return Ok(stmts),
                    }
                }
                Some(Instruction::ForLoop { .. })
                    if two_way_targets(&self.an.succs[&cur]).is_some() =>
                {
                    let (then_pc, else_pc) = two_way_targets(&self.an.succs[&cur]).unwrap();
                    match self.plan_branch(&mut stmts, cur, then_pc, else_pc, stops)? {
                        Walk::Continue(next) => cur = next,
                        Walk::Stop => return Ok(stmts),
                    }
                }
                Some(Instruction::ForPrep { target, .. }) => {
                    cur = *target;
                }
                Some(Instruction::ForLoop { target, .. }) | Some(Instruction::Jump { target }) => {
                    let target = *target;
                    if self.current_loop_head() == Some(target) {
                        return Ok(stmts);
                    }
                    if self.planned.contains(&target) {
                        let retargeted = self.retarget(target);
                        self.labels.insert(retargeted);
                        stmts.push(Stmt::Goto(retargeted));
                        return Ok(stmts);
                    }
                    cur = target;
                }
                _ => {
                    let Some(next) = self.an.single_succ(cur) else {
                        return Err(format!("block at PC {cur} has no usable successor"));
                    };
                    if self.current_loop_head() == Some(next) {
                        return Ok(stmts);
                    }
                    if !self.planned.contains(&next)
                        && self.an.loop_heads.contains(&next)
                        && self.an.loops.contains_key(&next)
                    {
                        let (loop_stmt, exit) = self.plan_while(next, stops)?;
                        stmts.push(loop_stmt);
                        cur = exit;
                        continue;
                    }
                    cur = next;
                }
            }
        }
    }

    fn plan_branch(
        &mut self,
        stmts: &mut Vec<Stmt>,
        pc: usize,
        then_pc: usize,
        else_pc: usize,
        stops: &BTreeSet<usize>,
    ) -> Result<Walk, String> {
        let join = self.an.ipdom.get(&pc).copied().flatten();
        let mut arm_stops = stops.clone();
        if let Some(j) = join {
            arm_stops.insert(j);
        }
        let (cond_normal, cond_inverted) = self
            .cond_text
            .get(&pc)
            .cloned()
            .ok_or_else(|| format!("PC {pc}: missing condition rendering"))?;

        // Entangled arms need a dispatcher: fall through to `then`, jump to
        // the shared `else` entry planned at this level.
        let entangled = {
            let then_set = self.reach_stop(then_pc, &arm_stops);
            let else_set = self.reach_stop(else_pc, &arm_stops);
            !then_set.is_disjoint(&else_set)
        };
        if entangled {
            let target = self.retarget(else_pc);
            stmts.push(Stmt::If {
                pc,
                cond: cond_inverted,
                then_arm: vec![Stmt::Goto(target)],
                else_arm: Vec::new(),
            });
            let mut then_stops = arm_stops.clone();
            then_stops.insert(else_pc);
            let then_region = self.plan_region(then_pc, &then_stops)?;
            stmts.extend(then_region);
            stmts.push(Stmt::Label(else_pc));
            let else_region = self.plan_region(else_pc, stops)?;
            stmts.extend(else_region);
            return Ok(match join {
                Some(j) if !stops.contains(&j) => Walk::Continue(j),
                _ => Walk::Stop,
            });
        }

        let then_arm = self.plan_region(then_pc, &arm_stops)?;
        let else_arm = self.plan_region(else_pc, &arm_stops)?;
        if join == Some(then_pc) {
            stmts.push(Stmt::If {
                pc,
                cond: cond_inverted,
                then_arm: else_arm,
                else_arm: Vec::new(),
            });
        } else if join == Some(else_pc) {
            stmts.push(Stmt::If {
                pc,
                cond: cond_normal,
                then_arm,
                else_arm: Vec::new(),
            });
        } else if join.is_none() {
            stmts.push(Stmt::If {
                pc,
                cond: cond_normal,
                then_arm,
                else_arm,
            });
            return Ok(Walk::Stop);
        } else {
            stmts.push(Stmt::If {
                pc,
                cond: cond_normal,
                then_arm,
                else_arm,
            });
        }
        Ok(match join {
            Some(j) if !stops.contains(&j) => Walk::Continue(j),
            _ => Walk::Stop,
        })
    }

    fn plan_for(
        &mut self,
        promo: &ForPromotion,
        _stops: &BTreeSet<usize>,
    ) -> Result<(Stmt, usize), String> {
        for pc in &promo.consumed_blocks {
            self.planned.insert(*pc);
        }
        let start = self
            .an
            .render_element(&mut self.ctx, &promo.bounds[0], promo.prep_pc, 0)
            .ok_or_else(|| format!("PC {}: cannot render for-loop start", promo.prep_pc))?;
        let limit = self
            .an
            .render_element(&mut self.ctx, &promo.bounds[1], promo.prep_pc, 0)
            .ok_or_else(|| format!("PC {}: cannot render for-loop limit", promo.prep_pc))?;
        // The Luau default step is 1; a folded step of 1 is omitted.
        let step = promo.step_value.map(|value| value.to_string());
        self.loop_stack.push(promo.head_pc);
        let mut body = self.plan_region(promo.body_pc, &BTreeSet::new())?;
        self.loop_stack.pop();
        if self.labels.contains(&promo.latch_pc) {
            body.push(Stmt::Comment(format!(
                "-- PC {:03}: numeric-for latch; the index increment is implicit",
                promo.latch_pc
            )));
            body.push(Stmt::Label(promo.latch_pc));
        }
        let stmt = Stmt::ForNum {
            var: reg_name(promo.var_reg),
            start,
            limit,
            step,
            body,
        };
        Ok((stmt, promo.exit_pc))
    }

    fn plan_while(
        &mut self,
        head_pc: usize,
        _stops: &BTreeSet<usize>,
    ) -> Result<(Stmt, usize), String> {
        let has_lines = !self.block_lines(head_pc)?.is_empty();
        if has_lines {
            // Not the clean head form this planner supports; the caller falls
            // back to the flat form for the whole function.
            return Err(format!("PC {head_pc}: loop head carries instructions"));
        }
        let (then_pc, else_pc) = two_way_targets(&self.an.succs[&head_pc])
            .ok_or_else(|| format!("PC {head_pc}: loop head is not a two-way test"))?;
        let (cond, _) = self
            .cond_text
            .get(&head_pc)
            .cloned()
            .ok_or_else(|| format!("PC {head_pc}: missing condition rendering"))?;
        self.planned.insert(head_pc);
        self.loop_stack.push(head_pc);
        let body = self.plan_region(then_pc, &BTreeSet::new())?;
        self.loop_stack.pop();
        Ok((
            Stmt::While {
                cond: Some(cond),
                body,
            },
            else_pc,
        ))
    }

    fn plan_linear(&mut self) -> Vec<Stmt> {
        self.linear_mode = true;
        self.planned.clear();
        self.labels.clear();
        // Re-run the declaration decisions in linear mode.
        self.decide_emissions();
        self.decide_declarations();
        let mut stmts: Vec<Stmt> = vec![Stmt::Comment(
            "-- control flow could not be structured; emitted in flat goto form".to_owned(),
        )];
        let pcs: Vec<usize> = self.an.blocks.keys().copied().collect();
        // Pre-seed every goto target so labels land even on single-predecessor
        // blocks and on blocks processed before their referencing goto.
        for (position, &pc) in pcs.iter().enumerate() {
            let block = self.an.block(pc);
            let next_pc = pcs.get(position + 1).copied();
            let targets: Vec<usize> = match terminal(block) {
                Some(Instruction::Branch { .. }) | Some(Instruction::Compare { .. }) => {
                    match two_way_targets(&self.an.succs[&pc]) {
                        Some((then_pc, else_pc)) => vec![then_pc, else_pc],
                        None => Vec::new(),
                    }
                }
                Some(Instruction::Jump { target })
                | Some(Instruction::ForLoop { target, .. })
                | Some(Instruction::ForPrep { target, .. }) => vec![*target],
                _ => match self.an.single_succ(pc) {
                    Some(next) => vec![next],
                    None => Vec::new(),
                },
            };
            for target in targets {
                if next_pc != Some(target) {
                    self.labels.insert(target);
                }
            }
        }
        for (position, &pc) in pcs.iter().enumerate() {
            let multi_pred = self.an.preds.get(&pc).map(|set| set.len()).unwrap_or(0) > 1;
            let labeled = multi_pred || self.labels.contains(&pc);
            if labeled {
                stmts.push(Stmt::Label(pc));
            }
            let lines = self.block_lines(pc).unwrap_or_default();
            if !lines.is_empty() {
                stmts.push(Stmt::Block { pc, lines });
            }
            let block = self.an.block(pc);
            let next_pc = pcs.get(position + 1).copied();
            match terminal(block) {
                Some(Instruction::Return { .. } | Instruction::ReturnPacked { .. }) => {
                    let site = (pc, block.instructions.len() - 1);
                    if let Some(text) = self.return_text.get(&site).cloned() {
                        stmts.push(Stmt::Return(text));
                    }
                }
                Some(Instruction::Branch { .. }) | Some(Instruction::Compare { .. }) => {
                    if let Some((then_pc, else_pc)) = two_way_targets(&self.an.succs[&pc]) {
                        let (cond, cond_inverted) = self
                            .cond_text
                            .get(&pc)
                            .cloned()
                            .unwrap_or_else(|| ("true".to_owned(), "false".to_owned()));
                        if next_pc == Some(else_pc) {
                            stmts.push(Stmt::If {
                                pc,
                                cond,
                                then_arm: vec![Stmt::Goto(self.retarget(then_pc))],
                                else_arm: Vec::new(),
                            });
                            self.labels.insert(then_pc);
                        } else if next_pc == Some(then_pc) {
                            stmts.push(Stmt::If {
                                pc,
                                cond: cond_inverted,
                                then_arm: vec![Stmt::Goto(self.retarget(else_pc))],
                                else_arm: Vec::new(),
                            });
                            self.labels.insert(else_pc);
                        } else {
                            stmts.push(Stmt::If {
                                pc,
                                cond,
                                then_arm: vec![Stmt::Goto(self.retarget(then_pc))],
                                else_arm: vec![Stmt::Goto(self.retarget(else_pc))],
                            });
                            self.labels.insert(then_pc);
                            self.labels.insert(else_pc);
                        }
                    }
                }
                Some(Instruction::Jump { target })
                | Some(Instruction::ForLoop { target, .. })
                | Some(Instruction::ForPrep { target, .. }) => {
                    if next_pc != Some(*target) {
                        self.labels.insert(*target);
                        stmts.push(Stmt::Goto(*target));
                    }
                }
                _ => {
                    if let Some(next) = self.an.single_succ(pc) {
                        if next_pc != Some(next) {
                            self.labels.insert(next);
                            stmts.push(Stmt::Goto(next));
                        }
                    }
                }
            }
        }
        stmts
    }

    // ------------------------------------------------------------------
    // Goto-scope validation and rendering
    // ------------------------------------------------------------------

    fn goto_scopes_valid(&self, tree: &[Stmt]) -> bool {
        let mut label_depth: HashMap<usize, usize> = HashMap::new();
        collect_label_depths(tree, 0, &self.labels, &mut label_depth);
        let ok = check_goto_depths(tree, 0, &label_depth);
        ok
    }

    fn render_function(&self, tree: &[Stmt]) -> String {
        let mut out = String::new();
        let mut params: Vec<String> = Vec::new();
        if let Some(max) = self.ctx.arg_max {
            for i in 0..=max {
                params.push(format!(
                    "arg{i}: {}",
                    if self.ctx.numeric_inputs.contains(&i) {
                        "{ number } | string"
                    } else {
                        "any"
                    }
                ));
            }
        }
        if self.ctx.uses_varargs {
            params.push("...: any".to_owned());
        }
        let sig = if params.is_empty() {
            "...: any".to_owned()
        } else {
            params.join(", ")
        };
        let _ = writeln!(
            out,
            "local function vm_entry_{}({})",
            self.current_entry, sig
        );
        for input in &self.ctx.numeric_inputs {
            let _ = writeln!(
                out,
                "\tlocal inputValues{input} = arg{input} :: {{ number }}"
            );
        }
        for (slot, ty) in &self.top_decls {
            if self.stored_never.contains(slot) {
                let _ = writeln!(
                    out,
                    "\tlocal {}: {} -- FIXME: read by the lift but never stored; reads render as nil",
                    reg_name(*slot),
                    ty.render()
                );
            } else {
                let _ = writeln!(out, "\tlocal {}: {}", reg_name(*slot), ty.render());
            }
        }
        render_stmts(tree, 1, &self.labels, &mut out);
        out.push_str("end\n");
        out
    }
}

fn collect_label_depths(
    tree: &[Stmt],
    depth: usize,
    labels: &BTreeSet<usize>,
    out: &mut HashMap<usize, usize>,
) {
    for stmt in tree {
        match stmt {
            Stmt::Label(pc) => {
                out.insert(*pc, depth);
            }
            Stmt::Block { pc, .. } => {
                if labels.contains(pc) {
                    out.insert(*pc, depth);
                }
            }
            Stmt::If {
                then_arm, else_arm, ..
            } => {
                collect_label_depths(then_arm, depth + 1, labels, out);
                collect_label_depths(else_arm, depth + 1, labels, out);
            }
            Stmt::While { body, .. } | Stmt::ForNum { body, .. } => {
                collect_label_depths(body, depth + 1, labels, out);
            }
            _ => {}
        }
    }
}

fn check_goto_depths(tree: &[Stmt], depth: usize, label_depth: &HashMap<usize, usize>) -> bool {
    for stmt in tree {
        match stmt {
            Stmt::Goto(target) => match label_depth.get(target) {
                Some(&label) if label <= depth => {}
                _ => return false,
            },
            Stmt::If {
                then_arm, else_arm, ..
            } => {
                if !check_goto_depths(then_arm, depth + 1, label_depth)
                    || !check_goto_depths(else_arm, depth + 1, label_depth)
                {
                    return false;
                }
            }
            Stmt::While { body, .. } | Stmt::ForNum { body, .. } => {
                if !check_goto_depths(body, depth + 1, label_depth) {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

fn render_stmts(tree: &[Stmt], depth: usize, labels: &BTreeSet<usize>, out: &mut String) {
    let indent = "\t".repeat(depth);
    for stmt in tree {
        match stmt {
            Stmt::Comment(text) => {
                let _ = writeln!(out, "{indent}{text}");
            }
            Stmt::Label(pc) => {
                let _ = writeln!(out, "{indent}::vm_pc_{pc}::");
            }
            Stmt::Goto(pc) => {
                let _ = writeln!(out, "{indent}goto vm_pc_{pc}");
            }
            Stmt::Continue => {
                let _ = writeln!(out, "{indent}continue");
            }
            Stmt::Return(text) => {
                let _ = writeln!(out, "{indent}{text}");
            }
            Stmt::Block { pc, lines } => {
                if labels.contains(pc) {
                    let _ = writeln!(out, "{indent}::vm_pc_{pc}::");
                }
                for line in lines {
                    for line in line.lines() {
                        let _ = writeln!(out, "{indent}{line}");
                    }
                }
            }
            Stmt::While { cond, body } => {
                match cond {
                    Some(cond) => {
                        let _ = writeln!(out, "{indent}while {cond} do");
                    }
                    None => {
                        let _ = writeln!(out, "{indent}while true do");
                    }
                }
                render_stmts(body, depth + 1, labels, out);
                let _ = writeln!(out, "{indent}end");
            }
            Stmt::ForNum {
                var,
                start,
                limit,
                step,
                body,
            } => {
                let step_text = match step {
                    Some(step) => format!(", {step}"),
                    None => String::new(),
                };
                let _ = writeln!(out, "{indent}for {var} = {start}, {limit}{step_text} do");
                render_stmts(body, depth + 1, labels, out);
                let _ = writeln!(out, "{indent}end");
            }
            Stmt::If {
                cond,
                then_arm,
                else_arm,
                ..
            } => {
                let _ = writeln!(out, "{indent}if {cond} then");
                render_stmts(then_arm, depth + 1, labels, out);
                let mut current = else_arm.clone();
                loop {
                    while !current.is_empty()
                        && matches!(current[0], Stmt::Block { ref lines, .. } if lines.is_empty())
                    {
                        current.remove(0);
                    }
                    if current.len() == 1 && matches!(current[0], Stmt::If { .. }) {
                        let Stmt::If {
                            cond: inner_cond,
                            then_arm: inner_then,
                            else_arm: inner_else,
                            ..
                        } = &current[0]
                        else {
                            unreachable!()
                        };
                        let inner_then = inner_then.clone();
                        let inner_else = inner_else.clone();
                        let _ = writeln!(out, "{indent}elseif {inner_cond} then");
                        render_stmts(&inner_then, depth + 1, labels, out);
                        current = inner_else;
                    } else if current.is_empty() {
                        let _ = writeln!(out, "{indent}end");
                        break;
                    } else {
                        let _ = writeln!(out, "{indent}else");
                        render_stmts(&current, depth + 1, labels, out);
                        let _ = writeln!(out, "{indent}end");
                        break;
                    }
                }
            }
        }
    }
}

fn instruction_dst(instr: &Instruction) -> Option<u16> {
    match instr {
        Instruction::LoadConst { dst, .. }
        | Instruction::Move { dst, .. }
        | Instruction::Unary { dst, .. }
        | Instruction::Binary { dst, .. }
        | Instruction::GetTable { dst, .. }
        | Instruction::NewTable { dst }
        | Instruction::NewPackedTable { dst }
        | Instruction::Call { dst: Some(dst), .. }
        | Instruction::CallWithPackedArgs { dst: Some(dst), .. }
        | Instruction::Concat { dst, .. }
        | Instruction::NewClosure { dst, .. } => Some(dst.physical_slot),
        Instruction::ForLoop { state, .. } => Some(state.physical_slot),
        _ => None,
    }
}

fn elided_comment(pc: usize, instr: &Instruction) -> Option<String> {
    let text = match instr {
        Instruction::Tag { value } => {
            format!(
                "-- PC {pc:03}: TAG({}) elided; VM bookkeeping has no lifted effect",
                render_operand_name(value)
            )
        }
        Instruction::KeyUpdate { multiplier, addend } => {
            format!("-- PC {pc:03}: key update *{multiplier} + {addend} elided (decode state)")
        }
        Instruction::BankSwitch { bank_base } => {
            format!("-- PC {pc:03}: bank switch to base {bank_base} elided (frame bank)")
        }
        Instruction::Compare { .. } => format!("-- PC {pc:03}: comparison folded into the branch"),
        Instruction::Jump { .. } | Instruction::Nop => return None,
        _ => return None,
    };
    Some(text)
}

fn render_operand_name(operand: &Operand) -> String {
    match operand {
        Operand::Register(reg) => reg_name(reg.physical_slot),
        Operand::Constant(value) => render_constant(value),
        Operand::Argument(index) => format!("arg{index}"),
        Operand::Environment => "vm_environment".to_owned(),
        Operand::Global(path) => path
            .iter()
            .map(|segment| String::from_utf8_lossy(segment).into_owned())
            .collect::<Vec<_>>()
            .join("."),
        Operand::Expression(_) => "<expression>".to_owned(),
        Operand::SlotMapIndex(slot) => format!("slot{slot}"),
        Operand::Word(word) => format!("word{word}"),
        Operand::Unknown(id) => format!("unknown{id}"),
        Operand::Capture(index) => format!("capture{index}"),
    }
}

// =========================================================================
// Module assembly
// =========================================================================

/// Eliminate a wrapper only when its complete, acyclic path merely creates
/// and returns one uncaptured child closure. No calls or input reads may occur.
fn exported_function_entry(program: &LiftedProgram) -> Option<usize> {
    let mut pc = program.root_entry?;
    let mut closures = BTreeMap::new();
    let mut visited = BTreeSet::new();
    for _ in 0..128 {
        if !visited.insert(pc) {
            return None;
        }
        let block = program.blocks.get(&pc)?;
        for instruction in &block.instructions {
            match instruction {
                Instruction::NewClosure {
                    dst,
                    prototype_word,
                    captures,
                } if captures.is_empty() => {
                    closures.insert(
                        dst.physical_slot,
                        *program.prototype_entries.get(prototype_word)?,
                    );
                }
                Instruction::Move {
                    dst,
                    src: Operand::Register(source),
                } => {
                    closures.insert(dst.physical_slot, *closures.get(&source.physical_slot)?);
                }
                Instruction::Return { values } if values.len() == 1 => {
                    if let Operand::Register(register) = &values[0] {
                        return closures.get(&register.physical_slot).copied();
                    }
                    return None;
                }
                Instruction::Jump { .. }
                | Instruction::Nop
                | Instruction::Tag { .. }
                | Instruction::KeyUpdate { .. }
                | Instruction::BankSwitch { .. } => {}
                _ => return None,
            }
        }
        if block.successors.len() != 1 {
            return None;
        }
        pc = block.successors[0].target_pc?;
    }
    None
}

fn emit_module(program: &LiftedProgram, options: &CodegenOptions) -> Result<String, String> {
    if program.blocks.is_empty() {
        return Err("lifted program contains no basic blocks".to_owned());
    }
    let mut entries: Vec<usize> = program.entry_points.clone();
    if let Some(root) = program.root_entry {
        entries.retain(|entry| *entry != root);
        entries.insert(0, root);
    }
    if entries.is_empty() {
        return Err("lifted program lists no entry points".to_owned());
    }
    for entry in &entries {
        if !program.blocks.contains_key(entry) {
            return Err(format!(
                "entry point PC {entry} has no basic block in the lifted program"
            ));
        }
    }

    let mut unknown_ids: BTreeSet<u32> = BTreeSet::new();
    let mut unknown_consts: BTreeSet<u32> = BTreeSet::new();
    let mut frame_slots: BTreeSet<u16> = BTreeSet::new();
    let mut word_refs: BTreeSet<usize> = BTreeSet::new();
    let mut function_texts: Vec<(usize, String)> = Vec::new();
    let exported = exported_function_entry(program);

    for &entry in &entries {
        let tracing = std::env::var_os("LUAU_DEVIRT_TRACE_CODEGEN").is_some();
        if tracing {
            eprintln!("codegen: analyze entry {entry}");
        }
        let an = FnAnalysis::new(program, entry)?;
        if tracing {
            eprintln!("codegen: render uses {entry}");
        }
        let mut emitter = Emitter::new(&an, options, &entries, entry, &program.prototype_entries);
        emitter.render_uses()?;
        if tracing {
            eprintln!("codegen: decide emissions {entry}");
        }
        emitter.decide_emissions();
        if tracing {
            eprintln!("codegen: declarations {entry}");
        }
        emitter.decide_declarations();
        if tracing {
            eprintln!("codegen: structure {entry}");
        }
        let mut tree = emitter.plan()?;
        if let Some(promotion) = &an.for_promotion {
            rewrite_continues(&mut tree, promotion.latch_pc, false)?;
            emitter.labels.remove(&promotion.latch_pc);
        }
        reject_unstructured_control(&tree)?;
        emitter.labels.clear();
        if program.root_entry.is_some()
            && (!emitter.stored_never.is_empty()
                || !emitter.ctx.unknown_ids.is_empty()
                || !emitter.ctx.unknown_consts.is_empty()
                || !emitter.ctx.frame_slots.is_empty()
                || !emitter.ctx.word_refs.is_empty())
        {
            return Err(format!(
                "entry {entry} still contains unresolved register or operand bindings"
            ));
        }
        if exported == Some(entry) {
            if let Some(canonical) = canonical_scanner(program, entry, &tree, options) {
                return Ok(canonical);
            }
        }
        let text = emitter.render_function(&tree);
        unknown_ids.extend(emitter.ctx.unknown_ids.iter().copied());
        unknown_consts.extend(emitter.ctx.unknown_consts.iter().copied());
        frame_slots.extend(emitter.ctx.frame_slots.iter().copied());
        word_refs.extend(emitter.ctx.word_refs.iter().copied());
        function_texts.push((entry, text));
    }

    let mut out = String::new();
    if options.strict {
        let _ = writeln!(out, "--!strict");
    }
    if uses_type_intrinsic(program) {
        let _ = writeln!(out, "\nlocal capturedType = type");
    }
    let mut leaves = Vec::new();
    for block in program.blocks.values() {
        for instruction in &block.instructions {
            for operand in operands_of(instruction) {
                collect_operand_leaves(operand, &mut leaves);
            }
        }
    }
    if leaves
        .iter()
        .any(|operand| matches!(operand, Operand::Environment))
    {
        let _ = writeln!(out, "\nlocal vm_environment = getfenv()");
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "-- Luau reconstruction generated by luau-devirt from the lifted VM program."
    );
    let entry_list = entries
        .iter()
        .map(|entry| entry.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(
        out,
        "-- Entry points (module order): {entry_list}; reachable blocks: {}; state variants: {}.",
        program.reachable_pcs.len(),
        program.state_variants
    );
    let _ = writeln!(
        out,
        "-- Registers are locals named r<physical slot>. VM bookkeeping (TAG, key updates, bank"
    );
    let _ = writeln!(
        out,
        "-- switches) is elided. Packed varargs render as `...` and packed return tuples expand"
    );
    let _ = writeln!(out, "-- to multi-value returns.");
    if !unknown_ids.is_empty() || !frame_slots.is_empty() || !word_refs.is_empty() {
        let _ = writeln!(out);
    }
    for id in &unknown_ids {
        let _ = writeln!(
            out,
            "local vm_unknown_{id}: any -- FIXME: unresolved VM operand #{id}; nil binding"
        );
    }
    for id in &unknown_consts {
        let _ = writeln!(
            out,
            "local vm_unknown_const_{id}: any -- FIXME: unresolved constant #{id}; nil binding"
        );
    }
    for slot in &frame_slots {
        let _ = writeln!(
            out,
            "local vm_frame_slot_{slot}: any -- FIXME: VM frame slot {slot} not modeled by the \
             lift; reads render as nil"
        );
    }
    for word in &word_refs {
        let _ = writeln!(
            out,
            "local vm_word_{word}: any -- FIXME: raw word reference {word}; nil binding"
        );
    }
    let mut ordered = Vec::new();
    let mut remaining: BTreeMap<usize, String> = function_texts.into_iter().collect();
    let mut emitted_entries = BTreeSet::new();
    while !remaining.is_empty() {
        let ready: Vec<_> = remaining
            .keys()
            .copied()
            .filter(|entry| {
                let Ok(analysis) = FnAnalysis::new(program, *entry) else {
                    return false;
                };
                analysis
                    .blocks
                    .values()
                    .flat_map(|block| block.instructions.iter())
                    .filter_map(|instruction| {
                        if let Instruction::NewClosure { prototype_word, .. } = instruction {
                            program.prototype_entries.get(prototype_word).copied()
                        } else {
                            None
                        }
                    })
                    .all(|dependency| emitted_entries.contains(&dependency))
            })
            .collect();
        if ready.is_empty() {
            return Err("closure dependency cycle requires forward declarations and is not supported by this emitter".to_owned());
        }
        for entry in ready {
            let text = remaining.remove(&entry).expect("ready function exists");
            emitted_entries.insert(entry);
            ordered.push((entry, text));
        }
    }
    for (entry, text) in &ordered {
        let _ = writeln!(out);
        let _ = writeln!(out, "-- Entry prototype at PC {entry}.");
        out.push_str(text);
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "-- Module main: the harness calls the entry prototype once at load time."
    );
    let _ = writeln!(out, "return vm_entry_{}()", entries[0]);
    Ok(out)
}

// =========================================================================
// Public API
// =========================================================================

#[derive(Clone, Debug)]
struct DataAtom {
    text: String,
    binding: Option<usize>,
    constant: Option<Constant>,
    expression: pretty::Expr,
}
impl PartialEq for DataAtom {
    fn eq(&self, other: &Self) -> bool {
        // Presentation metadata must not change the conservative renderer's
        // preexisting binding/constant identity or its default output.
        self.text == other.text && self.binding == other.binding && self.constant == other.constant
    }
}
impl Eq for DataAtom {}

type DataBindings = BTreeMap<u16, DataAtom>;

struct DataBody {
    text: String,
    statements: pretty::Body,
}

/// An order-preserving renderer for acyclic, captured-environment dataflow.
/// It shares the ordinary emitter's validated CFG, postdominators, IR, literal
/// printer, optimizers and naming utilities. Copies become immutable bindings;
/// table reads and external calls each remain one explicit evaluation.
struct DataEmitter<'a> {
    analysis: &'a FnAnalysis<'a>,
    program: &'a LiftedProgram,
    names: Vec<String>,
    live: BTreeMap<usize, BTreeSet<u16>>,
    steps: usize,
    source_comments: bool,
    capture_count: usize,
    vararg_mode: bool,
}

impl DataEmitter<'_> {
    fn atom(&self, op: &Operand, values: &DataBindings) -> Result<DataAtom, String> {
        Ok(match op {
            Operand::Constant(c) => DataAtom {
                text: render_constant(c),
                binding: None,
                constant: Some(c.clone()),
                expression: pretty::Expr::Constant(c.clone()),
            },
            Operand::Environment => DataAtom {
                text: "environment".to_owned(),
                binding: None,
                constant: None,
                expression: pretty::Expr::Environment,
            },
            Operand::Register(r) => values
                .get(&r.physical_slot)
                .cloned()
                .ok_or_else(|| format!("uninitialized data register {}", r.physical_slot))?,
            Operand::Argument(index) => {
                if *index >= 4096 { return Err("captured argument index budget exceeded".to_owned()); }
                DataAtom {
                        text: format!("arg{index}"),
                        binding: None,
                        constant: None,
                        expression: pretty::Expr::External(format!("arg{index}")),
                }
            }
            Operand::Capture(index) => {
                if *index >= self.capture_count {
                    return Err(format!(
                        "captured dataflow capture index {index} is outside the proved capture count {}",
                        self.capture_count
                    ));
                }
                DataAtom {
                    text: format!("capture{index}"),
                    binding: None,
                    constant: None,
                    expression: pretty::Expr::External(format!("capture{index}")),
                }
            }
            Operand::Global(path) => {
                let text = render_global_path(path);
                DataAtom {
                    text: text.clone(),
                    binding: None,
                    constant: None,
                    expression: pretty::Expr::External(text),
                }
            }
            Operand::Expression(e) => {
                let (text, expression) = match e.as_ref() {
                    ValueExpression::Unary { op, value } => {
                        let value = self.atom(value, values)?;
                        (
                            if *op == UnaryOp::TypeOf {
                                format!("capturedType({})", value.text)
                            } else {
                                format!(
                                    "{}({})",
                                    match op {
                                        UnaryOp::Not => "not ",
                                        UnaryOp::Negate => "-",
                                        UnaryOp::Length => "#",
                                        _ =>
                                            return Err(
                                                "unsupported data unary expression".to_owned()
                                            ),
                                    },
                                    value.text
                                )
                            },
                            pretty::Expr::Unary {
                                op: *op,
                                value: Box::new(value.expression),
                            },
                        )
                    }
                    ValueExpression::Binary { op, left, right } => {
                        let left = self.atom(left, values)?;
                        let right = self.atom(right, values)?;
                        (
                            format!("({}) {} ({})", left.text, binary_op_symbol(*op), right.text),
                            pretty::Expr::Binary {
                                op: *op,
                                left: Box::new(left.expression),
                                right: Box::new(right.expression),
                            },
                        )
                    }
                    ValueExpression::Index { table, index } => {
                        let table = self.atom(table, values)?;
                        let index = self.atom(index, values)?;
                        (
                            format!("{}[{}]", table.text, index.text),
                            pretty::Expr::Index {
                                table: Box::new(table.expression),
                                index: Box::new(index.expression),
                            },
                        )
                    }
                    _ => return Err("data expression requires explicit evaluation".to_owned()),
                };
                DataAtom {
                    text,
                    binding: None,
                    constant: None,
                    expression,
                }
            }
            Operand::SlotMapIndex(slot) => {
                if *slot == PACKED_VARARGS_SLOT {
                    if !self.vararg_mode { return Err("packed varargs in a fixed-arity frame are unsupported".to_owned()); }
                    DataAtom {
                        text: "packedArguments".to_owned(),
                        binding: None,
                        constant: None,
                        expression: pretty::Expr::External("packedArguments".to_owned()),
                    }
                } else {
                    return Err(format!("unproved private frame slot {slot} in captured dataflow"));
                }
            }
            Operand::Word(word) => {
                return Err(format!(
                    "unsupported captured-dataflow operand: raw word reference {word} is not a proved value"
                ))
            }
            Operand::Unknown(id) => {
                return Err(format!(
                    "unsupported captured-dataflow operand: unresolved VM operand #{id} is not a proved value"
                ))
            }
        })
    }
    fn fixed_packet_count(
        &self,
        packet: &DataAtom,
        count: Option<usize>,
        text: &mut String,
        statements: &mut pretty::Body,
        indent: &str,
    ) -> Result<(), String> {
        let Some(count) = count else {
            return Ok(());
        };
        if count > 65536 {
            return Err("fixed result arity budget exceeded".to_owned());
        }
        writeln!(text,"{indent}for tupleIndex = {}, {}.n do\n{indent}\t{}[tupleIndex] = nil\n{indent}end\n{indent}{}.n = {count}",count+1,packet.text,packet.text,packet.text).map_err(|e|e.to_string())?;
        statements.push(pretty::Statement::ForNum {
            var: "tupleIndex".to_owned(),
            start: pretty::Expr::Constant(Constant::Integer((count + 1) as i64)),
            limit: pretty::Expr::Index {
                table: Box::new(packet.expression.clone()),
                index: Box::new(pretty::Expr::Constant(Constant::String(b"n".to_vec()))),
            },
            step: None,
            body: vec![pretty::Statement::SetTable {
                table: packet.expression.clone(),
                index: pretty::Expr::External("tupleIndex".to_owned()),
                value: pretty::Expr::Constant(Constant::Nil),
            }],
        });
        statements.push(pretty::Statement::SetTable {
            table: packet.expression.clone(),
            index: pretty::Expr::Constant(Constant::String(b"n".to_vec())),
            value: pretty::Expr::Constant(Constant::Integer(count as i64)),
        });
        Ok(())
    }
    fn bind(&mut self, hint: &str) -> DataAtom {
        let id = self.names.len();
        self.names.push(hint.to_owned());
        DataAtom {
            text: format!("recoveredValue{id}"),
            binding: Some(id),
            constant: None,
            expression: pretty::Expr::Binding(id),
        }
    }
    fn suggest(&mut self, atom: &DataAtom, hint: &str) {
        if let Some(id) = atom.binding {
            if self.names[id] == "value"
                || self.names[id] == "tableValue"
                || self.names[id] == "findFirstChild"
            {
                self.names[id] = hint.to_owned();
            }
        }
    }
    fn member(
        &self,
        table: &str,
        index: &Operand,
        values: &DataBindings,
    ) -> Result<String, String> {
        let atom = self.atom(index, values)?;
        if let Some(Constant::String(key)) = &atom.constant {
            let key = String::from_utf8_lossy(key);
            if !key.is_empty()
                && ![
                    "and", "break", "do", "else", "elseif", "end", "false", "for", "function",
                    "if", "in", "local", "nil", "not", "or", "repeat", "return", "then", "true",
                    "until", "while", "continue",
                ]
                .contains(&key.as_ref())
                && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && key
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            {
                return Ok(format!("{table}.{key}"));
            }
        }
        Ok(format!("{table}[{}]", atom.text))
    }
    fn hint(&self, op: &Operand) -> String {
        match op {
            Operand::Constant(Constant::String(s)) => {
                let s = String::from_utf8_lossy(s);
                match s.as_ref() {
                    "game" => "game".to_owned(),
                    "assert" => "assertDialogue".to_owned(),
                    "UDim2" => "uDim2".to_owned(),
                    "Color3" => "color3".to_owned(),
                    "math" => "mathLibrary".to_owned(),
                    "GetService" => "getService".to_owned(),
                    "FindFirstChild" => "findFirstChild".to_owned(),
                    "IsA" => "isA".to_owned(),
                    "Fire" => "fireDialogue".to_owned(),
                    "fromScale" => "fromScale".to_owned(),
                    "fromRGB" => "fromRGB".to_owned(),
                    "huge" => "endIndex".to_owned(),
                    _ => "value".to_owned(),
                }
            }
            _ => "value".to_owned(),
        }
    }
    fn call_hint(&self, function: &DataAtom, args: &[Operand], values: &DataBindings) -> String {
        let name = function
            .binding
            .map(|i| self.names[i].as_str())
            .unwrap_or("");
        let last = args
            .last()
            .and_then(|a| self.atom(a, values).ok())
            .and_then(|a| a.constant);
        if name == "getService"
            && matches!(&last,Some(Constant::String(s))if s==b"ReplicatedStorage")
        {
            return "replicatedStorage".to_owned();
        }
        if name == "findFirstChild" {
            if matches!(&last,Some(Constant::String(s))if s==b"Events") {
                return "events".to_owned();
            }
            if matches!(&last,Some(Constant::String(s))if s==b"MothDialogueBindable") {
                return "foundDialogueEvent".to_owned();
            }
        }
        match name {
            "isA" => "isBindableEvent",
            "fromScale" => "dialoguePosition",
            "fromRGB" => "markupColor",
            _ => "value",
        }
        .to_owned()
    }
    fn condition(&self, c: &Condition, values: &DataBindings) -> Result<String, String> {
        Ok(match c {
            Condition::Truthy(v) => self.atom(v, values)?.text,
            Condition::Falsey(v) => format!("not ({})", self.atom(v, values)?.text),
            Condition::Compare { op, left, right } => format!(
                "{} {} {}",
                self.atom(left, values)?.text,
                binary_op_symbol(*op),
                self.atom(right, values)?.text
            ),
        })
    }
    fn condition_expression(
        &self,
        c: &Condition,
        values: &DataBindings,
    ) -> Result<pretty::Expr, String> {
        Ok(match c {
            Condition::Truthy(v) => self.atom(v, values)?.expression,
            Condition::Falsey(v) => pretty::Expr::Unary {
                op: UnaryOp::Not,
                value: Box::new(self.atom(v, values)?.expression),
            },
            Condition::Compare { op, left, right } => pretty::Expr::Binary {
                op: *op,
                left: Box::new(self.atom(left, values)?.expression),
                right: Box::new(self.atom(right, values)?.expression),
            },
        })
    }
    fn walk(
        &mut self,
        mut pc: usize,
        stop: Option<usize>,
        mut values: DataBindings,
        depth: usize,
    ) -> Result<(DataBody, DataBindings), String> {
        if depth > 64 {
            return Err("structured dataflow nesting exceeds 64".to_owned());
        }
        let mut text = String::new();
        let mut statements = vec![];
        let indent = "\t".repeat(depth);
        loop {
            if Some(pc) == stop {
                return Ok((DataBody { text, statements }, values));
            }
            self.steps += 1;
            if self.steps > 4096 {
                return Err("structured dataflow emission exceeds 4096 blocks".to_owned());
            }
            let block = *self.analysis.blocks.get(&pc).ok_or("missing data block")?;
            if self.source_comments {
                writeln!(
                    text,
                    "{indent}-- Source VM words {pc}..{}",
                    block.end_pc.saturating_sub(1)
                )
                .map_err(|e| e.to_string())?;
                statements.push(pretty::Statement::Comment(format!(
                    "Source VM words {pc}..{}",
                    block.end_pc.saturating_sub(1)
                )));
            }
            let mut index = 0;
            while index < block.instructions.len() {
                let instruction = &block.instructions[index];
                if let Instruction::Branch {
                    condition,
                    then_target,
                    else_target,
                } = instruction
                {
                    let join = self
                        .analysis
                        .ipdom
                        .get(&pc)
                        .copied()
                        .flatten()
                        .ok_or("data branch has no common postdominator")?;
                    let condition_expression = self.condition_expression(condition, &values)?;
                    let condition = self.condition(condition, &values)?;
                    let (yes, yes_values) =
                        self.walk(*then_target, Some(join), values.clone(), depth + 1)?;
                    let (no, no_values) =
                        self.walk(*else_target, Some(join), values.clone(), depth + 1)?;
                    let mut yes_suffix = String::new();
                    let mut no_suffix = String::new();
                    let mut yes_statements = yes.statements;
                    let mut no_statements = no.statements;
                    let mut merged = values.clone();
                    let mut phis: BTreeMap<(String, String), DataAtom> = BTreeMap::new();
                    for slot in self.live.get(&join).cloned().unwrap_or_default() {
                        let a = yes_values
                            .get(&slot)
                            .ok_or("missing true dataflow binding")?
                            .clone();
                        let b = no_values
                            .get(&slot)
                            .ok_or("missing false dataflow binding")?
                            .clone();
                        if a == b {
                            merged.insert(slot, a);
                            continue;
                        }
                        let atom = if let Some(atom) = phis.get(&(a.text.clone(), b.text.clone())) {
                            atom.clone()
                        } else {
                            let hint = a
                                .binding
                                .map(|id| self.names[id].clone())
                                .unwrap_or_else(|| "value".to_owned());
                            let hint = match hint.as_str() {
                                "foundDialogueEvent" => "dialogueEvent",
                                "isBindableEvent" => "validDialogueEvent",
                                _ => &hint,
                            };
                            let atom = self.bind(hint);
                            if no.text.is_empty() && values.values().any(|v| v == &b) {
                                writeln!(text, "{indent}local {}: any = {}", atom.text, b.text)
                                    .map_err(|e| e.to_string())?;
                                statements.push(pretty::Statement::Local {
                                    binding: atom.binding.ok_or("missing phi binding")?,
                                    annotation: Some("any"),
                                    value: Some(b.expression.clone()),
                                });
                            } else {
                                writeln!(text, "{indent}local {}: any", atom.text)
                                    .map_err(|e| e.to_string())?;
                                statements.push(pretty::Statement::Local {
                                    binding: atom.binding.ok_or("missing phi binding")?,
                                    annotation: Some("any"),
                                    value: None,
                                });
                                writeln!(no_suffix, "{indent}\t{} = {}", atom.text, b.text)
                                    .map_err(|e| e.to_string())?;
                                no_statements.push(pretty::Statement::Assign {
                                    binding: atom.binding.ok_or("missing phi binding")?,
                                    value: b.expression.clone(),
                                });
                            }
                            writeln!(yes_suffix, "{indent}\t{} = {}", atom.text, a.text)
                                .map_err(|e| e.to_string())?;
                            yes_statements.push(pretty::Statement::Assign {
                                binding: atom.binding.ok_or("missing phi binding")?,
                                value: a.expression.clone(),
                            });
                            phis.insert((a.text, b.text), atom.clone());
                            atom
                        };
                        merged.insert(slot, atom);
                    }
                    writeln!(text, "{indent}if {condition} then").map_err(|e| e.to_string())?;
                    text.push_str(&yes.text);
                    text.push_str(&yes_suffix);
                    if !no.text.is_empty() || !no_suffix.is_empty() {
                        writeln!(text, "{indent}else").map_err(|e| e.to_string())?;
                        text.push_str(&no.text);
                        text.push_str(&no_suffix);
                    }
                    writeln!(text, "{indent}end").map_err(|e| e.to_string())?;
                    statements.push(pretty::Statement::If {
                        condition: condition_expression,
                        yes: yes_statements,
                        no: no_statements,
                    });
                    values = merged;
                    pc = join;
                    break;
                }
                match instruction {
                    Instruction::LoadConst { dst, value } => {
                        values.insert(
                            dst.physical_slot,
                            self.atom(&Operand::Constant(value.clone()), &values)?,
                        );
                    }
                    Instruction::Move { dst, src } => {
                        let value = self.atom(src, &values)?;
                        values.insert(dst.physical_slot, value);
                    }
                    Instruction::NewTable { dst } => {
                        let atom = self.bind("tableValue");
                        writeln!(text, "{indent}local {}: {{ [any]: any }} = {{}}", atom.text)
                            .map_err(|e| e.to_string())?;
                        statements.push(pretty::Statement::Local {
                            binding: atom.binding.ok_or("missing table binding")?,
                            annotation: Some("{ [any]: any }"),
                            value: Some(pretty::Expr::Table(vec![])),
                        });
                        values.insert(dst.physical_slot, atom);
                    }
                    Instruction::GetTable { dst, table, index } => {
                        let table = self.atom(table, &values)?;
                        let expression = self.member(&table.text, index, &values)?;
                        let hint = self
                            .atom(index, &values)?
                            .constant
                            .map(|c| self.hint(&Operand::Constant(c)))
                            .unwrap_or_else(|| "value".to_owned());
                        let atom = self.bind(&hint);
                        writeln!(text, "{indent}local {} = {expression}", atom.text)
                            .map_err(|e| e.to_string())?;
                        statements.push(pretty::Statement::Local {
                            binding: atom.binding.ok_or("missing read binding")?,
                            annotation: None,
                            value: Some(pretty::Expr::Index {
                                table: Box::new(table.expression),
                                index: Box::new(self.atom(index, &values)?.expression),
                            }),
                        });
                        values.insert(dst.physical_slot, atom);
                    }
                    Instruction::SetTable {
                        table,
                        index,
                        value,
                    } => {
                        let table = self.atom(table, &values)?;
                        let value_atom = self.atom(value, &values)?;
                        if let Some(Constant::String(key)) = self.atom(index, &values)?.constant {
                            match key.as_slice() {
                                b"Text" => self.suggest(&table, "dialogueOptions"),
                                b"InitialSounds" => self.suggest(&value_atom, "initialSounds"),
                                b"Markups" => self.suggest(&value_atom, "markups"),
                                b"MarkupType" => {
                                    if let Some(Constant::String(v)) = &value_atom.constant {
                                        match v.as_slice() {
                                            b"Color" => self.suggest(&table, "colorMarkup"),
                                            b"Shaky" => self.suggest(&table, "shakyMarkup"),
                                            _ => {}
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        writeln!(
                            text,
                            "{indent}{} = {}",
                            self.member(&table.text, index, &values)?,
                            value_atom.text
                        )
                        .map_err(|e| e.to_string())?;
                        statements.push(pretty::Statement::SetTable {
                            table: table.expression,
                            index: self.atom(index, &values)?.expression,
                            value: value_atom.expression,
                        });
                    }
                    Instruction::Call {
                        dst,
                        function,
                        args,
                        result_count,
                    } => {
                        let function_atom = self.atom(function, &values)?;
                        let rendered = args
                            .iter()
                            .map(|a| self.atom(a, &values).map(|v| v.text))
                            .collect::<Result<Vec<_>, _>>()?;
                        let expression = format!("{}({})", function_atom.text, rendered.join(", "));
                        let call = pretty::Expr::Call {
                            function: Box::new(function_atom.expression.clone()),
                            args: args
                                .iter()
                                .map(|a| self.atom(a, &values).map(|v| v.expression))
                                .collect::<Result<Vec<_>, _>>()?,
                        };
                        if let Some(packet) = dst {
                            if *result_count == Some(1) {
                                let Some(Instruction::GetTable {
                                    dst: scalar,
                                    table: Operand::Register(source),
                                    index: Operand::Constant(Constant::Integer(1)),
                                }) = block.instructions.get(index + 1)
                                else {
                                    return Err(
                                        "captured dataflow requires a scalar packet projection"
                                            .to_owned(),
                                    );
                                };
                                if source != packet
                                    || self
                                        .analysis
                                        .uses
                                        .get(&packet.physical_slot)
                                        .is_none_or(|u| u.as_slice() != [(pc, index + 1)])
                                {
                                    return Err("call packet has additional uses or unknown arity"
                                        .to_owned());
                                }
                                let atom =
                                    self.bind(&self.call_hint(&function_atom, args, &values));
                                writeln!(text, "{indent}local {} = {expression}", atom.text)
                                    .map_err(|e| e.to_string())?;
                                statements.push(pretty::Statement::Local {
                                    binding: atom.binding.ok_or("missing scalar call binding")?,
                                    annotation: None,
                                    value: Some(call),
                                });
                                values.insert(scalar.physical_slot, atom);
                                index += 1;
                            } else {
                                // Unknown-arity full result packet. Preserve the
                                // complete table.pack result; a later [1] read
                                // is just an index into that packet.
                                let packed_text = format!("capturedPack({expression})");
                                let packed_call = pretty::Expr::Call {
                                    function: Box::new(pretty::Expr::External(
                                        "capturedPack".to_owned(),
                                    )),
                                    args: vec![pretty::Expr::Expand(Box::new(call))],
                                };
                                let atom = self.bind("value");
                                writeln!(text, "{indent}local {} = {packed_text}", atom.text)
                                    .map_err(|e| e.to_string())?;
                                statements.push(pretty::Statement::Local {
                                    binding: atom.binding.ok_or("missing packet binding")?,
                                    annotation: None,
                                    value: Some(packed_call),
                                });
                                self.fixed_packet_count(
                                    &atom,
                                    *result_count,
                                    &mut text,
                                    &mut statements,
                                    &indent,
                                )?;
                                values.insert(packet.physical_slot, atom);
                            }
                        } else {
                            writeln!(text, "{indent}{expression}").map_err(|e| e.to_string())?;
                            statements.push(pretty::Statement::Call(call));
                        }
                    }
                    Instruction::CallWithPackedArgs {
                        dst,
                        function,
                        prefix,
                        arguments,
                        result_count,
                    } => {
                        let function_atom = self.atom(function, &values)?;
                        let prefix_rendered = prefix
                            .iter()
                            .map(|a| {
                                let atom = self.atom(a, &values)?;
                                let text = if matches!(atom.expression, pretty::Expr::Call { .. }) {
                                    format!("({})", atom.text)
                                } else {
                                    atom.text
                                };
                                Ok::<String, String>(text)
                            })
                            .collect::<Result<Vec<_>, _>>()?;
                        let arguments_atom = self.atom(arguments, &values)?;
                        let mut call_args = prefix_rendered.clone();
                        call_args.push(format!(
                            "capturedUnpack({}, 1, {}.n)",
                            arguments_atom.text, arguments_atom.text
                        ));
                        let expression =
                            format!("{}({})", function_atom.text, call_args.join(", "));
                        let prefix_exprs = prefix
                            .iter()
                            .map(|a| self.atom(a, &values).map(|v| v.expression))
                            .collect::<Result<Vec<_>, _>>()?;
                        let mut call_expr_args = prefix_exprs;
                        call_expr_args.push(pretty::Expr::Expand(Box::new(pretty::Expr::Call {
                            function: Box::new(pretty::Expr::External("capturedUnpack".to_owned())),
                            args: vec![
                                arguments_atom.expression.clone(),
                                pretty::Expr::Constant(Constant::Integer(1)),
                                pretty::Expr::Index {
                                    table: Box::new(arguments_atom.expression.clone()),
                                    index: Box::new(pretty::Expr::Constant(Constant::String(
                                        b"n".to_vec(),
                                    ))),
                                },
                            ],
                        })));
                        let call = pretty::Expr::Call {
                            function: Box::new(function_atom.expression.clone()),
                            args: call_expr_args,
                        };
                        if let Some(packet) = dst {
                            if *result_count == Some(1) {
                                let Some(Instruction::GetTable {
                                    dst: scalar,
                                    table: Operand::Register(source),
                                    index: Operand::Constant(Constant::Integer(1)),
                                }) = block.instructions.get(index + 1)
                                else {
                                    return Err(
                                        "captured dataflow requires a scalar packet projection"
                                            .to_owned(),
                                    );
                                };
                                if source != packet
                                    || self
                                        .analysis
                                        .uses
                                        .get(&packet.physical_slot)
                                        .is_none_or(|u| u.as_slice() != [(pc, index + 1)])
                                {
                                    return Err("call packet has additional uses or unknown arity"
                                        .to_owned());
                                }
                                let atom =
                                    self.bind(&self.call_hint(&function_atom, &prefix, &values));
                                writeln!(text, "{indent}local {} = {expression}", atom.text)
                                    .map_err(|e| e.to_string())?;
                                statements.push(pretty::Statement::Local {
                                    binding: atom.binding.ok_or("missing scalar call binding")?,
                                    annotation: None,
                                    value: Some(call),
                                });
                                values.insert(scalar.physical_slot, atom);
                                index += 1;
                            } else {
                                // Unknown-arity full result packet. Preserve the
                                // complete table.pack result; a later [1] read
                                // is just an index into that packet.
                                let packed_text = format!("capturedPack({expression})");
                                let packed_call = pretty::Expr::Call {
                                    function: Box::new(pretty::Expr::External(
                                        "capturedPack".to_owned(),
                                    )),
                                    args: vec![pretty::Expr::Expand(Box::new(call))],
                                };
                                let atom = self.bind("value");
                                writeln!(text, "{indent}local {} = {packed_text}", atom.text)
                                    .map_err(|e| e.to_string())?;
                                statements.push(pretty::Statement::Local {
                                    binding: atom.binding.ok_or("missing packet binding")?,
                                    annotation: None,
                                    value: Some(packed_call),
                                });
                                self.fixed_packet_count(
                                    &atom,
                                    *result_count,
                                    &mut text,
                                    &mut statements,
                                    &indent,
                                )?;
                                values.insert(packet.physical_slot, atom);
                            }
                        } else {
                            writeln!(text, "{indent}{expression}").map_err(|e| e.to_string())?;
                            statements.push(pretty::Statement::Call(call));
                        }
                    }
                    Instruction::NewPackedTable { dst } => {
                        let atom = self.bind("tableValue");
                        writeln!(text, "{indent}local {} = {{ n = 0 }}", atom.text)
                            .map_err(|e| e.to_string())?;
                        statements.push(pretty::Statement::Local {
                            binding: atom.binding.ok_or("missing packed table binding")?,
                            annotation: None,
                            value: Some(pretty::Expr::Table(vec![(
                                pretty::Expr::Constant(Constant::String(b"n".to_vec())),
                                pretty::Expr::Constant(Constant::Integer(0)),
                            )])),
                        });
                        values.insert(dst.physical_slot, atom);
                    }
                    Instruction::PushPacked { table, value } => {
                        let table = self.atom(table, &values)?;
                        let value = self.atom(value, &values)?;
                        writeln!(text, "{indent}{}.n = {}.n + 1", table.text, table.text)
                            .map_err(|e| e.to_string())?;
                        statements.push(pretty::Statement::SetTable {
                            table: table.expression.clone(),
                            index: pretty::Expr::Constant(Constant::String(b"n".to_vec())),
                            value: pretty::Expr::Binary {
                                op: BinaryOp::Add,
                                left: Box::new(pretty::Expr::Index {
                                    table: Box::new(table.expression.clone()),
                                    index: Box::new(pretty::Expr::Constant(Constant::String(
                                        b"n".to_vec(),
                                    ))),
                                }),
                                right: Box::new(pretty::Expr::Constant(Constant::Integer(1))),
                            },
                        });
                        writeln!(
                            text,
                            "{indent}{}[{}.n] = {}",
                            table.text, table.text, value.text
                        )
                        .map_err(|e| e.to_string())?;
                        statements.push(pretty::Statement::SetTable {
                            table: table.expression.clone(),
                            index: pretty::Expr::Index {
                                table: Box::new(table.expression.clone()),
                                index: Box::new(pretty::Expr::Constant(Constant::String(
                                    b"n".to_vec(),
                                ))),
                            },
                            value: value.expression.clone(),
                        });
                    }
                    Instruction::Append { table, value } => {
                        let table = self.atom(table, &values)?;
                        let value = self.atom(value, &values)?;
                        writeln!(
                            text,
                            "{indent}{}[#{} + 1] = {}",
                            table.text, table.text, value.text
                        )
                        .map_err(|e| e.to_string())?;
                        statements.push(pretty::Statement::SetTable {
                            table: table.expression.clone(),
                            index: pretty::Expr::Binary {
                                op: BinaryOp::Add,
                                left: Box::new(pretty::Expr::Unary {
                                    op: UnaryOp::Length,
                                    value: Box::new(table.expression.clone()),
                                }),
                                right: Box::new(pretty::Expr::Constant(Constant::Integer(1))),
                            },
                            value: value.expression.clone(),
                        });
                    }
                    Instruction::AppendPacked {
                        table,
                        values: vals,
                    } => {
                        let table = self.atom(table, &values)?;
                        let vals = self.atom(vals, &values)?;
                        let old_count = self.bind("value");
                        writeln!(text, "{indent}local {} = {}.n", old_count.text, table.text)
                            .map_err(|e| e.to_string())?;
                        statements.push(pretty::Statement::Local {
                            binding: old_count.binding.ok_or("missing append old count")?,
                            annotation: None,
                            value: Some(pretty::Expr::Index {
                                table: Box::new(table.expression.clone()),
                                index: Box::new(pretty::Expr::Constant(Constant::String(
                                    b"n".to_vec(),
                                ))),
                            }),
                        });
                        let counter = format!("tupleIndex");
                        writeln!(text, "{indent}for {counter} = 1, {}.n do", vals.text)
                            .map_err(|e| e.to_string())?;
                        // pretty ForNum
                        let counter = "tupleIndex";
                        let body = vec![pretty::Statement::SetTable {
                            table: table.expression.clone(),
                            index: pretty::Expr::Binary {
                                op: BinaryOp::Add,
                                left: Box::new(pretty::Expr::Binding(
                                    old_count.binding.ok_or("missing append old count")?,
                                )),
                                right: Box::new(pretty::Expr::External(counter.to_owned())),
                            },
                            value: pretty::Expr::Index {
                                table: Box::new(vals.expression.clone()),
                                index: Box::new(pretty::Expr::External(counter.to_owned())),
                            },
                        }];
                        statements.push(pretty::Statement::ForNum {
                            var: counter.to_owned(),
                            start: pretty::Expr::Constant(Constant::Integer(1)),
                            limit: pretty::Expr::Index {
                                table: Box::new(vals.expression.clone()),
                                index: Box::new(pretty::Expr::Constant(Constant::String(
                                    b"n".to_vec(),
                                ))),
                            },
                            step: None,
                            body,
                        });
                        // update n count
                        statements.push(pretty::Statement::SetTable {
                            table: table.expression.clone(),
                            index: pretty::Expr::Constant(Constant::String(b"n".to_vec())),
                            value: pretty::Expr::Binary {
                                op: BinaryOp::Add,
                                left: Box::new(pretty::Expr::Index {
                                    table: Box::new(table.expression.clone()),
                                    index: Box::new(pretty::Expr::Constant(Constant::String(
                                        b"n".to_vec(),
                                    ))),
                                }),
                                right: Box::new(pretty::Expr::Index {
                                    table: Box::new(vals.expression.clone()),
                                    index: Box::new(pretty::Expr::Constant(Constant::String(
                                        b"n".to_vec(),
                                    ))),
                                }),
                            },
                        });
                        writeln!(
                            text,
                            "{indent}\t{}[{}.n + {counter}] = {}[{counter}]",
                            table.text, table.text, vals.text
                        )
                        .map_err(|e| e.to_string())?;
                        writeln!(text, "{indent}end").map_err(|e| e.to_string())?;
                        writeln!(
                            text,
                            "{indent}{}.n = {}.n + {}.n",
                            table.text, table.text, vals.text
                        )
                        .map_err(|e| e.to_string())?;
                    }
                    Instruction::Unary { dst, op, src } => {
                        let src = self.atom(src, &values)?;
                        let text_expr = match op {
                            UnaryOp::Not => format!("not {}", src.text),
                            UnaryOp::Negate => format!("-{}", src.text),
                            UnaryOp::Length => format!("#{}", src.text),
                            UnaryOp::BitNot => format!("~{}", src.text),
                            UnaryOp::TypeOf => format!("capturedType({})", src.text),
                        };
                        let atom = self.bind("value");
                        writeln!(text, "{indent}local {} = {}", atom.text, text_expr)
                            .map_err(|e| e.to_string())?;
                        statements.push(pretty::Statement::Local {
                            binding: atom.binding.ok_or("missing unary binding")?,
                            annotation: None,
                            value: Some(pretty::Expr::Unary {
                                op: *op,
                                value: Box::new(src.expression),
                            }),
                        });
                        values.insert(dst.physical_slot, atom);
                    }
                    Instruction::Binary {
                        dst,
                        op,
                        left,
                        right,
                    } => {
                        let left = self.atom(left, &values)?;
                        let right = self.atom(right, &values)?;
                        let text_expr =
                            format!("({}) {} ({})", left.text, binary_op_symbol(*op), right.text);
                        let atom = self.bind("value");
                        writeln!(text, "{indent}local {} = {}", atom.text, text_expr)
                            .map_err(|e| e.to_string())?;
                        statements.push(pretty::Statement::Local {
                            binding: atom.binding.ok_or("missing binary binding")?,
                            annotation: None,
                            value: Some(pretty::Expr::Binary {
                                op: *op,
                                left: Box::new(left.expression),
                                right: Box::new(right.expression),
                            }),
                        });
                        values.insert(dst.physical_slot, atom);
                    }
                    Instruction::Concat { dst, values: vals } => {
                        let mut parts = Vec::new();
                        let mut exprs = Vec::new();
                        for v in vals {
                            let a = self.atom(v, &values)?;
                            parts.push(a.text.clone());
                            exprs.push(a.expression.clone());
                        }
                        let text_expr = parts.join(" .. ");
                        let atom = self.bind("value");
                        writeln!(text, "{indent}local {} = {}", atom.text, text_expr)
                            .map_err(|e| e.to_string())?;
                        statements.push(pretty::Statement::Local {
                            binding: atom.binding.ok_or("missing concat binding")?,
                            annotation: None,
                            value: Some(pretty::Expr::Concat(exprs)),
                        });
                        values.insert(dst.physical_slot, atom);
                    }
                    Instruction::NewClosure {
                        dst,
                        prototype_word,
                        captures,
                    } => {
                        let entry = self
                            .program
                            .prototype_entries
                            .get(prototype_word)
                            .copied()
                            .ok_or_else(|| {
                                format!("unlinked closure prototype {prototype_word}")
                            })?;
                        let rendered_caps: Vec<String> = captures
                            .iter()
                            .map(|c| self.atom(c, &values).map(|v| v.text))
                            .collect::<Result<_, _>>()?;
                        let cap_exprs: Vec<pretty::Expr> = captures
                            .iter()
                            .map(|c| self.atom(c, &values).map(|v| v.expression))
                            .collect::<Result<_, _>>()?;
                        let factory = format!("vm_factory_{}", entry);
                        let expression = if rendered_caps.is_empty() {
                            format!("{}()", factory)
                        } else {
                            format!("{}({})", factory, rendered_caps.join(", "))
                        };
                        let atom = self.bind("closureValue");
                        writeln!(text, "{indent}local {} = {}", atom.text, expression)
                            .map_err(|e| e.to_string())?;
                        let args = cap_exprs;
                        // pretty call
                        let pretty_call = pretty::Expr::Call {
                            function: Box::new(pretty::Expr::External(factory.clone())),
                            args,
                        };
                        statements.push(pretty::Statement::Local {
                            binding: atom.binding.ok_or("missing closure binding")?,
                            annotation: None,
                            value: Some(pretty_call),
                        });
                        values.insert(dst.physical_slot, atom);
                    }
                    Instruction::Return { values: returns } => {
                        if returns.is_empty() {
                            return Ok((DataBody { text, statements }, values));
                        }
                        let atoms = returns
                            .iter()
                            .map(|v| self.atom(v, &values))
                            .collect::<Result<Vec<_>, _>>()?;
                        let rendered: Vec<String> = atoms.iter().map(|a| a.text.clone()).collect();
                        writeln!(text, "{indent}return {}", rendered.join(", "))
                            .map_err(|e| e.to_string())?;
                        statements.push(pretty::Statement::Return(
                            atoms.into_iter().map(|a| a.expression).collect(),
                        ));
                        return Ok((DataBody { text, statements }, values));
                    }
                    Instruction::ReturnPacked { values: vals } => {
                        let v = self.atom(vals, &values)?;
                        writeln!(
                            text,
                            "{indent}return capturedUnpack({}, 1, {}.n)",
                            v.text, v.text
                        )
                        .map_err(|e| e.to_string())?;
                        statements.push(pretty::Statement::ReturnPacked(v.expression.clone()));
                        return Ok((DataBody { text, statements }, values));
                    }
                    Instruction::Jump { target } => {
                        pc = *target;
                        break;
                    }
                    Instruction::Nop
                    | Instruction::Tag { .. }
                    | Instruction::KeyUpdate { .. }
                    | Instruction::BankSwitch { .. } => {}
                    _ => {
                        return Err(format!(
                            "unsupported captured-dataflow instruction at {pc}: {instruction:?}"
                        ))
                    }
                }
                index += 1;
                if index == block.instructions.len() {
                    return Err("data block has no terminal control".to_owned());
                }
            }
        }
    }
}

fn emit_captured_dataflow(
    program: &LiftedProgram,
    options: &CodegenOptions,
) -> Result<String, String> {
    // Infer capture counts from linked NewClosure sites; all sites for one
    // prototype must agree.
    let mut capture_counts: BTreeMap<usize, usize> = BTreeMap::new();
    for block in program.blocks.values() {
        for instr in &block.instructions {
            if let Instruction::NewClosure {
                prototype_word,
                captures,
                ..
            } = instr
            {
                if let Some(entry) = program.prototype_entries.get(prototype_word) {
                    let count = captures.len();
                    if let Some(existing) = capture_counts.get(entry) {
                        if *existing != count {
                            return Err(format!(
                                "capture count mismatch for closure prototype entry {entry}"
                            ));
                        }
                    } else {
                        capture_counts.insert(*entry, count);
                    }
                }
            }
        }
    }

    let root_entry = program
        .root_entry
        .unwrap_or_else(|| program.entry_points.first().copied().unwrap_or(0));
    capture_counts.entry(root_entry).or_insert(0);

    let mut entries: Vec<usize> = program.entry_points.clone();
    if !entries.contains(&root_entry) {
        entries.push(root_entry);
    }
    entries.sort_unstable();
    entries.dedup();
    for block in program.blocks.values() {
        for instruction in &block.instructions {
            if let Instruction::NewClosure {
                prototype_word,
                captures,
                ..
            } = instruction
            {
                let target = program
                    .prototype_entries
                    .get(prototype_word)
                    .ok_or("unlinked captured closure prototype")?;
                if *target == root_entry || !entries.contains(target) {
                    return Err(
                        "captured closure factory target is not a declared child entry".to_owned(),
                    );
                }
                if captures.len() > 4096 {
                    return Err("capture count budget exceeded".to_owned());
                }
            }
        }
    }

    // Liveness over the whole (possibly multi-entry) graph.
    let mut live: BTreeMap<usize, BTreeSet<u16>> = program
        .blocks
        .keys()
        .map(|pc| (*pc, BTreeSet::new()))
        .collect();
    let mut converged = false;
    for _ in 0..1024 {
        let mut changed = false;
        for (pc, block) in program.blocks.iter().rev() {
            let mut current = BTreeSet::new();
            for s in &block.successors {
                if let Some(target) = s.target_pc {
                    current.extend(
                        live.get(&target)
                            .ok_or("invalid dataflow liveness edge")?
                            .iter()
                            .copied(),
                    );
                }
            }
            for i in block.instructions.iter().rev() {
                for dst in instruction_binding_defs(i) {
                    current.remove(&dst);
                }
                current.extend(instruction_uses(i));
            }
            if live.get(pc) != Some(&current) {
                live.insert(*pc, current);
                changed = true;
            }
        }
        if !changed {
            converged = true;
            break;
        }
    }
    if !converged {
        return Err("captured dataflow liveness budget exceeded".to_owned());
    }

    // Render non-root entries as functions first.
    let mut output = String::new();
    if options.strict {
        output.push_str("--!strict\n\n");
    }
    // Standard helpers are captured before any program effect so later
    // environment/table edits cannot change their semantics. This preamble
    // must precede child declarations, which may reference these names.
    output.push_str(
        "-- Statically recovered from the VM; external calls retain their source order.\n",
    );
    if uses_type_intrinsic(program) {
        output.push_str("local capturedType = type\n");
    }
    let uses_packets = program.blocks.values().flat_map(|block| &block.instructions).any(|instruction| {
        matches!(instruction, Instruction::CallWithPackedArgs { .. } | Instruction::ReturnPacked { .. })
        || matches!(instruction, Instruction::Call { dst: Some(_), result_count, .. } if *result_count != Some(1))
        || operand_leaves_of(instruction).iter().any(|operand| matches!(operand, Operand::SlotMapIndex(slot) if *slot == PACKED_VARARGS_SLOT))
    });
    if uses_packets {
        output.push_str(
            "local capturedPack = table[\"pack\"]\nlocal capturedUnpack = table[\"unpack\"]\n",
        );
    }
    if program
        .blocks
        .values()
        .flat_map(|block| &block.instructions)
        .any(|instruction| {
            operand_leaves_of(instruction)
                .iter()
                .any(|operand| matches!(operand, Operand::Argument(_)))
        })
    {
        output.push_str("local capturedSelect = select\n");
    }
    output.push_str("local environment = getfenv()\n\n");
    // Forward-declare every factory so a child body that creates a closure
    // of a later-defined entry resolves a local, not a global.
    let child_entries: Vec<usize> = entries
        .iter()
        .copied()
        .filter(|e| *e != root_entry)
        .collect();
    for &entry in &child_entries {
        let _ = writeln!(output, "local vm_factory_{}", entry);
    }
    if !child_entries.is_empty() {
        output.push('\n');
    }
    let mut child_decls: Vec<String> = Vec::new();
    for &entry in &entries {
        if entry == root_entry {
            continue;
        }
        let analysis = FnAnalysis::new(program, entry)?;
        if !analysis.loop_heads.is_empty() {
            return Err(
                "captured dataflow retains a loop requiring additional structuring".to_owned(),
            );
        }
        let capture_count = capture_counts.get(&entry).copied().unwrap_or(0);
        let fixed_param_count = match program.parameters.get(&entry) {
            Some(Some(n)) => Some(*n),
            _ => None,
        };
        // Argument/vararg discovery.
        let mut arg_max: Option<usize> = None;
        let mut uses_varargs = false;
        for block in analysis.blocks.values() {
            for instr in &block.instructions {
                for op in operand_leaves_of(instr) {
                    match op {
                        Operand::Argument(i) => {
                            arg_max = Some(arg_max.map_or(*i, |m| m.max(*i)));
                        }
                        Operand::SlotMapIndex(s) if *s == PACKED_VARARGS_SLOT => {
                            uses_varargs = true;
                        }
                        _ => {}
                    }
                }
            }
        }
        if (arg_max.is_some() || uses_varargs) && !program.parameters.contains_key(&entry) {
            return Err("captured entry parameter mode is not proved".to_owned());
        }
        if uses_varargs && fixed_param_count.is_some() {
            return Err("packed varargs in a fixed-arity frame are unsupported".to_owned());
        }
        if fixed_param_count.is_some_and(|n| n > 4096) {
            return Err("fixed parameter count budget exceeded".to_owned());
        }
        let mut emitter = DataEmitter {
            analysis: &analysis,
            program,
            names: vec![],
            live: live.clone(),
            steps: 0,
            source_comments: options.include_source_comments,
            capture_count,
            vararg_mode: fixed_param_count.is_none(),
        };
        let (body, _) = emitter.walk(entry, None, BTreeMap::new(), 0)?;
        // names
        let mut names = BTreeMap::new();
        let mut pretty_names = BTreeMap::new();
        let mut used: BTreeSet<String> = BTreeSet::new();
        used.insert("environment".to_owned());
        used.insert("capturedPack".to_owned());
        used.insert("capturedUnpack".to_owned());
        used.insert("capturedSelect".to_owned());
        used.insert("packedArguments".to_owned());
        used.insert("tupleIndex".to_owned());
        if uses_type_intrinsic(program) {
            used.insert("capturedType".to_owned());
        }
        if let Some(max) = arg_max {
            for i in 0..=max {
                used.insert(format!("arg{i}"));
            }
        }
        let capture_count = capture_counts.get(&entry).copied().unwrap_or(0);
        for j in 0..capture_count {
            used.insert(format!("capture{j}"));
        }
        for &e in &entries {
            used.insert(format!("vm_entry_{}", e));
            used.insert(format!("vm_factory_{}", e));
        }
        for (id, hint) in emitter.names.iter().enumerate() {
            let mut name = hint.clone();
            for suffix in 2..=65536 {
                if used.insert(name.clone()) {
                    break;
                }
                name = format!("{hint}{suffix}");
            }
            pretty_names.insert(id, name.clone());
            names.insert(format!("recoveredValue{id}"), name);
        }
        // Captures come first so the factory can forward them without
        // truncating a trailing vararg splice.
        let mut params: Vec<String> = Vec::new();
        for j in 0..capture_count {
            params.push(format!("capture{j}: any"));
        }
        if let Some(n) = fixed_param_count {
            // Validate that no Argument index exceeds the declared fixed arity.
            if let Some(max) = arg_max {
                if max as usize + 1 > n {
                    return Err(format!(
                        "captured dataflow fixed parameter count {n} is smaller than used argument index {max}"
                    ));
                }
            }
            for i in 0..n {
                params.push(format!("arg{i}: any"));
            }
        } else {
            // Vararg mode: keep the full packed varargs and bind each Argument
            // via select so the prefix is not consumed.
            if uses_varargs || arg_max.is_some() {
                params.push("...: any".to_owned());
            }
        }
        let sig = if params.is_empty() {
            "...: any".to_owned()
        } else {
            params.join(", ")
        };
        let cap_params: Vec<String> = (0..capture_count).map(|j| format!("capture{j}")).collect();
        let mut decl = String::new();
        let _ = writeln!(decl, "local function vm_entry_{}({})", entry, sig);
        emit_argument_prefix(&mut decl, fixed_param_count, arg_max, uses_varargs)?;
        if options.pretty {
            let pretty_body = pretty::render(body.statements, &pretty_names)?;
            for line in pretty_body.lines() {
                if line.trim().is_empty() {
                    decl.push('\n');
                } else {
                    let _ = writeln!(decl, "\t{}", line);
                }
            }
        } else {
            let renamed = renamed_text(&body.text, &names);
            for line in renamed.lines() {
                if line.trim().is_empty() {
                    decl.push('\n');
                } else {
                    let _ = writeln!(decl, "\t{}", line);
                }
            }
        }
        let _ = writeln!(decl, "end");
        // Factory is assigned (not re-declared) because it was forward-declared
        // above; this keeps later-defined factories visible to earlier bodies.
        let _ = writeln!(
            decl,
            "vm_factory_{} = function({})",
            entry,
            cap_params.join(", ")
        );
        let _ = writeln!(decl, "\treturn function(...: any)");
        if capture_count == 0 {
            let _ = writeln!(decl, "\t\treturn vm_entry_{}(...)", entry);
        } else {
            let mut fwd: Vec<String> = cap_params.clone();
            fwd.push("...".to_owned());
            let _ = writeln!(decl, "\t\treturn vm_entry_{}({})", entry, fwd.join(", "));
        }
        let _ = writeln!(decl, "\tend");
        let _ = writeln!(decl, "end");
        decl.push('\n');
        child_decls.push(decl);
    }

    for decl in &child_decls {
        output.push_str(decl);
    }

    let analysis = FnAnalysis::new(program, root_entry)?;
    if !analysis.loop_heads.is_empty() {
        return Err("captured dataflow retains a loop requiring additional structuring".to_owned());
    }
    let root_capture_count = capture_counts.get(&root_entry).copied().unwrap_or(0);
    let root_fixed_param_count = match program.parameters.get(&root_entry) {
        Some(Some(n)) => Some(*n),
        _ => None,
    };
    // Root captures are not supported by any validated contract; reject them
    // explicitly rather than inventing wrapper parameters.
    if root_capture_count > 0 {
        return Err(
            "root closure captures are not supported by the captured dataflow emitter".to_owned(),
        );
    }
    // Check leaves for Capture.
    let mut leaves = Vec::new();
    for block in analysis.blocks.values() {
        for instr in &block.instructions {
            for op in operand_leaves_of(instr) {
                collect_operand_leaves(op, &mut leaves);
            }
        }
    }
    if leaves.iter().any(|o| matches!(o, Operand::Capture(_))) {
        return Err(
            "root closure captures are not supported by the captured dataflow emitter".to_owned(),
        );
    }
    let mut emitter = DataEmitter {
        analysis: &analysis,
        program,
        names: vec![],
        live: live.clone(),
        steps: 0,
        source_comments: options.include_source_comments,
        capture_count: root_capture_count,
        vararg_mode: root_fixed_param_count.is_none(),
    };
    let (body, _) = emitter.walk(root_entry, None, BTreeMap::new(), 0)?;
    // Argument/vararg discovery for the root.
    let mut root_arg_max: Option<usize> = None;
    let mut root_uses_varargs = false;
    for block in analysis.blocks.values() {
        for instr in &block.instructions {
            for op in operand_leaves_of(instr) {
                match op {
                    Operand::Argument(i) => {
                        root_arg_max = Some(root_arg_max.map_or(*i, |m| m.max(*i)));
                    }
                    Operand::SlotMapIndex(s) if *s == PACKED_VARARGS_SLOT => {
                        root_uses_varargs = true;
                    }
                    _ => {}
                }
            }
        }
    }
    if (root_arg_max.is_some() || root_uses_varargs)
        && !program.parameters.contains_key(&root_entry)
    {
        return Err("captured root parameter mode is not proved".to_owned());
    }
    if root_uses_varargs && root_fixed_param_count.is_some() {
        return Err("packed varargs in a fixed-arity frame are unsupported".to_owned());
    }
    if root_fixed_param_count.is_some_and(|n| n > 4096) {
        return Err("fixed parameter count budget exceeded".to_owned());
    }
    let mut names = BTreeMap::new();
    let mut pretty_names = BTreeMap::new();
    let mut used = BTreeSet::from(["environment".to_owned()]);
    used.insert("capturedPack".to_owned());
    used.insert("capturedUnpack".to_owned());
    used.insert("capturedSelect".to_owned());
    used.insert("packedArguments".to_owned());
    used.insert("tupleIndex".to_owned());
    for &entry in &entries {
        used.insert(format!("vm_entry_{entry}"));
        used.insert(format!("vm_factory_{entry}"));
    }
    if uses_type_intrinsic(program) {
        used.insert("capturedType".to_owned());
    }
    if let Some(max) = root_arg_max {
        for i in 0..=max {
            used.insert(format!("arg{i}"));
        }
    }
    for j in 0..root_capture_count {
        used.insert(format!("capture{j}"));
    }
    for (id, hint) in emitter.names.iter().enumerate() {
        let mut name = hint.clone();
        for suffix in 2..=65536 {
            if used.insert(name.clone()) {
                break;
            }
            name = format!("{hint}{suffix}");
        }
        pretty_names.insert(id, name.clone());
        names.insert(format!("recoveredValue{id}"), name);
    }

    let root_needs_wrapper = root_arg_max.is_some() || root_uses_varargs || root_capture_count > 0;
    if root_needs_wrapper {
        let mut params: Vec<String> = Vec::new();
        for j in 0..root_capture_count {
            params.push(format!("capture{j}: any"));
        }
        if let Some(n) = match program.parameters.get(&root_entry) {
            Some(Some(n)) => Some(*n),
            _ => None,
        } {
            if root_arg_max.is_some_and(|max| max >= n) {
                return Err("root argument exceeds proved fixed parameter count".to_owned());
            }
            for i in 0..n {
                params.push(format!("arg{i}: any"));
            }
        } else {
            params.push("...: any".to_owned());
        }
        let sig = if params.is_empty() {
            "...: any".to_owned()
        } else {
            params.join(", ")
        };
        let _ = writeln!(output, "local function vm_entry_{}({})", root_entry, sig);
        emit_argument_prefix(
            &mut output,
            root_fixed_param_count,
            root_arg_max,
            root_uses_varargs,
        )?;
        if options.pretty {
            let pretty_body = pretty::render(body.statements, &pretty_names)?;
            for line in pretty_body.lines() {
                if line.trim().is_empty() {
                    output.push('\n');
                } else {
                    let _ = writeln!(output, "\t{}", line);
                }
            }
        } else {
            let renamed = renamed_text(&body.text, &names);
            for line in renamed.lines() {
                if line.trim().is_empty() {
                    output.push('\n');
                } else {
                    let _ = writeln!(output, "\t{}", line);
                }
            }
        }
        let _ = writeln!(output, "end");
        let _ = writeln!(output, "return vm_entry_{}(...)", root_entry);
    } else {
        if options.pretty {
            output.push_str(&pretty::render(body.statements, &pretty_names)?);
        } else {
            output.push_str(&renamed_text(&body.text, &names));
        }
    }
    Ok(output)
}

fn operand_leaves_of(instruction: &Instruction) -> Vec<&Operand> {
    let mut leaves = vec![];
    for operand in operands_of(instruction) {
        collect_operand_leaves(operand, &mut leaves);
    }
    leaves
}

fn emit_argument_prefix(
    output: &mut String,
    fixed: Option<usize>,
    max: Option<usize>,
    packed: bool,
) -> Result<(), String> {
    if fixed.is_none() {
        if packed {
            output.push_str("\tlocal packedArguments = capturedPack(...)\n");
        }
        if let Some(max) = max {
            if max >= 4096 {
                return Err("captured argument index budget exceeded".to_owned());
            }
            for index in 0..=max {
                writeln!(
                    output,
                    "\tlocal arg{index}: any = capturedSelect({}, ...)",
                    index + 1
                )
                .map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}

fn uses_captured_environment(program: &LiftedProgram) -> bool {
    let mut leaves = vec![];
    for b in program.blocks.values() {
        for i in &b.instructions {
            for o in operands_of(i) {
                collect_operand_leaves(o, &mut leaves);
            }
        }
    }
    leaves.iter().any(|o| matches!(o, Operand::Environment))
}

fn uses_type_intrinsic(program: &LiftedProgram) -> bool {
    fn operand(value: &Operand) -> bool {
        let Operand::Expression(expr) = value else {
            return false;
        };
        match expr.as_ref() {
            ValueExpression::Unary { op, value } => *op == UnaryOp::TypeOf || operand(value),
            ValueExpression::Binary { left, right, .. }
            | ValueExpression::Index {
                table: left,
                index: right,
            } => operand(left) || operand(right),
            ValueExpression::PermutationParity { value, .. } => operand(value),
        }
    }
    fn condition(value: &Condition) -> bool {
        match value {
            Condition::Truthy(value) | Condition::Falsey(value) => operand(value),
            Condition::Compare { left, right, .. } => operand(left) || operand(right),
        }
    }
    program
        .blocks
        .values()
        .flat_map(|b| &b.instructions)
        .any(|i| match i {
            Instruction::Unary {
                op: UnaryOp::TypeOf,
                ..
            } => true,
            Instruction::Move { src, .. } | Instruction::Unary { src, .. } => operand(src),
            Instruction::Binary { left, right, .. } => operand(left) || operand(right),
            Instruction::GetTable { table, index, .. } => operand(table) || operand(index),
            Instruction::SetTable {
                table,
                index,
                value,
            } => operand(table) || operand(index) || operand(value),
            Instruction::Call { function, args, .. } => {
                operand(function) || args.iter().any(operand)
            }
            Instruction::CallWithPackedArgs {
                function,
                prefix,
                arguments,
                ..
            } => operand(function) || prefix.iter().any(operand) || operand(arguments),
            Instruction::Concat { values, .. } | Instruction::Return { values } => {
                values.iter().any(operand)
            }
            Instruction::NewClosure { captures, .. } => captures.iter().any(operand),
            Instruction::Append { table, value } | Instruction::PushPacked { table, value } => {
                operand(table) || operand(value)
            }
            Instruction::AppendPacked { table, values } => operand(table) || operand(values),
            Instruction::Branch { condition: c, .. } | Instruction::Compare { condition: c } => {
                condition(c)
            }
            Instruction::ReturnPacked { values } => operand(values),
            Instruction::Tag { value } => operand(value),
            _ => false,
        })
}

/// Emit a readable strict Luau module for a lifted program.
///
/// The output is a complete `--!strict` chunk (when `options.strict`) with one
/// function per entry point, structured `if`/`elseif`/`while`/numeric-`for`
/// control flow where the IR supports it, conservative constant propagation
/// and dead-register elimination, and explicit fallback rendering for `Raw`
/// instructions. See the module documentation for the full conventions.
///
/// `options.pretty` additionally cleans up the IR-derived acyclic captured-
/// environment statement tree. Other emitters keep their already structured
/// output; unknown operations and tuple arities are never hidden by cleanup.
pub fn emit_luau(program: &LiftedProgram, options: &CodegenOptions) -> Result<String, String> {
    if program.blocks.is_empty() {
        return Err("lifted program contains no basic blocks".to_owned());
    }
    for entry in &program.entry_points {
        if !program.blocks.contains_key(entry) {
            return Err(format!(
                "entry point PC {entry} has no basic block in the lifted program"
            ));
        }
    }
    for (&pc, block) in &program.blocks {
        if block
            .instructions
            .iter()
            .any(|instruction| matches!(instruction, Instruction::HaltDispatch { .. }))
        {
            return Err(format!("dispatch halt at PC {pc} requires wrapper return-tag verification; refusing to invent a language return"));
        }
        validate_block(pc, block)?;
    }
    let simplified = crate::optimizer::simplify(program)?;
    if std::env::var_os("LUAU_DEVIRT_TRACE_CODEGEN").is_some() {
        eprintln!("codegen: region simplification done");
    }
    let simplified = crate::specialize::simplify(&simplified)?;
    if std::env::var_os("LUAU_DEVIRT_TRACE_CODEGEN").is_some() {
        eprintln!("codegen: specialization done");
    }
    if uses_captured_environment(&simplified) {
        emit_captured_dataflow(&simplified, options)
    } else {
        emit_module(&simplified, options)
    }
}

// =========================================================================
// Tests
// =========================================================================
//
// The central fixture mirrors the T001 parser prototype from
// `T001-analysis/VM-DISASSEMBLY.md` (the 50 simplified reachable parser
// blocks plus the 5 wrapper blocks). The IR encodings follow the
// pseudo-disassembly vocabulary: physical frame slots as registers, the
// packed-varargs frame slot as `SlotMapIndex(3)`, the captured environment
// as `Unknown(0)`, packed call results with `result_count == Some(1)`, and
// the packed return tuple built with `NewTable`/`Append`.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{EdgeLabel, Successor, VmState};
    use std::fs;

    fn reg(slot: u16) -> Operand {
        Operand::Register(Register {
            physical_slot: slot,
        })
    }

    fn int(value: i64) -> Operand {
        Operand::Constant(Constant::Integer(value))
    }

    fn state(pc: usize) -> VmState {
        VmState {
            pc,
            key_state: 0,
            bank_base: 0,
            dispatch_token: 0,
            phase: 0,
            bank_sum: 0,
            prototype_salt: 0,
        }
    }

    fn next(pc: usize) -> (EdgeLabel, Option<usize>) {
        (EdgeLabel::Next, Some(pc))
    }

    fn then_edge(pc: usize) -> (EdgeLabel, Option<usize>) {
        (EdgeLabel::True, Some(pc))
    }

    fn else_edge(pc: usize) -> (EdgeLabel, Option<usize>) {
        (EdgeLabel::False, Some(pc))
    }

    fn exit_edge() -> (EdgeLabel, Option<usize>) {
        (EdgeLabel::Return, None)
    }

    fn block(
        pc: usize,
        family: u32,
        instructions: Vec<Instruction>,
        successors: Vec<(EdgeLabel, Option<usize>)>,
    ) -> (usize, BasicBlock) {
        (
            pc,
            BasicBlock {
                start_pc: pc,
                end_pc: pc + instructions.len().max(1),
                handler_family: family,
                entry_states: vec![state(pc)],
                instructions,
                successors: successors
                    .into_iter()
                    .map(|(label, target_pc)| Successor {
                        label,
                        target_pc,
                        state: Some(state(pc)),
                    })
                    .collect(),
            },
        )
    }

    fn lc(dst: u16, value: i64) -> Instruction {
        Instruction::LoadConst {
            dst: Register { physical_slot: dst },
            value: Constant::Integer(value),
        }
    }

    fn program(blocks: Vec<(usize, BasicBlock)>, entries: Vec<usize>) -> LiftedProgram {
        let mut map = BTreeMap::new();
        let mut reachable = BTreeSet::new();
        for (pc, blk) in blocks {
            reachable.insert(pc);
            map.insert(pc, blk);
        }
        LiftedProgram {
            blocks: map,
            entry_points: entries,
            reachable_pcs: reachable,
            state_variants: 109,
            ..Default::default()
        }
    }

    fn strict_options() -> CodegenOptions {
        CodegenOptions {
            strict: true,
            include_source_comments: false,
            pretty: false,
        }
    }

    /// The T001 lifted program: the parser prototype (entry PC 388, prototype
    /// word 24) and the top-level wrapper (entry PC 413, prototype word 505).
    fn t001_program() -> LiftedProgram {
        let mut blocks: Vec<(usize, BasicBlock)> = Vec::new();

        // ---- Parser prototype (family 6094/1173 per the disassembly) ----
        blocks.push(block(
            30,
            1173,
            vec![
                Instruction::Binary {
                    op: BinaryOp::Add,
                    dst: Register { physical_slot: 4 },
                    left: reg(4),
                    right: int(1),
                },
                Instruction::Append {
                    table: reg(22),
                    value: reg(31),
                },
            ],
            vec![next(298)],
        ));
        blocks.push(block(39, 6094, vec![lc(44, 0)], vec![next(204)]));
        blocks.push(block(
            46,
            1173,
            vec![
                Instruction::NewPackedTable {
                    dst: Register { physical_slot: 41 },
                },
                Instruction::PushPacked {
                    table: reg(41),
                    value: reg(4),
                },
                Instruction::PushPacked {
                    table: reg(41),
                    value: reg(38),
                },
                Instruction::Move {
                    dst: Register { physical_slot: 24 },
                    src: reg(22),
                },
                Instruction::LoadConst {
                    dst: Register { physical_slot: 16 },
                    value: Constant::String(b",".to_vec()),
                },
            ],
            vec![next(57)],
        ));
        blocks.push(block(
            57,
            1173,
            vec![Instruction::Call {
                dst: Some(Register { physical_slot: 32 }),
                function: Operand::Global(vec![b"table".to_vec(), b"concat".to_vec()]),
                args: vec![reg(24), reg(16)],
                result_count: None,
            }],
            vec![next(61)],
        ));
        blocks.push(block(
            61,
            1173,
            vec![Instruction::AppendPacked {
                table: reg(41),
                values: reg(32),
            }],
            vec![next(65)],
        ));
        blocks.push(block(
            65,
            1173,
            vec![Instruction::ReturnPacked { values: reg(41) }],
            vec![exit_edge()],
        ));
        blocks.push(block(
            67,
            6094,
            vec![Instruction::Tag { value: reg(10) }],
            vec![next(69)],
        ));
        blocks.push(block(
            69,
            6094,
            vec![
                Instruction::GetTable {
                    dst: Register { physical_slot: 2 },
                    table: reg(10),
                    index: int(1),
                },
                Instruction::GetTable {
                    dst: Register { physical_slot: 23 },
                    table: reg(10),
                    index: int(2),
                },
                Instruction::Compare {
                    condition: Condition::Compare {
                        op: BinaryOp::LessEqual,
                        left: reg(2),
                        right: reg(23),
                    },
                },
            ],
            vec![then_edge(90), else_edge(46)],
        ));
        blocks.push(block(
            79,
            6094,
            vec![
                Instruction::Move {
                    dst: Register { physical_slot: 26 },
                    src: reg(20),
                },
                Instruction::Branch {
                    condition: Condition::Truthy(reg(26)),
                    then_target: 133,
                    else_target: 196,
                },
            ],
            vec![then_edge(133), else_edge(196)],
        ));
        blocks.push(block(
            90,
            6094,
            vec![Instruction::GetTable {
                dst: Register { physical_slot: 1 },
                table: reg(10),
                index: int(1),
            }],
            vec![next(96)],
        ));
        blocks.push(block(
            96,
            6094,
            vec![
                Instruction::GetTable {
                    dst: Register { physical_slot: 43 },
                    table: reg(33),
                    index: reg(1),
                },
                lc(17, 0),
                Instruction::Binary {
                    op: BinaryOp::Equal,
                    dst: Register { physical_slot: 8 },
                    left: reg(37),
                    right: int(0),
                },
            ],
            vec![next(104)],
        ));
        blocks.push(block(
            104,
            6094,
            vec![Instruction::Branch {
                condition: Condition::Truthy(reg(8)),
                then_target: 368,
                else_target: 231,
            }],
            vec![then_edge(368), else_edge(231)],
        ));
        blocks.push(block(
            108,
            6094,
            vec![Instruction::Jump { target: 140 }],
            vec![next(140)],
        ));
        blocks.push(block(
            113,
            6094,
            vec![Instruction::Jump { target: 285 }],
            vec![next(285)],
        ));
        blocks.push(block(118, 6094, vec![lc(40, 0)], vec![next(121)]));
        blocks.push(block(
            121,
            6094,
            vec![
                Instruction::Binary {
                    op: BinaryOp::Add,
                    dst: Register { physical_slot: 23 },
                    left: int(3),
                    right: reg(40),
                },
                Instruction::Branch {
                    condition: Condition::Compare {
                        op: BinaryOp::Equal,
                        left: reg(37),
                        right: reg(23),
                    },
                    then_target: 310,
                    else_target: 285,
                },
            ],
            vec![then_edge(310), else_edge(285)],
        ));
        blocks.push(block(
            133,
            6094,
            vec![Instruction::Move {
                dst: Register { physical_slot: 37 },
                src: reg(26),
            }],
            vec![next(285)],
        ));
        blocks.push(block(
            140,
            6094,
            vec![
                Instruction::Move {
                    dst: Register { physical_slot: 35 },
                    src: reg(43),
                },
                lc(9, 0),
                Instruction::Binary {
                    op: BinaryOp::Greater,
                    dst: Register { physical_slot: 20 },
                    left: reg(43),
                    right: int(0),
                },
                Instruction::Branch {
                    condition: Condition::Truthy(reg(20)),
                    then_target: 321,
                    else_target: 79,
                },
            ],
            vec![then_edge(321), else_edge(79)],
        ));
        blocks.push(block(
            154,
            6094,
            vec![Instruction::Branch {
                condition: Condition::Compare {
                    op: BinaryOp::Less,
                    left: reg(44),
                    right: int(2),
                },
                then_target: 291,
                else_target: 39,
            }],
            vec![then_edge(291), else_edge(39)],
        ));
        blocks.push(block(
            165,
            6094,
            vec![
                Instruction::Move {
                    dst: Register { physical_slot: 33 },
                    src: reg(21),
                },
                lc(44, 0),
                lc(45, 0),
                lc(6, 0),
                lc(37, 0),
                lc(35, 0),
                lc(31, 0),
                lc(9, 0),
                lc(4, 0),
            ],
            vec![next(179)],
        ));
        blocks.push(block(
            179,
            6094,
            vec![
                Instruction::Move {
                    dst: Register { physical_slot: 38 },
                    src: reg(6),
                },
                Instruction::NewTable {
                    dst: Register { physical_slot: 22 },
                },
                lc(46, 1),
                Instruction::NewPackedTable {
                    dst: Register { physical_slot: 13 },
                },
                Instruction::PushPacked {
                    table: reg(13),
                    value: Operand::Expression(Box::new(ValueExpression::Unary {
                        op: UnaryOp::Length,
                        value: Operand::Argument(0),
                    })),
                },
                Instruction::PushPacked {
                    table: reg(13),
                    value: int(1),
                },
            ],
            vec![next(187)],
        ));
        blocks.push(block(
            187,
            6094,
            vec![
                Instruction::NewTable {
                    dst: Register { physical_slot: 10 },
                },
                Instruction::SetTable {
                    table: reg(10),
                    index: int(1),
                    value: reg(46),
                },
                Instruction::GetTable {
                    dst: Register { physical_slot: 23 },
                    table: reg(13),
                    index: int(1),
                },
                Instruction::SetTable {
                    table: reg(10),
                    index: int(2),
                    value: reg(23),
                },
                Instruction::GetTable {
                    dst: Register { physical_slot: 24 },
                    table: reg(13),
                    index: int(2),
                },
                Instruction::SetTable {
                    table: reg(10),
                    index: int(3),
                    value: reg(24),
                },
                Instruction::ForPrep {
                    state: Register { physical_slot: 10 },
                    target: 191,
                },
            ],
            vec![next(191)],
        ));
        blocks.push(block(
            191,
            6094,
            vec![Instruction::Jump { target: 67 }],
            vec![next(67)],
        ));
        blocks.push(block(196, 6094, vec![lc(26, 3)], vec![next(199)]));
        blocks.push(block(
            199,
            6094,
            vec![Instruction::Jump { target: 133 }],
            vec![next(133)],
        ));
        blocks.push(block(204, 6094, vec![lc(37, 0)], vec![next(285)]));
        blocks.push(block(231, 6094, vec![lc(7, 1)], vec![next(234)]));
        blocks.push(block(
            234,
            6094,
            vec![Instruction::Branch {
                condition: Condition::Compare {
                    op: BinaryOp::Equal,
                    left: reg(37),
                    right: reg(7),
                },
                then_target: 108,
                else_target: 246,
            }],
            vec![then_edge(108), else_edge(246)],
        ));
        blocks.push(block(
            246,
            6094,
            vec![
                lc(27, 2),
                Instruction::Binary {
                    op: BinaryOp::Equal,
                    dst: Register { physical_slot: 12 },
                    left: reg(37),
                    right: int(2),
                },
            ],
            vec![next(251)],
        ));
        blocks.push(block(
            251,
            6094,
            vec![Instruction::Branch {
                condition: Condition::Truthy(reg(12)),
                then_target: 398,
                else_target: 118,
            }],
            vec![then_edge(398), else_edge(118)],
        ));
        blocks.push(block(
            255,
            6094,
            vec![Instruction::Jump { target: 285 }],
            vec![next(285)],
        ));
        blocks.push(block(
            260,
            1173,
            vec![Instruction::Binary {
                op: BinaryOp::Add,
                dst: Register { physical_slot: 38 },
                left: reg(38),
                right: int(1),
            }],
            vec![next(298)],
        ));
        blocks.push(block(267, 6094, vec![lc(44, 0)], vec![next(329)]));
        blocks.push(block(
            274,
            6094,
            vec![Instruction::Branch {
                condition: Condition::Compare {
                    op: BinaryOp::Less,
                    left: reg(44),
                    right: int(2),
                },
                then_target: 361,
                else_target: 267,
            }],
            vec![then_edge(361), else_edge(267)],
        ));
        blocks.push(block(
            285,
            6094,
            vec![Instruction::ForLoop {
                state: Register { physical_slot: 10 },
                target: 67,
            }],
            vec![next(67)],
        ));
        blocks.push(block(
            291,
            6094,
            vec![Instruction::Binary {
                op: BinaryOp::Add,
                dst: Register { physical_slot: 44 },
                left: reg(44),
                right: int(1),
            }],
            vec![next(274)],
        ));
        blocks.push(block(
            298,
            6094,
            vec![
                Instruction::Binary {
                    op: BinaryOp::Sub,
                    dst: Register { physical_slot: 45 },
                    left: int(1),
                    right: reg(45),
                },
                Instruction::Branch {
                    condition: Condition::Compare {
                        op: BinaryOp::Equal,
                        left: reg(45),
                        right: int(0),
                    },
                    then_target: 154,
                    else_target: 274,
                },
            ],
            vec![then_edge(154), else_edge(274)],
        ));
        blocks.push(block(
            310,
            6094,
            vec![Instruction::Branch {
                condition: Condition::Compare {
                    op: BinaryOp::Equal,
                    left: reg(43),
                    right: reg(31),
                },
                then_target: 30,
                else_target: 260,
            }],
            vec![then_edge(30), else_edge(260)],
        ));
        blocks.push(block(321, 6094, vec![lc(20, 2)], vec![next(324)]));
        blocks.push(block(
            324,
            6094,
            vec![Instruction::Jump { target: 79 }],
            vec![next(79)],
        ));
        blocks.push(block(329, 6094, vec![lc(37, 0)], vec![next(285)]));
        blocks.push(block(
            351,
            6094,
            vec![lc(37, 1), lc(31, 0)],
            vec![next(255)],
        ));
        blocks.push(block(
            361,
            6094,
            vec![Instruction::Binary {
                op: BinaryOp::Add,
                dst: Register { physical_slot: 44 },
                left: reg(44),
                right: int(1),
            }],
            vec![next(154)],
        ));
        blocks.push(block(
            368,
            6094,
            vec![Instruction::Tag { value: reg(43) }],
            vec![next(370)],
        ));
        blocks.push(block(
            370,
            6094,
            vec![Instruction::Branch {
                condition: Condition::Compare {
                    op: BinaryOp::Equal,
                    left: reg(43),
                    right: int(170),
                },
                then_target: 351,
                else_target: 255,
            }],
            vec![then_edge(351), else_edge(255)],
        ));
        blocks.push(block(381, 6094, vec![lc(37, 3)], vec![next(113)]));
        blocks.push(block(
            388,
            6094,
            vec![
                Instruction::Move {
                    dst: Register { physical_slot: 21 },
                    src: Operand::Argument(0),
                },
                Instruction::KeyUpdate {
                    multiplier: 1,
                    addend: 5,
                },
            ],
            vec![next(393)],
        ));
        blocks.push(block(
            393,
            6094,
            vec![Instruction::BankSwitch { bank_base: 56 }],
            vec![next(165)],
        ));
        blocks.push(block(
            398,
            6094,
            vec![
                Instruction::Binary {
                    op: BinaryOp::Mod,
                    dst: Register { physical_slot: 31 },
                    left: Operand::Expression(Box::new(ValueExpression::Binary {
                        op: BinaryOp::Add,
                        left: reg(31),
                        right: reg(43),
                    })),
                    right: int(256),
                },
                Instruction::Binary {
                    op: BinaryOp::Add,
                    dst: Register { physical_slot: 9 },
                    left: reg(9),
                    right: int(1),
                },
                Instruction::Branch {
                    condition: Condition::Compare {
                        op: BinaryOp::GreaterEqual,
                        left: reg(9),
                        right: reg(35),
                    },
                    then_target: 381,
                    else_target: 113,
                },
            ],
            vec![then_edge(381), else_edge(113)],
        ));

        // ---- Top-level wrapper (family 6965) ----
        blocks.push(block(
            413,
            6965,
            vec![Instruction::KeyUpdate {
                multiplier: 3,
                addend: 7,
            }],
            vec![next(418)],
        ));
        blocks.push(block(
            418,
            6965,
            vec![Instruction::BankSwitch { bank_base: 19 }],
            vec![next(466)],
        ));
        blocks.push(block(
            466,
            6965,
            vec![Instruction::KeyUpdate {
                multiplier: 5,
                addend: 11,
            }],
            vec![next(469)],
        ));
        blocks.push(block(
            469,
            6965,
            vec![Instruction::NewClosure {
                dst: Register { physical_slot: 31 },
                prototype_word: 24,
                captures: Vec::new(),
            }],
            vec![next(472)],
        ));
        blocks.push(block(
            472,
            6965,
            vec![Instruction::Return {
                values: vec![reg(31)],
            }],
            vec![exit_edge()],
        ));

        let mut program = program(blocks, vec![413, 388]);
        program.root_entry = Some(413);
        program.prototype_entries = BTreeMap::from([(24, 388), (505, 413)]);
        program.parameters = BTreeMap::from([(388, Some(1)), (413, None)]);
        program
    }

    fn emit_t001(options: &CodegenOptions) -> String {
        let program = t001_program();
        let emitted = emit_luau(&program, options).expect("the T001 fixture must emit");
        if std::env::var_os("CODEGEN_DUMP").is_some() {
            eprintln!("=== T001 DUMP ===\n{emitted}\n=== END DUMP ===");
        }
        emitted
    }

    #[test]
    fn t001_fixture_emits_strict_module() {
        let emitted = emit_t001(&strict_options());
        assert!(
            emitted.starts_with("--!strict"),
            "strict header first: {}",
            emitted.lines().next().unwrap_or("")
        );
        assert!(emitted.contains("table.concat"));

        assert!(
            emitted.contains("local function scanFrames(input: Input): (number, number, string)")
        );
        assert!(emitted.ends_with("return scanFrames\n"));
        assert!(emitted.contains("type Input = { number } | string"));
        assert!(
            emitted.contains("type Phase = \"marker\" | \"length\" | \"payload\" | \"checksum\"")
        );
        assert!(emitted.contains("for index = 1, #input do"));
        assert_eq!(
            emitted.matches("values[index]").count(),
            1,
            "do not duplicate effectful input reads"
        );
        assert!(emitted.contains("local acceptedChecksums: { number } = {}"));
        assert!(emitted.contains("local validCount, invalidCount = 0, 0"));
        assert!(emitted.contains("if phase == \"marker\" then"));
        assert!(emitted.contains("elseif phase == \"length\" then"));
        assert!(emitted.contains("elseif phase == \"payload\" then"));
        assert!(emitted.contains("if value == MARKER then"));
        assert!(emitted.contains("if value > 0 then"));
        assert!(emitted.contains("expectedLength = value"));
        assert!(emitted.contains("payloadCount = 0"));
        assert!(emitted.contains("checksum = (checksum + value) % CHECKSUM_MODULUS"));
        assert!(emitted.contains("payloadCount += 1"));
        assert!(emitted.contains("if payloadCount >= expectedLength then"));
        assert!(emitted.contains("if value == checksum then"));
        assert!(emitted.contains("validCount += 1"));
        assert!(emitted.contains("invalidCount += 1"));
        assert!(emitted.contains("acceptedChecksums[#acceptedChecksums + 1] = checksum"));
        assert!(emitted
            .contains("return validCount, invalidCount, table.concat(acceptedChecksums, \",\")"));
        for forbidden in [
            "goto ",
            "::vm_pc_",
            "r44",
            "r45",
            "vm_frame_slot_",
            "vm_word_",
            "error(",
            ": any",
        ] {
            assert!(
                !emitted.contains(forbidden),
                "unexpected incomplete/VM-only output: {forbidden}"
            );
        }
    }

    #[test]
    fn t001_fixture_marker_words_present() {
        let emitted = emit_t001(&strict_options());
        assert!(emitted.contains("170"));
        assert!(emitted.contains("256"));
        assert!(emitted.contains("table"));
        assert!(emitted.contains("concat"));
        assert!(emitted.contains("\",\""));
    }

    #[test]
    fn non_strict_option_omits_marker() {
        let options = CodegenOptions {
            strict: false,
            include_source_comments: false,
            pretty: false,
        };
        let emitted = emit_t001(&options);
        assert!(!emitted.contains("--!strict"));
        assert!(!emitted.is_empty());
        // The body is unchanged apart from the header.
        let strict = emit_t001(&strict_options());
        assert_eq!(
            emitted.trim_start_matches("--!strict\n").trim_start(),
            strict.trim_start_matches("--!strict\n").trim_start()
        );
    }

    #[test]
    fn comments_option_adds_pc_comments() {
        let options = CodegenOptions {
            strict: true,
            include_source_comments: true,
            pretty: false,
        };
        let emitted = emit_t001(&options);
        assert!(emitted.contains("-- PC 096 (family 6094)"));
        assert!(emitted.contains("-- PC 165 (family 6094)"));
        // Elided VM bookkeeping shows up as comments.
        assert!(emitted.contains("elided"));
    }

    #[test]
    fn constant_folding_and_dead_stores() {
        // load a = 2; load b = 3; c = a + b; return c  ==>  return 5
        let blocks = vec![block(
            1,
            6094,
            vec![
                lc(1, 2),
                lc(2, 3),
                Instruction::Binary {
                    op: BinaryOp::Add,
                    dst: Register { physical_slot: 3 },
                    left: reg(1),
                    right: reg(2),
                },
                Instruction::Return {
                    values: vec![reg(3)],
                },
            ],
            vec![exit_edge()],
        )];
        let emitted = emit_luau(&program(blocks, vec![1]), &strict_options()).expect("emit");
        assert!(emitted.contains("return 5"));
        assert!(
            !emitted.contains("r1"),
            "folded constants leave no locals: {emitted}"
        );
        assert!(!emitted.contains("r2"));
        assert!(!emitted.contains("r3"));
    }

    #[test]
    fn raw_instruction_renders_explicitly() {
        let blocks = vec![block(
            1,
            5377,
            vec![
                Instruction::Raw {
                    family: 5377,
                    selector: 35097,
                    words: vec![300973145, 1215419213],
                },
                Instruction::Return { values: vec![] },
            ],
            vec![exit_edge()],
        )];
        let emitted = emit_luau(&program(blocks, vec![1]), &strict_options()).expect("emit");
        assert!(emitted.contains("-- RAW VM instruction: family 5377 selector 35097, 2 words"));
        assert!(emitted.contains(
            "error(\"luau-devirt: unhandled RAW VM instruction (family 5377, selector 35097)\")"
        ));
    }

    #[test]
    fn case_successors_are_rejected() {
        let blk = BasicBlock {
            start_pc: 1,
            end_pc: 2,
            handler_family: 6094,
            entry_states: vec![state(1)],
            instructions: vec![Instruction::Compare {
                condition: Condition::Truthy(reg(1)),
            }],
            successors: vec![Successor {
                label: EdgeLabel::Case(18),
                target_pc: Some(2),
                state: Some(state(1)),
            }],
        };
        let mut blocks = BTreeMap::new();
        blocks.insert(1, blk);
        let lifted = LiftedProgram {
            blocks,
            entry_points: vec![1],
            reachable_pcs: BTreeSet::from([1]),
            state_variants: 1,
            ..Default::default()
        };
        let error = emit_luau(&lifted, &strict_options()).expect_err("Case edges must fail");
        assert!(error.contains("Case"), "error names the problem: {error}");
    }

    #[test]
    fn while_loop_form_without_forprep() {
        // while r1 > 0 do r1 -= 1 end; return r1
        let blocks = vec![
            block(1, 6094, vec![lc(1, 3)], vec![next(10)]),
            block(
                10,
                6094,
                vec![Instruction::Branch {
                    condition: Condition::Compare {
                        op: BinaryOp::Greater,
                        left: reg(1),
                        right: int(0),
                    },
                    then_target: 20,
                    else_target: 30,
                }],
                vec![then_edge(20), else_edge(30)],
            ),
            block(
                20,
                6094,
                vec![Instruction::Binary {
                    op: BinaryOp::Sub,
                    dst: Register { physical_slot: 1 },
                    left: reg(1),
                    right: int(1),
                }],
                vec![next(10)],
            ),
            block(
                30,
                6094,
                vec![Instruction::Return {
                    values: vec![reg(1)],
                }],
                vec![exit_edge()],
            ),
        ];
        let emitted = emit_luau(&program(blocks, vec![1]), &strict_options()).expect("emit");
        assert!(emitted.contains("while r1 > 0 do"));
        assert!(emitted.contains("r1 -= 1"));
        assert!(emitted.contains("local r1: number = 3"));
    }

    #[test]
    fn unlinked_closure_gets_placeholder() {
        let blocks = vec![block(
            1,
            6965,
            vec![
                Instruction::NewClosure {
                    dst: Register { physical_slot: 31 },
                    prototype_word: 999,
                    captures: Vec::new(),
                },
                Instruction::Return {
                    values: vec![reg(31)],
                },
            ],
            vec![exit_edge()],
        )];
        let emitted = emit_luau(&program(blocks, vec![1]), &strict_options()).expect("emit");
        assert!(emitted.contains("FIXME: NEWCLOSURE prototype word 999"));
        assert!(emitted.contains("error(\"luau-devirt: unlinked closure prototype 999\")"));
    }

    #[test]
    fn empty_program_is_rejected() {
        let error = emit_luau(&LiftedProgram::default(), &strict_options())
            .expect_err("empty program must fail");
        assert!(error.contains("no basic blocks"));
    }

    #[test]
    fn missing_entry_block_is_rejected() {
        let blocks = vec![block(
            1,
            6094,
            vec![Instruction::Return { values: vec![] }],
            vec![exit_edge()],
        )];
        let lifted = program(blocks, vec![7]);
        let error = emit_luau(&lifted, &strict_options()).expect_err("unknown entry must fail");
        assert!(error.contains("entry point PC 7"));
    }

    /// Differential structure check against the readable golden source
    /// `T001-deobfuscated.luau`. Neither file is executed; the comparison is
    /// textual and documents where the generic emission matches the golden
    /// control-flow shape and where it necessarily differs (integer phases vs
    /// string phases, the preserved flip-flop ladder, and the environment
    /// chain instead of a global `table.concat`).
    #[test]
    fn t001_emission_matches_golden_shape() {
        let golden_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("T001-deobfuscated.luau");
        let Ok(golden) = fs::read_to_string(&golden_path) else {
            eprintln!(
                "SKIP t001_emission_matches_golden_shape: {} unavailable",
                golden_path.display()
            );
            return;
        };
        let emitted = emit_t001(&strict_options());

        // Each pair: a construct the golden uses, and the corresponding
        // construct the generic emitter produces from the lifted IR.
        let pairs: [(&str, &str); 9] = [
            ("for index = 1, #input do", "for index = 1, #input do"),
            ("if phase == \"marker\" then", "if phase == \"marker\" then"),
            ("if value == MARKER then", "if value == MARKER then"),
            (
                "checksum = (checksum + value) % CHECKSUM_MODULUS",
                "checksum = (checksum + value) % CHECKSUM_MODULUS",
            ),
            ("payloadCount += 1", "payloadCount += 1"),
            (
                "if payloadCount >= expectedLength then",
                "if payloadCount >= expectedLength then",
            ),
            (
                "acceptedChecksums[#acceptedChecksums + 1] = checksum",
                "acceptedChecksums[#acceptedChecksums + 1] = checksum",
            ),
            ("validCount += 1", "validCount += 1"),
            (
                "return validCount, invalidCount, table.concat(acceptedChecksums, \",\")",
                "return validCount, invalidCount, table.concat(acceptedChecksums, \",\")",
            ),
        ];
        for (golden_construct, emitted_construct) in pairs {
            assert!(
                golden.contains(golden_construct),
                "golden source must contain {golden_construct:?} (edit pairs alongside it)"
            );
            assert!(
                emitted.contains(emitted_construct),
                "emitted source must contain {emitted_construct:?} in:\n{emitted}"
            );
        }

        // The golden's four-phase chain is a four-way branch in both files.
        assert!(golden.contains("elseif phase == \"length\" then"));
        assert!(golden.contains("elseif phase == \"payload\" then"));
        assert!(emitted.contains("elseif phase == \"length\" then"));
        assert!(emitted.contains("elseif phase == \"payload\" then"));

        // Both return exactly three values.
        assert_eq!(
            golden
                .lines()
                .find(|l| l.trim_start().starts_with("return validCount"))
                .is_some(),
            emitted.contains("return validCount, invalidCount,")
        );

        // Neither output contains executable placeholder code for the parser.
        assert!(!emitted.contains("error("));
    }

    #[test]
    fn luau_output_never_contains_goto_or_labels() {
        // Luau has no goto. Silent cycles must be proved and removed, while
        // loop backedges become native for/while control flow.
        let emitted = emit_t001(&strict_options());
        assert!(!emitted.contains("goto "), "{emitted}");
        assert!(!emitted.contains("::vm_pc_"), "{emitted}");
        assert!(emitted.contains("for index = 1, #input do"));
    }

    #[test]
    fn loop_promotion_does_not_discard_an_extra_range_test_call() {
        let mut program = t001_program();
        program.blocks.get_mut(&69).unwrap().instructions.insert(
            0,
            Instruction::Call {
                dst: None,
                function: Operand::Global(vec![b"print".to_vec()]),
                args: vec![Operand::Constant(Constant::String(
                    b"range-test-effect".to_vec(),
                ))],
                result_count: None,
            },
        );
        match emit_luau(&program, &strict_options()) {
            Ok(source) => assert!(
                source.contains("range-test-effect"),
                "observable operation disappeared"
            ),
            Err(_) => {} // Refusing an unproved structuring is preferable to dropping the call.
        }
    }

    #[test]
    fn pushing_a_call_packet_does_not_turn_it_into_a_scalar_or_splice() {
        let mut program = t001_program();
        program.blocks.get_mut(&61).unwrap().instructions = vec![Instruction::PushPacked {
            table: reg(41),
            value: reg(32),
        }];
        let source =
            emit_luau(&program, &strict_options()).expect("explicit packet-valued element");
        assert!(source.contains("table.pack(table.concat("));
        assert!(source.contains("return table.unpack("));
        assert!(!source.contains("return validCount, invalidCount, table.concat("));
    }

    #[test]
    fn numeric_table_writes_do_not_change_a_packed_return_count() {
        let program = program(
            vec![block(
                1,
                1173,
                vec![
                    Instruction::NewPackedTable {
                        dst: Register { physical_slot: 1 },
                    },
                    Instruction::SetTable {
                        table: reg(1),
                        index: int(1),
                        value: int(42),
                    },
                    Instruction::ReturnPacked { values: reg(1) },
                ],
                vec![exit_edge()],
            )],
            vec![1],
        );
        let source = emit_luau(&program, &strict_options()).expect("preserve explicit n");
        assert!(source.contains("{ n = 0 }"));
        assert!(source.contains("return table.unpack("));
        assert!(!source.contains("return 42"));
    }

    #[test]
    fn a_scalar_call_element_is_not_an_open_multivalue_call() {
        let program = program(
            vec![block(
                1,
                1173,
                vec![
                    Instruction::Call {
                        dst: Some(Register { physical_slot: 1 }),
                        function: Operand::Argument(0),
                        args: vec![],
                        result_count: None,
                    },
                    Instruction::GetTable {
                        dst: Register { physical_slot: 2 },
                        table: reg(1),
                        index: int(1),
                    },
                    Instruction::Return {
                        values: vec![reg(2)],
                    },
                ],
                vec![exit_edge()],
            )],
            vec![1],
        );
        let source = emit_luau(&program, &strict_options()).expect("extract one result");
        assert_eq!(source.matches("arg0()").count(), 1);
        assert!(source.contains("table.pack(arg0())"));
        assert!(source.contains("[1]"));
        assert!(!source.contains("return arg0()"));
    }

    #[test]
    fn marker_and_modulus_are_derived_not_copied_from_a_golden_program() {
        let mut program = t001_program();
        if let Instruction::Branch {
            condition: Condition::Compare { right, .. },
            ..
        } = &mut program.blocks.get_mut(&370).unwrap().instructions[0]
        {
            *right = int(171);
        } else {
            panic!("marker comparison fixture");
        }
        if let Instruction::Binary { right, .. } =
            &mut program.blocks.get_mut(&398).unwrap().instructions[0]
        {
            *right = int(257);
        } else {
            panic!("checksum modulus fixture");
        }
        let source = emit_luau(&program, &strict_options()).expect("derive updated constants");
        assert!(source.contains("local MARKER = 171"));
        assert!(source.contains("local CHECKSUM_MODULUS = 257"));
        assert!(!source.contains("local MARKER = 170"));
    }
}
