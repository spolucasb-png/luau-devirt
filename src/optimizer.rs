//! Static, typed-IR simplification for lifted VM programs.
//!
//! This module never executes Lua, never reads dynamic input, and never
//! guesses at tuple semantics.  It only reasons about the lifted [`Instruction`]
//! graph in [`LiftedProgram`].
//!
//! # What is proven here
//!
//! A *silent region* is a connected subgraph that starts at a branch whose
//! condition reads only registers that are **not** output-relevant, contains
//! no observable operations (no calls, table reads/writes, tuple pushes,
//! returns, raw handlers, or throwing operations), and whose every path ends
//! at the same successor block with the same sequence of relevant effects.
//!
//! A silent region may contain cycles.  Such a cycle is only foldable if we
//! can prove it terminates.  We use a structural monotone-counter proof
//! (equivalent to a bounded set-constant analysis with branch refinement):
//! a cyclic SCC must contain a junk register that is
//!
//! * only ever **incremented by a positive constant** inside the SCC
//!   (no resets, decrements, or other writes there),
//! * incremented on **every** cycle of the SCC, and
//! * tested by a comparison branch whose "threshold reached" outcome leaves
//!   the SCC, and which itself lies on every cycle of the SCC.
//!
//! Since the counter strictly increases on every cycle and is never decreased
//! inside the SCC, an infinite path would force it past the threshold, which
//! sends control out of the SCC -- a contradiction.  Regions that cannot be
//! proven terminating are left unchanged (conservative), so possibly
//! nonterminating loops are never erased.
//!
//! Output-relevant registers are derived by backward def-use from returns,
//! calls, and mutable list/tuple/table writes.  A branch condition only becomes
//! relevant when its successors' first relevant effects actually differ;
//! this is what keeps the R44/R45 flip-flop ladder "junk" while preserving the
//! phase register that every ladder exit resets.

use std::collections::{BTreeMap, BTreeSet};

use crate::ir::{
    BasicBlock, BinaryOp, Condition, Constant, EdgeLabel, Instruction, LiftedProgram, Operand,
};

/// Hard ceiling on blocks in a candidate region (guards against pathological
/// graphs and keeps the SCC analysis cheap).
const MAX_REGION_BLOCKS: usize = 4096;
/// Step budget for the bounded effect-signature walk.
const MAX_SIGNATURE_STEPS: usize = 512;
/// Number of fold passes (each fold removes at least one block).
const MAX_FOLD_ROUNDS: usize = 128;

// ---------------------------------------------------------------------------
// Operand / instruction register helpers
// ---------------------------------------------------------------------------

fn operand_regs(op: &Operand, out: &mut BTreeSet<u16>) {
    match op {
        Operand::Register(reg) => {
            out.insert(reg.physical_slot);
        }
        Operand::Expression(expr) => value_expr_regs(expr, out),
        Operand::Constant(_)
        | Operand::Argument(_)
        | Operand::Global(_)
        | Operand::Environment
        | Operand::SlotMapIndex(_)
        | Operand::Word(_)
        | Operand::Unknown(_) => {}
    }
}

fn value_expr_regs(expr: &crate::ir::ValueExpression, out: &mut BTreeSet<u16>) {
    use crate::ir::ValueExpression;
    match expr {
        ValueExpression::Unary { value, .. } => operand_regs(value, out),
        ValueExpression::Binary { left, right, .. } => {
            operand_regs(left, out);
            operand_regs(right, out);
        }
        ValueExpression::Index { table, index } => {
            operand_regs(table, out);
            operand_regs(index, out);
        }
        ValueExpression::PermutationParity { value, .. } => operand_regs(value, out),
    }
}

fn condition_regs(cond: &Condition, out: &mut BTreeSet<u16>) {
    match cond {
        Condition::Truthy(op) | Condition::Falsey(op) => operand_regs(op, out),
        Condition::Compare { left, right, .. } => {
            operand_regs(left, out);
            operand_regs(right, out);
        }
    }
}

/// Destination register written by an instruction, if any.
fn inst_dst(inst: &Instruction) -> Option<u16> {
    match inst {
        Instruction::LoadConst { dst, .. }
        | Instruction::Move { dst, .. }
        | Instruction::Unary { dst, .. }
        | Instruction::Binary { dst, .. }
        | Instruction::GetTable { dst, .. }
        | Instruction::NewTable { dst }
        | Instruction::NewPackedTable { dst }
        | Instruction::Concat { dst, .. }
        | Instruction::NewClosure { dst, .. } => Some(dst.physical_slot),
        Instruction::Call { dst: Some(dst), .. } => Some(dst.physical_slot),
        Instruction::HaltDispatch { pc_slot, .. } => Some(pc_slot.physical_slot),
        _ => None,
    }
}

/// All registers read by an instruction.  New packed-tuple instructions are
/// treated exactly like their ordinary list counterparts for relevance.
fn inst_reads(inst: &Instruction) -> BTreeSet<u16> {
    let mut regs = BTreeSet::new();
    match inst {
        Instruction::Nop
        | Instruction::LoadConst { .. }
        | Instruction::NewTable { .. }
        | Instruction::NewPackedTable { .. }
        | Instruction::Jump { .. }
        | Instruction::KeyUpdate { .. }
        | Instruction::BankSwitch { .. }
        | Instruction::Raw { .. } => {}
        Instruction::Move { src, .. } | Instruction::Unary { src, .. } => {
            operand_regs(src, &mut regs)
        }
        Instruction::Binary { left, right, .. } => {
            operand_regs(left, &mut regs);
            operand_regs(right, &mut regs);
        }
        Instruction::GetTable { table, index, .. } => {
            operand_regs(table, &mut regs);
            operand_regs(index, &mut regs);
        }
        Instruction::SetTable {
            table,
            index,
            value,
            ..
        } => {
            operand_regs(table, &mut regs);
            operand_regs(index, &mut regs);
            operand_regs(value, &mut regs);
        }
        Instruction::Append { table, value, .. } | Instruction::PushPacked { table, value, .. } => {
            operand_regs(table, &mut regs);
            operand_regs(value, &mut regs);
        }
        Instruction::AppendPacked { table, values, .. } => {
            operand_regs(table, &mut regs);
            operand_regs(values, &mut regs);
        }
        Instruction::Compare { condition } => condition_regs(condition, &mut regs),
        Instruction::Branch { condition, .. } => condition_regs(condition, &mut regs),
        Instruction::ForPrep { state, .. } | Instruction::ForLoop { state, .. } => {
            regs.insert(state.physical_slot);
        }
        Instruction::Call { function, args, .. } => {
            operand_regs(function, &mut regs);
            for arg in args {
                operand_regs(arg, &mut regs);
            }
        }
        Instruction::Concat { values, .. } => {
            for value in values {
                operand_regs(value, &mut regs);
            }
        }
        Instruction::NewClosure { captures, .. } => {
            for capture in captures {
                operand_regs(capture, &mut regs);
            }
        }
        Instruction::Tag { value } => operand_regs(value, &mut regs),
        Instruction::Return { values } => {
            for value in values {
                operand_regs(value, &mut regs);
            }
        }
        Instruction::ReturnPacked { values } => operand_regs(values, &mut regs),
        Instruction::HaltDispatch { bank_slot, .. } => {
            regs.insert(bank_slot.physical_slot);
        }
    }
    regs
}

fn inst_tag(inst: &Instruction) -> &'static str {
    match inst {
        Instruction::Nop => "Nop",
        Instruction::LoadConst { .. } => "LoadConst",
        Instruction::Move { .. } => "Move",
        Instruction::Unary { .. } => "Unary",
        Instruction::Binary { .. } => "Binary",
        Instruction::GetTable { .. } => "GetTable",
        Instruction::SetTable { .. } => "SetTable",
        Instruction::NewTable { .. } => "NewTable",
        Instruction::NewPackedTable { .. } => "NewPackedTable",
        Instruction::Append { .. } => "Append",
        Instruction::PushPacked { .. } => "PushPacked",
        Instruction::AppendPacked { .. } => "AppendPacked",
        Instruction::Compare { .. } => "Compare",
        Instruction::Jump { .. } => "Jump",
        Instruction::Branch { .. } => "Branch",
        Instruction::ForPrep { .. } => "ForPrep",
        Instruction::ForLoop { .. } => "ForLoop",
        Instruction::Call { .. } => "Call",
        Instruction::Concat { .. } => "Concat",
        Instruction::NewClosure { .. } => "NewClosure",
        Instruction::Tag { .. } => "Tag",
        Instruction::KeyUpdate { .. } => "KeyUpdate",
        Instruction::BankSwitch { .. } => "BankSwitch",
        Instruction::Return { .. } => "Return",
        Instruction::ReturnPacked { .. } => "ReturnPacked",
        Instruction::HaltDispatch { .. } => "HaltDispatch",
        Instruction::Raw { .. } => "Raw",
    }
}

// ---------------------------------------------------------------------------
// Instruction effect classification
// ---------------------------------------------------------------------------

enum Effect {
    Silent,
    /// A write to an output-relevant scalar register.  Carries the original
    /// instruction so a folded region can reproduce the effect verbatim.
    Write(Instruction),
    /// Observable / throwing / opaque operation: never removed.
    Boundary,
}

fn classify(inst: &Instruction, relevant: &BTreeSet<u16>) -> Effect {
    match inst {
        // All of these are observable, may allocate an escaping object, or may
        // throw.  A fold region may not contain them.
        Instruction::Call { .. }
        | Instruction::Concat { .. }
        | Instruction::GetTable { .. }
        | Instruction::SetTable { .. }
        | Instruction::Append { .. }
        | Instruction::PushPacked { .. }
        | Instruction::AppendPacked { .. }
        | Instruction::NewTable { .. }
        | Instruction::NewPackedTable { .. }
        | Instruction::NewClosure { .. }
        | Instruction::ForPrep { .. }
        | Instruction::ForLoop { .. }
        | Instruction::Return { .. }
        | Instruction::ReturnPacked { .. }
        | Instruction::HaltDispatch { .. }
        | Instruction::Raw { .. } => Effect::Boundary,
        Instruction::Branch { condition, .. } | Instruction::Compare { condition } => {
            let mut regs = BTreeSet::new();
            condition_regs(condition, &mut regs);
            if regs.iter().any(|r| relevant.contains(r)) {
                Effect::Boundary
            } else {
                Effect::Silent
            }
        }
        _ => match inst_dst(inst) {
            Some(dst) if relevant.contains(&dst) => Effect::Write(inst.clone()),
            _ => Effect::Silent,
        },
    }
}

/// Canonical key for a relevant write.  Junk registers are collapsed so two
/// paths that write the same relevant value from different junk sources still
/// compare equal (conservative in the opposite direction too: if operands
/// contain nested expressions we keep their debug form, which simply makes us
/// decline a fold rather than guess).
fn write_key(inst: &Instruction, relevant: &BTreeSet<u16>) -> String {
    fn key(op: &Operand, relevant: &BTreeSet<u16>) -> String {
        match op {
            Operand::Register(reg) => {
                if relevant.contains(&reg.physical_slot) {
                    format!("R{}", reg.physical_slot)
                } else {
                    "JUNK".to_owned()
                }
            }
            Operand::Constant(value) => format!("C{value:?}"),
            Operand::Expression(_)
            | Operand::Argument(_)
            | Operand::Global(_)
            | Operand::Environment => {
                format!("{op:?}")
            }
            Operand::SlotMapIndex(_) | Operand::Word(_) | Operand::Unknown(_) => {
                format!("{op:?}")
            }
        }
    }
    match inst {
        Instruction::LoadConst { dst, value } => format!("LC({},{value:?})", dst.physical_slot),
        Instruction::Move { dst, src } => {
            format!("MV({},{})", dst.physical_slot, key(src, relevant))
        }
        Instruction::Unary { op, dst, src } => {
            format!("UN({op:?},{},{})", dst.physical_slot, key(src, relevant))
        }
        Instruction::Binary {
            op,
            dst,
            left,
            right,
        } => format!(
            "BN({op:?},{},{},{})",
            dst.physical_slot,
            key(left, relevant),
            key(right, relevant)
        ),
        _ => format!("{inst:?}"),
    }
}

// ---------------------------------------------------------------------------
// Output-relevant register analysis
// ---------------------------------------------------------------------------

fn seed_relevant(program: &LiftedProgram) -> BTreeSet<u16> {
    let mut relevant = BTreeSet::new();
    for block in program.blocks.values() {
        for inst in &block.instructions {
            let mut regs = BTreeSet::new();
            match inst {
                Instruction::Return { values } => {
                    for value in values {
                        operand_regs(value, &mut regs);
                    }
                }
                Instruction::ReturnPacked { values } => operand_regs(values, &mut regs),
                Instruction::Call {
                    dst,
                    function,
                    args,
                    ..
                } => {
                    if let Some(dst) = dst {
                        regs.insert(dst.physical_slot);
                    }
                    operand_regs(function, &mut regs);
                    for arg in args {
                        operand_regs(arg, &mut regs);
                    }
                }
                Instruction::SetTable {
                    table,
                    index,
                    value,
                    ..
                } => {
                    operand_regs(table, &mut regs);
                    operand_regs(index, &mut regs);
                    operand_regs(value, &mut regs);
                }
                Instruction::Append { table, value, .. }
                | Instruction::PushPacked { table, value, .. } => {
                    operand_regs(table, &mut regs);
                    operand_regs(value, &mut regs);
                }
                Instruction::AppendPacked { table, values, .. } => {
                    operand_regs(table, &mut regs);
                    operand_regs(values, &mut regs);
                }
                Instruction::GetTable {
                    dst, table, index, ..
                } => {
                    regs.insert(dst.physical_slot);
                    operand_regs(table, &mut regs);
                    operand_regs(index, &mut regs);
                }
                Instruction::ForPrep { state, .. } | Instruction::ForLoop { state, .. } => {
                    regs.insert(state.physical_slot);
                }
                Instruction::NewClosure { dst, captures, .. } => {
                    regs.insert(dst.physical_slot);
                    for capture in captures {
                        operand_regs(capture, &mut regs);
                    }
                }
                Instruction::Concat { dst, values, .. } => {
                    regs.insert(dst.physical_slot);
                    for value in values {
                        operand_regs(value, &mut regs);
                    }
                }
                Instruction::NewTable { dst } | Instruction::NewPackedTable { dst } => {
                    regs.insert(dst.physical_slot);
                }
                _ => {}
            }
            relevant.extend(regs);
        }
    }
    relevant
}

fn backward_close(program: &LiftedProgram, relevant: &mut BTreeSet<u16>) {
    loop {
        let before = relevant.clone();
        for block in program.blocks.values() {
            for inst in block.instructions.iter().rev() {
                if let Some(dst) = inst_dst(inst) {
                    if relevant.contains(&dst) {
                        for read in inst_reads(inst) {
                            relevant.insert(read);
                        }
                    }
                }
            }
        }
        if *relevant == before {
            return;
        }
    }
}

/// Bounded union of effect strings reachable from `start_pc`, used only to
/// decide whether a branch condition feeds genuinely different behavior.
fn effect_signature(program: &LiftedProgram, start_pc: usize, relevant: &BTreeSet<u16>) -> String {
    let mut effects = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut stack = vec![start_pc];
    let mut steps = 0usize;
    while let Some(pc) = stack.pop() {
        if !visited.insert(pc) {
            continue;
        }
        steps += 1;
        if steps > MAX_SIGNATURE_STEPS || !program.blocks.contains_key(&pc) {
            effects.insert("UNKNOWN".to_owned());
            break;
        }
        let block = &program.blocks[&pc];
        let mut boundary = false;
        for inst in &block.instructions {
            match classify(inst, relevant) {
                Effect::Write(i) => {
                    effects.insert(write_key(&i, relevant));
                }
                Effect::Boundary => {
                    effects.insert(format!("BOUNDARY:{}", inst_tag(inst)));
                    boundary = true;
                    break;
                }
                Effect::Silent => {}
            }
        }
        if boundary {
            continue;
        }
        for succ in &block.successors {
            if let Some(target) = succ.target_pc {
                stack.push(target);
            }
        }
    }
    let mut text = String::new();
    for effect in effects {
        text.push_str(&effect);
        text.push('|');
    }
    text
}

fn compute_relevant(program: &LiftedProgram) -> BTreeSet<u16> {
    let mut relevant = seed_relevant(program);
    backward_close(program, &mut relevant);

    // Iteratively promote a condition's operands when its first relevant
    // effects differ.  Reclose after each round so newly relevant registers
    // pull in their own definitions.
    loop {
        let before = relevant.clone();
        let mut promote = BTreeSet::new();
        for block in program.blocks.values() {
            for inst in &block.instructions {
                let condition = match inst {
                    Instruction::Branch { condition, .. } => Some(condition),
                    Instruction::Compare { condition } => Some(condition),
                    _ => None,
                };
                let Some(condition) = condition else { continue };
                let mut cond_regs = BTreeSet::new();
                condition_regs(condition, &mut cond_regs);
                if cond_regs.is_empty() || cond_regs.iter().any(|r| relevant.contains(r)) {
                    continue;
                }
                let mut signatures = BTreeSet::new();
                for succ in &block.successors {
                    if let Some(target) = succ.target_pc {
                        signatures.insert(effect_signature(program, target, &relevant));
                    }
                }
                if signatures.len() > 1 {
                    condition_regs(condition, &mut promote);
                }
            }
        }
        if promote.is_empty() {
            break;
        }
        relevant.extend(promote);
        backward_close(program, &mut relevant);
        if relevant == before {
            break;
        }
    }
    relevant
}

// ---------------------------------------------------------------------------
// SCC helpers (iterative Kosaraju)
// ---------------------------------------------------------------------------

fn region_edges(program: &LiftedProgram, region: &BTreeSet<usize>) -> BTreeMap<usize, Vec<usize>> {
    let mut edges: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for &pc in region {
        edges.insert(pc, Vec::new());
    }
    for &pc in region {
        if let Some(block) = program.blocks.get(&pc) {
            let list = edges.get_mut(&pc).expect("region node present");
            for succ in &block.successors {
                if let Some(target) = succ.target_pc {
                    if region.contains(&target) {
                        list.push(target);
                    }
                }
            }
        }
    }
    edges
}

fn sccs(nodes: &BTreeSet<usize>, edges: &BTreeMap<usize, Vec<usize>>) -> Vec<BTreeSet<usize>> {
    let mut visited = BTreeSet::new();
    let mut order = Vec::new();
    for &start in nodes {
        if visited.contains(&start) {
            continue;
        }
        visited.insert(start);
        let mut stack = vec![(start, 0usize)];
        loop {
            let Some(frame) = stack.last_mut() else { break };
            let node = frame.0;
            let idx = frame.1;
            let neighbors: &[usize] = edges.get(&node).map(|v| v.as_slice()).unwrap_or(&[]);
            if idx >= neighbors.len() {
                order.push(node);
                stack.pop();
                continue;
            }
            let next = neighbors[idx];
            frame.1 += 1;
            if nodes.contains(&next) && !visited.contains(&next) {
                visited.insert(next);
                stack.push((next, 0));
            }
        }
    }

    let mut reverse: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for &node in nodes {
        reverse.insert(node, Vec::new());
    }
    for (&node, outs) in edges {
        if !nodes.contains(&node) {
            continue;
        }
        for &next in outs {
            if nodes.contains(&next) {
                reverse
                    .get_mut(&next)
                    .expect("region node present")
                    .push(node);
            }
        }
    }

    let mut assigned = BTreeSet::new();
    let mut result = Vec::new();
    for &start in order.iter().rev() {
        if assigned.contains(&start) {
            continue;
        }
        let mut component = BTreeSet::new();
        let mut stack = vec![start];
        assigned.insert(start);
        while let Some(node) = stack.pop() {
            component.insert(node);
            if let Some(preds) = reverse.get(&node) {
                for &pred in preds {
                    if !assigned.contains(&pred) {
                        assigned.insert(pred);
                        stack.push(pred);
                    }
                }
            }
        }
        result.push(component);
    }
    result
}

fn is_cyclic(program: &LiftedProgram, component: &BTreeSet<usize>) -> bool {
    if component.len() > 1 {
        return true;
    }
    let Some(&pc) = component.iter().next() else {
        return false;
    };
    program.blocks.get(&pc).is_some_and(|block| {
        block
            .successors
            .iter()
            .any(|succ| succ.target_pc == Some(pc))
    })
}

/// True when the subgraph induced by `component`, after deleting every edge
/// out of `excluded` blocks, contains no cycle.  This proves that every cycle
/// passes through at least one excluded block.
fn acyclic_without(
    program: &LiftedProgram,
    component: &BTreeSet<usize>,
    excluded: &BTreeSet<usize>,
) -> bool {
    let mut edges: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for &pc in component {
        edges.insert(pc, Vec::new());
    }
    for &pc in component {
        if excluded.contains(&pc) {
            continue;
        }
        if let Some(block) = program.blocks.get(&pc) {
            let list = edges.get_mut(&pc).expect("component node present");
            for succ in &block.successors {
                if let Some(target) = succ.target_pc {
                    if component.contains(&target) {
                        list.push(target);
                    }
                }
            }
        }
    }
    sccs(component, &edges)
        .iter()
        .all(|part| !is_cyclic(program, part))
}

// ---------------------------------------------------------------------------
// Structural monotone-counter termination proof
// ---------------------------------------------------------------------------

/// If every definition of `reg` inside `scc` is `reg = reg + k` with `k > 0`,
/// return the smallest step.  Resets, decrements, or other writes make the
/// register unusable as a monotone counter.
fn pure_increment_step(program: &LiftedProgram, scc: &BTreeSet<usize>, reg: u16) -> Option<i64> {
    let mut step: Option<i64> = None;
    for &pc in scc {
        let Some(block) = program.blocks.get(&pc) else {
            return None;
        };
        for inst in &block.instructions {
            if inst_dst(inst) != Some(reg) {
                continue;
            }
            match inst {
                Instruction::Binary {
                    op: BinaryOp::Add,
                    dst,
                    left: Operand::Register(left),
                    right: Operand::Constant(Constant::Integer(k)),
                    ..
                } if dst.physical_slot == reg && left.physical_slot == reg && *k > 0 => {
                    step = Some(step.map_or(*k, |old| old.min(*k)));
                }
                _ => return None,
            }
        }
    }
    step
}

/// Normalize a comparison so the register is on the left.  Returns
/// `(register, op, threshold)` when `reg` appears on exactly one side as a
/// plain register and the other side is an integer constant.
fn normalized_comparison(
    op: BinaryOp,
    left: &Operand,
    right: &Operand,
    reg: u16,
) -> Option<(BinaryOp, i64)> {
    let flipped = match (left, right) {
        (Operand::Register(l), Operand::Constant(Constant::Integer(k)))
            if l.physical_slot == reg =>
        {
            (op, *k)
        }
        (Operand::Constant(Constant::Integer(k)), Operand::Register(r))
            if r.physical_slot == reg =>
        {
            (
                match op {
                    BinaryOp::Less => BinaryOp::Greater,
                    BinaryOp::LessEqual => BinaryOp::GreaterEqual,
                    BinaryOp::Greater => BinaryOp::Less,
                    BinaryOp::GreaterEqual => BinaryOp::LessEqual,
                    other => other,
                },
                *k,
            )
        }
        _ => return None,
    };
    Some(flipped)
}

/// Which truth value means "the counter reached / passed its threshold"?
fn threshold_truth(op: BinaryOp) -> Option<bool> {
    match op {
        // r < K / r <= K: still below threshold on true, so the leaving edge
        // is the false one.
        BinaryOp::Less | BinaryOp::LessEqual => Some(false),
        // r > K / r >= K: threshold reached on true.
        BinaryOp::Greater | BinaryOp::GreaterEqual => Some(true),
        _ => None,
    }
}

fn guard_leaves_scc(program: &LiftedProgram, scc: &BTreeSet<usize>, reg: u16) -> bool {
    for &pc in scc {
        let Some(block) = program.blocks.get(&pc) else {
            continue;
        };
        for inst in &block.instructions {
            let Instruction::Branch {
                condition: Condition::Compare { op, left, right },
                ..
            } = inst
            else {
                continue;
            };
            let Some((op, _threshold)) = normalized_comparison(*op, left, right, reg) else {
                continue;
            };
            let Some(truth) = threshold_truth(op) else {
                continue;
            };
            let wanted = if truth {
                EdgeLabel::True
            } else {
                EdgeLabel::False
            };
            if block.successors.iter().any(|succ| {
                succ.label == wanted && succ.target_pc.is_some_and(|target| !scc.contains(&target))
            }) {
                return true;
            }
        }
    }
    false
}

fn block_has_increment(program: &LiftedProgram, pc: usize, reg: u16, step: i64) -> bool {
    program.blocks.get(&pc).is_some_and(|block| {
        block.instructions.iter().any(|inst| {
            matches!(
                inst,
                Instruction::Binary {
                    op: BinaryOp::Add,
                    dst,
                    left: Operand::Register(left),
                    right: Operand::Constant(Constant::Integer(k)),
                    ..
                } if dst.physical_slot == reg && left.physical_slot == reg && *k == step
            )
        })
    })
}

fn block_has_guard(program: &LiftedProgram, pc: usize, reg: u16) -> bool {
    program.blocks.get(&pc).is_some_and(|block| {
        block.instructions.iter().any(|inst| {
            matches!(inst, Instruction::Branch { condition: Condition::Compare { op, left, right }, .. }
                if normalized_comparison(*op, left, right, reg).is_some()
                    && threshold_truth(normalized_comparison(*op, left, right, reg).unwrap().0).is_some())
        })
    })
}

/// Prove that every cycle in `scc` terminates via a monotone counter.
fn scc_terminates(program: &LiftedProgram, scc: &BTreeSet<usize>) -> bool {
    if !is_cyclic(program, scc) {
        return true;
    }
    let mut written: BTreeSet<u16> = BTreeSet::new();
    for &pc in scc {
        if let Some(block) = program.blocks.get(&pc) {
            for inst in &block.instructions {
                if let Some(dst) = inst_dst(inst) {
                    written.insert(dst);
                }
            }
        }
    }
    for reg in written {
        let Some(step) = pure_increment_step(program, scc, reg) else {
            continue;
        };
        if !guard_leaves_scc(program, scc, reg) {
            continue;
        }
        let increment_blocks: BTreeSet<usize> = scc
            .iter()
            .copied()
            .filter(|&pc| block_has_increment(program, pc, reg, step))
            .collect();
        let guard_blocks: BTreeSet<usize> = scc
            .iter()
            .copied()
            .filter(|&pc| block_has_guard(program, pc, reg))
            .collect();
        if increment_blocks.is_empty() || guard_blocks.is_empty() {
            continue;
        }
        if acyclic_without(program, scc, &increment_blocks)
            && acyclic_without(program, scc, &guard_blocks)
        {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Silent region discovery and folding
// ---------------------------------------------------------------------------

fn silent_block(block: &BasicBlock, relevant: &BTreeSet<u16>) -> bool {
    block
        .instructions
        .iter()
        .all(|inst| matches!(classify(inst, relevant), Effect::Silent | Effect::Write(_)))
}

/// Junction: a block ending in a branch whose operands are all junk.
fn is_junction(block: &BasicBlock, relevant: &BTreeSet<u16>) -> bool {
    block.instructions.iter().any(|inst| {
        if let Instruction::Branch { condition, .. } = inst {
            let mut regs = BTreeSet::new();
            condition_regs(condition, &mut regs);
            !regs.is_empty() && regs.iter().all(|r| !relevant.contains(r))
        } else {
            false
        }
    })
}

fn collect_region(
    program: &LiftedProgram,
    junction: usize,
    relevant: &BTreeSet<u16>,
) -> Option<BTreeSet<usize>> {
    let mut region = BTreeSet::new();
    let mut stack = vec![junction];
    while let Some(pc) = stack.pop() {
        if region.contains(&pc) {
            continue;
        }
        if region.len() >= MAX_REGION_BLOCKS {
            return None;
        }
        let block = program.blocks.get(&pc)?;
        if !silent_block(block, relevant) {
            // Boundary block: stop; do not include and do not traverse.
            continue;
        }
        region.insert(pc);
        for succ in &block.successors {
            if let Some(target) = succ.target_pc {
                if !region.contains(&target) {
                    stack.push(target);
                }
            }
        }
    }
    if !region.contains(&junction) {
        return None;
    }
    Some(region)
}

fn unique_exit(program: &LiftedProgram, region: &BTreeSet<usize>) -> Option<usize> {
    let mut exit: Option<usize> = None;
    for &pc in region {
        let block = program.blocks.get(&pc)?;
        for succ in &block.successors {
            match succ.target_pc {
                Some(target) if !region.contains(&target) => match exit {
                    None => exit = Some(target),
                    Some(existing) if existing != target => return None,
                    _ => {}
                },
                Some(_) => {}
                None => return None, // a return edge escapes the region
            }
        }
    }
    exit
}

/// Walk every path from `junction` to the unique exit.  Returns the single
/// relevant-effect instruction sequence shared by all paths, or `None` if the
/// paths disagree (or if a cyclic SCC contains a relevant write).
fn uniform_effects(
    program: &LiftedProgram,
    region: &BTreeSet<usize>,
    junction: usize,
    exit: usize,
    relevant: &BTreeSet<u16>,
) -> Option<Vec<Instruction>> {
    // A relevant write on a cycle could repeat; decline the fold.
    for component in &sccs(region, &region_edges(program, region)) {
        if !is_cyclic(program, component) {
            continue;
        }
        for &pc in component {
            let block = program.blocks.get(&pc)?;
            for inst in &block.instructions {
                if matches!(classify(inst, relevant), Effect::Write(_)) {
                    return None;
                }
            }
        }
        if !scc_terminates(program, component) {
            return None;
        }
    }

    fn walk(
        program: &LiftedProgram,
        region: &BTreeSet<usize>,
        relevant: &BTreeSet<u16>,
        pc: usize,
        exit: usize,
        on_path: &mut BTreeSet<usize>,
        acc_keys: &mut Vec<String>,
        acc_insts: &mut Vec<Instruction>,
        reference: &mut Option<(Vec<String>, Vec<Instruction>)>,
    ) -> bool {
        if !on_path.insert(pc) {
            // Revisit on the current path: the counter proof guarantees the
            // cycle is finite and contains only silent writes, so it adds no
            // relevant effects.
            return true;
        }
        let Some(block) = program.blocks.get(&pc) else {
            on_path.remove(&pc);
            return false;
        };
        let saved_keys = acc_keys.len();
        let saved_insts = acc_insts.len();
        for inst in &block.instructions {
            if let Effect::Write(write) = classify(inst, relevant) {
                acc_keys.push(write_key(&write, relevant));
                acc_insts.push(write);
            }
        }
        let mut ok = true;
        for succ in &block.successors {
            let Some(target) = succ.target_pc else {
                ok = false;
                break;
            };
            if target == exit && !region.contains(&target) {
                match reference {
                    None => *reference = Some((acc_keys.clone(), acc_insts.clone())),
                    Some((expected, _)) if *expected != *acc_keys => {
                        ok = false;
                        break;
                    }
                    _ => {}
                }
            } else if region.contains(&target) {
                if !walk(
                    program, region, relevant, target, exit, on_path, acc_keys, acc_insts,
                    reference,
                ) {
                    ok = false;
                    break;
                }
            } else {
                ok = false;
                break;
            }
        }
        acc_keys.truncate(saved_keys);
        acc_insts.truncate(saved_insts);
        on_path.remove(&pc);
        ok
    }

    let mut reference = None;
    let mut keys = Vec::new();
    let mut insts = Vec::new();
    let mut on_path = BTreeSet::new();
    if !walk(
        program,
        region,
        relevant,
        junction,
        exit,
        &mut on_path,
        &mut keys,
        &mut insts,
        &mut reference,
    ) {
        return None;
    }
    // Return the concrete instructions from the first path that reached the
    // exit; every other path was checked to agree on the canonical keys.
    reference.map(|(_, insts)| insts)
}

struct Fold {
    junction: usize,
    region: BTreeSet<usize>,
    exit: usize,
    effects: Vec<Instruction>,
}

fn try_fold(program: &LiftedProgram, junction: usize, relevant: &BTreeSet<u16>) -> Option<Fold> {
    let region = collect_region(program, junction, relevant)?;
    if region.len() < 2 {
        return None;
    }
    // Do not delete a block that is one of the program's entry points.
    if region
        .iter()
        .any(|pc| *pc != junction && program.entry_points.contains(pc))
    {
        return None;
    }
    let exit = unique_exit(program, &region)?;
    let effects = uniform_effects(program, &region, junction, exit, relevant)?;
    Some(Fold {
        junction,
        region,
        exit,
        effects,
    })
}

fn recompute_reachable(program: &mut LiftedProgram) {
    let mut reachable = BTreeSet::new();
    let mut stack = program.entry_points.clone();
    while let Some(pc) = stack.pop() {
        if !reachable.insert(pc) {
            continue;
        }
        if let Some(block) = program.blocks.get(&pc) {
            for succ in &block.successors {
                if let Some(target) = succ.target_pc {
                    stack.push(target);
                }
            }
        }
    }
    program.reachable_pcs = reachable;
}

/// Simplify a lifted program without executing anything.
///
/// Returns a new program; `program` is left untouched.  Every transformation
/// is guarded by a proof of termination and effect equivalence.  Cases that
/// cannot be proven are left unchanged rather than approximated.
pub fn simplify(program: &LiftedProgram) -> Result<LiftedProgram, String> {
    let mut optimized = program.clone();
    for _ in 0..MAX_FOLD_ROUNDS {
        let relevant = compute_relevant(&optimized);
        let mut best: Option<Fold> = None;
        for (&pc, block) in &optimized.blocks {
            if !is_junction(block, &relevant) {
                continue;
            }
            if let Some(fold) = try_fold(&optimized, pc, &relevant) {
                if best
                    .as_ref()
                    .map_or(true, |current| fold.region.len() > current.region.len())
                {
                    best = Some(fold);
                }
            }
        }
        let Some(fold) = best else { break };
        let exit_state = optimized.blocks[&fold.junction]
            .successors
            .iter()
            .find(|succ| succ.target_pc == Some(fold.exit))
            .and_then(|succ| succ.state.clone());
        let block = optimized
            .blocks
            .get_mut(&fold.junction)
            .expect("junction block exists");
        block.instructions = fold.effects;
        block
            .instructions
            .push(Instruction::Jump { target: fold.exit });
        block.successors = vec![crate::ir::Successor {
            label: EdgeLabel::Next,
            target_pc: Some(fold.exit),
            state: exit_state,
        }];
        for pc in &fold.region {
            if *pc != fold.junction {
                optimized.blocks.remove(pc);
            }
        }
    }
    recompute_reachable(&mut optimized);
    Ok(optimized)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BasicBlock, Register, Successor, VmState};

    fn reg(slot: u16) -> Register {
        Register {
            physical_slot: slot,
        }
    }
    fn rreg(slot: u16) -> Operand {
        Operand::Register(reg(slot))
    }
    fn iconst(value: i64) -> Operand {
        Operand::Constant(Constant::Integer(value))
    }
    fn block(
        start: usize,
        instructions: Vec<Instruction>,
        successors: Vec<(EdgeLabel, Option<usize>)>,
    ) -> BasicBlock {
        BasicBlock {
            start_pc: start,
            end_pc: start,
            handler_family: 0,
            entry_states: Vec::<VmState>::new(),
            instructions,
            successors: successors
                .into_iter()
                .map(|(label, target)| Successor {
                    label,
                    target_pc: target,
                    state: None,
                })
                .collect(),
        }
    }
    fn program(blocks: Vec<(usize, BasicBlock)>, entries: Vec<usize>) -> LiftedProgram {
        let blocks: BTreeMap<usize, BasicBlock> = blocks.into_iter().collect();
        let mut reachable = BTreeSet::new();
        let mut stack = entries.clone();
        while let Some(pc) = stack.pop() {
            if !reachable.insert(pc) {
                continue;
            }
            if let Some(block) = blocks.get(&pc) {
                for succ in &block.successors {
                    if let Some(target) = succ.target_pc {
                        stack.push(target);
                    }
                }
            }
        }
        LiftedProgram {
            blocks,
            entry_points: entries,
            reachable_pcs: reachable,
            ..Default::default()
        }
    }
    fn junction(condition: Condition, yes: usize, no: usize) -> Instruction {
        Instruction::Branch {
            condition,
            then_target: yes,
            else_target: no,
        }
    }
    fn lt(slot: u16, k: i64) -> Condition {
        Condition::Compare {
            op: BinaryOp::Less,
            left: rreg(slot),
            right: iconst(k),
        }
    }
    fn eq(slot: u16, k: i64) -> Condition {
        Condition::Compare {
            op: BinaryOp::Equal,
            left: rreg(slot),
            right: iconst(k),
        }
    }
    fn inc(slot: u16) -> Instruction {
        Instruction::Binary {
            op: BinaryOp::Add,
            dst: reg(slot),
            left: rreg(slot),
            right: iconst(1),
        }
    }
    fn reset(slot: u16, value: i64) -> Instruction {
        Instruction::LoadConst {
            dst: reg(slot),
            value: Constant::Integer(value),
        }
    }

    /// A finite flip-flop/counter diamond with a real phase reset.  Mirrors the
    /// shape documented in VM-DISASSEMBLY.md without pinning the algorithm to
    /// particular PCs or register slots.
    fn ladder(junction_pc: usize, exit_pc: usize, phase: u16, a: u16, b: u16) -> LiftedProgram {
        // J: b = 1 - b; branch b == 0 -> L else R
        // L: if a < 2 -> LI else LE
        // LI: a += 1 -> R
        // R: if a < 2 -> RI else RE
        // RI: a += 1 -> L
        // LE/RE: phase = 0 -> exit
        let blocks = vec![
            (
                junction_pc,
                block(
                    junction_pc,
                    vec![
                        Instruction::Binary {
                            op: BinaryOp::Sub,
                            dst: reg(b),
                            left: iconst(1),
                            right: rreg(b),
                        },
                        junction(eq(b, 0), junction_pc + 1, junction_pc + 3),
                    ],
                    vec![
                        (EdgeLabel::True, Some(junction_pc + 1)),
                        (EdgeLabel::False, Some(junction_pc + 3)),
                    ],
                ),
            ),
            (
                junction_pc + 1,
                block(
                    junction_pc + 1,
                    vec![junction(lt(a, 2), junction_pc + 2, junction_pc + 5)],
                    vec![
                        (EdgeLabel::True, Some(junction_pc + 2)),
                        (EdgeLabel::False, Some(junction_pc + 5)),
                    ],
                ),
            ),
            (
                junction_pc + 2,
                block(
                    junction_pc + 2,
                    vec![
                        inc(a),
                        Instruction::Jump {
                            target: junction_pc + 3,
                        },
                    ],
                    vec![(EdgeLabel::Next, Some(junction_pc + 3))],
                ),
            ),
            (
                junction_pc + 3,
                block(
                    junction_pc + 3,
                    vec![junction(lt(a, 2), junction_pc + 4, junction_pc + 6)],
                    vec![
                        (EdgeLabel::True, Some(junction_pc + 4)),
                        (EdgeLabel::False, Some(junction_pc + 6)),
                    ],
                ),
            ),
            (
                junction_pc + 4,
                block(
                    junction_pc + 4,
                    vec![
                        inc(a),
                        Instruction::Jump {
                            target: junction_pc + 1,
                        },
                    ],
                    vec![(EdgeLabel::Next, Some(junction_pc + 1))],
                ),
            ),
            (
                junction_pc + 5,
                block(
                    junction_pc + 5,
                    vec![
                        reset(a, 0),
                        reset(phase, 0),
                        Instruction::Jump { target: exit_pc },
                    ],
                    vec![(EdgeLabel::Next, Some(exit_pc))],
                ),
            ),
            (
                junction_pc + 6,
                block(
                    junction_pc + 6,
                    vec![
                        reset(a, 0),
                        reset(phase, 0),
                        Instruction::Jump { target: exit_pc },
                    ],
                    vec![(EdgeLabel::Next, Some(exit_pc))],
                ),
            ),
            (
                exit_pc,
                block(
                    exit_pc,
                    vec![Instruction::Return {
                        values: vec![rreg(phase)],
                    }],
                    vec![(EdgeLabel::Return, None)],
                ),
            ),
        ];
        program(blocks, vec![junction_pc])
    }

    #[test]
    fn terminating_ladder_contracts_to_one_reset_and_jump() {
        let original = ladder(10, 20, 37, 44, 45);
        let simplified = simplify(&original).expect("simplify succeeds");

        // The original program is untouched.
        assert_eq!(original.blocks.len(), 8);
        assert_eq!(original.blocks[&10].instructions.len(), 2);

        // Only the junction and the exit remain.
        assert_eq!(simplified.blocks.len(), 2, "ladder blocks must be removed");
        let head = &simplified.blocks[&10];
        assert_eq!(
            head.instructions,
            vec![reset(37, 0), Instruction::Jump { target: 20 }]
        );
        assert_eq!(head.successors.len(), 1);
        assert_eq!(head.successors[0].target_pc, Some(20));
        assert!(simplified.reachable_pcs.contains(&10));
        assert!(simplified.reachable_pcs.contains(&20));
    }

    #[test]
    fn terminating_ladder_is_idempotent() {
        let original = ladder(10, 20, 37, 44, 45);
        let once = simplify(&original).expect("first simplify succeeds");
        let twice = simplify(&once).expect("second simplify succeeds");
        assert_eq!(once, twice);
    }

    /// A silent cycle with no monotone counter: J -> A -> J and J -> B -> J.
    /// There is no exit at all except the shared outer target reached by a
    /// separate edge; the loop itself is unprovable and must stay.
    #[test]
    fn nonterminating_loop_is_not_dropped() {
        // J branches on junk r44 into two blocks that loop straight back to J.
        // A second branch edge leaves to an exit that resets phase.  Because
        // the cycle contains no guarded increment, the optimizer must refuse.
        let blocks = vec![
            (
                10,
                block(
                    10,
                    vec![junction(eq(44, 0), 11, 12)],
                    vec![(EdgeLabel::True, Some(11)), (EdgeLabel::False, Some(12))],
                ),
            ),
            (
                11,
                block(
                    11,
                    vec![Instruction::Jump { target: 10 }],
                    vec![(EdgeLabel::Next, Some(10))],
                ),
            ),
            (
                12,
                block(
                    12,
                    vec![Instruction::Jump { target: 10 }],
                    vec![(EdgeLabel::Next, Some(10))],
                ),
            ),
        ];
        let original = program(blocks, vec![10]);
        let simplified = simplify(&original).expect("simplify succeeds");
        assert_eq!(
            simplified, original,
            "an unproved loop must be kept verbatim"
        );
    }

    #[test]
    fn differing_relevant_effects_are_not_folded() {
        // Both successors manipulate only junk before exiting, but their
        // relevant effects differ (r37 reset vs r38 reset).  The junction's
        // condition is therefore relevant and the region is not silent.
        let blocks = vec![
            (
                10,
                block(
                    10,
                    vec![junction(eq(44, 0), 11, 12)],
                    vec![(EdgeLabel::True, Some(11)), (EdgeLabel::False, Some(12))],
                ),
            ),
            (
                11,
                block(11, vec![reset(37, 0)], vec![(EdgeLabel::Next, Some(13))]),
            ),
            (
                12,
                block(12, vec![reset(38, 0)], vec![(EdgeLabel::Next, Some(13))]),
            ),
            (
                13,
                block(
                    13,
                    vec![Instruction::Return {
                        values: vec![rreg(37), rreg(38)],
                    }],
                    vec![(EdgeLabel::Return, None)],
                ),
            ),
        ];
        let original = program(blocks, vec![10]);
        let relevant = compute_relevant(&original);
        assert!(relevant.contains(&44), "the condition must become relevant");
        let simplified = simplify(&original).expect("simplify succeeds");
        assert_eq!(simplified, original);
    }

    #[test]
    fn calls_and_mutable_writes_are_never_dropped() {
        // A junk-only counter sits in front of a call.  The junk counter may be
        // bypassed, but the call (an observable, possibly-throwing operation)
        // must survive unchanged.
        let blocks = vec![
            (
                10,
                block(
                    10,
                    vec![junction(eq(44, 0), 11, 12)],
                    vec![(EdgeLabel::True, Some(11)), (EdgeLabel::False, Some(12))],
                ),
            ),
            (
                11,
                block(
                    11,
                    vec![inc(44), Instruction::Jump { target: 12 }],
                    vec![(EdgeLabel::Next, Some(12))],
                ),
            ),
            (
                12,
                block(
                    12,
                    vec![Instruction::Call {
                        dst: Some(reg(1)),
                        function: Operand::Global(vec![b"f".to_vec()]),
                        args: vec![],
                        result_count: None,
                    }],
                    vec![(EdgeLabel::Next, Some(13))],
                ),
            ),
            (
                13,
                block(
                    13,
                    vec![Instruction::Return {
                        values: vec![rreg(1)],
                    }],
                    vec![(EdgeLabel::Return, None)],
                ),
            ),
        ];
        let original = program(blocks, vec![10]);
        let simplified = simplify(&original).expect("simplify succeeds");
        assert!(
            simplified.blocks.get(&11).is_none(),
            "junk counter is bypassed"
        );
        assert!(matches!(
            simplified.blocks[&10].instructions.as_slice(),
            [Instruction::Jump { target: 12 }]
        ));
        assert!(
            matches!(
                simplified.blocks[&12].instructions.first(),
                Some(Instruction::Call { .. })
            ),
            "the call must be preserved"
        );
        assert_eq!(original.blocks.len(), 4, "original is untouched");
    }

    /// End-to-end shape from `T001-analysis/VM-DISASSEMBLY.md`: the flip-flop
    /// junction at 298 and its R44 counter ladder (154/291/274/361/39/267)
    /// converge on `phase = 0` (204/329) and the numeric-for latch at 285.
    /// No PC or register identity is hard-coded in the optimizer itself; this
    /// test only feeds the real shape through it.
    #[test]
    fn sample_checksum_ladder_shape_folds_to_phase_reset_and_latch() {
        let blocks = vec![
            (
                298,
                block(
                    298,
                    vec![
                        Instruction::Binary {
                            op: BinaryOp::Sub,
                            dst: reg(45),
                            left: iconst(1),
                            right: rreg(45),
                        },
                        junction(eq(45, 0), 154, 274),
                    ],
                    vec![(EdgeLabel::True, Some(154)), (EdgeLabel::False, Some(274))],
                ),
            ),
            (
                154,
                block(
                    154,
                    vec![junction(lt(44, 2), 291, 39)],
                    vec![(EdgeLabel::True, Some(291)), (EdgeLabel::False, Some(39))],
                ),
            ),
            (
                291,
                block(
                    291,
                    vec![inc(44), Instruction::Jump { target: 274 }],
                    vec![(EdgeLabel::Next, Some(274))],
                ),
            ),
            (
                274,
                block(
                    274,
                    vec![junction(lt(44, 2), 361, 267)],
                    vec![(EdgeLabel::True, Some(361)), (EdgeLabel::False, Some(267))],
                ),
            ),
            (
                361,
                block(
                    361,
                    vec![inc(44), Instruction::Jump { target: 154 }],
                    vec![(EdgeLabel::Next, Some(154))],
                ),
            ),
            (
                39,
                block(
                    39,
                    vec![reset(44, 0), Instruction::Jump { target: 204 }],
                    vec![(EdgeLabel::Next, Some(204))],
                ),
            ),
            (
                267,
                block(
                    267,
                    vec![reset(44, 0), Instruction::Jump { target: 329 }],
                    vec![(EdgeLabel::Next, Some(329))],
                ),
            ),
            (
                204,
                block(
                    204,
                    vec![reset(37, 0), Instruction::Jump { target: 285 }],
                    vec![(EdgeLabel::Next, Some(285))],
                ),
            ),
            (
                329,
                block(
                    329,
                    vec![reset(37, 0), Instruction::Jump { target: 285 }],
                    vec![(EdgeLabel::Next, Some(285))],
                ),
            ),
            (
                285,
                block(
                    285,
                    vec![Instruction::ForLoop {
                        state: reg(10),
                        target: 67,
                    }],
                    vec![(EdgeLabel::Next, Some(67))],
                ),
            ),
            (
                67,
                block(
                    67,
                    vec![Instruction::Return {
                        values: vec![rreg(10)],
                    }],
                    vec![(EdgeLabel::Return, None)],
                ),
            ),
            (
                121,
                block(
                    121,
                    vec![junction(eq(37, 3), 310, 285)],
                    vec![(EdgeLabel::True, Some(310)), (EdgeLabel::False, Some(285))],
                ),
            ),
            (
                310,
                block(
                    310,
                    vec![
                        Instruction::Append {
                            table: rreg(22),
                            value: rreg(31),
                        },
                        Instruction::Jump { target: 298 },
                    ],
                    vec![(EdgeLabel::Next, Some(298))],
                ),
            ),
        ];
        let original = program(blocks, vec![121, 298]);
        let relevant = compute_relevant(&original);
        assert!(relevant.contains(&37), "phase must be relevant");
        assert!(
            relevant.contains(&22) && relevant.contains(&31),
            "mutable writes are roots"
        );
        assert!(
            !relevant.contains(&44) && !relevant.contains(&45),
            "ladder state is junk"
        );

        let simplified = simplify(&original).expect("simplify succeeds");
        for pc in [154, 291, 274, 361, 39, 267, 204, 329] {
            assert!(
                !simplified.blocks.contains_key(&pc),
                "block {pc} must be folded away"
            );
        }
        assert_eq!(
            simplified.blocks[&298].instructions,
            vec![reset(37, 0), Instruction::Jump { target: 285 }]
        );
        assert!(
            simplified.blocks.contains_key(&285),
            "the real loop latch survives"
        );
    }

    #[test]
    fn packed_tuple_writes_are_observable() {
        // PushPacked / ReturnPacked are roots for relevance; a register that
        // only feeds them must not be treated as junk.
        let blocks = vec![(
            10,
            block(
                10,
                vec![
                    Instruction::NewPackedTable { dst: reg(50) },
                    Instruction::PushPacked {
                        table: rreg(50),
                        value: rreg(44),
                    },
                    Instruction::ReturnPacked { values: rreg(50) },
                ],
                vec![(EdgeLabel::Return, None)],
            ),
        )];
        let original = program(blocks, vec![10]);
        let relevant = compute_relevant(&original);
        assert!(relevant.contains(&44));
        assert!(relevant.contains(&50));
    }
}
