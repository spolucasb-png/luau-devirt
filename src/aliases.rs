//! Prove and normalize bank-dependent physical-register aliases.
//!
//! The same instruction address can use different transient physical slots in
//! different dispatcher states. A single per-PC IR is safe only when those
//! variants agree modulo register names and the proposed aliases never merge
//! simultaneously live values in any concrete state.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::ir::{BasicBlock, Condition, Instruction, Operand, Register, ValueExpression, VmState};

#[derive(Clone)]
pub(crate) struct Variant {
    pub instructions: Vec<Instruction>,
    pub successors: Vec<VmState>,
}

fn operand_registers(operand: &mut Operand, visit: &mut impl FnMut(&mut Register)) {
    match operand {
        Operand::Register(register) => visit(register),
        Operand::Expression(expression) => match expression.as_mut() {
            ValueExpression::Unary { value, .. }
            | ValueExpression::PermutationParity { value, .. } => operand_registers(value, visit),
            ValueExpression::Binary { left, right, .. } => {
                operand_registers(left, visit);
                operand_registers(right, visit);
            }
            ValueExpression::Index { table, index } => {
                operand_registers(table, visit);
                operand_registers(index, visit);
            }
        },
        _ => {}
    }
}

fn condition_registers(condition: &mut Condition, visit: &mut impl FnMut(&mut Register)) {
    match condition {
        Condition::Truthy(operand) | Condition::Falsey(operand) => {
            operand_registers(operand, visit)
        }
        Condition::Compare { left, right, .. } => {
            operand_registers(left, visit);
            operand_registers(right, visit);
        }
    }
}

fn instruction_registers(instruction: &mut Instruction, visit: &mut impl FnMut(&mut Register)) {
    use Instruction::*;
    match instruction {
        LoadConst { dst, .. } | NewTable { dst } | NewPackedTable { dst } => visit(dst),
        Move { dst, src } | Unary { dst, src, .. } => {
            visit(dst);
            operand_registers(src, visit);
        }
        Binary {
            dst, left, right, ..
        } => {
            visit(dst);
            operand_registers(left, visit);
            operand_registers(right, visit);
        }
        GetTable { dst, table, index } => {
            visit(dst);
            operand_registers(table, visit);
            operand_registers(index, visit);
        }
        SetTable {
            table,
            index,
            value,
        } => {
            operand_registers(table, visit);
            operand_registers(index, visit);
            operand_registers(value, visit);
        }
        Append { table, value } | PushPacked { table, value } => {
            operand_registers(table, visit);
            operand_registers(value, visit);
        }
        AppendPacked { table, values } => {
            operand_registers(table, visit);
            operand_registers(values, visit);
        }
        Compare { condition } | Branch { condition, .. } => condition_registers(condition, visit),
        ForPrep { state, .. } | ForLoop { state, .. } => visit(state),
        Call {
            dst,
            function,
            args,
            ..
        } => {
            if let Some(dst) = dst {
                visit(dst);
            }
            operand_registers(function, visit);
            for operand in args {
                operand_registers(operand, visit);
            }
        }
        Concat { dst, values } => {
            visit(dst);
            for operand in values {
                operand_registers(operand, visit);
            }
        }
        NewClosure { dst, captures, .. } => {
            visit(dst);
            for operand in captures {
                operand_registers(operand, visit);
            }
        }
        Return { values } => {
            for operand in values {
                operand_registers(operand, visit);
            }
        }
        ReturnPacked { values } => operand_registers(values, visit),
        HaltDispatch { pc_slot, bank_slot } => {
            visit(pc_slot);
            visit(bank_slot);
        }
        Tag { .. } | Nop | Jump { .. } | KeyUpdate { .. } | BankSwitch { .. } | Raw { .. } => {}
    }
}

fn shape(instructions: &[Instruction]) -> (Vec<Instruction>, Vec<u16>) {
    let mut normalized = instructions.to_vec();
    let mut slots = Vec::new();
    for instruction in &mut normalized {
        instruction_registers(instruction, &mut |register| {
            slots.push(register.physical_slot);
            register.physical_slot = 0;
        });
    }
    (normalized, slots)
}

fn root(parents: &mut [u16], slot: u16) -> u16 {
    let parent = parents[slot as usize];
    if parent == slot {
        slot
    } else {
        let canonical = root(parents, parent);
        parents[slot as usize] = canonical;
        canonical
    }
}

fn definition(instruction: &Instruction) -> Option<u16> {
    use Instruction::*;
    match instruction {
        LoadConst { dst, .. }
        | Move { dst, .. }
        | Unary { dst, .. }
        | Binary { dst, .. }
        | GetTable { dst, .. }
        | NewTable { dst }
        | NewPackedTable { dst }
        | Concat { dst, .. }
        | NewClosure { dst, .. }
        | Call { dst: Some(dst), .. } => Some(dst.physical_slot),
        HaltDispatch { pc_slot, .. } => Some(pc_slot.physical_slot),
        _ => None,
    }
}

fn uses(instruction: &Instruction) -> BTreeSet<u16> {
    let mut copy = instruction.clone();
    let mut result = BTreeSet::new();
    // A destination is visited first; skip it, while preserving any read of
    // that same register in the instruction's operands (x = x + 1).
    let mut skip_destination = definition(instruction).is_some();
    instruction_registers(&mut copy, &mut |register| {
        if skip_destination {
            skip_destination = false;
        } else {
            result.insert(register.physical_slot);
        }
    });
    result
}

fn ensure_injective(
    slots: &BTreeSet<u16>,
    parents: &mut [u16],
    state: &VmState,
) -> Result<(), String> {
    let mut seen = BTreeMap::new();
    for &slot in slots {
        let canonical = root(parents, slot);
        if let Some(other) = seen.insert(canonical, slot) {
            if other != slot {
                return Err(format!(
                    "cannot merge bank aliases {other} and {slot}: both live at word {}",
                    state.pc
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn canonicalize(
    blocks: &mut BTreeMap<usize, BasicBlock>,
    variants: &HashMap<VmState, Variant>,
) -> Result<(), String> {
    let mut parents: Vec<u16> = (0..=u16::MAX).collect();
    let mut representatives = BTreeMap::new();
    for (&pc, block) in blocks.iter() {
        representatives.insert(pc, shape(&block.instructions));
    }
    let mut has_aliases = false;
    for (state, variant) in variants {
        let (expected_shape, expected_slots) = &representatives[&state.pc];
        let (actual_shape, actual_slots) = shape(&variant.instructions);
        if expected_shape != &actual_shape {
            return Err(format!(
                "dispatcher states disagree on lifted semantics at word {}",
                state.pc
            ));
        }
        for (&left, &right) in expected_slots.iter().zip(actual_slots.iter()) {
            let a = root(&mut parents, left);
            let b = root(&mut parents, right);
            if a != b {
                parents[a.max(b) as usize] = a.min(b);
                has_aliases = true;
            }
        }
    }
    if !has_aliases {
        return Ok(());
    }
    if variants.values().any(|variant| {
        variant
            .instructions
            .iter()
            .any(|i| matches!(i, Instruction::Raw { .. }))
    }) {
        return Err(
            "cannot prove bank aliases while instruction semantics are unresolved".to_owned(),
        );
    }

    // Backward liveness over the full concrete dispatcher-state graph.
    let mut live_in: HashMap<VmState, BTreeSet<u16>> = variants
        .keys()
        .cloned()
        .map(|state| (state, BTreeSet::new()))
        .collect();
    let mut converged = false;
    for _ in 0..1024 {
        let mut changed = false;
        for (state, variant) in variants {
            let mut live = BTreeSet::new();
            for successor in &variant.successors {
                let successor_live = live_in.get(successor).ok_or_else(|| {
                    format!(
                        "missing dispatcher state for successor at word {}",
                        successor.pc
                    )
                })?;
                live.extend(successor_live.iter().copied());
            }
            for instruction in variant.instructions.iter().rev() {
                if let Some(dst) = definition(instruction) {
                    live.remove(&dst);
                }
                live.extend(uses(instruction));
            }
            if live_in[state] != live {
                live_in.insert(state.clone(), live);
                changed = true;
            }
        }
        if !changed {
            converged = true;
            break;
        }
    }
    if !converged {
        return Err("bank-alias liveness proof exceeded its iteration budget".to_owned());
    }
    for (state, variant) in variants {
        let mut live = BTreeSet::new();
        for successor in &variant.successors {
            live.extend(live_in[successor].iter().copied());
        }
        ensure_injective(&live, &mut parents, state)?;
        for instruction in variant.instructions.iter().rev() {
            if let Some(dst) = definition(instruction) {
                let mut interference = live.clone();
                interference.insert(dst);
                ensure_injective(&interference, &mut parents, state)?;
                live.remove(&dst);
            }
            live.extend(uses(instruction));
            ensure_injective(&live, &mut parents, state)?;
        }
    }
    for block in blocks.values_mut() {
        for instruction in &mut block.instructions {
            instruction_registers(instruction, &mut |register| {
                register.physical_slot = root(&mut parents, register.physical_slot);
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Constant, EdgeLabel, Successor};

    fn state(bank: u32) -> VmState {
        VmState {
            pc: 1,
            key_state: 0,
            bank_base: bank,
            dispatch_token: 6094,
            phase: 0,
            bank_sum: 3,
            prototype_salt: 0,
        }
    }

    fn reg(slot: u16) -> Operand {
        Operand::Register(Register {
            physical_slot: slot,
        })
    }

    fn block(instructions: Vec<Instruction>) -> BTreeMap<usize, BasicBlock> {
        BTreeMap::from([(
            1,
            BasicBlock {
                start_pc: 1,
                end_pc: 2,
                handler_family: 6094,
                entry_states: vec![state(1), state(2)],
                instructions,
                successors: vec![Successor {
                    label: EdgeLabel::Return,
                    target_pc: None,
                    state: None,
                }],
            },
        )])
    }

    #[test]
    fn non_overlapping_bank_temporaries_are_canonicalized() {
        let make = |slot| {
            vec![
                Instruction::LoadConst {
                    dst: Register {
                        physical_slot: slot,
                    },
                    value: Constant::Integer(7),
                },
                Instruction::Return {
                    values: vec![reg(slot)],
                },
            ]
        };
        let mut blocks = block(make(1));
        let variants = HashMap::from([
            (
                state(1),
                Variant {
                    instructions: make(1),
                    successors: vec![],
                },
            ),
            (
                state(2),
                Variant {
                    instructions: make(2),
                    successors: vec![],
                },
            ),
        ]);
        canonicalize(&mut blocks, &variants).expect("non-overlapping aliases");
        assert_eq!(blocks[&1].instructions, make(1));
    }

    #[test]
    fn simultaneously_live_values_cannot_be_merged() {
        let make = |a, b| {
            vec![
                Instruction::Move {
                    dst: Register { physical_slot: a },
                    src: Operand::Argument(0),
                },
                Instruction::LoadConst {
                    dst: Register { physical_slot: b },
                    value: Constant::Integer(7),
                },
                Instruction::Return {
                    values: vec![reg(a), reg(b)],
                },
            ]
        };
        let mut blocks = block(make(1, 2));
        let variants = HashMap::from([
            (
                state(1),
                Variant {
                    instructions: make(1, 2),
                    successors: vec![],
                },
            ),
            (
                state(2),
                Variant {
                    instructions: make(2, 1),
                    successors: vec![],
                },
            ),
        ]);
        let error = canonicalize(&mut blocks, &variants).expect_err("live values are distinct");
        assert!(error.contains("both live"));
    }

    #[test]
    fn semantic_disagreement_is_not_treated_as_register_renaming() {
        let make = |value| {
            vec![Instruction::LoadConst {
                dst: Register { physical_slot: 1 },
                value: Constant::Integer(value),
            }]
        };
        let mut blocks = block(make(7));
        let variants = HashMap::from([
            (
                state(1),
                Variant {
                    instructions: make(7),
                    successors: vec![],
                },
            ),
            (
                state(2),
                Variant {
                    instructions: make(8),
                    successors: vec![],
                },
            ),
        ]);
        assert!(canonicalize(&mut blocks, &variants).is_err());
    }

    #[test]
    fn a_dead_destination_cannot_clobber_a_live_alias() {
        let mut variants = HashMap::new();
        let mut blocks = BTreeMap::new();
        for pc in 1..=3 {
            let make = |live, dead| match pc {
                1 => vec![Instruction::LoadConst {
                    dst: Register {
                        physical_slot: live,
                    },
                    value: Constant::Integer(10),
                }],
                2 => vec![Instruction::LoadConst {
                    dst: Register {
                        physical_slot: dead,
                    },
                    value: Constant::Integer(99),
                }],
                _ => vec![Instruction::Return {
                    values: vec![reg(live)],
                }],
            };
            for (bank, live, dead) in [(1, 1, 2), (2, 2, 1)] {
                let mut current = state(bank);
                current.pc = pc;
                let successors = if pc < 3 {
                    let mut next = current.clone();
                    next.pc += 1;
                    vec![next]
                } else {
                    vec![]
                };
                variants.insert(
                    current,
                    Variant {
                        instructions: make(live, dead),
                        successors,
                    },
                );
            }
            blocks.insert(
                pc,
                BasicBlock {
                    start_pc: pc,
                    end_pc: pc + 1,
                    handler_family: 6094,
                    entry_states: vec![],
                    instructions: make(1, 2),
                    successors: vec![],
                },
            );
        }
        assert!(canonicalize(&mut blocks, &variants)
            .expect_err("dead writes interfere")
            .contains("both live"));
    }
}
