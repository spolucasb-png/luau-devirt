//! Specialize short constant dispatch chains under a proven boolean condition.

use std::collections::{BTreeMap, BTreeSet};

use crate::ir::*;

fn written_slot(instruction: &Instruction) -> Option<u16> {
    match instruction {
        Instruction::LoadConst { dst, .. }
        | Instruction::Move { dst, .. }
        | Instruction::Unary { dst, .. }
        | Instruction::Binary { dst, .. }
        | Instruction::GetTable { dst, .. }
        | Instruction::NewTable { dst }
        | Instruction::NewPackedTable { dst }
        | Instruction::NewClosure { dst, .. }
        | Instruction::Concat { dst, .. }
        | Instruction::Call { dst: Some(dst), .. } => Some(dst.physical_slot),
        _ => None,
    }
}

fn operand_slots(operand: &Operand) -> BTreeSet<u16> {
    match operand {
        Operand::Register(register) => BTreeSet::from([register.physical_slot]),
        Operand::Expression(expression) => match expression.as_ref() {
            ValueExpression::Unary { value, .. }
            | ValueExpression::PermutationParity { value, .. } => operand_slots(value),
            ValueExpression::Binary { left, right, .. } => operand_slots(left)
                .into_iter()
                .chain(operand_slots(right))
                .collect(),
            ValueExpression::Index { table, index } => operand_slots(table)
                .into_iter()
                .chain(operand_slots(index))
                .collect(),
        },
        _ => BTreeSet::new(),
    }
}

fn resolve(value: &Operand, facts: &BTreeMap<u16, Constant>) -> Option<Constant> {
    match value {
        Operand::Constant(constant) => Some(constant.clone()),
        Operand::Register(register) => facts.get(&register.physical_slot).cloned(),
        Operand::Expression(expression) => match expression.as_ref() {
            ValueExpression::Binary { op, left, right } => {
                fold(*op, &resolve(left, facts)?, &resolve(right, facts)?)
            }
            ValueExpression::Unary {
                op: UnaryOp::Not,
                value,
            } => Some(Constant::Boolean(!truthy(&resolve(value, facts)?))),
            _ => None,
        },
        _ => None,
    }
}

fn truthy(value: &Constant) -> bool {
    !matches!(value, Constant::Nil | Constant::Boolean(false))
}

fn number(value: &Constant) -> Option<f64> {
    match value {
        Constant::Integer(value) => Some(*value as f64),
        Constant::U32(value) => Some(f64::from(*value)),
        Constant::NumberBits(bits) => Some(f64::from_bits(*bits)),
        _ => None,
    }
}

fn fold(op: BinaryOp, left: &Constant, right: &Constant) -> Option<Constant> {
    match op {
        BinaryOp::Equal | BinaryOp::NotEqual => {
            let equal = match (number(left), number(right)) {
                (Some(a), Some(b)) => a == b,
                _ => left == right,
            };
            Some(Constant::Boolean(if op == BinaryOp::Equal {
                equal
            } else {
                !equal
            }))
        }
        BinaryOp::Less | BinaryOp::LessEqual | BinaryOp::Greater | BinaryOp::GreaterEqual => {
            let (a, b) = (number(left)?, number(right)?);
            Some(Constant::Boolean(match op {
                BinaryOp::Less => a < b,
                BinaryOp::LessEqual => a <= b,
                BinaryOp::Greater => a > b,
                _ => a >= b,
            }))
        }
        BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul => {
            let (Constant::Integer(a), Constant::Integer(b)) = (left, right) else {
                return None;
            };
            let value = match op {
                BinaryOp::Add => a.checked_add(*b)?,
                BinaryOp::Sub => a.checked_sub(*b)?,
                _ => a.checked_mul(*b)?,
            };
            (value.unsigned_abs() <= (1u64 << 53)).then_some(Constant::Integer(value))
        }
        _ => None,
    }
}

fn evaluate(condition: &Condition, facts: &BTreeMap<u16, Constant>) -> Option<bool> {
    match condition {
        Condition::Truthy(value) => Some(truthy(&resolve(value, facts)?)),
        Condition::Falsey(value) => Some(!truthy(&resolve(value, facts)?)),
        Condition::Compare { op, left, right } => {
            let Constant::Boolean(value) =
                fold(*op, &resolve(left, facts)?, &resolve(right, facts)?)?
            else {
                return None;
            };
            Some(value)
        }
    }
}

/// Walk only constant scalar stores and already-proven branches. Stop before
/// reads, calls, table mutation, loop operations, or any unknown calculation.
fn trace(
    program: &LiftedProgram,
    start: usize,
    mut facts: BTreeMap<u16, Constant>,
) -> Option<(Vec<Instruction>, usize)> {
    let mut pc = start;
    let mut instructions = Vec::new();
    let mut visited = BTreeSet::new();
    for _ in 0..128 {
        if !visited.insert(pc) {
            return None;
        }
        let block = program.blocks.get(&pc)?;
        let checkpoint = instructions.len();
        let mut next = None;
        let mut supported = true;
        for instruction in &block.instructions {
            match instruction {
                Instruction::LoadConst { dst, value } => {
                    facts.insert(dst.physical_slot, value.clone());
                    instructions.push(instruction.clone());
                }
                Instruction::Move { dst, src } => {
                    if let Some(value) = resolve(src, &facts) {
                        facts.insert(dst.physical_slot, value.clone());
                        instructions.push(Instruction::LoadConst {
                            dst: dst.clone(),
                            value,
                        });
                    } else {
                        supported = false;
                        break;
                    }
                }
                Instruction::Binary {
                    dst,
                    op,
                    left,
                    right,
                } => {
                    if let Some(value) = resolve(left, &facts).and_then(|left| {
                        resolve(right, &facts).and_then(|right| fold(*op, &left, &right))
                    }) {
                        facts.insert(dst.physical_slot, value.clone());
                        instructions.push(Instruction::LoadConst {
                            dst: dst.clone(),
                            value,
                        });
                    } else {
                        supported = false;
                        break;
                    }
                }
                Instruction::Branch {
                    condition,
                    then_target,
                    else_target,
                } => {
                    next = Some(if evaluate(condition, &facts)? {
                        *then_target
                    } else {
                        *else_target
                    });
                }
                Instruction::Jump { target } => next = Some(*target),
                Instruction::Nop
                | Instruction::Tag { .. }
                | Instruction::KeyUpdate { .. }
                | Instruction::BankSwitch { .. } => {}
                _ => {
                    supported = false;
                    break;
                }
            }
        }
        if !supported {
            instructions.truncate(checkpoint);
            return (!instructions.is_empty()).then_some((instructions, pc));
        }
        pc = next.or_else(|| {
            (block.successors.len() == 1)
                .then(|| block.successors[0].target_pc)
                .flatten()
        })?;
    }
    None
}

pub(crate) fn simplify(program: &LiftedProgram) -> Result<LiftedProgram, String> {
    let mut output = program.clone();
    let mut next_id = program
        .blocks
        .keys()
        .next_back()
        .copied()
        .unwrap_or(0)
        .checked_add(1024)
        .ok_or("synthetic block identifier overflow")?;
    for (&pc, block) in &program.blocks {
        let Some(Instruction::Branch {
            condition,
            then_target,
            else_target,
        }) = block.instructions.last()
        else {
            continue;
        };
        let (Condition::Truthy(Operand::Register(predicate))
        | Condition::Falsey(Operand::Register(predicate))) = condition
        else {
            continue;
        };
        let Some((
            definition_index,
            Instruction::Binary {
                dst,
                op,
                left,
                right,
            },
        )) = block
            .instructions
            .iter()
            .enumerate()
            .rev()
            .skip(1)
            .find(|(_, instruction)| written_slot(instruction) == Some(predicate.physical_slot))
        else {
            continue;
        };
        if dst != predicate
            || !matches!(
                op,
                BinaryOp::Equal
                    | BinaryOp::NotEqual
                    | BinaryOp::Less
                    | BinaryOp::LessEqual
                    | BinaryOp::Greater
                    | BinaryOp::GreaterEqual
            )
        {
            continue;
        }
        let operands = operand_slots(left)
            .into_iter()
            .chain(operand_slots(right))
            .collect::<BTreeSet<_>>();
        if block.instructions[definition_index + 1..block.instructions.len() - 1]
            .iter()
            .any(|instruction| {
                written_slot(instruction).is_some_and(|slot| operands.contains(&slot))
                    || !matches!(
                        instruction,
                        Instruction::Move { .. }
                            | Instruction::LoadConst { .. }
                            | Instruction::Nop
                            | Instruction::KeyUpdate { .. }
                            | Instruction::BankSwitch { .. }
                    )
            })
        {
            continue;
        }
        let inverted = matches!(condition, Condition::Falsey(_));
        let mut then_facts = BTreeMap::new();
        then_facts.insert(dst.physical_slot, Constant::Boolean(!inverted));
        let mut else_facts = BTreeMap::new();
        else_facts.insert(dst.physical_slot, Constant::Boolean(inverted));
        let Some((then_instructions, then_exit)) = trace(program, *then_target, then_facts) else {
            continue;
        };
        let Some((else_instructions, else_exit)) = trace(program, *else_target, else_facts) else {
            continue;
        };
        if then_exit != else_exit {
            continue;
        }
        let then_id = next_id;
        let else_id = next_id
            .checked_add(1)
            .ok_or("synthetic block identifier overflow")?;
        next_id = next_id
            .checked_add(2)
            .ok_or("synthetic block identifier overflow")?;
        for (id, mut instructions) in [(then_id, then_instructions), (else_id, else_instructions)] {
            instructions.push(Instruction::Jump { target: then_exit });
            output.blocks.insert(
                id,
                BasicBlock {
                    start_pc: id,
                    end_pc: id + 1,
                    handler_family: block.handler_family,
                    entry_states: block.entry_states.clone(),
                    instructions,
                    successors: vec![Successor {
                        label: EdgeLabel::Next,
                        target_pc: Some(then_exit),
                        state: None,
                    }],
                },
            );
        }
        let controller = output
            .blocks
            .get_mut(&pc)
            .ok_or("missing branch controller")?;
        let last = controller
            .instructions
            .last_mut()
            .ok_or("empty branch controller")?;
        *last = Instruction::Branch {
            condition: condition.clone(),
            then_target: then_id,
            else_target: else_id,
        };
        controller.successors = vec![
            Successor {
                label: EdgeLabel::True,
                target_pc: Some(then_id),
                state: None,
            },
            Successor {
                label: EdgeLabel::False,
                target_pc: Some(else_id),
                state: None,
            },
        ];
    }
    let mut reachable = BTreeSet::new();
    let mut todo = output.entry_points.clone();
    while let Some(pc) = todo.pop() {
        if reachable.insert(pc) {
            let block = output
                .blocks
                .get(&pc)
                .ok_or_else(|| format!("missing block {pc}"))?;
            todo.extend(block.successors.iter().filter_map(|edge| edge.target_pc));
        }
    }
    output.blocks.retain(|pc, _| reachable.contains(pc));
    output.reachable_pcs = reachable;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(slot: u16) -> Operand {
        Operand::Register(Register {
            physical_slot: slot,
        })
    }
    fn integer(value: i64) -> Operand {
        Operand::Constant(Constant::Integer(value))
    }

    fn fixture(extra: Instruction) -> LiftedProgram {
        let block = |pc, instructions: Vec<Instruction>, targets: Vec<usize>| BasicBlock {
            start_pc: pc,
            end_pc: pc + 1,
            handler_family: 6094,
            entry_states: vec![],
            instructions,
            successors: targets
                .into_iter()
                .map(|target| Successor {
                    label: EdgeLabel::Next,
                    target_pc: Some(target),
                    state: None,
                })
                .collect(),
        };
        LiftedProgram {
            blocks: BTreeMap::from([
                (
                    1,
                    block(
                        1,
                        vec![
                            Instruction::Binary {
                                dst: Register { physical_slot: 2 },
                                op: BinaryOp::Greater,
                                left: reg(1),
                                right: integer(0),
                            },
                            extra,
                            Instruction::Branch {
                                condition: Condition::Truthy(reg(2)),
                                then_target: 2,
                                else_target: 3,
                            },
                        ],
                        vec![2, 3],
                    ),
                ),
                (
                    2,
                    block(
                        2,
                        vec![
                            Instruction::LoadConst {
                                dst: Register { physical_slot: 3 },
                                value: Constant::Integer(10),
                            },
                            Instruction::Jump { target: 4 },
                        ],
                        vec![4],
                    ),
                ),
                (
                    3,
                    block(
                        3,
                        vec![
                            Instruction::LoadConst {
                                dst: Register { physical_slot: 3 },
                                value: Constant::Integer(20),
                            },
                            Instruction::Jump { target: 4 },
                        ],
                        vec![4],
                    ),
                ),
                (
                    4,
                    block(
                        4,
                        vec![Instruction::Return {
                            values: vec![reg(3)],
                        }],
                        vec![],
                    ),
                ),
            ]),
            entry_points: vec![1],
            reachable_pcs: BTreeSet::from([1, 2, 3, 4]),
            ..Default::default()
        }
    }

    #[test]
    fn intervening_predicate_definition_blocks_specialization() {
        let original = fixture(Instruction::LoadConst {
            dst: Register { physical_slot: 2 },
            value: Constant::Boolean(false),
        });
        assert_eq!(simplify(&original).unwrap(), original);
    }

    #[test]
    fn modified_comparison_operand_blocks_specialization() {
        let original = fixture(Instruction::LoadConst {
            dst: Register { physical_slot: 1 },
            value: Constant::Integer(0),
        });
        assert_eq!(simplify(&original).unwrap(), original);
    }
}
