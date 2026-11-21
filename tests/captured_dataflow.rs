//! Structural regression tests for the captured-environment dataflow renderer.
//!
//! The tests build manual `LiftedProgram`s through the public IR API and inspect
//! emitted source text only. No Lua/Luau is executed; no fixture is read.

use std::collections::{BTreeMap, BTreeSet};

use luau_devirt::emit_luau;
use luau_devirt::ir::{
    BasicBlock, CodegenOptions, Condition, Constant, EdgeLabel, Instruction, LiftedProgram,
    Operand, Register, Successor,
};

fn reg(slot: u16) -> Operand {
    Operand::Register(Register {
        physical_slot: slot,
    })
}

fn string(value: &str) -> Operand {
    Operand::Constant(Constant::String(value.as_bytes().to_vec()))
}

fn integer(value: i64) -> Operand {
    Operand::Constant(Constant::Integer(value))
}

fn environment_member(dst: u16, key: &str) -> Instruction {
    Instruction::GetTable {
        dst: Register { physical_slot: dst },
        table: Operand::Environment,
        index: string(key),
    }
}

fn successor(label: EdgeLabel, target: Option<usize>) -> Successor {
    Successor {
        label,
        target_pc: target,
        state: None,
    }
}

fn block(
    pc: usize,
    instructions: Vec<Instruction>,
    successors: Vec<Successor>,
) -> (usize, BasicBlock) {
    (
        pc,
        BasicBlock {
            start_pc: pc,
            end_pc: pc + instructions.len().max(1),
            handler_family: 0,
            entry_states: vec![],
            instructions,
            successors,
        },
    )
}

fn program(entry: usize, blocks: Vec<(usize, BasicBlock)>) -> LiftedProgram {
    let mut map = BTreeMap::new();
    let mut reachable = BTreeSet::new();
    for (pc, item) in blocks {
        reachable.insert(pc);
        map.insert(pc, item);
    }
    LiftedProgram {
        blocks: map,
        entry_points: vec![entry],
        reachable_pcs: reachable,
        state_variants: 0,
        root_entry: Some(entry),
        prototype_entries: BTreeMap::new(),
        parameters: BTreeMap::new(),
    }
}

fn strict() -> CodegenOptions {
    CodegenOptions {
        strict: true,
        include_source_comments: false,
    }
}

fn scalar_call(dst: u16, function: u16, argument: &str) -> Vec<Instruction> {
    vec![
        Instruction::Call {
            dst: Some(Register { physical_slot: dst }),
            function: reg(function),
            args: vec![string(argument)],
            result_count: Some(1),
        },
        Instruction::GetTable {
            dst: Register {
                physical_slot: dst + 1,
            },
            table: reg(dst),
            index: integer(1),
        },
    ]
}

#[test]
fn environment_is_captured_once_and_scalar_calls_keep_order() {
    let mut first = vec![environment_member(1, "fn")];
    first.extend(scalar_call(2, 1, "left"));
    first.extend(scalar_call(4, 1, "right"));
    first.push(Instruction::Jump { target: 2 });

    let source = emit_luau(
        &program(
            1,
            vec![
                block(1, first, vec![successor(EdgeLabel::Next, Some(2))]),
                block(
                    2,
                    vec![Instruction::Return { values: vec![] }],
                    vec![successor(EdgeLabel::Return, None)],
                ),
            ],
        ),
        &strict(),
    )
    .expect("captured environment should render");

    assert_eq!(source.matches("getfenv()").count(), 1, "{source}");
    assert!(source.contains("local environment = getfenv()"), "{source}");
    assert_eq!(source.matches("environment.fn").count(), 1, "{source}");
    assert_eq!(source.matches("\"left\"").count(), 1, "{source}");
    assert_eq!(source.matches("\"right\"").count(), 1, "{source}");
    assert!(!source.contains("table.pack"), "{source}");
    assert!(!source.contains("table.unpack"), "{source}");
    assert!(!source.contains("[1]"), "{source}");

    let left = source.find("\"left\"").expect("left call");
    let right = source.find("\"right\"").expect("right call");
    assert!(left < right, "calls must retain source order:\n{source}");

    for line in source.lines() {
        if line.contains("\"left\"") || line.contains("\"right\"") {
            assert_eq!(
                line.matches('(').count(),
                1,
                "each scalar call is emitted exactly once:\n{line}\n{source}"
            );
        }
    }
}

#[test]
fn table_aliases_keep_identity_and_reads_follow_overwrites() {
    let instructions = vec![
        Instruction::NewTable {
            dst: Register { physical_slot: 1 },
        },
        Instruction::Move {
            dst: Register { physical_slot: 2 },
            src: reg(1),
        },
        Instruction::NewTable {
            dst: Register { physical_slot: 3 },
        },
        Instruction::SetTable {
            table: reg(1),
            index: string("x"),
            value: integer(1),
        },
        Instruction::GetTable {
            dst: Register { physical_slot: 4 },
            table: reg(2),
            index: string("x"),
        },
        Instruction::SetTable {
            table: reg(3),
            index: string("x"),
            value: integer(2),
        },
        Instruction::GetTable {
            dst: Register { physical_slot: 5 },
            table: reg(3),
            index: string("x"),
        },
        Instruction::SetTable {
            table: reg(1),
            index: string("x"),
            value: integer(3),
        },
        Instruction::GetTable {
            dst: Register { physical_slot: 6 },
            table: reg(2),
            index: string("x"),
        },
        // Route this program through the captured-environment renderer; the
        // read is intentionally after the table operations so the alias names
        // above stay stable.
        environment_member(7, "seed"),
        Instruction::Jump { target: 2 },
    ];
    let source = emit_luau(
        &program(
            1,
            vec![
                block(1, instructions, vec![successor(EdgeLabel::Next, Some(2))]),
                block(
                    2,
                    vec![Instruction::Return { values: vec![] }],
                    vec![successor(EdgeLabel::Return, None)],
                ),
            ],
        ),
        &strict(),
    )
    .expect("table aliases should render");

    // Two constructors stay distinct; the alias is not a second table.
    assert_eq!(source.matches("{ [any]: any } = {}").count(), 2, "{source}");
    assert!(source.contains("tableValue"), "{source}");
    assert!(source.contains("tableValue2"), "{source}");

    let write_one = source.find("tableValue.x = 1").expect("first write");
    let read_alias = source
        .find("local value = tableValue.x")
        .expect("alias read after first write");
    let write_other = source.find("tableValue2.x = 2").expect("other table write");
    let read_other = source
        .find("local value2 = tableValue2.x")
        .expect("other table read");
    let write_two = source.find("tableValue.x = 3").expect("overwrite");
    let read_again = source
        .find("local value3 = tableValue.x")
        .expect("alias read after overwrite");

    assert!(write_one < read_alias, "{source}");
    assert!(read_alias < write_other, "{source}");
    assert!(write_other < read_other, "{source}");
    assert!(read_other < write_two, "{source}");
    assert!(write_two < read_again, "{source}");

    // No element was inlined through either alias; both reads are real reads.
    for line in source.lines() {
        let line = line.trim();
        if line.contains("= tableValue") || line.contains("= tableValue2") {
            assert!(
                line.contains(".x"),
                "table reads must not inline element constants:\n{line}\n{source}"
            );
        }
    }
}

#[test]
fn branch_phi_preserves_false_and_nil_without_truthiness_shortcuts() {
    let mut entry = vec![environment_member(1, "predicate")];
    entry.push(Instruction::Branch {
        condition: Condition::Truthy(reg(1)),
        then_target: 2,
        else_target: 3,
    });

    let mut join = vec![Instruction::Call {
        dst: None,
        function: reg(1),
        args: vec![reg(2)],
        result_count: None,
    }];
    join.push(Instruction::Jump { target: 5 });

    let source = emit_luau(
        &program(
            1,
            vec![
                block(
                    1,
                    entry,
                    vec![
                        successor(EdgeLabel::True, Some(2)),
                        successor(EdgeLabel::False, Some(3)),
                    ],
                ),
                block(
                    2,
                    vec![
                        Instruction::LoadConst {
                            dst: Register { physical_slot: 2 },
                            value: Constant::Boolean(false),
                        },
                        Instruction::Jump { target: 4 },
                    ],
                    vec![successor(EdgeLabel::Next, Some(4))],
                ),
                block(
                    3,
                    vec![
                        Instruction::LoadConst {
                            dst: Register { physical_slot: 2 },
                            value: Constant::Nil,
                        },
                        Instruction::Jump { target: 4 },
                    ],
                    vec![successor(EdgeLabel::Next, Some(4))],
                ),
                block(4, join, vec![successor(EdgeLabel::Next, Some(5))]),
                block(
                    5,
                    vec![Instruction::Return { values: vec![] }],
                    vec![successor(EdgeLabel::Return, None)],
                ),
            ],
        ),
        &strict(),
    )
    .expect("branch phi should render");

    let condition_line = source
        .lines()
        .find(|line| line.contains("environment.predicate"))
        .expect("predicate load");
    let condition = condition_line
        .trim()
        .strip_prefix("local ")
        .expect("local predicate binding")
        .split_whitespace()
        .next()
        .expect("predicate name");
    assert!(source.contains(&format!("if {condition} then")), "{source}");

    let phi_line = source
        .lines()
        .find(|line| line.trim_start().starts_with("local ") && line.contains(": any"))
        .expect("merged phi binding");
    assert!(
        !phi_line.contains('='),
        "the phi must be initialized in both arms, not guessed:\n{phi_line}\n{source}"
    );
    let phi = phi_line
        .trim()
        .strip_prefix("local ")
        .expect("local phi")
        .split(':')
        .next()
        .expect("phi name")
        .trim();

    let false_assignment = format!("{phi} = false");
    let nil_assignment = format!("{phi} = nil");
    assert_eq!(source.matches(&false_assignment).count(), 1, "{source}");
    assert_eq!(source.matches(&nil_assignment).count(), 1, "{source}");
    assert!(
        source.find(&false_assignment) < source.find(&nil_assignment),
        "truthy then-arm must keep false and the else-arm nil:\n{source}"
    );
    assert!(source.contains(&format!("{condition}({phi})")), "{source}");
    assert!(!source.contains("false or"), "{source}");
    assert!(!source.contains("nil or"), "{source}");
    assert!(
        !source
            .lines()
            .any(|line| line.contains("false") && line.contains("nil")),
        "false and nil must not be folded into one expression:\n{source}"
    );
    assert!(
        !source
            .lines()
            .any(|line| line.trim_start().starts_with("return")),
        "an empty return must not fabricate return values:\n{source}"
    );
}

#[test]
fn falsey_condition_is_logical_not_without_coercing_false_to_nil() {
    let entry = vec![
        environment_member(1, "flag"),
        Instruction::Branch {
            condition: Condition::Falsey(Operand::Constant(Constant::Boolean(false))),
            then_target: 2,
            else_target: 3,
        },
    ];
    let source = emit_luau(
        &program(
            1,
            vec![
                block(
                    1,
                    entry,
                    vec![
                        successor(EdgeLabel::True, Some(2)),
                        successor(EdgeLabel::False, Some(3)),
                    ],
                ),
                block(
                    2,
                    vec![Instruction::Nop, Instruction::Jump { target: 4 }],
                    vec![successor(EdgeLabel::Next, Some(4))],
                ),
                block(
                    3,
                    vec![Instruction::Nop, Instruction::Jump { target: 4 }],
                    vec![successor(EdgeLabel::Next, Some(4))],
                ),
                block(
                    4,
                    vec![Instruction::Return { values: vec![] }],
                    vec![successor(EdgeLabel::Return, None)],
                ),
            ],
        ),
        &strict(),
    )
    .expect("falsey condition should render");

    assert!(source.contains("if not (false) then"), "{source}");
    assert!(!source.contains("not (nil)"), "{source}");
    assert_eq!(source.matches("false").count(), 1, "{source}");
    assert!(!source.contains("return"), "{source}");
}

#[test]
fn empty_return_does_not_fabricate_any_return_values() {
    let source = emit_luau(
        &program(
            1,
            vec![
                block(
                    1,
                    vec![environment_member(1, "x"), Instruction::Jump { target: 2 }],
                    vec![successor(EdgeLabel::Next, Some(2))],
                ),
                block(
                    2,
                    vec![Instruction::Return { values: vec![] }],
                    vec![successor(EdgeLabel::Return, None)],
                ),
            ],
        ),
        &strict(),
    )
    .expect("empty return should render");

    assert!(source.contains("environment.x"), "{source}");
    assert!(!source.contains("return nil"), "{source}");
    assert!(!source.contains("return ,"), "{source}");
    assert!(
        !source
            .lines()
            .any(|line| line.trim_start().starts_with("return")),
        "empty Return must not become a value-producing return:\n{source}"
    );
}

#[test]
fn raw_instruction_is_rejected_by_the_captured_renderer() {
    let error = emit_luau(
        &program(
            1,
            vec![
                block(
                    1,
                    vec![
                        environment_member(1, "fn"),
                        Instruction::Raw {
                            family: 7,
                            selector: 9,
                            words: vec![1, 2, 3],
                        },
                        Instruction::Jump { target: 2 },
                    ],
                    vec![successor(EdgeLabel::Next, Some(2))],
                ),
                block(
                    2,
                    vec![Instruction::Return { values: vec![] }],
                    vec![successor(EdgeLabel::Return, None)],
                ),
            ],
        ),
        &strict(),
    )
    .expect_err("Raw must fail closed");

    let lower = error.to_ascii_lowercase();
    assert!(
        lower.contains("unsupported") || lower.contains("raw"),
        "unexpected Raw error: {error}"
    );
}

#[test]
fn cyclic_captured_environment_program_fails_instead_of_silently_unrolling() {
    let error = emit_luau(
        &program(
            1,
            vec![
                block(
                    1,
                    vec![
                        environment_member(1, "loop"),
                        Instruction::Jump { target: 2 },
                    ],
                    vec![successor(EdgeLabel::Next, Some(2))],
                ),
                block(
                    2,
                    vec![Instruction::Nop, Instruction::Jump { target: 1 }],
                    vec![successor(EdgeLabel::Next, Some(1))],
                ),
            ],
        ),
        &strict(),
    )
    .expect_err("a captured-environment loop must not be silently unrolled");

    assert!(
        error.to_ascii_lowercase().contains("loop"),
        "unexpected loop error: {error}"
    );
}
