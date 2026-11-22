//! Static-only regressions for optional presentation cleanup. Calls below are
//! IR descriptions, never invocations of Lua/Luau or recovered functions.

use luau_devirt::ir::{
    BasicBlock, BinaryOp, CodegenOptions, Condition, Constant, EdgeLabel, Instruction,
    LiftedProgram, Operand, Register, Successor, ValueExpression,
};
use luau_devirt::{decode_file, emit_luau, walk_cfg};
use std::collections::BTreeMap;

fn register(slot: u16) -> Register {
    Register {
        physical_slot: slot,
    }
}

fn reg(slot: u16) -> Operand {
    Operand::Register(register(slot))
}

fn string(text: &str) -> Operand {
    Operand::Constant(Constant::String(text.as_bytes().to_vec()))
}

fn int(value: i64) -> Operand {
    Operand::Constant(Constant::Integer(value))
}

fn read(dst: u16, table: Operand, key: &str) -> Instruction {
    Instruction::GetTable {
        dst: register(dst),
        table,
        index: string(key),
    }
}

fn write(table: u16, key: &str, value: Operand) -> Instruction {
    Instruction::SetTable {
        table: reg(table),
        index: string(key),
        value,
    }
}

fn call(function: u16, args: Vec<Operand>) -> Instruction {
    Instruction::Call {
        dst: None,
        function: reg(function),
        args,
        result_count: None,
    }
}

fn scalar(packet: u16, dst: u16, function: u16, args: Vec<Operand>) -> Vec<Instruction> {
    vec![
        Instruction::Call {
            dst: Some(register(packet)),
            function: reg(function),
            args,
            result_count: Some(1),
        },
        Instruction::GetTable {
            dst: register(dst),
            table: reg(packet),
            index: int(1),
        },
    ]
}

fn edge(label: EdgeLabel, pc: Option<usize>) -> Successor {
    Successor {
        label,
        target_pc: pc,
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
            end_pc: pc + instructions.len(),
            handler_family: 0,
            entry_states: vec![],
            instructions,
            successors,
        },
    )
}

fn program(blocks: Vec<(usize, BasicBlock)>) -> LiftedProgram {
    let blocks: BTreeMap<_, _> = blocks.into_iter().collect();
    LiftedProgram {
        reachable_pcs: blocks.keys().copied().collect(),
        blocks,
        entry_points: vec![1],
        root_entry: Some(1),
        ..LiftedProgram::default()
    }
}

fn linear(mut instructions: Vec<Instruction>) -> LiftedProgram {
    instructions.push(Instruction::Return { values: vec![] });
    program(vec![block(
        1,
        instructions,
        vec![edge(EdgeLabel::Return, None)],
    )])
}

fn pretty(program: &LiftedProgram) -> String {
    emit_luau(
        program,
        &CodegenOptions {
            pretty: true,
            ..CodegenOptions::default()
        },
    )
    .expect("pretty emission")
}

fn diamond(mut yes: Vec<Instruction>, mut no: Vec<Instruction>) -> LiftedProgram {
    yes.push(Instruction::Jump { target: 4 });
    no.push(Instruction::Jump { target: 4 });
    program(vec![
        block(
            1,
            vec![
                read(1, Operand::Environment, "predicate"),
                Instruction::Move {
                    dst: register(2),
                    src: reg(1),
                },
                Instruction::Branch {
                    condition: Condition::Truthy(reg(1)),
                    then_target: 2,
                    else_target: 3,
                },
            ],
            vec![
                edge(EdgeLabel::True, Some(2)),
                edge(EdgeLabel::False, Some(3)),
            ],
        ),
        block(2, yes, vec![edge(EdgeLabel::Next, Some(4))]),
        block(3, no, vec![edge(EdgeLabel::Next, Some(4))]),
        block(
            4,
            vec![
                read(10, Operand::Environment, "sink"),
                call(10, vec![reg(2)]),
                Instruction::Return { values: vec![] },
            ],
            vec![edge(EdgeLabel::Return, None)],
        ),
    ])
}

#[test]
fn pretty_is_opt_in_and_all_three_profile_defaults_are_unchanged() {
    assert!(!CodegenOptions::default().pretty);
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let expected = include_str!("fixtures/sarp.pretty.luau");
    for (fixture, golden) in [
        (
            "sample.lua",
            include_str!("../examples/sample.recovered.luau"),
        ),
        (
            "base85-rotor.lua",
            include_str!("../decompilation/message/target.deobfuscated.lua"),
        ),
        (
            "sarp.lua",
            include_str!("../decompilation/sarp/target.deobfuscated.lua"),
        ),
    ] {
        let input = root.join("tests/fixtures").join(fixture);
        let before = std::fs::read(&input).unwrap();
        let vm = decode_file(&input).unwrap();
        let program = walk_cfg(&vm).unwrap();
        let ir_before = program.clone();
        assert_eq!(
            emit_luau(&program, &CodegenOptions::default()).unwrap(),
            golden
        );
        let output = pretty(&program);
        if fixture == "sample.lua" {
            // The scanner already has a proved high-level renderer; tuple and
            // loop handling deliberately retain that established output.
            assert_eq!(output, golden);
        } else {
            assert_eq!(output, expected);
            assert!(output.len() < golden.len());
            assert!(output.contains("events and events.FindFirstChild("));
            assert!(output.contains("dialogueEvent and dialogueEvent.IsA("));
            assert!(!output.contains("local getService"));
            assert!(output.contains("local dialogueOptions: { [any]: any } = {\n"));
        }
        assert_eq!(program, ir_before, "presentation must not modify shared IR");
        assert_eq!(
            emit_luau(&program, &CodegenOptions::default()).unwrap(),
            golden
        );
        assert_eq!(std::fs::read(input).unwrap(), before);
    }
}

#[test]
fn pretty_retains_method_cache_across_an_effect_and_never_expands_call_arguments() {
    let mut instructions = vec![
        read(1, Operand::Environment, "subject"),
        read(2, reg(1), "method"),
        read(3, Operand::Environment, "produce"),
    ];
    instructions.extend(scalar(4, 5, 3, vec![]));
    instructions.push(call(2, vec![reg(1), reg(5)]));
    let output = pretty(&linear(instructions));
    let method = output.find(".method").unwrap();
    let producer = output.find("environment.produce()").unwrap();
    assert!(method < producer, "{output}");
    assert_eq!(output.matches(".method").count(), 1, "{output}");
    assert_eq!(
        output.matches("environment.produce()").count(),
        1,
        "{output}"
    );
    assert!(!output.contains(", environment.produce()"), "{output}");
    assert!(
        output.contains("local value4 = environment.produce()"),
        "{output}"
    );
}

#[test]
fn pretty_inlines_scalar_field_values_without_reordering_calls_or_reloading_the_function() {
    let mut instructions = vec![
        read(1, Operand::Environment, "factory"),
        Instruction::NewTable { dst: register(10) },
    ];
    instructions.extend(scalar(2, 3, 1, vec![string("left")]));
    instructions.push(write(10, "x", reg(3)));
    instructions.extend(scalar(4, 5, 1, vec![string("right")]));
    instructions.push(write(10, "y", reg(5)));
    let output = pretty(&linear(instructions));
    assert_eq!(output.matches("environment.factory").count(), 1, "{output}");
    assert!(
        output.contains("tableValue.x = value(\"left\")"),
        "{output}"
    );
    assert!(
        output.contains("tableValue.y = value(\"right\")"),
        "{output}"
    );
    assert!(
        output.find("\"left\"") < output.find("\"right\""),
        "{output}"
    );
    assert!(!output.contains("x = value(\"left\"),"), "{output}");
}

#[test]
fn pretty_short_circuits_only_predicate_carrying_arms() {
    let mut rhs = vec![read(3, reg(1), "method")];
    rhs.extend(scalar(4, 5, 3, vec![reg(1)]));
    rhs.push(Instruction::Move {
        dst: register(2),
        src: reg(5),
    });
    for (yes, no, operator) in [
        (rhs.clone(), vec![Instruction::Nop], "and"),
        (vec![Instruction::Nop], rhs, "or"),
    ] {
        let output = pretty(&diamond(yes, no));
        assert!(!output.contains("\nif "), "{output}");
        assert!(
            output.contains(&format!(" {operator} value.method(value)")),
            "{output}"
        );
        assert_eq!(output.matches(".method(").count(), 1, "{output}");
        assert_eq!(
            output.matches("environment.predicate").count(),
            1,
            "{output}"
        );
    }
}

#[test]
fn pretty_keeps_false_nil_and_nonpredicate_fallbacks_distinct() {
    let output = pretty(&diamond(
        vec![Instruction::LoadConst {
            dst: register(2),
            value: Constant::Boolean(false),
        }],
        vec![Instruction::LoadConst {
            dst: register(2),
            value: Constant::Nil,
        }],
    ));
    assert!(output.contains("\nif value then"), "{output}");
    assert!(output.contains(" = false\n"), "{output}");
    assert!(output.contains(" = nil\n"), "{output}");
    assert!(!output.contains(" and "), "{output}");
    assert!(!output.contains(" or "), "{output}");

    let output = pretty(&diamond(
        vec![Instruction::LoadConst {
            dst: register(2),
            value: Constant::Integer(7),
        }],
        vec![Instruction::LoadConst {
            dst: register(2),
            value: Constant::Nil,
        }],
    ));
    assert!(output.contains("\nif value then"), "{output}");
    assert!(
        !output.contains(" and "),
        "false predicate must not be replaced with nil:\n{output}"
    );
}

#[test]
fn pretty_never_makes_a_conditional_side_effect_eager() {
    let output = pretty(&diamond(
        vec![
            call(1, vec![string("conditional-effect")]),
            Instruction::LoadConst {
                dst: register(2),
                value: Constant::Boolean(false),
            },
        ],
        vec![Instruction::Nop],
    ));
    let condition = output.find("if value then").unwrap();
    let effect = output.find("\tvalue(\"conditional-effect\")").unwrap();
    let end = output[effect..].find("\nend").unwrap() + effect;
    assert!(condition < effect && effect < end, "{output}");
    assert!(!output.contains(" and "), "{output}");
}

#[test]
fn pretty_table_prefix_keeps_aliases_duplicate_writes_and_self_reference() {
    let output = pretty(&linear(vec![
        read(9, Operand::Environment, "seed"),
        Instruction::NewTable { dst: register(1) },
        Instruction::Move {
            dst: register(2),
            src: reg(1),
        },
        write(2, "x", int(1)),
        write(1, "x", int(2)),
        read(3, reg(2), "x"),
        write(1, "self", reg(2)),
    ]));
    assert_eq!(output.matches("local tableValue:").count(), 1, "{output}");
    assert!(output.contains("= { x = 1 }"), "{output}");
    assert!(output.contains("tableValue.x = 2"), "{output}");
    assert!(
        output.find("tableValue.x = 2") < output.find("= tableValue.x"),
        "{output}"
    );
    assert!(output.contains("tableValue.self = tableValue"), "{output}");
    assert!(!output.contains("{ self = tableValue"), "{output}");
}

#[test]
fn pretty_constructor_stops_at_escape_allocation_read_and_invalid_or_dynamic_keys() {
    let output = pretty(&linear(vec![
        read(9, Operand::Environment, "sink"),
        Instruction::NewTable { dst: register(1) },
        call(9, vec![reg(1)]),
        write(1, "x", int(1)),
    ]));
    assert!(output.contains("= {}"), "{output}");
    assert!(
        output.find("(tableValue)") < output.find("tableValue.x = 1"),
        "{output}"
    );

    let output = pretty(&linear(vec![
        read(9, Operand::Environment, "seed"),
        Instruction::NewTable { dst: register(1) },
        Instruction::NewTable { dst: register(2) },
        write(1, "x", int(1)),
        read(3, reg(1), "x"),
        write(1, "y", int(2)),
        Instruction::SetTable {
            table: reg(2),
            index: Operand::Constant(Constant::Nil),
            value: int(3),
        },
    ]));
    assert!(
        output.contains("local tableValue: { [any]: any } = {}"),
        "{output}"
    );
    assert!(output.contains("tableValue.x = 1"), "{output}");
    assert!(
        output.find("= tableValue.x") < output.find("tableValue.y = 2"),
        "{output}"
    );
    assert!(output.contains("tableValue2[nil] = 3"), "{output}");

    let output = pretty(&linear(vec![
        read(9, Operand::Environment, "key"),
        Instruction::NewTable { dst: register(1) },
        Instruction::SetTable {
            table: reg(1),
            index: reg(9),
            value: int(1),
        },
    ]));
    assert!(output.contains("= {}"), "{output}");
    assert!(output.contains("tableValue[value] = 1"), "{output}");
}

#[test]
fn pretty_preserves_escaped_keys_literals_and_scalar_expression_precedence() {
    let output = pretty(&linear(vec![
        read(9, Operand::Environment, "seed"),
        Instruction::NewTable { dst: register(1) },
        write(1, "end", string("recoveredValue0")),
        write(1, "not a field", string("and or false nil")),
        Instruction::SetTable {
            table: reg(1),
            index: string("result"),
            value: Operand::Expression(Box::new(ValueExpression::Binary {
                op: BinaryOp::Mul,
                left: int(3),
                right: Operand::Expression(Box::new(ValueExpression::Binary {
                    op: BinaryOp::Add,
                    left: int(1),
                    right: int(2),
                })),
            })),
        },
        Instruction::SetTable {
            table: reg(1),
            index: string("power"),
            value: Operand::Expression(Box::new(ValueExpression::Binary {
                op: BinaryOp::Pow,
                left: int(-1),
                right: int(2),
            })),
        },
        Instruction::SetTable {
            table: reg(1),
            index: string("fractionalPower"),
            value: Operand::Expression(Box::new(ValueExpression::Binary {
                op: BinaryOp::Pow,
                left: Operand::Constant(Constant::NumberBits((-2.5f64).to_bits())),
                right: int(2),
            })),
        },
    ]));
    assert!(
        output.contains("[\"end\"] = \"recoveredValue0\""),
        "{output}"
    );
    assert!(
        output.contains("[\"not a field\"] = \"and or false nil\""),
        "{output}"
    );
    assert!(output.contains("= 3 * (1 + 2)"), "{output}");
    assert!(output.contains("= (-1) ^ 2"), "{output}");
    assert!(output.contains("= (-2.5) ^ 2"), "{output}");
}

#[test]
fn pretty_composes_with_comments_and_no_strict_without_losing_address_evidence() {
    let vm = decode_file(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sarp.lua"),
    )
    .unwrap();
    let program = walk_cfg(&vm).unwrap();
    let options = CodegenOptions {
        pretty: true,
        include_source_comments: true,
        strict: false,
    };
    let output = emit_luau(&program, &options).unwrap();
    assert!(!output.contains("--!strict"));
    let conservative = emit_luau(
        &program,
        &CodegenOptions {
            pretty: false,
            ..options.clone()
        },
    )
    .unwrap();
    let comments = |text: &str| {
        text.lines()
            .filter(|s| s.trim().starts_with("-- Source VM words"))
            .map(|s| s.trim().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(comments(&output), comments(&conservative));
    assert!(!comments(&output).is_empty());

    let strict = pretty(&program);
    let non_strict = emit_luau(
        &program,
        &CodegenOptions {
            strict: false,
            pretty: true,
            ..CodegenOptions::default()
        },
    )
    .unwrap();
    assert_eq!(strict.strip_prefix("--!strict\n\n").unwrap(), non_strict);
}

#[test]
fn pretty_keeps_unproved_tuple_arity_and_raw_instructions_as_errors() {
    let mut instructions = vec![read(1, Operand::Environment, "factory")];
    instructions.extend(scalar(2, 3, 1, vec![]));
    if let Instruction::Call { result_count, .. } = &mut instructions[1] {
        *result_count = None;
    }
    let program = linear(instructions);
    for pretty in [false, true] {
        let output = emit_luau(
            &program,
            &CodegenOptions {
                pretty,
                ..CodegenOptions::default()
            },
        )
        .expect("unknown-arity packet keeps a generic [1] projection");
        assert!(output.contains("[1]"), "{output}");
    }
    let program = linear(vec![
        read(1, Operand::Environment, "seed"),
        Instruction::Raw {
            family: 1,
            selector: 2,
            words: vec![3],
        },
    ]);
    for pretty in [false, true] {
        let error = emit_luau(
            &program,
            &CodegenOptions {
                pretty,
                ..CodegenOptions::default()
            },
        )
        .unwrap_err();
        assert!(
            error.contains("unsupported captured-dataflow instruction"),
            "{error}"
        );
    }
}

#[test]
fn pretty_does_not_change_escaped_packed_tuple_counts_or_nil_elements() {
    let program = program(vec![block(
        1,
        vec![
            Instruction::NewPackedTable { dst: register(1) },
            Instruction::PushPacked {
                table: reg(1),
                value: Operand::Constant(Constant::Nil),
            },
            Instruction::PushPacked {
                table: reg(1),
                value: Operand::Constant(Constant::Boolean(false)),
            },
            Instruction::Call {
                dst: None,
                function: Operand::Global(vec![b"observe".to_vec()]),
                args: vec![reg(1)],
                result_count: None,
            },
            Instruction::ReturnPacked { values: reg(1) },
        ],
        vec![edge(EdgeLabel::Return, None)],
    )]);
    let conservative = emit_luau(&program, &CodegenOptions::default()).unwrap();
    let output = pretty(&program);
    assert_eq!(output, conservative);
    assert!(output.contains(".n"), "{output}");
    assert!(
        output.contains("nil") && output.contains("false"),
        "{output}"
    );
    assert!(output.contains("table.unpack"), "{output}");
}

#[test]
fn pretty_keeps_multiple_live_branch_results_in_their_original_shared_control_flow() {
    let mut program = diamond(
        vec![
            Instruction::LoadConst {
                dst: register(2),
                value: Constant::Boolean(false),
            },
            Instruction::LoadConst {
                dst: register(3),
                value: Constant::Integer(1),
            },
        ],
        vec![Instruction::Nop],
    );
    program.blocks.get_mut(&1).unwrap().instructions.insert(
        2,
        Instruction::Move {
            dst: register(3),
            src: reg(1),
        },
    );
    if let Instruction::Call { args, .. } = &mut program.blocks.get_mut(&4).unwrap().instructions[1]
    {
        args.push(reg(3));
    }
    let output = pretty(&program);
    assert!(output.contains("\nif value then"), "{output}");
    assert!(
        output.contains(" = false\n") && output.contains(" = 1\n"),
        "{output}"
    );
    assert!(!output.contains(" and "), "{output}");
    assert!(!output.contains(" or "), "{output}");
}
