//! Extended captured-environment dataflow smoke tests for newer IR constructs.

use std::collections::{BTreeMap, BTreeSet};

use luau_devirt::emit_luau;
use luau_devirt::ir::{
    BasicBlock, CodegenOptions, Constant, EdgeLabel, Instruction, LiftedProgram, Operand, Register,
    Successor,
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
        pretty: false,
    }
}

#[test]
fn call_with_packed_args_renders_table_unpack() {
    let mut first = vec![environment_member(1, "fn")];
    first.push(Instruction::NewPackedTable {
        dst: Register { physical_slot: 2 },
    });
    first.push(Instruction::PushPacked {
        table: reg(2),
        value: integer(7),
    });
    first.push(Instruction::CallWithPackedArgs {
        dst: None,
        function: reg(1),
        prefix: vec![string("left")],
        arguments: reg(2),
        result_count: None,
    });
    first.push(Instruction::Jump { target: 3 });

    let source = emit_luau(
        &program(
            1,
            vec![
                block(1, first, vec![successor(EdgeLabel::Next, Some(3))]),
                block(
                    3,
                    vec![Instruction::Return { values: vec![] }],
                    vec![successor(EdgeLabel::Return, None)],
                ),
            ],
        ),
        &strict(),
    )
    .expect("CallWithPackedArgs should render");

    assert!(source.contains("capturedUnpack"), "{source}");
    assert!(source.contains("\"left\""), "{source}");
}

#[test]
fn capture_operand_renders_as_capture_binding() {
    // A child prototype receiving a captured value must render it as capture0,
    // preserving capture identity rather than inventing a register.
    // child entry 2 receives capture0
    // Build a two-entry program: root creates closure with one capture.
    // We'll just test the child body rendering via a captured-env program.
    let child_block = block(
        2,
        vec![
            Instruction::Move {
                dst: Register { physical_slot: 3 },
                src: Operand::Capture(0),
            },
            Instruction::Return {
                values: vec![reg(3)],
            },
        ],
        vec![successor(EdgeLabel::Return, None)],
    );
    let mut root = vec![environment_member(1, "value")];
    root.push(Instruction::NewClosure {
        dst: Register { physical_slot: 4 },
        prototype_word: 7,
        captures: vec![reg(1)],
    });
    root.push(Instruction::Return {
        values: vec![reg(4)],
    });
    root.push(Instruction::Jump { target: 3 });

    let prog = LiftedProgram {
        blocks: {
            let mut m = BTreeMap::new();
            let r = block(1, root, vec![successor(EdgeLabel::Next, Some(3))]);
            // fix: block already
            m.insert(1, r.1);
            m.insert(2, child_block.1);
            m.insert(
                3,
                block(
                    3,
                    vec![Instruction::Return { values: vec![] }],
                    vec![successor(EdgeLabel::Return, None)],
                )
                .1,
            );
            m
        },
        entry_points: vec![1, 2],
        reachable_pcs: BTreeSet::from([1, 2, 3]),
        state_variants: 0,
        root_entry: Some(1),
        prototype_entries: BTreeMap::from([(7, 2)]),
        parameters: BTreeMap::from([(1, None), (2, Some(0))]),
    };

    let source = emit_luau(&prog, &strict()).expect("capture should render");
    assert!(source.contains("capture0"), "{source}");
    // factory must be declared and invoked with the captured value
    assert!(source.contains("vm_factory_2"), "{source}");
}

#[test]
fn type_of_renders_captured_type() {
    let mut first = vec![environment_member(1, "value")];
    first.push(Instruction::Unary {
        dst: Register { physical_slot: 2 },
        op: luau_devirt::ir::UnaryOp::TypeOf,
        src: reg(1),
    });
    first.push(Instruction::Return {
        values: vec![reg(2)],
    });
    first.push(Instruction::Jump { target: 3 });

    let source = emit_luau(
        &program(
            1,
            vec![
                block(1, first, vec![successor(EdgeLabel::Next, Some(3))]),
                block(
                    3,
                    vec![Instruction::Return { values: vec![] }],
                    vec![successor(EdgeLabel::Return, None)],
                ),
            ],
        ),
        &strict(),
    )
    .expect("TypeOf should render");
    assert!(source.contains("capturedType"), "{source}");
    assert!(source.contains("local capturedType = type"), "{source}");
}

#[test]
fn unknown_arity_first_projection_keeps_packet_and_index() {
    let mut first = vec![environment_member(1, "fn")];
    first.push(Instruction::Call {
        dst: Some(Register { physical_slot: 2 }),
        function: reg(1),
        args: vec![],
        result_count: None,
    });
    first.push(Instruction::GetTable {
        dst: Register { physical_slot: 3 },
        table: reg(2),
        index: integer(1),
    });
    first.push(Instruction::Return {
        values: vec![reg(3)],
    });
    first.push(Instruction::Jump { target: 4 });

    let source = emit_luau(
        &program(
            1,
            vec![
                block(1, first, vec![successor(EdgeLabel::Next, Some(4))]),
                block(
                    4,
                    vec![Instruction::Return { values: vec![] }],
                    vec![successor(EdgeLabel::Return, None)],
                ),
            ],
        ),
        &strict(),
    )
    .expect("unknown-arity [1] projection should render");
    assert!(source.contains("capturedPack"), "{source}");
    assert!(source.contains("[1]"), "{source}");
}

#[test]
fn word_and_unknown_operands_are_rejected() {
    let mut first = vec![Instruction::Move {
        dst: Register { physical_slot: 1 },
        src: Operand::Word(42),
    }];
    first.push(Instruction::Return {
        values: vec![reg(1)],
    });
    first.push(Instruction::Jump { target: 3 });
    let err = emit_luau(
        &program(
            1,
            vec![
                block(1, first, vec![successor(EdgeLabel::Next, Some(3))]),
                block(
                    3,
                    vec![Instruction::Return { values: vec![] }],
                    vec![successor(EdgeLabel::Return, None)],
                ),
            ],
        ),
        &strict(),
    )
    .unwrap_err();
    assert!(
        err.contains("raw word reference")
            || err.contains("not a proved value")
            || err.contains("unresolved register or operand bindings"),
        "{err}"
    );
}

#[test]
fn unknown_operand_rejected_in_captured_dataflow() {
    let mut first = vec![environment_member(1, "value")];
    first.push(Instruction::Move {
        dst: Register { physical_slot: 2 },
        src: Operand::Unknown(7),
    });
    first.push(Instruction::Return {
        values: vec![reg(2)],
    });
    first.push(Instruction::Jump { target: 3 });

    let err = emit_luau(
        &program(
            1,
            vec![
                block(1, first, vec![successor(EdgeLabel::Next, Some(3))]),
                block(
                    3,
                    vec![Instruction::Return { values: vec![] }],
                    vec![successor(EdgeLabel::Return, None)],
                ),
            ],
        ),
        &strict(),
    )
    .unwrap_err();
    assert!(err.contains("unresolved VM operand"), "{err}");
}

// ---- Both-flags static contract tests ----

fn pretty_opts() -> CodegenOptions {
    CodegenOptions {
        strict: true,
        include_source_comments: false,
        pretty: true,
    }
}

#[test]
fn return_terminal_renders_actual_return_both_flags() {
    let mut first = vec![environment_member(1, "value")];
    first.push(Instruction::Return {
        values: vec![reg(1)],
    });
    // no trailing Jump: Return is the terminal.
    for pretty in [false, true] {
        let opts = if pretty { pretty_opts() } else { strict() };
        let source = emit_luau(
            &program(
                1,
                vec![block(
                    1,
                    first.clone(),
                    vec![successor(EdgeLabel::Return, None)],
                )],
            ),
            &opts,
        )
        .expect("valid Return terminal should emit");
        assert!(source.contains("return"), "{source}");
        assert!(!source.contains("-- return"), "{source}");
        assert!(!source.contains("Comment"), "{source}");
    }
}

#[test]
fn call_with_packed_args_exact_arity_both_flags() {
    let mut first = vec![environment_member(1, "fn")];
    first.push(Instruction::NewPackedTable {
        dst: Register { physical_slot: 2 },
    });
    first.push(Instruction::PushPacked {
        table: reg(2),
        value: integer(7),
    });
    first.push(Instruction::CallWithPackedArgs {
        dst: Some(Register { physical_slot: 3 }),
        function: reg(1),
        prefix: vec![string("left")],
        arguments: reg(2),
        result_count: Some(1),
    });
    first.push(Instruction::GetTable {
        dst: Register { physical_slot: 4 },
        table: reg(3),
        index: integer(1),
    });
    first.push(Instruction::Return {
        values: vec![reg(4)],
    });
    for pretty in [false, true] {
        let opts = if pretty { pretty_opts() } else { strict() };
        let source = emit_luau(
            &program(
                1,
                vec![block(
                    1,
                    first.clone(),
                    vec![successor(EdgeLabel::Return, None)],
                )],
            ),
            &opts,
        )
        .expect("packed args should emit");
        assert!(
            source.contains("capturedPack") || source.contains("table.pack"),
            "{source}"
        );
        assert!(
            source.contains("capturedUnpack") || source.contains("table.unpack"),
            "{source}"
        );
        assert!(source.contains("\"left\""), "{source}");
    }
}

#[test]
fn concat_renamed_binding_both_flags() {
    let mut first = vec![environment_member(1, "a")];
    first.push(environment_member(2, "b"));
    first.push(Instruction::Concat {
        dst: Register { physical_slot: 3 },
        values: vec![reg(1), reg(2)],
    });
    first.push(Instruction::Return {
        values: vec![reg(3)],
    });
    for pretty in [false, true] {
        let opts = if pretty { pretty_opts() } else { strict() };
        let source = emit_luau(
            &program(
                1,
                vec![block(
                    1,
                    first.clone(),
                    vec![successor(EdgeLabel::Return, None)],
                )],
            ),
            &opts,
        )
        .expect("concat should emit");
        assert!(source.contains(".."), "{source}");
    }
}

#[test]
fn append_packed_nil_self_both_flags() {
    let mut first = vec![Instruction::NewPackedTable {
        dst: Register { physical_slot: 1 },
    }];
    first.push(Instruction::PushPacked {
        table: reg(1),
        value: Operand::Constant(Constant::Nil),
    });
    first.push(Instruction::AppendPacked {
        table: reg(1),
        values: reg(1),
    });
    first.push(Instruction::ReturnPacked { values: reg(1) });
    for pretty in [false, true] {
        let opts = if pretty { pretty_opts() } else { strict() };
        let source = emit_luau(
            &program(
                1,
                vec![block(
                    1,
                    first.clone(),
                    vec![successor(EdgeLabel::Return, None)],
                )],
            ),
            &opts,
        )
        .expect("append packed self should emit");
        assert!(source.contains("nil"), "{source}");
    }
}

#[test]
fn root_capture_rejected() {
    let mut first = vec![environment_member(1, "value")];
    first.push(Instruction::NewClosure {
        dst: Register { physical_slot: 2 },
        prototype_word: 7,
        captures: vec![reg(1)],
    });
    first.push(Instruction::Return {
        values: vec![reg(2)],
    });
    // root_entry captures via NewClosure creates root capture contract violation
    let prog = LiftedProgram {
        blocks: {
            let mut m = BTreeMap::new();
            m.insert(
                1,
                block(1, first, vec![successor(EdgeLabel::Return, None)]).1,
            );
            m
        },
        entry_points: vec![1],
        reachable_pcs: BTreeSet::from([1]),
        state_variants: 0,
        root_entry: Some(1),
        prototype_entries: BTreeMap::from([(7, 1)]),
        parameters: BTreeMap::new(),
    };
    let err = emit_luau(&prog, &strict()).unwrap_err();
    assert!(
        err.contains("root closure captures")
            || err.contains("unlinked closure")
            || err.contains("declared child"),
        "{err}"
    );
}
