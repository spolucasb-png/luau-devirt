//! Manual typed IR only. Static assertions and official compile/analyze checks
//! never execute generated chunks, the protected input, or a VM.
use luau_devirt::{emit_luau, ir::*};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    process::Command,
};

fn r(slot: u16) -> Register {
    Register {
        physical_slot: slot,
    }
}
fn op(slot: u16) -> Operand {
    Operand::Register(r(slot))
}
fn text(value: &str) -> Operand {
    Operand::Constant(Constant::String(value.as_bytes().to_vec()))
}
fn member(dst: u16, name: &str) -> Instruction {
    Instruction::GetTable {
        dst: r(dst),
        table: Operand::Environment,
        index: text(name),
    }
}
fn block(pc: usize, instructions: Vec<Instruction>) -> BasicBlock {
    BasicBlock {
        start_pc: pc,
        end_pc: pc + 1,
        handler_family: 0,
        entry_states: vec![],
        instructions,
        successors: vec![Successor {
            label: EdgeLabel::Return,
            target_pc: None,
            state: None,
        }],
    }
}
fn root(instructions: Vec<Instruction>) -> LiftedProgram {
    LiftedProgram {
        blocks: BTreeMap::from([(1, block(1, instructions))]),
        reachable_pcs: BTreeSet::from([1]),
        entry_points: vec![1],
        root_entry: Some(1),
        parameters: BTreeMap::from([(1, None)]),
        ..Default::default()
    }
}
fn checked(program: &LiftedProgram, pretty: bool, name: &str) -> String {
    let source = emit_luau(
        program,
        &CodegenOptions {
            pretty,
            ..Default::default()
        },
    )
    .unwrap();
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let file = directory.join("target").join(format!(
        "manual-ir-{name}-{}-{pretty}.luau",
        std::process::id()
    ));
    std::fs::write(&file, &source).unwrap();
    for (variable, executable, args) in [
        ("LUAU_DEVIRT_COMPILER", "luau-compile.exe", vec!["--null"]),
        ("LUAU_DEVIRT_ANALYZER", "luau-analyze.exe", vec![]),
    ] {
        let explicit = std::env::var_os(variable);
        let tool = explicit
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| directory.join("tools/luau-0.747").join(executable));
        if !tool.is_file() {
            assert!(explicit.is_none(), "invalid {variable}");
            eprintln!("SKIP {name}: optional official {executable} unavailable");
            continue;
        }
        let output = Command::new(tool).args(args).arg(&file).output().unwrap();
        assert!(
            output.status.success(),
            "{name} pretty={pretty}:\n{}\n{}\n{source}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    source
        .replace("(capturedPack)", "capturedPack")
        .replace("(capturedUnpack)", "capturedUnpack")
}

#[test]
fn open_call_results_and_packed_arguments_expand_in_both_emitters() {
    let program = root(vec![
        member(1, "produce"),
        member(2, "consume"),
        Instruction::Call {
            dst: Some(r(3)),
            function: op(1),
            args: vec![],
            result_count: None,
        },
        Instruction::CallWithPackedArgs {
            dst: Some(r(4)),
            function: op(2),
            prefix: vec![text("prefix")],
            arguments: op(3),
            result_count: None,
        },
        Instruction::ReturnPacked { values: op(4) },
    ]);
    for pretty in [false, true] {
        let source = checked(&program, pretty, "open-tuples");
        let produce = source
            .lines()
            .find_map(|line| {
                line.strip_prefix("local ")
                    .and_then(|line| line.strip_suffix(" = environment.produce"))
            })
            .expect("producer lookup remains before consumer lookup");
        let consume = source
            .lines()
            .find_map(|line| {
                line.strip_prefix("local ")
                    .and_then(|line| line.strip_suffix(" = environment.consume"))
            })
            .expect("consumer lookup remains before producer call");
        assert!(
            source.contains(&format!("capturedPack({produce}())")),
            "{source}"
        );
        assert!(
            source.contains(&format!("{consume}(\"prefix\", capturedUnpack(")),
            "{source}"
        );
        assert!(
            !source.contains(&format!("capturedPack(({produce}())")),
            "{source}"
        );
        assert!(source.contains("return capturedUnpack("), "{source}");
    }
}

#[test]
fn fixed_call_result_packets_truncate_and_pad_without_guessing_arity() {
    for count in [0, 2, 4] {
        for packed in [false, true] {
            let mut instructions = vec![
                member(1, "produce"),
                Instruction::NewPackedTable { dst: r(2) },
            ];
            instructions.push(if packed {
                Instruction::CallWithPackedArgs {
                    dst: Some(r(3)),
                    function: op(1),
                    prefix: vec![],
                    arguments: op(2),
                    result_count: Some(count),
                }
            } else {
                Instruction::Call {
                    dst: Some(r(3)),
                    function: op(1),
                    args: vec![],
                    result_count: Some(count),
                }
            });
            instructions.push(Instruction::ReturnPacked { values: op(3) });
            for pretty in [false, true] {
                let source = checked(
                    &root(instructions.clone()),
                    pretty,
                    &format!("fixed-{count}-{packed}"),
                );
                assert!(
                    source.contains(&format!("for tupleIndex = {},", count + 1)),
                    "{source}"
                );
                assert!(source.contains(&format!(".n = {count}")), "{source}");
                assert!(source.contains("[tupleIndex] = nil"), "{source}");
            }
        }
    }
}

#[test]
fn root_varargs_are_packed_once_and_all_arguments_and_returns_are_forwarded() {
    let program = root(vec![
        member(1, "consume"),
        Instruction::Move {
            dst: r(2),
            src: Operand::Argument(0),
        },
        Instruction::CallWithPackedArgs {
            dst: None,
            function: op(1),
            prefix: vec![op(2)],
            arguments: Operand::SlotMapIndex(3),
            result_count: None,
        },
        Instruction::ReturnPacked {
            values: Operand::SlotMapIndex(3),
        },
    ]);
    for pretty in [false, true] {
        let source = checked(&program, pretty, "root-varargs");
        assert!(
            source.contains("local function vm_entry_1(...: any)"),
            "{source}"
        );
        assert_eq!(
            source
                .matches("local packedArguments = capturedPack(...)")
                .count(),
            1,
            "{source}"
        );
        assert!(
            source.contains("local arg0: any = capturedSelect(1, ...)"),
            "{source}"
        );
        assert!(source.ends_with("return vm_entry_1(...)\n"), "{source}");
        assert!(!source.contains("....n"), "{source}");
    }
}

#[test]
fn child_capture_snapshot_and_varargs_keep_independent_parameter_positions() {
    let mut program = root(vec![
        member(1, "cell"),
        Instruction::NewClosure {
            dst: r(2),
            prototype_word: 7,
            captures: vec![op(1)],
        },
        Instruction::Return {
            values: vec![op(2)],
        },
    ]);
    program.blocks.insert(
        2,
        block(
            2,
            vec![
                member(1, "consume"),
                Instruction::CallWithPackedArgs {
                    dst: None,
                    function: op(1),
                    prefix: vec![Operand::Capture(0), Operand::Argument(0)],
                    arguments: Operand::SlotMapIndex(3),
                    result_count: None,
                },
                Instruction::ReturnPacked {
                    values: Operand::SlotMapIndex(3),
                },
            ],
        ),
    );
    program.entry_points.push(2);
    program.reachable_pcs.insert(2);
    program.parameters.insert(2, None);
    program.prototype_entries.insert(7, 2);
    for pretty in [false, true] {
        let source = checked(&program, pretty, "child-varargs");
        assert!(
            source.contains("local function vm_entry_2(capture0: any, ...: any)"),
            "{source}"
        );
        assert!(
            source.contains("return vm_entry_2(capture0, ...)"),
            "{source}"
        );
        assert!(source.contains("capturedSelect(1, ...)"), "{source}");
        assert!(
            source.find("local environment").unwrap()
                < source.find("local function vm_entry_2").unwrap(),
            "{source}"
        );
    }
}

#[test]
fn invalid_frame_interfaces_and_root_factories_fail_explicitly() {
    let mut program = root(vec![
        member(1, "consume"),
        Instruction::CallWithPackedArgs {
            dst: None,
            function: op(1),
            prefix: vec![],
            arguments: Operand::SlotMapIndex(3),
            result_count: None,
        },
        Instruction::Return { values: vec![] },
    ]);
    program.parameters.insert(1, Some(1));
    for pretty in [false, true] {
        assert!(emit_luau(
            &program,
            &CodegenOptions {
                pretty,
                ..Default::default()
            }
        )
        .unwrap_err()
        .contains("fixed-arity"));
    }
    let mut program = root(vec![
        member(1, "cell"),
        Instruction::NewClosure {
            dst: r(2),
            prototype_word: 7,
            captures: vec![],
        },
        Instruction::Return {
            values: vec![op(2)],
        },
    ]);
    program.prototype_entries.insert(7, 1);
    assert!(emit_luau(&program, &Default::default())
        .unwrap_err()
        .contains("declared child"));
}

#[test]
fn concat_low_precedence_operands_remain_grouped() {
    let expression = Operand::Expression(Box::new(ValueExpression::Binary {
        op: BinaryOp::Or,
        left: text("left"),
        right: text("fallback"),
    }));
    let program = root(vec![
        member(1, "value"),
        Instruction::Concat {
            dst: r(2),
            values: vec![expression, op(1)],
        },
        Instruction::Return {
            values: vec![op(2)],
        },
    ]);
    for pretty in [false, true] {
        let source = checked(&program, pretty, "concat-precedence");
        assert!(source.contains("\"fallback\") .. "), "{source}");
        assert!(!source.contains("\"fallback\" .. "), "{source}");
        assert!(!source.contains("recoveredValue"), "{source}");
    }
}
