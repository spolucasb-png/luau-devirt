//! Completion and strict type checks for recovered output, without Luau execution.

use std::{fs, path::PathBuf, process::Command};

use luau_devirt::ir::{CodegenOptions, Instruction};
use luau_devirt::{decode_file, emit_luau, walk_cfg};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn sample_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("LUAU_DEVIRT_SAMPLE") {
        let path = PathBuf::from(path);
        assert!(
            path.is_file(),
            "invalid LUAU_DEVIRT_SAMPLE: {}",
            path.display()
        );
        return Some(path);
    }
    let path = root().join("tests").join("fixtures").join("sample.lua");
    if !path.is_file() {
        eprintln!("SKIP: fixture absent at {}", path.display());
        return None;
    }
    Some(path)
}

#[test]
fn every_reachable_instruction_has_typed_semantics() {
    let Some(sample) = sample_path() else { return };
    let vm = decode_file(sample).expect("decode sample");
    let program = walk_cfg(&vm).expect("walk sample");
    let unsupported: Vec<_> = program
        .blocks
        .iter()
        .flat_map(|(pc, block)| {
            block.instructions.iter().filter_map(move |instruction| {
                if let Instruction::Raw {
                    family, selector, ..
                } = instruction
                {
                    Some((*pc, *family, *selector))
                } else {
                    None
                }
            })
        })
        .collect();
    assert!(
        unsupported.is_empty(),
        "reachable sample instructions remain unsupported: {unsupported:?}"
    );
}

#[test]
fn emitted_source_passes_official_strict_type_analysis() {
    let Some(sample) = sample_path() else { return };
    let override_path = std::env::var_os("LUAU_DEVIRT_ANALYZER").map(PathBuf::from);
    let analyzer = override_path.clone().unwrap_or_else(|| {
        root()
            .join("tools")
            .join("luau-0.747")
            .join(if cfg!(windows) {
                "luau-analyze.exe"
            } else {
                "luau-analyze"
            })
    });
    if !analyzer.is_file() {
        assert!(
            override_path.is_none(),
            "invalid LUAU_DEVIRT_ANALYZER: {}",
            analyzer.display()
        );
        eprintln!("SKIP: official analyzer absent at {}", analyzer.display());
        return;
    }
    let vm = decode_file(sample).expect("decode sample");
    let program = walk_cfg(&vm).expect("walk sample");
    let source = emit_luau(&program, &CodegenOptions::default()).expect("emit sample");
    assert!(source
        .lines()
        .next()
        .is_some_and(|line| line == "--!strict"));
    let stage = root()
        .join("target")
        .join(format!("strict-output-{}.luau", std::process::id()));
    fs::write(&stage, source).expect("stage generated source");
    let result = Command::new(&analyzer).arg(&stage).output();
    let _ = fs::remove_file(&stage);
    let output = result.expect("run official static analyzer");
    assert!(
        output.status.success(),
        "strict analysis failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
