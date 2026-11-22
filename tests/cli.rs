//! CLI smoke tests. Running the Rust decoder does not execute any Lua source.

use std::{fs, path::PathBuf, process::Command};

use luau_devirt::{decode_file, emit_luau, ir::CodegenOptions, walk_cfg};

fn executable() -> &'static str {
    env!("CARGO_BIN_EXE_luau-devirt")
}

fn sample() -> Option<PathBuf> {
    let explicit = std::env::var_os("LUAU_DEVIRT_SAMPLE").map(PathBuf::from);
    let path = explicit.clone().unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("sample.lua")
    });
    if path.is_file() {
        Some(path)
    } else {
        assert!(explicit.is_none(), "invalid LUAU_DEVIRT_SAMPLE");
        eprintln!("SKIP: CLI sample unavailable");
        None
    }
}

#[test]
fn cli_help_and_bad_options_have_correct_exit_statuses() {
    let help = Command::new(executable()).arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("--pretty"));
    let invalid = Command::new(executable())
        .arg("--not-an-option")
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("unknown option"));
}

#[test]
fn cli_pretty_emission_and_combined_flags_match_the_library_without_changing_the_input() {
    let input = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sarp.lua");
    let before = fs::read(&input).unwrap();
    let program = walk_cfg(&decode_file(&input).unwrap()).unwrap();
    for (flags, options) in [
        (
            vec!["--pretty"],
            CodegenOptions {
                pretty: true,
                ..CodegenOptions::default()
            },
        ),
        (
            vec!["--pretty", "--comments", "--no-strict"],
            CodegenOptions {
                pretty: true,
                include_source_comments: true,
                strict: false,
            },
        ),
    ] {
        let output = Command::new(executable())
            .arg(&input)
            .args(flags)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            emit_luau(&program, &options).unwrap()
        );
        assert_eq!(before, fs::read(&input).unwrap());
    }
    let inspect = Command::new(executable())
        .arg(&input)
        .arg("--inspect")
        .output()
        .unwrap();
    let pretty_inspect = Command::new(executable())
        .arg(&input)
        .args(["--pretty", "--inspect"])
        .output()
        .unwrap();
    assert!(inspect.status.success() && pretty_inspect.status.success());
    assert_eq!(
        inspect.stdout, pretty_inspect.stdout,
        "pretty is an emission option only"
    );
}

#[test]
fn cli_refuses_to_overwrite_the_input_artifact() {
    let Some(sample) = sample() else { return };
    let before = fs::read(&sample).unwrap();
    let output = Command::new(executable())
        .arg(&sample)
        .arg("-o")
        .arg(&sample)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(before, fs::read(sample).unwrap());
    assert!(String::from_utf8_lossy(&output.stderr).contains("input artifact"));
}

#[test]
fn cli_emission_matches_the_library_pipeline_exactly() {
    let Some(sample) = sample() else { return };
    let before = fs::read(&sample).unwrap();
    let vm = decode_file(&sample).unwrap();
    let expected = emit_luau(&walk_cfg(&vm).unwrap(), &CodegenOptions::default()).unwrap();
    let destination = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("cli-output-{}.luau", std::process::id()));
    let output = Command::new(executable())
        .arg(&sample)
        .arg("-o")
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let actual = fs::read_to_string(&destination).unwrap();
    fs::remove_file(destination).unwrap();
    assert_eq!(actual, expected);
    assert_eq!(before, fs::read(sample).unwrap());
}

#[test]
fn cli_reports_release_version_and_decodes_metadata_without_emission() {
    let version = Command::new(executable())
        .arg("--version")
        .output()
        .unwrap();
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8_lossy(&version.stdout).trim(),
        concat!("luau-devirt ", env!("CARGO_PKG_VERSION"))
    );
    let Some(sample) = sample() else { return };
    let info = Command::new(executable())
        .arg(sample)
        .arg("--inspect")
        .output()
        .unwrap();
    assert!(info.status.success());
    let text = String::from_utf8_lossy(&info.stdout);
    assert!(text.contains("Payload bytes: 2276"));
    assert!(text.contains("Root prototype word: 505"));
    assert!(text.contains("Master key: 2702369233"));
    assert!(!text.contains("local function"));
}

#[test]
fn cli_preserves_existing_output_unless_force_is_explicit() {
    let Some(sample) = sample() else { return };
    let before = fs::read(&sample).unwrap();
    let destination = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("cli-existing-{}.luau", std::process::id()));
    fs::write(&destination, "user output").unwrap();
    let refused = Command::new(executable())
        .arg(&sample)
        .arg("-o")
        .arg(&destination)
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert_eq!(fs::read_to_string(&destination).unwrap(), "user output");
    let replaced = Command::new(executable())
        .arg(&sample)
        .arg("-o")
        .arg(&destination)
        .arg("--force")
        .output()
        .unwrap();
    assert!(
        replaced.status.success(),
        "{}",
        String::from_utf8_lossy(&replaced.stderr)
    );
    assert!(fs::read_to_string(&destination)
        .unwrap()
        .starts_with("--!strict"));
    assert_eq!(before, fs::read(sample).unwrap());
    fs::remove_file(destination).unwrap();
}

#[test]
fn cli_large_preview_reports_incomplete_analysis_and_never_replaces_output() {
    let input = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/protected.luau");
    let before = fs::read(&input).unwrap();
    let destination = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!(
            "cli-protected-existing-{}.luau",
            std::process::id()
        ));
    fs::write(&destination, "preserved user output").unwrap();
    for flags in [
        vec!["--inspect"],
        vec!["--pretty", "--inspect"],
        vec![],
        vec!["--pretty"],
    ] {
        let mut command = Command::new(executable());
        command.arg(&input).args(&flags);
        if !flags.contains(&"--inspect") {
            command.arg("-o").arg(&destination).arg("--force");
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains("unsupported helper 25 generic iteration"),
            "{error}"
        );
        if flags.contains(&"--inspect") {
            assert!(error.contains("Status: INCOMPLETE"), "{error}");
            assert!(error.contains("Payload bytes: 568176"), "{error}");
            assert!(
                error.contains("No complete IR, default Luau or pretty Luau"),
                "{error}"
            );
        }
        assert_eq!(fs::read(&destination).unwrap(), b"preserved user output");
        assert_eq!(fs::read(&input).unwrap(), before);
    }
    fs::remove_file(destination).unwrap();
}
