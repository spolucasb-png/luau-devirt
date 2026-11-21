//! Regression checks for current-source extraction and fail-closed decoding.

use std::path::PathBuf;

use luau_devirt::decode_source;

fn sample() -> Option<String> {
    let explicit = std::env::var_os("LUAU_DEVIRT_SAMPLE").map(PathBuf::from);
    let path = explicit.clone().unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("sample.lua")
    });
    match std::fs::read_to_string(&path) {
        Ok(source) => Some(source),
        Err(error) if explicit.is_some() => panic!("{}: {error}", path.display()),
        Err(_) => {
            eprintln!(
                "SKIP: decoder mutation fixture absent at {}",
                path.display()
            );
            None
        }
    }
}

#[test]
fn corrupted_payload_is_rejected_by_integrity_check() {
    let Some(source) = sample() else { return };
    let mutated = source.replacen(r#""\183n"#, r#""\182n"#, 1);
    assert_ne!(source, mutated, "expected leading payload escape");
    let error = decode_source(&mutated).expect_err("corrupted payload must fail");
    assert!(error.contains("integrity"), "unexpected error: {error}");
}

#[test]
fn corrupted_source_checksum_is_rejected() {
    let Some(source) = sample() else { return };
    let mutated = source.replacen("2467128108", "2467128109", 1);
    assert_ne!(source, mutated, "expected payload Adler-32 literal");
    let error = decode_source(&mutated).expect_err("corrupted checksum must fail");
    assert!(error.contains("integrity"), "unexpected error: {error}");
}

#[test]
fn initializer_argument_is_read_from_current_source() {
    let Some(source) = sample() else { return };
    let baseline = decode_source(&source).expect("valid baseline");
    let mutated = source.replacen("18932807, 3954275856", "18932806, 3954275856", 1);
    assert_ne!(source, mutated, "expected initializer call arguments");
    match decode_source(&mutated) {
        Ok(vm) => {
            assert_ne!(baseline.initialization_argument, vm.initialization_argument);
            assert_ne!(baseline.master_key, vm.master_key);
        }
        Err(error) => {
            assert!(
                error.contains("bounds") || error.contains("prototype") || error.contains("region"),
                "changed key must fail in mathematical decoding, not literal extraction: {error}"
            );
        }
    }
}

#[test]
fn comment_and_whitespace_changes_preserve_decoded_data() {
    let Some(source) = sample() else { return };
    let expected = decode_source(&source).expect("valid baseline");
    let changed = format!("--[=[ ignored }}; and \\\" literals ]=]\n\n{source}");
    let actual = decode_source(&changed).expect("comments must not alter extraction");
    assert_eq!(expected.payload, actual.payload);
    assert_eq!(expected.decoded_words, actual.decoded_words);
    assert_eq!(expected.master_key, actual.master_key);
    assert_eq!(expected.slot_map, actual.slot_map);
    assert_eq!(expected.prototypes, actual.prototypes);
    assert_eq!(expected.strings, actual.strings);
    assert_eq!(expected.numbers, actual.numbers);
}

#[test]
fn truncated_and_invalid_literal_inputs_return_errors_without_panics() {
    for source in [
        "local t = {\"",
        "local t = {\"\\",
        r#"local t = {"\256"}"#,
        r#"local t = {"\xQ0"}"#,
        "--[=[ unterminated comment",
        "local t = {[=[ unterminated long string",
    ] {
        let result = std::panic::catch_unwind(|| decode_source(source));
        assert!(result.is_ok(), "decoder panicked on {source:?}");
        assert!(result.unwrap().is_err(), "decoder accepted {source:?}");
    }
}

#[test]
fn changed_wrapper_algorithm_constants_are_never_silently_ignored() {
    let Some(source) = sample() else { return };
    for (before, after) in [
        ("1002186909", "1002186908"),
        ("3491394721", "3491394720"),
        ("617852180", "617852181"),
        ("888490141", "888490140"),
    ] {
        let changed = source.replacen(before, after, 1);
        assert_ne!(source, changed, "missing algorithm literal {before}");
        assert!(
            decode_source(&changed).is_err(),
            "unsupported formula change {before} -> {after} was silently ignored"
        );
    }
}

#[test]
fn unused_matching_checksum_table_cannot_hide_corrupted_active_table() {
    let Some(source) = sample() else { return };
    let assignment = source
        .find("local tbl3 = {")
        .expect("active checksum table");
    let start = assignment + source[assignment..].find('{').unwrap();
    let end = start + source[start..].find('}').unwrap();
    let original_values = &source[start..=end];
    let invalid = source.replacen("2467128108", "2467128109", 1);
    let decoy = format!("{invalid}\nlocal unusedChecksums = {original_values};\n");
    assert!(
        decode_source(&decoy).is_err(),
        "unused matching values must not substitute for the active integrity table"
    );
}

#[test]
fn literal_utf8_bytes_cannot_impersonate_single_decimal_escape() {
    let Some(source) = sample() else { return };
    let changed = source.replacen(r"\233", "é", 1);
    assert_ne!(source, changed);
    assert!(
        decode_source(&changed).is_err(),
        "raw UTF-8 C3 A9 must not decode as decimal escape E9"
    );
}

#[test]
fn raw_newline_inside_short_payload_literal_is_rejected() {
    let Some(source) = sample() else { return };
    let changed = source.replacen(r#""\183n"#, "\"\\183\n", 1);
    assert_ne!(source, changed);
    assert!(decode_source(&changed).is_err());
}

#[test]
fn dead_initializer_call_cannot_hide_changed_real_argument() {
    let Some(source) = sample() else { return };
    let changed = source.replacen("18932807, 3954275856", "18932806, 3954275856", 1);
    let inserted = changed.replacen(
        "local var651 =",
        "if false then var40(var58(18932807, 3954275856)); end;\nlocal var651 =",
        1,
    );
    assert_ne!(changed, inserted);
    assert!(
        decode_source(&inserted).is_err(),
        "ambiguous initializer calls must not select stale dead-code arguments"
    );
}

#[test]
fn changing_an_operator_without_changing_constants_is_rejected() {
    let Some(source) = sample() else { return };
    let changed = source.replacen("* 18089 + 3507744737", "* 18089 - 3507744737", 1);
    assert_ne!(source, changed, "bias recurrence fixture");
    assert!(
        decode_source(&changed).is_err(),
        "a noncontiguous expression match must not accept changed arithmetic"
    );
}
