//! Differential comparison of all seven state fields, not just state count.

use std::{collections::BTreeSet, path::PathBuf};

use luau_devirt::{decode_file, walk_cfg};

#[test]
fn all_109_symbolic_states_match_the_static_python_reference() {
    let override_path = std::env::var_os("LUAU_DEVIRT_SAMPLE").map(PathBuf::from);
    let path = override_path.clone().unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("sample.lua")
    });
    if !path.is_file() {
        assert!(override_path.is_none(), "invalid explicit sample path");
        eprintln!("SKIP: state fixture input absent at {}", path.display());
        return;
    }
    let vm = decode_file(path).expect("decode sample");
    let program = walk_cfg(&vm).expect("symbolic walk");
    let actual: BTreeSet<[u64; 7]> = program
        .blocks
        .values()
        .flat_map(|block| &block.entry_states)
        .map(|state| {
            [
                state.pc as u64,
                u64::from(state.key_state),
                u64::from(state.bank_base),
                u64::from(state.dispatch_token),
                u64::from(state.phase),
                u64::from(state.bank_sum),
                u64::from(state.prototype_salt),
            ]
        })
        .collect();
    let expected: BTreeSet<[u64; 7]> = include_str!("fixtures/cfg-states.txt")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let values: Vec<u64> = line
                .split_ascii_whitespace()
                .map(|value| value.parse().expect("state field"))
                .collect();
            values.try_into().expect("seven state fields")
        })
        .collect();
    assert_eq!(expected.len(), 109);
    assert_eq!(actual, expected);
}
