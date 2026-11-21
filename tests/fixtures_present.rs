use std::path::Path;

#[test]
fn distributed_regression_fixtures_are_present() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures");
    for name in [
        "sample.lua",
        "decoded-metadata.json",
        "cfg-states.txt",
        "VM-DISASSEMBLY.md",
        "T001-VM-ANALYSIS.md",
        "T001-deobfuscated.luau",
    ] {
        assert!(root.join(name).is_file(), "release fixture missing: {name}");
    }
}
