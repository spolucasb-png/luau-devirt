//! Static SARP artifacts through the same library used by the CLI.
use luau_devirt::{decode_file, emit_luau, ir::CodegenOptions, sarp};
use std::{env, fmt::Write as _, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() < 2 {
        return Err("usage: recover_sarp INPUT OUTDIR [--decode-only]".into());
    }
    let vm = decode_file(&args[0])?;
    if !sarp::is_profile(&vm) {
        return Err("input is not certified SARP".into());
    }
    let dir = PathBuf::from(&args[1]);
    fs::create_dir_all(&dir)?;
    fs::write(dir.join("target.decoded.bin"), &vm.payload)?;
    let mut meta=format!("Profile: {}\nSource SHA-256: {}\nPayload bytes: {}\nWords: {}\nRange: {:?}\nArgument: {}\nMaster key: {}\nSlots: {:?}\nBiases: {:?}\nPrototypes: {:#?}\n",sarp::PROFILE,vm.source_sha256.as_deref().unwrap_or("unknown"),vm.payload.len(),vm.raw_words.len(),vm.decoded_range,vm.initialization_argument,vm.master_key,vm.slot_map,vm.immediate_biases,vm.prototypes);
    for (i, w) in vm.decoded_words.iter().enumerate() {
        writeln!(meta, "W[{i}] = {w:?}")?;
    }
    fs::write(dir.join("target.metadata.txt"), meta)?;
    if args.get(2).is_some_and(|s| s == "--decode-only") {
        return Ok(());
    }
    let a = sarp::analyze(&vm)?;
    fs::write(dir.join("target.ir.txt"), format!("{:#?}\n", a.raw_program))?;
    fs::write(
        dir.join("target.structured-ir.txt"),
        format!("{:#?}\n", a.program),
    )?;
    let mut listing = String::new();
    for row in &a.trace {
        writeln!(
            listing,
            "PC {}..{} family={} selector={} helper={:?}\nstate={:?}",
            row.state.pc, row.end_pc, row.family, row.selector, row.transition_helper, row.state
        )?;
        for pc in row.state.pc..row.end_pc {
            writeln!(
                listing,
                "W[{pc}]={:?}",
                vm.decoded_words.get(pc).copied().flatten()
            )?;
        }
        for i in &row.instructions {
            writeln!(listing, "{i:?}")?;
        }
        for (s, t) in &row.successors {
            writeln!(listing, "{s:?} -> {t:?}")?;
        }
        if let Some(proof) = &row.hash_proof {
            writeln!(listing, "HashProof {proof:?}")?;
        }
    }
    fs::write(dir.join("target.bytecode.txt"), listing)?;
    let covered = a
        .trace
        .iter()
        .flat_map(|r| r.state.pc..r.end_pc)
        .collect::<std::collections::BTreeSet<_>>();
    let unreferenced = (vm.decoded_range.0..=vm.decoded_range.1)
        .filter(|pc| {
            !covered.contains(pc) && !(*pc >= vm.entry_prototype && *pc < vm.entry_prototype + 7)
        })
        .collect::<Vec<_>>();
    fs::write(dir.join("target.coverage.txt"),format!("Instruction spans cover {} word positions.\nRoot descriptor: {}..{}\nOther unreferenced decoded words: {unreferenced:?}\nUnreferenced does not mean a guessed instruction; raw payload and words are preserved.\n",covered.len(),vm.entry_prototype,vm.entry_prototype+6))?;
    let mut constants = String::new();
    for (r, s) in &a.strings {
        writeln!(constants, "String {r}: {:?}", String::from_utf8_lossy(s))?;
    }
    for (r, n) in &a.numbers {
        writeln!(
            constants,
            "Number {r}: {} bits={n:016x}",
            f64::from_bits(*n)
        )?;
    }
    fs::write(dir.join("target.constants.txt"), constants)?;
    eprintln!(
        "SARP: {} states / {} raw addresses / {} structured blocks / {} strings / {} numbers",
        a.trace.len(),
        a.raw_program.blocks.len(),
        a.program.blocks.len(),
        a.strings.len(),
        a.numbers.len()
    );
    fs::write(
        dir.join("target.deobfuscated.lua"),
        emit_luau(&a.program, &CodegenOptions::default())?,
    )?;
    Ok(())
}
