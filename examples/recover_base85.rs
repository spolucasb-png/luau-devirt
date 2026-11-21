//! Reproduce static recovery artifacts; never launches a Lua runtime.
use luau_devirt::{base85, decode_file, emit_luau, ir::CodegenOptions};
use std::{env, fmt::Write as _, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() < 2 {
        return Err("usage: cargo run --example recover_base85 -- INPUT OUTDIR [--emit]".into());
    }
    let vm = decode_file(&args[0])?;
    let dir = PathBuf::from(&args[1]);
    fs::create_dir_all(&dir)?;
    let analysis = base85::analyze(&vm)?;
    eprintln!(
        "Static lifting complete: {} states, {} addresses",
        analysis.trace.len(),
        analysis.raw_program.blocks.len()
    );
    fs::write(dir.join("target.decoded.bin"), &vm.payload)?;
    let mut listing = String::new();
    writeln!(listing,"Profile: {}\nSource SHA-256: {}\nPayload: {} bytes / {} words\nDecoded range: {:?}\nRoot: prototype {} / PC {}\nStates: {} / addresses: {} / structured blocks: {}\n",base85::PROFILE,vm.source_sha256.as_deref().unwrap_or("unknown"),vm.payload.len(),vm.raw_words.len(),vm.decoded_range,vm.entry_prototype,analysis.program.root_entry.unwrap_or(0),analysis.trace.len(),analysis.raw_program.blocks.len(),analysis.program.blocks.len())?;
    for row in &analysis.trace {
        writeln!(
            listing,
            "PC {:03}..{:03} family={} selector={}\n  state={:?}",
            row.state.pc, row.end_pc, row.family, row.selector, row.state
        )?;
        for at in row.state.pc..row.end_pc {
            writeln!(
                listing,
                "  W[{at}] = {}",
                vm.decoded_words
                    .get(at)
                    .copied()
                    .flatten()
                    .ok_or("missing listing word")?
            )?;
        }
        for instruction in &row.instructions {
            writeln!(listing, "  {instruction:?}")?;
        }
        for (label, state) in &row.successors {
            writeln!(listing, "  {label:?} -> {state:?}")?;
        }
    }
    fs::write(dir.join("target.bytecode.txt"), listing)?;
    fs::write(
        dir.join("target.ir.txt"),
        format!("{:#?}\n", analysis.raw_program),
    )?;
    fs::write(
        dir.join("target.structured-ir.txt"),
        format!("{:#?}\n", analysis.program),
    )?;
    let covered = analysis
        .trace
        .iter()
        .flat_map(|r| r.state.pc..r.end_pc)
        .collect::<std::collections::BTreeSet<_>>();
    let unreferenced = (vm.entry_prototype + 5..=vm.decoded_range.1)
        .filter(|pc| !covered.contains(pc))
        .collect::<Vec<_>>();
    fs::write(dir.join("target.coverage.txt"), format!("Raw reachable instruction addresses: {}\nDispatcher states: {}\nCovered instruction/operand words: {}\nRoot descriptor words: {}..{}\nUnreferenced decoded words after the root descriptor: {unreferenced:?}\nThese words are neither instruction starts nor read operands in any recovered state; no instruction is replaced by a placeholder.\nStructured blocks after proved control specialization: {}\n",analysis.raw_program.blocks.len(),analysis.trace.len(),covered.len(),vm.entry_prototype,vm.entry_prototype+4,analysis.program.blocks.len()))?;
    let simplified = luau_devirt::optimizer::simplify(&analysis.program)?;
    fs::write(
        dir.join("target.optimized-ir.txt"),
        format!("{simplified:#?}\n"),
    )?;
    eprintln!(
        "Region optimization: {} -> {} addresses",
        analysis.program.blocks.len(),
        simplified.blocks.len()
    );
    let mut constants = String::new();
    for (reference, value) in &analysis.strings {
        writeln!(
            constants,
            "string ref={reference} offset={} bytes={} value={:?}",
            reference ^ 701714,
            value.len(),
            String::from_utf8_lossy(value)
        )?;
    }
    for (reference, bits) in &analysis.numbers {
        writeln!(
            constants,
            "number ref={reference} index={} bits=0x{bits:016x} value={}",
            reference ^ 1329030,
            f64::from_bits(*bits)
        )?;
    }
    fs::write(dir.join("target.constants.txt"), constants)?;
    if args.get(2).is_some_and(|a| a == "--emit") {
        eprintln!("Emitting through shared Rust optimizer and Luau emitter");
        let output = emit_luau(&analysis.program, &CodegenOptions::default())?;
        fs::write(dir.join("target.deobfuscated.lua"), output)?;
    }
    Ok(())
}
