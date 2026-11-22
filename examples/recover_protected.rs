//! Diagnostic/production entry into the fourth profile, never a Lua runner.
use luau_devirt::{decode_file, emit_luau, ir::CodegenOptions, sarp_large};
use std::{env, fmt::Write as _, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    if !(args.len() == 2 || (args.len() == 3 && args[2] == "--decode-only")) {
        return Err("usage: recover_protected INPUT OUTDIR [--decode-only]".into());
    }
    let vm = decode_file(&args[0])?;
    if !sarp_large::is_profile(&vm) {
        return Err("input is not certified large SARP".into());
    }
    let out = PathBuf::from(&args[1]);
    fs::create_dir_all(&out)?;
    let input = fs::canonicalize(&args[0])?;
    for name in [
        "target.transport.bin",
        "target.metadata.txt",
        "target.handlers.parsed.txt",
        "permutation-A.bin",
        "permutation-B.bin",
        "permutation-C.bin",
        "target.vm.bin",
        "target.status.txt",
        "target.partial-bytecode.txt",
        "target.ir.txt",
        "target.deobfuscated.lua",
        "target.pretty.luau",
    ] {
        if out.join(name).exists() && fs::canonicalize(out.join(name))? == input {
            return Err("artifact destination resolves to protected input".into());
        }
    }
    fs::write(out.join("target.status.txt"), "INCOMPLETE: transport/initialization artifacts only.\nSemantic analysis/emission has not completed in this invocation.\nExisting IR or Luau files, if any, are not certified by this invocation.\n")?;
    fs::write(out.join("target.transport.bin"), &vm.payload)?;
    let (_, _, _, init) = sarp_large::initialize_data(&vm.payload, vm.initialization_argument)?;
    let mut text = format!("Profile: {}\nSource: {:?}\nArgument: {}\nK0: {}\nHeader: {:?}\nFloat: {:016x}\nZero counts: {}\nRange: {:?}\nSlots: {:?}\nBiases: {:?}\nPrototypes: {:#?}\n",
        sarp_large::PROFILE, vm.source_sha256, vm.initialization_argument, vm.master_key,
        init.header, init.float_bits, init.zero_counts, vm.decoded_range, vm.slot_map,
        vm.immediate_biases, vm.prototypes);
    for (index, value) in vm.decoded_words.iter().enumerate() {
        writeln!(text, "W[{index}] = {value:?}")?;
    }
    fs::write(out.join("target.metadata.txt"), text)?;
    fs::write(
        out.join("target.handlers.parsed.txt"),
        sarp_large::source_model_report(&vm)?,
    )?;
    for (name, values) in [
        ("A", init.permutation_a),
        ("B", init.permutation_b),
        ("C", init.permutation_c),
    ] {
        fs::write(
            out.join(format!("permutation-{name}.bin")),
            values
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect::<Vec<_>>(),
        )?;
    }
    // Sparse working-word image: explicit presence bytes; absent data is never
    // fabricated as a decoded zero. See the artifact format documentation.
    let mut image = b"LVDW\x01\0\0\0".to_vec();
    image.extend_from_slice(&(vm.decoded_words.len() as u32).to_le_bytes());
    for word in &vm.decoded_words {
        image.push(u8::from(word.is_some()));
        if let Some(value) = word {
            image.extend_from_slice(&value.to_le_bytes());
        }
    }
    fs::write(out.join("target.vm.bin"), image)?;
    if args.get(2).is_some_and(|s| s == "--decode-only") {
        return Ok(());
    }
    let analysis = match sarp_large::analyze(&vm) {
        Ok(analysis) => analysis,
        Err(error) => {
            fs::write(out.join("target.status.txt"), format!("INCOMPLETE: {error}\nTransport, initialization, parsed handlers and partial trace are available.\nComplete linked IR, default Luau and pretty Luau are unavailable.\nExisting IR or Luau files, if any, are not certified by this invocation.\n"))?;
            let mut trace=format!("INCOMPLETE ANALYSIS: {error}\nFailed state: {:?}\nNo complete IR or Luau output is certified.\n",error.failed_state);
            for row in &error.trace {
                writeln!(
                    trace,
                    "PC {} family={} selector={} helpers={:?}\nState: {:?}\nInstructions: {:?}\nSuccessors: {:?}\nOperations: {:?}\nHash proofs: {:?}\nFactory requests: {:?}",
                    row.state.pc,
                    row.family,
                    row.selector,
                    row.helpers,
                    row.state,
                    row.instructions,
                    row.successors,
                    row.operations,
                    row.hash_proofs,
                    row.factories
                )?;
            }
            fs::write(out.join("target.partial-bytecode.txt"), trace)?;
            return Err(error.into());
        }
    };
    let program = analysis.program;
    fs::write(out.join("target.ir.txt"), format!("{program:#?}\n"))?;
    fs::write(out.join("target.status.txt"), "Linked IR traversal complete.\nLuau emission has not completed in this invocation.\nExisting Luau files, if any, are not certified by this invocation.\n")?;
    let default = emit_luau(&program, &CodegenOptions::default())?;
    let pretty = emit_luau(
        &program,
        &CodegenOptions {
            pretty: true,
            ..CodegenOptions::default()
        },
    )?;
    fs::write(out.join("target.deobfuscated.lua"), default)?;
    fs::write(out.join("target.pretty.luau"), pretty)?;
    fs::write(out.join("target.status.txt"), "Linked IR, default Luau and pretty Luau generated in this invocation.\nNot executed; compile-only and static analysis are separate checks.\n")?;
    Ok(())
}
