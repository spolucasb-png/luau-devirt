use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use luau_devirt::ir::{CodegenOptions, DecodedVm, Instruction};
use luau_devirt::{decode_file, emit_luau, walk_cfg};

fn help() {
    println!(
        "luau-devirt {}\n\
         Static devirtualizer for independently certified Luau VM profiles.\n\
          Complete profiles: Adler-32/LCG, Base85/rotor, and five-fragment SARP.\n\
          Development preview: four-fragment large SARP (partial, fail-closed).\n\n\
         Usage: luau-devirt <input.lua> [options]\n\n\
         Options:\n\
           -o, --output <path>  Write the result to a file; otherwise use stdout\n\
           --force              Replace an existing output file safely\n\
            --inspect            Inspect metadata/profile analysis without Luau emission\n\
            --pretty             Safely simplify recovered code for comfortable reading\n\
           --comments           Include source-address comments in Luau output\n\
           --no-strict          Omit the --!strict directive\n\
           -V, --version        Print the release version\n\
           -h, --help           Print this help\n\
           --                   Treat subsequent arguments as input filenames\n\n\
         Examples:\n\
            luau-devirt sample.lua -o recovered.luau\n\
            luau-devirt sample.lua --pretty -o readable.luau\n\
           luau-devirt sample.lua --inspect\n\n\
         The input and its virtual instructions are never executed.\n\
         Unsupported profiles and instructions fail explicitly.",
        env!("CARGO_PKG_VERSION")
    );
}

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("luau-devirt: {}", message.as_ref());
    std::process::exit(1);
}

fn argument_error(message: impl AsRef<str>) -> ! {
    eprintln!("luau-devirt: {}\nUse --help for usage.", message.as_ref());
    std::process::exit(2);
}

fn inspect(vm: &DecodedVm) -> Result<String, String> {
    if luau_devirt::sarp_large::is_profile(vm) {
        let mut out=format!("Profile: {}\nWrapper fingerprint: {}\nSource SHA-256: {}\nPayload bytes: {}\nRaw u32 words: {}\nInitially populated W words: {}\nDecoded range: {}..={} (one-based)\nInitializer argument: {}\nMaster key: {}\nSlot-map entries: {}\nRoot prototype: {}\n",luau_devirt::sarp_large::PROFILE,luau_devirt::sarp_large::WRAPPER_SHA256,vm.source_sha256.as_deref().unwrap_or("unknown"),vm.payload.len(),vm.raw_words.len(),vm.decoded_words.iter().flatten().count(),vm.decoded_range.0,vm.decoded_range.1,vm.initialization_argument,vm.master_key,vm.slot_map.len()-1,vm.entry_prototype);
        let analysis = match luau_devirt::sarp_large::analyze(vm) {
            Ok(analysis) => analysis,
            Err(error) => {
                writeln!(out,"Status: INCOMPLETE / unsupported VM semantics\n{error}\nNo complete IR, default Luau or pretty Luau is certified.").map_err(|e|e.to_string())?;
                return Err(out);
            }
        };
        writeln!(out,"Status: reachable IR traversal complete (no runtime execution)\nDiscovered prototypes: {}\nAnalyzed dispatcher states: {}\nReachable instruction addresses: {}\nString records referenced: {}\nNumber records referenced: {}\nLuau emission: not requested by --inspect",analysis.prototypes.len(),analysis.trace.len(),analysis.program.blocks.len(),analysis.strings.len(),analysis.numbers.len()).map_err(|e|e.to_string())?;
        return Ok(out);
    }
    if luau_devirt::sarp::is_profile(vm) {
        let analysis = luau_devirt::sarp::analyze(vm)?;
        let unresolved = analysis
            .raw_program
            .blocks
            .values()
            .flat_map(|b| &b.instructions)
            .filter(|i| matches!(i, Instruction::Raw { .. }))
            .count();
        let mut out=format!("Profile: {}\nWrapper fingerprint: {}\nSource SHA-256: {}\nPayload bytes: {}\nRaw u32 words: {}\nDecoded words: {}\nDecoded range: {}..={} (one-based)\nInitializer argument: {}\nMaster key: {} (0x{:08x})\nSlot-map entries: {}\nRoot prototype word: {}\nPrototypes: {}\nString records referenced: {}\nNumber records referenced: {}\nReachable instruction addresses: {}\nSymbolic dispatcher states: {}\nStructured data blocks: {}\nUnresolved instructions: {}\n",luau_devirt::sarp::PROFILE,luau_devirt::sarp::WRAPPER_SHA256,vm.source_sha256.as_deref().unwrap_or("unknown"),vm.payload.len(),vm.raw_words.len(),vm.decoded_words.iter().flatten().count(),vm.decoded_range.0,vm.decoded_range.1,vm.initialization_argument,vm.master_key,vm.master_key,vm.slot_map.len()-1,vm.entry_prototype,vm.prototypes.len(),analysis.strings.len(),analysis.numbers.len(),analysis.raw_program.blocks.len(),analysis.trace.len(),analysis.program.blocks.len(),unresolved);
        for p in &vm.prototypes {
            writeln!(out,"  prototype={} entry={} key={} token={} bank={} salt={} frame={} parameters={:?} captures={}",p.word,p.entry_pc,p.initial_decode_state,p.dispatch_token,p.bank_base,p.prototype_salt,p.frame_capacity,p.fixed_parameter_count,p.captures.len()).map_err(|e|e.to_string())?;
        }
        for (r, v) in &analysis.strings {
            writeln!(
                out,
                "  string reference={r} bytes={} value={:?}",
                v.len(),
                String::from_utf8_lossy(v)
            )
            .map_err(|e| e.to_string())?;
        }
        for (r, v) in &analysis.numbers {
            writeln!(
                out,
                "  number reference={r} bits={v:016x} value={}",
                f64::from_bits(*v)
            )
            .map_err(|e| e.to_string())?;
        }
        return Ok(out);
    }
    if luau_devirt::base85::is_profile(vm) {
        let analysis = luau_devirt::base85::analyze(vm)?;
        return Ok(format!(
            "Profile: {}\nWrapper: certified token skeleton (payload excluded)\nPayload bytes: {}\nRaw u32 words: {}\nDecoded words: {}\nDecoded range: {}..={} (one-based)\nInitializer argument: {}\nMaster key: {} (0x{:08x})\nSlot-map entries: {}\nRoot prototype word: {}\nReachable prototypes: {}\nString records referenced: {}\nNumber records referenced: {}\nReachable instruction addresses: {}\nSymbolic dispatcher states: {}\nStructured data blocks: {}\n",
            luau_devirt::base85::PROFILE,vm.payload.len(),vm.raw_words.len(),
            vm.decoded_words.iter().flatten().count(),vm.decoded_range.0,vm.decoded_range.1,
            vm.initialization_argument,vm.master_key,vm.master_key,vm.slot_map.len()-1,
            vm.entry_prototype,vm.prototypes.len(),analysis.strings.len(),analysis.numbers.len(),
            analysis.raw_program.blocks.len(),analysis.trace.len(),analysis.program.blocks.len()
        ));
    }
    let mut output = String::new();
    let _ = writeln!(output, "Profile: adler32-lcg-5word-v1");
    let _ = writeln!(
        output,
        "Integrity: verified ({} literals)",
        vm.table_integrity.len()
    );
    let _ = writeln!(output, "Payload bytes: {}", vm.payload.len());
    let _ = writeln!(output, "Raw u32 words: {}", vm.raw_words.len());
    let _ = writeln!(
        output,
        "Decoded words: {}",
        vm.decoded_words.iter().flatten().count()
    );
    let _ = writeln!(
        output,
        "Decoded range: {}..={} (one-based)",
        vm.decoded_range.0, vm.decoded_range.1
    );
    let _ = writeln!(
        output,
        "Initializer argument: {}",
        vm.initialization_argument
    );
    let _ = writeln!(
        output,
        "Master key: {} (0x{:08x})",
        vm.master_key, vm.master_key
    );
    let _ = writeln!(
        output,
        "Slot-map entries: {}",
        vm.slot_map.len().saturating_sub(1)
    );
    let _ = writeln!(output, "Root prototype word: {}", vm.entry_prototype);
    let _ = writeln!(output, "Prototypes: {}", vm.prototypes.len());
    for prototype in &vm.prototypes {
        let _ = writeln!(
            output,
            "  word={} pc={} bank={} token={} salt={} parameters={:?} captures={}",
            prototype.word,
            prototype.entry_pc,
            prototype.bank_base,
            prototype.dispatch_token,
            prototype.prototype_salt,
            prototype.fixed_parameter_count,
            prototype.captures.len()
        );
    }
    let _ = writeln!(output, "String records: {}", vm.strings.len());
    for constant in &vm.strings {
        let hex: String = constant
            .value
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let _ = writeln!(
            output,
            "  offset={} bytes={} hex={hex}",
            constant.byte_offset,
            constant.value.len()
        );
    }
    let _ = writeln!(output, "Number records: {}", vm.numbers.len());
    for constant in &vm.numbers {
        let _ = writeln!(
            output,
            "  index={} offset={} value={} bits=0x{:016x}",
            constant.index, constant.byte_offset, constant.value, constant.bits
        );
    }
    Ok(output)
}

fn same_path(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => {
            if cfg!(windows) {
                left.to_string_lossy()
                    .eq_ignore_ascii_case(&right.to_string_lossy())
            } else {
                left == right
            }
        }
        _ => false,
    }
}

fn write_output(path: &Path, contents: &[u8], force: bool) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    if !force {
        let result = {
            let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
            file.write_all(contents).and_then(|_| file.sync_all())
        };
        if result.is_err() {
            let _ = fs::remove_file(path); // Only the newly created output belongs to this run.
        }
        return result;
    }

    // Never write through an existing symlink or hard link. Stage a new file
    // in the destination directory, then replace the directory entry.
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "output has no filename"))?;
    for attempt in 0..32 {
        let mut temporary_name = OsString::from(".");
        temporary_name.push(name);
        temporary_name.push(format!(".luau-devirt-{}-{attempt}.tmp", std::process::id()));
        let temporary = parent.join(temporary_name);
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        let write = file.write_all(contents).and_then(|_| file.sync_all());
        drop(file);
        let result = write.and_then(|_| fs::rename(&temporary, path));
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        return result;
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "unable to reserve a temporary output file",
    ))
}

fn main() {
    let mut arguments = env::args_os().skip(1);
    let mut input = None;
    let mut output = None;
    let mut force = false;
    let mut metadata_only = false;
    let mut positional_only = false;
    let mut options = CodegenOptions::default();
    while let Some(argument) = arguments.next() {
        if !positional_only {
            if argument == "--help" || argument == "-h" {
                help();
                return;
            }
            if argument == "--version" || argument == "-V" {
                println!("luau-devirt {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            if argument == "--" {
                positional_only = true;
                continue;
            }
            if argument == "--force" {
                force = true;
                continue;
            }
            if argument == "--inspect" {
                metadata_only = true;
                continue;
            }
            if argument == "--comments" {
                options.include_source_comments = true;
                continue;
            }
            if argument == "--pretty" {
                options.pretty = true;
                continue;
            }
            if argument == "--no-strict" {
                options.strict = false;
                continue;
            }
            if argument == "--output" || argument == "-o" {
                if output.is_some() {
                    argument_error("output path specified more than once");
                }
                output = Some(PathBuf::from(
                    arguments
                        .next()
                        .unwrap_or_else(|| argument_error("missing output path")),
                ));
                continue;
            }
            if argument.to_string_lossy().starts_with('-') {
                argument_error(format!("unknown option {:?}", argument));
            }
        }
        if input.replace(PathBuf::from(argument)).is_some() {
            argument_error("expected exactly one input file");
        }
    }
    let input = input.unwrap_or_else(|| argument_error("missing input file"));
    if output
        .as_ref()
        .is_some_and(|output| same_path(&input, output))
    {
        fail("output resolves to the input artifact; choose a separate path");
    }
    let vm = decode_file(&input).unwrap_or_else(|error| fail(error));
    let result = if metadata_only {
        inspect(&vm).unwrap_or_else(|error| fail(error))
    } else {
        let program = walk_cfg(&vm).unwrap_or_else(|error| fail(error));
        for (pc, block) in &program.blocks {
            for instruction in &block.instructions {
                match instruction {
                    Instruction::Raw { family, selector, .. } => fail(format!("unsupported instruction at word {pc}: family={family}, selector={selector}")),
                    Instruction::NewClosure { prototype_word, captures, .. } => {
                        if !program.prototype_entries.contains_key(prototype_word) { fail(format!("unvalidated child prototype {prototype_word}")); }
                        if !captures.is_empty() { fail("captured closure binding is not supported by this release"); }
                    }
                    _ => {}
                }
            }
        }
        emit_luau(&program, &options).unwrap_or_else(|error| fail(error))
    };
    if let Some(path) = output {
        write_output(&path, result.as_bytes(), force).unwrap_or_else(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                fail(format!(
                    "output already exists: {}; use --force to replace it",
                    path.display()
                ));
            }
            fail(format!("cannot write {}: {error}", path.display()));
        });
    } else {
        io::stdout()
            .write_all(result.as_bytes())
            .unwrap_or_else(|error| fail(error.to_string()));
    }
}
