//! Static diagnostics for a decoded/lifted artifact. Does not execute Luau.

use luau_devirt::{decode_file, walk_cfg};

fn main() -> Result<(), String> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or_else(|| "usage: cargo run --example inspect -- <sample.lua>".to_owned())?;
    let vm = decode_file(path)?;
    let program = walk_cfg(&vm)?;
    println!(
        "{} payload bytes; {} populated words; {} prototypes; {} reachable addresses; {} states",
        vm.payload.len(),
        vm.decoded_words.iter().flatten().count(),
        vm.prototypes.len(),
        program.reachable_pcs.len(),
        program.state_variants
    );
    for prototype in &vm.prototypes {
        println!(
            "prototype word {}: pc {}, args {:?}, bank {}, token {}",
            prototype.word,
            prototype.entry_pc,
            prototype.fixed_parameter_count,
            prototype.bank_base,
            prototype.dispatch_token
        );
    }
    for (pc, block) in program.blocks {
        println!(
            "pc {pc}, H{}, {:?}",
            block.handler_family,
            block
                .successors
                .iter()
                .map(|edge| (&edge.label, edge.target_pc))
                .collect::<Vec<_>>()
        );
        for instruction in block.instructions {
            println!("  {instruction:?}");
        }
    }
    Ok(())
}
