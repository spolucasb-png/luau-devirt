#![forbid(unsafe_code)]

mod aliases;
pub mod base85;
pub mod cfg;
pub mod codegen;
pub mod decoder;
pub mod ir;
pub mod lifter;
pub mod optimizer;
pub mod sarp;
pub mod sarp_large;
mod specialize;

pub use cfg::walk_cfg;
pub use codegen::emit_luau;
pub use decoder::{decode_file, decode_source};
pub use ir::{DecodedVm, LiftedProgram};
