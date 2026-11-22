//! Shared data model for the static decoder, CFG walker, lifter, and emitter.

use std::collections::{BTreeMap, BTreeSet};

pub const U32_MODULUS: u64 = 1u64 << 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmProfile {
    Adler32Lcg5Word,
    Base85Rotor3Bank,
    Sarp,
    SarpLarge,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableIntegrity {
    pub index: usize,
    pub length: usize,
    pub adler32: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DecodedVm {
    pub profile: VmProfile,
    pub source_text: String,
    pub source_sha256: Option<String>,
    pub payload: Vec<u8>,
    pub raw_words: Vec<u32>,
    /// One-based decoded word table. Index zero is always `None`.
    pub decoded_words: Vec<Option<u32>>,
    /// One-based physical slot map. Index zero is always zero.
    pub slot_map: Vec<u16>,
    /// One-based immediate-bias table. Index zero is always zero.
    pub immediate_biases: Vec<u32>,
    pub initialization_argument: u32,
    pub master_key: u32,
    pub decoded_range: (usize, usize),
    pub table_integrity: Vec<TableIntegrity>,
    pub initial_strings: Vec<Vec<u8>>,
    pub prototypes: Vec<Prototype>,
    /// Header word of the source-derived top-level prototype.
    pub entry_prototype: usize,
    pub strings: Vec<StringConstant>,
    pub numbers: Vec<NumberConstant>,
    pub dispatch_families: BTreeMap<u32, u32>,
    pub permutation_parity: BTreeMap<u16, u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prototype {
    pub word: usize,
    pub byte_offset: usize,
    pub encoded_reference: u32,
    pub entry_pc: usize,
    pub initial_decode_state: u32,
    pub dispatch_token: u32,
    pub frame_capacity: u16,
    pub bank_base: u32,
    pub prototype_salt: u16,
    pub fixed_parameter_mode: bool,
    pub fixed_parameter_count: Option<u16>,
    pub parameter_operands: Vec<u16>,
    pub captures: Vec<CaptureDescriptor>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureDescriptor {
    pub destination_operand: u16,
    pub source_operand: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StringConstant {
    pub byte_offset: usize,
    pub encoded_reference: u32,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct NumberConstant {
    pub index: usize,
    pub byte_offset: usize,
    pub encoded_reference: u32,
    pub bits: u64,
    pub value: f64,
}

impl PartialEq for NumberConstant {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index
            && self.byte_offset == other.byte_offset
            && self.encoded_reference == other.encoded_reference
            && self.bits == other.bits
    }
}

impl Eq for NumberConstant {}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VmState {
    pub pc: usize,
    pub key_state: u32,
    pub bank_base: u32,
    pub dispatch_token: u32,
    pub phase: u32,
    pub bank_sum: u32,
    pub prototype_salt: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Register {
    pub physical_slot: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Constant {
    Nil,
    Boolean(bool),
    Integer(i64),
    NumberBits(u64),
    String(Vec<u8>),
    U32(u32),
    Unknown(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operand {
    Register(Register),
    Constant(Constant),
    /// Zero-based source function argument, before VM parameter copies.
    Argument(usize),
    /// A value captured by a source-proved closure factory. Captured tables
    /// and boxes preserve reference identity; this is not an invented register.
    Capture(usize),
    /// A path through the captured global environment, e.g. table.concat.
    Global(Vec<Vec<u8>>),
    /// The environment captured once by the protected wrapper's getfenv().
    Environment,
    /// A side-effect-free nested value without an invented physical register.
    Expression(Box<ValueExpression>),
    SlotMapIndex(u16),
    Word(usize),
    Unknown(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValueExpression {
    Unary {
        op: UnaryOp,
        value: Operand,
    },
    Binary {
        op: BinaryOp,
        left: Operand,
        right: Operand,
    },
    Index {
        table: Operand,
        index: Operand,
    },
    /// Intact initialized permutation parity. Source uses numeric inputs;
    /// nonnumeric values produce the explicitly recorded fallback.
    PermutationParity {
        value: Operand,
        parity: Vec<u8>,
        nonnumeric: u8,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    FloorDiv,
    Pow,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    And,
    Or,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnaryOp {
    Negate,
    Not,
    Length,
    BitNot,
    /// Standard Luau `type`, captured by the certified wrapper before program
    /// effects. This is not a lookup of a mutable `environment.type` property.
    TypeOf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Condition {
    Truthy(Operand),
    Falsey(Operand),
    Compare {
        op: BinaryOp,
        left: Operand,
        right: Operand,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Instruction {
    Nop,
    LoadConst {
        dst: Register,
        value: Constant,
    },
    Move {
        dst: Register,
        src: Operand,
    },
    Unary {
        op: UnaryOp,
        dst: Register,
        src: Operand,
    },
    Binary {
        op: BinaryOp,
        dst: Register,
        left: Operand,
        right: Operand,
    },
    GetTable {
        dst: Register,
        table: Operand,
        index: Operand,
    },
    SetTable {
        table: Operand,
        index: Operand,
        value: Operand,
    },
    NewTable {
        dst: Register,
    },
    /// A tuple with an explicit `.n` count, including nil elements.
    NewPackedTable {
        dst: Register,
    },
    Append {
        table: Operand,
        value: Operand,
    },
    PushPacked {
        table: Operand,
        value: Operand,
    },
    AppendPacked {
        table: Operand,
        values: Operand,
    },
    Compare {
        condition: Condition,
    },
    Jump {
        target: usize,
    },
    Branch {
        condition: Condition,
        then_target: usize,
        else_target: usize,
    },
    ForPrep {
        state: Register,
        target: usize,
    },
    ForLoop {
        state: Register,
        target: usize,
    },
    Call {
        dst: Option<Register>,
        function: Operand,
        args: Vec<Operand>,
        /// Known packed result arity; `None` preserves every returned value.
        result_count: Option<usize>,
    },
    /// Prefix scalar values followed by a packed varargs splice:
    /// `function(prefix..., table.unpack(arguments, 1, arguments.n))`.
    CallWithPackedArgs {
        dst: Option<Register>,
        function: Operand,
        prefix: Vec<Operand>,
        arguments: Operand,
        result_count: Option<usize>,
    },
    Concat {
        dst: Register,
        values: Vec<Operand>,
    },
    NewClosure {
        dst: Register,
        prototype_word: usize,
        captures: Vec<Operand>,
    },
    Tag {
        value: Operand,
    },
    KeyUpdate {
        multiplier: u32,
        addend: u32,
    },
    BankSwitch {
        bank_base: u32,
    },
    Return {
        values: Vec<Operand>,
    },
    ReturnPacked {
        values: Operand,
    },
    /// Copy the frame bank value into its PC field and stop dispatch. This is
    /// not a language-level return; the wrapper still validates return tags.
    HaltDispatch {
        pc_slot: Register,
        bank_slot: Register,
    },
    Raw {
        family: u32,
        selector: i64,
        words: Vec<u32>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EdgeLabel {
    Next,
    True,
    False,
    Case(i64),
    Return,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Successor {
    pub label: EdgeLabel,
    pub target_pc: Option<usize>,
    pub state: Option<VmState>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedInstruction {
    pub start_pc: usize,
    pub end_pc: usize,
    pub handler_family: u32,
    pub selector: i64,
    pub instructions: Vec<Instruction>,
    pub successors: Vec<Successor>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BasicBlock {
    pub start_pc: usize,
    pub end_pc: usize,
    pub handler_family: u32,
    pub entry_states: Vec<VmState>,
    pub instructions: Vec<Instruction>,
    pub successors: Vec<Successor>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LiftedProgram {
    pub blocks: BTreeMap<usize, BasicBlock>,
    pub entry_points: Vec<usize>,
    pub reachable_pcs: BTreeSet<usize>,
    pub state_variants: usize,
    pub root_entry: Option<usize>,
    pub prototype_entries: BTreeMap<usize, usize>,
    /// `Some(n)` for fixed arity, `None` for a packed-vararg entry.
    pub parameters: BTreeMap<usize, Option<usize>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodegenOptions {
    pub strict: bool,
    pub include_source_comments: bool,
    /// Optional, proved presentation cleanup. The conservative output remains
    /// byte-identical when this is false.
    pub pretty: bool,
}

impl Default for CodegenOptions {
    fn default() -> Self {
        Self {
            strict: true,
            include_source_comments: false,
            pretty: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_constants_compare_by_encoded_bits_including_nan() {
        let bits = 0x7ff8_0000_0000_0042;
        let number = NumberConstant {
            index: 1,
            byte_offset: 16,
            encoded_reference: 2023801,
            bits,
            value: f64::from_bits(bits),
        };
        assert!(number.value.is_nan());
        assert_eq!(number, number.clone());
        let other_bits = bits + 1;
        let other = NumberConstant {
            bits: other_bits,
            value: f64::from_bits(other_bits),
            ..number.clone()
        };
        assert_ne!(number, other);
    }
}
