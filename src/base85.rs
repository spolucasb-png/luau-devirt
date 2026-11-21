//! Certified Base85 / rotated-key / three-bank VM profile.
//!
//! Static decoding and symbolic lifting only: no Lua interpreter, VM loop,
//! external function invocation, or target-program table evaluation exists here.
//! The whole wrapper token skeleton is certified (excluding the payload literal)
//! before any algorithm is applied. Unrecognized wrapper changes fail closed.
//! The original decoder, bounded IR optimizers, and structured emitter remain
//! the primary pipeline. This adapter supplies the new transport and state model.

use std::collections::{BTreeMap, HashSet, VecDeque};

use crate::decoder::{scan_quoted, sha256_hex, tokenize, Token, TokenKind};
use crate::ir::*;

pub const PROFILE: &str = "base85-rotor-3bank-v1";
const WRAPPER_SHA256: &str = "3fdbcad7ec61989dadc90cad4226c55434a585d35083244dc4f491a945a90739";
const MAX_PAYLOAD: usize = 1024 * 1024;
const MAX_STATES: usize = 512;
const SMA: u32 = 3501875219;
const SMB: u32 = 4044522868;
const INITIAL_K1: u32 = 1542308556 ^ 432963489;
const CM_INDEX: [usize; 15] = [13, 5, 11, 9, 2, 7, 4, 10, 8, 6, 15, 3, 14, 12, 1];

pub fn is_profile(vm: &DecodedVm) -> bool {
    vm.profile == VmProfile::Base85Rotor3Bank
}

fn unique_sequence(ts: &[Token], text: &[&str]) -> Result<usize, String> {
    let matches: Vec<_> = ts
        .windows(text.len())
        .enumerate()
        .filter(|(_, row)| row.iter().map(|t| t.text.as_str()).eq(text.iter().copied()))
        .map(|(i, _)| i)
        .collect();
    match matches.as_slice() {
        [i] => Ok(*i),
        _ => Err(format!(
            "{PROFILE}: expected one {text:?}, found {}",
            matches.len()
        )),
    }
}

pub(crate) fn certify(ts: &[Token]) -> Result<usize, String> {
    let literal = unique_sequence(ts, &["_b85", "=", "bfrom", "("])? + 4;
    if ts.get(literal).map(|t| t.kind) != Some(TokenKind::String) {
        return Err(format!("{PROFILE}: payload must be a literal"));
    }
    let normalized = ts
        .iter()
        .enumerate()
        .map(|(i, t)| if i == literal { "PAYLOAD" } else { &t.text })
        .collect::<Vec<_>>()
        .join("\n");
    if sha256_hex(normalized.as_bytes()) != WRAPPER_SHA256 {
        return Err(format!("unsupported VM profile: {PROFILE} wrapper token skeleton changed; refusing unchecked formulas or instructions"));
    }
    Ok(literal)
}

/// Least-significant Base85 digit first, then little-endian low-u32 writes.
/// Unlike Ascii85, no whitespace, shorthand, padding, or invalid bytes are skipped.
pub fn decode_transport(
    encoded: &[u8],
    alphabet: &[u8],
    byte_length: usize,
) -> Result<Vec<u8>, String> {
    if alphabet.len() != 85 || byte_length == 0 || byte_length > MAX_PAYLOAD || byte_length % 4 != 0
    {
        return Err("invalid Base85 alphabet length or output size".to_owned());
    }
    if encoded.len() != byte_length / 4 * 5 {
        return Err("Base85 length is not exactly five characters per word".to_owned());
    }
    let mut digits = [None; 256];
    for (i, byte) in alphabet.iter().copied().enumerate() {
        if digits[byte as usize].replace(i as u64).is_some() {
            return Err("duplicate Base85 alphabet byte".to_owned());
        }
    }
    let mut result = Vec::with_capacity(byte_length);
    for (i, group) in encoded.chunks_exact(5).enumerate() {
        let mut word = 0u64;
        for byte in group.iter().rev() {
            let digit = digits[*byte as usize]
                .ok_or_else(|| format!("invalid Base85 byte {byte} in word {i}"))?;
            word = word * 85 + digit;
        }
        // buffer.writeu32 converts the exact (<2^53) integer modulo 2^32.
        result.extend_from_slice(&(word as u32).to_le_bytes());
    }
    Ok(result)
}

fn read32(data: &[u8], offset: usize) -> Result<u32, String> {
    let end = offset.checked_add(4).ok_or("buffer offset overflow")?;
    let bytes: [u8; 4] = data
        .get(offset..end)
        .ok_or_else(|| format!("u32 read out of bounds at byte {offset}"))?
        .try_into()
        .map_err(|_| "invalid u32 slice")?;
    Ok(u32::from_le_bytes(bytes))
}

fn next_key(value: u32) -> u32 {
    let mut value = value
        .wrapping_mul(386733)
        .wrapping_add(3401468729)
        .rotate_left(5);
    value ^= value << 9;
    value ^= value >> 5;
    value ^= value << 1;
    value
}

fn word(vm: &DecodedVm, at: usize) -> Result<u32, String> {
    vm.decoded_words
        .get(at)
        .copied()
        .flatten()
        .ok_or_else(|| format!("absent decoded word {at}"))
}

fn slot(vm: &DecodedVm, at: usize) -> Result<u16, String> {
    vm.slot_map
        .get(at)
        .copied()
        .filter(|s| at > 0 && *s > 0)
        .ok_or_else(|| format!("invalid physical register-map index {at}"))
}

pub(crate) fn decode(source: &str, ts: &[Token]) -> Result<DecodedVm, String> {
    let literal = certify(ts)?;
    let (encoded, _) = scan_quoted(source, ts[literal].offset)?;
    let alphabet_at = unique_sequence(ts, &["_ab", "=", "bfrom", "("])? + 4;
    let (alphabet, _) = scan_quoted(source, ts[alphabet_at].offset)?;
    let payload = decode_transport(&encoded, &alphabet, 2248)?;
    let raw_words = payload
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .collect::<Vec<_>>();
    let initialization_argument = 3932670614 ^ 2196270296;
    let mut key = initialization_argument ^ 3516382929;
    let mut decoded_words = vec![None; raw_words.len() + 1];
    for i in 1..=4 {
        key = next_key(key);
        decoded_words[i] = Some(raw_words[i - 1] ^ key);
    }
    let bw = read32(&payload, 8)?;
    let m0 = initialization_argument ^ bw;
    let master_key = m0.wrapping_mul(28595).wrapping_add(624331951)
        ^ decoded_words[3]
            .ok_or("missing header word 3")?
            .swap_bytes()
        ^ m0.rotate_right(13)
        ^ bw.wrapping_shl(19);
    let low = (decoded_words[2].ok_or("missing header 2")? ^ 1783661776 ^ master_key) as usize;
    let high = (decoded_words[1].ok_or("missing header 1")? ^ 291832251 ^ master_key) as usize;
    if low < 5 || low > high || high > raw_words.len() {
        return Err(format!(
            "{PROFILE}: invalid decoded word range {low}..={high}"
        ));
    }
    for i in low..=high {
        key = next_key(key);
        decoded_words[i] = Some(raw_words[i - 1] ^ key);
    }
    let mut slot_map = vec![0];
    key = 783776128 ^ master_key;
    for i in 0..56 {
        key = key.wrapping_mul(2185).wrapping_add(3437004073);
        let v = read32(&payload, high * 4 + i * 4)? ^ key;
        slot_map.push(v as u16);
        if slot_map.len() <= 111 {
            slot_map.push((v >> 16) as u16);
        }
    }
    if slot_map.iter().skip(1).any(|s| *s == 0) {
        return Err("unsupported profile: zero physical register binding".to_owned());
    }
    if slot_map.iter().copied().max().unwrap_or(0) >= 256 {
        return Err(
            "unsupported physical slots overlap the bounded temporary register area".to_owned(),
        );
    }
    let mut immediate_biases = vec![0];
    key = 3291815529;
    for _ in 0..64 {
        key = key.wrapping_mul(15449).wrapping_add(631628129);
        immediate_biases.push(1 + key % 200000);
    }
    let dispatch_families = BTreeMap::from([
        (18273, 1952),
        (58811, 3080),
        (26325, 1952),
        (37911, 3424),
        (32567, 1408),
        (26754, 2117),
        (7922, 2517),
        (10900, 8358),
        (48861, 1408),
        (48352, 1952),
        (22505, 5521),
        (39012, 3080),
        (34417, 1574),
        (53090, 3080),
        (3879, 1408),
    ]);
    let entry_prototype = (master_key ^ 2137129886u32.wrapping_add(347380486) ^ 731522) as usize;
    let mut vm = DecodedVm {
        profile: VmProfile::Base85Rotor3Bank,
        source_text: source.to_owned(),
        source_sha256: Some(sha256_hex(source.as_bytes())),
        payload,
        raw_words,
        decoded_words,
        slot_map,
        immediate_biases,
        initialization_argument,
        master_key,
        decoded_range: (low, high),
        table_integrity: vec![],
        initial_strings: vec![encoded, alphabet],
        prototypes: vec![],
        entry_prototype,
        strings: vec![],
        numbers: vec![],
        dispatch_families,
        permutation_parity: BTreeMap::new(),
    };
    // Follow the actual boot reference, not a heuristic scan of random words.
    // Certified handlers contain no call to make: there are no reachable child
    // factories. Unsupported root descriptors propagate their precise error.
    vm.prototypes.push(prototype(&vm, entry_prototype, 0)?);
    Ok(vm)
}

fn prototype(vm: &DecodedVm, p: usize, mask: u32) -> Result<Prototype, String> {
    let k = vm.master_key ^ mask;
    let token = word(vm, p)? ^ 3227379408 ^ k;
    if !vm.dispatch_families.contains_key(&token) {
        return Err("invalid prototype token".to_owned());
    }
    let entry = (word(vm, p + 1)? ^ 2202049935 ^ k) as usize;
    let b = word(vm, p + 2)? ^ 4048458749 ^ k;
    let initial_decode_state = word(vm, p + 3)? ^ 3942273499 ^ k;
    let a = word(vm, p + 4)? ^ 2928019701 ^ k;
    let frame_capacity = ((a >> 19) & 8191) as u16;
    let fixed = (a >> 2) & 1 != 0;
    let bank = b & 131071;
    let arity = ((b >> 17) & 7) as u16;
    let captures = ((b >> 20) & 1023) as usize;
    if bank == 0 || bank as usize + 4 >= vm.slot_map.len() || frame_capacity < 4 || arity > 4 {
        return Err("invalid prototype frame/arity".to_owned());
    }
    word(vm, entry)?;
    let mut parameter_operands = Vec::new();
    let aw = if fixed { (arity as usize + 1) / 2 } else { 0 };
    for i in 0..aw {
        let v = word(vm, p + 5 + i)? ^ 2814438330 ^ k;
        parameter_operands.extend([v as u16, (v >> 16) as u16]);
    }
    parameter_operands.truncate(if fixed { arity as usize } else { 0 });
    for operand in &parameter_operands {
        slot(vm, bank as usize + *operand as usize)?;
    }
    if captures != 0 {
        // The source only stores a destination index here. The source capture
        // value comes from make's ups table, not an invented high-half binding.
        return Err("captured prototype requires explicit ups binding analysis".to_owned());
    }
    Ok(Prototype {
        word: p,
        byte_offset: (p - 1) * 4,
        encoded_reference: p as u32 ^ 731522,
        entry_pc: entry,
        initial_decode_state,
        dispatch_token: token,
        frame_capacity,
        bank_base: bank,
        prototype_salt: ((a >> 3) & 65535) as u16,
        fixed_parameter_mode: fixed,
        fixed_parameter_count: if fixed { Some(arity) } else { None },
        parameter_operands,
        captures: vec![],
    })
}

// A small, bounded expression/statement parser for certified handler leaves.
// It does not parse or evaluate the target program as Lua.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum E {
    Int(i64),
    Str(Vec<u8>),
    Id(String),
    Index(Box<E>, Box<E>),
    Call(Box<E>, Vec<E>),
    Bin(String, Box<E>, Box<E>),
    Unary(String, Box<E>),
    Table,
}
#[derive(Clone, Debug)]
pub(crate) enum S {
    Local(Vec<String>, Vec<E>),
    Assign(Vec<E>, Vec<E>),
    Do(Vec<S>),
    If(Vec<(E, Vec<S>)>, Vec<S>),
    Return(Vec<E>),
    Expr(E),
}
pub(crate) struct Parser<'a> {
    pub(crate) ts: &'a [Token],
    pub(crate) source: &'a str,
    pub(crate) at: usize,
    pub(crate) depth: usize,
}
impl<'a> Parser<'a> {
    fn peek(&self) -> &str {
        self.ts.get(self.at).map(|t| t.text.as_str()).unwrap_or("")
    }
    pub(crate) fn eat(&mut self, s: &str) -> bool {
        if self.peek() == s {
            self.at += 1;
            true
        } else {
            false
        }
    }
    pub(crate) fn expect(&mut self, s: &str) -> Result<(), String> {
        if self.eat(s) {
            Ok(())
        } else {
            Err(format!(
                "expected {s}, got {} near token {}",
                self.peek(),
                self.at
            ))
        }
    }
    fn id(&mut self) -> Result<String, String> {
        let t = self.ts.get(self.at).ok_or("missing identifier")?;
        if t.kind != TokenKind::Identifier {
            return Err(format!("expected identifier, got {}", t.text));
        }
        self.at += 1;
        Ok(t.text.clone())
    }
    fn exprs(&mut self) -> Result<Vec<E>, String> {
        let mut v = vec![self.expr(0)?];
        while self.eat(",") {
            v.push(self.expr(0)?);
        }
        Ok(v)
    }
    pub(crate) fn expr(&mut self, min: u8) -> Result<E, String> {
        self.depth += 1;
        if self.depth > 96 {
            return Err("expression nesting budget exceeded".to_owned());
        }
        let token = self.ts.get(self.at).ok_or("missing expression")?.clone();
        self.at += 1;
        let mut left = if matches!(token.text.as_str(), "-" | "not" | "#") {
            E::Unary(token.text, Box::new(self.expr(7)?))
        } else if token.text == "(" {
            let e = self.expr(0)?;
            self.expect(")")?;
            e
        } else if token.text == "{" {
            self.expect("}")?;
            E::Table
        } else if token.kind == TokenKind::Number {
            E::Int(
                token
                    .text
                    .parse()
                    .map_err(|_| "unsupported numeric spelling")?,
            )
        } else if token.kind == TokenKind::String {
            E::Str(scan_quoted(self.source, token.offset)?.0)
        } else {
            E::Id(token.text)
        };
        loop {
            if self.eat("[") {
                let i = self.expr(0)?;
                self.expect("]")?;
                left = E::Index(Box::new(left), Box::new(i));
                continue;
            }
            if self.eat(".") {
                let key = self.id()?;
                left = E::Index(Box::new(left), Box::new(E::Str(key.into_bytes())));
                continue;
            }
            if self.eat("(") {
                let args = if self.eat(")") {
                    vec![]
                } else {
                    let a = self.exprs()?;
                    self.expect(")")?;
                    a
                };
                left = E::Call(Box::new(left), args);
                continue;
            }
            let (prec, op) = match self.peek() {
                "or" => (1, "or"),
                "and" => (2, "and"),
                "==" => (3, "=="),
                "~=" => (3, "~="),
                "<" => (3, "<"),
                "<=" => (3, "<="),
                ">" => (3, ">"),
                ">=" => (3, ">="),
                "+" => (4, "+"),
                "-" => (4, "-"),
                "*" => (5, "*"),
                "%" => (5, "%"),
                _ => break,
            };
            if prec < min {
                break;
            }
            self.at += 1;
            let right = self.expr(prec + 1)?;
            left = E::Bin(op.to_owned(), Box::new(left), Box::new(right));
        }
        self.depth -= 1;
        Ok(left)
    }
    pub(crate) fn block(&mut self) -> Result<Vec<S>, String> {
        self.depth += 1;
        if self.depth > 96 {
            return Err("statement nesting budget exceeded".to_owned());
        }
        let mut result = vec![];
        while !matches!(self.peek(), "" | "end" | "else" | "elseif") {
            if self.eat(";") {
                continue;
            }
            if self.eat("local") {
                let mut names = vec![self.id()?];
                while self.eat(",") {
                    names.push(self.id()?);
                }
                let values = if self.eat("=") { self.exprs()? } else { vec![] };
                result.push(S::Local(names, values));
            } else if self.eat("do") {
                let b = self.block()?;
                self.expect("end")?;
                result.push(S::Do(b));
            } else if self.eat("if") {
                let mut arms = vec![];
                loop {
                    let c = self.expr(0)?;
                    self.expect("then")?;
                    let b = self.block()?;
                    arms.push((c, b));
                    if !self.eat("elseif") {
                        break;
                    }
                }
                let otherwise = if self.eat("else") {
                    self.block()?
                } else {
                    vec![]
                };
                self.expect("end")?;
                result.push(S::If(arms, otherwise));
            } else if self.eat("return") {
                let args = if matches!(self.peek(), ";" | "end" | "else" | "") {
                    vec![]
                } else {
                    self.exprs()?
                };
                result.push(S::Return(args));
            } else {
                let targets = self.exprs()?;
                if self.eat("=") {
                    result.push(S::Assign(targets, self.exprs()?));
                } else if targets.len() == 1 {
                    result.push(S::Expr(
                        targets.into_iter().next().ok_or("empty statement")?,
                    ));
                } else {
                    return Err("unsupported statement".to_owned());
                }
            }
            if result.len() > 4096 {
                return Err("statement budget exceeded".to_owned());
            }
        }
        self.depth -= 1;
        Ok(result)
    }
}

#[derive(Clone, Debug)]
struct Family {
    selector: E,
    tree: S,
}
fn families(source: &str) -> Result<BTreeMap<u32, Family>, String> {
    let ts = tokenize(source)?;
    certify(&ts)?;
    let mut result = BTreeMap::new();
    for i in 0..ts.len().saturating_sub(6) {
        if ts[i].text != "_dr"
            || ts[i + 1].text != "["
            || ts[i + 3].text != "]"
            || ts[i + 4].text != "="
            || ts[i + 5].text != "function"
        {
            continue;
        }
        let family = ts[i + 2]
            .text
            .parse::<u32>()
            .map_err(|_| "invalid family")?;
        let anchor = (i + 6..ts.len().saturating_sub(3))
            .find(|j| ts[*j].text == "local" && ts[*j + 1].text == "op" && ts[*j + 2].text == "=")
            .ok_or("family discriminator missing")?;
        let mut parser = Parser {
            ts: &ts,
            source,
            at: anchor + 3,
            depth: 0,
        };
        let selector = parser.expr(0)?;
        parser.eat(";");
        // Parse exactly the root comparison tree; never the family dispatch loop.
        parser.expect("if")?;
        let mut arms = vec![];
        loop {
            let c = parser.expr(0)?;
            parser.expect("then")?;
            let b = parser.block()?;
            arms.push((c, b));
            if !parser.eat("elseif") {
                break;
            }
        }
        let otherwise = if parser.eat("else") {
            parser.block()?
        } else {
            vec![]
        };
        parser.expect("end")?;
        if result
            .insert(
                family,
                Family {
                    selector,
                    tree: S::If(arms, otherwise),
                },
            )
            .is_some()
        {
            return Err("duplicate handler family".to_owned());
        }
    }
    Ok(result)
}

// Lifting implementation follows below. It only materializes data operations
// into the shared IR; target values and external functions are never evaluated.

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct State {
    pub pc: usize,
    pub key: u32,
    pub bank: u32,
    pub token: u32,
    pub salt: u16,
    /// Normalized `(rotor + SMB + F[phase_slot]) mod 2^32`.
    pub phase: u32,
    pub window: u32,
    pub bank_end: u32,
    pub pool_key: u32,
}

#[derive(Clone, Debug)]
pub struct TraceRow {
    pub state: State,
    pub family: u32,
    pub selector: i64,
    pub end_pc: usize,
    pub instructions: Vec<Instruction>,
    pub successors: Vec<(EdgeLabel, State)>,
}

#[derive(Clone, Debug)]
pub struct Analysis {
    pub program: LiftedProgram,
    pub raw_program: LiftedProgram,
    pub trace: Vec<TraceRow>,
    pub strings: BTreeMap<u32, Vec<u8>>,
    pub numbers: BTreeMap<u32, u64>,
}

#[derive(Clone, Debug)]
enum V {
    Int(i64),
    Bool(bool),
    Nil,
    Data(Operand),
    Witness(u8),
}
impl V {
    fn int(&self) -> Result<i64, String> {
        if let Self::Int(i) = self {
            Ok(*i)
        } else {
            Err(format!(
                "metadata expression needs a proved integer, got {self:?}"
            ))
        }
    }
    fn u32(&self) -> Result<u32, String> {
        let i = self.int()?;
        u32::try_from(i).map_err(|_| format!("integer {i} outside u32"))
    }
    fn operand(&self) -> Result<Operand, String> {
        match self {
            Self::Int(i) => Ok(Operand::Constant(Constant::Integer(*i))),
            Self::Bool(b) => Ok(Operand::Constant(Constant::Boolean(*b))),
            Self::Nil => Ok(Operand::Constant(Constant::Nil)),
            Self::Data(v) => Ok(v.clone()),
            Self::Witness(_) => Err("permutation witness is not a program value".to_owned()),
        }
    }
    fn truth(&self) -> Option<bool> {
        match self {
            Self::Bool(v) => Some(*v),
            Self::Nil => Some(false),
            Self::Int(_) => Some(true),
            Self::Data(Operand::Constant(Constant::Boolean(b))) => Some(*b),
            Self::Data(Operand::Constant(Constant::Nil)) => Some(false),
            _ => None,
        }
    }
}

fn ident(expr: &E, name: &str) -> bool {
    matches!(expr,E::Id(n) if n==name)
}
fn index_ident(expr: &E, name: &str) -> bool {
    matches!(expr,E::Index(t,_) if ident(t,name))
}
fn binary(op: &str) -> Result<BinaryOp, String> {
    Ok(match op {
        "+" => BinaryOp::Add,
        "-" => BinaryOp::Sub,
        "*" => BinaryOp::Mul,
        "%" => BinaryOp::Mod,
        "==" => BinaryOp::Equal,
        "~=" => BinaryOp::NotEqual,
        "<" => BinaryOp::Less,
        "<=" => BinaryOp::LessEqual,
        ">" => BinaryOp::Greater,
        ">=" => BinaryOp::GreaterEqual,
        "and" => BinaryOp::And,
        "or" => BinaryOp::Or,
        _ => return Err(format!("unsupported binary operator {op}")),
    })
}
fn reg(slot: u16) -> Register {
    Register {
        physical_slot: slot,
    }
}
fn rop(slot: u16) -> Operand {
    Operand::Register(reg(slot))
}

struct Lift<'a> {
    vm: &'a DecodedVm,
    state: State,
    locals: BTreeMap<String, V>,
    out: Vec<Instruction>,
    fresh: u16,
    fresh_end: u16,
    max_offset: usize,
    strings: BTreeMap<u32, Vec<u8>>,
    numbers: BTreeMap<u32, u64>,
    control: Option<Control>,
    witness_writes: Vec<(usize, u8)>,
}
#[derive(Clone, Debug)]
enum Control {
    Next(State),
    Branch(Condition, State, State),
    Return,
}

impl<'a> Lift<'a> {
    /// A bijection for the current frame, not a liveness-based alias merge.
    /// Both helper directions preserve the value in logical u1 and logical u2:
    /// the source's parallel copies move each value into that role's new slot.
    /// Rotor/phase slots are excluded from program data. All other slots stay
    /// unchanged. The transition verifies all four physical identities.
    fn program_register(&self, raw: u16) -> Result<u16, String> {
        if CM_INDEX
            .iter()
            .any(|i| self.vm.slot_map.get(*i) == Some(&raw))
        {
            return Err(format!("program accesses reserved frame slot {raw}"));
        }
        let aliases = [
            slot(self.vm, self.state.bank as usize + 1)?,
            slot(self.vm, self.state.bank as usize + 2)?,
            slot(self.vm, self.state.bank as usize + 3)?,
            slot(self.vm, self.state.bank as usize + 4)?,
        ];
        if aliases
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != 4
        {
            return Err("bank role mapping is not injective".to_owned());
        }
        let base = self.vm.slot_map.iter().copied().max().unwrap_or(0);
        if raw == aliases[2] {
            return base
                .checked_add(1)
                .ok_or_else(|| "scratch role overflow".to_owned());
        }
        if raw == aliases[3] {
            return base
                .checked_add(2)
                .ok_or_else(|| "scratch role overflow".to_owned());
        }
        if raw == aliases[0] || raw == aliases[1] {
            return Err(format!("program reads/writes rotor metadata slot {raw}"));
        }
        Ok(raw)
    }
    fn new(vm: &'a DecodedVm, state: &State) -> Self {
        let locals = BTreeMap::from([
            ("ip".to_owned(), V::Int(state.pc as i64)),
            ("st".to_owned(), V::Int(state.key as i64)),
            ("rb".to_owned(), V::Int(state.bank as i64)),
            ("sh".to_owned(), V::Int(state.token as i64)),
            ("ps".to_owned(), V::Int(state.salt as i64)),
            ("_rbs".to_owned(), V::Int(state.window as i64)),
            ("stop".to_owned(), V::Int(0)),
            ("exit".to_owned(), V::Int(0)),
            ("K0".to_owned(), V::Int(vm.master_key as i64)),
            ("K1".to_owned(), V::Int(state.pool_key as i64)),
        ]);
        let fresh =
            u16::try_from(256 + state.pc * 64).expect("certified payload has only 562 words");
        Self {
            vm,
            state: state.clone(),
            locals,
            out: vec![],
            fresh,
            fresh_end: fresh + 64,
            max_offset: 0,
            strings: BTreeMap::new(),
            numbers: BTreeMap::new(),
            control: None,
            witness_writes: vec![],
        }
    }
    fn temp(&mut self) -> Result<u16, String> {
        let r = self.fresh;
        self.fresh = self
            .fresh
            .checked_add(1)
            .filter(|s| *s <= self.fresh_end)
            .ok_or("leaf temporary budget exceeded")?;
        Ok(r)
    }
    fn put(&mut self, dst: u16, src: Operand) {
        let dst = reg(dst);
        let instruction = match src {
            Operand::Constant(value) => Instruction::LoadConst { dst, value },
            Operand::Expression(e) => match *e {
                ValueExpression::Binary { op, left, right } => Instruction::Binary {
                    op,
                    dst,
                    left,
                    right,
                },
                ValueExpression::Unary { op, value } => Instruction::Unary {
                    op,
                    dst,
                    src: value,
                },
                other => Instruction::Move {
                    dst,
                    src: Operand::Expression(Box::new(other)),
                },
            },
            src => Instruction::Move { dst, src },
        };
        self.out.push(instruction);
    }
    fn value(&mut self, op: Operand) -> Result<V, String> {
        let dst = self.temp()?;
        self.put(dst, op);
        Ok(V::Data(rop(dst)))
    }
    fn frame_field(&self, e: &E) -> Option<usize> {
        if let E::Index(t, i) = e {
            if ident(t, "_cm") {
                if let E::Int(i) = i.as_ref() {
                    return usize::try_from(*i).ok();
                }
            }
        }
        None
    }
    fn eval(&mut self, e: &E) -> Result<V, String> {
        match e {
            E::Int(i) => Ok(V::Int(*i)),
            E::Str(s) => Ok(V::Data(Operand::Constant(Constant::String(s.clone())))),
            E::Id(n) => match n.as_str() {
                "true" => Ok(V::Bool(true)),
                "false" => Ok(V::Bool(false)),
                "nil" => Ok(V::Nil),
                "_sma" => Ok(V::Int(SMA as i64)),
                "_smb" => Ok(V::Int(SMB as i64)),
                "_pxs" | "_pys" | "_u1s" | "_u2s" => {
                    let offset = match n.as_str() {
                        "_pxs" => 1,
                        "_pys" => 2,
                        "_u1s" => 3,
                        _ => 4,
                    };
                    Ok(V::Int(
                        slot(self.vm, self.state.bank as usize + offset)? as i64
                    ))
                }
                _ => self
                    .locals
                    .get(n)
                    .cloned()
                    .ok_or_else(|| format!("unresolved identifier {n}")),
            },
            E::Table => {
                let dst = self.temp()?;
                self.out.push(Instruction::NewTable { dst: reg(dst) });
                Ok(V::Data(rop(dst)))
            }
            E::Unary(op, a) => {
                let v = self.eval(a)?;
                match (op.as_str(), &v) {
                    ("-", V::Int(i)) => Ok(V::Int(i.checked_neg().ok_or("negative overflow")?)),
                    ("not", _) if v.truth().is_some() => {
                        Ok(V::Bool(!v.truth().ok_or("truth value missing")?))
                    }
                    _ => {
                        let op = match op.as_str() {
                            "not" => UnaryOp::Not,
                            "-" => UnaryOp::Negate,
                            "#" => UnaryOp::Length,
                            _ => return Err("unsupported unary operation".to_owned()),
                        };
                        Ok(V::Data(Operand::Expression(Box::new(
                            ValueExpression::Unary {
                                op,
                                value: v.operand()?,
                            },
                        ))))
                    }
                }
            }
            E::Bin(op, a, b) => {
                // Internal SM/NM caches are total only after their record is
                // statically validated. Their fallback has identical decode semantics.
                if op == "or" && (index_ident(a, "SM") || index_ident(a, "NM")) {
                    return self.eval(b);
                }
                let a = self.eval(a)?;
                if op == "and" || op == "or" {
                    if let Some(truth) = a.truth() {
                        return if (op == "and" && truth) || (op == "or" && !truth) {
                            self.eval(b)
                        } else {
                            Ok(a)
                        };
                    }
                }
                let b = self.eval(b)?;
                if let (V::Int(a), V::Int(b)) = (&a, &b) {
                    let result = match op.as_str() {
                        "+" => a.checked_add(*b),
                        "-" => a.checked_sub(*b),
                        "*" => a.checked_mul(*b),
                        "%" if *b > 0 => Some(a.rem_euclid(*b)),
                        _ => None,
                    };
                    if let Some(i) = result {
                        return Ok(V::Int(i));
                    }
                    let cmp = match op.as_str() {
                        "==" => Some(a == b),
                        "~=" => Some(a != b),
                        "<" => Some(a < b),
                        "<=" => Some(a <= b),
                        ">" => Some(a > b),
                        ">=" => Some(a >= b),
                        _ => None,
                    };
                    if let Some(v) = cmp {
                        return Ok(V::Bool(v));
                    }
                }
                if matches!(op.as_str(), "==" | "~=")
                    && matches!((&a, &b), (V::Int(_), V::Nil) | (V::Nil, V::Int(_)))
                {
                    return Ok(V::Bool(op == "~="));
                }
                Ok(V::Data(Operand::Expression(Box::new(
                    ValueExpression::Binary {
                        op: binary(op)?,
                        left: a.operand()?,
                        right: b.operand()?,
                    },
                ))))
            }
            E::Index(t, i) => {
                if ident(t, "_w") {
                    let at = usize::try_from(self.eval(i)?.int()?)
                        .map_err(|_| "negative word reference")?;
                    let off = at
                        .checked_sub(self.state.pc)
                        .ok_or("word before instruction")?;
                    if off > 256 {
                        return Err("operand span exceeds budget".to_owned());
                    }
                    self.max_offset = self.max_offset.max(off);
                    return Ok(V::Int(word(self.vm, at)? as i64));
                }
                if ident(t, "_rm") {
                    let at =
                        usize::try_from(self.eval(i)?.int()?).map_err(|_| "negative slot index")?;
                    return Ok(V::Int(slot(self.vm, at)? as i64));
                }
                if ident(t, "_kb") {
                    let at =
                        usize::try_from(self.eval(i)?.int()?).map_err(|_| "negative bias index")?;
                    return Ok(V::Int(
                        *self
                            .vm
                            .immediate_biases
                            .get(at)
                            .filter(|_| at > 0)
                            .ok_or("bias out of bounds")? as i64,
                    ));
                }
                if ident(t, "F") {
                    if let Some(field) = self.frame_field(i) {
                        return match field {
                            3 => Ok(V::Int(self.state.window as i64)),
                            4 => Ok(V::Int(self.state.bank as i64)),
                            9 => Ok(V::Int(self.state.bank_end as i64)),
                            _ => Err(format!("unmodeled frame metadata read CM[{field}]")),
                        };
                    }
                    if ident(i, "_pxs") {
                        return Err("raw rotor value is intentionally absent from normalized symbolic state".to_owned());
                    }
                    let dst =
                        u16::try_from(self.eval(i)?.int()?).map_err(|_| "invalid F register")?;
                    return Ok(V::Data(rop(self.program_register(dst)?)));
                }
                if ident(t, "G") {
                    let key = self.eval(i)?.operand()?;
                    let dst = self.temp()?;
                    self.out.push(Instruction::GetTable {
                        dst: reg(dst),
                        table: Operand::Environment,
                        index: key,
                    });
                    return Ok(V::Data(rop(dst)));
                }
                let t = self.eval(t)?.operand()?;
                let i = self.eval(i)?.operand()?;
                let dst = self.temp()?;
                self.out.push(Instruction::GetTable {
                    dst: reg(dst),
                    table: t,
                    index: i,
                });
                Ok(V::Data(rop(dst)))
            }
            E::Call(target, args) => self.call(target, args),
        }
    }
    fn call(&mut self, target: &E, args: &[E]) -> Result<V, String> {
        if let E::Id(n) = target {
            if n == "bxor" {
                let mut v = 0u32;
                for a in args {
                    v ^= self.eval(a)?.u32()?;
                }
                return Ok(V::Int(v as i64));
            }
            if n == "U" {
                if args.len() != 7 {
                    return Err("invalid U arity".to_owned());
                }
                let op = self.eval(&args[6])?.u32()? ^ 3300;
                if op == 14471 {
                    if self.eval(&args[2])?.u32()? != 300222 {
                        return Err("nonzero witness displacement unsupported".to_owned());
                    }
                    return Err(
                        "permutation tuple must be lifted as a complete witness pair".to_owned(),
                    );
                }
                if op > 42673 {
                    if self.eval(&args[2])?.u32()? != 413384 {
                        return Err("nonzero parity displacement".to_owned());
                    }
                    return Ok(V::Int(53112));
                }
                if op >= 31151 && op < 35324 {
                    let reference = self.eval(&args[1])?.u32()?;
                    let key = self.eval(&args[2])?.u32()?;
                    return self.string(reference, key);
                }
                if op > 39792 && op < 42673 {
                    let reference = self.eval(&args[1])?.u32()?;
                    let key = self.eval(&args[2])?.u32()?;
                    return self.number(reference, key);
                }
                return Err(format!("unsupported U operation {op}"));
            }
        }
        // A program function is represented by IR only; never called by Rust.
        let function = self.eval(target)?.operand()?;
        let mut operands = vec![];
        for arg in args {
            operands.push(self.eval(arg)?.operand()?);
        }
        let packet = self.temp()?;
        self.out.push(Instruction::Call {
            dst: Some(reg(packet)),
            function,
            args: operands,
            result_count: Some(1),
        });
        let dst = self.temp()?;
        self.out.push(Instruction::GetTable {
            dst: reg(dst),
            table: rop(packet),
            index: Operand::Constant(Constant::Integer(1)),
        });
        Ok(V::Data(rop(dst)))
    }
    fn string(&mut self, reference: u32, key: u32) -> Result<V, String> {
        let offset = (reference ^ 701714) as usize;
        let seed = read32(&self.vm.payload, offset)? ^ 1656731775;
        let len = (read32(&self.vm.payload, offset + 4)? ^ 85451734 ^ seed) as usize;
        let end = offset
            .checked_add(8)
            .and_then(|v| v.checked_add(len))
            .ok_or("string extent overflow")?;
        if len > MAX_PAYLOAD || end > self.vm.payload.len() {
            return Err(format!("invalid string extent at {offset} length {len}"));
        }
        let mut value = vec![];
        let mut state = seed ^ self.vm.master_key ^ key ^ 53112;
        for i in 0..len / 4 {
            state = state.wrapping_mul(2151).wrapping_add(549576011);
            value.extend_from_slice(
                &(read32(&self.vm.payload, offset + 8 + i * 4)? ^ state).to_le_bytes(),
            );
        }
        for i in len / 4 * 4..len {
            state = state.wrapping_mul(2151).wrapping_add(549576011);
            value.push(self.vm.payload[offset + 8 + i] ^ (state as u8));
        }
        if let Some(old) = self.strings.insert(reference, value.clone()) {
            if old != value {
                return Err("string has inconsistent keys".to_owned());
            }
        }
        Ok(V::Data(Operand::Constant(Constant::String(value))))
    }
    fn number(&mut self, reference: u32, key: u32) -> Result<V, String> {
        let index = reference ^ 1329030;
        if index == 0 || index > 65536 {
            return Err("invalid number reference".to_owned());
        }
        let base = (word(self.vm, 4)? ^ 3139019791 ^ self.vm.master_key) as usize;
        let offset = base
            .checked_add((index as usize - 1) * 8)
            .ok_or("number offset overflow")?;
        let extra = key ^ 53112;
        let lo = read32(&self.vm.payload, offset)?
            ^ 4177466961u32.wrapping_add(index.wrapping_mul(267459))
            ^ self.vm.master_key
            ^ extra;
        let hi = read32(&self.vm.payload, offset + 4)?
            ^ 1751540260u32.wrapping_add(index.wrapping_mul(473879))
            ^ self.vm.master_key.rotate_left(21)
            ^ extra.rotate_left(25);
        let bits = (hi as u64) << 32 | lo as u64;
        if let Some(old) = self.numbers.insert(reference, bits) {
            if old != bits {
                return Err("number has inconsistent keys".to_owned());
            }
        }
        Ok(V::Data(Operand::Constant(Constant::NumberBits(bits))))
    }
    fn snapshot(&mut self, v: V) -> Result<V, String> {
        match v {
            V::Data(Operand::Register(_) | Operand::Expression(_) | Operand::Global(_)) => {
                self.value(v.operand()?)
            }
            _ => Ok(v),
        }
    }
    fn assign(&mut self, target: &E, value: V) -> Result<(), String> {
        if let E::Id(n) = target {
            self.locals.insert(n.clone(), value);
            return Ok(());
        }
        let E::Index(table, index) = target else {
            return Err("invalid assignment target".to_owned());
        };
        if ident(table, "F") {
            if let Some(field) = self.frame_field(index) {
                match (field, value) {
                    (3, V::Int(n)) => {
                        self.state.window = u32::try_from(n).map_err(|_| "invalid bank window")?
                    }
                    (9, V::Int(n)) => {
                        self.state.bank_end = u32::try_from(n).map_err(|_| "invalid bank end")?
                    }
                    (10, V::Witness(i)) | (13, V::Witness(i)) => {
                        self.witness_writes.push((field, i))
                    }
                    _ => return Err(format!("unsupported metadata assignment CM[{field}]")),
                };
                return Ok(());
            }
            if ident(index, "_pxs") || ident(index, "_pys") {
                return Err("entry rotor assignments require a proved entry template".to_owned());
            }
            let dst = u16::try_from(self.eval(index)?.int()?).map_err(|_| "invalid destination")?;
            let dst = self.program_register(dst)?;
            self.put(dst, value.operand()?);
            return Ok(());
        }
        let table = self.eval(table)?.operand()?;
        let index = self.eval(index)?.operand()?;
        self.out.push(Instruction::SetTable {
            table,
            index,
            value: value.operand()?,
        });
        Ok(())
    }
    fn statements(&mut self, statements: &[S]) -> Result<(), String> {
        for s in statements {
            if self.control.is_some() {
                break;
            }
            match s {
                S::Do(b) => {
                    let previous = self.locals.clone();
                    self.statements(b)?;
                    let updates = self.locals.clone();
                    self.locals = previous;
                    for (n, v) in updates {
                        if self.locals.contains_key(&n) {
                            self.locals.insert(n, v);
                        }
                    }
                }
                S::Local(names, exprs) => {
                    if names.len() == 2 && exprs.len() == 1 {
                        if let E::Call(t, args) = &exprs[0] {
                            if ident(t, "U")
                                && args.len() == 7
                                && self.eval(&args[6])?.u32()? == 13411
                                && self.eval(&args[2])?.u32()? == 300222
                            {
                                self.locals.insert(names[0].clone(), V::Witness(0));
                                self.locals.insert(names[1].clone(), V::Witness(1));
                                continue;
                            }
                        }
                    }
                    if names.len() != exprs.len() && !exprs.is_empty() {
                        return Err("unmodeled local multi-result expression".to_owned());
                    }
                    let mut values = vec![];
                    for e in exprs {
                        let v = self.eval(e)?;
                        values.push(self.snapshot(v)?);
                    }
                    for (i, n) in names.iter().enumerate() {
                        self.locals
                            .insert(n.clone(), values.get(i).cloned().unwrap_or(V::Nil));
                    }
                }
                S::Assign(targets, values) => {
                    if self.helper_assignment(targets, values)? {
                        continue;
                    }
                    if targets.len() != values.len() {
                        return Err("unmodeled multiple assignment".to_owned());
                    }
                    let mut evaluated = vec![];
                    for e in values {
                        let v = self.eval(e)?;
                        evaluated.push(if values.len() > 1 {
                            self.snapshot(v)?
                        } else {
                            v
                        });
                    }
                    for (target, value) in targets.iter().zip(evaluated) {
                        self.assign(target, value)?;
                    }
                }
                S::If(arms, other) => {
                    let mut selected = None;
                    for (c, b) in arms {
                        let v = self.eval(c)?;
                        let truth = v
                            .truth()
                            .ok_or_else(|| format!("unmodeled runtime if in leaf: {c:?}"))?;
                        if truth {
                            selected = Some(b);
                            break;
                        }
                    }
                    self.statements(selected.unwrap_or(other))?;
                }
                S::Return(args) => {
                    if args.len() == 2
                        && ident(&args[0], "true")
                        && matches!(args[1], E::Int(93375))
                    {
                        self.control = Some(Control::Return);
                    } else {
                        return Err(format!("unsupported handler return {args:?}"));
                    }
                }
                S::Expr(E::Call(target, args)) => {
                    let value = self.call(target, args)?;
                    if let V::Data(Operand::Register(_)) = value {
                    } else {
                        return Err("unsupported non-program call statement".to_owned());
                    }
                }
                _ => return Err("unsupported leaf statement".to_owned()),
            }
        }
        Ok(())
    }
    fn helper_assignment(&mut self, targets: &[E], values: &[E]) -> Result<bool, String> {
        let [E::Call(target, args)] = values else {
            return Ok(false);
        };
        let E::Index(table, id) = target.as_ref() else {
            return Ok(false);
        };
        if !ident(table, "_hc") {
            return Ok(false);
        }
        let E::Int(id) = id.as_ref() else {
            return Err("nonliteral transition helper".to_owned());
        };
        let id = u32::try_from(*id).map_err(|_| "invalid helper id")?;
        if targets.len() != 3 {
            return Err("transition helper return arity changed".to_owned());
        }
        if !matches!(id, 1 | 3 | 6 | 15 | 16 | 32) {
            return Err(format!("unsupported transition helper {id}"));
        }
        let params = helper_parameters(&self.vm.source_text, id)?;
        if params.len() != args.len() {
            return Err(format!("helper {id} argument count mismatch"));
        }
        let mut bound = BTreeMap::new();
        for (name, arg) in params.iter().zip(args) {
            bound.insert(name.clone(), arg.clone());
        }
        let arg = |ctx: &mut Self, name: &str| -> Result<V, String> {
            ctx.eval(
                bound
                    .get(name)
                    .ok_or_else(|| format!("helper {id} lacks {name}"))?,
            )
        };
        let delta = |ctx: &mut Self, name: &str| -> Result<i64, String> { arg(ctx, name)?.int() };
        if id == 16 || id == 32 {
            let d = delta(self, "_d")?;
            let ds = delta(self, "_ds")?;
            let h = delta(self, "_h")?;
            let ct = delta(self, "_ct")?;
            let next = self.transition(d, ds, h, ct, id == 32, 0)?;
            self.control = Some(Control::Next(next));
            return Ok(true);
        }
        let (condition, yes, no) = if id == 1 {
            let x = arg(self, "_x")?.operand()?;
            let hp = arg(self, "_hp")?.u32()?;
            let mask = arg(self, "_m32")?.u32()?;
            let (expected, kv) = inverse_equality(hp ^ mask);
            let condition = Condition::Compare {
                op: BinaryOp::Equal,
                left: x,
                right: Operand::Constant(Constant::Integer(expected as i32 as i64)),
            };
            let deq = delta(self, "_deq")?;
            let seq = delta(self, "_seq")?;
            let heq = delta(self, "_heq")?;
            let ceq = delta(self, "_ceq")?;
            let yes = self.transition(
                deq + kv as i64,
                seq + kv as i64,
                heq + kv as i64,
                ceq + kv as i64,
                true,
                0,
            )?;
            let dne = delta(self, "_dne")?;
            let sne = delta(self, "_sne")?;
            let hne = delta(self, "_hne")?;
            let cne = delta(self, "_cne")?;
            let no = self.transition(dne, sne, hne, cne, false, 0)?;
            (condition, yes, no)
        } else {
            let c = arg(self, "_c")?.operand()?;
            let condition = if let Operand::Expression(e) = &c {
                if let ValueExpression::Binary { op, left, right } = e.as_ref() {
                    if matches!(
                        op,
                        BinaryOp::Less
                            | BinaryOp::Equal
                            | BinaryOp::Greater
                            | BinaryOp::LessEqual
                            | BinaryOp::GreaterEqual
                            | BinaryOp::NotEqual
                    ) {
                        Condition::Compare {
                            op: *op,
                            left: left.clone(),
                            right: right.clone(),
                        }
                    } else {
                        Condition::Truthy(c)
                    }
                } else {
                    Condition::Truthy(c)
                }
            } else {
                Condition::Truthy(c)
            };
            // Helper 6's BM2 expression is true precisely for truthy c;
            // helpers 3 and 15 use BM1 and choose their first arm for false c.
            let first_is_true = id == 6;
            let dt = delta(self, "_dt")?;
            let st0 = delta(self, "_st0")?;
            let ht = delta(self, "_ht")?;
            let ct = delta(self, "_ct")?;
            let first = self.transition(dt, st0, ht, ct, true, 53112)?;
            let df = delta(self, "_df")?;
            let sf = delta(self, "_sf")?;
            let hf = delta(self, "_hf")?;
            let cf = delta(self, "_cf")?;
            let second = self.transition(df, sf, hf, cf, false, 53112)?;
            if first_is_true {
                (condition, first, second)
            } else {
                (condition, second, first)
            }
        };
        self.control = Some(Control::Branch(condition, yes, no));
        Ok(true)
    }
    fn transition(
        &self,
        d: i64,
        ds: i64,
        token: i64,
        phase: i64,
        forward: bool,
        boolean_salt: u32,
    ) -> Result<State, String> {
        if self.state.window == 0 {
            return Err("transition before entry bank initialization".to_owned());
        }
        let mut next = self.state.clone();
        let pc = (self.state.pc as i64)
            .checked_add(d)
            .ok_or("PC arithmetic overflow")?;
        next.pc = usize::try_from(pc).map_err(|_| "negative branch destination")?;
        word(self.vm, next.pc)?;
        next.key =
            (self.state.key as i64 + ds + self.state.phase as i64 + 53112 + boolean_salt as i64)
                .rem_euclid(1i64 << 32) as u32;
        next.token = (token + self.state.phase as i64 + 53112).rem_euclid(1i64 << 32) as u32;
        if !self.vm.dispatch_families.contains_key(&next.token) {
            return Err(format!(
                "transition reaches unknown token {} at word {}",
                next.token, next.pc
            ));
        }
        next.phase = phase.rem_euclid(1i64 << 32) as u32;
        let bank = self.state.bank as i64;
        let width = self.state.window as i64;
        let end = self.state.bank_end as i64;
        let new_bank = if forward {
            if bank >= end {
                bank - 2 * width
            } else {
                bank + width
            }
        } else if bank <= end - 2 * width {
            bank + 2 * width
        } else {
            bank - width
        };
        next.bank = u32::try_from(new_bank).map_err(|_| "invalid rotated bank")?;
        let old = [
            slot(self.vm, self.state.bank as usize + 1)?,
            slot(self.vm, self.state.bank as usize + 2)?,
            slot(self.vm, self.state.bank as usize + 3)?,
            slot(self.vm, self.state.bank as usize + 4)?,
        ];
        let new = [
            slot(self.vm, next.bank as usize + 1)?,
            slot(self.vm, next.bank as usize + 2)?,
            slot(self.vm, next.bank as usize + 3)?,
            slot(self.vm, next.bank as usize + 4)?,
        ];
        let expected = if forward {
            [old[2], old[1], old[3], old[0]]
        } else {
            [old[3], old[1], old[0], old[2]]
        };
        if new != expected {
            return Err("register-map rotation does not prove helper alias updates".to_owned());
        }
        Ok(next)
    }
    fn entry(&mut self, body: &[S]) -> Result<bool, String> {
        let Some(S::Local(names, values)) = body.first() else {
            return Ok(false);
        };
        if names.iter().map(String::as_str).collect::<Vec<_>>() != ["_a0", "_sr", "_ls", "_cs"] {
            return Ok(false);
        }
        let mut resolved = vec![];
        for value in values {
            resolved.push(self.eval(value)?);
        }
        if resolved.len() != 4 {
            return Err("entry operand arity mismatch".to_owned());
        }
        for (name, value) in names.iter().zip(&resolved) {
            self.locals.insert(name.clone(), value.clone());
        }
        let a0 = resolved[0].u32()?;
        let width = resolved[2].u32()?;
        let phase = resolved[3].u32()?;
        if width < 4 || width > 111 {
            return Err("invalid entry bank window".to_owned());
        }
        if a0 != 0 {
            let dst = slot(self.vm, self.state.bank as usize + a0 as usize)?;
            self.out.push(Instruction::Move {
                dst: reg(dst),
                src: Operand::Argument(0),
            });
        }
        // Certified entry's only other program-data operation is the optional
        // first-argument copy above. Remaining stores initialize rotor metadata.
        if self.state.pool_key == INITIAL_K1 {
            let expression =
                find_assignment(body, "K1").ok_or("entry lacks K1 rekey expression")?;
            self.state.pool_key = self.eval(expression)?.u32()?;
            self.locals
                .insert("K1".to_owned(), V::Int(self.state.pool_key as i64));
        }
        self.state.phase = phase;
        self.state.window = width;
        self.state.bank_end = self
            .state
            .bank
            .checked_add(width.checked_mul(2).ok_or("bank width overflow")?)
            .ok_or("bank end overflow")?;
        for offset in 1..=4 {
            slot(self.vm, self.state.bank_end as usize + offset)?;
        }
        Ok(true)
    }
}

pub fn walk(vm: &DecodedVm) -> Result<LiftedProgram, String> {
    Ok(analyze(vm)?.program)
}

fn helper_parameters(source: &str, id: u32) -> Result<Vec<String>, String> {
    let ts = tokenize(source)?;
    let id = id.to_string();
    let i = unique_sequence(&ts, &["_h", "[", &id, "]", "=", "function", "("])? + 7;
    let mut names = vec![];
    let mut at = i;
    while let Some(t) = ts.get(at) {
        if t.text == ")" {
            return Ok(names);
        }
        if t.text != "," {
            names.push(t.text.clone());
        }
        at += 1;
        if names.len() > 32 {
            return Err("helper parameter budget".to_owned());
        }
    }
    Err("unterminated helper parameters".to_owned())
}

fn permutations() -> (Vec<u16>, Vec<u16>, Vec<u16>) {
    let mut a = (0..16384u16).collect::<Vec<_>>();
    let mut b = a.clone();
    let mut c = vec![0; 16384];
    let mut ka = 2147576667u32;
    let mut kb = 2377930657u32;
    for i in (1..16384usize).rev() {
        ka = ka.wrapping_mul(19985).wrapping_add(4096326383);
        a.swap(i, (ka % (i as u32 + 1)) as usize);
        kb = kb.wrapping_mul(19985).wrapping_add(4096326383);
        b.swap(i, (kb % (i as u32 + 1)) as usize);
    }
    for i in 0..16384 {
        c[a[i] as usize] = ((b[i] as u32 * 4
            + ((i as u32 * 17 + 8644) % 16384) * 2
            + ((a[i] as u32 >> 9) & 1)
            + 53112)
            % 65536) as u16;
    }
    (a, b, c)
}
fn inverse_equality(packed: u32) -> (u32, u16) {
    let (a, b, c) = permutations();
    let low = (packed & 16383) as u16;
    let middle = ((packed >> 14) & 16383) as u16;
    let ai = a
        .iter()
        .position(|v| *v == low)
        .expect("permutation is bijective") as u32;
    let bi = b
        .iter()
        .position(|v| *v == middle)
        .expect("permutation is bijective") as u32;
    (
        ai | (bi << 14) | (packed & 0xf0000000),
        c[low as usize] ^ middle,
    )
}
fn find_assignment<'a>(body: &'a [S], name: &str) -> Option<&'a E> {
    for s in body {
        match s {
            S::Assign(t, v) if t.len() == 1 && ident(&t[0], name) => return v.first(),
            S::Do(b) => {
                if let Some(e) = find_assignment(b, name) {
                    return Some(e);
                }
            }
            S::If(a, b) => {
                for (_, b) in a {
                    if let Some(e) = find_assignment(b, name) {
                        return Some(e);
                    }
                }
                if let Some(e) = find_assignment(b, name) {
                    return Some(e);
                }
            }
            _ => {}
        }
    }
    None
}
fn contains_ident(e: &E, name: &str) -> bool {
    match e {
        E::Id(n) => n == name,
        E::Index(a, b) | E::Bin(_, a, b) => contains_ident(a, name) || contains_ident(b, name),
        E::Unary(_, a) => contains_ident(a, name),
        E::Call(t, a) => contains_ident(t, name) || a.iter().any(|v| contains_ident(v, name)),
        _ => false,
    }
}
fn select(body: &[S], ctx: &mut Lift<'_>) -> Result<Vec<S>, String> {
    let mut result = vec![];
    for s in body {
        if let S::If(arms, otherwise) = s {
            if arms.iter().all(|(c, _)| contains_ident(c, "op")) {
                let mut selected = otherwise;
                for (c, b) in arms {
                    if ctx
                        .eval(c)?
                        .truth()
                        .ok_or("selector condition unresolved")?
                    {
                        selected = b;
                        break;
                    }
                }
                result.extend(select(selected, ctx)?);
                continue;
            }
        }
        result.push(s.clone());
    }
    Ok(result)
}

type PoolRecords = (BTreeMap<u32, Vec<u8>>, BTreeMap<u32, u64>);
fn lift(
    vm: &DecodedVm,
    state: &State,
    family: &Family,
    id: u32,
) -> Result<(TraceRow, PoolRecords), String> {
    let mut ctx = Lift::new(vm, state);
    let selector = ctx.eval(&family.selector)?.int()?;
    ctx.locals.insert("op".to_owned(), V::Int(selector));
    let selected = select(std::slice::from_ref(&family.tree), &mut ctx)?;
    for s in &selected {
        if let S::Do(body) = s {
            if ctx.entry(body)? {
                continue;
            }
        }
        ctx.statements(std::slice::from_ref(s))?;
        if ctx.control.is_some() {
            break;
        }
    }
    if !ctx.witness_writes.is_empty() && ctx.witness_writes != [(10, 0), (13, 1)] {
        return Err("permutation witness pair is incomplete or reordered".to_owned());
    }
    let mut successors = vec![];
    match ctx.control.take() {
        Some(Control::Return) => ctx.out.push(Instruction::Return { values: vec![] }),
        Some(Control::Next(next)) => {
            ctx.out.push(Instruction::Jump { target: next.pc });
            successors.push((EdgeLabel::Next, next));
        }
        Some(Control::Branch(c, yes, no)) => {
            ctx.out.push(Instruction::Branch {
                condition: c,
                then_target: yes.pc,
                else_target: no.pc,
            });
            successors.push((EdgeLabel::True, yes));
            successors.push((EdgeLabel::False, no));
        }
        None => {
            let mut next = ctx.state.clone();
            next.pc = usize::try_from(ctx.locals.get("ip").ok_or("missing next ip")?.int()?)
                .map_err(|_| "invalid next ip")?;
            next.key = ctx.locals.get("st").ok_or("missing next key")?.u32()?;
            if next.pc <= state.pc || next.pc > state.pc + 257 {
                return Err("unsupported non-transition PC adjustment".to_owned());
            }
            word(vm, next.pc)?;
            ctx.max_offset = ctx.max_offset.max(next.pc - state.pc - 1);
            ctx.out.push(Instruction::Jump { target: next.pc });
            successors.push((EdgeLabel::Next, next));
        }
    }
    let end_pc = state
        .pc
        .checked_add(ctx.max_offset + 1)
        .ok_or("instruction extent overflow")?;
    for at in state.pc..end_pc {
        word(vm, at)?;
    }
    Ok((
        TraceRow {
            state: state.clone(),
            family: id,
            selector,
            end_pc,
            instructions: ctx.out,
            successors,
        },
        (ctx.strings, ctx.numbers),
    ))
}

pub fn analyze(vm: &DecodedVm) -> Result<Analysis, String> {
    if vm.raw_words.len() != 562 || vm.decoded_words.len() != 563 {
        return Err("Base85 analysis requires the certified 562-word layout".to_owned());
    }
    let models = families(&vm.source_text)?;
    let root = vm
        .prototypes
        .iter()
        .find(|p| p.word == vm.entry_prototype)
        .ok_or("missing root descriptor")?;
    word(vm, root.entry_pc)?;
    if root.fixed_parameter_mode || !root.parameter_operands.is_empty() {
        return Err(
            "fixed-parameter root binding is not supported by this profile adapter".to_owned(),
        );
    }
    let initial = State {
        pc: root.entry_pc,
        key: root.initial_decode_state.wrapping_add(62760),
        bank: root.bank_base,
        token: root.dispatch_token,
        salt: root.prototype_salt,
        phase: 0,
        window: 0,
        bank_end: 0,
        pool_key: INITIAL_K1,
    };
    let mut queue = VecDeque::from([initial]);
    let mut visited = HashSet::new();
    let mut trace = vec![];
    let (mut strings, mut numbers) = (BTreeMap::new(), BTreeMap::new());
    while let Some(state) = queue.pop_front() {
        if !visited.insert(state.clone()) {
            continue;
        }
        if visited.len() > MAX_STATES {
            return Err("Base85 CFG visited-state budget exceeded (512)".to_owned());
        }
        let id = *vm
            .dispatch_families
            .get(&state.token)
            .ok_or_else(|| format!("unknown dispatcher token {}", state.token))?;
        if !matches!(id, 3080 | 1952 | 1408) {
            return Err(format!(
                "unsupported reached dispatcher family {id} at word {}",
                state.pc
            ));
        }
        let family = models
            .get(&id)
            .ok_or_else(|| format!("missing dispatcher family {id}"))?;
        let (row, (state_strings, state_numbers)) = lift(vm, &state, family, id)
            .map_err(|e| format!("{PROFILE}: failed at word {} family {id}: {e}", state.pc))?;
        for (reference, value) in state_strings {
            if let Some(old) = strings.insert(reference, value.clone()) {
                if old != value {
                    return Err(format!("string key disagreement for reference {reference}"));
                }
            }
        }
        for (reference, value) in state_numbers {
            if let Some(old) = numbers.insert(reference, value) {
                if old != value {
                    return Err(format!("number key disagreement for reference {reference}"));
                }
            }
        }
        for (_, next) in &row.successors {
            queue.push_back(next.clone());
        }
        trace.push(row);
    }
    let mut blocks = BTreeMap::new();
    for row in &trace {
        let successors = row
            .successors
            .iter()
            .map(|(label, s)| Successor {
                label: label.clone(),
                target_pc: Some(s.pc),
                state: None,
            })
            .collect::<Vec<_>>();
        let block = BasicBlock {
            start_pc: row.state.pc,
            end_pc: row.end_pc,
            handler_family: row.family,
            entry_states: vec![],
            instructions: row.instructions.clone(),
            successors,
        };
        if let Some(previous) = blocks.insert(row.state.pc, block.clone()) {
            if previous != block {
                return Err(format!("normalized states disagree on full instruction semantics at word {}\nfirst={previous:#?}\nother={block:#?}",row.state.pc));
            }
        }
    }
    let reachable_pcs = blocks.keys().copied().collect();
    let program = LiftedProgram {
        blocks,
        entry_points: vec![root.entry_pc],
        reachable_pcs,
        state_variants: visited.len(),
        root_entry: Some(root.entry_pc),
        prototype_entries: BTreeMap::from([(root.word, root.entry_pc)]),
        parameters: BTreeMap::from([(root.entry_pc, root.fixed_parameter_count.map(usize::from))]),
    };
    let raw_program = program;
    let program = compact_data(&specialize_control(&raw_program)?)?;
    Ok(Analysis {
        program,
        raw_program,
        trace,
        strings,
        numbers,
    })
}

fn data_reads(op: &Operand, out: &mut std::collections::BTreeSet<u16>) {
    match op {
        Operand::Register(r) => {
            out.insert(r.physical_slot);
        }
        Operand::Expression(e) => match e.as_ref() {
            ValueExpression::Unary { value, .. }
            | ValueExpression::PermutationParity { value, .. } => data_reads(value, out),
            ValueExpression::Binary { left, right, .. } => {
                data_reads(left, out);
                data_reads(right, out);
            }
            ValueExpression::Index { table, index } => {
                data_reads(table, out);
                data_reads(index, out);
            }
        },
        _ => {}
    }
}
fn condition_reads(c: &Condition) -> std::collections::BTreeSet<u16> {
    let mut r = std::collections::BTreeSet::new();
    match c {
        Condition::Truthy(v) | Condition::Falsey(v) => data_reads(v, &mut r),
        Condition::Compare { left, right, .. } => {
            data_reads(left, &mut r);
            data_reads(right, &mut r);
        }
    }
    r
}
fn instruction_data(i: &Instruction) -> (Option<u16>, std::collections::BTreeSet<u16>) {
    let mut reads = std::collections::BTreeSet::new();
    let dst = match i {
        Instruction::LoadConst { dst, .. }
        | Instruction::NewTable { dst }
        | Instruction::NewPackedTable { dst } => Some(dst.physical_slot),
        Instruction::Move { dst, src } | Instruction::Unary { dst, src, .. } => {
            data_reads(src, &mut reads);
            Some(dst.physical_slot)
        }
        Instruction::Binary {
            dst, left, right, ..
        } => {
            data_reads(left, &mut reads);
            data_reads(right, &mut reads);
            Some(dst.physical_slot)
        }
        Instruction::GetTable { dst, table, index } => {
            data_reads(table, &mut reads);
            data_reads(index, &mut reads);
            Some(dst.physical_slot)
        }
        Instruction::SetTable {
            table,
            index,
            value,
        } => {
            data_reads(table, &mut reads);
            data_reads(index, &mut reads);
            data_reads(value, &mut reads);
            None
        }
        Instruction::Call {
            dst,
            function,
            args,
            ..
        } => {
            data_reads(function, &mut reads);
            for a in args {
                data_reads(a, &mut reads);
            }
            dst.as_ref().map(|r| r.physical_slot)
        }
        Instruction::Branch { condition, .. } | Instruction::Compare { condition } => {
            reads = condition_reads(condition);
            None
        }
        Instruction::Return { values } => {
            for a in values {
                data_reads(a, &mut reads);
            }
            None
        }
        Instruction::Jump { .. } | Instruction::Nop => None,
        _ => {
            return (None, std::collections::BTreeSet::from([u16::MAX]));
        }
    };
    (dst, reads)
}
fn pure_control_definition(i: &Instruction) -> bool {
    matches!(
        i,
        Instruction::LoadConst {
            value: Constant::Integer(_),
            ..
        } | Instruction::Move { .. }
            | Instruction::Binary {
                op: BinaryOp::Add | BinaryOp::Sub,
                ..
            }
    )
}
fn fact_operand(o: &Operand, f: &BTreeMap<u16, i64>) -> Option<i64> {
    match o {
        Operand::Constant(Constant::Integer(i)) => Some(*i),
        Operand::Register(r) => f.get(&r.physical_slot).copied(),
        _ => None,
    }
}
fn fact_condition(c: &Condition, f: &BTreeMap<u16, i64>) -> Option<bool> {
    match c {
        Condition::Compare { op, left, right } => {
            let a = fact_operand(left, f)?;
            let b = fact_operand(right, f)?;
            Some(match op {
                BinaryOp::Equal => a == b,
                BinaryOp::NotEqual => a != b,
                BinaryOp::Less => a < b,
                BinaryOp::LessEqual => a <= b,
                BinaryOp::Greater => a > b,
                BinaryOp::GreaterEqual => a >= b,
                _ => return None,
            })
        }
        Condition::Truthy(o) => {
            fact_operand(o, f)?;
            Some(true)
        }
        Condition::Falsey(o) => {
            fact_operand(o, f)?;
            Some(false)
        }
    }
}

/// Path-sensitive abstract interpretation of nonescaping integer control facts.
/// No calls, table reads/writes, source functions, or virtual instructions are
/// executed. Only already-lifted integer SSA facts are propagated. Each removed
/// operation has a closed constant dependency set and cannot escape to data.
pub(crate) fn specialize_control(program: &LiftedProgram) -> Result<LiftedProgram, String> {
    use std::collections::BTreeSet;
    let mut candidates = BTreeSet::new();
    for b in program.blocks.values() {
        for i in &b.instructions {
            if pure_control_definition(i) {
                if let Some(dst) = instruction_data(i).0 {
                    candidates.insert(dst);
                }
            }
        }
    }
    loop {
        let previous = candidates.clone();
        for b in program.blocks.values() {
            for i in &b.instructions {
                let (dst, reads) = instruction_data(i);
                if let Some(dst) = dst {
                    if !pure_control_definition(i) || !reads.is_subset(&candidates) {
                        candidates.remove(&dst);
                    }
                }
                let allowed = dst.is_some_and(|d| candidates.contains(&d))
                    && pure_control_definition(i)
                    || matches!(i, Instruction::Branch { .. } | Instruction::Compare { .. })
                        && reads.is_subset(&candidates);
                if !allowed {
                    for r in reads {
                        candidates.remove(&r);
                    }
                }
            }
        }
        if previous == candidates {
            break;
        }
    }
    if candidates.is_empty() {
        return Ok(program.clone());
    }
    type Facts = BTreeMap<u16, i64>;
    fn process(
        program: &LiftedProgram,
        pc: usize,
        mut facts: Facts,
        candidates: &BTreeSet<u16>,
    ) -> Result<(Vec<Instruction>, Vec<(EdgeLabel, usize, Facts)>), String> {
        let block = program.blocks.get(&pc).ok_or("missing control block")?;
        let mut output = vec![];
        let mut chosen = None;
        for i in &block.instructions {
            let (dst, _) = instruction_data(i);
            if let Some(dst) = dst.filter(|d| candidates.contains(d)) {
                let value = match i {
                    Instruction::LoadConst {
                        value: Constant::Integer(v),
                        ..
                    } => Some(*v),
                    Instruction::Move { src, .. } => fact_operand(src, &facts),
                    Instruction::Binary {
                        op, left, right, ..
                    } => {
                        let a = fact_operand(left, &facts);
                        let b = fact_operand(right, &facts);
                        match (a, b, op) {
                            (Some(a), Some(b), BinaryOp::Add) => a.checked_add(b),
                            (Some(a), Some(b), BinaryOp::Sub) => a.checked_sub(b),
                            _ => None,
                        }
                    }
                    _ => None,
                }
                .ok_or("control fact read before initialization or arithmetic overflow")?;
                if value.unsigned_abs() > (1u64 << 52) {
                    return Err("control fact exceeds exact integer analysis budget".to_owned());
                }
                facts.insert(dst, value);
                continue;
            }
            if let Instruction::Branch {
                condition,
                then_target,
                else_target,
            } = i
            {
                if condition_reads(condition).is_subset(candidates) {
                    chosen = Some(
                        if fact_condition(condition, &facts).ok_or("unproved control predicate")? {
                            *then_target
                        } else {
                            *else_target
                        },
                    );
                    continue;
                }
            }
            if !matches!(i, Instruction::Jump { .. }) {
                output.push(i.clone());
            }
        }
        let edges = if let Some(target) = chosen {
            vec![(EdgeLabel::Next, target, facts)]
        } else {
            block
                .successors
                .iter()
                .filter_map(|s| s.target_pc.map(|pc| (s.label.clone(), pc, facts.clone())))
                .collect()
        };
        Ok((output, edges))
    }
    fn resolve(
        program: &LiftedProgram,
        mut pc: usize,
        mut facts: Facts,
        candidates: &BTreeSet<u16>,
    ) -> Result<(usize, Facts), String> {
        let mut seen = BTreeSet::new();
        for _ in 0..512 {
            if !seen.insert((pc, facts.clone())) {
                return Err("nonterminating pure control region".to_owned());
            }
            let (body, edges) = process(program, pc, facts.clone(), candidates)?;
            if !body.is_empty() {
                return Ok((pc, facts));
            }
            let [(_, next, f)] = edges.as_slice() else {
                return Err("ambiguous silent control region".to_owned());
            };
            pc = *next;
            facts = f.clone();
        }
        Err("pure control resolution exceeded 512 steps".to_owned())
    }
    let root = program
        .root_entry
        .ok_or("missing root for control specialization")?;
    let mut queue = VecDeque::from([(root, Facts::new())]);
    let mut seen = BTreeSet::new();
    let mut blocks = BTreeMap::new();
    while let Some((pc, facts)) = queue.pop_front() {
        if !seen.insert((pc, facts.clone())) {
            continue;
        }
        if seen.len() > 512 {
            return Err("control specialization state budget exceeded".to_owned());
        }
        let (mut body, edges) = process(program, pc, facts, &candidates)?;
        let mut resolved = vec![];
        for (label, next, facts) in edges {
            let (next, facts) = resolve(program, next, facts, &candidates)?;
            queue.push_back((next, facts));
            resolved.push((label, next));
        }
        if let Some(Instruction::Branch {
            then_target,
            else_target,
            ..
        }) = body.last_mut()
        {
            *then_target = resolved
                .iter()
                .find(|(l, _)| *l == EdgeLabel::True)
                .ok_or("missing true control edge")?
                .1;
            *else_target = resolved
                .iter()
                .find(|(l, _)| *l == EdgeLabel::False)
                .ok_or("missing false control edge")?
                .1;
        } else if let [(_, target)] = resolved.as_slice() {
            body.push(Instruction::Jump { target: *target });
        }
        let mut block = program.blocks[&pc].clone();
        block.instructions = body;
        block.successors = resolved
            .iter()
            .map(|(label, target)| Successor {
                label: label.clone(),
                target_pc: Some(*target),
                state: None,
            })
            .collect();
        if let Some(old) = blocks.insert(pc, block.clone()) {
            if old != block {
                return Err(format!(
                    "control contexts require distinct output blocks at source word {pc}"
                ));
            }
        }
    }
    let mut output = program.clone();
    output.reachable_pcs = blocks.keys().copied().collect();
    output.blocks = blocks;
    Ok(output)
}

/// Remove only dead pure definitions. Calls and potentially effectful table
/// reads/writes retain their exact order. Reading the first element of the
/// adapter's private packed call packet is pure; user table reads are not.
pub(crate) fn compact_data(program: &LiftedProgram) -> Result<LiftedProgram, String> {
    use std::collections::BTreeSet;
    fn private_projection(block: &BasicBlock, index: usize) -> bool {
        if index == 0 {
            return false;
        }
        matches!((&block.instructions[index-1],&block.instructions[index]),
            (Instruction::Call{dst:Some(packet),result_count:Some(1),..},Instruction::GetTable{table:Operand::Register(t),index:Operand::Constant(Constant::Integer(1)),..})if packet==t)
    }
    let pure = |block: &BasicBlock, index: usize| {
        matches!(
            block.instructions[index],
            Instruction::Move { .. }
                | Instruction::LoadConst { .. }
                | Instruction::NewTable { .. }
                | Instruction::NewPackedTable { .. }
        ) || private_projection(block, index)
    };
    let mut incoming: BTreeMap<usize, BTreeSet<u16>> = program
        .blocks
        .keys()
        .map(|pc| (*pc, BTreeSet::new()))
        .collect();
    let mut converged = false;
    for _ in 0..1024 {
        let mut changed = false;
        for (pc, block) in program.blocks.iter().rev() {
            let mut live = BTreeSet::new();
            for successor in &block.successors {
                if let Some(target) = successor.target_pc {
                    live.extend(
                        incoming
                            .get(&target)
                            .ok_or("missing liveness successor")?
                            .iter()
                            .copied(),
                    );
                }
            }
            for (index, i) in block.instructions.iter().enumerate().rev() {
                let (dst, reads) = instruction_data(i);
                if dst.is_some_and(|d| !live.contains(&d)) && pure(block, index) {
                    continue;
                }
                if let Some(dst) = dst {
                    live.remove(&dst);
                }
                live.extend(reads);
            }
            if incoming.get(pc) != Some(&live) {
                incoming.insert(*pc, live);
                changed = true;
            }
        }
        if !changed {
            converged = true;
            break;
        }
    }
    if !converged {
        return Err("data liveness budget exceeded".to_owned());
    }
    let mut output = program.clone();
    for (pc, block) in &program.blocks {
        let mut live = BTreeSet::new();
        for s in &block.successors {
            if let Some(target) = s.target_pc {
                live.extend(incoming[&target].iter().copied());
            }
        }
        let mut kept = vec![];
        for (index, i) in block.instructions.iter().enumerate().rev() {
            let (dst, reads) = instruction_data(i);
            if dst.is_some_and(|d| !live.contains(&d)) && pure(block, index) {
                continue;
            }
            let mut instruction = i.clone();
            if let Instruction::Call {
                dst: Some(d),
                function,
                args,
                result_count,
            } = i
            {
                if !live.contains(&d.physical_slot) {
                    instruction = Instruction::Call {
                        dst: None,
                        function: function.clone(),
                        args: args.clone(),
                        result_count: *result_count,
                    };
                }
            }
            if let Some(dst) = dst {
                live.remove(&dst);
            }
            live.extend(reads);
            kept.push(instruction);
        }
        kept.reverse();
        output
            .blocks
            .get_mut(pc)
            .ok_or("missing compacted block")?
            .instructions = kept;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn int(n: i64) -> Operand {
        Operand::Constant(Constant::Integer(n))
    }
    fn block(
        pc: usize,
        instructions: Vec<Instruction>,
        edges: &[(EdgeLabel, usize)],
    ) -> BasicBlock {
        BasicBlock {
            start_pc: pc,
            end_pc: pc + 1,
            handler_family: 0,
            entry_states: vec![],
            instructions,
            successors: edges
                .iter()
                .map(|(label, pc)| Successor {
                    label: label.clone(),
                    target_pc: Some(*pc),
                    state: None,
                })
                .collect(),
        }
    }
    fn program(blocks: Vec<BasicBlock>) -> LiftedProgram {
        let blocks = blocks
            .into_iter()
            .map(|b| (b.start_pc, b))
            .collect::<BTreeMap<_, _>>();
        LiftedProgram {
            reachable_pcs: blocks.keys().copied().collect(),
            blocks,
            entry_points: vec![1],
            root_entry: Some(1),
            ..LiftedProgram::default()
        }
    }

    #[test]
    fn synthetic_control_counter_is_specialized_without_losing_the_call() {
        let p = program(vec![
            block(
                1,
                vec![
                    Instruction::LoadConst {
                        dst: reg(1),
                        value: Constant::Integer(0),
                    },
                    Instruction::Jump { target: 2 },
                ],
                &[(EdgeLabel::Next, 2)],
            ),
            block(
                2,
                vec![Instruction::Branch {
                    condition: Condition::Compare {
                        op: BinaryOp::Less,
                        left: rop(1),
                        right: int(3),
                    },
                    then_target: 3,
                    else_target: 4,
                }],
                &[(EdgeLabel::True, 3), (EdgeLabel::False, 4)],
            ),
            block(
                3,
                vec![
                    Instruction::Binary {
                        op: BinaryOp::Add,
                        dst: reg(1),
                        left: rop(1),
                        right: int(1),
                    },
                    Instruction::Jump { target: 2 },
                ],
                &[(EdgeLabel::Next, 2)],
            ),
            block(
                4,
                vec![
                    Instruction::Call {
                        dst: None,
                        function: Operand::Global(vec![b"observe".to_vec()]),
                        args: vec![],
                        result_count: Some(1),
                    },
                    Instruction::Return { values: vec![] },
                ],
                &[],
            ),
        ]);
        let out = specialize_control(&p).unwrap();
        assert_eq!(out.blocks.len(), 2);
        assert_eq!(
            out.blocks[&1].instructions,
            vec![Instruction::Jump { target: 4 }]
        );
        assert_eq!(out.blocks[&4], p.blocks[&4]);
    }
    #[test]
    fn uninitialized_or_nonterminating_control_is_never_erased() {
        let read = program(vec![block(
            1,
            vec![
                Instruction::Binary {
                    op: BinaryOp::Add,
                    dst: reg(1),
                    left: rop(1),
                    right: int(1),
                },
                Instruction::Jump { target: 1 },
            ],
            &[(EdgeLabel::Next, 1)],
        )]);
        assert!(specialize_control(&read)
            .unwrap_err()
            .contains("before initialization"));
        let looping = program(vec![
            block(
                1,
                vec![
                    Instruction::LoadConst {
                        dst: reg(1),
                        value: Constant::Integer(0),
                    },
                    Instruction::Jump { target: 2 },
                ],
                &[(EdgeLabel::Next, 2)],
            ),
            block(
                2,
                vec![
                    Instruction::Binary {
                        op: BinaryOp::Add,
                        dst: reg(1),
                        left: rop(1),
                        right: int(1),
                    },
                    Instruction::Jump { target: 2 },
                ],
                &[(EdgeLabel::Next, 2)],
            ),
        ]);
        assert!(specialize_control(&looping).unwrap_err().contains("512"));
    }
    #[test]
    fn control_values_that_escape_to_calls_remain_program_data() {
        let p = program(vec![block(
            1,
            vec![
                Instruction::LoadConst {
                    dst: reg(1),
                    value: Constant::Integer(7),
                },
                Instruction::Call {
                    dst: None,
                    function: Operand::Global(vec![b"observe".to_vec()]),
                    args: vec![rop(1)],
                    result_count: Some(1),
                },
                Instruction::Return { values: vec![] },
            ],
            &[],
        )]);
        assert_eq!(specialize_control(&p).unwrap(), p);
    }
    #[test]
    fn dead_table_reads_and_calls_remain_observable() {
        let p = program(vec![block(
            1,
            vec![
                Instruction::GetTable {
                    dst: reg(1),
                    table: Operand::Environment,
                    index: Operand::Constant(Constant::String(b"probe".to_vec())),
                },
                Instruction::Call {
                    dst: None,
                    function: rop(1),
                    args: vec![],
                    result_count: Some(1),
                },
                Instruction::GetTable {
                    dst: reg(2),
                    table: Operand::Environment,
                    index: Operand::Constant(Constant::String(b"effectfulIndex".to_vec())),
                },
                Instruction::Return { values: vec![] },
            ],
            &[],
        )]);
        assert_eq!(compact_data(&p).unwrap(), p);
    }
    #[test]
    fn int32_permutation_equality_inverts_positive_and_negative_cases() {
        let (a, b, c) = permutations();
        for value in [
            0u32, 1, 16383, 16384, 0x12345678, 0x7fffffff, 0x80000000, 0xffffffff,
        ] {
            let low = a[(value & 16383) as usize] as u32;
            let mid = b[((value >> 14) & 16383) as usize] as u32;
            let packed = low | (mid << 14) | (value & 0xf0000000);
            let (decoded, kv) = inverse_equality(packed);
            assert_eq!(decoded, value);
            assert_eq!(kv, c[low as usize] ^ mid as u16);
        }
        for i in 0..16384 {
            let expected =
                (b[i] as u32 * 4 + ((i as u32 * 17 + 8644) % 16384) * 2 + ((a[i] as u32 >> 9) & 1))
                    % 65536;
            assert_eq!((c[a[i] as usize] as u32 + 65536 - expected) % 65536, 53112);
        }
    }
    #[test]
    fn both_bank_directions_preserve_two_distinct_scratch_values() {
        let vm = crate::decode_source(include_str!("../tests/fixtures/base85-rotor.lua")).unwrap();
        for bank in [15, 36, 57] {
            let state = State {
                pc: 199,
                key: 123,
                bank,
                token: 48352,
                salt: 31541,
                phase: 17,
                window: 21,
                bank_end: 57,
                pool_key: 135918109,
            };
            let ctx = Lift::new(&vm, &state);
            let old = [
                slot(&vm, bank as usize + 1).unwrap(),
                slot(&vm, bank as usize + 2).unwrap(),
                slot(&vm, bank as usize + 3).unwrap(),
                slot(&vm, bank as usize + 4).unwrap(),
            ];
            for forward in [false, true] {
                let target = ctx
                    .transition(0, 0, 48352 - 17 - 53112, 9, forward, 0)
                    .unwrap();
                let next = Lift::new(&vm, &target);
                let u1 = slot(&vm, target.bank as usize + 3).unwrap();
                let u2 = slot(&vm, target.bank as usize + 4).unwrap();
                assert_ne!(
                    next.program_register(u1).unwrap(),
                    next.program_register(u2).unwrap()
                );
                assert_eq!(
                    ctx.program_register(old[2]).unwrap(),
                    next.program_register(u1).unwrap()
                );
                assert_eq!(
                    ctx.program_register(old[3]).unwrap(),
                    next.program_register(u2).unwrap()
                );
            }
        }
    }
}
