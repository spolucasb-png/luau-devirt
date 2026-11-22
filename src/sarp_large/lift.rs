//! Static handler-to-IR lifting. Runtime values remain operands, never Rust
//! calls or simulated program tables. Wrapper arithmetic is separately proved.
use super::model::{contains, Family, Model, E, S};
use super::{read32, slot, word, Initialization, INITIAL_K1, SALT};
use crate::ir::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub(super) const SMA: u32 = 608916103;
pub(super) const SMB: u32 = 1981805674;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Fact {
    Integer(i64),
    Boolean(bool),
    Nil,
    NonInt32,
    Text(u64, u8),
    StringLength(usize),
    String,
    Table,
    Function,
    BooleanUnknown,
    Number,
}

fn text_fact(bytes: &[u8]) -> Fact {
    if bytes.len() > 8 {
        return Fact::StringLength(bytes.len());
    }
    let mut word = [0u8; 8];
    word[..bytes.len()].copy_from_slice(bytes);
    Fact::Text(u64::from_le_bytes(word), bytes.len() as u8)
}

fn fact_truth(fact: &Fact) -> Option<bool> {
    match fact {
        Fact::Nil => Some(false),
        Fact::Boolean(v) => Some(*v),
        Fact::Integer(_)
        | Fact::NonInt32
        | Fact::Text(_, _)
        | Fact::String
        | Fact::StringLength(_)
        | Fact::Table
        | Fact::Function
        | Fact::Number => Some(true),
        Fact::BooleanUnknown => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct State {
    pub prototype: usize,
    pub pc: usize,
    pub key: u32,
    pub bank: u32,
    pub token: u32,
    pub salt: u16,
    pub phase: u32,
    pub window: u32,
    pub bank_end: u32,
    pub pool_key: u32,
    pub facts: BTreeMap<u16, Fact>,
    /// Slots definitely written on this invocation. Cached AF frames may retain
    /// arbitrary old values, so child slots are not assumed initially nil.
    pub initialized: BTreeSet<u16>,
}

#[derive(Clone, Debug)]
pub struct TraceRow {
    pub state: State,
    pub family: u32,
    pub selector: i64,
    pub end_pc: usize,
    pub instructions: Vec<Instruction>,
    pub successors: Vec<(EdgeLabel, State)>,
    pub helpers: Vec<u32>,
    pub operations: Vec<(String, u32)>,
    pub temps: usize,
    pub hash_proofs: Vec<super::control::HashProof>,
    pub factories: Vec<FactoryRequest>,
}

#[derive(Clone, Debug)]
pub struct FactoryRequest {
    pub prototype: Prototype,
    pub mask: u32,
    pub code_start: usize,
    pub code_length: usize,
    pub captured: Vec<Operand>,
}
pub(super) type Strings = BTreeMap<u32, (u32, Arc<Vec<u8>>)>;
pub(super) type Numbers = BTreeMap<u32, (u32, u64)>;

#[derive(Clone, Debug)]
pub(super) enum V {
    Int(i64),
    Bool(bool),
    Nil,
    String(Arc<Vec<u8>>),
    Data(Operand),
    FrameCopy(u16),
    Witness(u8),
    Helper(u32),
}

impl V {
    pub fn int(&self) -> Result<i64, String> {
        match self {
            Self::Int(v) => Ok(*v),
            _ => Err(format!("unproved metadata integer {self:?}")),
        }
    }
    pub fn truth(&self) -> Option<bool> {
        match self {
            Self::Int(_) | Self::String(_) | Self::Helper(_) => Some(true),
            Self::Bool(v) => Some(*v),
            Self::Nil => Some(false),
            Self::Data(Operand::Constant(Constant::Nil)) => Some(false),
            Self::Data(Operand::Constant(Constant::Boolean(v))) => Some(*v),
            Self::Data(Operand::Constant(_)) => Some(true),
            _ => None,
        }
    }
}

pub(super) enum Control {
    Next(State),
    Branch(Condition, State, State),
    Return(Vec<Operand>),
    ReturnPacked(Operand),
}

enum Place {
    Local(String),
    Frame { raw: u16, metadata: bool },
    Table { table: Operand, index: Operand },
}

pub(super) fn reg(slot: u16) -> Register {
    Register {
        physical_slot: slot,
    }
}
pub(super) fn r(slot: u16) -> Operand {
    Operand::Register(reg(slot))
}
pub(super) fn id(expr: &E, name: &str) -> bool {
    matches!(expr, E::Id(n) if n == name)
}
fn index(expr: &E, name: &str) -> bool {
    matches!(expr,E::Index(t,_) if id(t,name))
}

pub(super) fn binary(name: &str) -> Result<BinaryOp, String> {
    Ok(match name {
        "+" => BinaryOp::Add,
        "-" => BinaryOp::Sub,
        "*" => BinaryOp::Mul,
        "/" => BinaryOp::Div,
        "//" => BinaryOp::FloorDiv,
        "%" => BinaryOp::Mod,
        "^" => BinaryOp::Pow,
        "==" => BinaryOp::Equal,
        "~=" => BinaryOp::NotEqual,
        "<" => BinaryOp::Less,
        "<=" => BinaryOp::LessEqual,
        ">" => BinaryOp::Greater,
        ">=" => BinaryOp::GreaterEqual,
        "and" => BinaryOp::And,
        "or" => BinaryOp::Or,
        _ => return Err(format!("unsupported source operator {name}")),
    })
}

pub(super) struct Context<'a> {
    pub vm: &'a DecodedVm,
    pub model: &'a Model,
    pub family: &'a Family,
    pub initialization: &'a Initialization,
    pub state: State,
    pub locals: BTreeMap<String, V>,
    pub output: Vec<Instruction>,
    pub control: Option<Control>,
    pub helper_ids: Vec<u32>,
    pub operations: Vec<(String, u32)>,
    pub hash_proofs: Vec<super::control::HashProof>,
    pub factories: Vec<FactoryRequest>,
    pub max_offset: usize,
    pub transfer_tail: Vec<S>,
    pub temp_next: u32,
    pub temp_start: u32,
    pub strings: &'a mut Strings,
    pub numbers: &'a mut Numbers,
    steps: usize,
    literal_bytes: usize,
    witnesses: Vec<u8>,
}

impl<'a> Context<'a> {
    pub fn new(
        vm: &'a DecodedVm,
        model: &'a Model,
        family: &'a Family,
        initialization: &'a Initialization,
        state: &State,
        temp_start: u32,
        strings: &'a mut Strings,
        numbers: &'a mut Numbers,
    ) -> Result<Self, String> {
        let wi = word(vm, state.pc)?;
        Ok(Self {
            vm,
            model,
            family,
            initialization,
            state: state.clone(),
            locals: BTreeMap::from([
                ("ip".to_owned(), V::Int(state.pc as i64)),
                ("st".to_owned(), V::Int(state.key as i64)),
                ("rb".to_owned(), V::Int(state.bank as i64)),
                ("ps".to_owned(), V::Int(state.salt as i64)),
                ("sh".to_owned(), V::Int(state.token as i64)),
                ("stop".to_owned(), V::Int(0)),
                ("exit".to_owned(), V::Int(0)),
                ("_rbs".to_owned(), V::Int(state.window as i64)),
                ("K0".to_owned(), V::Int(vm.master_key as i64)),
                ("K1".to_owned(), V::Int(state.pool_key as i64)),
                ("_wi".to_owned(), V::Int(wi as i64)),
                ("_wx".to_owned(), V::Int((wi ^ state.salt as u32) as i64)),
            ]),
            output: vec![],
            control: None,
            helper_ids: vec![],
            operations: vec![],
            hash_proofs: vec![],
            factories: vec![],
            max_offset: 0,
            transfer_tail: vec![],
            temp_next: temp_start,
            temp_start,
            strings,
            numbers,
            steps: 0,
            literal_bytes: 0,
            witnesses: vec![],
        })
    }
    fn step(&mut self) -> Result<(), String> {
        self.steps += 1;
        if self.steps > 20000 {
            return Err("per-instruction source-analysis budget exceeded".to_owned());
        }
        Ok(())
    }
    pub fn temp(&mut self) -> Result<u16, String> {
        if self.temp_next - self.temp_start >= 256 {
            return Err("instruction temporary budget exceeded".to_owned());
        }
        let result =
            u16::try_from(self.temp_next).map_err(|_| "IR temporary register budget exceeded")?;
        self.temp_next += 1;
        Ok(result)
    }
    pub fn operand(&mut self, value: &V) -> Result<Operand, String> {
        Ok(match value {
            V::Int(v) => Operand::Constant(Constant::Integer(*v)),
            V::Bool(v) => Operand::Constant(Constant::Boolean(*v)),
            V::Nil => Operand::Constant(Constant::Nil),
            V::String(v) => {
                self.literal_bytes = self
                    .literal_bytes
                    .checked_add(v.len())
                    .ok_or("literal byte overflow")?;
                if self.literal_bytes > 8 * 1024 * 1024 {
                    return Err("instruction literal allocation budget exceeded".to_owned());
                }
                Operand::Constant(Constant::String(v.as_ref().clone()))
            }
            V::Data(v) => v.clone(),
            _ => return Err("wrapper metadata cannot become a program operand".to_owned()),
        })
    }
    pub fn fact(&self, operand: &Operand) -> Option<Fact> {
        match operand {
            Operand::Register(r) => self.state.facts.get(&r.physical_slot).cloned(),
            Operand::Constant(Constant::Integer(v)) => Some(Fact::Integer(*v)),
            Operand::Constant(Constant::U32(v)) => Some(Fact::Integer(*v as i64)),
            Operand::Constant(Constant::Boolean(v)) => Some(Fact::Boolean(*v)),
            Operand::Constant(Constant::Nil) => Some(Fact::Nil),
            Operand::Constant(Constant::String(value)) => Some(text_fact(value)),
            Operand::Constant(Constant::NumberBits(bits)) => {
                let value = f64::from_bits(*bits);
                if value.is_finite()
                    && value.fract() == 0.0
                    && value >= i32::MIN as f64
                    && value <= i32::MAX as f64
                {
                    Some(Fact::Integer(value as i64))
                } else if !value.is_finite()
                    || value.fract() != 0.0
                    || value < i32::MIN as f64
                    || value > i32::MAX as f64
                {
                    Some(Fact::NonInt32)
                } else {
                    None
                }
            }
            Operand::Expression(expr) => match expr.as_ref() {
                ValueExpression::Unary {
                    op: UnaryOp::Not,
                    value,
                } => Some(match self.fact(value).as_ref().and_then(fact_truth) {
                    Some(v) => Fact::Boolean(!v),
                    None => Fact::BooleanUnknown,
                }),
                ValueExpression::Unary {
                    op: UnaryOp::TypeOf,
                    value,
                } => {
                    let name = match self.fact(value)? {
                        Fact::Nil => b"nil".as_slice(),
                        Fact::Boolean(_) | Fact::BooleanUnknown => b"boolean".as_slice(),
                        Fact::Integer(_) | Fact::NonInt32 | Fact::Number => b"number".as_slice(),
                        Fact::Text(_, _) | Fact::StringLength(_) | Fact::String => {
                            b"string".as_slice()
                        }
                        Fact::Table => b"table".as_slice(),
                        Fact::Function => b"function".as_slice(),
                    };
                    Some(text_fact(name))
                }
                ValueExpression::Unary {
                    op: UnaryOp::Length,
                    value,
                } => match self.fact(value) {
                    Some(Fact::Text(_, length)) => Some(Fact::Integer(length as i64)),
                    Some(Fact::StringLength(length)) => {
                        i64::try_from(length).ok().map(Fact::Integer)
                    }
                    _ => None,
                },
                ValueExpression::Unary {
                    op: UnaryOp::Negate,
                    value,
                } => match self.fact(value) {
                    Some(Fact::Integer(v)) => v.checked_neg().map(Fact::Integer),
                    _ => None,
                },
                ValueExpression::Binary { op, left, right } => {
                    let a = self.fact(left);
                    let b = self.fact(right);
                    if matches!(op, BinaryOp::And | BinaryOp::Or) {
                        let a = a?;
                        let truth = fact_truth(&a)?;
                        return if *op == BinaryOp::And && truth || *op == BinaryOp::Or && !truth {
                            b
                        } else {
                            Some(a)
                        };
                    }
                    if matches!(op, BinaryOp::Equal | BinaryOp::NotEqual) {
                        if let (Some(a), Some(b)) = (&a, &b) {
                            if matches!(
                                a,
                                Fact::Integer(_) | Fact::Boolean(_) | Fact::Nil | Fact::Text(_, _)
                            ) && matches!(
                                b,
                                Fact::Integer(_) | Fact::Boolean(_) | Fact::Nil | Fact::Text(_, _)
                            ) {
                                return Some(Fact::Boolean(if *op == BinaryOp::Equal {
                                    a == b
                                } else {
                                    a != b
                                }));
                            }
                        }
                    }
                    let (Some(Fact::Integer(a)), Some(Fact::Integer(b))) = (a, b) else {
                        return if matches!(
                            op,
                            BinaryOp::Equal
                                | BinaryOp::NotEqual
                                | BinaryOp::Less
                                | BinaryOp::LessEqual
                                | BinaryOp::Greater
                                | BinaryOp::GreaterEqual
                        ) {
                            Some(Fact::BooleanUnknown)
                        } else {
                            None
                        };
                    };
                    let arithmetic = match op {
                        BinaryOp::Add => a.checked_add(b),
                        BinaryOp::Sub => a.checked_sub(b),
                        BinaryOp::Mul => a.checked_mul(b),
                        _ => None,
                    };
                    arithmetic
                        .filter(|v| v.unsigned_abs() < 1u64 << 53)
                        .map(Fact::Integer)
                        .or_else(|| {
                            let value = match op {
                                BinaryOp::Equal => a == b,
                                BinaryOp::NotEqual => a != b,
                                BinaryOp::Less => a < b,
                                BinaryOp::LessEqual => a <= b,
                                BinaryOp::Greater => a > b,
                                BinaryOp::GreaterEqual => a >= b,
                                _ => return None,
                            };
                            Some(Fact::Boolean(value))
                        })
                }
                _ => None,
            },
            _ => None,
        }
    }
    pub fn u32(&self, value: &V) -> Result<u32, String> {
        let integer = match value {
            V::Int(v) => *v,
            V::Data(o) => match self.fact(o) {
                Some(Fact::Integer(v)) => v,
                fact => {
                    return Err(format!(
                        "bit operation requires a proved integer: operand={o:?}, fact={fact:?}"
                    ))
                }
            },
            _ => return Err("bit operation received nonnumeric metadata".to_owned()),
        };
        if !(-(1i64 << 32)..=(1i64 << 32)).contains(&integer) {
            return Err("bitwise exact-integer conversion budget exceeded".to_owned());
        }
        Ok(integer as u32)
    }
    pub fn put(&mut self, dst: u16, value: Operand) {
        self.state.initialized.insert(dst);
        if let Some(fact) = self.fact(&value) {
            self.state.facts.insert(dst, fact);
        } else {
            self.state.facts.remove(&dst);
        }
        let instruction = match value {
            Operand::Constant(value) => Instruction::LoadConst {
                dst: reg(dst),
                value,
            },
            Operand::Expression(expr) => match *expr {
                ValueExpression::Binary { op, left, right } => Instruction::Binary {
                    dst: reg(dst),
                    op,
                    left,
                    right,
                },
                ValueExpression::Unary { op, value } => Instruction::Unary {
                    dst: reg(dst),
                    op,
                    src: value,
                },
                other => Instruction::Move {
                    dst: reg(dst),
                    src: Operand::Expression(Box::new(other)),
                },
            },
            value => Instruction::Move {
                dst: reg(dst),
                src: value,
            },
        };
        self.output.push(instruction);
    }
    fn snapshot(&mut self, value: V) -> Result<V, String> {
        if matches!(
            value,
            V::Data(Operand::Register(_) | Operand::Expression(_))
        ) {
            let dst = self.temp()?;
            let operand = self.operand(&value)?;
            self.put(dst, operand);
            Ok(V::Data(r(dst)))
        } else {
            Ok(value)
        }
    }
    pub fn program_slot(&self, raw: u16) -> Result<u16, String> {
        let controls = [15usize, 3, 7, 9, 17, 18, 33, 21, 6, 29, 24, 2, 23, 5, 12];
        for index in controls {
            if raw == slot(self.vm, index)? {
                return Err(format!("program data accesses private control slot {raw}"));
            }
        }
        let roles = [
            slot(self.vm, self.state.bank as usize + 5)?,
            slot(self.vm, self.state.bank as usize + 6)?,
            slot(self.vm, self.state.bank as usize + 9)?,
            slot(self.vm, self.state.bank as usize + 10)?,
        ];
        if roles
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != 4
        {
            return Err("noninjective rotor/data roles".to_owned());
        }
        if raw == roles[2] {
            return Ok(72);
        }
        if raw == roles[3] {
            return Ok(73);
        }
        if raw == roles[0] || raw == roles[1] {
            return Err("program data touches a rotor/phase cell".to_owned());
        }
        Ok(raw)
    }
    fn read_program_slot(&self, raw: u16) -> Result<u16, String> {
        let logical = self.program_slot(raw)?;
        if !self.state.initialized.contains(&logical) {
            return Err(format!("program reads slot {logical} before an invocation-local write; AF cached-frame contents are unsupported"));
        }
        Ok(logical)
    }
    pub fn eval(&mut self, expression: &E) -> Result<V, String> {
        self.step()?;
        match expression {
            E::Int(v) => Ok(V::Int(*v)),
            E::Number(v) => Ok(V::Data(Operand::Constant(Constant::NumberBits(*v)))),
            E::Str(v) => Ok(V::String(Arc::new(v.clone()))),
            E::Id(name) => match name.as_str() {
                "true" => Ok(V::Bool(true)),
                "false" => Ok(V::Bool(false)),
                "nil" => Ok(V::Nil),
                "_sma" => Ok(V::Int(SMA as i64)),
                "_smb" => Ok(V::Int(SMB as i64)),
                "_pxs" | "_pys" | "_u1s" | "_u2s" => {
                    let offset = match name.as_str() {
                        "_pxs" => 5,
                        "_pys" => 6,
                        "_u1s" => 9,
                        _ => 10,
                    };
                    Ok(V::Int(
                        slot(self.vm, self.state.bank as usize + offset)? as i64
                    ))
                }
                _ => self
                    .locals
                    .get(name)
                    .cloned()
                    .ok_or_else(|| format!("unresolved source identifier {name}")),
            },
            E::Unary(op, value) => {
                let value = self.eval(value)?;
                if op == "not" {
                    if let Some(truth) = value.truth() {
                        return Ok(V::Bool(!truth));
                    }
                }
                if op == "-" {
                    if let V::Int(v) = value {
                        let v = v
                            .checked_neg()
                            .filter(|v| v.unsigned_abs() < 1u64 << 53)
                            .ok_or("metadata negation outside exact domain")?;
                        return Ok(V::Int(v));
                    }
                }
                let op = match op.as_str() {
                    "not" => UnaryOp::Not,
                    "-" => UnaryOp::Negate,
                    "#" => UnaryOp::Length,
                    _ => return Err("unsupported unary".to_owned()),
                };
                let value = self.operand(&value)?;
                Ok(V::Data(Operand::Expression(Box::new(
                    ValueExpression::Unary { op, value },
                ))))
            }
            E::Bin(op, left, right) => {
                if op == "or" && (index(left, "SM") || index(left, "NM")) {
                    let E::Index(cache, key) = left.as_ref() else {
                        return Err("invalid cache access".to_owned());
                    };
                    let E::Call(function, args) = right.as_ref() else {
                        return Err("unproved cache fallback".to_owned());
                    };
                    if !id(function, "U")
                        || args.len() != 9
                        || **key != args[1]
                        || !id(&args[5], "F")
                        || !id(&args[8], "K1")
                    {
                        return Err("constant cache key/frame/pool proof failed".to_owned());
                    }
                    let checkpoint = (
                        self.output.len(),
                        self.temp_next,
                        self.factories.len(),
                        self.operations.len(),
                        self.state.clone(),
                    );
                    let operation_value = self.eval(&args[2])?;
                    if (
                        self.output.len(),
                        self.temp_next,
                        self.factories.len(),
                        self.operations.len(),
                        self.state.clone(),
                    ) != checkpoint
                    {
                        return Err(
                            "constant cache operation expression has observable effects".to_owned()
                        );
                    }
                    let operation = self.u32(&operation_value)? ^ 43554;
                    if !(id(cache, "SM") && (29713..35726).contains(&operation)
                        || id(cache, "NM") && operation < 26166 && operation != 11715)
                    {
                        return Err("constant cache channel mismatch".to_owned());
                    }
                    return self.eval(right);
                }
                let a = self.eval(left)?;
                if matches!(op.as_str(), "and" | "or") {
                    if let Some(truth) = a.truth() {
                        return if op == "and" && truth || op == "or" && !truth {
                            self.eval(right)
                        } else {
                            Ok(a)
                        };
                    }
                }
                let checkpoint = (
                    self.output.len(),
                    self.temp_next,
                    self.factories.len(),
                    self.operations.len(),
                    self.state.clone(),
                );
                let b = self.eval(right)?;
                if matches!(op.as_str(), "and" | "or")
                    && a.truth().is_none()
                    && (
                        self.output.len(),
                        self.temp_next,
                        self.factories.len(),
                        self.operations.len(),
                        self.state.clone(),
                    ) != checkpoint
                {
                    return Err(
                        "unknown short-circuit RHS has eager observable evaluations".to_owned()
                    );
                }
                if let (V::Int(a), V::Int(b)) = (&a, &b) {
                    let arithmetic = match op.as_str() {
                        "+" => a.checked_add(*b),
                        "-" => a.checked_sub(*b),
                        "*" => a.checked_mul(*b),
                        "%" if *b > 0 => Some(a.rem_euclid(*b)),
                        "//" if *b > 0 => Some(a.div_euclid(*b)),
                        _ => None,
                    };
                    if let Some(value) = arithmetic {
                        if value.unsigned_abs() >= 1u64 << 53 {
                            return Err(
                                "metadata arithmetic outside exact integer domain".to_owned()
                            );
                        }
                        return Ok(V::Int(value));
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
                    if let Some(value) = cmp {
                        return Ok(V::Bool(value));
                    }
                }
                if matches!(op.as_str(), "==" | "~=")
                    && matches!(
                        (&a, &b),
                        (V::Nil, V::Int(_) | V::Helper(_)) | (V::Int(_) | V::Helper(_), V::Nil)
                    )
                {
                    return Ok(V::Bool(op == "~="));
                }
                let left = self.operand(&a)?;
                let right = self.operand(&b)?;
                if op == ".." {
                    let dst = self.temp()?;
                    self.output.push(Instruction::Concat {
                        dst: reg(dst),
                        values: vec![left, right],
                    });
                    return Ok(V::Data(r(dst)));
                }
                Ok(V::Data(Operand::Expression(Box::new(
                    ValueExpression::Binary {
                        op: binary(op)?,
                        left,
                        right,
                    },
                ))))
            }
            E::Table(fields) => self.table(fields),
            E::Index(table, key) => {
                if id(table, "_w") || id(table, "W") {
                    let at = usize::try_from(self.eval(key)?.int()?)
                        .map_err(|_| "negative working word index")?;
                    let offset = at
                        .checked_sub(self.state.pc)
                        .filter(|n| *n <= 256)
                        .ok_or("instruction operand span outside budget")?;
                    self.max_offset = self.max_offset.max(offset);
                    return Ok(V::Int(word(self.vm, at)? as i64));
                }
                if id(table, "_rm") {
                    let at = usize::try_from(self.eval(key)?.int()?)
                        .map_err(|_| "negative map index")?;
                    return Ok(V::Int(slot(self.vm, at)? as i64));
                }
                if id(table, "_kb") {
                    let at = usize::try_from(self.eval(key)?.int()?)
                        .map_err(|_| "negative bias index")?;
                    return Ok(V::Int(
                        *self
                            .vm
                            .immediate_biases
                            .get(at)
                            .filter(|_| at > 0)
                            .ok_or("invalid bias index")? as i64,
                    ));
                }
                if ["_cm", "_cm2", "_cm3"].iter().any(|n| id(table, n)) {
                    let at = usize::try_from(self.eval(key)?.int()?)
                        .map_err(|_| "negative control table index")?;
                    let values = if id(table, "_cm2") {
                        &self.model.cm2
                    } else if id(table, "_cm3") {
                        &self.model.cm3
                    } else {
                        &self.family.metadata
                    };
                    return Ok(V::Int(
                        *values
                            .get(at.checked_sub(1).ok_or("zero control table index")?)
                            .ok_or("control table index out of bounds")?
                            as i64,
                    ));
                }
                if id(table, "_rt") {
                    let v = self.eval(key)?;
                    let key = self.u32(&v)?;
                    return Ok(self
                        .vm
                        .dispatch_families
                        .get(&key)
                        .map(|v| V::Int(*v as i64))
                        .unwrap_or(V::Nil));
                }
                if id(table, "_hc") {
                    let value = self.eval(key)?;
                    let key = self.u32(&value)?;
                    let id = (key & 4095) ^ ((self.state.pool_key >> 12) & 4095) ^ 2056;
                    return Ok(if self.model.helpers.contains_key(&id) {
                        V::Helper(id)
                    } else {
                        V::Nil
                    });
                }
                if id(table, "F") {
                    let raw = u16::try_from(self.eval(key)?.int()?)
                        .map_err(|_| "invalid physical frame index")?;
                    if matches!(key.as_ref(),E::Index(t,_)if id(t,"_cm")||id(t,"_cm2")||id(t,"_cm3"))
                    {
                        return Ok(V::FrameCopy(raw));
                    }
                    if self.state.window == 0
                        && (raw == slot(self.vm, self.state.bank as usize + 5)?
                            || raw == slot(self.vm, self.state.bank as usize + 6)?)
                    {
                        return Ok(V::Data(Operand::Argument(0)));
                    }
                    return Ok(V::Data(r(self.read_program_slot(raw)?)));
                }
                let table = if id(table, "G") {
                    Operand::Environment
                } else {
                    let value = self.eval(table)?;
                    self.operand(&value)?
                };
                let key = self.eval(key)?;
                let key = self.operand(&key)?;
                let dst = self.temp()?;
                self.output.push(Instruction::GetTable {
                    dst: reg(dst),
                    table,
                    index: key,
                });
                Ok(V::Data(r(dst)))
            }
            E::Call(target, args) => self.call(target, args, false),
        }
    }
    fn table(&mut self, fields: &[(Option<E>, E)]) -> Result<V, String> {
        let packed = fields.iter().find_map(|(k, v)| {
            if matches!(k,Some(E::Str(k))if k==b"n") {
                if let E::Int(n) = v {
                    Some(*n)
                } else {
                    None
                }
            } else {
                None
            }
        });
        let list_count = fields.iter().filter(|(key, _)| key.is_none()).count();
        let dst = self.temp()?;
        if let Some(n) = packed {
            if n < 0 || n as usize != list_count || fields.len() != list_count + 1 {
                return Err("unproved explicit packed constructor count".to_owned());
            }
            self.output
                .push(Instruction::NewPackedTable { dst: reg(dst) });
        } else {
            self.output.push(Instruction::NewTable { dst: reg(dst) });
        }
        self.state.facts.insert(dst, Fact::Table);
        let mut next = 1i64;
        for (key, value) in fields {
            if packed.is_some() && matches!(key,Some(E::Str(k))if k==b"n") {
                continue;
            }
            let key = if let Some(key) = key {
                let value = self.eval(key)?;
                self.operand(&value)?
            } else {
                let key = Operand::Constant(Constant::Integer(next));
                next += 1;
                key
            };
            let value = self.eval(value)?;
            let value = self.operand(&value)?;
            if packed.is_some() {
                self.output.push(Instruction::PushPacked {
                    table: r(dst),
                    value,
                });
            } else {
                self.output.push(Instruction::SetTable {
                    table: r(dst),
                    index: key,
                    value,
                });
            }
        }
        Ok(V::Data(r(dst)))
    }
    pub fn call(&mut self, target: &E, args: &[E], discard: bool) -> Result<V, String> {
        if let E::Id(name) = target {
            if [
                "bxor", "band", "bor", "lshift", "rshift", "lrot", "rrot", "bswap", "bext", "clz",
                "crz",
            ]
            .contains(&name.as_str())
            {
                let mut values = vec![];
                for a in args {
                    let value = self.eval(a)?;
                    values.push(self.u32(&value)?);
                }
                let value = match name.as_str() {
                    "bxor" => values.iter().fold(0, |a, b| a ^ b),
                    "band" => values.iter().fold(u32::MAX, |a, b| a & b),
                    "bor" => values.iter().fold(0, |a, b| a | b),
                    "lshift" if values.len() == 2 => values[0].checked_shl(values[1]).unwrap_or(0),
                    "rshift" if values.len() == 2 => values[0].checked_shr(values[1]).unwrap_or(0),
                    "lrot" if values.len() == 2 => values[0].rotate_left(values[1]),
                    "rrot" if values.len() == 2 => values[0].rotate_right(values[1]),
                    "bswap" if values.len() == 1 => values[0].swap_bytes(),
                    "clz" if values.len() == 1 => values[0].leading_zeros(),
                    "crz" if values.len() == 1 => values[0].trailing_zeros(),
                    "bext"
                        if values.len() == 3
                            && values[2] > 0
                            && values[1].checked_add(values[2]).is_some_and(|n| n <= 32) =>
                    {
                        values[0]
                            .checked_shr(values[1])
                            .ok_or("invalid extraction shift")?
                            & if values[2] == 32 {
                                u32::MAX
                            } else {
                                (1u32 << values[2]) - 1
                            }
                    }
                    _ => return Err(format!("unsupported bit operation/arity {name}")),
                };
                return Ok(V::Int(value as i64));
            }
            if name == "r16" {
                let [table, offset] = args else {
                    return Err("invalid permutation read".to_owned());
                };
                let at = usize::try_from(self.eval(offset)?.int()?)
                    .map_err(|_| "negative permutation byte")?;
                if at % 2 != 0 {
                    return Err("unaligned permutation read".to_owned());
                }
                let values = if id(table, "BL_A") {
                    &self.initialization.permutation_a
                } else if id(table, "BL_B") {
                    &self.initialization.permutation_b
                } else if id(table, "BL_C") {
                    &self.initialization.permutation_c
                } else {
                    return Err("unproved permutation table".to_owned());
                };
                return Ok(V::Int(
                    *values.get(at / 2).ok_or("permutation read out of bounds")? as i64,
                ));
            }
            if name == "U" {
                return self.decode_constant(args);
            }
            if name == "_mo" || name == "_mo2" {
                return self.operation(name, args);
            }
            if name == "tcreate" {
                for a in args {
                    let v = self.eval(a)?;
                    v.int()?;
                }
                let dst = self.temp()?;
                self.output.push(Instruction::NewTable { dst: reg(dst) });
                self.state.facts.insert(dst, Fact::Table);
                return Ok(V::Data(r(dst)));
            }
            if name == "tpack" {
                if let [E::Call(function, values)] = args {
                    return self.program_call(function, values, None, false);
                }
                let dst = self.temp()?;
                self.output
                    .push(Instruction::NewPackedTable { dst: reg(dst) });
                for a in args {
                    let v = self.eval(a)?;
                    let value = self.operand(&v)?;
                    self.output.push(Instruction::PushPacked {
                        table: r(dst),
                        value,
                    });
                }
                self.state.facts.insert(dst, Fact::Table);
                return Ok(V::Data(r(dst)));
            }
            if name == "tunpack" {
                return Err(
                    "packed tuple expansion requires explicit call/return context".to_owned(),
                );
            }
            if name == "tFn" {
                let [arg] = args else {
                    return Err("type helper arity".to_owned());
                };
                let value = self.eval(arg)?;
                let value = self.operand(&value)?;
                return Ok(V::Data(Operand::Expression(Box::new(
                    ValueExpression::Unary {
                        op: UnaryOp::TypeOf,
                        value,
                    },
                ))));
            }
        }
        self.program_call(target, args, Some(1), discard)
    }
    fn program_call(
        &mut self,
        target: &E,
        args: &[E],
        count: Option<usize>,
        discard: bool,
    ) -> Result<V, String> {
        let function = self.eval(target)?;
        if let V::Helper(id) = function {
            if id == 19 {
                return self.factory(args);
            }
            return Err(format!(
                "unsupported scalar helper {id}; prototype/capture analysis required"
            ));
        }
        let function = self.snapshot(function)?;
        let function = self.operand(&function)?;
        let mut values = vec![];
        let mut packed = None;
        for (index, arg) in args.iter().enumerate() {
            if let E::Call(function, arguments) = arg {
                if id(function, "tunpack") {
                    if index + 1 != args.len() {
                        return Err("non-final packed argument expansion is unsupported".to_owned());
                    }
                    let [table, E::Int(1), E::Index(same, key)] = arguments.as_slice() else {
                        return Err("packed expansion requires explicit table,1,table.n".to_owned());
                    };
                    if table != same.as_ref() || !matches!(key.as_ref(),E::Str(name)if name==b"n") {
                        return Err(
                            "packed expansion count does not reference the same table".to_owned()
                        );
                    }
                    let value = self.eval(table)?;
                    let value = self.snapshot(value)?;
                    packed = Some(self.operand(&value)?);
                    continue;
                }
                if index + 1 == args.len() {
                    return Err(
                        "last call argument requires proved scalar or packed expansion".to_owned(),
                    );
                }
            }
            let value = self.eval(arg)?;
            let value = self.snapshot(value)?;
            values.push(self.operand(&value)?);
        }
        let packet = if discard {
            None
        } else {
            Some(reg(self.temp()?))
        };
        if let Some(arguments) = packed {
            self.output.push(Instruction::CallWithPackedArgs {
                dst: packet.clone(),
                function,
                prefix: values,
                arguments,
                result_count: count,
            });
        } else {
            self.output.push(Instruction::Call {
                dst: packet.clone(),
                function,
                args: values,
                result_count: count,
            });
        }
        let Some(packet) = packet else {
            return Ok(V::Nil);
        };
        let packet = packet.physical_slot;
        self.state.facts.insert(packet, Fact::Table);
        if count == Some(1) {
            let dst = self.temp()?;
            self.output.push(Instruction::GetTable {
                dst: reg(dst),
                table: r(packet),
                index: Operand::Constant(Constant::Integer(1)),
            });
            self.state.facts.remove(&dst);
            Ok(V::Data(r(dst)))
        } else {
            Ok(V::Data(r(packet)))
        }
    }

    fn tuple(&mut self, values: &[E], count: usize) -> Result<Vec<V>, String> {
        if values.len() == 1 && count > 1 {
            if let E::Call(function, args) = &values[0] {
                let packet = self.program_call(function, args, Some(count), false)?;
                let packet = self.operand(&packet)?;
                let mut result = vec![];
                for index in 1..=count {
                    let dst = self.temp()?;
                    self.output.push(Instruction::GetTable {
                        dst: reg(dst),
                        table: packet.clone(),
                        index: Operand::Constant(Constant::Integer(index as i64)),
                    });
                    self.state.facts.remove(&dst);
                    result.push(V::Data(r(dst)));
                }
                return Ok(result);
            }
        }
        if values.len() != count {
            return Err("tuple requires a source-proved final call projection".to_owned());
        }
        let mut result = vec![];
        for value in values {
            let value = self.eval(value)?;
            result.push(if count > 1 {
                self.snapshot(value)?
            } else {
                value
            });
        }
        Ok(result)
    }

    fn factory(&mut self, args: &[E]) -> Result<V, String> {
        let helper = self
            .model
            .helpers
            .get(&19)
            .ok_or("missing closure helper")?;
        if helper.params.len() != args.len() {
            return Err("closure helper arity mismatch".to_owned());
        }
        let bound = helper
            .params
            .iter()
            .zip(args)
            .map(|(n, v)| (n.as_str(), v))
            .collect::<BTreeMap<_, _>>();
        for (name, expected) in [("_F", "F"), ("_rb", "rb"), ("_st", "st")] {
            if !bound.get(name).is_some_and(|value| id(value, expected)) {
                return Err(format!("closure helper context mismatch {name}"));
            }
        }
        for (name, value) in &bound {
            if name.starts_with("_hd") && !matches!(value, E::Int(_)) {
                return Err("effectful/unknown closure filler argument".to_owned());
            }
        }
        let tk = self.eval(bound.get("_tk").ok_or("closure helper token missing")?)?;
        let tk = self.u32(&tk)?;
        let mask = self.state.pool_key ^ SALT;
        // SALT^3893==42823 proves make's checked branch: _mp=0, no
        // descriptor shift or unproved fallback code length is used.
        if SALT ^ 3893 != 42823 {
            return Err("factory witness cookie proof failed".to_owned());
        }
        let p = (tk ^ 266632) as usize;
        let prototype = super::prototype(self.vm, p, mask)?;
        let code_start = (word(self.vm, p + 6)? ^ 3330028092 ^ self.vm.master_key ^ mask) as usize;
        let code_length = (word(self.vm, p + 1)? ^ 322097349 ^ self.vm.master_key ^ mask) as usize;
        if code_length > self.vm.decoded_range.1 - self.vm.decoded_range.0 + 1
            || code_start.checked_add(code_length).is_none_or(|end| {
                code_length > 0
                    && (code_start < self.vm.decoded_range.0 || end > self.vm.decoded_range.1 + 1)
            })
        {
            return Err("factory lazy-code extent is outside working data".to_owned());
        }
        let mut captured = vec![];
        for capture in &prototype.captures {
            let raw = slot(
                self.vm,
                self.state.bank as usize + capture.source_operand as usize,
            )?;
            let source = self.read_program_slot(raw)?;
            let value = self.snapshot(V::Data(r(source)))?;
            captured.push(self.operand(&value)?);
        }
        let dst = self.temp()?;
        self.output.push(Instruction::NewClosure {
            dst: reg(dst),
            prototype_word: p,
            captures: captured.clone(),
        });
        self.state.facts.insert(dst, Fact::Function);
        self.factories.push(FactoryRequest {
            prototype,
            mask,
            code_start,
            code_length,
            captured,
        });
        Ok(V::Data(r(dst)))
    }
    fn decode_constant(&mut self, args: &[E]) -> Result<V, String> {
        if args.len() != 9 {
            return Err("U argument count differs from source".to_owned());
        }
        for index in [0, 3, 4, 6, 7] {
            if !matches!(args[index], E::Int(_)) {
                return Err("effectful or unknown U filler argument".to_owned());
            }
        }
        let operation = self.eval(&args[2])?;
        let operation = self.u32(&operation)? ^ 43554;
        if operation == 11715 {
            return Err("witness U result requires an explicit pair".to_owned());
        }
        if (35726..=53722).contains(&operation) {
            let key = self.eval(&args[8])?;
            let key = self.u32(&key)?;
            if (key ^ 48556) != 764977 {
                return Err("nonzero branch salt displacement".to_owned());
            }
            return Ok(V::Int(SALT as i64));
        }
        let reference = self.eval(&args[1])?;
        let reference = self.u32(&reference)?;
        let key = self.eval(&args[8])?;
        let key = self.u32(&key)?;
        if !id(&args[5], "F") || key != self.state.pool_key {
            return Err("constant pool frame/key proof failed".to_owned());
        }
        if operation < 26166 {
            let index = reference ^ 1433946;
            if index == 0 || index > 65536 {
                return Err("numeric reference outside budget".to_owned());
            }
            let base = (word(self.vm, 1)? ^ 2939307859 ^ self.vm.master_key) as usize;
            let offset = base
                .checked_add(
                    (index as usize - 1)
                        .checked_mul(8)
                        .ok_or("numeric extent overflow")?,
                )
                .ok_or("numeric offset overflow")?;
            let extra = key ^ SALT;
            let lo = read32(&self.vm.payload, offset)?
                ^ 1770095756u32.wrapping_add(index.wrapping_mul(388145))
                ^ self.vm.master_key
                ^ extra;
            let hi = read32(
                &self.vm.payload,
                offset
                    .checked_add(4)
                    .ok_or("numeric upper offset overflow")?,
            )? ^ 2239952298u32.wrapping_add(index.wrapping_mul(280443))
                ^ self.vm.master_key.rotate_left(21)
                ^ extra.rotate_left(25);
            let bits = (hi as u64) << 32 | lo as u64;
            if let Some((old_key, old)) = self.numbers.insert(reference, (key, bits)) {
                if old_key != key || old != bits {
                    return Err("inconsistent numeric constant keys".to_owned());
                }
            }
            return Ok(V::Data(Operand::Constant(Constant::NumberBits(bits))));
        }
        if (29713..35726).contains(&operation) {
            if let Some((old_key, value)) = self.strings.get(&reference) {
                if *old_key != key {
                    return Err("inconsistent string constant keys".to_owned());
                }
                return Ok(V::String(value.clone()));
            }
            let offset = (reference ^ 628995) as usize;
            let seed = read32(&self.vm.payload, offset)? ^ 3148276683;
            let length = (read32(
                &self.vm.payload,
                offset.checked_add(4).ok_or("string header overflow")?,
            )? ^ 1529521387
                ^ seed) as usize;
            let start = offset.checked_add(8).ok_or("string data offset overflow")?;
            let end = start
                .checked_add(length)
                .filter(|e| *e <= self.vm.payload.len())
                .ok_or("string record out of bounds")?;
            if length > super::MAX_PAYLOAD {
                return Err("string allocation budget exceeded".to_owned());
            }
            let mut value = Vec::with_capacity(length);
            let mut stream = seed ^ self.vm.master_key ^ key ^ SALT;
            for index in 0..length / 4 {
                stream = stream.wrapping_mul(7971).wrapping_add(744303207);
                value.extend_from_slice(
                    &(read32(&self.vm.payload, start + index * 4)? ^ stream).to_le_bytes(),
                );
            }
            for at in start + length / 4 * 4..end {
                stream = stream.wrapping_mul(7971).wrapping_add(744303207);
                value.push(self.vm.payload[at] ^ stream as u8);
            }
            let value = Arc::new(value);
            self.strings.insert(reference, (key, value.clone()));
            return Ok(V::String(value));
        }
        Err(format!("unsupported U operation {operation}"))
    }
    fn operation(&mut self, name: &str, args: &[E]) -> Result<V, String> {
        if !(2..=4).contains(&args.len()) {
            return Err("operation helper argument tuple outside arity".to_owned());
        }
        let mut values = vec![];
        for arg in args {
            values.push(self.eval(arg)?);
        }
        let key = self.u32(&values[0])?;
        let salt = self.u32(&values[1])?;
        let lookup = if name == "_mo" {
            &self.initialization.permutation_a
        } else {
            &self.initialization.permutation_b
        };
        let multiplier = if name == "_mo" { 121 } else { 49 };
        let mask = if name == "_mo" { 936 } else { 454 };
        let operation = key
            ^ salt
            ^ (lookup[((self.state.pool_key ^ salt.wrapping_mul(multiplier)) & 16383) as usize]
                as u32
                & 2047)
            ^ mask;
        self.operations.push((name.to_owned(), operation));
        let old = self.locals.clone();
        for (i, name) in ["k", "s", "a", "b"].iter().enumerate() {
            self.locals
                .insert((*name).to_owned(), values.get(i).cloned().unwrap_or(V::Nil));
        }
        self.locals
            .insert("_op".to_owned(), V::Int(operation as i64));
        let tree = if name == "_mo" {
            self.model.mo.clone()
        } else {
            self.model.mo2.clone()
        };
        let body = select(&tree, self, "_op")?;
        let body = body
            .into_iter()
            .filter(|s| !matches!(s,S::Local(names,_)if names==&["_op".to_owned()]))
            .collect::<Vec<_>>();
        let value = self.operation_return(&body);
        self.locals = old;
        value
    }
    fn operation_return(&mut self, body: &[S]) -> Result<V, String> {
        match body {
            [S::Return(values)] if values.len() == 1 => self.eval(&values[0]),
            [S::If(arms, other)] if arms.len() == 1 => {
                let boolean = |body: &[S]| -> Option<bool> {
                    if let [S::Return(values)] = body {
                        if let [E::Bin(op, a, b)] = values.as_slice() {
                            if op == "==" {
                                if let (E::Int(a), E::Int(b)) = (a.as_ref(), b.as_ref()) {
                                    return Some(a == b);
                                }
                            }
                        }
                    }
                    None
                };
                if let (Some(yes), Some(no)) = (boolean(&arms[0].1), boolean(other)) {
                    if yes == no {
                        return Err("equal boolean arms could conceal predicate effects".to_owned());
                    }
                    let condition = self.eval(&arms[0].0)?;
                    let value = self.operand(&condition)?;
                    let expression = if yes {
                        Operand::Expression(Box::new(ValueExpression::Unary {
                            op: UnaryOp::Not,
                            value: Operand::Expression(Box::new(ValueExpression::Unary {
                                op: UnaryOp::Not,
                                value,
                            })),
                        }))
                    } else {
                        Operand::Expression(Box::new(ValueExpression::Unary {
                            op: UnaryOp::Not,
                            value,
                        }))
                    };
                    return Ok(V::Data(expression));
                }
                Err("unsupported runtime operation-helper control flow".to_owned())
            }
            [S::Assign(targets, values), S::Return(returns)]
                if targets.len() == 1
                    && values.len() == 1
                    && returns.len() == 1
                    && id(&returns[0], "nil") =>
            {
                let value = self.eval(&values[0])?;
                self.assign(&targets[0], value)?;
                Ok(V::Nil)
            }
            _ => Err(format!("unsupported operation-helper body {body:?}")),
        }
    }
    fn prepare(&mut self, target: &E) -> Result<Place, String> {
        if let E::Id(name) = target {
            return Ok(Place::Local(name.clone()));
        }
        let E::Index(table, key) = target else {
            return Err("unsupported assignment target".to_owned());
        };
        if id(table, "F") {
            let raw =
                u16::try_from(self.eval(key)?.int()?).map_err(|_| "invalid frame destination")?;
            let metadata =
                matches!(key.as_ref(),E::Index(t,_)if id(t,"_cm")||id(t,"_cm2")||id(t,"_cm3"));
            return Ok(Place::Frame { raw, metadata });
        }
        // Lua prepares indexed assignment addresses before evaluating RHS.
        // Snapshot each address so RHS calls cannot change its binding.
        let table = self.eval(table)?;
        let table = self.snapshot(table)?;
        let table = self.operand(&table)?;
        let key = self.eval(key)?;
        let key = self.snapshot(key)?;
        let index = self.operand(&key)?;
        Ok(Place::Table { table, index })
    }
    fn assign(&mut self, target: &E, value: V) -> Result<(), String> {
        let place = self.prepare(target)?;
        self.store(place, value)
    }
    fn store(&mut self, place: Place, value: V) -> Result<(), String> {
        if let Place::Local(name) = place {
            if ["stop", "exit"].contains(&name.as_str()) && value.int()? != 0 {
                return Err("unsupported dispatcher stop/exit write".to_owned());
            }
            self.locals.insert(name, value);
            return Ok(());
        }
        if let Place::Frame { raw, metadata } = place {
            if metadata {
                match value {
                    V::FrameCopy(source) if source == raw => return Ok(()),
                    V::Witness(which) if raw == slot(self.vm, if which == 0 { 6 } else { 7 })? => {
                        self.witnesses.push(which);
                        return Ok(());
                    }
                    _ => return Err(format!("unproved private frame write {raw}")),
                }
            }
            let dst = self.program_slot(raw)?;
            let value = self.operand(&value)?;
            self.put(dst, value);
            return Ok(());
        }
        let Place::Table { table, index } = place else {
            return Err("invalid prepared assignment".to_owned());
        };
        let value = self.operand(&value)?;
        self.output.push(Instruction::SetTable {
            table,
            index,
            value,
        });
        Ok(())
    }
    pub fn statements(&mut self, body: &[S]) -> Result<(), String> {
        for (index, statement) in body.iter().enumerate() {
            self.step()?;
            if self.control.is_some() {
                if matches!(
                    self.control,
                    Some(Control::Next(_) | Control::Branch(_, _, _))
                ) {
                    self.transfer_tail.extend_from_slice(&body[index..]);
                }
                break;
            }
            match statement {
                S::Do(body) => {
                    if self.type_salt_block(body)? {
                        continue;
                    }
                    if self.entry(body)? {
                        continue;
                    }
                    let old = self.locals.clone();
                    self.statements(body)?;
                    let changes = self.locals.clone();
                    self.locals = old;
                    for (name, value) in changes {
                        if self.locals.contains_key(&name) {
                            self.locals.insert(name, value);
                        }
                    }
                }
                S::Local(names, values) => {
                    if names.len() == 2 && values.len() == 1 {
                        if let E::Call(function, args) = &values[0] {
                            if id(function, "U") && args.len() == 9 {
                                let operation = self.eval(&args[2])?;
                                if self.u32(&operation)? ^ 43554 == 11715 {
                                    for index in [0, 3, 4, 6, 7] {
                                        if !matches!(args[index], E::Int(_)) {
                                            return Err("effectful witness filler".to_owned());
                                        }
                                    }
                                    let key = self.eval(&args[8])?;
                                    if self.u32(&key)? ^ 1040301 != 293041 {
                                        return Err("nonzero witness displacement".to_owned());
                                    }
                                    self.locals.insert(names[0].clone(), V::Witness(0));
                                    self.locals.insert(names[1].clone(), V::Witness(1));
                                    continue;
                                }
                            }
                        }
                    }
                    let output = if values.is_empty() {
                        vec![]
                    } else {
                        self.tuple(values, names.len())?
                    };
                    let output = output
                        .into_iter()
                        .map(|value| self.snapshot(value))
                        .collect::<Result<Vec<_>, _>>()?;
                    for (index, name) in names.iter().enumerate() {
                        self.locals
                            .insert(name.clone(), output.get(index).cloned().unwrap_or(V::Nil));
                    }
                }
                S::Assign(targets, values) => {
                    if self.transition_call(targets, values)? {
                        continue;
                    }
                    let places = targets
                        .iter()
                        .map(|target| self.prepare(target))
                        .collect::<Result<Vec<_>, _>>()?;
                    let output = self.tuple(values, targets.len())?;
                    for (place, value) in places.into_iter().zip(output) {
                        self.store(place, value)?;
                    }
                }
                S::If(arms, other) => {
                    let mut selected = other;
                    for (condition, body) in arms {
                        if self.eval(condition)?.truth().ok_or_else(|| {
                            format!("unproved runtime handler branch {condition:?}")
                        })? {
                            selected = body;
                            break;
                        }
                    }
                    self.statements(selected)?;
                }
                S::For(name, start, end, step, body) => {
                    let start = self.eval(start)?.int()?;
                    let end = self.eval(end)?.int()?;
                    let step = self.eval(step)?.int()?;
                    if step == 0 {
                        return Err("zero metadata loop step".to_owned());
                    }
                    let old = self.locals.get(name).cloned();
                    let mut value = start;
                    let mut iterations = 0;
                    while step > 0 && value <= end || step < 0 && value >= end {
                        iterations += 1;
                        if iterations > 256 {
                            return Err("metadata loop iteration budget exceeded".to_owned());
                        }
                        self.locals.insert(name.clone(), V::Int(value));
                        self.statements(body)?;
                        value = value
                            .checked_add(step)
                            .ok_or("metadata loop counter overflow")?;
                    }
                    if let Some(value) = old {
                        self.locals.insert(name.clone(), value);
                    } else {
                        self.locals.remove(name);
                    }
                }
                S::Return(values) => {
                    let [E::Id(yes), E::Int(tag), rest @ ..] = values.as_slice() else {
                        return Err("unproved dispatcher return tuple".to_owned());
                    };
                    if yes != "true" {
                        return Err("unsupported dispatcher return status".to_owned());
                    }
                    let arity = match tag {
                        638771 => 0,
                        422210 => 1,
                        298197 => 2,
                        862653 => 3,
                        308995 => 4,
                        874660 => usize::MAX,
                        _ => return Err(format!("unknown return tag {tag}")),
                    };
                    if arity == usize::MAX {
                        let [value] = rest else {
                            return Err("packed return tag arity mismatch".to_owned());
                        };
                        let value = self.eval(value)?;
                        let value = self.operand(&value)?;
                        self.control = Some(Control::ReturnPacked(value));
                    } else {
                        if rest.len() != arity {
                            return Err("return-tag scalar arity mismatch".to_owned());
                        }
                        let mut output = vec![];
                        for value in rest {
                            let value = self.eval(value)?;
                            output.push(self.operand(&value)?);
                        }
                        self.control = Some(Control::Return(output));
                    }
                }
                S::Expr(E::Call(target, args)) => {
                    self.call(target, args, true)?;
                }
                _ => return Err("unsupported handler statement".to_owned()),
            }
        }
        Ok(())
    }
    fn entry(&mut self, body: &[S]) -> Result<bool, String> {
        let Some(S::Local(names, values)) = body.first() else {
            return Ok(false);
        };
        if names.iter().map(String::as_str).collect::<Vec<_>>() != ["_a0", "_sr", "_ls", "_cs"] {
            return Ok(false);
        }
        if self.state.window != 0 || values.len() != 4 {
            return Err("entry initialization outside fresh frame".to_owned());
        }
        self.validate_entry_body(body)?;
        let mut decoded = vec![];
        for value in values {
            decoded.push(self.eval(value)?);
        }
        for (name, value) in names.iter().zip(&decoded) {
            self.locals.insert(name.clone(), value.clone());
        }
        let spill = self.u32(&decoded[0])?;
        let rotor = self.u32(&decoded[1])?;
        let width = self.u32(&decoded[2])?;
        let phase = self.u32(&decoded[3])?;
        if rotor & 1 != 1 || width < 10 || width > 1734 {
            return Err("entry rotor/window proof failed".to_owned());
        }
        if spill != 0 {
            let dst = slot(self.vm, self.state.bank as usize + spill as usize)?;
            let dst = self.program_slot(dst)?;
            self.put(dst, Operand::Argument(0));
        }
        if self.state.pool_key == INITIAL_K1 {
            let expression =
                find_assignment(body, "K1").ok_or("missing entry pool-key expression")?;
            let value = self.eval(expression)?;
            self.state.pool_key = self.u32(&value)?;
            self.locals
                .insert("K1".to_owned(), V::Int(self.state.pool_key as i64));
        }
        self.state.window = width;
        self.state.phase = phase;
        self.state.bank_end = self
            .state
            .bank
            .checked_add(width.checked_mul(2).ok_or("bank window overflow")?)
            .ok_or("bank ceiling overflow")?;
        for offset in [5, 6, 9, 10] {
            slot(self.vm, self.state.bank_end as usize + offset)?;
        }
        self.locals.insert("_rbs".to_owned(), V::Int(width as i64));
        Ok(true)
    }
    fn validate_entry_body(&self, body: &[S]) -> Result<(), String> {
        let Some(S::If(arms, other)) = body.get(1) else {
            return Err("missing entry key guard".to_owned());
        };
        let [(condition, key_body)] = arms.as_slice() else {
            return Err("entry key guard has multiple arms".to_owned());
        };
        let [S::Assign(targets, values)] = key_body.as_slice() else {
            return Err("entry key guard has unproved effects".to_owned());
        };
        if !other.is_empty() || targets.len() != 1 || !id(&targets[0], "K1") || values.len() != 1 {
            return Err("invalid entry key assignment".to_owned());
        }
        let metadata_index = |slot_index| -> Result<usize, String> {
            let raw = slot(self.vm, slot_index)?;
            self.family
                .metadata
                .iter()
                .position(|value| *value == raw)
                .map(|index| index + 1)
                .ok_or("missing entry metadata role".to_owned())
        };
        let width = metadata_index(33)?;
        let ceiling = metadata_index(24)?;
        let source=format!("if bxor(K1,355957541)==1030971814 then K1=__key end; if _a0~=0 then local _sl=_rm[rb+_a0];F[_sl]=F[_pxs] end;F[_pxs]=bxor(_sr,_sma);F[_pys]=(_cs-(_sr+_smb))%4294967296;_rbs=_ls;F[_cm[{width}]]=_rbs;F[_cm[{ceiling}]]=rb+2*_ls;_r=_sr");
        let tokens = crate::decoder::tokenize(&source)?;
        let mut expected = super::model::Parser::new(&tokens, &source, 0).block()?;
        let S::If(expected_arms, _) = &mut expected[0] else {
            return Err("invalid entry template".to_owned());
        };
        if &expected_arms[0].0 != condition {
            return Err("entry activation predicate is not proved".to_owned());
        }
        let S::Assign(_, expected_values) = &mut expected_arms[0].1[0] else {
            return Err("invalid entry key template".to_owned());
        };
        expected_values[0] = values[0].clone();
        if body[1..] != expected {
            return Err("entry setup contains unsummarized statements/effects".to_owned());
        }
        Ok(())
    }
}

fn find_assignment<'a>(body: &'a [S], name: &str) -> Option<&'a E> {
    for statement in body {
        match statement {
            S::Assign(targets, values) if targets.len() == 1 && id(&targets[0], name) => {
                return values.first()
            }
            S::Do(body) => {
                if let Some(value) = find_assignment(body, name) {
                    return Some(value);
                }
            }
            S::If(arms, other) => {
                for (_, body) in arms {
                    if let Some(value) = find_assignment(body, name) {
                        return Some(value);
                    }
                }
                if let Some(value) = find_assignment(other, name) {
                    return Some(value);
                }
            }
            _ => {}
        }
    }
    None
}

pub(super) fn select(
    body: &[S],
    context: &mut Context<'_>,
    selector: &str,
) -> Result<Vec<S>, String> {
    let mut output = vec![];
    for statement in body {
        if let S::If(arms, other) = statement {
            if arms
                .iter()
                .all(|(condition, _)| contains(condition, selector))
            {
                let mut selected = other;
                for (condition, body) in arms {
                    if context
                        .eval(condition)?
                        .truth()
                        .ok_or("unproved handler comparison")?
                    {
                        selected = body;
                        break;
                    }
                }
                output.extend(select(selected, context, selector)?);
                continue;
            }
        }
        output.push(statement.clone());
    }
    Ok(output)
}

pub(super) fn lift(
    vm: &DecodedVm,
    model: &Model,
    initialization: &Initialization,
    state: &State,
    temp_start: u32,
    strings: &mut Strings,
    numbers: &mut Numbers,
) -> Result<TraceRow, String> {
    let id = *vm
        .dispatch_families
        .get(&state.token)
        .ok_or("unknown dispatch token")?;
    let family = model
        .families
        .get(&id)
        .ok_or("unsupported handler family")?;
    let mut context = Context::new(
        vm,
        model,
        family,
        initialization,
        state,
        temp_start,
        strings,
        numbers,
    )?;
    let selector = context.eval(&family.selector)?.int()?;
    context.locals.insert("op".to_owned(), V::Int(selector));
    let body = select(std::slice::from_ref(&family.tree), &mut context, "op")?;
    context
        .statements(&body)
        .map_err(|e| format!("PC {} family={id} selector={selector}: {e}", state.pc))?;
    if matches!(
        context.control,
        Some(Control::Next(_) | Control::Branch(_, _, _))
    ) {
        context.validate_transfer_tail()?;
    }
    let mut successors = vec![];
    match context.control.take() {
        Some(Control::Next(next)) => {
            context.output.push(Instruction::Jump { target: next.pc });
            successors.push((EdgeLabel::Next, next));
        }
        Some(Control::Branch(condition, yes, no)) => {
            context.output.push(Instruction::Branch {
                condition,
                then_target: yes.pc,
                else_target: no.pc,
            });
            successors.push((EdgeLabel::True, yes));
            successors.push((EdgeLabel::False, no));
        }
        Some(Control::Return(values)) => context.output.push(Instruction::Return { values }),
        Some(Control::ReturnPacked(values)) => {
            context.output.push(Instruction::ReturnPacked { values })
        }
        None => {
            let mut next = context.state.clone();
            next.pc = usize::try_from(context.locals.get("ip").ok_or("missing PC")?.int()?)
                .map_err(|_| "negative next PC")?;
            next.key = context.u32(context.locals.get("st").ok_or("missing key")?)?;
            if next.pc <= state.pc || next.pc.checked_sub(state.pc).is_none_or(|span| span > 257) {
                return Err("unsupported plain instruction PC update".to_owned());
            }
            for (name, value) in [
                ("rb", state.bank),
                ("ps", state.salt as u32),
                ("sh", state.token),
            ] {
                if context.u32(
                    context
                        .locals
                        .get(name)
                        .ok_or("missing plain state field")?,
                )? != value
                {
                    return Err(format!("unproved plain state update {name}"));
                }
            }
            word(vm, next.pc)?;
            context.max_offset = context.max_offset.max(next.pc - state.pc - 1);
            context.output.push(Instruction::Jump { target: next.pc });
            successors.push((EdgeLabel::Next, next));
        }
    }
    for (_, state) in &mut successors {
        // Retain proved cipher inputs, not guessed type-only replacements.
        // Cyclic fact growth remains bounded by the outer worklist budgets.
        state.facts.retain(|slot, _| *slot < 256);
        state.initialized.retain(|slot| *slot < 256);
    }
    if !context.witnesses.is_empty() && context.witnesses != [0, 1] {
        return Err("incomplete permutation witness writes".to_owned());
    }
    let end_pc = state
        .pc
        .checked_add(context.max_offset + 1)
        .ok_or("instruction extent overflow")?;
    for at in state.pc..end_pc {
        word(vm, at)?;
    }
    Ok(TraceRow {
        state: state.clone(),
        family: id,
        selector,
        end_pc,
        instructions: context.output,
        successors,
        helpers: context.helper_ids,
        operations: context.operations,
        temps: (context.temp_next - context.temp_start) as usize,
        hash_proofs: context.hash_proofs,
        factories: context.factories,
    })
}
