//! Protected-handler decoding into the shared instruction IR.
//!
//! [`build_source_model`] locates the `tbl5` handler definitions inside
//! [`DecodedVm::source_text`] and resolves, per handler family, the identifier
//! roles (word table, program counter, rolling key, bank, slot map, bias
//! table, helper table, discriminator) from the handler preamble and the
//! discriminator expression alone. [`lift_instruction`] then maps one
//! dispatcher [`VmState`] to a [`DecodedInstruction`]:
//!
//! 1. the handler family comes from `dispatch_families`,
//! 2. the discriminator/selector is evaluated statically from the decoded word
//!    at the current program counter, the rolling key, and the prototype salt,
//! 3. the handler's `if`/`else` comparison tree is walked line by line down to
//!    the single leaf implementing the selector,
//! 4. the leaf's variable-length word operands are resolved through
//!    `decoded_words`, `slot_map`, and `immediate_biases`,
//! 5. the leaf's statements are matched against supported templates and
//!    lowered into the shared IR.
//!
//! A leaf whose statements do not fully match a supported template is reported
//! explicitly as [`Instruction::Raw`] together with the instruction's raw
//! words; its control-flow successors are still recovered so that the CFG
//! walk stays complete. Nothing here executes the payload: every value is
//! recovered statically from the decoded tables.
//!
//! Facts that cannot be re-derived from `DecodedVm` alone are kept explicit
//! and documented at their use: the helper argument roles (which argument
//! positions of each scrambled helper feed the next program counter, key,
//! token, and phase), the `tbl4` selector-table rows, and the
//! prototype-reference constant `651803`.

use std::collections::{BTreeMap, BTreeSet};

use crate::ir::{
    BinaryOp, Condition, Constant, DecodedInstruction, DecodedVm, EdgeLabel, Instruction, Operand,
    Register, Successor, UnaryOp, ValueExpression, VmState,
};

/// Seed added to each prototype's initial decode state when entering the
/// dispatcher. The protected source derives it from a value-type hash whose
/// standard cases collapse to this constant (T001 analysis notes).
pub const VALUE_SEED: u32 = 52_918;

/// XOR mask between a prototype's encoded reference and its word position.
const PROTOTYPE_MASK: u32 = 651_803;

/// `(family, selector)` pairs whose leaf installs a fresh decode phase and
/// the bank sum used to alternate register banks on entry to a prototype.
const ENTRY_WINDOWS: &[(u32, i64)] = &[(6_965, 624), (6_094, 791)];

/// One arm of a helper transition: which helper argument positions, in the
/// formatted source's `argNN` numbering, sum to the next program counter,
/// key, token, and phase. These roles are a property of the source's
/// scrambled helper signatures; they were cross-checked against the helper
/// implementations in the formatted source.
struct HelperArm {
    label: EdgeLabel,
    pc: &'static [u32],
    key: &'static [u32],
    token: &'static [u32],
    phase: &'static [u32],
}

struct HelperSpec {
    /// The `argNN` number of the helper's first parameter: argument `j`
    /// (0-based) in a call corresponds to `cleave + j`.
    cleave: u32,
    /// Position of the branch predicate inside the call argument list.
    predicate: Option<usize>,
    arms: &'static [HelperArm],
}

const fn arm(
    label: EdgeLabel,
    pc: &'static [u32],
    key: &'static [u32],
    token: &'static [u32],
    phase: &'static [u32],
) -> HelperArm {
    HelperArm {
        label,
        pc,
        key,
        token,
        phase,
    }
}

/// Helper transition table keyed by helper id as used in `var394[h](...)`.
/// Helper 19 (the three-way selector-table transition) carries no arms; the
/// walker resolves its rows through the `tbl4` selector table.
static HELPERS: &[(u32, HelperSpec)] = &[
    (
        6,
        HelperSpec {
            cleave: 134,
            // The predicate position for helper 6 is not exercised by the
            // supplied target; a leaf using it stays Raw rather than guessed.
            predicate: None,
            arms: &[
                arm(EdgeLabel::True, &[139, 149], &[148, 136], &[146], &[144]),
                arm(EdgeLabel::False, &[139, 141], &[148, 140], &[137], &[142]),
            ],
        },
    ),
    (
        14,
        HelperSpec {
            cleave: 6,
            predicate: None,
            arms: &[arm(EdgeLabel::Next, &[16, 12], &[11, 15], &[13], &[10])],
        },
    ),
    (
        15,
        HelperSpec {
            // Numeric-for range test; the loop state table is the predicate.
            cleave: 186,
            predicate: Some(4),
            arms: &[
                arm(EdgeLabel::True, &[198, 189], &[199, 192], &[187], &[193]),
                arm(EdgeLabel::False, &[198, 194], &[199, 195], &[201], &[191]),
            ],
        },
    ),
    (
        19,
        HelperSpec {
            cleave: 240,
            predicate: Some(9),
            arms: &[],
        },
    ),
    (
        20,
        HelperSpec {
            cleave: 118,
            predicate: Some(8),
            arms: &[
                arm(EdgeLabel::False, &[125, 127], &[121, 120], &[129], &[123]),
                arm(EdgeLabel::True, &[125, 132], &[121, 130], &[119], &[124]),
            ],
        },
    ),
    (
        21,
        HelperSpec {
            cleave: 60,
            predicate: Some(0),
            arms: &[
                arm(EdgeLabel::False, &[67, 68], &[66, 63], &[75], &[72]),
                arm(EdgeLabel::True, &[67, 70], &[66, 64], &[61], &[65]),
            ],
        },
    ),
    (
        22,
        HelperSpec {
            cleave: 250,
            predicate: Some(5),
            arms: &[
                arm(EdgeLabel::True, &[252, 250], &[262, 264], &[259], &[253]),
                arm(EdgeLabel::False, &[252, 251], &[262, 260], &[261], &[263]),
            ],
        },
    ),
    (
        23,
        HelperSpec {
            cleave: 87,
            predicate: None,
            arms: &[arm(EdgeLabel::Next, &[90, 96], &[92, 89], &[95], &[94])],
        },
    ),
];

fn helper_spec(id: u32) -> Option<&'static HelperSpec> {
    HELPERS.iter().find(|(h, _)| *h == id).map(|(_, spec)| spec)
}

/// Helpers that stop dispatch by returning from the handler. Their value
/// argument positions: helper 3 returns nothing, helper 5 the packed list at
/// argument 0, helper 7 the single value at argument 1.
const RETURN_HELPERS: &[u32] = &[3, 5, 7];

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Int(i64),
    Ident(String),
    Plus,
    Minus,
    Star,
    Percent,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Assign,
    LParen,
    RParen,
    LBrack,
    RBrack,
    LBrace,
    RBrace,
    Comma,
    Semi,
    Hash,
    Dot,
}

fn lex(line: &str) -> Result<Vec<Tok>, String> {
    if line.len() > 256 * 1024 {
        return Err("handler expression exceeds the source-line budget".to_owned());
    }
    let mut out = Vec::new();
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c.is_ascii_digit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            let text: String = chars[start..i].iter().collect();
            let value: i64 = text.parse().map_err(|_| format!("bad integer `{text}`"))?;
            out.push(Tok::Int(value));
            continue;
        }
        if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let text: String = chars[start..i].iter().collect();
            out.push(Tok::Ident(text));
            continue;
        }
        let two = if i + 1 < chars.len() {
            chars[i..i + 2].iter().collect::<String>()
        } else {
            String::new()
        };
        let matched = match two.as_str() {
            "==" => Some(Tok::Eq),
            "~=" => Some(Tok::Ne),
            "<=" => Some(Tok::Le),
            ">=" => Some(Tok::Ge),
            _ => None,
        };
        if let Some(tok) = matched {
            out.push(tok);
            i += 2;
            continue;
        }
        let tok = match c {
            '+' => Tok::Plus,
            '-' => Tok::Minus,
            '*' => Tok::Star,
            '%' => Tok::Percent,
            '=' => Tok::Assign,
            '<' => Tok::Lt,
            '>' => Tok::Gt,
            '(' => Tok::LParen,
            ')' => Tok::RParen,
            '[' => Tok::LBrack,
            ']' => Tok::RBrack,
            '{' => Tok::LBrace,
            '}' => Tok::RBrace,
            ',' => Tok::Comma,
            ';' => Tok::Semi,
            '#' => Tok::Hash,
            '.' => Tok::Dot,
            other => return Err(format!("unexpected character `{other}`")),
        };
        out.push(tok);
        i += 1;
    }
    if out.len() > 8192 {
        return Err("handler expression exceeds the token budget".to_owned());
    }
    let mut depth = 0usize;
    let mut unary_run = 0usize;
    for token in &out {
        match token {
            Tok::LParen | Tok::LBrack | Tok::LBrace => {
                depth += 1;
                if depth > 128 {
                    return Err("handler expression nesting exceeds 128".to_owned());
                }
            }
            Tok::RParen | Tok::RBrack | Tok::RBrace => depth = depth.saturating_sub(1),
            _ => {}
        }
        if matches!(token, Tok::Minus | Tok::Hash) {
            unary_run += 1;
            if unary_run > 128 {
                return Err("handler unary-expression nesting exceeds 128".to_owned());
            }
        } else {
            unary_run = 0;
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Expression and statement AST
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BinKind {
    Add,
    Sub,
    Mul,
    Mod,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl BinKind {
    fn to_ir(self) -> BinaryOp {
        match self {
            BinKind::Add => BinaryOp::Add,
            BinKind::Sub => BinaryOp::Sub,
            BinKind::Mul => BinaryOp::Mul,
            BinKind::Mod => BinaryOp::Mod,
            BinKind::Eq => BinaryOp::Equal,
            BinKind::Ne => BinaryOp::NotEqual,
            BinKind::Lt => BinaryOp::Less,
            BinKind::Le => BinaryOp::LessEqual,
            BinKind::Gt => BinaryOp::Greater,
            BinKind::Ge => BinaryOp::GreaterEqual,
        }
    }
    fn is_compare(self) -> bool {
        matches!(
            self,
            BinKind::Eq | BinKind::Ne | BinKind::Lt | BinKind::Le | BinKind::Gt | BinKind::Ge
        )
    }
}

#[derive(Clone, Debug)]
pub enum Expr {
    Int(i64),
    Ident(String),
    Index(Box<Expr>, Box<Expr>),
    Call(Box<Expr>, Vec<Expr>),
    Bin(BinKind, Box<Expr>, Box<Expr>),
    Len(Box<Expr>),
    Neg(Box<Expr>),
    /// Table constructor; `None` marks a positional field.
    Table(Vec<(Option<String>, Expr)>),
}

#[derive(Clone, Debug)]
enum Stmt {
    Do,
    End,
    Else,
    Break,
    Return,
    /// `if <expr> then` (block markers stay flat).
    If(Expr),
    /// `for <loop variable> = <from>, <to>, <step> do`
    For(String, Expr, Expr, Expr),
    Local(Vec<String>, Vec<Expr>),
    Assign(Vec<Expr>, Expr),
    ExprStmt(Expr),
    /// A line outside the supported grammar.
    Opaque,
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn new(line: &str) -> Result<Self, String> {
        Ok(Parser {
            toks: lex(line)?,
            pos: 0,
        })
    }
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }
    fn eat(&mut self, tok: &Tok) -> bool {
        if self.peek() == Some(tok) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn expect_ident(&mut self) -> Result<String, String> {
        match self.next() {
            Some(Tok::Ident(name)) => Ok(name),
            other => Err(format!("expected identifier, got {other:?}")),
        }
    }
    fn expect(&mut self, tok: Tok, what: &str) -> Result<(), String> {
        if self.eat(&tok) {
            Ok(())
        } else {
            Err(format!("expected {what}"))
        }
    }
    fn at_end(&self) -> bool {
        self.pos >= self.toks.len()
    }

    fn parse_expr_list(&mut self) -> Result<Vec<Expr>, String> {
        let mut out = vec![self.parse_expr()?];
        while self.eat(&Tok::Comma) {
            out.push(self.parse_expr()?);
        }
        Ok(out)
    }

    fn parse_expr(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_add()?;
        while let Some(tok) = self.peek() {
            let kind = match tok {
                Tok::Eq => BinKind::Eq,
                Tok::Ne => BinKind::Ne,
                Tok::Lt => BinKind::Lt,
                Tok::Le => BinKind::Le,
                Tok::Gt => BinKind::Gt,
                Tok::Ge => BinKind::Ge,
                _ => break,
            };
            self.pos += 1;
            let right = self.parse_add()?;
            left = Expr::Bin(kind, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_add(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_mul()?;
        loop {
            let kind = match self.peek() {
                Some(Tok::Plus) => BinKind::Add,
                Some(Tok::Minus) => BinKind::Sub,
                _ => break,
            };
            self.pos += 1;
            let right = self.parse_mul()?;
            left = Expr::Bin(kind, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_mul(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_unary()?;
        loop {
            let kind = match self.peek() {
                Some(Tok::Star) => BinKind::Mul,
                Some(Tok::Percent) => BinKind::Mod,
                _ => break,
            };
            self.pos += 1;
            let right = self.parse_unary()?;
            left = Expr::Bin(kind, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Expr, String> {
        if self.eat(&Tok::Minus) {
            return Ok(Expr::Neg(Box::new(self.parse_unary()?)));
        }
        if self.eat(&Tok::Hash) {
            return Ok(Expr::Len(Box::new(self.parse_unary()?)));
        }
        self.parse_postfix()
    }

    fn parse_postfix(&mut self) -> Result<Expr, String> {
        let mut expr = self.parse_primary()?;
        loop {
            if self.eat(&Tok::LBrack) {
                let index = self.parse_expr()?;
                self.expect(Tok::RBrack, "`]`")?;
                expr = Expr::Index(Box::new(expr), Box::new(index));
                continue;
            }
            if self.eat(&Tok::Dot) {
                let name = self.expect_ident()?;
                expr = Expr::Index(Box::new(expr), Box::new(Expr::Ident(name)));
                continue;
            }
            if self.eat(&Tok::LParen) {
                let mut args = Vec::new();
                if !self.eat(&Tok::RParen) {
                    args = self.parse_expr_list()?;
                    self.expect(Tok::RParen, "`)`")?;
                }
                expr = Expr::Call(Box::new(expr), args);
                continue;
            }
            break;
        }
        Ok(expr)
    }

    fn parse_primary(&mut self) -> Result<Expr, String> {
        match self.next() {
            Some(Tok::Int(v)) => Ok(Expr::Int(v)),
            Some(Tok::Ident(name)) => Ok(Expr::Ident(name)),
            Some(Tok::LParen) => {
                let inner = self.parse_expr()?;
                self.expect(Tok::RParen, "`)`")?;
                Ok(inner)
            }
            Some(Tok::LBrace) => {
                let mut fields = Vec::new();
                if !self.eat(&Tok::RBrace) {
                    loop {
                        let named =
                            match (self.peek().cloned(), self.toks.get(self.pos + 1).cloned()) {
                                (Some(Tok::Ident(name)), Some(Tok::Assign)) => Some(name),
                                _ => None,
                            };
                        if let Some(name) = named {
                            self.pos += 2;
                            let value = self.parse_expr()?;
                            fields.push((Some(name), value));
                        } else {
                            fields.push((None, self.parse_expr()?));
                        }
                        if !self.eat(&Tok::Comma) {
                            break;
                        }
                    }
                    self.expect(Tok::RBrace, "`}`")?;
                }
                Ok(Expr::Table(fields))
            }
            other => Err(format!("unexpected token {other:?}")),
        }
    }
}

fn parse_stmt(line: &str) -> Result<Stmt, String> {
    let stripped = line.trim();
    match stripped {
        "do" => return Ok(Stmt::Do),
        "end" | "end;" => return Ok(Stmt::End),
        "else" => return Ok(Stmt::Else),
        "break" | "break;" => return Ok(Stmt::Break),
        _ => {}
    }
    let mut parser = Parser::new(stripped)?;
    let first = match parser.peek() {
        Some(Tok::Ident(name)) => name.clone(),
        _ => {
            let expr = parser.parse_expr()?;
            return parse_tail(parser, Stmt::ExprStmt(expr));
        }
    };
    match first.as_str() {
        "return" => {
            parser.next();
            if parser.at_end() {
                return Ok(Stmt::Opaque);
            }
            let _ = parser.parse_expr()?;
            parse_tail(parser, Stmt::Return)
        }
        "local" => {
            parser.next();
            let mut names = vec![parser.expect_ident()?];
            while parser.eat(&Tok::Comma) {
                names.push(parser.expect_ident()?);
            }
            if !parser.eat(&Tok::Assign) {
                return parse_tail(parser, Stmt::Local(names, Vec::new()));
            }
            let exprs = parser.parse_expr_list()?;
            parse_tail(parser, Stmt::Local(names, exprs))
        }
        "if" => {
            parser.next();
            let cond = parser.parse_expr()?;
            if parser.next() != Some(Tok::Ident("then".to_owned())) {
                return Err("expected `then`".to_owned());
            }
            parse_tail(parser, Stmt::If(cond))
        }
        "for" => {
            parser.next();
            let name = parser.expect_ident()?;
            parser.expect(Tok::Assign, "`=`")?;
            let from = parser.parse_expr()?;
            parser.expect(Tok::Comma, "`,`")?;
            let to = parser.parse_expr()?;
            let step = if parser.eat(&Tok::Comma) {
                Some(parser.parse_expr()?)
            } else {
                None
            };
            if parser.next() != Some(Tok::Ident("do".to_owned())) {
                return Err("expected `do` after `for`".to_owned());
            }
            parse_tail(
                parser,
                Stmt::For(name, from, to, step.unwrap_or(Expr::Int(1))),
            )
        }
        _ => {
            let mut targets = vec![parser.parse_expr()?];
            while parser.eat(&Tok::Comma) {
                targets.push(parser.parse_expr()?);
            }
            if parser.eat(&Tok::Assign) {
                // Lua assignments may list several values (alias rotation);
                // only the first is ever inspected by the templates.
                let values = parser.parse_expr_list()?;
                let value = values.into_iter().next().unwrap();
                parse_tail(parser, Stmt::Assign(targets, value))
            } else if targets.len() == 1 {
                let expr = targets.remove(0);
                parse_tail(parser, Stmt::ExprStmt(expr))
            } else {
                Err("expression statement cannot have multiple targets".to_owned())
            }
        }
    }
}

fn parse_tail(mut parser: Parser, stmt: Stmt) -> Result<Stmt, String> {
    parser.eat(&Tok::Semi);
    if !parser.at_end() {
        return Err("trailing tokens after statement".to_owned());
    }
    Ok(stmt)
}

/// True when `expr` is `name[field]` for a literal field spelling.
fn is_field_of(expr: &Expr, name: &str, field: &str) -> bool {
    let Expr::Index(table, f) = expr else {
        return false;
    };
    matches!(table.as_ref(), Expr::Ident(n) if n == name)
        && matches!(f.as_ref(), Expr::Ident(x) if x.as_str() == field)
}

// ---------------------------------------------------------------------------
// Source model
// ---------------------------------------------------------------------------

/// Per-family identifier roles resolved from the handler preamble.
pub struct FamilyModel {
    pub family: u32,
    /// 1-based line of the first comparison node of the dispatch tree.
    pub root_line: usize,
    /// Name of the discriminator local.
    pub disc_ident: String,
    /// Parsed discriminator expression.
    pub disc: Expr,
    pub frame: String,
    pub words: String,
    pub slots: String,
    pub bias: String,
    pub helpers: String,
    pub pc: String,
    pub key: String,
    pub token: String,
    pub salt: String,
    pub bank: String,
    pub bank_sum: String,
    pub aliases: [String; 3],
    /// Preamble locals that only ever receive bookkeeping values (the rolling
    /// checksum witnesses and loop sentinels).
    pub bookkeeping: Vec<String>,
}

/// Parsed handler table plus the selector-table rows used by helper 19.
pub struct SourceModel {
    pub lines: Vec<String>,
    pub handlers: BTreeMap<u32, FamilyModel>,
    /// `tbl4` rows keyed by tag: (pc delta, key delta, token value, phase).
    pub jump_rows: BTreeMap<i64, [i64; 4]>,
    /// Families whose handler is the short exit form (copy bank slot into the
    /// encoded program counter slot and stop dispatch).
    pub short_handlers: BTreeSet<u32>,
}

/// Applies the successor-state rotation shared by every helper transition: the
/// key and token candidates get the *outgoing* phase added, the register bank
/// alternates against the bank sum, and the phase is replaced.
fn rotate(state: &VmState, pc: i64, key: i64, token: i64, phase: i64) -> Result<VmState, String> {
    let masked_pc = pc & 0xFFFF_FFFF;
    if masked_pc < 0 {
        return Err(format!("successor program counter {masked_pc} is negative"));
    }
    let new_phase = (phase & 0xFFFF_FFFF) as u32;
    let mask = 0xFFFF_FFFFu64;
    Ok(VmState {
        pc: masked_pc as usize,
        key_state: (((key as u64 & mask) + state.phase as u64) & mask) as u32,
        dispatch_token: (((token as u64 & mask) + state.phase as u64) & mask) as u32,
        bank_base: state.bank_sum.wrapping_sub(state.bank_base),
        phase: new_phase,
        bank_sum: state.bank_sum,
        prototype_salt: state.prototype_salt,
    })
}

/// Collects the plain identifiers used in an expression, skipping call targets
/// so the discriminator's `bxor` helper never masquerades as a role.
fn collect_idents(expr: &Expr, out: &mut Vec<String>) {
    match expr {
        Expr::Ident(name) => out.push(name.clone()),
        Expr::Index(a, b) => {
            collect_idents(a, out);
            collect_idents(b, out);
        }
        Expr::Call(_, args) => {
            for arg in args {
                collect_idents(arg, out);
            }
        }
        Expr::Bin(_, a, b) => {
            collect_idents(a, out);
            collect_idents(b, out);
        }
        Expr::Len(a) | Expr::Neg(a) => collect_idents(a, out),
        Expr::Int(_) | Expr::Table(_) => {}
    }
}

/// True when `name` is used as an indexed table somewhere in `expr`.
fn has_indexed_table(expr: &Expr, name: &str) -> bool {
    match expr {
        Expr::Index(a, _) => {
            matches!(a.as_ref(), Expr::Ident(n) if n == name) || has_indexed_table(a, name)
        }
        Expr::Bin(_, a, b) => has_indexed_table(a, name) || has_indexed_table(b, name),
        Expr::Call(_, args) => args.iter().any(|a| has_indexed_table(a, name)),
        Expr::Len(a) | Expr::Neg(a) => has_indexed_table(a, name),
        _ => false,
    }
}

/// The identifier used to index `table` inside `expr`.
fn indexed_by(expr: &Expr, table: &str) -> Option<String> {
    match expr {
        Expr::Index(a, b) => match (a.as_ref(), b.as_ref()) {
            (Expr::Ident(n), Expr::Ident(index)) if n == table => Some(index.clone()),
            _ => indexed_by(b, table).or_else(|| indexed_by(a, table)),
        },
        Expr::Bin(_, a, b) => indexed_by(a, table).or_else(|| indexed_by(b, table)),
        Expr::Call(_, args) => args.iter().filter_map(|a| indexed_by(a, table)).next(),
        _ => None,
    }
}

/// `slots[bank + <int>]` shape.
fn alias_shape(expr: &Expr) -> Option<(String, String)> {
    let Expr::Index(table, index) = expr else {
        return None;
    };
    let Expr::Ident(table) = table.as_ref() else {
        return None;
    };
    let Expr::Bin(BinKind::Add, left, right) = index.as_ref() else {
        return None;
    };
    let (Expr::Ident(bank), Expr::Int(_)) = (left.as_ref(), right.as_ref()) else {
        return None;
    };
    Some((table.clone(), bank.clone()))
}

/// Extracts `name` from a prefix of the form `name[123]`.
fn leading_indexed_ident(text: &str) -> Option<String> {
    let text = text.trim_start();
    let bracket = text.find('[')?;
    let name = &text[..bracket];
    if name.is_empty()
        || !name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    let close = text[bracket..].find(']')? + bracket;
    let inner = &text[bracket + 1..close];
    if !inner.is_empty() && inner.chars().all(|c| c.is_ascii_digit()) {
        Some(name.to_owned())
    } else {
        None
    }
}

/// Extracts `name` from the first `name[123](` occurrence in a line.
fn called_indexed_ident(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'[' {
            let mut start = i;
            while start > 0
                && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_')
            {
                start -= 1;
            }
            let close = text[i..].find(']')? + i;
            let inner = &text[i + 1..close];
            if !inner.is_empty() && inner.chars().all(|c| c.is_ascii_digit()) {
                let after = text[close + 1..].chars().next();
                if after == Some('(') && start < i {
                    return Some(text[start..i].to_owned());
                }
            }
            i = close;
        } else {
            i += 1;
        }
    }
    None
}

fn build_family(
    family: u32,
    lines: &[String],
    fn_line: usize,
    scan_end: usize,
) -> Result<FamilyModel, String> {
    // Locate the dispatch loop; the discriminator local follows it.
    let mut while_line = None;
    for n in fn_line..(fn_line + 40).min(lines.len()) {
        if lines[n].trim_start().starts_with("while ") {
            while_line = Some(n);
            break;
        }
    }
    let while_line = while_line.ok_or_else(|| format!("handler {family} has no dispatch loop"))?;
    let disc_line = while_line + 1;
    let (disc, disc_ident) = match parse_stmt(&lines[disc_line]) {
        Ok(Stmt::Local(names, exprs)) if names.len() == 1 && exprs.len() == 1 => {
            (exprs[0].clone(), names[0].clone())
        }
        other => {
            return Err(format!(
                "handler {family} discriminator is not a single local: {other:?}"
            ))
        }
    };

    // The discriminator references the word table indexed by the program
    // counter plus exactly two further plain identifiers: key and salt.
    let mut disc_idents = Vec::new();
    collect_idents(&disc, &mut disc_idents);
    let words = disc_idents
        .iter()
        .find(|name| has_indexed_table(&disc, name))
        .cloned()
        .ok_or_else(|| format!("handler {family} discriminator lacks a word index"))?;
    let pc = indexed_by(&disc, &words)
        .ok_or_else(|| format!("handler {family} word index is not the program counter"))?;
    let mut unknowns: Vec<String> = disc_idents
        .iter()
        .filter(|n| **n != words && **n != pc)
        .cloned()
        .collect();
    unknowns.dedup();
    if unknowns.len() != 2 {
        return Err(format!(
            "handler {family} discriminator does not expose key and salt"
        ));
    }

    // Walk the preamble locals to bind the remaining roles.
    let mut frame_ident: Option<String> = None;
    let mut bank: Option<String> = None;
    let mut salt: Option<String> = None;
    let mut slots: Option<String> = None;
    let mut aliases: Option<[String; 3]> = None;
    let mut bank_sum: Option<String> = None;
    let mut token: Option<String> = None;
    let mut key: Option<String> = None;
    let mut bookkeeping: Vec<String> = Vec::new();
    for n in fn_line + 1..while_line {
        let (names, exprs) = match parse_stmt(&lines[n]) {
            Ok(Stmt::Local(names, exprs)) => (names, exprs),
            _ => continue,
        };
        if names.len() != exprs.len() {
            continue;
        }
        let frame_read = |expr: &Expr| -> Option<String> {
            if let Expr::Index(inner, _) = expr {
                if let Expr::Ident(table) = inner.as_ref() {
                    return Some(table.clone());
                }
            }
            None
        };
        // `local bank, salt, sentinel, sentinel = frame[c], .., .., ..`
        if names.len() == 4 && exprs.iter().all(|e| frame_read(e).is_some()) {
            if frame_ident.is_none() {
                frame_ident = frame_read(&exprs[0]);
            }
            if unknowns.contains(&names[1]) {
                bank = Some(names[0].clone());
                salt = Some(names[1].clone());
                bookkeeping.push(names[2].clone());
                bookkeeping.push(names[3].clone());
            }
            continue;
        }
        // `local pc, key, token = frame[c], frame[c], frame[c]`
        if names.len() == 3 && names[0] == pc && exprs.iter().all(|e| frame_read(e).is_some()) {
            key = Some(names[1].clone());
            token = Some(names[2].clone());
            continue;
        }
        // `local a, b, c = slots[bank + 1], slots[bank + 2], slots[bank + 3]`
        if names.len() == 3 {
            let mut resolved: Option<(String, String)> = None;
            let mut ok = true;
            for expr in &exprs {
                match alias_shape(expr) {
                    Some((table, bank_name)) => {
                        if resolved.is_none() {
                            resolved = Some((table, bank_name));
                        }
                    }
                    None => ok = false,
                }
            }
            if let Some((table, bank_name)) = resolved {
                if ok && Some(&bank_name) == bank.as_ref() {
                    slots = Some(table);
                    aliases = Some([names[0].clone(), names[1].clone(), names[2].clone()]);
                }
            }
            continue;
        }
        if names.len() == 1 && exprs.len() == 1 {
            // `local bank_sum = frame[c]`
            if let Some(table) = frame_read(&exprs[0]) {
                if frame_ident.as_deref() == Some(table.as_str()) {
                    bank_sum = Some(names[0].clone());
                    continue;
                }
            }
            // `local witness = <int>` (rolling checksum and family consts).
            if matches!(exprs[0], Expr::Int(_)) {
                bookkeeping.push(names[0].clone());
            }
        }
    }

    let frame = frame_ident.ok_or_else(|| format!("handler {family} frame not found"))?;
    let bank = bank.ok_or_else(|| format!("handler {family} bank not found"))?;
    let salt = salt.ok_or_else(|| format!("handler {family} salt not found"))?;
    let slots = slots.ok_or_else(|| format!("handler {family} slot map not found"))?;
    let aliases = aliases.ok_or_else(|| format!("handler {family} aliases not found"))?;
    let bank_sum = bank_sum.ok_or_else(|| format!("handler {family} bank sum not found"))?;
    let key = key.ok_or_else(|| format!("handler {family} key not found"))?;
    let token = token.ok_or_else(|| format!("handler {family} token not found"))?;
    if !unknowns.contains(&key) {
        return Err(format!(
            "handler {family} key does not match the discriminator"
        ));
    }

    // Resolve the bias and helper-table identifiers by their unique usage
    // shapes inside the handler body: `- name[int]` for a biased immediate
    // and `name[int](` for a helper call.
    let mut bias = None;
    let mut helpers = None;
    for n in fn_line..scan_end.min(lines.len()) {
        let line = &lines[n];
        if bias.is_none() {
            for (pos, _) in line.match_indices("- ") {
                let rest = &line[pos + 2..];
                if let Some(name) = leading_indexed_ident(rest) {
                    bias = Some(name);
                    break;
                }
            }
        }
        if helpers.is_none() {
            if let Some(name) = called_indexed_ident(line) {
                helpers = Some(name);
            }
        }
        if bias.is_some() && helpers.is_some() {
            break;
        }
    }
    let bias = bias.ok_or_else(|| format!("handler {family} bias table not found"))?;
    let helpers = helpers.ok_or_else(|| format!("handler {family} helper table not found"))?;

    let root_line = disc_line + 2;
    if !lines
        .get(root_line - 1)
        .is_some_and(|l| l.trim_start().starts_with("if "))
    {
        return Err(format!("handler {family} comparison tree is missing"));
    }

    Ok(FamilyModel {
        family,
        root_line,
        disc_ident,
        disc,
        frame,
        words,
        slots,
        bias,
        helpers,
        pc,
        key,
        token,
        salt,
        bank,
        bank_sum,
        aliases,
        bookkeeping,
    })
}

/// Scans the source once and builds the handler and selector-table models.
pub fn build_source_model(vm: &DecodedVm) -> Result<SourceModel, String> {
    let lines: Vec<String> = vm
        .source_text
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l).to_owned())
        .collect();
    if lines.is_empty() {
        return Err("source text is empty".to_owned());
    }

    // Index handler definitions: `<table>[<family>] = function(<frame>, <arg>)`.
    let mut definitions: Vec<(u32, usize)> = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let stripped = line.trim_start();
        // Find `<ident>[`.
        let Some(bracket) = stripped.find('[') else {
            continue;
        };
        let name = &stripped[..bracket];
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let Some(close) = stripped[bracket..].find(']') else {
            continue;
        };
        let close = bracket + close;
        let Ok(family) = stripped[bracket + 1..close].parse::<u32>() else {
            continue;
        };
        let rest = stripped[close + 1..].trim_start();
        if !rest.starts_with("= function(") {
            continue;
        }
        // Require two parameters: `function(<a>, <b>)`.
        let params = &rest["= function(".len()..];
        if !params.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
            continue;
        }
        definitions.push((family, idx + 1));
    }

    // Short exit handlers: two statements, copy bank slot into encoded pc
    // slot and stop dispatch. Register them explicitly so a reached one is
    // lifted as a terminal instead of failing as an unknown preamble.
    let mut short_handlers = BTreeSet::new();
    for &(family, fn_line) in &definitions {
        let fn_idx = fn_line - 1;
        if fn_idx + 2 >= lines.len() {
            continue;
        }
        let s0 = lines[fn_idx + 1].trim();
        let s1 = lines[fn_idx + 2].trim();
        let assigns = match (parse_stmt(s0), parse_stmt(s1)) {
            (Ok(Stmt::Assign(targets, value)), Ok(Stmt::Return)) if targets.len() == 1 => {
                matches!(targets[0], Expr::Index(ref t, ref i)
                    if matches!(t.as_ref(), Expr::Ident(_))
                        && matches!(i.as_ref(), Expr::Ident(_)))
                    && matches!(value, Expr::Index(ref t2, ref i2)
                        if matches!(t2.as_ref(), Expr::Ident(_))
                            && matches!(i2.as_ref(), Expr::Ident(_)))
            }
            _ => false,
        };
        if assigns {
            short_handlers.insert(family);
        }
    }

    let mut handlers = BTreeMap::new();
    for (idx, &(family, fn_line)) in definitions.iter().enumerate() {
        let scan_end = definitions
            .get(idx + 1)
            .map(|&(_, next)| next - 1)
            .unwrap_or(fn_line + 700);
        if let Ok(model) = build_family(family, &lines, fn_line - 1, scan_end) {
            handlers.insert(family, model);
        }
        // Families whose preamble does not resolve (the short exit handlers)
        // are intentionally absent: lifting them reports an explicit error,
        // mirroring the reference walk's unexpected-handler failure.
    }

    // Parse the selector-table rows used by helper 19: any definition of the
    // Parse the selector-table rows used by helper 19: any definition of the
    // form `<table>[<tag>] = { <int>, <int>, <int>, <int> }` (possibly
    // spanning multiple source lines, as in the deobfuscated source).
    let mut jump_rows = BTreeMap::new();
    let mut i = 0;
    while i < lines.len() {
        let stripped = lines[i].trim_start();
        let bracket = match stripped.find('[') {
            Some(b) => b,
            None => {
                i += 1;
                continue;
            }
        };
        let name = &stripped[..bracket];
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            i += 1;
            continue;
        }
        let close = match stripped[bracket..].find(']') {
            Some(c) => bracket + c,
            None => {
                i += 1;
                continue;
            }
        };
        let tag: i64 = match stripped[bracket + 1..close].parse() {
            Ok(v) => v,
            Err(_) => {
                i += 1;
                continue;
            }
        };
        let rest = stripped[close + 1..].trim_start();
        let rest = match rest.strip_prefix('=') {
            Some(r) => r.trim_start(),
            None => {
                i += 1;
                continue;
            }
        };
        let rest = match rest.strip_prefix('{') {
            Some(r) => r,
            None => {
                i += 1;
                continue;
            }
        };
        let mut buf = rest.to_owned();
        let mut j = i;
        while !buf.contains('}') && j + 1 < lines.len() {
            j += 1;
            buf.push(' ');
            buf.push_str(lines[j].trim());
        }
        let shut = match buf.find('}') {
            Some(s) => s,
            None => {
                i += 1;
                continue;
            }
        };
        let inner = &buf[..shut];
        let mut parts = [0i64; 4];
        let mut ok = true;
        for (slot, piece) in inner.split(',').enumerate() {
            if slot < 4 {
                match piece.trim().parse::<i64>() {
                    Ok(v) => parts[slot] = v,
                    Err(_) => ok = false,
                }
            }
        }
        if ok {
            jump_rows.insert(tag, parts);
        }
        i = j + 1;
    }

    Ok(SourceModel {
        lines,
        handlers,
        jump_rows,
        short_handlers,
    })
}

// ---------------------------------------------------------------------------
// Leaf selection: walk the comparison tree for one selector value.
// ---------------------------------------------------------------------------

/// Matches `if <a> <cmp> <b> then` against the selector when the line is a
/// comparison node over the discriminator; `None` marks a leaf body.
fn branch_matches(line: &str, disc: &str, selector: i64) -> Result<Option<bool>, String> {
    let stripped = line.trim();
    let Some(rest) = stripped.strip_prefix("if ") else {
        return Ok(None);
    };
    let Some(rest) = rest.strip_suffix(" then") else {
        return Ok(None);
    };
    for cmp in ["<=", ">=", "<", ">"] {
        if let Some((left, right)) = rest.split_once(cmp) {
            let left = left.trim();
            let right = right.trim();
            if left == disc && is_plain_int(right) {
                let bound: i64 = right.parse().unwrap();
                return Ok(Some(compare(cmp, selector, bound)));
            }
            if right == disc && is_plain_int(left) {
                let bound: i64 = left.parse().unwrap();
                return Ok(Some(compare(cmp, bound, selector)));
            }
            // An if-line not over the discriminator starts a leaf body.
            return Ok(None);
        }
    }
    Ok(None)
}

fn is_plain_int(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    !digits.is_empty()
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && text.parse::<i64>().is_ok()
}

fn compare(op: &str, left: i64, right: i64) -> bool {
    match op {
        "<" => left < right,
        ">" => left > right,
        "<=" => left <= right,
        ">=" => left >= right,
        _ => false,
    }
}

/// Walks the comparison tree from the family root to the leaf implementing
/// `selector` and returns its inclusive 1-based line range.
fn find_leaf(
    model: &SourceModel,
    fam: &FamilyModel,
    selector: i64,
) -> Result<(usize, usize), String> {
    let at = |n: usize| -> &str { model.lines.get(n - 1).map(|s| s.as_str()).unwrap_or("") };
    let indent = |n: usize| -> usize { at(n).len() - at(n).trim_start().len() };

    let mut n = fam.root_line;
    loop {
        let Some(selected) = branch_matches(at(n), &fam.disc_ident, selector)? else {
            // Leaf body: extend to the end of the nested block.
            let mut end = n;
            while end <= model.lines.len() && indent(end) >= indent(n) {
                end += 1;
            }
            return Ok((n, end.saturating_sub(1)));
        };
        if selected {
            n += 1;
        } else {
            let base = indent(n);
            n += 1;
            loop {
                if n > model.lines.len() {
                    return Err("comparison tree ran past the end of the source".to_owned());
                }
                let text = at(n).trim();
                if indent(n) == base && (text == "else" || text == "end" || text == "end;") {
                    break;
                }
                n += 1;
            }
            if at(n).trim() != "else" {
                return Err(format!(
                    "comparison node at line {n} has no else arm; the tree walk is unsupported"
                ));
            }
            n += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Static leaf evaluation
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum Value {
    Int(i64),
    Reg(u16),
    Str(Vec<u8>),
    Global(Vec<Vec<u8>>),
    Expr(Box<ValueExpression>),
    Bin {
        op: BinaryOp,
        left: Box<Value>,
        right: Box<Value>,
    },
    /// A pending table read that becomes `GetTable` once a destination
    /// register exists.
    FieldRead {
        table: Box<Value>,
        index: Box<Value>,
    },
    NewTable {
        packed: bool,
    },
    /// A value that this lifter declines to interpret; the payload documents
    /// what was unresolvable for diagnostics.
    Unresolved(#[allow(dead_code)] String),
}

struct EvalCtx<'a> {
    vm: &'a DecodedVm,
    fam: &'a FamilyModel,
    state: &'a VmState,
    /// Leaf-local temporaries.
    locals: BTreeMap<String, Value>,
    /// Highest word offset `pc + k` referenced while evaluating the leaf.
    max_offset: usize,
    /// For entry-window leaves: the destination slot and source argument index
    /// of the parameter copy, when it can be proven.
    entry_argument: Option<(u16, usize)>,
}

impl<'a> EvalCtx<'a> {
    fn eval(&mut self, expr: &Expr) -> Result<Value, String> {
        match expr {
            Expr::Int(v) => Ok(Value::Int(*v)),
            Expr::Ident(name) => {
                if let Some(value) = self.resolve_ident(name) {
                    Ok(value)
                } else {
                    Ok(Value::Unresolved(name.clone()))
                }
            }
            Expr::Neg(inner) => match self.eval(inner)? {
                Value::Int(v) => Ok(Value::Int(-v)),
                _ => Ok(Value::Unresolved("negate".to_owned())),
            },
            Expr::Len(inner) => {
                let value = self.eval(inner)?;
                match value {
                    Value::Reg(slot) => Ok(Value::Expr(Box::new(ValueExpression::Unary {
                        op: UnaryOp::Length,
                        value: Operand::Register(Register {
                            physical_slot: slot,
                        }),
                    }))),
                    Value::Expr(expr) => Ok(Value::Expr(Box::new(ValueExpression::Unary {
                        op: UnaryOp::Length,
                        value: Operand::Expression(expr),
                    }))),
                    Value::Int(_) => Ok(Value::Unresolved("length of number".to_owned())),
                    _ => Ok(Value::Unresolved("length".to_owned())),
                }
            }
            Expr::Table(fields) if fields.is_empty() => Ok(Value::NewTable { packed: false }),
            Expr::Table(fields)
                if fields.len() == 1
                    && fields[0].0.as_deref() == Some("n")
                    && matches!(fields[0].1, Expr::Int(0)) =>
            {
                Ok(Value::NewTable { packed: true })
            }
            Expr::Table(_) => Ok(Value::Unresolved("nonempty table constructor".to_owned())),
            Expr::Index(table, index) => self.eval_index(table, index),
            Expr::Call(target, args) => self.eval_call(target, args),
            Expr::Bin(kind, left, right) => self.eval_bin(*kind, left, right),
        }
    }

    fn resolve_ident(&self, name: &str) -> Option<Value> {
        if let Some(value) = self.locals.get(name) {
            return Some(value.clone());
        }
        if name == self.fam.pc {
            return Some(Value::Int(self.state.pc as i64));
        }
        if name == self.fam.key {
            return Some(Value::Int(self.state.key_state as i64));
        }
        if name == self.fam.salt {
            return Some(Value::Int(self.state.prototype_salt as i64));
        }
        if name == self.fam.bank {
            return Some(Value::Int(self.state.bank_base as i64));
        }
        if let Some(offset) = self.fam.aliases.iter().position(|a| a == name) {
            let index = self.state.bank_base as usize + offset + 1;
            let slot = *self
                .vm
                .slot_map
                .get(index)
                .ok_or_else(|| format!("alias slot map index {index} is out of range"))
                .ok()?;
            return Some(Value::Int(slot as i64));
        }
        None
    }

    fn word_at(&mut self, offset: usize) -> Result<i64, String> {
        if offset > self.max_offset {
            self.max_offset = offset;
        }
        let position = self.state.pc + offset;
        let word = self
            .vm
            .decoded_words
            .get(position)
            .cloned()
            .flatten()
            .ok_or_else(|| format!("word {position} is not decoded"))?;
        Ok(word as i64)
    }

    fn eval_index(&mut self, table: &Expr, index: &Expr) -> Result<Value, String> {
        if let Expr::Ident(name) = table {
            if name == &self.fam.words {
                // Word reference `words[pc + k]`.
                if let Expr::Ident(idx) = index {
                    if idx == &self.fam.pc {
                        return Ok(Value::Int(self.word_at(0)?));
                    }
                }
                if let Expr::Bin(BinKind::Add, base, off) = index {
                    if let (Expr::Ident(idx), Expr::Int(k)) = (base.as_ref(), off.as_ref()) {
                        if idx == &self.fam.pc {
                            if *k < 0 || *k > 4096 {
                                return Err(format!("word offset {k} is out of range"));
                            }
                            return Ok(Value::Int(self.word_at(*k as usize)?));
                        }
                    }
                }
                return Ok(Value::Unresolved("word index".to_owned()));
            }
            if name == &self.fam.slots {
                let Value::Int(position) = self.eval(index)? else {
                    return Ok(Value::Unresolved("slot map index".to_owned()));
                };
                if position < 0 || (position as usize) >= self.vm.slot_map.len() {
                    return Err(format!("slot map index {position} is out of range"));
                }
                let slot = *self
                    .vm
                    .slot_map
                    .get(position as usize)
                    .ok_or_else(|| format!("slot map index {position} is out of range"))?;
                return Ok(Value::Int(slot as i64));
            }
            if name == &self.fam.bias {
                let Value::Int(position) = self.eval(index)? else {
                    return Ok(Value::Unresolved("bias index".to_owned()));
                };
                if position < 0 || (position as usize) >= self.vm.immediate_biases.len() {
                    return Err(format!("bias index {position} is out of range"));
                }
                return Ok(Value::Int(
                    self.vm.immediate_biases[position as usize] as i64,
                ));
            }
            if name == &self.fam.frame {
                match self.eval(index)? {
                    Value::Int(slot) if (0..=65535).contains(&slot) => {
                        return Ok(Value::Reg(slot as u16))
                    }
                    _ => return Ok(Value::Unresolved("frame index".to_owned())),
                }
            }
            // Global environment access: an unknown table indexed by a string
            // reference chains into a path (env["table"]["concat"]).
            if !self.locals.contains_key(name)
                && name != &self.fam.frame
                && name != &self.fam.words
                && name != &self.fam.slots
                && name != &self.fam.bias
            {
                if let Ok(Value::Str(bytes)) = self.eval(index) {
                    return Ok(Value::Global(vec![bytes]));
                }
            }
        }
        let table = self.eval(table)?;
        let index = self.eval(index)?;
        if let (Value::Global(path), Value::Str(bytes)) = (&table, &index) {
            let mut path = path.clone();
            path.push(bytes.clone());
            return Ok(Value::Global(path));
        }
        if matches!(table, Value::Unresolved(_)) {
            return Ok(table);
        }
        Ok(Value::FieldRead {
            table: Box::new(table),
            index: Box::new(index),
        })
    }

    fn eval_call(&mut self, target: &Expr, args: &[Expr]) -> Result<Value, String> {
        if let Expr::Ident(name) = target {
            if name == "var58" {
                // bit32-style bxor over the arguments.
                let mut acc: i64 = 0;
                for arg in args {
                    match self.eval(arg)? {
                        Value::Int(v) => acc ^= v & 0xFFFF_FFFF,
                        _ => return Ok(Value::Unresolved("bxor over non-number".to_owned())),
                    }
                }
                return Ok(Value::Int(acc));
            }
            if name == "var33" {
                // String constant decoder: var33(encoded_reference).
                if let Some(arg) = args.first() {
                    if let Ok(Value::Int(reference)) = self.eval(arg) {
                        if let Some(constant) = self
                            .vm
                            .strings
                            .iter()
                            .find(|s| s.encoded_reference == reference as u32)
                        {
                            return Ok(Value::Str(constant.value.clone()));
                        }
                    }
                }
                return Ok(Value::Unresolved("string reference".to_owned()));
            }
        }
        Ok(Value::Unresolved("call".to_owned()))
    }

    fn eval_bin(&mut self, kind: BinKind, left: &Expr, right: &Expr) -> Result<Value, String> {
        let left_value = self.eval(left)?;
        let right_value = self.eval(right)?;
        if let (Value::Int(a), Value::Int(b)) = (&left_value, &right_value) {
            if !kind.is_compare() {
                let result = match kind {
                    BinKind::Add => a.checked_add(*b),
                    BinKind::Sub => a.checked_sub(*b),
                    BinKind::Mul => a.checked_mul(*b),
                    BinKind::Mod => {
                        if *b <= 0 {
                            None
                        } else {
                            Some(a.rem_euclid(*b))
                        }
                    }
                    _ => None,
                };
                if let Some(result) = result {
                    return Ok(Value::Int(result));
                }
            }
        }
        // Fold additive identities so `0 + reg` stays a symbolic register.
        if kind == BinKind::Add {
            if let Value::Int(0) = left_value {
                return Ok(right_value);
            }
            if let Value::Int(0) = right_value {
                return Ok(left_value);
            }
        }
        if kind == BinKind::Sub {
            if let Value::Int(0) = right_value {
                return Ok(left_value);
            }
        }
        let symbolic = matches!(
            left_value,
            Value::Reg(_) | Value::Bin { .. } | Value::FieldRead { .. }
        ) || matches!(
            right_value,
            Value::Reg(_) | Value::Bin { .. } | Value::FieldRead { .. }
        );
        if symbolic || kind.is_compare() {
            return Ok(Value::Bin {
                op: kind.to_ir(),
                left: Box::new(left_value),
                right: Box::new(right_value),
            });
        }
        Ok(Value::Unresolved("binary".to_owned()))
    }
}

fn operand_of(value: &Value) -> Option<Operand> {
    match value {
        Value::Int(v) => Some(Operand::Constant(Constant::Integer(*v))),
        Value::Reg(slot) => Some(Operand::Register(Register {
            physical_slot: *slot,
        })),
        Value::Str(bytes) => Some(Operand::Constant(Constant::String(bytes.clone()))),
        Value::Global(path) => Some(Operand::Global(path.clone())),
        Value::Expr(expr) => Some(Operand::Expression(expr.clone())),
        Value::Bin { op, left, right } => {
            let left_op = operand_of(left)?;
            let right_op = operand_of(right)?;
            Some(Operand::Expression(Box::new(ValueExpression::Binary {
                op: *op,
                left: left_op,
                right: right_op,
            })))
        }
        Value::FieldRead { table, index } => {
            let table_op = operand_of(table)?;
            let index_op = operand_of(index)?;
            Some(Operand::Expression(Box::new(ValueExpression::Index {
                table: table_op,
                index: index_op,
            })))
        }
        Value::NewTable { .. } | Value::Unresolved(_) => None,
    }
}

fn is_compare_op(op: BinaryOp) -> bool {
    matches!(
        op,
        BinaryOp::Equal
            | BinaryOp::NotEqual
            | BinaryOp::Less
            | BinaryOp::LessEqual
            | BinaryOp::Greater
            | BinaryOp::GreaterEqual
    )
}

/// Converts an operand expression, preferring the frame slot a temporary was
/// stored into when its value is a computed expression (branch predicates
/// read back computed registers).
fn ast_operand(
    ctx: &mut EvalCtx,
    expr: &Expr,
    temp_slots: &BTreeMap<String, u16>,
) -> Option<Operand> {
    if let Expr::Ident(name) = expr {
        if let Some(slot) = temp_slots.get(name) {
            return Some(Operand::Register(Register {
                physical_slot: *slot,
            }));
        }
    }
    match ctx.eval(expr) {
        Ok(value) => operand_of(&value),
        Err(_) => None,
    }
}

/// Builds the branch condition of a helper predicate argument.
fn to_condition(
    ctx: &mut EvalCtx,
    expr: &Expr,
    temp_slots: &BTreeMap<String, u16>,
) -> Option<Condition> {
    if let Expr::Bin(kind, left, right) = expr {
        if kind.is_compare() {
            let left_op = ast_operand(ctx, left, temp_slots)?;
            let right_op = ast_operand(ctx, right, temp_slots)?;
            return Some(Condition::Compare {
                op: kind.to_ir(),
                left: left_op,
                right: right_op,
            });
        }
    }
    let operand = ast_operand(ctx, expr, temp_slots)?;
    Some(Condition::Truthy(operand))
}

// ---------------------------------------------------------------------------
// Control classification and successors
// ---------------------------------------------------------------------------

enum Control {
    /// Program counter increment plus the explicit rolling-key update.
    Next {
        delta: i64,
        multiplier: u32,
        addend: u32,
    },
    /// Entry window: like `Next`, but installing a fresh phase and bank sum.
    Entry {
        delta: i64,
        multiplier: u32,
        addend: u32,
        phase: u32,
        bank_sum: u32,
    },
    /// Helper call with transition arms.
    Helper { id: u32, args: Vec<Expr> },
    /// Return helper that stops dispatch.
    Return { helper: u32, args: Vec<Expr> },
}

fn key_update_shape(value: &Expr, key: &str) -> Option<(u32, u32)> {
    // key = (key * M + A) % 4294967296
    let Expr::Bin(BinKind::Mod, inner, modulus) = value else {
        return None;
    };
    if !matches!(modulus.as_ref(), Expr::Int(4_294_967_296)) {
        return None;
    }
    let Expr::Bin(BinKind::Add, mul, addend) = inner.as_ref() else {
        return None;
    };
    let Expr::Int(a) = addend.as_ref() else {
        return None;
    };
    let Expr::Bin(BinKind::Mul, base, m_expr) = mul.as_ref() else {
        return None;
    };
    let Expr::Int(m) = m_expr.as_ref() else {
        return None;
    };
    if !matches!(base.as_ref(), Expr::Ident(name) if name == key) {
        return None;
    }
    if *m <= 0 || *a <= 0 || *m > u32::MAX as i64 || *a > u32::MAX as i64 {
        return None;
    }
    Some((*m as u32, *a as u32))
}

/// Extracts `(helper id, arguments)` from a call expression targeting the
/// family's helper table.
fn helper_call_parts<'e>(expr: &'e Expr, fam: &FamilyModel) -> Option<(u32, &'e [Expr])> {
    let Expr::Call(target, args) = expr else {
        return None;
    };
    let Expr::Index(table, id_expr) = target.as_ref() else {
        return None;
    };
    let Expr::Ident(name) = table.as_ref() else {
        return None;
    };
    if name != &fam.helpers {
        return None;
    }
    let Expr::Int(h) = id_expr.as_ref() else {
        return None;
    };
    Some((*h as u32, args))
}

fn classify_control(fam: &FamilyModel, stmts: &[Stmt]) -> Result<Control, String> {
    // 1. A three-target helper assignment drives a transition.
    for stmt in stmts {
        let Stmt::Assign(targets, value) = stmt else {
            continue;
        };
        if targets.len() != 3 || !targets.iter().all(|t| matches!(t, Expr::Ident(_))) {
            continue;
        }
        if let Some((id, args)) = helper_call_parts(value, fam) {
            if id == 19 || helper_spec(id).is_some() {
                return Ok(Control::Helper {
                    id,
                    args: args.to_vec(),
                });
            }
            return Err(format!(
                "leaf at the current word calls unexpected helper {id}"
            ));
        }
    }
    // 2. A program counter increment falls through to the next instruction.
    let mut delta: Option<i64> = None;
    let mut key_update: Option<(u32, u32)> = None;
    for stmt in stmts {
        let Stmt::Assign(targets, value) = stmt else {
            continue;
        };
        if targets.len() != 1 {
            continue;
        }
        let Expr::Ident(name) = &targets[0] else {
            continue;
        };
        if name == &fam.pc {
            if let Expr::Bin(BinKind::Add, base, off) = value {
                if let (Expr::Ident(idx), Expr::Int(n)) = (base.as_ref(), off.as_ref()) {
                    if idx == &fam.pc {
                        delta = Some(*n);
                    }
                }
            }
        } else if name == &fam.key {
            if let Some(pair) = key_update_shape(value, &fam.key) {
                key_update = Some(pair);
            }
        }
    }
    if let Some(delta) = delta {
        let (multiplier, addend) =
            key_update.ok_or_else(|| "increment leaf lacks the rolling-key update".to_owned())?;
        return Ok(Control::Next {
            delta,
            multiplier,
            addend,
        });
    }
    // 3. A return helper call stops dispatch.
    for stmt in stmts {
        let Stmt::ExprStmt(expr) = stmt else { continue };
        if let Some((id, args)) = helper_call_parts(expr, fam) {
            if RETURN_HELPERS.contains(&id) {
                return Ok(Control::Return {
                    helper: id,
                    args: args.to_vec(),
                });
            }
        }
    }
    Err("leaf has no supported control transfer".to_owned())
}

/// Sums the helper arguments at `indices` (given in `argNN` numbering).
fn sum_args(ctx: &mut EvalCtx, args: &[Expr], indices: &[u32], cleave: u32) -> Result<i64, String> {
    let mut total: i64 = 0;
    for index in indices {
        let position = index
            .checked_sub(cleave)
            .ok_or_else(|| format!("helper argument {index} precedes signature start {cleave}"))?
            as usize;
        let arg = args
            .get(position)
            .ok_or_else(|| format!("helper argument {index} is missing"))?;
        match ctx.eval(arg)? {
            Value::Int(v) => total = total.checked_add(v).ok_or("helper argument sum overflow")?,
            other => {
                return Err(format!(
                    "helper argument {index} did not resolve to a number ({other:?})"
                ))
            }
        }
    }
    Ok(total)
}

fn wrapping_mul_add(key: u32, multiplier: u32, addend: u32) -> u32 {
    (((key as u64).wrapping_mul(multiplier as u64)).wrapping_add(addend as u64) & 0xFFFF_FFFF)
        as u32
}

fn next_state(
    state: &VmState,
    delta: i64,
    multiplier: u32,
    addend: u32,
) -> Result<VmState, String> {
    let target = state.pc as i64 + delta;
    if target < 0 {
        return Err(format!("next program counter {target} is negative"));
    }
    Ok(VmState {
        pc: target as usize,
        key_state: wrapping_mul_add(state.key_state, multiplier, addend),
        dispatch_token: state.dispatch_token,
        bank_base: state.bank_base,
        phase: state.phase,
        bank_sum: state.bank_sum,
        prototype_salt: state.prototype_salt,
    })
}

fn build_successors(
    vm: &DecodedVm,
    model: &SourceModel,
    state: &VmState,
    control: &Control,
    ctx: &mut EvalCtx,
    const_hints: &BTreeMap<usize, BTreeMap<u16, i64>>,
    tag_slot_out: &mut Option<u16>,
) -> Result<Vec<Successor>, String> {
    match control {
        Control::Next {
            delta,
            multiplier,
            addend,
        } => {
            let next = next_state(state, *delta, *multiplier, *addend)?;
            Ok(vec![Successor {
                label: EdgeLabel::Next,
                target_pc: Some(next.pc),
                state: Some(next),
            }])
        }
        Control::Entry {
            delta,
            multiplier,
            addend,
            phase,
            bank_sum,
        } => {
            let mut next = next_state(state, *delta, *multiplier, *addend)?;
            next.phase = *phase;
            next.bank_sum = *bank_sum;
            Ok(vec![Successor {
                label: EdgeLabel::Next,
                target_pc: Some(next.pc),
                state: Some(next),
            }])
        }
        Control::Helper { id: 19, args } => {
            let base_arg = args
                .first()
                .ok_or_else(|| "helper 19 has no tag base".to_owned())?;
            let base = match ctx.eval(base_arg)? {
                Value::Int(v) => v,
                _ => return Err("helper 19 tag base did not resolve".to_owned()),
            };
            // The tag operand register (argument 4) drives the parity choice.
            *tag_slot_out = match args.get(4) {
                Some(expr) => match ctx.eval(expr) {
                    Ok(Value::Reg(slot)) => Some(slot),
                    _ => None,
                },
                None => None,
            };
            let hint = (*tag_slot_out).and_then(|slot| {
                const_hints
                    .get(&state.pc)
                    .and_then(|m| m.get(&slot).copied())
            });
            let parity =
                hint.and_then(|v| vm.permutation_parity.get(&((v & 16_383) as u16)).copied());
            let tags: Vec<i64> = match parity {
                Some(p) if hint.is_some() => vec![base, base + 1 + i64::from(p)],
                _ => vec![base, base + 1, base + 2],
            };
            let mut out = Vec::new();
            for tag in tags {
                let row = model
                    .jump_rows
                    .get(&tag)
                    .ok_or_else(|| format!("selector-table row {tag} is missing"))?;
                let next = rotate(
                    state,
                    state.pc as i64 + row[0],
                    state.key_state as i64 + row[1],
                    row[2],
                    row[3],
                )?;
                out.push(Successor {
                    label: EdgeLabel::Case(tag),
                    target_pc: Some(next.pc),
                    state: Some(next),
                });
            }
            Ok(out)
        }
        Control::Helper { id, args } => {
            let spec = helper_spec(*id)
                .ok_or_else(|| format!("helper {id} has no transition specification"))?;
            let mut out = Vec::new();
            for helper_arm in spec.arms {
                let pc = sum_args(ctx, args, helper_arm.pc, spec.cleave)?;
                let key = sum_args(ctx, args, helper_arm.key, spec.cleave)?;
                let token = sum_args(ctx, args, helper_arm.token, spec.cleave)?;
                let phase = sum_args(ctx, args, helper_arm.phase, spec.cleave)?;
                let next = rotate(state, pc, key, token, phase)?;
                out.push(Successor {
                    label: helper_arm.label.clone(),
                    target_pc: Some(next.pc),
                    state: Some(next),
                });
            }
            Ok(out)
        }
        Control::Return { .. } => Ok(vec![Successor {
            label: EdgeLabel::Return,
            target_pc: None,
            state: None,
        }]),
    }
}

// ---------------------------------------------------------------------------
// Leaf statement lowering
// ---------------------------------------------------------------------------

struct LeafBody {
    instructions: Vec<Instruction>,
    /// Physical slot -> constant stored by this instruction.
    effects: BTreeMap<u16, i64>,
    /// Temporaries that were also stored into a frame register.
    temp_slots: BTreeMap<String, u16>,
    modeled: bool,
    /// State register of a numeric-for increment statement, when present.
    forloop_state: Option<u16>,
}

impl LeafBody {
    fn new() -> Self {
        LeafBody {
            instructions: Vec::new(),
            effects: BTreeMap::new(),
            temp_slots: BTreeMap::new(),
            modeled: true,
            forloop_state: None,
        }
    }
    fn raw(&mut self) {
        self.modeled = false;
    }
}

fn is_bookkeeping_ident(fam: &FamilyModel, name: &str) -> bool {
    name == fam.bank
        || name == fam.bank_sum
        || name == fam.token
        || name == fam.salt
        || fam.aliases.iter().any(|a| a == name)
        || fam.bookkeeping.iter().any(|b| b == name)
}

/// Emits a symbolic binary tree as sequential `Binary` instructions writing
/// into `dst`; a nested side computes into `dst` first.
fn emit_bin_tree(body: &mut LeafBody, dst: &Register, value: &Value) {
    let Value::Bin { op, left, right } = value else {
        body.raw();
        return;
    };
    if matches!(left.as_ref(), Value::Bin { .. }) && matches!(right.as_ref(), Value::Bin { .. }) {
        // Computing both sides through one destination would clobber the
        // first result; leave such leaves explicit as Raw.
        body.raw();
        return;
    }
    let left_op = match operand_of(left) {
        Some(op) => op,
        None => {
            emit_bin_tree(body, dst, left);
            Operand::Register(dst.clone())
        }
    };
    let right_op = match operand_of(right) {
        Some(op) => op,
        None => {
            emit_bin_tree(body, dst, right);
            Operand::Register(dst.clone())
        }
    };
    body.instructions.push(Instruction::Binary {
        op: *op,
        dst: dst.clone(),
        left: left_op,
        right: right_op,
    });
}

/// Resolves the closure capture operands of a child prototype relative to
/// the current bank. Unresolvable operands stay explicit as `Unknown`.
fn closure_captures(vm: &DecodedVm, state: &VmState, word: u32) -> Vec<Operand> {
    let Some(proto) = vm.prototypes.iter().find(|p| p.word as u32 == word) else {
        return Vec::new();
    };
    proto
        .captures
        .iter()
        .map(|capture| {
            let index = state.bank_base as usize + capture.source_operand as usize;
            match vm.slot_map.get(index) {
                Some(&slot) => Operand::Register(Register {
                    physical_slot: slot,
                }),
                None => Operand::Unknown(capture.source_operand as u32),
            }
        })
        .collect()
}

/// Lowers one data store `frame[slots[index]] = value`.
fn store_data(
    ctx: &mut EvalCtx,
    body: &mut LeafBody,
    fam: &FamilyModel,
    index: &Expr,
    value_expr: &Expr,
) {
    let position = match ctx.eval(index) {
        Ok(Value::Int(v)) if v > 0 && (v as usize) < ctx.vm.slot_map.len() => v as usize,
        _ => {
            body.raw();
            return;
        }
    };
    let slot = ctx.vm.slot_map[position];
    let dst = Register {
        physical_slot: slot,
    };

    // Template: closure creation through helper 12.
    if let Some((12, args)) = helper_call_parts(value_expr, fam) {
        if args.len() >= 2 {
            if let Ok(Value::Int(encoded)) = ctx.eval(&args[1]) {
                let word = (encoded as u32) ^ PROTOTYPE_MASK;
                let captures = closure_captures(ctx.vm, ctx.state, word);
                body.instructions.push(Instruction::NewClosure {
                    dst: dst.clone(),
                    prototype_word: word as usize,
                    captures,
                });
                return;
            }
        }
    }

    // Template: packed call result stored to a register.
    if let Expr::Call(target, wrap_args) = value_expr {
        if matches!(target.as_ref(), Expr::Ident(_)) && wrap_args.len() == 1 {
            if let Expr::Call(inner_target, call_args) = &wrap_args[0] {
                if let Expr::Index(table, _) = inner_target.as_ref() {
                    if let Expr::Ident(name) = table.as_ref() {
                        if name == &fam.frame {
                            if let Ok(Value::Reg(function)) = ctx.eval(inner_target) {
                                let mut operands = Vec::new();
                                let mut ok = true;
                                for arg in call_args {
                                    match ctx.eval(arg) {
                                        Ok(value) => match operand_of(&value) {
                                            Some(op) => operands.push(op),
                                            None => ok = false,
                                        },
                                        Err(_) => ok = false,
                                    }
                                }
                                if ok {
                                    body.instructions.push(Instruction::Call {
                                        dst: Some(dst.clone()),
                                        function: Operand::Register(Register {
                                            physical_slot: function,
                                        }),
                                        args: operands,
                                        result_count: None,
                                    });
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let value = match ctx.eval(value_expr) {
        Ok(value) => value,
        Err(_) => {
            body.raw();
            return;
        }
    };
    match &value {
        Value::Int(v) => {
            body.instructions.push(Instruction::LoadConst {
                dst: dst.clone(),
                value: Constant::Integer(*v),
            });
            body.effects.insert(slot, *v);
        }
        Value::Reg(src) => {
            body.instructions.push(Instruction::Move {
                dst: dst.clone(),
                src: Operand::Register(Register {
                    physical_slot: *src,
                }),
            });
        }
        Value::Str(bytes) => {
            body.instructions.push(Instruction::LoadConst {
                dst: dst.clone(),
                value: Constant::String(bytes.clone()),
            });
        }
        Value::Global(path) => {
            body.instructions.push(Instruction::Move {
                dst: dst.clone(),
                src: Operand::Global(path.clone()),
            });
        }
        Value::Expr(expr) => {
            body.instructions.push(Instruction::Move {
                dst: dst.clone(),
                src: Operand::Expression(expr.clone()),
            });
        }
        Value::NewTable { packed } => {
            body.instructions.push(if *packed {
                Instruction::NewPackedTable { dst: dst.clone() }
            } else {
                Instruction::NewTable { dst: dst.clone() }
            });
        }
        Value::FieldRead { table, index } => match (operand_of(table), operand_of(index)) {
            (Some(table_op), Some(index_op)) => {
                body.instructions.push(Instruction::GetTable {
                    dst: dst.clone(),
                    table: table_op,
                    index: index_op,
                });
            }
            _ => body.raw(),
        },
        Value::Bin { op, left, right } if is_compare_op(*op) => {
            match (operand_of(left), operand_of(right)) {
                (Some(left_op), Some(right_op)) => {
                    body.instructions.push(Instruction::Binary {
                        op: *op,
                        dst: dst.clone(),
                        left: left_op,
                        right: right_op,
                    });
                }
                _ => body.raw(),
            }
        }
        Value::Bin { .. } => emit_bin_tree(body, &dst, &value),
        Value::Unresolved(_) => body.raw(),
    }
    if let Expr::Ident(name) = value_expr {
        body.temp_slots.insert(name.clone(), slot);
        if let Value::NewTable { .. } = value {
            ctx.locals.insert(name.clone(), Value::Reg(slot));
        }
    }
}

/// `t[#t + k] = value` with `t` bound to a register: append at end of list.
fn try_append(ctx: &mut EvalCtx, body: &mut LeafBody, target: &Expr, value: &Expr) -> bool {
    let Expr::Index(table, index) = target else {
        return false;
    };
    let Expr::Ident(temp) = table.as_ref() else {
        return false;
    };
    let Expr::Bin(BinKind::Add, len_side, append_offset) = index.as_ref() else {
        return false;
    };
    if !matches!(ctx.eval(append_offset), Ok(Value::Int(1))) {
        return false;
    }
    let Expr::Len(len_inner) = len_side.as_ref() else {
        return false;
    };
    let Expr::Ident(len_of) = len_inner.as_ref() else {
        return false;
    };
    if temp != len_of {
        return false;
    }
    let Some(Value::Reg(slot)) = ctx.locals.get(temp).cloned() else {
        return false;
    };
    let value_op = match ctx.eval(value) {
        Ok(value) => operand_of(&value),
        Err(_) => None,
    };
    let Some(value_op) = value_op else {
        body.raw();
        return true;
    };
    body.instructions.push(Instruction::Append {
        table: Operand::Register(Register {
            physical_slot: slot,
        }),
        value: value_op,
    });
    true
}

/// `t[1] = t[1] + t[3]` with `t` bound to a register: the numeric-for index
/// increment. Records the state register and stays silent in the body.
fn try_forloop_increment(ctx: &EvalCtx, body: &mut LeafBody, target: &Expr, value: &Expr) -> bool {
    let Expr::Index(table, one) = target else {
        return false;
    };
    let Expr::Ident(temp) = table.as_ref() else {
        return false;
    };
    if !matches!(one.as_ref(), Expr::Int(k) if *k == 1) {
        return false;
    }
    let Some(Value::Reg(slot)) = ctx.locals.get(temp).cloned() else {
        return false;
    };
    let Expr::Bin(BinKind::Add, left, right) = value else {
        return false;
    };
    let reads = |expr: &Expr, element: i64| -> bool {
        let Expr::Index(inner, k) = expr else {
            return false;
        };
        let Expr::Ident(n) = inner.as_ref() else {
            return false;
        };
        n == temp && matches!(k.as_ref(), Expr::Int(v) if *v == element)
    };
    if reads(left, 1) && reads(right, 3) {
        body.forloop_state = Some(slot);
        true
    } else {
        false
    }
}

/// The inline permutation-parity derive: `dst = parity(src)` with a
/// non-numeric fallback, lowered to a typed expression (or a folded constant
/// when the source register is provably constant).
fn try_parity_derive(
    ctx: &mut EvalCtx,
    const_hints: &BTreeMap<usize, BTreeMap<u16, i64>>,
    stmts: &[Stmt],
) -> Option<Instruction> {
    let fam = ctx.fam;
    // Bind leaf locals so slot indices and values resolve.
    for stmt in stmts {
        if let Stmt::Local(names, exprs) = stmt {
            if names.len() == exprs.len() {
                for (name, expr) in names.iter().zip(exprs.iter()) {
                    let value = ctx
                        .eval(expr)
                        .unwrap_or(Value::Unresolved("eval error".to_owned()));
                    ctx.locals.insert(name.clone(), value);
                }
            }
        }
    }
    let mut dst_operand: Option<i64> = None;
    for stmt in stmts {
        if let Stmt::Local(names, exprs) = stmt {
            if names.len() == 1 && exprs.len() == 1 {
                if let Ok(Value::Int(v)) = ctx.eval(&exprs[0]) {
                    if v > 0 {
                        dst_operand = Some(v);
                    }
                }
            }
        }
    }
    let dst_operand = dst_operand?;
    // `local src = <reg>` (the tagged value).
    let mut src_name: Option<String> = None;
    let mut src_slot: Option<u16> = None;
    for stmt in stmts {
        if let Stmt::Local(names, exprs) = stmt {
            if names.len() == 1 && exprs.len() == 1 {
                if let Ok(Value::Reg(slot)) = ctx.eval(&exprs[0]) {
                    src_name = Some(names[0].clone());
                    src_slot = Some(slot);
                }
            }
        }
    }
    let src_name = src_name?;
    let src_slot = src_slot?;
    // The type check `if type(src) == "number" then`.
    let mut saw_type_check = false;
    for stmt in stmts {
        if let Stmt::If(cond) = stmt {
            if let Expr::Bin(BinKind::Eq, left, right) = cond {
                // left must be a type(...) call over src_name
                let left_ok = match left.as_ref() {
                    Expr::Call(target, args) => {
                        if args.len() != 1 {
                            false
                        } else {
                            let target_ok = matches!(target.as_ref(), Expr::Ident(_));
                            let arg_ok = match &args[0] {
                                Expr::Ident(n) => n == &src_name,
                                _ => false,
                            };
                            target_ok && arg_ok
                        }
                    }
                    _ => false,
                };
                let right_ok = matches!(right.as_ref(), Expr::Index(_, i) if matches!(i.as_ref(), Expr::Int(6)));
                if left_ok && right_ok {
                    saw_type_check = true;
                }
            }
        }
    }
    if !saw_type_check {
        return None;
    }
    // Then-branch: `frame[slots[dst_operand]] = <parity expr>` where the
    // outermost call is the parity extractor (band with 1) over src.
    let mut nonnumeric: i64 = 0;
    let mut found_else_value = false;
    let mut parity_expr_ok = false;
    for stmt in stmts {
        if let Stmt::Assign(targets, value) = stmt {
            if targets.len() != 1 {
                continue;
            }
            let Expr::Index(table, slot_index) = &targets[0] else {
                continue;
            };
            let Expr::Ident(frame) = table.as_ref() else {
                continue;
            };
            if frame != &fam.frame {
                continue;
            }
            let Expr::Index(slot_table, index) = slot_index.as_ref() else {
                continue;
            };
            if !matches!(slot_table.as_ref(), Expr::Ident(n) if n == &fam.slots) {
                continue;
            }
            let Ok(Value::Int(pos)) = ctx.eval(index) else {
                continue;
            };
            if pos != ctx.state.bank_base as i64 + dst_operand {
                continue;
            }
            // Then branch: outermost call is band(..., 1).
            if let Expr::Call(_, args) = value {
                if args.len() == 2 {
                    if let Expr::Int(1) = args[1] {
                        if format!("{value:?}").contains(&src_name) {
                            parity_expr_ok = true;
                        }
                    }
                }
            }
            // Else branch: a constant fallback.
            if let Expr::Int(v) = value {
                nonnumeric = *v;
                found_else_value = true;
            }
        }
    }
    if !parity_expr_ok || !found_else_value || !(0..=1).contains(&nonnumeric) {
        return None;
    }
    // Destination physical slot.
    let position = (ctx.state.bank_base as usize) + dst_operand as usize;
    if position == 0 || position >= ctx.vm.slot_map.len() {
        return None;
    }
    let dst_slot = ctx.vm.slot_map[position];
    // Fold when the source register is provably constant.
    if let Some(v) = const_hints
        .get(&ctx.state.pc)
        .and_then(|m| m.get(&src_slot))
        .copied()
    {
        let parity = (0..16384usize)
            .map(|i| *ctx.vm.permutation_parity.get(&(i as u16)).unwrap_or(&0))
            .collect::<Vec<_>>();
        let bit = parity[(v as u32 & 16383) as usize] as i64;
        return Some(Instruction::LoadConst {
            dst: Register {
                physical_slot: dst_slot,
            },
            value: Constant::Integer(bit),
        });
    }
    // Otherwise keep the typed expression for codegen propagation.
    let parity_vec = (0..16384usize)
        .map(|i| *ctx.vm.permutation_parity.get(&(i as u16)).unwrap_or(&0))
        .collect::<Vec<_>>();
    if parity_vec.len() != 16384 {
        return None;
    }
    Some(Instruction::Move {
        dst: Register {
            physical_slot: dst_slot,
        },
        src: Operand::Expression(Box::new(ValueExpression::PermutationParity {
            value: Operand::Register(Register {
                physical_slot: src_slot,
            }),
            parity: parity_vec,
            nonnumeric: nonnumeric as u8,
        })),
    })
}

/// The numeric-for preparation block: normalize bounds, coerce non-numbers,
/// and rebuild the loop state table.
fn try_forprep(
    ctx: &mut EvalCtx,
    stmts: &[Stmt],
    next_target: Option<usize>,
) -> Option<Vec<Instruction>> {
    let target = next_target?;
    let fam = ctx.fam;
    // `local s = <reg>`: the source loop-state table.
    let mut state_temp: Option<String> = None;
    for stmt in stmts {
        if let Stmt::Local(names, exprs) = stmt {
            if names.len() == exprs.len() {
                for (name, expr) in names.iter().zip(exprs.iter()) {
                    let value = ctx.eval(expr).ok()?;
                    ctx.locals.insert(name.clone(), value);
                }
            }
            if names.len() == 1 && exprs.len() == 1 {
                if ctx
                    .eval(&exprs[0])
                    .is_ok_and(|v| matches!(v, Value::Reg(_)))
                {
                    state_temp = Some(names[0].clone());
                }
            }
        }
    }
    let s = state_temp?;
    // `local a, b, c = <reg>, s[1], s[2]`
    let mut loop_names: Option<[String; 3]> = None;
    for stmt in stmts {
        if let Stmt::Local(names, exprs) = stmt {
            if names.len() == 3 && exprs.len() == 3 {
                let element = |expr: &Expr, k: i64| -> bool {
                    let Expr::Index(inner, idx) = expr else {
                        return false;
                    };
                    let Expr::Ident(n) = inner.as_ref() else {
                        return false;
                    };
                    n == &s && matches!(idx.as_ref(), Expr::Int(v) if *v == k)
                };
                if element(&exprs[1], 1)
                    && element(&exprs[2], 2)
                    && ctx
                        .eval(&exprs[0])
                        .is_ok_and(|v| matches!(v, Value::Reg(_)))
                {
                    loop_names = Some([names[0].clone(), names[1].clone(), names[2].clone()]);
                }
            }
        }
    }
    let names = loop_names?;
    // `for i = a, b, c do` around a break.
    let saw_for = stmts.iter().any(|stmt| {
        let Stmt::For(_, from, to, step) = stmt else {
            return false;
        };
        matches!(from, Expr::Ident(a) if a == &names[0])
            && matches!(to, Expr::Ident(b) if b == &names[1])
            && matches!(step, Expr::Ident(c) if c == &names[2])
    });
    if !saw_for || !stmts.iter().any(|stmt| matches!(stmt, Stmt::Break)) {
        return None;
    }
    // Final store `frame[slots[e]] = {a, b, c}` rebuilds the state table.
    for stmt in stmts {
        let Stmt::Assign(targets, value) = stmt else {
            continue;
        };
        let Expr::Table(fields) = value else { continue };
        if fields.len() != 3 || targets.len() != 1 {
            continue;
        }
        let idents: Vec<&String> = fields
            .iter()
            .filter_map(|(_, expr)| match expr {
                Expr::Ident(name) => Some(name),
                _ => None,
            })
            .collect();
        if idents.len() != 3 || idents.iter().zip(names.iter()).any(|(a, b)| *a != b) {
            continue;
        }
        let Expr::Index(table, slot_index) = &targets[0] else {
            continue;
        };
        let Expr::Ident(frame) = table.as_ref() else {
            continue;
        };
        if frame != &fam.frame {
            continue;
        }
        let Expr::Index(slot_table, index_expr) = slot_index.as_ref() else {
            continue;
        };
        if !matches!(slot_table.as_ref(), Expr::Ident(n) if n == &fam.slots) {
            continue;
        }
        if let Ok(Value::Int(position)) = ctx.eval(index_expr) {
            if position > 0 && (position as usize) < ctx.vm.slot_map.len() {
                let slot = ctx.vm.slot_map[position as usize];
                let state = Register {
                    physical_slot: slot,
                };
                let values: Vec<Operand> = fields
                    .iter()
                    .map(|(_, expr)| ctx.eval(expr).ok().and_then(|value| operand_of(&value)))
                    .collect::<Option<_>>()?;
                let mut instructions = vec![Instruction::NewTable { dst: state.clone() }];
                instructions.extend(values.into_iter().map(|value| Instruction::Append {
                    table: Operand::Register(state.clone()),
                    value,
                }));
                instructions.push(Instruction::ForPrep { state, target });
                return Some(instructions);
            }
        }
        return None;
    }
    None
}

/// The packed-result append loop: copy every element of one packed list into
/// another and merge the counters.
fn try_append_loop(ctx: &mut EvalCtx, stmts: &[Stmt]) -> Option<Instruction> {
    for idx in 0..stmts.len() {
        let Stmt::Local(names, exprs) = &stmts[idx] else {
            continue;
        };
        if names.len() != 2 || exprs.len() != 2 {
            continue;
        }
        let dst_slot = match ctx.eval(&exprs[0]) {
            Ok(Value::Reg(slot)) => slot,
            _ => continue,
        };
        let src_slot = match ctx.eval(&exprs[1]) {
            Ok(Value::Reg(slot)) => slot,
            _ => continue,
        };
        let (dst, src) = (&names[0], &names[1]);
        // for i = 1, src.n do dst[dst.n + i] = src[i] end
        let Some(Stmt::For(loop_var, from, to, _)) = stmts.get(idx + 1) else {
            continue;
        };
        if !matches!(from, Expr::Int(1)) {
            continue;
        }
        if !is_field_of(to, src, "n") {
            continue;
        }
        let Some(Stmt::Assign(targets, value)) = stmts.get(idx + 2) else {
            continue;
        };
        if targets.len() != 1 {
            continue;
        }
        let ok_target = match &targets[0] {
            Expr::Index(t_table, t_index) => {
                let base_ok = matches!(t_table.as_ref(), Expr::Ident(n) if n == dst);
                let index_ok = match t_index.as_ref() {
                    Expr::Bin(BinKind::Add, l, r) => {
                        is_field_of(l, dst, "n")
                            && matches!(r.as_ref(), Expr::Ident(v) if v == loop_var)
                    }
                    _ => false,
                };
                base_ok && index_ok
            }
            _ => false,
        };
        let ok_value = match value {
            Expr::Index(table, index) => {
                matches!(table.as_ref(), Expr::Ident(name) if name == src)
                    && matches!(index.as_ref(), Expr::Ident(name) if name == loop_var)
            }
            _ => false,
        };
        if !ok_target || !ok_value {
            continue;
        }
        // dst.n = dst.n + src.n
        let Some(Stmt::Assign(final_targets, final_value)) = stmts.get(idx + 4) else {
            continue;
        };
        let ok_final = final_targets.len() == 1
            && is_field_of(&final_targets[0], dst, "n")
            && matches!(
                final_value,
                Expr::Bin(BinKind::Add, a, b)
                    if is_field_of(a, dst, "n") && is_field_of(b, src, "n")
            );
        if !ok_final {
            continue;
        }
        return Some(Instruction::AppendPacked {
            table: Operand::Register(Register {
                physical_slot: dst_slot,
            }),
            values: Operand::Register(Register {
                physical_slot: src_slot,
            }),
        });
    }
    None
}

/// Generic statement lowering for one leaf.
fn generic_loop(
    ctx: &mut EvalCtx,
    body: &mut LeafBody,
    fam: &FamilyModel,
    stmts: &[Stmt],
    const_hints: &BTreeMap<usize, BTreeMap<u16, i64>>,
) {
    // Inline permutation-parity derive takes precedence over statement-level
    // lowering; it folds when the source register is provably constant.
    if let Some(instruction) = try_parity_derive(ctx, const_hints, stmts) {
        body.instructions.push(instruction);
        return;
    }
    let mut gate: Option<bool> = None;
    let mut idx = 0;
    while idx < stmts.len() {
        let stmt = &stmts[idx];
        match stmt {
            Stmt::Do | Stmt::Else | Stmt::Break => {}
            Stmt::End => gate = None,
            Stmt::Return => {}
            Stmt::Opaque | Stmt::For(..) => body.raw(),
            Stmt::If(cond) => {
                // Entry windows statically gate the parameter copy.
                match cond {
                    Expr::Bin(BinKind::Ne, name, bound)
                        if matches!(bound.as_ref(), Expr::Int(0)) =>
                    {
                        match name.as_ref() {
                            Expr::Ident(ident) => match ctx.resolve_ident(ident) {
                                Some(Value::Int(v)) => gate = Some(v != 0),
                                _ => body.raw(),
                            },
                            _ => body.raw(),
                        }
                    }
                    _ => body.raw(),
                }
            }
            Stmt::Local(names, exprs) => {
                // Pack-append block: local t = <list>; local n = t.n + 1;
                // t.n = n; t[n] = <value>;
                if idx + 3 < stmts.len() {
                    if let Some(append) = try_pack_append_at(ctx, body, stmts, idx) {
                        body.instructions.push(append);
                        idx += 3;
                        idx += 1;
                        continue;
                    }
                }
                if names.len() != exprs.len() {
                    body.raw();
                    idx += 1;
                    continue;
                }
                for (name, expr) in names.iter().zip(exprs.iter()) {
                    let value = match ctx.eval(expr) {
                        Ok(value) => value,
                        Err(_) => {
                            body.raw();
                            Value::Unresolved("eval error".to_owned())
                        }
                    };
                    ctx.locals.insert(name.clone(), value);
                }
            }
            Stmt::Assign(targets, value) => {
                if targets.len() == 1 {
                    let target = &targets[0];
                    match target {
                        Expr::Ident(name) => {
                            if name == &fam.pc
                                || name == &fam.key
                                || is_bookkeeping_ident(fam, name)
                            {
                                // Control lines and handler bookkeeping.
                            } else {
                                body.raw();
                            }
                        }
                        Expr::Index(table, index) => {
                            let Expr::Ident(tname) = table.as_ref() else {
                                body.raw();
                                idx += 1;
                                continue;
                            };
                            if tname == &fam.frame {
                                if let Expr::Index(inner, slot_index) = index.as_ref() {
                                    if matches!(inner.as_ref(), Expr::Ident(n) if n == &fam.slots) {
                                        if gate == Some(false) {
                                            gate = None;
                                            idx += 1;
                                            continue;
                                        }
                                        if let Some((arg_slot, arg_index)) = ctx.entry_argument {
                                            let dst_physical =
                                                ctx.eval(slot_index).ok().and_then(|v| match v {
                                                    Value::Int(pos)
                                                        if pos > 0
                                                            && (pos as usize)
                                                                < ctx.vm.slot_map.len() =>
                                                    {
                                                        Some(ctx.vm.slot_map[pos as usize])
                                                    }
                                                    _ => None,
                                                });
                                            let source_physical =
                                                ctx.eval(value).ok().and_then(|value| {
                                                    if let Value::Reg(slot) = value {
                                                        Some(slot)
                                                    } else {
                                                        None
                                                    }
                                                });
                                            if let Some(destination) = dst_physical
                                                .filter(|_| source_physical == Some(arg_slot))
                                            {
                                                body.instructions.push(Instruction::Move {
                                                    dst: Register {
                                                        physical_slot: destination,
                                                    },
                                                    src: Operand::Argument(arg_index),
                                                });
                                                gate = None;
                                                idx += 1;
                                                continue;
                                            }
                                        }
                                        store_data(ctx, body, fam, slot_index, value);
                                        gate = None;
                                        idx += 1;
                                        continue;
                                    }
                                }
                                // frame[<bookkeeping slot>] = ...
                                idx += 1;
                                continue;
                            }
                            if try_forloop_increment(ctx, body, target, value) {
                                idx += 1;
                                continue;
                            }
                            if try_append(ctx, body, target, value) {
                                idx += 1;
                                continue;
                            }
                            body.raw();
                        }
                        _ => body.raw(),
                    }
                } else {
                    // Multi-assignment: helper unpacking (control) or
                    // bookkeeping rotation.
                    let helper_unpack = helper_call_parts(value, fam).is_some();
                    let bookkeeping = targets.iter().all(|t| {
                        matches!(t, Expr::Ident(n)
                            if is_bookkeeping_ident(fam, n) || n == &fam.pc || n == &fam.key)
                    });
                    if !(helper_unpack || bookkeeping) {
                        body.raw();
                    }
                }
            }
            Stmt::ExprStmt(expr) => {
                // Return-helper calls are the control transfer itself.
                if let Some((id, _)) = helper_call_parts(expr, fam) {
                    if RETURN_HELPERS.contains(&id) {
                        idx += 1;
                        continue;
                    }
                }
                // The value-tag call: TAG(frame, <reg>, const, const).
                if let Expr::Call(target, args) = expr {
                    if matches!(target.as_ref(), Expr::Ident(_)) && args.len() == 4 {
                        if let Expr::Ident(frame) = &args[0] {
                            if frame == &fam.frame {
                                if let Ok(Value::Reg(slot)) = ctx.eval(&args[1]) {
                                    body.instructions.push(Instruction::Tag {
                                        value: Operand::Register(Register {
                                            physical_slot: slot,
                                        }),
                                    });
                                    idx += 1;
                                    continue;
                                }
                            }
                        }
                    }
                }
                body.raw();
            }
        }
        idx += 1;
    }
}

/// Pack-append block: `local t = <list>; local n = t.n + 1;
/// t.n = n; t[n] = <value>;` lowered to one Append.
fn try_pack_append_at(
    ctx: &mut EvalCtx,
    body: &mut LeafBody,
    stmts: &[Stmt],
    idx: usize,
) -> Option<Instruction> {
    // stmts[idx] = local t = <list>
    let Stmt::Local(t_names, t_exprs) = &stmts[idx] else {
        return None;
    };
    if t_names.len() != 1 || t_exprs.len() != 1 {
        return None;
    }
    let t = &t_names[0];
    let list_slot = match ctx.eval(&t_exprs[0]) {
        Ok(Value::Reg(slot)) => slot,
        _ => return None,
    };
    // stmts[idx+1] = local n = t.n + 1
    let Stmt::Local(n_names, n_exprs) = stmts.get(idx + 1)? else {
        return None;
    };
    if n_names.len() != 1 || n_exprs.len() != 1 {
        return None;
    }
    let n = &n_names[0];
    let Expr::Bin(BinKind::Add, left, right) = &n_exprs[0] else {
        return None;
    };
    let Expr::Index(t_inner, n_field) = left.as_ref() else {
        return None;
    };
    if !matches!(t_inner.as_ref(), Expr::Ident(x) if x == t) {
        return None;
    }
    if !matches!(n_field.as_ref(), Expr::Ident(f) if f.as_str() == "n") {
        return None;
    }
    if !matches!(right.as_ref(), Expr::Int(1)) {
        return None;
    }
    // stmts[idx+2] = t.n = n
    let Stmt::Assign(tn_targets, tn_value) = stmts.get(idx + 2)? else {
        return None;
    };
    if tn_targets.len() != 1 {
        return None;
    }
    let Expr::Index(t2, f2) = &tn_targets[0] else {
        return None;
    };
    if !matches!(t2.as_ref(), Expr::Ident(x) if x == t)
        || !matches!(f2.as_ref(), Expr::Ident(f) if f.as_str() == "n")
    {
        return None;
    }
    if !matches!(tn_value, Expr::Ident(x) if x == n) {
        return None;
    }
    // stmts[idx+3] = t[n] = <value>
    let Stmt::Assign(tn_targets2, value_expr) = stmts.get(idx + 3)? else {
        return None;
    };
    if tn_targets2.len() != 1 {
        return None;
    }
    let Expr::Index(t3, n2) = &tn_targets2[0] else {
        return None;
    };
    if !matches!(t3.as_ref(), Expr::Ident(x) if x == t)
        || !matches!(n2.as_ref(), Expr::Ident(x) if x == n)
    {
        return None;
    }
    let value_op = match ctx.eval(value_expr) {
        Ok(v) => operand_of(&v),
        Err(_) => None,
    };
    let Some(value_op) = value_op else {
        body.raw();
        return Some(Instruction::Nop);
    };
    Some(Instruction::PushPacked {
        table: Operand::Register(Register {
            physical_slot: list_slot,
        }),
        value: value_op,
    })
}
// ---------------------------------------------------------------------------
// Public lifting entry point
// ---------------------------------------------------------------------------

/// One lifted dispatcher state.
pub struct LiftOutcome {
    pub decoded: DecodedInstruction,
    /// Inclusive source line range of the leaf that was lifted.
    pub leaf_lines: (usize, usize),
    /// Constant immediates this instruction stores into physical slots.
    pub constant_effects: BTreeMap<u16, i64>,
    /// Physical slots written by this instruction (constant or not), for
    /// constant propagation through the CFG.
    pub writes: BTreeSet<u16>,
    /// Physical slot of the tag operand when this leaf is a selector-table
    /// transition; the walk uses it to derive the parity pruning hints.
    pub tag_operand_slot: Option<u16>,
}

/// Resolves the entry-window leaf (fresh phase and bank sum) for the known
/// `(family, selector)` pairs. Fails explicitly when the shape changed.
fn verify_entry(
    ctx: &mut EvalCtx,
    fam: &FamilyModel,
    stmts: &[Stmt],
) -> Result<(u32, u32), String> {
    // `local param, rekey, window, phase = <word>, <word>, <word>, <word>`
    let mut values: Option<Vec<i64>> = None;
    for stmt in stmts {
        if let Stmt::Local(names, exprs) = stmt {
            if names.len() == 4 && exprs.len() == 4 && values.is_none() {
                let mut resolved = Vec::new();
                let mut ok = true;
                for expr in exprs {
                    match ctx.eval(expr) {
                        Ok(Value::Int(v)) => resolved.push(v),
                        _ => ok = false,
                    }
                }
                if ok {
                    values = Some(resolved);
                }
            }
        }
    }
    let values =
        values.ok_or_else(|| "entry window leaf lacks its four decoded operands".to_owned())?;
    // `bank_sum = 2 * bank + window`
    for stmt in stmts {
        let Stmt::Assign(targets, value) = stmt else {
            continue;
        };
        if targets.len() != 1 {
            continue;
        }
        let Expr::Ident(name) = &targets[0] else {
            continue;
        };
        if name != &fam.bank_sum {
            continue;
        }
        let Expr::Bin(BinKind::Add, left, right) = value else {
            continue;
        };
        let Expr::Bin(BinKind::Mul, two, bank_ident) = left.as_ref() else {
            continue;
        };
        if !matches!(two.as_ref(), Expr::Int(2)) {
            continue;
        }
        let Expr::Ident(bank) = bank_ident.as_ref() else {
            continue;
        };
        if bank != &fam.bank {
            continue;
        }
        // The window operand is the third entry local; its value is already
        // captured, so the identifier only needs to exist.
        if !matches!(right.as_ref(), Expr::Ident(_)) {
            continue;
        }
        let phase = (values[3] & 0xFFFF_FFFF) as u32;
        let bank_sum = ((ctx.state.bank_base as u64)
            .wrapping_mul(2)
            .wrapping_add(values[2] as u64 & 0xFFFF_FFFF)
            & 0xFFFF_FFFF) as u32;
        return Ok((phase, bank_sum));
    }
    Err("entry window leaf lacks the bank sum update".to_owned())
}

/// Lifts one dispatcher state into a decoded instruction.
///
/// `tag_hints` maps a program counter to the statically known tag operand
/// value for selector-table transitions; a missing hint keeps all three
/// selector arms instead of guessing one.
pub fn lift_instruction(
    vm: &DecodedVm,
    model: &SourceModel,
    state: &VmState,
    const_hints: &BTreeMap<usize, BTreeMap<u16, i64>>,
) -> Result<LiftOutcome, String> {
    let family = *vm
        .dispatch_families
        .get(&state.dispatch_token)
        .ok_or_else(|| {
            format!(
                "dispatch token {} has no handler family",
                state.dispatch_token
            )
        })?;
    if model.short_handlers.contains(&family) {
        let pc_slot = *vm
            .slot_map
            .get(1)
            .filter(|slot| **slot != 0)
            .ok_or("missing PC bookkeeping slot")?;
        let bank_slot = *vm
            .slot_map
            .get(6)
            .filter(|slot| **slot != 0)
            .ok_or("missing bank bookkeeping slot")?;
        return Ok(LiftOutcome {
            decoded: DecodedInstruction {
                start_pc: state.pc,
                end_pc: state.pc.checked_add(1).ok_or("short-handler PC overflow")?,
                handler_family: family,
                selector: 0,
                instructions: vec![Instruction::HaltDispatch {
                    pc_slot: Register {
                        physical_slot: pc_slot,
                    },
                    bank_slot: Register {
                        physical_slot: bank_slot,
                    },
                }],
                successors: vec![Successor {
                    label: EdgeLabel::Return,
                    target_pc: None,
                    state: None,
                }],
            },
            leaf_lines: (state.pc, state.pc),
            constant_effects: BTreeMap::new(),
            writes: BTreeSet::from([pc_slot]),
            tag_operand_slot: None,
        });
    }
    let fam = model
        .handlers
        .get(&family)
        .ok_or_else(|| format!("handler family {family} is not present in tbl5"))?;
    let mut ctx = EvalCtx {
        vm,
        fam,
        state,
        locals: BTreeMap::new(),
        max_offset: 0,
        entry_argument: None,
    };

    let selector = match ctx.eval(&fam.disc)? {
        Value::Int(v) => v,
        _ => return Err(format!("handler {family} discriminator did not resolve")),
    };
    let leaf_lines = find_leaf(model, fam, selector)?;

    let mut stmts = Vec::new();
    for n in leaf_lines.0..=leaf_lines.1 {
        let line = &model.lines[n - 1];
        match parse_stmt(line) {
            Ok(stmt) => stmts.push(stmt),
            Err(_) => stmts.push(Stmt::Opaque),
        }
    }

    let mut control = classify_control(fam, &stmts)?;
    let next_values = match &control {
        Control::Next {
            delta,
            multiplier,
            addend,
        } => Some((*delta, *multiplier, *addend)),
        _ => None,
    };
    if let Some((delta, multiplier, addend)) = next_values {
        if ENTRY_WINDOWS.contains(&(family, selector)) {
            let (phase, bank_sum) = verify_entry(&mut ctx, fam, &stmts)?;
            control = Control::Entry {
                delta,
                multiplier,
                addend,
                phase,
                bank_sum,
            };
            let is_argument_entry = vm.prototypes.iter().any(|prototype| {
                prototype.entry_pc == state.pc
                    && prototype.bank_base == state.bank_base
                    && prototype.initial_decode_state.wrapping_add(VALUE_SEED) == state.key_state
                    && (!prototype.fixed_parameter_mode
                        || prototype
                            .fixed_parameter_count
                            .is_some_and(|count| count > 0))
            });
            if is_argument_entry {
                let argument_slot = *vm
                    .slot_map
                    .get(state.bank_base as usize + 1)
                    .ok_or_else(|| "entry argument slot is outside the slot map".to_owned())?;
                ctx.entry_argument = Some((argument_slot, 0));
            }
        }
    }

    let mut tag_slot: Option<u16> = None;
    let successors = build_successors(
        vm,
        model,
        state,
        &control,
        &mut ctx,
        const_hints,
        &mut tag_slot,
    )?;
    let next_target = successors.iter().find_map(|s| s.target_pc);

    // Lower the leaf body; whole-block templates take precedence.
    let mut body = LeafBody::new();
    if matches!(control, Control::Entry { .. }) {
        generic_loop(&mut ctx, &mut body, fam, &stmts, const_hints);
    } else if let Some(prep) = try_forprep(&mut ctx, &stmts, next_target) {
        body.instructions.extend(prep);
    } else if let Some(append) = try_append_loop(&mut ctx, &stmts) {
        body.instructions.push(append);
    } else if let Some(parity) = try_parity_derive(&mut ctx, const_hints, &stmts) {
        body.instructions.push(parity);
    } else {
        generic_loop(&mut ctx, &mut body, fam, &stmts, const_hints);
    }

    // Assemble the control instruction.
    if body.modeled {
        match &control {
            Control::Next {
                multiplier, addend, ..
            }
            | Control::Entry {
                multiplier, addend, ..
            } => {
                body.instructions.push(Instruction::KeyUpdate {
                    multiplier: *multiplier,
                    addend: *addend,
                });
                match next_target {
                    Some(target) => body.instructions.push(Instruction::Jump { target }),
                    None => body.raw(),
                }
            }
            Control::Helper { id: 14, .. } => {
                if let (Some(slot), Some(target)) = (body.forloop_state, next_target) {
                    body.instructions.push(Instruction::ForLoop {
                        state: Register {
                            physical_slot: slot,
                        },
                        target,
                    });
                } else if let Some(target) = next_target {
                    body.instructions.push(Instruction::Jump { target });
                } else {
                    body.raw();
                }
            }
            Control::Helper { id: 23, .. } => match next_target {
                Some(target) => body.instructions.push(Instruction::Jump { target }),
                None => body.raw(),
            },
            Control::Helper { id: 15, args } => {
                // Numeric-for range test over the loop state table.
                let mut state_reg: Option<u16> = None;
                if let Some(idx) = helper_spec(15).and_then(|spec| spec.predicate) {
                    if let Some(expr) = args.get(idx) {
                        if let Ok(Value::Reg(slot)) = ctx.eval(expr) {
                            state_reg = Some(slot);
                        }
                    }
                }
                let in_range = successors
                    .iter()
                    .find(|s| s.label == EdgeLabel::True)
                    .and_then(|s| s.target_pc);
                match (state_reg, in_range) {
                    (Some(slot), Some(target)) => {
                        body.instructions.push(Instruction::ForLoop {
                            state: Register {
                                physical_slot: slot,
                            },
                            target,
                        });
                    }
                    _ => body.raw(),
                }
            }
            Control::Helper { id, args } if matches!(*id, 6 | 20 | 21 | 22) => {
                let mut condition: Option<Condition> = None;
                if let Some(idx) = helper_spec(*id).and_then(|spec| spec.predicate) {
                    if let Some(expr) = args.get(idx) {
                        condition = to_condition(&mut ctx, expr, &body.temp_slots);
                    }
                }
                let then_target = successors
                    .iter()
                    .find(|s| s.label == EdgeLabel::True)
                    .and_then(|s| s.target_pc);
                let else_target = successors
                    .iter()
                    .find(|s| s.label == EdgeLabel::False)
                    .and_then(|s| s.target_pc);
                match (condition, then_target, else_target) {
                    (Some(condition), Some(then_target), Some(else_target)) => {
                        body.instructions.push(Instruction::Branch {
                            condition,
                            then_target,
                            else_target,
                        });
                    }
                    _ => body.raw(),
                }
            }
            Control::Helper { id: 19, args } => {
                // Selector-table transition with a resolved parity hint.
                let base_arg = args
                    .first()
                    .cloned()
                    .ok_or_else(|| "helper 19 has no tag base".to_owned())?;
                let base = match ctx.eval(&base_arg)? {
                    Value::Int(v) => v,
                    _ => 0,
                };
                let arms: Vec<(i64, Option<usize>)> = successors
                    .iter()
                    .filter_map(|s| match s.label {
                        EdgeLabel::Case(tag) => Some((tag, s.target_pc)),
                        _ => None,
                    })
                    .collect();
                let then_target = arms
                    .iter()
                    .find(|(tag, _)| *tag == base)
                    .and_then(|(_, t)| *t);
                let else_target = arms
                    .iter()
                    .find(|(tag, _)| *tag != base)
                    .and_then(|(_, t)| *t);
                let mut condition: Option<Condition> = None;
                if let Some(expr) = args.get(9) {
                    condition = to_condition(&mut ctx, expr, &body.temp_slots);
                }
                match (condition, then_target, else_target, arms.len()) {
                    (Some(condition), Some(then_target), Some(else_target), 2) => {
                        body.instructions.push(Instruction::Branch {
                            condition,
                            then_target,
                            else_target,
                        });
                    }
                    _ => body.raw(),
                }
            }
            Control::Return { helper, args } => {
                let values: Vec<Operand> = match *helper {
                    3 => Vec::new(),
                    5 | 7 => {
                        let idx = if *helper == 5 { 0 } else { 1 };
                        let mut values = Vec::new();
                        if let Some(expr) = args.get(idx) {
                            if let Some(operand) = ast_operand(&mut ctx, expr, &body.temp_slots) {
                                values.push(operand);
                            } else {
                                body.raw();
                            }
                        } else {
                            body.raw();
                        }
                        values
                    }
                    _ => {
                        body.raw();
                        Vec::new()
                    }
                };
                if body.modeled {
                    if *helper == 5 && values.len() == 1 {
                        body.instructions.push(Instruction::ReturnPacked {
                            values: values[0].clone(),
                        });
                    } else {
                        body.instructions.push(Instruction::Return { values });
                    }
                }
            }
            Control::Helper { .. } => body.raw(),
        }
    }

    // The consumed-word span: the increment when the leaf states one,
    // otherwise one past the highest referenced word offset.
    let span = match &control {
        Control::Next { delta, .. } | Control::Entry { delta, .. } if *delta > 0 => *delta as usize,
        _ => ctx.max_offset + 1,
    };
    let end_pc = state
        .pc
        .checked_add(span)
        .filter(|end| *end <= vm.decoded_words.len())
        .ok_or_else(|| format!("instruction at word {} exceeds decoded bounds", state.pc))?;

    if !body.modeled {
        let words: Vec<u32> = vm
            .decoded_words
            .get(state.pc..end_pc)
            .ok_or("invalid raw instruction span")?
            .iter()
            .enumerate()
            .map(|(offset, word)| {
                word.ok_or_else(|| {
                    format!(
                        "raw instruction references absent word {}",
                        state.pc + offset
                    )
                })
            })
            .collect::<Result<_, _>>()?;
        body.effects.clear();
        body.instructions = vec![Instruction::Raw {
            family,
            selector,
            words,
        }];
    }

    // Collect every data slot this instruction writes, so the walker can
    // invalidate constants that do not survive it.
    let mut writes = BTreeSet::new();
    if body
        .instructions
        .iter()
        .any(|instruction| matches!(instruction, Instruction::Raw { .. }))
    {
        writes.extend(vm.slot_map.iter().copied().filter(|slot| *slot != 0));
    }
    for instruction in &body.instructions {
        match instruction {
            Instruction::LoadConst { dst, .. }
            | Instruction::Move { dst, .. }
            | Instruction::Unary { dst, .. }
            | Instruction::Binary { dst, .. }
            | Instruction::GetTable { dst, .. }
            | Instruction::NewTable { dst }
            | Instruction::NewPackedTable { dst }
            | Instruction::NewClosure { dst, .. }
            | Instruction::Concat { dst, .. } => {
                writes.insert(dst.physical_slot);
            }
            Instruction::ForPrep { state, .. } | Instruction::ForLoop { state, .. } => {
                writes.insert(state.physical_slot);
            }
            Instruction::SetTable { table, .. }
            | Instruction::Append { table, .. }
            | Instruction::PushPacked { table, .. }
            | Instruction::AppendPacked { table, .. } => {
                if let Operand::Register(r) = table {
                    writes.insert(r.physical_slot);
                }
            }
            Instruction::Call { dst: Some(dst), .. } => {
                writes.insert(dst.physical_slot);
            }
            _ => {}
        }
    }

    Ok(LiftOutcome {
        decoded: DecodedInstruction {
            start_pc: state.pc,
            end_pc,
            handler_family: family,
            selector,
            instructions: body.instructions,
            successors,
        },
        leaf_lines,
        constant_effects: body.effects,
        writes,
        tag_operand_slot: tag_slot,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_deep_expressions_are_rejected_before_recursive_parsing() {
        assert!(lex(&format!("{}1{}", "(".repeat(129), ")".repeat(129))).is_err());
        assert!(lex(&format!("{}1", "- ".repeat(129))).is_err());
        assert!(lex(&"x".repeat(256 * 1024 + 1)).is_err());
    }

    #[test]
    fn comparison_tree_accepts_signed_literal_bounds() {
        assert!(is_plain_int("-1"));
        assert!(!is_plain_int("-"));
        assert_eq!(
            branch_matches("if selector < -1 then", "selector", -2).unwrap(),
            Some(true)
        );
        assert_eq!(
            branch_matches("if selector < -1 then", "selector", 0).unwrap(),
            Some(false)
        );
    }
}
