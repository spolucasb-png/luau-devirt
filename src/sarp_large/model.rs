//! Bounded source grammar for the certified comparison trees. Parsing a handler
//! is not a semantics proof: active unsupported statements still fail lifting.
use super::{certify, sequence, slot, unique, PROFILE};
use crate::decoder::{scan_quoted, tokenize, Token, TokenKind};
use crate::ir::DecodedVm;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum E {
    Int(i64),
    Number(u64),
    Str(Vec<u8>),
    Id(String),
    Index(Box<E>, Box<E>),
    Call(Box<E>, Vec<E>),
    Bin(String, Box<E>, Box<E>),
    Unary(String, Box<E>),
    Table(Vec<(Option<E>, E)>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum S {
    Local(Vec<String>, Vec<E>),
    Assign(Vec<E>, Vec<E>),
    Do(Vec<S>),
    If(Vec<(E, Vec<S>)>, Vec<S>),
    For(String, E, E, E, Vec<S>),
    Return(Vec<E>),
    Expr(E),
}

pub(super) struct Parser<'a> {
    pub ts: &'a [Token],
    pub source: &'a str,
    pub at: usize,
    depth: usize,
    nodes: usize,
}

impl<'a> Parser<'a> {
    pub fn new(ts: &'a [Token], source: &'a str, at: usize) -> Self {
        Self {
            ts,
            source,
            at,
            depth: 0,
            nodes: 0,
        }
    }
    fn peek(&self) -> &str {
        self.ts.get(self.at).map(|t| t.text.as_str()).unwrap_or("")
    }
    pub fn eat(&mut self, text: &str) -> bool {
        if self.peek() == text {
            self.at += 1;
            true
        } else {
            false
        }
    }
    pub fn expect(&mut self, text: &str) -> Result<(), String> {
        if self.eat(text) {
            Ok(())
        } else {
            Err(format!(
                "{PROFILE}: expected {text}, got {:?} at token {}",
                self.peek(),
                self.at
            ))
        }
    }
    fn enter(&mut self) -> Result<(), String> {
        self.depth += 1;
        self.nodes += 1;
        if self.depth > 96 || self.nodes > 100_000 {
            return Err("large SARP grammar depth/node budget exceeded".to_owned());
        }
        Ok(())
    }
    fn identifier(&mut self) -> Result<String, String> {
        let token = self
            .ts
            .get(self.at)
            .filter(|t| t.kind == TokenKind::Identifier)
            .ok_or_else(|| format!("expected identifier at token {}", self.at))?;
        self.at += 1;
        Ok(token.text.clone())
    }
    fn expressions(&mut self) -> Result<Vec<E>, String> {
        let mut values = vec![self.expr(0)?];
        while self.eat(",") {
            values.push(self.expr(0)?);
            if values.len() > 256 {
                return Err("expression tuple budget exceeded".to_owned());
            }
        }
        Ok(values)
    }
    pub fn expr(&mut self, minimum: u8) -> Result<E, String> {
        self.enter()?;
        let token = self.ts.get(self.at).ok_or("truncated expression")?.clone();
        self.at += 1;
        let mut left = match token.text.as_str() {
            "-" | "not" | "#" => E::Unary(token.text.clone(), Box::new(self.expr(7)?)),
            "(" => {
                let value = self.expr(0)?;
                self.expect(")")?;
                value
            }
            "{" => {
                let mut fields = vec![];
                while !self.eat("}") {
                    let key = if self.eat("[") {
                        let key = self.expr(0)?;
                        self.expect("]")?;
                        self.expect("=")?;
                        Some(key)
                    } else if self.ts.get(self.at + 1).is_some_and(|t| t.text == "=") {
                        let name = self.identifier()?;
                        self.expect("=")?;
                        Some(E::Str(name.into_bytes()))
                    } else {
                        None
                    };
                    fields.push((key, self.expr(0)?));
                    if fields.len() > 4096 {
                        return Err("table field budget exceeded".to_owned());
                    }
                    if !self.eat(",") && !self.eat(";") {
                        self.expect("}")?;
                        break;
                    }
                }
                E::Table(fields)
            }
            _ if token.kind == TokenKind::Number => {
                if let Ok(value) = token.text.parse::<i64>() {
                    E::Int(value)
                } else {
                    let value = token
                        .text
                        .parse::<f64>()
                        .map_err(|_| "unsupported number spelling")?;
                    if !value.is_finite() {
                        return Err("nonfinite source numeric literal".to_owned());
                    }
                    E::Number(value.to_bits())
                }
            }
            _ if token.kind == TokenKind::String => {
                E::Str(scan_quoted(self.source, token.offset)?.0)
            }
            _ if token.kind == TokenKind::Identifier
                || matches!(token.text.as_str(), "nil" | "true" | "false" | "...") =>
            {
                E::Id(token.text.clone())
            }
            _ => return Err(format!("unsupported expression token {:?}", token.text)),
        };
        loop {
            if self.eat("[") {
                let key = self.expr(0)?;
                self.expect("]")?;
                left = E::Index(Box::new(left), Box::new(key));
                continue;
            }
            if self.eat(".") {
                let name = self.identifier()?;
                left = E::Index(Box::new(left), Box::new(E::Str(name.into_bytes())));
                continue;
            }
            if self.eat("(") {
                let args = if self.eat(")") {
                    vec![]
                } else {
                    let values = self.expressions()?;
                    self.expect(")")?;
                    values
                };
                left = E::Call(Box::new(left), args);
                continue;
            }
            let (precedence, right_associative) = match self.peek() {
                "or" => (1, false),
                "and" => (2, false),
                "==" | "~=" | "<" | "<=" | ">" | ">=" => (3, false),
                ".." => (4, true),
                "+" | "-" => (5, false),
                "*" | "/" | "//" | "%" => (6, false),
                "^" => (8, true),
                _ => break,
            };
            if precedence < minimum {
                break;
            }
            let operation = self.peek().to_owned();
            self.at += 1;
            let right = self.expr(precedence + u8::from(!right_associative))?;
            left = E::Bin(operation, Box::new(left), Box::new(right));
        }
        self.depth -= 1;
        Ok(left)
    }
    pub fn block(&mut self) -> Result<Vec<S>, String> {
        self.enter()?;
        let mut body = vec![];
        while !matches!(self.peek(), "" | "end" | "else" | "elseif") {
            if self.eat(";") {
                continue;
            }
            let statement = if self.eat("local") {
                let mut names = vec![self.identifier()?];
                while self.eat(",") {
                    names.push(self.identifier()?);
                }
                let values = if self.eat("=") {
                    self.expressions()?
                } else {
                    vec![]
                };
                S::Local(names, values)
            } else if self.eat("do") {
                let body = self.block()?;
                self.expect("end")?;
                S::Do(body)
            } else if self.eat("if") {
                let mut arms = vec![];
                loop {
                    let condition = self.expr(0)?;
                    self.expect("then")?;
                    arms.push((condition, self.block()?));
                    if !self.eat("elseif") {
                        break;
                    }
                }
                let other = if self.eat("else") {
                    self.block()?
                } else {
                    vec![]
                };
                self.expect("end")?;
                S::If(arms, other)
            } else if self.eat("for") {
                let name = self.identifier()?;
                self.expect("=")?;
                let start = self.expr(0)?;
                self.expect(",")?;
                let end = self.expr(0)?;
                let step = if self.eat(",") {
                    self.expr(0)?
                } else {
                    E::Int(1)
                };
                self.expect("do")?;
                let body = self.block()?;
                self.expect("end")?;
                S::For(name, start, end, step, body)
            } else if self.eat("return") {
                let values = if matches!(self.peek(), "" | ";" | "end" | "else" | "elseif") {
                    vec![]
                } else {
                    self.expressions()?
                };
                S::Return(values)
            } else {
                let targets = self.expressions()?;
                if self.eat("=") {
                    S::Assign(targets, self.expressions()?)
                } else {
                    let [expression] = targets.as_slice() else {
                        return Err("unsupported expression statement tuple".to_owned());
                    };
                    S::Expr(expression.clone())
                }
            };
            body.push(statement);
            if body.len() > 8192 {
                return Err("handler statement budget exceeded".to_owned());
            }
        }
        self.depth -= 1;
        Ok(body)
    }
}

#[derive(Clone, Debug)]
pub(super) struct Family {
    pub selector: E,
    pub tree: S,
    pub metadata: Vec<u16>,
    pub source_first: usize,
    pub source_last: usize,
}

#[derive(Clone, Debug)]
pub(super) struct Helper {
    pub params: Vec<String>,
    pub source_first: usize,
    pub source_last: usize,
}

pub(super) struct Model {
    pub families: BTreeMap<u32, Family>,
    pub helpers: BTreeMap<u32, Helper>,
    pub mo: Vec<S>,
    pub mo2: Vec<S>,
    pub cm: Vec<u16>,
    pub cm2: Vec<u16>,
    pub cm3: Vec<u16>,
}

pub(super) fn contains(expression: &E, name: &str) -> bool {
    match expression {
        E::Id(n) => n == name,
        E::Index(a, b) | E::Bin(_, a, b) => contains(a, name) || contains(b, name),
        E::Unary(_, v) => contains(v, name),
        E::Call(t, args) => contains(t, name) || args.iter().any(|a| contains(a, name)),
        E::Table(fields) => fields
            .iter()
            .any(|(k, v)| k.as_ref().is_some_and(|k| contains(k, name)) || contains(v, name)),
        _ => false,
    }
}

fn function_end(ts: &[Token], at: usize) -> Result<usize, String> {
    let mut stack = vec![("function", false)];
    for (index, token) in ts.iter().enumerate().skip(at + 1) {
        if token.kind == TokenKind::String {
            continue;
        }
        match token.text.as_str() {
            "function" => stack.push(("function", false)),
            "if" => stack.push(("if", false)),
            "repeat" => stack.push(("repeat", false)),
            "for" => stack.push(("for", true)),
            "while" => stack.push(("while", true)),
            "do" => {
                if let Some((_, pending)) = stack.last_mut().filter(|(_, pending)| *pending) {
                    *pending = false;
                } else {
                    stack.push(("do", false));
                }
            }
            "end" | "until" => {
                let (kind, _) = stack.pop().ok_or("unbalanced function body")?;
                if (token.text == "until") != (kind == "repeat") {
                    return Err("mismatched function terminator".to_owned());
                }
                if stack.is_empty() {
                    return Ok(index);
                }
            }
            _ => {}
        }
        if stack.len() > 96 || index - at > 100_000 {
            return Err("function extent budget exceeded".to_owned());
        }
    }
    Err("unterminated handler function".to_owned())
}

impl Model {
    pub fn read(vm: &DecodedVm) -> Result<Self, String> {
        let ts = tokenize(&vm.source_text)?;
        certify(&ts)?;
        let controls = [
            ("C_KD", 15usize),
            ("C_SH", 3),
            ("C_SB2", 7),
            ("C_AP", 9),
            ("C_RN", 17),
            ("C_PS", 18),
            ("C_RBS", 33),
            ("C_RB", 21),
            ("C_SB1", 6),
            ("C_IP", 29),
            ("C_RBE", 24),
            ("C_RV", 2),
            ("C_ST", 23),
            ("C_STOP", 5),
            ("C_EXIT", 12),
        ]
        .into_iter()
        .map(|(name, index)| Ok((name, slot(vm, index)?)))
        .collect::<Result<BTreeMap<_, _>, String>>()?;
        let metadata = |name: &str| -> Result<Vec<u16>, String> {
            let at = unique(&ts, &[name, "=", "{"])? + 2;
            let expression = Parser::new(&ts, &vm.source_text, at).expr(0)?;
            let E::Table(fields) = expression else {
                return Err("invalid metadata table".to_owned());
            };
            fields
                .into_iter()
                .map(|(key, value)| {
                    if key.is_some() {
                        return Err("metadata table is not an ordered list".to_owned());
                    }
                    match value {
                        E::Int(v) => {
                            u16::try_from(v).map_err(|_| "metadata slot out of u16".to_owned())
                        }
                        E::Id(n) => controls
                            .get(n.as_str())
                            .copied()
                            .ok_or_else(|| format!("unknown control role {n}")),
                        _ => Err("nonconstant control metadata".to_owned()),
                    }
                })
                .collect()
        };
        let cm = metadata("CM")?;
        let cm2 = metadata("CM2")?;
        let cm3 = metadata("CM3")?;
        if (cm.len(), cm2.len(), cm3.len()) != (22, 25, 21) {
            return Err("invalid large SARP metadata dimensions".to_owned());
        }
        let mut helpers = BTreeMap::new();
        let mut families = BTreeMap::new();
        for index in 0..ts.len().saturating_sub(7) {
            if !(sequence(&ts, index, &["_h", "["]) || sequence(&ts, index, &["_dr", "["]))
                || !sequence(&ts, index + 3, &["]", "=", "function", "("])
            {
                continue;
            }
            let id = ts[index + 2]
                .text
                .parse::<u32>()
                .map_err(|_| "invalid function id")?;
            let function_end = function_end(&ts, index + 5)?;
            let mut at = index + 7;
            let mut params = vec![];
            while !sequence(&ts, at, &[")"]) {
                let token = ts.get(at).ok_or("truncated function signature")?;
                if token.text != "," {
                    params.push(token.text.clone());
                }
                at += 1;
                if params.len() > 32 {
                    return Err("helper parameter budget exceeded".to_owned());
                }
            }
            if ts[index].text == "_h" {
                if helpers
                    .insert(
                        id,
                        Helper {
                            params,
                            source_first: index,
                            source_last: function_end,
                        },
                    )
                    .is_some()
                {
                    return Err("duplicate helper".to_owned());
                }
                continue;
            }
            let selector_at = (at + 1..function_end.saturating_sub(3))
                .find(|at| sequence(&ts, *at, &["local", "op", "="]))
                .ok_or("missing selector")?;
            let mut parser = Parser::new(&ts, &vm.source_text, selector_at + 3);
            let selector = parser.expr(0)?;
            parser.eat(";");
            parser.expect("if")?;
            let mut arms = vec![];
            loop {
                let condition = parser.expr(0)?;
                parser.expect("then")?;
                arms.push((condition, parser.block()?));
                if !parser.eat("elseif") {
                    break;
                }
            }
            let other = if parser.eat("else") {
                parser.block()?
            } else {
                vec![]
            };
            parser.expect("end")?;
            let metadata = if id == 2094 {
                cm2.clone()
            } else if id == 8415 {
                cm3.clone()
            } else {
                cm.clone()
            };
            if families
                .insert(
                    id,
                    Family {
                        selector,
                        tree: S::If(arms, other),
                        metadata,
                        source_first: index,
                        source_last: parser.at,
                    },
                )
                .is_some()
            {
                return Err("duplicate handler family".to_owned());
            }
        }
        if families.keys().copied().collect::<BTreeSet<_>>()
            != BTreeSet::from([301, 2094, 2380, 2880, 4043, 7559, 8415])
            || helpers.len() != 32
        {
            return Err("incomplete certified handler/helper model".to_owned());
        }
        let parse_operation = |name: &str| -> Result<Vec<S>, String> {
            let at = unique(&ts, &[name, "=", "function", "("])?;
            let begin = (at + 4..ts.len())
                .find(|i| ts[*i].text == ")")
                .ok_or("truncated operation signature")?
                + 1;
            Parser::new(&ts, &vm.source_text, begin).block()
        };
        Ok(Self {
            families,
            helpers,
            mo: parse_operation("MO")?,
            mo2: parse_operation("MO2")?,
            cm,
            cm2,
            cm3,
        })
    }
}
