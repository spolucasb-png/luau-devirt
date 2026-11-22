//! Optional presentation cleanup of an IR-derived statement tree.
//!
//! This is not a source-text rewriter. Binding identities, scalar call
//! projections and branch joins come from the ordinary dataflow emitter.
//! Lookups may invoke metamethods: only adjacent, single-use evaluations move,
//! and only into positions with an identical evaluation order. Calls are never
//! inlined into argument lists (where the last call could expand its tuple).
//! Fresh tables absorb only consecutive, unique literal-key/pure-value writes;
//! no read, escape, allocation or call is crossed.

use super::{binary_op_symbol, render_constant, BinaryOp, Constant, UnaryOp};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

const MAX_EXPRESSION_DEPTH: usize = 128;
const MAX_NODES: usize = 65_536;
const MAX_PASSES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Expr {
    Binding(usize),
    Constant(Constant),
    Environment,
    Unary {
        op: UnaryOp,
        value: Box<Expr>,
    },
    Binary {
        op: BinaryOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    Index {
        table: Box<Expr>,
        index: Box<Expr>,
    },
    Call {
        function: Box<Expr>,
        args: Vec<Expr>,
    },
    /// An explicitly open tuple, permitted only at the end of a call's args.
    /// Ordinary Call expressions remain scalar and are parenthesized there.
    Expand(Box<Expr>),
    Concat(Vec<Expr>),
    Table(Vec<(Expr, Expr)>),
    External(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Statement {
    Local {
        binding: usize,
        annotation: Option<&'static str>,
        value: Option<Expr>,
    },
    Assign {
        binding: usize,
        value: Expr,
    },
    SetTable {
        table: Expr,
        index: Expr,
        value: Expr,
    },
    Call(Expr),
    Return(Vec<Expr>),
    ReturnPacked(Expr),
    If {
        condition: Expr,
        yes: Body,
        no: Body,
    },
    ForNum {
        var: String,
        start: Expr,
        limit: Expr,
        step: Option<Expr>,
        body: Body,
    },
    Comment(String),
}

pub(super) type Body = Vec<Statement>;

impl Expr {
    /// Only captured values/literals, not operations or table allocations.
    fn leaf(&self) -> bool {
        matches!(self, Self::Binding(_) | Self::Environment)
            || matches!(self, Self::Constant(c) if !matches!(c, Constant::Unknown(_)))
    }

    fn children(&self) -> Vec<&Expr> {
        match self {
            Self::Unary { value, .. } => vec![value],
            Self::Binary { left, right, .. } => vec![left, right],
            Self::Index { table, index } => vec![table, index],
            Self::Call { function, args } => {
                let mut result = vec![function.as_ref()];
                result.extend(args);
                result
            }
            Self::Concat(parts) => parts.iter().collect(),
            Self::Expand(value) => vec![value],
            Self::Table(fields) => fields.iter().flat_map(|(k, v)| [k, v]).collect(),
            _ => vec![],
        }
    }

    fn contains(&self, binding: usize) -> bool {
        matches!(self, Self::Binding(id) if *id == binding)
            || self.children().iter().any(|e| e.contains(binding))
    }

    fn depth(&self) -> usize {
        1 + self.children().iter().map(|e| e.depth()).max().unwrap_or(0)
    }
}

#[derive(Default)]
struct Counts {
    uses: BTreeMap<usize, usize>,
    definitions: BTreeMap<usize, usize>,
}

fn count_expr(expr: &Expr, counts: &mut Counts) {
    if let Expr::Binding(id) = expr {
        *counts.uses.entry(*id).or_default() += 1;
    }
    for child in expr.children() {
        count_expr(child, counts);
    }
}

fn counts(body: &[Statement], result: &mut Counts) {
    for statement in body {
        match statement {
            Statement::Local { binding, value, .. } => {
                *result.definitions.entry(*binding).or_default() += 1;
                if let Some(value) = value {
                    count_expr(value, result);
                }
            }
            Statement::Assign { binding, value } => {
                *result.definitions.entry(*binding).or_default() += 1;
                count_expr(value, result);
            }
            Statement::SetTable {
                table,
                index,
                value,
            } => {
                for expr in [table, index, value] {
                    count_expr(expr, result);
                }
            }
            Statement::Call(expr) => count_expr(expr, result),
            Statement::Return(exprs) => {
                for e in exprs {
                    count_expr(e, result);
                }
            }
            Statement::ReturnPacked(expr) => count_expr(expr, result),
            Statement::If { condition, yes, no } => {
                count_expr(condition, result);
                counts(yes, result);
                counts(no, result);
            }
            Statement::ForNum {
                start,
                limit,
                step,
                body,
                ..
            } => {
                count_expr(start, result);
                count_expr(limit, result);
                if let Some(step) = step {
                    count_expr(step, result);
                }
                counts(body, result);
            }
            Statement::Comment(_) => {}
        }
    }
}

fn validate_expr(expr: &Expr, depth: usize, nodes: &mut usize) -> Result<(), String> {
    *nodes += 1;
    if depth > MAX_EXPRESSION_DEPTH || *nodes > MAX_NODES {
        return Err("pretty expression depth/node budget exceeded".to_owned());
    }
    for child in expr.children() {
        validate_expr(child, depth + 1, nodes)?;
    }
    Ok(())
}

fn validate(body: &[Statement], depth: usize, nodes: &mut usize) -> Result<(), String> {
    if depth > 64 {
        return Err("pretty statement nesting exceeds 64".to_owned());
    }
    for statement in body {
        *nodes += 1;
        if *nodes > MAX_NODES {
            return Err("pretty statement node budget exceeded".to_owned());
        }
        match statement {
            Statement::Local {
                value: Some(expr), ..
            }
            | Statement::Assign { value: expr, .. }
            | Statement::Call(expr) => validate_expr(expr, 1, nodes)?,
            Statement::Return(exprs) => {
                for e in exprs {
                    validate_expr(e, 1, nodes)?;
                }
            }
            Statement::ReturnPacked(expr) => validate_expr(expr, 1, nodes)?,
            Statement::SetTable {
                table,
                index,
                value,
            } => {
                for expr in [table, index, value] {
                    validate_expr(expr, 1, nodes)?;
                }
            }
            Statement::If { condition, yes, no } => {
                validate_expr(condition, 1, nodes)?;
                validate(yes, depth + 1, nodes)?;
                validate(no, depth + 1, nodes)?;
            }
            Statement::ForNum {
                start,
                limit,
                step,
                body,
                ..
            } => {
                validate_expr(start, 1, nodes)?;
                validate_expr(limit, 1, nodes)?;
                if let Some(step) = step {
                    validate_expr(step, 1, nodes)?;
                }
                validate(body, depth + 1, nodes)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Fold only the unescaped prefix immediately following a fresh allocation.
/// Aliased registers already share the same binding identity at this stage.
fn constructor(body: &mut Body, position: usize) -> bool {
    let Statement::Local {
        binding,
        value: Some(Expr::Table(fields)),
        ..
    } = &body[position]
    else {
        return false;
    };
    if !fields.is_empty() {
        return false;
    }
    let binding = *binding;
    let mut fields = vec![];
    let mut keys = BTreeSet::new();
    for statement in body.iter().skip(position + 1) {
        let Statement::SetTable {
            table: Expr::Binding(table),
            index: Expr::Constant(Constant::String(key)),
            value,
        } = statement
        else {
            break;
        };
        if *table != binding
            || !value.leaf()
            || value.contains(binding)
            || !keys.insert(key.clone())
        {
            break;
        }
        fields.push((Expr::Constant(Constant::String(key.clone())), value.clone()));
    }
    if fields.is_empty() {
        return false;
    }
    let count = fields.len();
    if let Statement::Local { value, .. } = &mut body[position] {
        *value = Some(Expr::Table(fields));
    }
    body.drain(position + 1..position + 1 + count);
    true
}

/// No general substitution: every allowed sink has only inert evaluations
/// before the replacement and consumes a scalar, exactly once.
fn inline(statement: &mut Statement, binding: usize, replacement: &Expr) -> bool {
    let replace = |value: &mut Expr| {
        if *value == Expr::Binding(binding) {
            *value = replacement.clone();
            true
        } else {
            false
        }
    };
    match statement {
        Statement::Local {
            value: Some(expr), ..
        }
        | Statement::Call(expr) => {
            // Indexing/calling evaluates its receiver/function before its
            // inert index/arguments. Keep scalar calls out of argument lists.
            if replacement.depth() + expr.depth() > MAX_EXPRESSION_DEPTH {
                return false;
            }
            match expr {
                Expr::Index { table, index }
                    if matches!(replacement, Expr::Index { .. }) && index.leaf() =>
                {
                    replace(table)
                }
                Expr::Call { function, args }
                    if matches!(replacement, Expr::Index { .. }) && args.iter().all(Expr::leaf) =>
                {
                    replace(function)
                }
                _ => false,
            }
        }
        Statement::Assign { value, .. } => replace(value),
        Statement::SetTable {
            table,
            index,
            value,
        } if table.leaf() && index.leaf() => replace(value),
        _ => false,
    }
}

fn assignment<'a>(
    arm: &'a [Statement],
    binding: usize,
    initial: &'a Option<Expr>,
) -> Option<&'a Expr> {
    match arm {
        [] => initial.as_ref(),
        [Statement::Assign {
            binding: dst,
            value,
        }] if *dst == binding => Some(value),
        _ => None,
    }
}

/// `c and rhs` is valid only when the false arm returns *c itself*, not a
/// guessed nil. Likewise `c or rhs` requires the true arm to return c.
/// No `c and a or b` rewrite is used: a may legitimately be false or nil.
fn short_circuit(first: &Statement, second: &Statement, counts: &Counts) -> Option<Statement> {
    let Statement::Local {
        binding,
        annotation,
        value: initial,
    } = first
    else {
        return None;
    };
    let Statement::If { condition, yes, no } = second else {
        return None;
    };
    if !condition.leaf()
        || condition.contains(*binding)
        || initial.as_ref().is_some_and(|v| v != condition)
        || counts.definitions.get(binding).copied()
            != Some(1 + usize::from(!yes.is_empty()) + usize::from(!no.is_empty()))
    {
        return None;
    }
    let a = assignment(yes, *binding, initial)?;
    let b = assignment(no, *binding, initial)?;
    if a.contains(*binding) || b.contains(*binding) {
        return None;
    }
    let (op, rhs) = if b == condition {
        (BinaryOp::And, a)
    } else if a == condition {
        (BinaryOp::Or, b)
    } else {
        return None;
    };
    if rhs.depth() + 1 > MAX_EXPRESSION_DEPTH {
        return None;
    }
    Some(Statement::Local {
        binding: *binding,
        annotation: *annotation,
        value: Some(Expr::Binary {
            op,
            left: Box::new(condition.clone()),
            right: Box::new(rhs.clone()),
        }),
    })
}

fn cleanup(body: &mut Body, counts: &Counts) -> bool {
    let mut changed = false;
    for statement in body.iter_mut() {
        if let Statement::If { yes, no, .. } = statement {
            changed |= cleanup(yes, counts);
            changed |= cleanup(no, counts);
        }
        if let Statement::ForNum { body, .. } = statement {
            changed |= cleanup(body, counts);
        }
    }
    let mut position = 0;
    while position < body.len() {
        changed |= constructor(body, position);
        if position + 1 < body.len() {
            if let Some(folded) = short_circuit(&body[position], &body[position + 1], counts) {
                body[position] = folded;
                body.remove(position + 1);
                changed = true;
                continue;
            }
            if let Statement::Local {
                binding,
                value: Some(value),
                ..
            } = &body[position]
            {
                let binding = *binding;
                let value = value.clone();
                // An initializer is never moved until all its writes have
                // been considered; only an empty, single-use allocation can
                // disappear into an immediately following scalar store.
                let movable = !matches!(&value, Expr::Table(fields) if !fields.is_empty());
                if movable
                    && counts.uses.get(&binding) == Some(&1)
                    && counts.definitions.get(&binding) == Some(&1)
                    && inline(&mut body[position + 1], binding, &value)
                {
                    body.remove(position);
                    changed = true;
                    continue;
                }
            }
        }
        position += 1;
    }
    changed
}

fn identifier(key: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(key).ok()?;
    let first = *key.first()?;
    if !(first.is_ascii_alphabetic() || first == b'_')
        || !key.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
        || [
            "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "if", "in",
            "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while",
            "continue",
        ]
        .contains(&text)
    {
        return None;
    }
    Some(text)
}

struct Renderer<'a> {
    names: &'a BTreeMap<usize, String>,
}

impl Renderer<'_> {
    fn name(&self, binding: usize) -> Result<&str, String> {
        self.names
            .get(&binding)
            .map(String::as_str)
            .ok_or_else(|| format!("missing pretty binding {binding}"))
    }

    fn field(&self, key: &Expr) -> Result<String, String> {
        if let Expr::Constant(Constant::String(key)) = key {
            if let Some(key) = identifier(key) {
                return Ok(key.to_owned());
            }
        }
        Ok(format!("[{}]", self.expr(key, 0)?))
    }

    fn prefix(&self, expr: &Expr) -> Result<String, String> {
        let text = self.expr(expr, 0)?;
        Ok(
            if matches!(
                expr,
                Expr::Binding(_) | Expr::Environment | Expr::Index { .. } | Expr::Call { .. }
            ) {
                text
            } else {
                format!("({text})")
            },
        )
    }

    fn expr(&self, expr: &Expr, parent: u8) -> Result<String, String> {
        let (text, precedence) = match expr {
            Expr::Binding(id) => (self.name(*id)?.to_owned(), 10),
            Expr::Environment => ("environment".to_owned(), 10),
            Expr::Constant(c) => {
                let text = render_constant(c);
                // A negative literal has unary precedence: `-1 ^ 2` is not
                // the same expression as `(-1) ^ 2`.
                let precedence = if text.starts_with('-') { 7 } else { 10 };
                (text, precedence)
            }
            Expr::Unary { op, value } => {
                if *op == UnaryOp::TypeOf {
                    return Ok(format!("capturedType({})", self.expr(value, 0)?));
                }
                let op = match op {
                    UnaryOp::Not => "not ",
                    UnaryOp::Negate => "-",
                    UnaryOp::Length => "#",
                    UnaryOp::BitNot => return Err("unsupported pretty unary operator".to_owned()),
                    UnaryOp::TypeOf => unreachable!("handled above"),
                };
                // Explicit parentheses also avoid `--` for a negative operand.
                (format!("{op}({})", self.expr(value, 0)?), 7)
            }
            Expr::Binary { op, left, right } => {
                let precedence = match op {
                    BinaryOp::Or => 1,
                    BinaryOp::And => 2,
                    BinaryOp::Equal
                    | BinaryOp::NotEqual
                    | BinaryOp::Less
                    | BinaryOp::LessEqual
                    | BinaryOp::Greater
                    | BinaryOp::GreaterEqual => 3,
                    BinaryOp::Add | BinaryOp::Sub => 4,
                    BinaryOp::Mul | BinaryOp::Div | BinaryOp::FloorDiv | BinaryOp::Mod => 5,
                    BinaryOp::Pow => 8,
                };
                (
                    format!(
                        "{} {} {}",
                        self.expr(left, precedence + 1)?,
                        binary_op_symbol(*op),
                        self.expr(right, precedence + 1)?
                    ),
                    precedence,
                )
            }
            Expr::Index { table, index } => {
                let table = self.prefix(table)?;
                let field = self.field(index)?;
                (
                    if field.starts_with('[') {
                        format!("{table}{field}")
                    } else {
                        format!("{table}.{field}")
                    },
                    9,
                )
            }
            Expr::Call { function, args } => {
                if args
                    .iter()
                    .take(args.len().saturating_sub(1))
                    .any(|arg| matches!(arg, Expr::Expand(_)))
                {
                    return Err("tuple expansion is not in the final argument position".to_owned());
                }
                let args = args
                    .iter()
                    .map(|arg| {
                        let text = self.expr(arg, 0)?;
                        // Every Expr::Call is a proved scalar, including a last
                        // argument. Parentheses prevent accidental tuple expansion.
                        Ok(if matches!(arg, Expr::Call { .. }) {
                            format!("({text})")
                        } else {
                            text
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                (
                    format!("{}({})", self.prefix(function)?, args.join(", ")),
                    9,
                )
            }
            Expr::External(text) => (text.clone(), 10),
            Expr::Expand(value) => return self.expr(value, parent),
            Expr::Concat(parts) => {
                let parts = parts
                    .iter()
                    .map(|p| self.expr(p, 5))
                    .collect::<Result<Vec<_>, _>>()?;
                (parts.join(" .. "), 4)
            }
            Expr::Table(fields) => {
                let fields = fields
                    .iter()
                    .map(|(key, value)| {
                        Ok(format!("{} = {}", self.field(key)?, self.expr(value, 0)?))
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                (
                    if fields.is_empty() {
                        "{}".to_owned()
                    } else {
                        format!("{{ {} }}", fields.join(", "))
                    },
                    10,
                )
            }
        };
        Ok(if precedence < parent {
            format!("({text})")
        } else {
            text
        })
    }

    fn body(&self, body: &[Statement], depth: usize, output: &mut String) -> Result<(), String> {
        let indent = "\t".repeat(depth);
        let mut previous_empty_table = false;
        for statement in body {
            let table = matches!(
                statement,
                Statement::Local {
                    value: Some(Expr::Table(_)),
                    ..
                }
            );
            let call = matches!(statement, Statement::Call(_));
            if depth == 0
                && (table && !previous_empty_table || call)
                && !output.is_empty()
                && !output.ends_with("\n\n")
            {
                output.push('\n');
            }
            match statement {
                Statement::Local {
                    binding,
                    annotation,
                    value,
                } => {
                    write!(output, "{indent}local {}", self.name(*binding)?)
                        .map_err(|e| e.to_string())?;
                    if let Some(annotation) = annotation {
                        write!(output, ": {annotation}").map_err(|e| e.to_string())?;
                    }
                    if let Some(Expr::Table(fields)) = value
                        .as_ref()
                        .filter(|v| matches!(v, Expr::Table(fields) if fields.len() > 2))
                    {
                        output.push_str(" = {\n");
                        for (key, value) in fields {
                            writeln!(
                                output,
                                "{indent}\t{} = {},",
                                self.field(key)?,
                                self.expr(value, 0)?
                            )
                            .map_err(|e| e.to_string())?;
                        }
                        writeln!(output, "{indent}}}\n").map_err(|e| e.to_string())?;
                    } else {
                        if let Some(value) = value {
                            write!(output, " = {}", self.expr(value, 0)?)
                                .map_err(|e| e.to_string())?;
                        }
                        output.push('\n');
                    }
                }
                Statement::Assign { binding, value } => {
                    writeln!(
                        output,
                        "{indent}{} = {}",
                        self.name(*binding)?,
                        self.expr(value, 0)?
                    )
                    .map_err(|e| e.to_string())?;
                }
                Statement::SetTable {
                    table,
                    index,
                    value,
                } => {
                    let target = Expr::Index {
                        table: Box::new(table.clone()),
                        index: Box::new(index.clone()),
                    };
                    writeln!(
                        output,
                        "{indent}{} = {}",
                        self.expr(&target, 0)?,
                        self.expr(value, 0)?
                    )
                    .map_err(|e| e.to_string())?;
                }
                Statement::Call(expr) => {
                    writeln!(output, "{indent}{}", self.expr(expr, 0)?)
                        .map_err(|e| e.to_string())?;
                }
                Statement::Return(exprs) => {
                    let rendered = exprs
                        .iter()
                        .map(|e| self.expr(e, 0))
                        .collect::<Result<Vec<_>, _>>()?;
                    if rendered.is_empty() {
                        writeln!(output, "{indent}return").map_err(|e| e.to_string())?;
                    } else {
                        writeln!(output, "{indent}return {}", rendered.join(", "))
                            .map_err(|e| e.to_string())?;
                    }
                }
                Statement::ReturnPacked(expr) => {
                    let text = self.expr(expr, 0)?;
                    writeln!(
                        output,
                        "{indent}return capturedUnpack({}, 1, {}.n)",
                        text, text
                    )
                    .map_err(|e| e.to_string())?;
                }
                Statement::If { condition, yes, no } => {
                    writeln!(output, "{indent}if {} then", self.expr(condition, 0)?)
                        .map_err(|e| e.to_string())?;
                    self.body(yes, depth + 1, output)?;
                    if !no.is_empty() {
                        writeln!(output, "{indent}else").map_err(|e| e.to_string())?;
                        self.body(no, depth + 1, output)?;
                    }
                    writeln!(output, "{indent}end").map_err(|e| e.to_string())?;
                }
                Statement::Comment(text) => {
                    writeln!(output, "{indent}-- {text}").map_err(|e| e.to_string())?;
                }
                Statement::ForNum {
                    var,
                    start,
                    limit,
                    step,
                    body,
                } => {
                    let start = self.expr(start, 0)?;
                    let limit = self.expr(limit, 0)?;
                    let step_text = match step {
                        Some(step) => format!(", {}", self.expr(step, 0)?),
                        None => String::new(),
                    };
                    writeln!(output, "{indent}for {var} = {start}, {limit}{step_text} do")
                        .map_err(|e| e.to_string())?;
                    self.body(body, depth + 1, output)?;
                    writeln!(output, "{indent}end").map_err(|e| e.to_string())?;
                }
            }
            previous_empty_table = matches!(statement, Statement::Local { value: Some(Expr::Table(fields)), .. } if fields.is_empty());
        }
        Ok(())
    }
}

pub(super) fn render(mut body: Body, names: &BTreeMap<usize, String>) -> Result<String, String> {
    validate(&body, 0, &mut 0)?;
    // A bounded optional pass: exhausting cleanup opportunities/passes does
    // not invent an expression or prevent conservative emission.
    for _ in 0..MAX_PASSES {
        let mut uses = Counts::default();
        counts(&body, &mut uses);
        if !cleanup(&mut body, &uses) {
            break;
        }
    }
    validate(&body, 0, &mut 0)?;
    let mut output = String::new();
    Renderer { names }.body(&body, 0, &mut output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(binding: usize, value: Expr) -> Statement {
        Statement::Local {
            binding,
            annotation: None,
            value: Some(value),
        }
    }

    fn read(table: Expr, key: &str) -> Expr {
        Expr::Index {
            table: Box::new(table),
            index: Box::new(Expr::Constant(Constant::String(key.as_bytes().to_vec()))),
        }
    }

    fn names() -> BTreeMap<usize, String> {
        (0..=256).map(|id| (id, format!("value{id}"))).collect()
    }

    #[test]
    fn scalar_calls_in_last_argument_positions_are_parenthesized_not_expanded() {
        let expr = Expr::Call {
            function: Box::new(Expr::Binding(0)),
            args: vec![Expr::Call {
                function: Box::new(Expr::Binding(1)),
                args: vec![],
            }],
        };
        assert_eq!(
            render(vec![Statement::Call(expr)], &names()).unwrap(),
            "value0((value1()))\n"
        );
    }

    #[test]
    fn branch_cleanup_requires_predicate_identity_and_no_extra_definition() {
        let declaration = Statement::Local {
            binding: 2,
            annotation: Some("any"),
            value: None,
        };
        let branch = Statement::If {
            condition: Expr::Binding(0),
            yes: vec![Statement::Assign {
                binding: 2,
                value: Expr::Binding(1),
            }],
            no: vec![Statement::Assign {
                binding: 2,
                value: Expr::Binding(0),
            }],
        };
        let mut count = Counts::default();
        counts(&[declaration.clone(), branch.clone()], &mut count);
        assert!(short_circuit(&declaration, &branch, &count).is_some());
        *count.definitions.get_mut(&2).unwrap() += 1;
        assert!(short_circuit(&declaration, &branch, &count).is_none());
        *count.definitions.get_mut(&2).unwrap() -= 1;

        let unrelated = Statement::Local {
            binding: 2,
            annotation: Some("any"),
            value: Some(Expr::Constant(Constant::Nil)),
        };
        assert!(short_circuit(&unrelated, &branch, &count).is_none());
        let Statement::If { yes, no, .. } = branch else {
            unreachable!()
        };
        let effectful = Statement::If {
            condition: read(Expr::Environment, "flag"),
            yes,
            no,
        };
        // The expression has a lookup rather than an already captured value.
        assert!(short_circuit(&declaration, &effectful, &count).is_none());
    }

    #[test]
    fn comments_are_barriers_for_lookup_inlining_and_constructor_folding() {
        let output = render(
            vec![
                local(0, read(Expr::Environment, "root")),
                Statement::Comment("Source VM words 1..3".to_owned()),
                local(1, read(Expr::Binding(0), "child")),
                local(2, Expr::Table(vec![])),
                Statement::Comment("Source VM words 4..5".to_owned()),
                Statement::SetTable {
                    table: Expr::Binding(2),
                    index: Expr::Constant(Constant::String(b"x".to_vec())),
                    value: Expr::Constant(Constant::Integer(1)),
                },
            ],
            &names(),
        )
        .unwrap();
        assert!(output.contains(
            "local value0 = environment.root\n-- Source VM words 1..3\nlocal value1 = value0.child"
        ));
        assert!(output.contains("local value2 = {}\n-- Source VM words 4..5\nvalue2.x = 1"));
    }

    #[test]
    fn depth_limit_stops_optional_inlining_without_discarding_the_remaining_locals() {
        let mut body = vec![local(0, read(Expr::Environment, "root"))];
        for id in 1..=200 {
            body.push(local(id, read(Expr::Binding(id - 1), "next")));
        }
        body.push(Statement::Call(Expr::Call {
            function: Box::new(Expr::Binding(200)),
            args: vec![],
        }));
        let output = render(body, &names()).unwrap();
        assert!(output.matches("local ").count() >= 1);
        assert_eq!(output.matches(".next").count(), 200);
        assert_eq!(output.matches("environment.root").count(), 1);
    }

    #[test]
    fn excessive_input_expression_depth_is_an_explicit_error() {
        let mut expr = Expr::Binding(0);
        for _ in 0..MAX_EXPRESSION_DEPTH {
            expr = Expr::Unary {
                op: UnaryOp::Not,
                value: Box::new(expr),
            };
        }
        let error = render(vec![local(1, expr)], &names()).unwrap_err();
        assert!(error.contains("depth/node budget"));
    }

    #[test]
    fn mutable_bindings_are_not_inlined_even_when_the_current_use_is_adjacent() {
        let output = render(
            vec![
                local(2, Expr::Table(vec![])),
                local(0, read(Expr::Environment, "root")),
                local(1, read(Expr::Binding(0), "cached")),
                Statement::SetTable {
                    table: Expr::Binding(2),
                    index: Expr::Constant(Constant::String(b"x".to_vec())),
                    value: Expr::Binding(1),
                },
                Statement::Assign {
                    binding: 1,
                    value: Expr::Constant(Constant::Nil),
                },
            ],
            &names(),
        )
        .unwrap();
        assert!(
            output.contains("local value1 = environment.root.cached"),
            "{output}"
        );
        assert!(output.contains("value2.x = value1"), "{output}");
    }
}
