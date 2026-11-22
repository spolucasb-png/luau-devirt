//! Static Lua-source parsing and VM payload decoding.
//!
//! This module never executes Luau, never calls `loadstring`, and never runs
//! any decoded instruction. It implements three layers of pure static
//! analysis:
//!
//! 1. A Lua lexer that treats quoted literals atomically (so the binary
//!    payload containing `};` is never split) and decodes escapes exactly the
//!    way the wrapper's own parser would: standard escapes, up to three
//!    decimal digits, two-digit hex, `\z`, and escaped newlines.
//! 2. Source-level extraction: the leading `local <name> = { ... }` string
//!    table, the integrity length/checksum tables, the lazy initializer call
//!    `<init>(<bxor>(NUM, NUM))`, and the numeric dispatch-family table.
//!    Lengths and Adler-32 values are verified against the tables parsed from
//!    the current source; nothing is carried over from a prior sample.
//! 3. Payload decryption with wrapping u32 arithmetic, mirroring the
//!    initializer (`var40`), prototype/string/number decoders (`var39`,
//!    `var33`, `var34`), slot map (`var29`), immediate biases, and the
//!    permutation tables: header words, master key and decoded word range,
//!    the 120-entry slot map, 64 immediate biases, prototype headers with
//!    captures and parameters, string records, f64 number records, the
//!    dispatch family lookup, and permutation parity.
//!
//! Formula constants below (XOR masks, LCG multipliers/addends, permutation
//! seeds) are part of the VM algorithm itself and are all present in the
//! wrapper source; sample-specific values such as the initializer argument,
//! integrity tables, master key, and prototype locations are parsed or
//! derived from the current source instead of being hard-coded.

use crate::ir::{
    CaptureDescriptor, DecodedVm, NumberConstant, Prototype, StringConstant, TableIntegrity,
    U32_MODULUS,
};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

const KEYWORDS: [&str; 22] = [
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "if", "in", "local",
    "nil", "not", "or", "repeat", "return", "then", "true", "until", "while", "continue",
];

const OPERATORS: [&str; 19] = [
    "...", "..=", "//=", "==", "~=", "<=", ">=", "+=", "-=", "*=", "/=", "%=", "^=", "//", "..",
    "::", "->", "<<", ">>",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TokenKind {
    Keyword,
    Identifier,
    Number,
    String,
    Operator,
}

#[derive(Clone, Debug)]
pub(crate) struct Token {
    pub(crate) kind: TokenKind,
    /// Exact spelling of the token as it appears in the source.
    pub(crate) text: String,
    /// Byte offset of the token in the source.
    pub(crate) offset: usize,
}

fn is_op(token: &Token, text: &str) -> bool {
    token.kind == TokenKind::Operator && token.text == text
}

fn is_keyword(token: &Token, text: &str) -> bool {
    token.kind == TokenKind::Keyword && token.text == text
}

fn is_identifier(token: &Token, text: &str) -> bool {
    token.kind == TokenKind::Identifier && token.text == text
}

/// Tokenize Lua/Luau source. Quoted and long-bracket strings are single
/// tokens, so a `};` inside a string literal can never terminate a table.
pub(crate) fn tokenize(source: &str) -> Result<Vec<Token>, String> {
    let bytes = source.as_bytes();
    let mut tokens: Vec<Token> = Vec::new();
    let mut pos = 0usize;
    while pos < bytes.len() {
        if tokens.len() >= 500_000 {
            return Err("source token count exceeds the 500000-token analysis budget".to_owned());
        }
        let byte = bytes[pos];
        if matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | b'\x0B' | b'\x0C') {
            pos += 1;
            continue;
        }
        if byte == b'-' && bytes.get(pos + 1) == Some(&b'-') {
            pos = skip_comment(source, pos)?;
            continue;
        }
        if byte == b'"' || byte == b'\'' {
            let (_, end) = scan_quoted(source, pos)?;
            tokens.push(Token {
                kind: TokenKind::String,
                text: source[pos..end].to_owned(),
                offset: pos,
            });
            pos = end;
            continue;
        }
        if byte == b'[' {
            if let Some((level, content_start)) = long_bracket_shape(bytes, pos) {
                let end = find_long_bracket_close(bytes, content_start, level)
                    .ok_or_else(|| format!("unterminated long string at byte {pos}"))?;
                tokens.push(Token {
                    kind: TokenKind::String,
                    text: source[pos..end].to_owned(),
                    offset: pos,
                });
                pos = end;
                continue;
            }
        }
        if byte.is_ascii_alphabetic() || byte == b'_' {
            let mut end = pos + 1;
            while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
                end += 1;
            }
            let text = &source[pos..end];
            let kind = if KEYWORDS.contains(&text) {
                TokenKind::Keyword
            } else {
                TokenKind::Identifier
            };
            tokens.push(Token {
                kind,
                text: text.to_owned(),
                offset: pos,
            });
            pos = end;
            continue;
        }
        if let Some(end) = scan_number(bytes, pos) {
            tokens.push(Token {
                kind: TokenKind::Number,
                text: source[pos..end].to_owned(),
                offset: pos,
            });
            pos = end;
            continue;
        }
        let operator = OPERATORS
            .iter()
            .find(|op| source[pos..].starts_with(**op))
            .map(|op| op.to_string());
        if let Some(operator) = operator {
            tokens.push(Token {
                kind: TokenKind::Operator,
                text: operator.clone(),
                offset: pos,
            });
            pos += operator.len();
            continue;
        }
        let char_length = source[pos..]
            .chars()
            .next()
            .map(|c| c.len_utf8())
            .unwrap_or(1);
        tokens.push(Token {
            kind: TokenKind::Operator,
            text: source[pos..pos + char_length].to_owned(),
            offset: pos,
        });
        pos += char_length;
    }
    Ok(tokens)
}

/// Consume one comment starting at `--` and return the new cursor.
fn skip_comment(source: &str, start: usize) -> Result<usize, String> {
    let bytes = source.as_bytes();
    let mut pos = start + 2;
    if bytes.get(pos) == Some(&b'[') {
        if let Some((level, content_start)) = long_bracket_shape(bytes, pos) {
            let end = find_long_bracket_close(bytes, content_start, level)
                .ok_or_else(|| format!("unterminated long comment at byte {start}"))?;
            return Ok(end);
        }
    }
    while pos < bytes.len() && bytes[pos] != b'\n' {
        pos += 1;
    }
    Ok(pos)
}

/// Detect a `[=*[` opening. Returns the level and the content start offset.
fn long_bracket_shape(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    if bytes.get(start) != Some(&b'[') {
        return None;
    }
    let mut cursor = start + 1;
    let mut level = 0usize;
    while bytes.get(cursor) == Some(&b'=') {
        level += 1;
        cursor += 1;
    }
    if bytes.get(cursor) == Some(&b'[') {
        Some((level, cursor + 1))
    } else {
        None
    }
}

/// Find the matching `]=*]` close for a long bracket. Returns the offset one
/// past the closing bracket.
fn find_long_bracket_close(bytes: &[u8], from: usize, level: usize) -> Option<usize> {
    let mut cursor = from;
    while cursor < bytes.len() {
        if bytes[cursor] == b']' {
            let mut probe = cursor + 1;
            let mut count = 0usize;
            while bytes.get(probe) == Some(&b'=') {
                count += 1;
                probe += 1;
            }
            if count == level && bytes.get(probe) == Some(&b']') {
                return Some(probe + 1);
            }
        }
        cursor += 1;
    }
    None
}

/// Decode one quoted literal starting at the quote byte. Mirrors the wrapper's
/// own escape handling: standard escapes, decimal escapes of up to three
/// digits, two-digit hex, `\z`, and escaped newlines.
pub(crate) fn scan_quoted(source: &str, start: usize) -> Result<(Vec<u8>, usize), String> {
    let bytes = source.as_bytes();
    let quote = *bytes
        .get(start)
        .ok_or_else(|| "expected a quoted string literal".to_owned())?;
    if quote != b'"' && quote != b'\'' {
        return Err(format!("expected a quoted string literal at byte {start}"));
    }
    let mut out: Vec<u8> = Vec::new();
    let mut cursor = start + 1;
    loop {
        let ch = match source[cursor..].chars().next() {
            Some(ch) => ch,
            None => return Err("unterminated quoted string".to_owned()),
        };
        if ch as u32 == quote as u32 {
            return Ok((out, cursor + 1));
        }
        if ch != '\\' {
            if ch == '\r' || ch == '\n' {
                return Err(format!("raw newline in quoted string at byte {cursor}"));
            }
            // Preserve the raw UTF-8 bytes of the source; do not collapse
            // non-ASCII characters to their code point.
            out.extend_from_slice(&source[cursor..cursor + ch.len_utf8()].as_bytes());
            cursor += ch.len_utf8();
            continue;
        }
        cursor += 1;
        let escaped = match source[cursor..].chars().next() {
            Some(escaped) => escaped,
            None => return Err("unterminated escape in quoted string".to_owned()),
        };
        match escaped {
            'a' => {
                out.push(7);
                cursor += 1;
            }
            'b' => {
                out.push(8);
                cursor += 1;
            }
            'f' => {
                out.push(12);
                cursor += 1;
            }
            'n' => {
                out.push(10);
                cursor += 1;
            }
            'r' => {
                out.push(13);
                cursor += 1;
            }
            't' => {
                out.push(9);
                cursor += 1;
            }
            'v' => {
                out.push(11);
                cursor += 1;
            }
            '\\' => {
                out.push(92);
                cursor += 1;
            }
            '"' => {
                out.push(34);
                cursor += 1;
            }
            '\'' => {
                out.push(39);
                cursor += 1;
            }
            '0'..='9' => {
                let mut end = cursor;
                let mut value: u32 = 0;
                while end < bytes.len() && end < cursor + 3 && bytes[end].is_ascii_digit() {
                    value = value * 10 + (bytes[end] - b'0') as u32;
                    end += 1;
                }
                if value > 255 {
                    return Err(format!(
                        "invalid decimal escape \\{value} at byte {}",
                        cursor - 1
                    ));
                }
                out.push(value as u8);
                cursor = end;
            }
            'x' => {
                let high = bytes
                    .get(cursor + 1)
                    .copied()
                    .and_then(|b| (b as char).to_digit(16));
                let low = bytes
                    .get(cursor + 2)
                    .copied()
                    .and_then(|b| (b as char).to_digit(16));
                match (high, low) {
                    (Some(high), Some(low)) => {
                        out.push((high * 16 + low) as u8);
                        cursor += 3;
                    }
                    _ => return Err(format!("invalid hex escape at byte {}", cursor - 1)),
                }
            }
            'z' => {
                cursor += 1;
                while cursor < bytes.len() {
                    match bytes[cursor] {
                        b' ' | b'\t' | b'\n' | b'\x0B' | b'\x0C' | b'\r' => {
                            cursor += 1;
                        }
                        _ => break,
                    }
                }
            }
            '\r' | '\n' => {
                if escaped == '\r' && source[cursor + 1..].starts_with('\n') {
                    cursor += 2;
                } else {
                    cursor += 1;
                }
                out.push(10);
            }
            other => {
                return Err(format!(
                    "unsupported escape {other:?} at byte {}",
                    cursor - 1
                ))
            }
        }
    }
}

/// Scan a Lua number starting at `pos`. Returns the exclusive end offset.
/// Malformed `0x`/`0b` prefixes fall back to a plain decimal scan of the
/// leading zero, mirroring the reference lexer.
fn scan_number(bytes: &[u8], pos: usize) -> Option<usize> {
    let first = *bytes.get(pos)?;
    let mut cursor = pos;
    if first == b'0' {
        if matches!(bytes.get(cursor + 1), Some(b'x') | Some(b'X')) {
            let mut probe = cursor + 2;
            let digits_start = probe;
            while matches!(bytes.get(probe), Some(b) if b.is_ascii_hexdigit()) {
                probe += 1;
            }
            if probe != digits_start {
                cursor = probe;
                if bytes.get(cursor) == Some(&b'.') {
                    cursor += 1;
                    while matches!(bytes.get(cursor), Some(b) if b.is_ascii_hexdigit()) {
                        cursor += 1;
                    }
                }
                if matches!(bytes.get(cursor), Some(b'p') | Some(b'P')) {
                    let save = cursor;
                    cursor += 1;
                    if matches!(bytes.get(cursor), Some(b'+') | Some(b'-')) {
                        cursor += 1;
                    }
                    let exponent_start = cursor;
                    while matches!(bytes.get(cursor), Some(b) if b.is_ascii_digit()) {
                        cursor += 1;
                    }
                    if cursor == exponent_start {
                        cursor = save;
                    }
                }
                return Some(cursor);
            }
        } else if matches!(bytes.get(cursor + 1), Some(b'b') | Some(b'B')) {
            let mut probe = cursor + 2;
            let digits_start = probe;
            while matches!(bytes.get(probe), Some(b'0') | Some(b'1') | Some(b'_')) {
                probe += 1;
            }
            if probe != digits_start {
                return Some(probe);
            }
        }
    }
    if first.is_ascii_digit() {
        while matches!(bytes.get(cursor), Some(b) if b.is_ascii_digit()) {
            cursor += 1;
        }
        if bytes.get(cursor) == Some(&b'.') && bytes.get(cursor + 1) != Some(&b'.') {
            cursor += 1;
            while matches!(bytes.get(cursor), Some(b) if b.is_ascii_digit()) {
                cursor += 1;
            }
        }
    } else if first == b'.' && matches!(bytes.get(cursor + 1), Some(b) if b.is_ascii_digit()) {
        cursor += 1;
        while matches!(bytes.get(cursor), Some(b) if b.is_ascii_digit()) {
            cursor += 1;
        }
    } else {
        return None;
    }
    if matches!(bytes.get(cursor), Some(b'e') | Some(b'E')) {
        let save = cursor;
        cursor += 1;
        if matches!(bytes.get(cursor), Some(b'+') | Some(b'-')) {
            cursor += 1;
        }
        let exponent_start = cursor;
        while matches!(bytes.get(cursor), Some(b) if b.is_ascii_digit()) {
            cursor += 1;
        }
        if cursor == exponent_start {
            cursor = save;
        }
    }
    Some(cursor)
}

/// Parse a number token's spelling as a non-negative integer (decimal, hex,
/// or binary). Floats, exponents, and malformed literals return `None`.
fn lua_integer(text: &str) -> Option<u64> {
    let cleaned: String = text.chars().filter(|c| *c != '_').collect();
    if let Some(rest) = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
    {
        if rest.is_empty() || !rest.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        return u64::from_str_radix(rest, 16).ok();
    }
    if let Some(rest) = cleaned
        .strip_prefix("0b")
        .or_else(|| cleaned.strip_prefix("0B"))
    {
        if rest.is_empty() || !rest.chars().all(|c| c == '0' || c == '1') {
            return None;
        }
        return u64::from_str_radix(rest, 2).ok();
    }
    if cleaned.is_empty() || !cleaned.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    cleaned.parse::<u64>().ok()
}

// ---------------------------------------------------------------------------
// Adler-32 and SHA-256
// ---------------------------------------------------------------------------

/// Adler-32 as computed by the wrapper's integrity loop: running sums modulo
/// 65521, result `B * 65536 + A`.
fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// SHA-256 digest as lowercase hex. Used only to fingerprint the analyzed
/// source in `DecodedVm::source_sha256`.
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut message = data.to_vec();
    let bit_length = (data.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_length.to_be_bytes());
    for block in message.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (index, word) in block.chunks_exact(4).enumerate() {
            w[index] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }
        let mut v = state;
        for index in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
            let temp1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let temp2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(temp1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = temp1.wrapping_add(temp2);
        }
        for index in 0..8 {
            state[index] = state[index].wrapping_add(v[index]);
        }
    }
    state.iter().map(|word| format!("{word:08x}")).collect()
}

// ---------------------------------------------------------------------------
// Source-level extraction
// ---------------------------------------------------------------------------

/// Parse the leading `local <name> = { "literal", ... }` table. Returns the
/// table's name (so the integrity comparison can be bound to it) together
/// with the decoded literals.
fn parse_first_string_table(
    tokens: &[Token],
    source: &str,
) -> Result<(String, Vec<Vec<u8>>), String> {
    if tokens.len() < 4
        || !is_keyword(&tokens[0], "local")
        || tokens[1].kind != TokenKind::Identifier
        || !is_op(&tokens[2], "=")
        || !is_op(&tokens[3], "{")
    {
        return Err("unexpected first table prefix: expected `local <name> = {`".to_owned());
    }
    let name = tokens[1].text.clone();
    let mut strings: Vec<Vec<u8>> = Vec::new();
    let mut index = 4usize;
    loop {
        let token = tokens
            .get(index)
            .ok_or_else(|| "first table is unterminated".to_owned())?;
        if is_op(token, "}") {
            break;
        }
        if token.kind == TokenKind::String {
            if token.text.starts_with('[') {
                return Err("first-table strings must be quoted literals".to_owned());
            }
            let (bytes, _) = scan_quoted(source, token.offset)?;
            strings.push(bytes);
        } else if !is_op(token, ",") {
            return Err(format!(
                "unexpected first-table token `{}` at byte {}",
                token.text, token.offset
            ));
        }
        index += 1;
    }
    if strings.is_empty() {
        return Err("first table contains no string literals".to_owned());
    }
    Ok((name, strings))
}

struct NumberTable {
    name: String,
    values: Vec<u64>,
}

/// Collect every `local <name> = { <number>, ... }` table whose elements are
/// all plain integers. Non-numeric tables are ignored.
fn parse_local_number_tables(tokens: &[Token]) -> Vec<NumberTable> {
    let mut tables = Vec::new();
    let mut index = 0usize;
    while index + 3 < tokens.len() {
        if is_keyword(&tokens[index], "local")
            && tokens[index + 1].kind == TokenKind::Identifier
            && is_op(&tokens[index + 2], "=")
            && is_op(&tokens[index + 3], "{")
        {
            let mut values: Vec<u64> = Vec::new();
            let mut pure = true;
            let mut cursor = index + 4;
            let mut expect_value = true;
            while let Some(token) = tokens.get(cursor) {
                if is_op(token, "}") {
                    break;
                }
                if expect_value {
                    if token.kind == TokenKind::Number {
                        match lua_integer(&token.text) {
                            Some(value) => values.push(value),
                            None => pure = false,
                        }
                    } else {
                        pure = false;
                    }
                    expect_value = false;
                } else if is_op(token, ",") {
                    expect_value = true;
                } else {
                    pure = false;
                }
                cursor += 1;
            }
            if pure && !values.is_empty() {
                tables.push(NumberTable {
                    name: tokens[index + 1].text.clone(),
                    values,
                });
            }
        }
        index += 1;
    }
    tables
}

/// Identify the length table and the Adler-32 table among the parsed number
/// tables and verify every literal against them. Both tables must be unique
/// and match the current source's own literals exactly.
/// Bind the integrity comparison to the active tables named in the source's
/// `if #... ~= ... or ... ~= ...` check. Returns the string-table name, the
/// length-table name, the checksum-table name, and the loop bound.
fn find_integrity_binding(tokens: &[Token]) -> Result<(String, String, String, usize), String> {
    let mut found = None;
    for i in 0..tokens.len().saturating_sub(19) {
        if is_keyword(&tokens[i], "if")
            && tokens[i + 1].kind == TokenKind::Operator
            && tokens[i + 1].text == "#"
            && tokens[i + 2].kind == TokenKind::Identifier
            && is_op(&tokens[i + 3], "~=")
            && tokens[i + 4].kind == TokenKind::Identifier
            && is_op(&tokens[i + 5], "[")
            && tokens[i + 6].kind == TokenKind::Identifier
            && is_op(&tokens[i + 7], "]")
            && is_keyword(&tokens[i + 8], "or")
            && tokens[i + 9].kind == TokenKind::Identifier
            && is_op(&tokens[i + 10], "*")
            && tokens[i + 11].kind == TokenKind::Number
            && tokens[i + 11].text == "65536"
            && is_op(&tokens[i + 12], "+")
            && tokens[i + 13].kind == TokenKind::Identifier
            && is_op(&tokens[i + 14], "~=")
            && tokens[i + 15].kind == TokenKind::Identifier
            && is_op(&tokens[i + 16], "[")
            && tokens[i + 17].kind == TokenKind::Identifier
            && is_op(&tokens[i + 18], "]")
            && is_keyword(&tokens[i + 19], "then")
        {
            if tokens[i + 6].text != tokens[i + 17].text {
                continue;
            }
            found = Some((i, tokens[i + 4].text.clone(), tokens[i + 15].text.clone()));
            break;
        }
    }
    let (cmp_i, length_table, checksum_table) =
        found.ok_or_else(|| "integrity comparison not found in source".to_owned())?;

    let mut string_binding = None;
    for i in (0..cmp_i).rev() {
        if is_keyword(&tokens[i], "local")
            && i + 6 < tokens.len()
            && tokens[i + 1].kind == TokenKind::Identifier
            && is_op(&tokens[i + 2], "=")
            && tokens[i + 3].kind == TokenKind::Identifier
            && is_op(&tokens[i + 4], "[")
            && tokens[i + 5].kind == TokenKind::Identifier
            && is_op(&tokens[i + 6], "]")
        {
            string_binding = Some(tokens[i + 3].text.clone());
            break;
        }
    }
    let string_binding =
        string_binding.ok_or_else(|| "integrity string-table reference not found".to_owned())?;

    let mut loop_bound = None;
    for i in (0..cmp_i).rev() {
        if is_keyword(&tokens[i], "for")
            && i + 6 < tokens.len()
            && tokens[i + 1].kind == TokenKind::Identifier
            && is_op(&tokens[i + 2], "=")
            && tokens[i + 3].kind == TokenKind::Number
            && tokens[i + 3].text == "1"
            && is_op(&tokens[i + 4], ",")
            && tokens[i + 5].kind == TokenKind::Number
            && is_keyword(&tokens[i + 6], "do")
        {
            loop_bound = lua_integer(&tokens[i + 5].text);
            break;
        }
    }
    let loop_bound = loop_bound.ok_or_else(|| "integrity loop bound not found".to_owned())?;

    Ok((
        string_binding,
        length_table,
        checksum_table,
        loop_bound as usize,
    ))
}

fn verify_integrity(
    tokens: &[Token],
    tables: &[NumberTable],
    strings: &[Vec<u8>],
    first_table_name: &str,
) -> Result<(Vec<u64>, Vec<u64>), String> {
    let (string_table, length_table_name, checksum_table_name, loop_bound) =
        find_integrity_binding(tokens)?;
    if string_table != first_table_name {
        return Err(format!(
            "integrity string table `{string_table}` does not match parsed first table `{first_table_name}`"
        ));
    }
    if loop_bound != strings.len() {
        return Err(format!(
            "integrity loop bound {loop_bound} does not match literal count {}",
            strings.len()
        ));
    }
    let length_table = tables
        .iter()
        .find(|table| table.name == length_table_name)
        .ok_or_else(|| format!("integrity: active length table `{length_table_name}` not found"))?;
    let checksum_table = tables
        .iter()
        .find(|table| table.name == checksum_table_name)
        .ok_or_else(|| {
            format!("integrity: active checksum table `{checksum_table_name}` not found")
        })?;
    if length_table.values.len() != strings.len() {
        return Err(format!(
            "integrity: active length table `{length_table_name}` has {} entries, expected {}",
            length_table.values.len(),
            strings.len()
        ));
    }
    if !length_table
        .values
        .iter()
        .zip(strings.iter())
        .all(|(value, literal)| *value == literal.len() as u64)
    {
        return Err("integrity: active length table does not match literal lengths".to_owned());
    }
    let adlers: Vec<u32> = strings.iter().map(|s| adler32(s)).collect();
    if checksum_table.values.len() != strings.len() {
        return Err(format!(
            "integrity: active checksum table `{checksum_table_name}` has {} entries, expected {}",
            checksum_table.values.len(),
            strings.len()
        ));
    }
    if !checksum_table
        .values
        .iter()
        .zip(adlers.iter())
        .all(|(value, adler)| *value == *adler as u64)
    {
        return Err(
            "integrity: active checksum table does not match literal Adler-32 values".to_owned(),
        );
    }
    Ok((length_table.values.clone(), checksum_table.values.clone()))
}

/// Build a map of local names to their resolved library binding, e.g.
/// `var58 -> "bit32.bxor"`. Only declarations whose value is a simple
/// `base.member` (or a bare identifier that is a known global library) are
/// resolved; everything else stays unresolved (`None`). Conflicting bindings
/// for the same name make that name ambiguous (mapped to `None`).
fn library_bindings(tokens: &[Token]) -> std::collections::HashMap<String, String> {
    use std::collections::HashMap;
    let mut bindings: HashMap<String, String> = HashMap::new();
    let mut ambiguous: std::collections::HashSet<String> = std::collections::HashSet::new();
    const KNOWN_BASES: [&str; 10] = [
        "bit32",
        "buffer",
        "table",
        "string",
        "math",
        "os",
        "io",
        "coroutine",
        "utf8",
        "debug",
    ];
    let mut cursor = 0usize;
    while cursor < tokens.len() {
        if !is_keyword(&tokens[cursor], "local") {
            cursor += 1;
            continue;
        }
        let header_start = cursor + 1;
        // Parse `name (, name)* =`.
        let mut names: Vec<String> = Vec::new();
        let mut i = header_start;
        loop {
            if i >= tokens.len() || tokens[i].kind != TokenKind::Identifier {
                break;
            }
            names.push(tokens[i].text.clone());
            i += 1;
            if i < tokens.len() && is_op(&tokens[i], ",") {
                i += 1;
                continue;
            }
            if i < tokens.len() && is_op(&tokens[i], "=") {
                i += 1;
                break;
            }
            names.clear();
            break;
        }
        if names.is_empty() {
            cursor += 1;
            continue;
        }
        // Value groups until depth-zero `;`.
        let mut groups: Vec<Vec<usize>> = vec![Vec::new()];
        let mut depth = 0i64;
        let mut j = i;
        while j < tokens.len() {
            let token = &tokens[j];
            if depth == 0 && is_op(token, ";") {
                break;
            }
            if depth == 0 && is_op(token, ",") {
                groups.push(Vec::new());
                j += 1;
                continue;
            }
            if is_op(token, "(") || is_op(token, "[") || is_op(token, "{") {
                depth += 1;
            } else if is_op(token, ")") || is_op(token, "]") || is_op(token, "}") {
                depth -= 1;
            }
            groups.last_mut().expect("groups is never empty").push(j);
            j += 1;
        }
        // Bind names positionally to value groups.
        for (position, name) in names.iter().enumerate() {
            if position >= groups.len() {
                break;
            }
            let group = &groups[position];
            let binding = if group.len() == 3
                && KNOWN_BASES.contains(&tokens[group[0]].text.as_str())
                && is_op(&tokens[group[1]], ".")
            {
                Some(format!(
                    "{}.{}",
                    tokens[group[0]].text, tokens[group[2]].text
                ))
            } else if group.len() == 1 && KNOWN_BASES.contains(&tokens[group[0]].text.as_str()) {
                Some(tokens[group[0]].text.clone())
            } else {
                None
            };
            if let Some(binding) = binding {
                if let Some(existing) = bindings.get(name) {
                    if existing != &binding {
                        ambiguous.insert(name.clone());
                    }
                } else {
                    bindings.insert(name.clone(), binding);
                }
            }
        }
        cursor += 1;
    }
    for name in ambiguous {
        bindings.remove(&name);
    }
    bindings
}

/// Parse the lazy initializer call `<initializer>(<xor>(NUM, NUM))` and return
/// `NUM_a xor NUM_b`. The initializer function is located through the
/// key-derivation constant it contains, so no sample-specific value is
/// assumed.
fn parse_initializer_argument(tokens: &[Token]) -> Result<u32, String> {
    const KEY_DERIVATION_SEED: u64 = 1473535036;
    let anchor = tokens
        .iter()
        .position(|token| {
            token.kind == TokenKind::Number && lua_integer(&token.text) == Some(KEY_DERIVATION_SEED)
        })
        .ok_or_else(|| "key-derivation seed 1473535036 not found in source".to_owned())?;

    // Nearest preceding `<name> = function(<param>)` is the initializer.
    let mut initializer_name: Option<String> = None;
    if anchor >= 6 {
        for index in (0..=anchor - 6).rev() {
            if tokens[index].kind == TokenKind::Identifier
                && is_op(&tokens[index + 1], "=")
                && is_keyword(&tokens[index + 2], "function")
                && is_op(&tokens[index + 3], "(")
                && tokens[index + 4].kind == TokenKind::Identifier
                && is_op(&tokens[index + 5], ")")
            {
                initializer_name = Some(tokens[index].text.clone());
                break;
            }
        }
    }
    let initializer_name =
        initializer_name.ok_or_else(|| "initializer function definition not found".to_owned())?;
    // Collect every local name bound to bit32.bxor so that a renamed wrapper is
    // still recognized and so that ambiguity can be detected.
    let xor_names: Vec<String> = library_bindings(tokens)
        .into_iter()
        .filter(|(_, binding)| binding == "bit32.bxor")
        .map(|(name, _)| name)
        .collect();
    if xor_names.is_empty() {
        return Err("bit32.bxor binding not found in source".to_owned());
    }

    let mut matches: Vec<u32> = Vec::new();
    for index in 0..tokens.len().saturating_sub(8) {
        if is_identifier(&tokens[index], &initializer_name)
            && is_op(&tokens[index + 1], "(")
            && xor_names
                .iter()
                .any(|name| is_identifier(&tokens[index + 2], name))
            && is_op(&tokens[index + 3], "(")
            && tokens[index + 4].kind == TokenKind::Number
            && is_op(&tokens[index + 5], ",")
            && tokens[index + 6].kind == TokenKind::Number
            && is_op(&tokens[index + 7], ")")
            && is_op(&tokens[index + 8], ")")
        {
            let left = lua_integer(&tokens[index + 4].text)
                .filter(|value| *value <= u32::MAX as u64)
                .ok_or_else(|| "initializer constant out of u32 range".to_owned())?;
            let right = lua_integer(&tokens[index + 6].text)
                .filter(|value| *value <= u32::MAX as u64)
                .ok_or_else(|| "initializer constant out of u32 range".to_owned())?;
            matches.push((left ^ right) as u32);
        }
    }
    if matches.is_empty() {
        return Err(format!(
            "initializer call `{initializer_name}(bit32.bxor(NUM, NUM))` not found"
        ));
    }
    if matches.len() > 1 {
        return Err(format!(
            "ambiguous initializer call: {} matches found",
            matches.len()
        ));
    }
    Ok(matches[0])
}

/// Parse the dispatch-family table: the unique assignment of the form
/// `<name> = { [NUM] = NUM, ... }` where every key and value is a number.
fn parse_dispatch_map(tokens: &[Token]) -> Result<BTreeMap<u32, u32>, String> {
    let mut maps: Vec<BTreeMap<u32, u32>> = Vec::new();
    let mut index = 0usize;
    while index < tokens.len() {
        if tokens[index].kind == TokenKind::Identifier
            && tokens
                .get(index + 1)
                .map(|token| is_op(token, "="))
                .unwrap_or(false)
            && tokens
                .get(index + 2)
                .map(|token| is_op(token, "{"))
                .unwrap_or(false)
        {
            let mut cursor = index + 3;
            let mut entries: BTreeMap<u32, u32> = BTreeMap::new();
            let mut well_formed = true;
            loop {
                let token = match tokens.get(cursor) {
                    Some(token) => token,
                    None => {
                        well_formed = false;
                        break;
                    }
                };
                if is_op(token, "}") {
                    break;
                }
                let key = tokens
                    .get(cursor + 1)
                    .filter(|token| token.kind == TokenKind::Number)
                    .and_then(|token| lua_integer(&token.text))
                    .and_then(|value| u32::try_from(value).ok());
                let value = tokens
                    .get(cursor + 4)
                    .filter(|token| token.kind == TokenKind::Number)
                    .and_then(|token| lua_integer(&token.text))
                    .and_then(|value| u32::try_from(value).ok());
                let shape = tokens.get(cursor).map(|t| is_op(t, "[")).unwrap_or(false)
                    && key.is_some()
                    && tokens
                        .get(cursor + 2)
                        .map(|t| is_op(t, "]"))
                        .unwrap_or(false)
                    && tokens
                        .get(cursor + 3)
                        .map(|t| is_op(t, "="))
                        .unwrap_or(false)
                    && value.is_some();
                if !shape {
                    well_formed = false;
                    break;
                }
                entries.insert(key.expect("checked above"), value.expect("checked above"));
                cursor += 5;
                if tokens
                    .get(cursor)
                    .map(|token| is_op(token, ","))
                    .unwrap_or(false)
                {
                    cursor += 1;
                }
            }
            if well_formed && !entries.is_empty() {
                maps.push(entries);
            }
        }
        index += 1;
    }
    if maps.len() != 1 {
        return Err(format!(
            "expected exactly one numeric dispatch-family table, found {}",
            maps.len()
        ));
    }
    Ok(maps.pop().expect("maps is non-empty"))
}

// ---------------------------------------------------------------------------
// Payload decoding
// ---------------------------------------------------------------------------

// VM algorithm constants. Each of these appears verbatim in the wrapper
// source (initializer, prototype/string/number decoders); they define the
// format rather than any one sample's data.
const KEY_DERIVATION_XOR: u32 = 1473535036;
const WORD_KEY_MULTIPLIER: u32 = 50673;
const WORD_KEY_ADDEND: u32 = 3849295765;
const MASTER_KEY_MULTIPLIER: u32 = 27383;
const MASTER_KEY_ADDEND: u32 = 2179554977;
const RANGE_LOW_XOR: u32 = 2967641488;
const RANGE_HIGH_XOR: u32 = 3915592545;
const SLOT_SEED_XOR: u32 = 839935492;
const SLOT_KEY_MULTIPLIER: u32 = 2441;
const SLOT_KEY_ADDEND: u32 = 597684479;
const SLOT_KEY_WORDS: usize = 60;
const SLOT_MAP_ENTRIES: usize = 120;
const BIAS_SEED: u32 = 1002186909;
const BIAS_MULTIPLIER: u32 = 18089;
const BIAS_ADDEND: u32 = 3507744737;
const BIAS_MODULUS: u32 = 200000;
const BIAS_COUNT: usize = 64;
const PERMUTATION_SIZE: usize = 16384;
const PERMUTATION_SEED_A: u32 = 3491394721;
const PERMUTATION_SEED_B: u32 = 3448714115;
const PERMUTATION_MULTIPLIER: u32 = 22421;
const PERMUTATION_ADDEND: u32 = 1113088905;
const PERMUTATION_INDEX_SCALE: usize = 17;
const PERMUTATION_INDEX_OFFSET: usize = 6191;
/// Field masks for prototype words `p+0..p+4`:
/// dispatch token, decode state, frame/bank, call/salt, entry pc.
const PROTOTYPE_MASKS: [u32; 5] = [3909646029, 1413943958, 362291774, 2011604317, 3907258247];
const PROTOTYPE_REFERENCE_XOR: u32 = 651803;
const PROTOTYPE_TOP_ADDENDS: (u32, u32) = (1006110062, 1696795845);
const CAPTURE_XOR: u32 = 204142014;
const PARAMETER_XOR: u32 = 160755387;
const STRING_HEADER_KEY_XOR: u32 = 4111886139;
const STRING_LENGTH_XOR: u32 = 617852180;
const STRING_STREAM_MULTIPLIER: u32 = 16177;
const STRING_STREAM_ADDEND: u32 = 888490141;
const STRING_REFERENCE_XOR: u32 = 451966;
const NUMBER_BASE_XOR: u32 = 1307047751;
const NUMBER_REFERENCE_XOR: u32 = 2023800;
const NUMBER_FIRST_BASE: u64 = 3118829571;
const NUMBER_FIRST_STRIDE: u64 = 457487;
const NUMBER_SECOND_BASE: u64 = 3221349176;
const NUMBER_SECOND_STRIDE: u64 = 476665;

// Resource budgets for the byte-offset string scan. The payload itself is
// bounded, and the aggregate decoded string bytes, candidate count, and scan
// work are bounded so that a crafted payload cannot force quadratic
// allocation or unbounded work.
const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_SOURCE_BYTES: usize = 8 * 1024 * 1024;
const MAX_STRING_RECORDS: usize = 4096;
const MAX_STRING_BYTES_TOTAL: usize = 16 * 1024 * 1024;
const MAX_NUMBER_RECORDS: usize = 65536;

fn read_u32(payload: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        payload[offset],
        payload[offset + 1],
        payload[offset + 2],
        payload[offset + 3],
    ])
}

/// Advance the rolling word-key state (`state * 50673 + 3849295765`, then the
/// xorshift-style fold with shifts 9, 5, 1). All arithmetic wraps at 2^32.
fn next_word_key(state: u32) -> u32 {
    let mut state = state
        .wrapping_mul(WORD_KEY_MULTIPLIER)
        .wrapping_add(WORD_KEY_ADDEND);
    state ^= state << 9;
    state ^= state >> 5;
    state ^= state << 1;
    state
}

fn decoded_word(words: &[Option<u32>], index: usize) -> Option<u32> {
    words.get(index).copied().flatten()
}

/// Build the two 16-bit permutations and the checksum table exactly as the
/// initializer does, verify the `var35` identity, and return the parity of
/// every permutation-A entry (the bit the branch helpers consume).
fn build_permutation_parity() -> Result<BTreeMap<u16, u8>, String> {
    let mut permutation_a: Vec<u16> = (0..PERMUTATION_SIZE as u16).collect();
    let mut permutation_b: Vec<u16> = (0..PERMUTATION_SIZE as u16).collect();
    let mut state_a = PERMUTATION_SEED_A;
    let mut state_b = PERMUTATION_SEED_B;
    for index in (1..PERMUTATION_SIZE).rev() {
        state_a = state_a
            .wrapping_mul(PERMUTATION_MULTIPLIER)
            .wrapping_add(PERMUTATION_ADDEND);
        let swap_a = (state_a % (index as u32 + 1)) as usize;
        permutation_a.swap(index, swap_a);
        state_b = state_b
            .wrapping_mul(PERMUTATION_MULTIPLIER)
            .wrapping_add(PERMUTATION_ADDEND);
        let swap_b = (state_b % (index as u32 + 1)) as usize;
        permutation_b.swap(index, swap_b);
    }

    let expected_at = |index: usize| -> u16 {
        let first = permutation_a[index];
        let second = permutation_b[index] as u32;
        let scaled = ((index * PERMUTATION_INDEX_SCALE + PERMUTATION_INDEX_OFFSET)
            % PERMUTATION_SIZE) as u32;
        ((second * 4 + scaled * 2 + (first & 1) as u32) % 65536) as u16
    };
    let mut checksum_table = vec![0u16; PERMUTATION_SIZE];
    for index in 0..PERMUTATION_SIZE {
        checksum_table[permutation_a[index] as usize] = expected_at(index);
    }
    // var35 must be identically zero when the tables are intact: the checksum
    // stored at permutation_a[i] equals the value recomputed from index i.
    for index in 0..PERMUTATION_SIZE {
        if checksum_table[permutation_a[index] as usize] != expected_at(index) {
            return Err("permutation checksum table is inconsistent".to_owned());
        }
    }

    let mut parity = BTreeMap::new();
    for (index, &value) in permutation_a.iter().enumerate() {
        parity.insert(index as u16, (value & 1) as u8);
    }
    Ok(parity)
}

/// Decode every structurally valid prototype in the decoded word region. A
/// candidate is accepted when its five header words are decoded, its dispatch
/// token exists in the parsed family map, its entry pc addresses a decoded
/// word, and its parameter and capture words are decoded and in bounds.
fn scan_prototypes(
    decoded_words: &[Option<u32>],
    word_count: usize,
    master_key: u32,
    dispatch_families: &BTreeMap<u32, u32>,
) -> Result<Vec<Prototype>, String> {
    let mut prototypes = Vec::new();
    for word in 1..=word_count.saturating_sub(4) {
        let mut header = [0u32; 5];
        let mut complete = true;
        for offset in 0..5 {
            match decoded_word(decoded_words, word + offset) {
                Some(value) => header[offset] = value,
                None => {
                    complete = false;
                    break;
                }
            }
        }
        if !complete {
            continue;
        }
        let token = header[0] ^ PROTOTYPE_MASKS[0] ^ master_key;
        if !dispatch_families.contains_key(&token) {
            continue;
        }
        let initial_decode_state = header[1] ^ PROTOTYPE_MASKS[1] ^ master_key;
        let frame = header[2] ^ PROTOTYPE_MASKS[2] ^ master_key;
        let call = header[3] ^ PROTOTYPE_MASKS[3] ^ master_key;
        let entry_pc = (header[4] ^ PROTOTYPE_MASKS[4] ^ master_key) as usize;
        if entry_pc == 0 || entry_pc > word_count || decoded_word(decoded_words, entry_pc).is_none()
        {
            continue;
        }
        let fixed = frame & 1 == 1;
        let bank_base = (frame >> 14) & 131071;
        let parameter_count = ((call >> 1) & 7) as u16;
        let capture_count = ((call >> 5) & 1023) as usize;
        // Supported closure factories: 0..=4 fixed parameters (var28[5] is the
        // vararg factory). Reject unsupported arities.
        if fixed && parameter_count > 4 {
            continue;
        }
        // The register bank window must sit inside the 120-entry slot map.
        if bank_base + 3 > SLOT_MAP_ENTRIES as u32 {
            continue;
        }
        let parameter_words: usize = if fixed {
            ((parameter_count + 1) >> 1) as usize
        } else {
            0
        };
        let mut parameter_raw: Vec<u32> = Vec::new();
        for offset in 0..parameter_words {
            match decoded_word(decoded_words, word + 5 + offset) {
                Some(value) => parameter_raw.push(value),
                None => break,
            }
        }
        if parameter_raw.len() != parameter_words {
            continue;
        }
        let capture_at = word + 5 + parameter_words;
        let mut capture_raw: Vec<u32> = Vec::new();
        for offset in 0..capture_count {
            match decoded_word(decoded_words, capture_at + offset) {
                Some(value) => capture_raw.push(value),
                None => break,
            }
        }
        if capture_raw.len() != capture_count {
            continue;
        }

        let mut parameter_operands: Vec<u16> = Vec::new();
        for raw in parameter_raw {
            let value = raw ^ PARAMETER_XOR ^ master_key;
            parameter_operands.push((value & 0xFFFF) as u16);
            parameter_operands.push((value >> 16) as u16);
        }
        parameter_operands.truncate(parameter_count as usize);
        let captures: Vec<CaptureDescriptor> = capture_raw
            .iter()
            .map(|raw| {
                let value = *raw ^ CAPTURE_XOR ^ master_key;
                CaptureDescriptor {
                    destination_operand: (value & 0xFFFF) as u16,
                    source_operand: (value >> 16) as u16,
                }
            })
            .collect();

        // Parameter and capture operands must index the slot map relative to
        // the bank base.
        let mut operands_in_bounds = true;
        for operand in &parameter_operands {
            if (bank_base as usize) + (*operand as usize) > SLOT_MAP_ENTRIES {
                operands_in_bounds = false;
                break;
            }
        }
        if operands_in_bounds {
            for capture in &captures {
                if (bank_base as usize) + (capture.destination_operand as usize) > SLOT_MAP_ENTRIES
                    || (bank_base as usize) + (capture.source_operand as usize) > SLOT_MAP_ENTRIES
                {
                    operands_in_bounds = false;
                    break;
                }
            }
        }
        if !operands_in_bounds {
            continue;
        }

        prototypes.push(Prototype {
            word,
            byte_offset: (word - 1) * 4,
            encoded_reference: word as u32 ^ PROTOTYPE_REFERENCE_XOR,
            entry_pc,
            initial_decode_state,
            dispatch_token: token,
            frame_capacity: ((frame >> 1) & 8191) as u16,
            bank_base,
            prototype_salt: (call >> 16) as u16,
            fixed_parameter_mode: fixed,
            fixed_parameter_count: if fixed { Some(parameter_count) } else { None },
            parameter_operands,
            captures,
        });
    }
    if prototypes.is_empty() {
        return Err("no structurally valid prototypes found in the decoded words".to_owned());
    }
    // The entry prototype is derived from the master key; it must be among
    // the scanned candidates, otherwise the payload does not match the VM
    // structure found in the source.
    let top_reference = master_key
        ^ PROTOTYPE_TOP_ADDENDS
            .0
            .wrapping_add(PROTOTYPE_TOP_ADDENDS.1);
    let top_word = (top_reference ^ PROTOTYPE_REFERENCE_XOR) as usize;
    if !prototypes
        .iter()
        .any(|prototype| prototype.word == top_word)
    {
        return Err(format!(
            "top-level prototype at word {top_word} failed structural validation"
        ));
    }
    Ok(prototypes)
}

/// Scan every byte offset for a `var33` string record whose decoded length
/// fits inside the remaining payload, and decrypt the record body.
fn scan_string_records(payload: &[u8], master_key: u32) -> Result<Vec<StringConstant>, String> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(format!(
            "payload length {} exceeds the supported budget of {} bytes",
            payload.len(),
            MAX_PAYLOAD_BYTES
        ));
    }
    let mut records: Vec<StringConstant> = Vec::new();
    let mut total_bytes: usize = 0;
    let mut work: usize = 0;
    let mut offset = 0usize;
    while offset + 8 <= payload.len() {
        work += 8;
        if work > MAX_STRING_BYTES_TOTAL * 4 {
            return Err("string scan work budget exceeded".to_owned());
        }
        let record_key = read_u32(payload, offset) ^ STRING_HEADER_KEY_XOR;
        let length = (read_u32(payload, offset + 4) ^ (STRING_LENGTH_XOR ^ record_key)) as usize;
        if length <= payload.len() - offset - 8 {
            if records.len() >= MAX_STRING_RECORDS {
                return Err("too many string record candidates".to_owned());
            }
            if total_bytes + length > MAX_STRING_BYTES_TOTAL {
                return Err("aggregate string byte budget exceeded".to_owned());
            }
            // Reject overlapping record candidates: a real layout has disjoint
            // records, and overlap is a sign of a crafted/ambiguous header.
            if let Some(previous) = records.last() {
                let previous_end = previous.byte_offset + 8 + previous.value.len();
                if offset < previous_end {
                    return Err("overlapping string record candidate".to_owned());
                }
            }
            let mut value = vec![0u8; length];
            let mut state = record_key ^ master_key;
            let whole_words = length / 4;
            for index in 0..whole_words {
                state = state
                    .wrapping_mul(STRING_STREAM_MULTIPLIER)
                    .wrapping_add(STRING_STREAM_ADDEND);
                let word = read_u32(payload, offset + 8 + index * 4) ^ state;
                value[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
            for index in whole_words * 4..length {
                state = state
                    .wrapping_mul(STRING_STREAM_MULTIPLIER)
                    .wrapping_add(STRING_STREAM_ADDEND);
                value[index] = payload[offset + 8 + index] ^ (state % 256) as u8;
            }
            work += length;
            if work > MAX_STRING_BYTES_TOTAL * 4 {
                return Err("string scan work budget exceeded".to_owned());
            }
            total_bytes += length;
            records.push(StringConstant {
                byte_offset: offset,
                encoded_reference: offset as u32 ^ STRING_REFERENCE_XOR,
                value,
            });
        }
        offset += 1;
    }
    Ok(records)
}

/// Decode the encrypted f64 number records between the region base (decoded
/// header word 3) and the first string record.
fn scan_number_records(
    payload: &[u8],
    decoded_words: &[Option<u32>],
    master_key: u32,
    strings: &[StringConstant],
) -> Result<Vec<NumberConstant>, String> {
    let base_word = decoded_word(decoded_words, 3)
        .ok_or_else(|| "decoded header word 3 is missing".to_owned())?;
    let base = (base_word ^ NUMBER_BASE_XOR ^ master_key) as usize;
    let end = strings
        .iter()
        .map(|record| record.byte_offset)
        .min()
        .ok_or_else(|| {
            "no string records found; the numeric-region boundary is unknown".to_owned()
        })?;
    // Corroborate the string records: they must be mutually disjoint.
    let mut sorted_strings: Vec<&StringConstant> = strings.iter().collect();
    sorted_strings.sort_by_key(|record| record.byte_offset);
    for window in sorted_strings.windows(2) {
        let previous_end = window[0].byte_offset + 8 + window[0].value.len();
        if window[1].byte_offset < previous_end {
            return Err("overlapping string record candidate".to_owned());
        }
    }
    // No string record may overlap the numeric region [base, end).
    for record in strings {
        let record_end = record.byte_offset + 8 + record.value.len();
        if record.byte_offset < end && record_end > base {
            return Err("string record overlaps the numeric region".to_owned());
        }
    }
    // Do not blindly accept a header sitting exactly at the numeric base,
    // which would leave an uncorroborated empty f64 pool.
    if base == end && !strings.is_empty() {
        return Err("uncorroborated empty f64 pool at the numeric base".to_owned());
    }
    if base > end || end > payload.len() || (end - base) % 8 != 0 {
        return Err(format!(
            "numeric-region bounds are inconsistent: base {base}, end {end}"
        ));
    }
    let mut numbers = Vec::new();
    let count = (end - base) / 8;
    if count > MAX_NUMBER_RECORDS {
        return Err(format!(
            "numeric region contains {count} records, exceeding the supported budget of {MAX_NUMBER_RECORDS}"
        ));
    }
    for index in 1..=count {
        let byte_offset = base + (index - 1) * 8;
        let first = read_u32(payload, byte_offset)
            ^ (((NUMBER_FIRST_BASE + index as u64 * NUMBER_FIRST_STRIDE) % U32_MODULUS) as u32)
            ^ master_key;
        let second = read_u32(payload, byte_offset + 4)
            ^ (((NUMBER_SECOND_BASE + index as u64 * NUMBER_SECOND_STRIDE) % U32_MODULUS) as u32)
            ^ ((master_key >> 11) ^ (master_key << 21));
        let bits = (second as u64) << 32 | first as u64;
        numbers.push(NumberConstant {
            index,
            byte_offset,
            encoded_reference: index as u32 ^ NUMBER_REFERENCE_XOR,
            bits,
            value: f64::from_bits(bits),
        });
    }
    Ok(numbers)
}

// ---------------------------------------------------------------------------
// Profile validation: every algorithm constant and critical decoder expression
// must be present in the (identifier-normalized) source. A renamed wrapper is
// accepted because identifiers are resolved to their library binding; a
// changed formula is rejected because its constant or structure is absent.
// ---------------------------------------------------------------------------

fn normalized_tokens(
    tokens: &[Token],
    bindings: &std::collections::HashMap<String, String>,
) -> Vec<String> {
    tokens
        .iter()
        .map(|token| match token.kind {
            TokenKind::Identifier => bindings
                .get(&token.text)
                .cloned()
                .unwrap_or_else(|| "%id".to_owned()),
            TokenKind::Number => match lua_integer(&token.text) {
                Some(value) => value.to_string(),
                None => token.text.clone(),
            },
            _ => token.text.clone(),
        })
        .collect()
}

fn contains_sequence(haystack: &[String], needle: &[&str]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    // Redundant parentheses vary between beautifiers; ignore only those,
    // never unrelated intervening operators, statements, or functions.
    let haystack: Vec<&str> = haystack
        .iter()
        .map(String::as_str)
        .filter(|token| !matches!(*token, "(" | ")"))
        .collect();
    let needle: Vec<&str> = needle
        .iter()
        .copied()
        .filter(|token| !matches!(*token, "(" | ")"))
        .collect();
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

const PROFILE_PATTERNS: &[(&str, &[&str])] = &[
    (
        "key derivation seed",
        &["%id", "=", "bit32.bxor", "(", "%id", ",", "1473535036", ")"],
    ),
    (
        "word-key LCG",
        &[
            "(",
            "(",
            "%id",
            "*",
            "50673",
            "+",
            "3849295765",
            ")",
            ")",
            "%",
            "4294967296",
        ],
    ),
    (
        "xorshift fold (lshift 9)",
        &[
            "%id",
            "=",
            "bit32.bxor",
            "(",
            "%id",
            ",",
            "bit32.lshift",
            "(",
            "%id",
            ",",
            "9",
            ")",
            ")",
        ],
    ),
    (
        "xorshift fold (rshift 5)",
        &[
            "%id",
            "=",
            "bit32.bxor",
            "(",
            "%id",
            ",",
            "bit32.rshift",
            "(",
            "%id",
            ",",
            "5",
            ")",
            ")",
        ],
    ),
    (
        "xorshift fold (lshift 1)",
        &[
            "%id",
            "=",
            "bit32.bxor",
            "(",
            "%id",
            ",",
            "bit32.lshift",
            "(",
            "%id",
            ",",
            "1",
            ")",
            ")",
        ],
    ),
    (
        "header word decode",
        &[
            "%id",
            "[",
            "%id",
            "]",
            "=",
            "bit32.bxor",
            "(",
            "buffer.readu32",
            "(",
            "%id",
            ",",
            "%id",
            ")",
            ",",
            "%id",
            ")",
        ],
    ),
    (
        "seed read",
        &[
            "local",
            "%id",
            "=",
            "buffer.readu32",
            "(",
            "%id",
            ",",
            "12",
            ")",
        ],
    ),
    (
        "master key LCG",
        &[
            "(",
            "(",
            "%id",
            "*",
            "27383",
            "+",
            "2179554977",
            ")",
            ")",
            "%",
            "4294967296",
        ],
    ),
    (
        "master key fold",
        &[
            "%id",
            "=",
            "bit32.bxor",
            "(",
            "bit32.bxor",
            "(",
            "%id",
            ",",
            "%id",
            "[",
            "4",
            "]",
            ")",
            ",",
            "bit32.bxor",
            "(",
            "bit32.rshift",
            "(",
            "%id",
            ",",
            "13",
            ")",
            ",",
            "bit32.lshift",
            "(",
            "%id",
            ",",
            "19",
            ")",
            ")",
            ")",
        ],
    ),
    (
        "decoded range low",
        &[
            "%id",
            "=",
            "bit32.bxor",
            "(",
            "%id",
            "[",
            "1",
            "]",
            ",",
            "bit32.bxor",
            "(",
            "2967641488",
            ",",
            "%id",
            ")",
            ")",
        ],
    ),
    (
        "decoded range high",
        &[
            "%id",
            "=",
            "bit32.bxor",
            "(",
            "%id",
            "[",
            "2",
            "]",
            ",",
            "bit32.bxor",
            "(",
            "3915592545",
            ",",
            "%id",
            ")",
            ")",
        ],
    ),
    (
        "slot seed",
        &[
            "local",
            "%id",
            "=",
            "bit32.bxor",
            "(",
            "839935492",
            ",",
            "%id",
            ")",
        ],
    ),
    (
        "slot LCG",
        &[
            "(",
            "(",
            "%id",
            "*",
            "2441",
            "+",
            "597684479",
            ")",
            ")",
            "%",
            "4294967296",
        ],
    ),
    (
        "slot low half",
        &[
            "%id",
            "[",
            "%id",
            "]",
            "=",
            "bit32.band",
            "(",
            "%id",
            ",",
            "65535",
            ")",
        ],
    ),
    (
        "slot high half",
        &[
            "%id",
            "[",
            "%id",
            "+",
            "1",
            "]",
            "=",
            "bit32.rshift",
            "(",
            "%id",
            ",",
            "16",
            ")",
        ],
    ),
    ("bias seed", &["local", "%id", "=", "1002186909"]),
    (
        "bias LCG",
        &[
            "(",
            "(",
            "%id",
            "*",
            "18089",
            "+",
            "3507744737",
            ")",
            ")",
            "%",
            "4294967296",
        ],
    ),
    (
        "bias formula",
        &[
            "%id", "[", "%id", "]", "=", "1", "+", "(", "%id", "%", "200000", ")",
        ],
    ),
    (
        "permutation seeds",
        &[
            "local",
            "%id",
            ",",
            "%id",
            "=",
            "3491394721",
            ",",
            "3448714115",
        ],
    ),
    (
        "permutation LCG",
        &[
            "(",
            "(",
            "%id",
            "*",
            "22421",
            "+",
            "1113088905",
            ")",
            ")",
            "%",
            "4294967296",
        ],
    ),
    (
        "permutation swap index",
        &[
            "local",
            "%id",
            "=",
            "bit32.lshift",
            "(",
            "%id",
            "%",
            "(",
            "(",
            "%id",
            "+",
            "1",
            ")",
            ")",
            ",",
            "1",
            ")",
        ],
    ),
    (
        "permutation checksum write",
        &[
            "buffer.writeu16",
            "(",
            "%id",
            ",",
            "bit32.lshift",
            "(",
            "%id",
            ",",
            "1",
            ")",
            ",",
            "(",
            "(",
            "(",
            "%id",
            "*",
            "4",
            "+",
            "(",
            "(",
            "(",
            "%id",
            "*",
            "17",
            "+",
            "6191",
            ")",
            ")",
            "%",
            "16384",
            ")",
            ")",
            "*",
            "2",
            ")",
            "+",
            "bit32.band",
            "(",
            "%id",
            ",",
            "1",
            ")",
            ")",
            "%",
            "65536",
            ")",
        ],
    ),
    (
        "prototype mask 0",
        &[
            "local",
            "%id",
            "=",
            "bit32.bxor",
            "(",
            "%id",
            "[",
            "%id",
            "+",
            "0",
            "]",
            ",",
            "bit32.bxor",
            "(",
            "3909646029",
            ",",
            "%id",
            ")",
            ")",
        ],
    ),
    (
        "prototype mask 1",
        &[
            "local",
            "%id",
            "=",
            "bit32.bxor",
            "(",
            "%id",
            "[",
            "%id",
            "+",
            "1",
            "]",
            ",",
            "bit32.bxor",
            "(",
            "1413943958",
            ",",
            "%id",
            ")",
            ")",
        ],
    ),
    (
        "prototype mask 2",
        &[
            "local",
            "%id",
            "=",
            "bit32.bxor",
            "(",
            "%id",
            "[",
            "%id",
            "+",
            "2",
            "]",
            ",",
            "bit32.bxor",
            "(",
            "362291774",
            ",",
            "%id",
            ")",
            ")",
        ],
    ),
    (
        "prototype mask 3",
        &[
            "local",
            "%id",
            "=",
            "bit32.bxor",
            "(",
            "%id",
            "[",
            "%id",
            "+",
            "3",
            "]",
            ",",
            "bit32.bxor",
            "(",
            "2011604317",
            ",",
            "%id",
            ")",
            ")",
        ],
    ),
    (
        "prototype mask 4",
        &[
            "local",
            "%id",
            "=",
            "bit32.bxor",
            "(",
            "%id",
            "[",
            "%id",
            "+",
            "4",
            "]",
            ",",
            "bit32.bxor",
            "(",
            "3907258247",
            ",",
            "%id",
            ")",
            ")",
        ],
    ),
    (
        "prototype reference xor",
        &[
            "local",
            "%id",
            "=",
            "bit32.bxor",
            "(",
            "%id",
            ",",
            "651803",
            ")",
        ],
    ),
    (
        "prototype top addends",
        &[
            "local",
            "%id",
            "=",
            "bit32.bxor",
            "(",
            "%id",
            ",",
            "(",
            "(",
            "1006110062",
            "+",
            "1696795845",
            ")",
            ")",
            "%",
            "4294967296",
            ")",
        ],
    ),
    (
        "prototype field extract",
        &[
            "local",
            "%id",
            ",",
            "%id",
            ",",
            "%id",
            ",",
            "%id",
            ",",
            "%id",
            ",",
            "%id",
            "=",
            "bit32.extract",
            "(",
            "%id",
            ",",
            "1",
            ",",
            "13",
            ")",
            ",",
            "bit32.extract",
            "(",
            "%id",
            ",",
            "5",
            ",",
            "10",
            ")",
            ",",
            "bit32.band",
            "(",
            "bit32.rshift",
            "(",
            "%id",
            ",",
            "1",
            ")",
            ",",
            "7",
            ")",
            ",",
            "bit32.band",
            "(",
            "%id",
            ",",
            "1",
            ")",
            ",",
            "bit32.band",
            "(",
            "bit32.rshift",
            "(",
            "%id",
            ",",
            "14",
            ")",
            ",",
            "131071",
            ")",
            ",",
            "bit32.extract",
            "(",
            "%id",
            ",",
            "16",
            ",",
            "16",
            ")",
        ],
    ),
    (
        "capture xor",
        &[
            "bit32.extract",
            "(",
            "bit32.bxor",
            "(",
            "%id",
            "[",
            "(",
            "%id",
            "+",
            "%id",
            ")",
            "-",
            "1",
            "]",
            ",",
            "bit32.bxor",
            "(",
            "204142014",
            ",",
            "%id",
            ")",
            ")",
            ",",
            "0",
            ",",
            "16",
            ")",
        ],
    ),
    (
        "parameter xor",
        &["bit32.bxor", "(", "160755387", ",", "%id", ")"],
    ),
    (
        "string header key",
        &[
            "local",
            "%id",
            "=",
            "bit32.bxor",
            "(",
            "buffer.readu32",
            "(",
            "%id",
            ",",
            "%id",
            ")",
            ",",
            "4111886139",
            ")",
        ],
    ),
    (
        "string length",
        &[
            "local",
            "%id",
            "=",
            "bit32.bxor",
            "(",
            "buffer.readu32",
            "(",
            "%id",
            ",",
            "%id",
            "+",
            "4",
            ")",
            ",",
            "bit32.bxor",
            "(",
            "617852180",
            ",",
            "%id",
            ")",
            ")",
        ],
    ),
    (
        "string stream LCG",
        &[
            "(",
            "(",
            "%id",
            "*",
            "16177",
            "+",
            "888490141",
            ")",
            ")",
            "%",
            "4294967296",
        ],
    ),
    (
        "string reference",
        &[
            "local",
            "%id",
            "=",
            "bit32.bxor",
            "(",
            "%id",
            ",",
            "451966",
            ")",
        ],
    ),
    (
        "number base",
        &[
            "local",
            "%id",
            "=",
            "bit32.bxor",
            "(",
            "%id",
            "[",
            "3",
            "]",
            ",",
            "bit32.bxor",
            "(",
            "1307047751",
            ",",
            "%id",
            ")",
            ")",
        ],
    ),
    (
        "number reference",
        &[
            "local",
            "%id",
            "=",
            "bit32.bxor",
            "(",
            "%id",
            ",",
            "2023800",
            ")",
        ],
    ),
    (
        "number first",
        &[
            "bit32.bxor",
            "(",
            "(",
            "(",
            "3118829571",
            "+",
            "%id",
            "*",
            "457487",
            ")",
            ")",
            "%",
            "4294967296",
            ",",
            "%id",
            ")",
        ],
    ),
    (
        "number second",
        &[
            "bit32.bxor",
            "(",
            "(",
            "(",
            "3221349176",
            "+",
            "%id",
            "*",
            "476665",
            ")",
            ")",
            "%",
            "4294967296",
            ",",
            "bit32.bxor",
            "(",
            "bit32.rshift",
            "(",
            "%id",
            ",",
            "11",
            ")",
            ",",
            "bit32.lshift",
            "(",
            "%id",
            ",",
            "21",
            ")",
            ")",
            ")",
        ],
    ),
    (
        "integrity tbl1 ref",
        &[
            "for", "%id", "=", "1", ",", "13", "do", "local", "%id", "=", "%id", "[", "%id", "]",
        ],
    ),
    (
        "integrity comparison",
        &[
            "if",
            "#",
            "%id",
            "~=",
            "%id",
            "[",
            "%id",
            "]",
            "or",
            "%id",
            "*",
            "65536",
            "+",
            "%id",
            "~=",
            "%id",
            "[",
            "%id",
            "]",
            "then",
            "%id",
            "(",
            "\"ARTIFACT_INTEGRITY\"",
            ",",
            "0",
            ")",
        ],
    ),
    (
        "integrity loop bound",
        &[
            "for", "%id", "=", "1", ",", "13", "do", "local", "%id", "=", "%id", "[", "%id", "]",
        ],
    ),
    (
        "adler accum A",
        &[
            "(",
            "(",
            "%id",
            "+",
            "string.byte",
            "(",
            "%id",
            ",",
            "%id",
            ")",
            ")",
            "%",
            "65521",
        ],
    ),
    (
        "adler accum B",
        &[
            "%id", "=", "(", "(", "%id", "+", "%id", ")", ")", "%", "65521",
        ],
    ),
    (
        "integrity error",
        &["%id", "(", "\"ARTIFACT_INTEGRITY\"", ",", "0", ")"],
    ),
];

const CONSTANT_COUNTS: &[(&str, usize)] = &[
    ("1473535036", 1),
    ("50673", 2),
    ("3849295765", 2),
    ("27383", 1),
    ("2179554977", 1),
    ("2967641488", 1),
    ("3915592545", 1),
    ("839935492", 1),
    ("2441", 1),
    ("597684479", 1),
    ("1002186909", 1),
    ("18089", 1),
    ("3507744737", 1),
    ("200000", 1),
    ("3491394721", 1),
    ("3448714115", 1),
    ("22421", 2),
    ("1113088905", 2),
    ("3909646029", 2),
    ("1413943958", 2),
    ("362291774", 3),
    ("2011604317", 3),
    ("3907258247", 2),
    ("651803", 3),
    ("1006110062", 1),
    ("1696795845", 1),
    ("204142014", 3),
    ("160755387", 4),
    ("4111886139", 1),
    ("617852180", 1),
    ("16177", 2),
    ("888490141", 2),
    ("451966", 1),
    ("1307047751", 1),
    ("2023800", 1),
    ("3118829571", 1),
    ("457487", 1),
    ("3221349176", 1),
    ("476665", 1),
    ("65536", 4),
    ("65535", 15),
    ("65521", 2),
    ("16384", 3),
    ("131071", 2),
    ("120", 2),
    ("64", 2),
];

fn validate_profile(
    tokens: &[Token],
    bindings: &std::collections::HashMap<String, String>,
) -> Result<(), String> {
    let haystack = normalized_tokens(tokens, bindings);
    let missing: Vec<_> = PROFILE_PATTERNS
        .iter()
        .filter_map(|(name, pattern)| (!contains_sequence(&haystack, pattern)).then_some(*name))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "unsupported VM profile: expected expression(s) missing: {}",
            missing.join(", ")
        ));
    }
    // Every algorithm constant must occur exactly as often as in the supported
    // profile. A changed (or removed) constant therefore fails closed instead
    // of being silently ignored.
    for (constant, expected_count) in CONSTANT_COUNTS {
        let actual = haystack
            .iter()
            .filter(|token| token.as_str() == *constant)
            .count();
        if actual != *expected_count {
            return Err(format!(
                "unsupported VM profile: constant {constant} occurs {actual} time(s), expected {expected_count}"
            ));
        }
    }
    Ok(())
}

/// Statically decode the protected Lua source into the shared VM model. No
/// Luau is executed and no payload instruction is interpreted.
pub fn decode_source(source: &str) -> Result<DecodedVm, String> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(format!(
            "source exceeds the {MAX_SOURCE_BYTES}-byte analysis budget"
        ));
    }
    let tokens = tokenize(source)?;
    let rotor = crate::base85::certify(&tokens).is_ok();
    let sarp = crate::sarp::certify(&tokens).is_ok();
    let sarp_large = crate::sarp_large::certify(&tokens).is_ok();
    if usize::from(rotor) + usize::from(sarp) + usize::from(sarp_large) > 1 {
        return Err("ambiguous certified VM profiles".to_owned());
    }
    if rotor {
        return crate::base85::decode(source, &tokens);
    }
    if sarp {
        return crate::sarp::decode(source, &tokens);
    }
    if sarp_large {
        return crate::sarp_large::decode(source, &tokens);
    }
    let bindings = library_bindings(&tokens);
    validate_profile(&tokens, &bindings)?;
    let (first_table_name, initial_strings) = parse_first_string_table(&tokens, source)?;
    let number_tables = parse_local_number_tables(&tokens);
    let (_lengths, _checksums) =
        verify_integrity(&tokens, &number_tables, &initial_strings, &first_table_name)?;
    let initialization_argument = parse_initializer_argument(&tokens)?;
    let dispatch_families = parse_dispatch_map(&tokens)?;

    let payload = initial_strings
        .first()
        .ok_or_else(|| "the first table contains no payload literal".to_owned())?;
    if payload.is_empty() {
        return Err("payload literal is empty".to_owned());
    }
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(format!(
            "payload length {} exceeds the supported budget of {} bytes",
            payload.len(),
            MAX_PAYLOAD_BYTES
        ));
    }
    if payload.len() % 4 != 0 {
        return Err(format!(
            "payload length {} is not a multiple of four",
            payload.len()
        ));
    }
    let word_count = payload.len() / 4;
    if word_count < 4 {
        return Err("payload has fewer than four header words".to_owned());
    }

    let raw_words: Vec<u32> = (0..word_count)
        .map(|index| read_u32(payload, index * 4))
        .collect();

    // Header words 1..=4 with the rolling key stream.
    let mut decoded_words: Vec<Option<u32>> = vec![None; word_count + 1];
    let mut key_state = initialization_argument ^ KEY_DERIVATION_XOR;
    for index in 1..=4usize {
        key_state = next_word_key(key_state);
        decoded_words[index] = Some(read_u32(payload, (index - 1) * 4) ^ key_state);
    }

    // Master key, then the decoded word range [low, high].
    let seed = read_u32(payload, 12);
    let temporary = initialization_argument ^ seed;
    let header_word_4 =
        decoded_words[4].ok_or_else(|| "decoded header word 4 is missing".to_owned())?;
    let master_key = temporary
        .wrapping_mul(MASTER_KEY_MULTIPLIER)
        .wrapping_add(MASTER_KEY_ADDEND)
        ^ header_word_4
        ^ (temporary >> 13)
        ^ (seed << 19);
    let header_word_1 =
        decoded_words[1].ok_or_else(|| "decoded header word 1 is missing".to_owned())?;
    let header_word_2 =
        decoded_words[2].ok_or_else(|| "decoded header word 2 is missing".to_owned())?;
    let low = header_word_1 ^ RANGE_LOW_XOR ^ master_key;
    let high = header_word_2 ^ RANGE_HIGH_XOR ^ master_key;
    if low == 0 || low > high || high as usize > word_count {
        return Err(format!(
            "decoded word bounds invalid: low {low}, high {high}, words {word_count}"
        ));
    }
    for index in low..=high {
        key_state = next_word_key(key_state);
        decoded_words[index as usize] =
            Some(read_u32(payload, (index as usize - 1) * 4) ^ key_state);
    }

    // 120-entry physical slot map, read from the raw words after the range.
    let slot_base = high as usize * 4;
    if slot_base + SLOT_KEY_WORDS * 4 > payload.len() {
        return Err("slot map extends past the end of the payload".to_owned());
    }
    let mut slot_map: Vec<u16> = vec![0];
    let mut slot_state = SLOT_SEED_XOR ^ master_key;
    for index in 0..SLOT_KEY_WORDS {
        slot_state = slot_state
            .wrapping_mul(SLOT_KEY_MULTIPLIER)
            .wrapping_add(SLOT_KEY_ADDEND);
        let value = read_u32(payload, slot_base + index * 4) ^ slot_state;
        slot_map.push((value & 0xFFFF) as u16);
        if slot_map.len() <= SLOT_MAP_ENTRIES {
            slot_map.push((value >> 16) as u16);
        }
    }
    if slot_map.len() != SLOT_MAP_ENTRIES + 1 {
        return Err("slot map does not contain 120 entries".to_owned());
    }

    // 64 one-based immediate biases.
    let mut immediate_biases: Vec<u32> = vec![0];
    let mut bias_state = BIAS_SEED;
    for _ in 0..BIAS_COUNT {
        bias_state = bias_state
            .wrapping_mul(BIAS_MULTIPLIER)
            .wrapping_add(BIAS_ADDEND);
        immediate_biases.push(1 + bias_state % BIAS_MODULUS);
    }

    let permutation_parity = build_permutation_parity()?;

    let prototypes = scan_prototypes(&decoded_words, word_count, master_key, &dispatch_families)?;
    let entry_prototype = (master_key
        ^ PROTOTYPE_TOP_ADDENDS
            .0
            .wrapping_add(PROTOTYPE_TOP_ADDENDS.1)
        ^ PROTOTYPE_REFERENCE_XOR) as usize;
    let strings = scan_string_records(payload, master_key)?;
    let numbers = scan_number_records(payload, &decoded_words, master_key, &strings)?;

    let table_integrity: Vec<TableIntegrity> = initial_strings
        .iter()
        .enumerate()
        .map(|(index, literal)| TableIntegrity {
            index: index + 1,
            length: literal.len(),
            adler32: adler32(literal),
        })
        .collect();

    Ok(DecodedVm {
        profile: crate::ir::VmProfile::Adler32Lcg5Word,
        source_text: source.to_owned(),
        source_sha256: Some(sha256_hex(source.as_bytes())),
        payload: payload.clone(),
        raw_words,
        decoded_words,
        slot_map,
        immediate_biases,
        initialization_argument,
        master_key,
        decoded_range: (low as usize, high as usize),
        table_integrity,
        initial_strings,
        prototypes,
        entry_prototype,
        strings,
        numbers,
        dispatch_families,
        permutation_parity,
    })
}

pub fn decode_file(path: impl AsRef<std::path::Path>) -> Result<DecodedVm, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let mut source = String::new();
    file.take(MAX_SOURCE_BYTES as u64 + 1)
        .read_to_string(&mut source)
        .map_err(|error| error.to_string())?;
    decode_source(&source)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.lua");

    #[test]
    fn adler32_matches_reference_values() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"a"), 98 * 65536 + 98);
        assert_eq!(adler32(b"function"), 256181095);
        assert_eq!(adler32(b"table"), 103809545);
        assert_eq!(adler32(b"sym"), 45810010);
        assert_eq!(adler32(b"_"), 6291552);
    }

    #[test]
    fn adler32_accumulates_with_mod_65521() {
        // 300 bytes of 0xFF force repeated reductions past the Adler modulus.
        let data = vec![0xFFu8; 300];
        assert_eq!(adler32(&data), 3104778980);
        // A payload-scale input keeps the running sums below the modulus at
        // every step; the result matches an independent implementation.
        let data = vec![7u8; 2276];
        let mut a: u32 = 1;
        let mut b: u32 = 0;
        for &byte in &data {
            a = (a + byte as u32) % 65521;
            b = (b + a) % 65521;
        }
        assert_eq!(adler32(&data), (b << 16) | a);
    }

    #[test]
    fn quoted_literal_decodes_standard_escapes() {
        let source = r#""a\tb\\c\"d\ne""#;
        let (bytes, end) = scan_quoted(source, 0).unwrap();
        assert_eq!(bytes, b"a\tb\\c\"d\ne");
        assert_eq!(end, source.len());
        let (bytes, _) = scan_quoted("'\\a\\b\\f\\r\\v'", 0).unwrap();
        assert_eq!(bytes, [7, 8, 12, 13, 11]);
        let (bytes, _) = scan_quoted(r#"'\''"#, 0).unwrap();
        assert_eq!(bytes, [39]);
        let (bytes, _) = scan_quoted(r#"'"'"#, 0).unwrap();
        assert_eq!(bytes, [34]);
        let (bytes, _) = scan_quoted(r#""\'\"""#, 0).unwrap();
        assert_eq!(bytes, [39, 34]);
    }

    #[test]
    fn quoted_literal_decodes_decimal_escapes_up_to_three_digits() {
        let (bytes, end) = scan_quoted(r#""\78\79""#, 0).unwrap();
        assert_eq!(bytes, b"NO");
        assert_eq!(end, r#""\78\79""#.len());
        let (bytes, _) = scan_quoted(r#""\110\117""#, 0).unwrap();
        assert_eq!(bytes, b"nu");
        let (bytes, _) = scan_quoted(r#""\0\00\000\255""#, 0).unwrap();
        assert_eq!(bytes, [0, 0, 0, 255]);
        // Only three digits are consumed; the fourth is literal.
        let (bytes, _) = scan_quoted(r#""\1234""#, 0).unwrap();
        assert_eq!(bytes, [123, b'4']);
        // Values above 255 are rejected, exactly like the wrapper parser.
        assert!(scan_quoted(r#""\256""#, 0).is_err());
        assert!(scan_quoted(r#""\999""#, 0).is_err());
    }

    #[test]
    fn quoted_literal_decodes_hex_z_and_escaped_newline() {
        let (bytes, _) = scan_quoted(r#""\x41\x4c""#, 0).unwrap();
        assert_eq!(bytes, b"AL");
        assert!(scan_quoted(r#""\xZZ""#, 0).is_err());
        assert!(scan_quoted(r#""\x4""#, 0).is_err());
        let (bytes, _) = scan_quoted("\"a\\z    bc\"", 0).unwrap();
        assert_eq!(bytes, b"abc");
        let (bytes, _) = scan_quoted("\"a\\\nb\"", 0).unwrap();
        assert_eq!(bytes, b"a\nb");
        let (bytes, _) = scan_quoted("\"a\\\r\nb\"", 0).unwrap();
        assert_eq!(bytes, b"a\nb");
        let (bytes, _) = scan_quoted("\"a\\\rb\"", 0).unwrap();
        assert_eq!(bytes, b"a\nb");
        // Raw UTF-8 source bytes are preserved byte-for-byte, including
        // multi-byte characters; nothing is collapsed to a code point.
        let (bytes, _) = scan_quoted("\"é\"", 0).unwrap();
        assert_eq!(bytes, [0xC3, 0xA9]);
        let (bytes, _) = scan_quoted("\"Ā\"", 0).unwrap();
        assert_eq!(bytes, [0xC4, 0x80]);
        // Raw newlines are not allowed inside a short string literal.
        assert!(scan_quoted("\"a\nb\"", 0).is_err());
        assert!(scan_quoted("\"a\rb\"", 0).is_err());
        // \z skips ASCII Lua whitespace only (space, tab, newline, vtab, ff, CR).
        let (bytes, _) = scan_quoted("\"a\\z   bc\"", 0).unwrap();
        assert_eq!(bytes, b"abc");
        let (bytes, _) = scan_quoted("\"a\\z\u{00A0}b\"", 0).unwrap();
        assert_eq!(bytes, [b'a', 0xC2, 0xA0, b'b']);
        assert!(scan_quoted(r#""unterminated"#, 0).is_err());
    }

    #[test]
    fn tokenizer_never_splits_on_brace_semicolon_inside_literals() {
        // The payload literal contains the byte sequence `};`, which must
        // never terminate the surrounding table.
        let source = concat!(
            "local t = {\"\\175};\\149\", \"ok\"};\n",
            "local l = {4, 2};\n",
            "local c = {2467128108, 256181095};\n"
        );
        let tokens = tokenize(source).unwrap();
        let (_, strings) = parse_first_string_table(&tokens, source).unwrap();
        assert_eq!(strings, vec![vec![0xAF, b'}', b';', 0x95], b"ok".to_vec()]);
        let tables = parse_local_number_tables(&tokens);
        assert_eq!(tables.len(), 2);
        assert_eq!(tables[0].values, vec![4, 2]);
        assert_eq!(tables[1].values, vec![2467128108, 256181095]);
    }

    #[test]
    fn tokenizer_handles_comments_and_long_brackets() {
        let source = "-- header\nlocal t = {[[a}b]], \"x\"}; -- trailing\n";
        let tokens = tokenize(source).unwrap();
        // Long-bracket literals are recognized but rejected as payload
        // containers, mirroring the wrapper's quoted-literal parser.
        assert!(parse_first_string_table(&tokens, source).is_err());
        assert!(tokenize("--[==[ never closed").is_err());
        assert!(tokenize("\"unterminated").is_err());
    }

    #[test]
    fn lua_integer_parses_decimal_hex_and_binary() {
        assert_eq!(lua_integer("2276"), Some(2276));
        assert_eq!(lua_integer("0x10"), Some(16));
        assert_eq!(lua_integer("0b101"), Some(5));
        assert_eq!(lua_integer("1.5"), None);
        assert_eq!(lua_integer("1e3"), None);
        assert_eq!(lua_integer("-1"), None);
    }

    #[test]
    fn sha256_matches_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"The quick brown fox jumps over the lazy dog"),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        );
    }

    /// Mutation mirror: corrupted payload byte is rejected by integrity check.
    #[test]
    fn mutation_corrupted_payload_rejected() {
        let path = std::path::Path::new(SAMPLE_PATH);
        if !path.exists() {
            return;
        }
        let source = std::fs::read_to_string(path).unwrap();
        let mutated = source.replacen(r#""\183n"#, r#""\182n"#, 1);
        assert_ne!(source, mutated);
        let err = decode_source(&mutated).expect_err("corrupted payload must fail");
        assert!(err.contains("integrity"), "unexpected error: {err}");
    }

    /// Mutation mirror: corrupted checksum literal is rejected.
    #[test]
    fn mutation_corrupted_checksum_rejected() {
        let path = std::path::Path::new(SAMPLE_PATH);
        if !path.exists() {
            return;
        }
        let source = std::fs::read_to_string(path).unwrap();
        let mutated = source.replacen("2467128108", "2467128109", 1);
        assert_ne!(source, mutated);
        let err = decode_source(&mutated).expect_err("corrupted checksum must fail");
        assert!(err.contains("integrity"), "unexpected error: {err}");
    }

    /// Mutation mirror: changed algorithm constant is rejected.
    #[test]
    fn mutation_changed_constant_rejected() {
        let path = std::path::Path::new(SAMPLE_PATH);
        if !path.exists() {
            return;
        }
        let source = std::fs::read_to_string(path).unwrap();
        for (before, after) in [
            ("1002186909", "1002186908"),
            ("3491394721", "3491394720"),
            ("617852180", "617852181"),
            ("888490141", "888490140"),
        ] {
            let changed = source.replacen(before, after, 1);
            assert_ne!(source, changed);
            assert!(
                decode_source(&changed).is_err(),
                "unsupported formula change {before} -> {after} was silently ignored"
            );
        }
    }

    /// Mutation mirror: unused matching checksum table cannot hide corrupted active table.
    #[test]
    fn mutation_decoy_integrity_rejected() {
        let path = std::path::Path::new(SAMPLE_PATH);
        if !path.exists() {
            return;
        }
        let source = std::fs::read_to_string(path).unwrap();
        let assignment = source
            .find("local tbl3 = {")
            .expect("active checksum table");
        let start = assignment + source[assignment..].find('{').unwrap();
        let end = start + source[start..].find('}').unwrap();
        let original_values = &source[start..=end];
        let invalid = source.replacen("2467128108", "2467128109", 1);
        let decoy = format!("{invalid}\nlocal unusedChecksums = {original_values};\n");
        assert!(
            decode_source(&decoy).is_err(),
            "unused matching values must not substitute"
        );
    }

    /// Mutation mirror: raw UTF-8 bytes cannot impersonate a decimal escape.
    #[test]
    fn mutation_raw_utf8_rejected() {
        let path = std::path::Path::new(SAMPLE_PATH);
        if !path.exists() {
            return;
        }
        let source = std::fs::read_to_string(path).unwrap();
        let changed = source.replacen(r"\233", "é", 1);
        assert_ne!(source, changed);
        assert!(decode_source(&changed).is_err());
    }

    /// Mutation mirror: raw newline inside short payload literal is rejected.
    #[test]
    fn mutation_raw_newline_rejected() {
        let path = std::path::Path::new(SAMPLE_PATH);
        if !path.exists() {
            return;
        }
        let source = std::fs::read_to_string(path).unwrap();
        let changed = source.replacen(r#""\183n"#, "\"\\183\n", 1);
        assert_ne!(source, changed);
        assert!(decode_source(&changed).is_err());
    }

    /// Mutation mirror: dead initializer call cannot hide changed real argument.
    #[test]
    fn mutation_dead_initializer_rejected() {
        let path = std::path::Path::new(SAMPLE_PATH);
        if !path.exists() {
            return;
        }
        let source = std::fs::read_to_string(path).unwrap();
        let changed = source.replacen("18932807, 3954275856", "18932806, 3954275856", 1);
        let inserted = changed.replacen(
            "local var651 =",
            "if false then var40(var58(18932807, 3954275856)); end;\nlocal var651 =",
            1,
        );
        assert_ne!(changed, inserted);
        assert!(decode_source(&inserted).is_err());
    }

    /// Mutation mirror: initializer argument is read from current source.
    #[test]
    fn mutation_initializer_argument_from_source() {
        let path = std::path::Path::new(SAMPLE_PATH);
        if !path.exists() {
            return;
        }
        let source = std::fs::read_to_string(path).unwrap();
        let baseline = decode_source(&source).expect("valid baseline");
        let mutated = source.replacen("18932807, 3954275856", "18932806, 3954275856", 1);
        assert_ne!(source, mutated);
        match decode_source(&mutated) {
            Ok(vm) => {
                assert_ne!(baseline.initialization_argument, vm.initialization_argument);
                assert_ne!(baseline.master_key, vm.master_key);
            }
            Err(error) => {
                assert!(
                    error.contains("bounds")
                        || error.contains("prototype")
                        || error.contains("region"),
                    "changed key must fail in mathematical decoding: {error}"
                );
            }
        }
    }

    /// Mutation mirror: comment and whitespace changes preserve decoded data.
    #[test]
    fn mutation_comments_preserve_data() {
        let path = std::path::Path::new(SAMPLE_PATH);
        if !path.exists() {
            return;
        }
        let source = std::fs::read_to_string(path).unwrap();
        let expected = decode_source(&source).expect("valid baseline");
        let changed = format!("--[=[ ignored }}; and \\\" literals ]=]\n\n{source}");
        let actual = decode_source(&changed).expect("comments must not alter extraction");
        assert_eq!(expected.payload, actual.payload);
        assert_eq!(expected.decoded_words, actual.decoded_words);
        assert_eq!(expected.master_key, actual.master_key);
        assert_eq!(expected.slot_map, actual.slot_map);
        assert_eq!(expected.prototypes, actual.prototypes);
        assert_eq!(expected.strings, actual.strings);
        assert_eq!(expected.numbers, actual.numbers);
    }

    /// Focused: profile validation rejects each mutated algorithm constant.
    #[test]
    fn focused_profile_rejects_changed_constant() {
        // Use a tiny synthetic check: a source missing the bias seed must fail.
        let bad = "local t = {\"x\"};\nlocal tbl2 = {1};\nlocal tbl3 = {2467128108};\n";
        assert!(decode_source(bad).is_err());
    }

    /// Focused: scan_quoted preserves raw UTF-8 and rejects raw newlines.
    #[test]
    fn focused_raw_utf8_and_newline() {
        let (b, _) = scan_quoted("\"é\"", 0).unwrap();
        assert_eq!(b, [0xC3, 0xA9]);
        let (b, _) = scan_quoted("\"a\\z\u{00A0}b\"", 0).unwrap();
        assert_eq!(b, [b'a', 0xC2, 0xA0, b'b']);
        assert!(scan_quoted("\"a\nb\"", 0).is_err());
    }
    /// the local attachment is not present so the suite stays portable.
    #[test]
    fn decodes_supplied_sample_statically() {
        let path = std::path::Path::new(SAMPLE_PATH);
        if !path.exists() {
            eprintln!("skipping: sample source not present at {SAMPLE_PATH}");
            return;
        }
        let vm = decode_file(path).unwrap();

        // Source fingerprint of deobfuscated-beautifully_at_least.lua.
        assert_eq!(
            vm.source_sha256.as_deref(),
            Some("df8b4fa9a80278af33f069cd836470a49b86c2dd53059afb80d1aba0dfdd69ec")
        );
        // The 2276-byte protected buffer matches the reference payload.
        assert_eq!(vm.payload.len(), 2276);
        assert_eq!(
            sha256_hex(&vm.payload),
            "aedd2957ca229f1c1684ebdea85eaa4d5d247cc52a21b8ec47d2a29e932dad91"
        );

        // Initializer argument parsed from the source call site, and the
        // var40-derived master key and decoded word range.
        assert_eq!(vm.initialization_argument, 3935408727);
        assert_eq!(vm.master_key, 2702369233);
        assert_eq!(vm.decoded_range, (24, 509));
        assert_eq!(vm.decoded_words.len(), 570);
        assert_eq!(
            vm.decoded_words
                .iter()
                .filter(|word| word.is_some())
                .count(),
            490
        );
        assert_eq!(vm.raw_words.len(), 569);
        assert_eq!(vm.decoded_words[1], Some(300973145));
        assert_eq!(vm.decoded_words[2], Some(1215419213));
        assert_eq!(vm.decoded_words[3], Some(3975485062));
        assert_eq!(vm.decoded_words[4], Some(2440930595));
        assert_eq!(vm.decoded_words[24], Some(1209685656));
        assert_eq!(vm.decoded_words[388], Some(3188590727));
        assert_eq!(vm.decoded_words[413], Some(834354289));
        assert_eq!(vm.decoded_words[505], Some(1209683746));
        assert_eq!(vm.decoded_words[509], Some(1240917963));
        // Words outside the header and range stay absent, never zero.
        assert_eq!(vm.decoded_words[5], None);
        assert_eq!(vm.decoded_words[23], None);
        assert_eq!(vm.decoded_words[510], None);

        // 120-entry slot map (one-based, index zero zero).
        assert_eq!(vm.slot_map.len(), 121);
        assert_eq!(
            &vm.slot_map[1..=16],
            &[30, 28, 29, 14, 11, 15, 19, 3, 34, 39, 25, 36, 42, 5, 44, 1]
        );
        assert_eq!(vm.slot_map[120], 20);

        // Immediate biases (one-based, index zero zero).
        assert_eq!(vm.immediate_biases.len(), 65);
        assert_eq!(
            &vm.immediate_biases[1..=6],
            &[185223, 14104, 91281, 55282, 186811, 104876]
        );
        assert_eq!(vm.immediate_biases[64], 159198);

        // Prototype scan finds exactly the two reference prototypes.
        assert_eq!(
            vm.prototypes.iter().map(|p| p.word).collect::<Vec<_>>(),
            vec![24, 505]
        );
        let a = &vm.prototypes[0];
        assert_eq!(
            (
                a.word,
                a.byte_offset,
                a.encoded_reference,
                a.entry_pc,
                a.initial_decode_state,
                a.dispatch_token,
                a.frame_capacity,
                a.bank_base,
                a.prototype_salt
            ),
            (24, 92, 651779, 388, 4073635425, 49540, 46, 24, 12228)
        );
        assert!(a.fixed_parameter_mode);
        assert_eq!(a.fixed_parameter_count, Some(1));
        assert_eq!(a.parameter_operands, vec![5]);
        assert!(a.captures.is_empty());
        let b = &vm.prototypes[1];
        assert_eq!(
            (
                b.word,
                b.byte_offset,
                b.encoded_reference,
                b.entry_pc,
                b.initial_decode_state,
                b.dispatch_token,
                b.frame_capacity,
                b.bank_base,
                b.prototype_salt
            ),
            (505, 2016, 652258, 413, 834226203, 55358, 44, 14, 30664)
        );
        assert!(!b.fixed_parameter_mode);
        assert_eq!(b.fixed_parameter_count, None);
        assert!(b.parameter_operands.is_empty());
        assert!(b.captures.is_empty());

        // var33 string records found by the full byte-offset scan.
        assert_eq!(vm.strings.len(), 3);
        assert_eq!(
            (vm.strings[0].byte_offset, vm.strings[0].encoded_reference),
            (48, 451918)
        );
        assert_eq!(vm.strings[0].value, b"table");
        assert_eq!(vm.strings[1].byte_offset, 64);
        assert_eq!(vm.strings[1].value, b"concat");
        assert_eq!(vm.strings[2].byte_offset, 80);
        assert_eq!(vm.strings[2].value, b",");

        // var34 f64 records between the region base and the first string.
        assert_eq!(vm.numbers.len(), 4);
        assert_eq!(vm.numbers[0].index, 1);
        assert_eq!(vm.numbers[0].byte_offset, 16);
        assert_eq!(vm.numbers[0].encoded_reference, 2023801);
        assert_eq!(vm.numbers[0].value, -131.0);
        assert_eq!(vm.numbers[0].bits, (-131.0f64).to_bits());
        assert_eq!(vm.numbers[1].byte_offset, 24);
        assert_eq!(vm.numbers[1].value, 757.0);
        assert_eq!(vm.numbers[2].byte_offset, 32);
        assert_eq!(vm.numbers[2].value, -650.0 / 7.0);
        assert_eq!(vm.numbers[3].byte_offset, 40);
        assert_eq!(vm.numbers[3].value, 289.0);
        assert_eq!(vm.numbers[3].encoded_reference, 2023804);

        // Dispatch families parsed from the source's var17 table.
        assert_eq!(vm.dispatch_families.len(), 13);
        assert_eq!(vm.dispatch_families.get(&9179), Some(&1173));
        assert_eq!(vm.dispatch_families.get(&57492), Some(&4270));
        assert_eq!(vm.dispatch_families.get(&42961), Some(&8258));
        assert_eq!(vm.dispatch_families.get(&49540), Some(&6094));
        assert_eq!(vm.dispatch_families.get(&55358), Some(&6965));
        assert_eq!(vm.dispatch_families.get(&35097), Some(&5377));
        assert_eq!(vm.dispatch_families.get(&16911), Some(&8487));

        // Permutation parity: full 16384-entry map, with the reference
        // branch probes at indices 0 and 2.
        assert_eq!(vm.permutation_parity.len(), 16384);
        assert_eq!(vm.permutation_parity.get(&0), Some(&1));
        assert_eq!(vm.permutation_parity.get(&2), Some(&0));

        // Integrity metadata derived from the parsed literals and tables.
        assert_eq!(vm.table_integrity.len(), 13);
        assert_eq!(
            vm.table_integrity[0],
            TableIntegrity {
                index: 1,
                length: 2276,
                adler32: 2467128108
            }
        );
        assert_eq!(vm.table_integrity[1].adler32, 256181095);
        assert_eq!(vm.table_integrity[12].adler32, 6291552);
        assert_eq!(vm.initial_strings.len(), 13);
        assert_eq!(vm.initial_strings[1], b"function".to_vec());
        assert_eq!(vm.initial_strings[8], b"string".to_vec());
        assert_eq!(vm.initial_strings[9], b"table".to_vec());
        assert_eq!(vm.initial_strings[11], b"nil".to_vec());
        assert_eq!(vm.initial_strings[12], b"_".to_vec());
        assert_eq!(vm.source_text.len(), 122794);
    }
}
