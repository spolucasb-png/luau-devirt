//! Integration verification of the static Luau devirtualizer against the
//! checked-in Python analysis baseline for the protected T001 sample.
//!
//! # Scope and safety
//!
//! * The only inputs are static file reads: the uploaded sample
//!   `deobfuscated-beautifully_at_least.lua` and the checked-in baseline
//!   (`T001-analysis/decoded-metadata.json`, `T001-analysis/VM-DISASSEMBLY.md`,
//!   and `T001-VM-ANALYSIS.md`). The sample and every emitted Luau chunk are
//!   parsed as text only. **Nothing is ever executed** — no `loadstring`, no
//!   script runner, no Roblox/game/service boundary is ever reached from here.
//! * The optional validator step invokes only the local `luau-decompiler
//!   validate --builtin --no-color <file>` syntax-validation subcommand on
//!   **generated output only** (never the sample). `--builtin` forces the
//!   validator's own in-process checker and skips its PATH probe (the default
//!   probe would find the installed `luau.exe`, which executes scripts, and
//!   call an unsupported flag). This is parser/syntax validation, NOT official
//!   bytecode compilation. As defense in depth the child `PATH` is also
//!   scrubbed to the validator's own directory so no external tool can be
//!   spawned even if the flag semantics change.
//!
//! # Baseline facts compared
//!
//! Decoded payload digest/size (2,276 bytes, SHA-256 from the analysis MD),
//! initialization argument and master key, decoded/populated word range with
//! absent words kept `None` rather than zero, the 120-entry slot map and the
//! 64 immediate biases, both prototype headers (word 24 and word 505), the
//! three string constants (`table`, `concat`, `","`), the four f64 constants,
//! the 55 reachable instruction addresses and the 109 retained state variants,
//! the dispatch token map, the 13-string integrity table, the emitted output
//! markers, and the emitted chunk's full token structure against the sibling
//! readable reconstruction `T001-deobfuscated.luau` (comments/whitespace
//! ignored, exact non-identifier tokens, decoded string/number literal
//! values, one consistent bijective identifier rename).
//!
//! # Portability
//!
//! * `LUAU_DEVIRT_SAMPLE` overrides `tests/fixtures/sample.lua`.
//! * `LUAU_DEVIRT_ANALYSIS_DIR` overrides the bundled `tests/fixtures` directory.
//! * `LUAU_DEVIRT_BASELINE_OUTPUT` overrides the readable reference output;
//!   otherwise `tests/fixtures/T001-deobfuscated.luau` is used.
//! * `LUAU_DEVIRT_VALIDATOR` overrides the syntax-validator executable;
//!   otherwise `tools/validator-build/release/luau-decompiler(.exe)` is used.
//! * If a default input is genuinely unavailable the test prints a clear
//!   `SKIP: ...` line to stderr (use `cargo test -- --nocapture` to see it)
//!   and passes without asserting. An explicitly configured override that
//!   cannot be read fails loudly instead.
//!
//! The release includes all regression input data. Optional external compiler,
//! analyzer, and parser checks state clearly when their tools are unavailable.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use luau_devirt::ir::{CodegenOptions, DecodedVm, LiftedProgram, VmState};
use luau_devirt::{decode_source, emit_luau, walk_cfg};

// =========================================================================
// Path resolution and baseline access
// =========================================================================

const SAMPLE_BASENAME: &str = "sample.lua";
const VM_ANALYSIS_BASENAME: &str = "T001-VM-ANALYSIS.md";
const DISASSEMBLY_BASENAME: &str = "VM-DISASSEMBLY.md";
const METADATA_BASENAME: &str = "decoded-metadata.json";
const BASELINE_OUTPUT_BASENAME: &str = "T001-deobfuscated.luau";

/// The crate directory, baked in at compile time by cargo.
fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name).map(PathBuf::from)
}

/// Load the sample source. `None` (a skip) only when neither the
/// `LUAU_DEVIRT_SAMPLE` override nor the sibling file exists; an override
/// that is set but unreadable fails loudly.
fn load_sample_source() -> Option<String> {
    if let Some(path) = env_path("LUAU_DEVIRT_SAMPLE") {
        let bytes = fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "LUAU_DEVIRT_SAMPLE is set but unreadable ({}): {error}",
                path.display()
            )
        });
        return Some(String::from_utf8_lossy(&bytes).into_owned());
    }
    let sibling = manifest_dir()
        .join("tests")
        .join("fixtures")
        .join(SAMPLE_BASENAME);
    if !sibling.is_file() {
        return None;
    }
    Some(read_lossy(&sibling))
}

fn analysis_dir() -> PathBuf {
    env_path("LUAU_DEVIRT_ANALYSIS_DIR")
        .unwrap_or_else(|| manifest_dir().join("tests").join("fixtures"))
}

/// Locate a baseline file inside the analysis directory, optionally also
/// checking one level above it (T001-VM-ANALYSIS.md lives next to it).
fn baseline_file(basename: &str, also_parent: bool) -> Option<PathBuf> {
    let dir = analysis_dir();
    let primary = dir.join(basename);
    if primary.is_file() {
        return Some(primary);
    }
    if also_parent {
        let parent = dir.join("..").join(basename);
        if parent.is_file() {
            return Some(parent);
        }
    }
    None
}

fn read_lossy(path: &Path) -> String {
    let bytes =
        fs::read(path).unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    String::from_utf8_lossy(&bytes).into_owned()
}

fn load_metadata() -> Option<Json> {
    let path = baseline_file(METADATA_BASENAME, false)?;
    let text = read_lossy(&path);
    Some(
        parse_json(&text)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display())),
    )
}

fn load_vm_analysis() -> Option<String> {
    baseline_file(VM_ANALYSIS_BASENAME, true).map(|path| read_lossy(&path))
}

fn load_disassembly() -> Option<String> {
    baseline_file(DISASSEMBLY_BASENAME, false).map(|path| read_lossy(&path))
}

/// Load the readable reference output that the emitter is expected to match
/// modulo identifier rename. `None` (a skip) only when neither the
/// `LUAU_DEVIRT_BASELINE_OUTPUT` override nor the sibling file exists; an
/// override that is set but unreadable fails loudly.
fn load_baseline_output() -> Option<String> {
    if let Some(path) = env_path("LUAU_DEVIRT_BASELINE_OUTPUT") {
        let bytes = fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "LUAU_DEVIRT_BASELINE_OUTPUT is set but unreadable ({}): {error}",
                path.display()
            )
        });
        return Some(String::from_utf8_lossy(&bytes).into_owned());
    }
    let sibling = manifest_dir()
        .join("tests")
        .join("fixtures")
        .join(BASELINE_OUTPUT_BASENAME);
    sibling.is_file().then(|| read_lossy(&sibling))
}

fn skip_test(reason: &str) {
    let name = std::thread::current()
        .name()
        .unwrap_or("<unnamed>")
        .to_owned();
    eprintln!(
        "SKIP {name}: {reason} (skips print to stderr; run `cargo test -- --nocapture` to see them)"
    );
}

const SAMPLE_SKIP: &str = "sample unavailable: set LUAU_DEVIRT_SAMPLE or place \
     deobfuscated-beautifully_at_least.lua next to the crate";
const METADATA_SKIP: &str = "decoded-metadata.json unavailable: set \
     LUAU_DEVIRT_ANALYSIS_DIR or restore the T001-analysis baseline directory";
const BASELINE_OUTPUT_SKIP: &str = "baseline readable output unavailable: set \
     LUAU_DEVIRT_BASELINE_OUTPUT or place T001-deobfuscated.luau next to the crate";

// =========================================================================
// Stage helpers with merge-readiness reporting
// =========================================================================

/// Report a failing pipeline stage. While the decoder/CFG/codegen modules are
/// unmerged stubs their errors say "not initialized"; turn that into an
/// actionable merge note instead of a confusing baseline mismatch.
fn stage_failure(stage: &str, message: &str) -> ! {
    panic!("{stage} failed: {message}");
}

fn decode_or_explain(source: &str) -> DecodedVm {
    match decode_source(source) {
        Ok(vm) => vm,
        Err(message) => stage_failure("decode_source", &message),
    }
}

fn walk_or_explain(vm: &DecodedVm) -> LiftedProgram {
    match walk_cfg(vm) {
        Ok(program) => program,
        Err(message) => stage_failure("walk_cfg", &message),
    }
}

fn emit_or_explain(program: &LiftedProgram, options: &CodegenOptions) -> String {
    match emit_luau(program, options) {
        Ok(source) => source,
        Err(message) => stage_failure("emit_luau", &message),
    }
}

// =========================================================================
// Minimal JSON support (std-only; no external dependency)
// =========================================================================

#[derive(Clone, Debug)]
enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, value)| value),
            _ => None,
        }
    }

    fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Int(value) => u64::try_from(*value).ok(),
            _ => None,
        }
    }

    fn as_usize(&self) -> Option<usize> {
        self.as_u64().and_then(|value| usize::try_from(value).ok())
    }

    fn as_u32(&self) -> Option<u32> {
        self.as_u64().and_then(|value| u32::try_from(value).ok())
    }

    fn as_u16(&self) -> Option<u16> {
        self.as_u64().and_then(|value| u16::try_from(value).ok())
    }

    fn as_u8(&self) -> Option<u8> {
        self.as_u64().and_then(|value| u8::try_from(value).ok())
    }

    fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Int(value) => Some(*value as f64),
            Json::Float(value) => Some(*value),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(value) => Some(value),
            _ => None,
        }
    }

    fn as_arr(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(items) => Some(items),
            _ => None,
        }
    }

    fn as_pairs(&self) -> Option<&[(String, Json)]> {
        match self {
            Json::Obj(pairs) => Some(pairs),
            _ => None,
        }
    }

    fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(value) => Some(*value),
            _ => None,
        }
    }

    fn is_null(&self) -> bool {
        matches!(self, Json::Null)
    }
}

fn parse_json(text: &str) -> Result<Json, String> {
    let mut parser = JsonParser {
        bytes: text.as_bytes(),
        pos: 0,
    };
    parser.skip_ws();
    let value = parser.parse_value()?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err(format!("trailing data at byte {}", parser.pos));
    }
    Ok(value)
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(format!("expected {:?} at byte {}", byte as char, self.pos))
        }
    }

    fn parse_value(&mut self) -> Result<Json, String> {
        match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(Json::Str(self.parse_string()?)),
            Some(b't') => self.parse_literal("true", Json::Bool(true)),
            Some(b'f') => self.parse_literal("false", Json::Bool(false)),
            Some(b'n') => self.parse_literal("null", Json::Null),
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            other => Err(format!(
                "unexpected {:?} at byte {}",
                other.map(|byte| byte as char),
                self.pos
            )),
        }
    }

    fn parse_literal(&mut self, spelling: &str, value: Json) -> Result<Json, String> {
        if self.bytes[self.pos..].starts_with(spelling.as_bytes()) {
            self.pos += spelling.len();
            Ok(value)
        } else {
            Err(format!("invalid literal at byte {}", self.pos))
        }
    }

    fn parse_object(&mut self) -> Result<Json, String> {
        self.expect(b'{')?;
        let mut pairs = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Obj(pairs));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let value = self.parse_value()?;
            pairs.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Obj(pairs));
                }
                other => {
                    return Err(format!(
                        "expected ',' or '}}' at byte {} ({:?})",
                        self.pos,
                        other.map(|byte| byte as char)
                    ))
                }
            }
        }
    }

    fn parse_array(&mut self) -> Result<Json, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            self.skip_ws();
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Arr(items));
                }
                other => {
                    return Err(format!(
                        "expected ',' or ']' at byte {} ({:?})",
                        self.pos,
                        other.map(|byte| byte as char)
                    ))
                }
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err("unterminated JSON string".to_owned());
            };
            self.pos += 1;
            match byte {
                b'"' => return Ok(out),
                b'\\' => {
                    let Some(escape) = self.peek() else {
                        return Err("unterminated JSON escape".to_owned());
                    };
                    self.pos += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hex = self.take_chars(4)?;
                            let code = u16::from_str_radix(&hex, 16)
                                .map_err(|_| "invalid \\u escape".to_owned())?;
                            out.push(
                                char::from_u32(u32::from(code)).ok_or("invalid \\u code point")?,
                            );
                        }
                        other => return Err(format!("invalid escape \\{}", other as char)),
                    }
                }
                other if other < 0x20 => return Err("control character in JSON string".to_owned()),
                other => {
                    let length = utf8_char_len(other);
                    let end = self.pos - 1 + length;
                    if end > self.bytes.len() {
                        return Err("truncated character in JSON string".to_owned());
                    }
                    let chunk = std::str::from_utf8(&self.bytes[self.pos - 1..end])
                        .map_err(|_| "invalid UTF-8 in JSON string".to_owned())?;
                    out.push_str(chunk);
                    self.pos = end;
                }
            }
        }
    }

    fn take_chars(&mut self, count: usize) -> Result<String, String> {
        if self.pos + count > self.bytes.len() {
            return Err("truncated JSON escape".to_owned());
        }
        let chunk = std::str::from_utf8(&self.bytes[self.pos..self.pos + count])
            .map_err(|_| "invalid UTF-8 in JSON escape".to_owned())?
            .to_owned();
        self.pos += count;
        Ok(chunk)
    }

    fn parse_number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let mut is_float = false;
        while let Some(byte) = self.peek() {
            match byte {
                b'0'..=b'9' => self.pos += 1,
                b'.' => {
                    is_float = true;
                    self.pos += 1;
                }
                b'e' | b'E' => {
                    is_float = true;
                    self.pos += 1;
                    if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                        self.pos += 1;
                    }
                }
                _ => break,
            }
        }
        let spelling = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| "invalid number".to_owned())?;
        if is_float {
            Ok(Json::Float(
                spelling
                    .parse::<f64>()
                    .map_err(|_| format!("invalid float {spelling}"))?,
            ))
        } else {
            Ok(Json::Int(
                spelling
                    .parse::<i64>()
                    .map_err(|_| format!("invalid integer {spelling}"))?,
            ))
        }
    }
}

// =========================================================================
// Digest helpers (std-only implementations of the baseline algorithms)
// =========================================================================

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// SHA-256 of the decoded payload, compared against the digest recorded in
/// T001-VM-ANALYSIS.md. Pure std; no external dependency.
fn sha256(data: &[u8]) -> [u8; 32] {
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

    let bit_length = (data.len() as u64).wrapping_mul(8);
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_length.to_be_bytes());

    for chunk in message.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (index, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([
                chunk[4 * index],
                chunk[4 * index + 1],
                chunk[4 * index + 2],
                chunk[4 * index + 3],
            ]);
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

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut digest = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        digest[4 * index..4 * index + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

fn sha256_hex(data: &[u8]) -> String {
    hex_lower(&sha256(data))
}

/// Adler-32 with modulus 65,521, as used by the sample's leading integrity
/// check ("The leading integrity check computes Adler-32 (modulus 65,521)").
fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

// =========================================================================
// Lua string-literal scanning (mirrors T001-analyze.py `lua_string`)
// =========================================================================

fn utf8_char_len(byte: u8) -> usize {
    if byte < 0x80 {
        1
    } else if byte >> 5 == 0b110 {
        2
    } else if byte >> 4 == 0b1110 {
        3
    } else if byte >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Match `[[`, `[=[`, `[==[` ... returning the closing bracket text and the
/// number of bytes the opener occupies.
fn long_bracket_open(rest: &[u8]) -> Option<(String, usize)> {
    if rest.first() != Some(&b'[') {
        return None;
    }
    let mut equals = 0usize;
    let mut index = 1usize;
    while index < rest.len() && rest[index] == b'=' {
        equals += 1;
        index += 1;
    }
    if index >= rest.len() || rest[index] != b'[' {
        return None;
    }
    Some((format!("]{}]", "=".repeat(equals)), index + 1))
}

/// Extract the first string literal (quoted or long-bracket) from Lua source,
/// mirroring the escape handling of the checked-in `T001-analyze.py`
/// `lua_string` helper: up-to-three-digit decimal escapes, `\xHH`, `\z`
/// whitespace skips, single-character escapes, and backslash-newline
/// continuation. Comments are skipped. Static text analysis only; nothing is
/// executed. Used to independently re-derive the protected payload bytes that
/// the decoder is required to produce.
fn first_string_literal(source: &str) -> Result<(Vec<u8>, usize), String> {
    let bytes = source.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        match byte {
            b'-' if bytes.get(index + 1) == Some(&b'-') => {
                if let Some((closer, consumed)) = long_bracket_open(&bytes[index + 2..]) {
                    let start = index + 2 + consumed;
                    match find_sub(&bytes[start..], closer.as_bytes()) {
                        Some(relative) => index = start + relative + closer.len(),
                        None => {
                            return Err(
                                "unterminated long comment before the first string".to_owned()
                            )
                        }
                    }
                } else {
                    while index < bytes.len() && bytes[index] != b'\n' {
                        index += 1;
                    }
                }
            }
            b'[' => {
                if let Some((closer, consumed)) = long_bracket_open(&bytes[index..]) {
                    let start = index + consumed;
                    return match find_sub(&bytes[start..], closer.as_bytes()) {
                        Some(relative) => Ok((
                            bytes[start..start + relative].to_vec(),
                            start + relative + closer.len(),
                        )),
                        None => Err("unterminated long string".to_owned()),
                    };
                }
                index += 1;
            }
            b'"' | b'\'' => return decode_quoted(source, index),
            _ => index += 1,
        }
    }
    Err("no string literal found in source".to_owned())
}

fn decode_quoted(source: &str, start: usize) -> Result<(Vec<u8>, usize), String> {
    let bytes = source.as_bytes();
    let quote = bytes[start];
    let mut out = Vec::new();
    let mut index = start + 1;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == quote {
            return Ok((out, index + 1));
        }
        if byte != b'\\' {
            let length = utf8_char_len(byte);
            if index + length > bytes.len() {
                return Err(format!("truncated character at byte {index}"));
            }
            out.extend_from_slice(&bytes[index..index + length]);
            index += length;
            continue;
        }
        index += 1;
        if index >= bytes.len() {
            return Err("escape at end of input".to_owned());
        }
        let escape = bytes[index];
        match escape {
            b'a' => {
                out.push(7);
                index += 1;
            }
            b'b' => {
                out.push(8);
                index += 1;
            }
            b'f' => {
                out.push(12);
                index += 1;
            }
            b'n' => {
                out.push(10);
                index += 1;
            }
            b'r' => {
                out.push(13);
                index += 1;
            }
            b't' => {
                out.push(9);
                index += 1;
            }
            b'v' => {
                out.push(11);
                index += 1;
            }
            b'\\' => {
                out.push(92);
                index += 1;
            }
            b'"' => {
                out.push(34);
                index += 1;
            }
            b'\'' => {
                out.push(39);
                index += 1;
            }
            b'0'..=b'9' => {
                let mut value: u32 = 0;
                let mut taken = 0;
                while index < bytes.len() && taken < 3 && bytes[index].is_ascii_digit() {
                    value = value * 10 + u32::from(bytes[index] - b'0');
                    index += 1;
                    taken += 1;
                }
                if value > 255 {
                    return Err(format!("decimal escape > 255 near byte {index}"));
                }
                out.push(value as u8);
            }
            b'x' => {
                let hex = source
                    .get(index + 1..index + 3)
                    .ok_or("truncated \\x escape")?;
                let value = u8::from_str_radix(hex, 16)
                    .map_err(|_| format!("invalid \\x escape near byte {index}"))?;
                out.push(value);
                index += 3;
            }
            b'z' => {
                index += 1;
                while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                    index += 1;
                }
            }
            b'\r' | b'\n' => {
                if escape == b'\r' && bytes.get(index + 1) == Some(&b'\n') {
                    index += 1;
                }
                out.push(10);
                index += 1;
            }
            other => {
                return Err(format!(
                    "unsupported escape \\{} at byte {index}",
                    other as char
                ))
            }
        }
    }
    Err("unterminated quoted string".to_owned())
}

// =========================================================================
// Luau token normalization for output comparison
// =========================================================================

/// Reserved words are non-identifier tokens and must match exactly; Luau's
/// contextual words (`type`, `export`) stay identifiers and go through the
/// rename map. Same set as the checked-in `T001-analyze.py` KEYWORDS.
const LUAU_KEYWORDS: [&str; 22] = [
    "and", "break", "continue", "do", "else", "elseif", "end", "false", "for", "function", "if",
    "in", "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while",
];

/// Multi-character operators, tried longest-compatible first. Same list as
/// the checked-in `T001-analyze.py` OPERATORS.
const LUAU_OPERATORS: [&str; 19] = [
    "...", "..=", "//=", "==", "~=", "<=", ">=", "+=", "-=", "*=", "/=", "%=", "^=", "//", "..",
    "::", "->", "<<", ">>",
];

/// A normalized Luau token. Comments and whitespace are already gone.
/// `Number` and `String` carry decoded values, so `170` and `0xAA` are the
/// same token.
#[derive(Clone, Debug, PartialEq)]
enum TokenKind {
    Identifier(String),
    Keyword(String),
    Number(f64),
    String(Vec<u8>),
    Operator(String),
}

fn scan_number_spelling(source: &str, start: usize) -> String {
    let bytes = source.as_bytes();
    let mut index = start;
    if bytes[index] == b'0' && matches!(bytes.get(index + 1), Some(b'x' | b'X')) {
        index += 2;
        while matches!(
            bytes.get(index),
            Some(b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' | b'_')
        ) {
            index += 1;
        }
        if bytes.get(index) == Some(&b'.') {
            index += 1;
            while matches!(
                bytes.get(index),
                Some(b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' | b'_')
            ) {
                index += 1;
            }
        }
        if matches!(bytes.get(index), Some(b'p' | b'P')) {
            index += 1;
            if matches!(bytes.get(index), Some(b'+' | b'-')) {
                index += 1;
            }
            while matches!(bytes.get(index), Some(b'0'..=b'9' | b'_')) {
                index += 1;
            }
        }
        return source[start..index].to_owned();
    }
    if bytes[index] == b'0' && matches!(bytes.get(index + 1), Some(b'b' | b'B')) {
        index += 2;
        while matches!(bytes.get(index), Some(b'0' | b'1' | b'_')) {
            index += 1;
        }
        return source[start..index].to_owned();
    }
    while matches!(bytes.get(index), Some(b'0'..=b'9' | b'_')) {
        index += 1;
    }
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        while matches!(bytes.get(index), Some(b'0'..=b'9' | b'_')) {
            index += 1;
        }
    }
    if matches!(bytes.get(index), Some(b'e' | b'E')) {
        index += 1;
        if matches!(bytes.get(index), Some(b'+' | b'-')) {
            index += 1;
        }
        while matches!(bytes.get(index), Some(b'0'..=b'9' | b'_')) {
            index += 1;
        }
    }
    source[start..index].to_owned()
}

fn parse_hex_mantissa(text: &str) -> Result<f64, String> {
    let (int_part, frac_part) = match text.split_once('.') {
        Some((int_part, frac_part)) => (int_part, frac_part),
        None => (text, ""),
    };
    if int_part.is_empty() && frac_part.is_empty() {
        return Err("empty hex mantissa".to_owned());
    }
    let int_value: u64 = if int_part.is_empty() {
        0
    } else {
        u64::from_str_radix(int_part, 16).map_err(|_| "invalid hex integer part".to_owned())?
    };
    let mut value = int_value as f64;
    if !frac_part.is_empty() {
        let frac_value: u64 =
            u64::from_str_radix(frac_part, 16).map_err(|_| "invalid hex fraction".to_owned())?;
        value += frac_value as f64 / 16f64.powi(frac_part.len() as i32);
    }
    Ok(value)
}

fn parse_number_literal(spelling: &str) -> Result<f64, String> {
    let cleaned: String = spelling
        .chars()
        .filter(|character| *character != '_')
        .collect();
    let lowered = cleaned.to_ascii_lowercase();
    if let Some(rest) = lowered.strip_prefix("0x") {
        let (mantissa, exponent) = match rest.split_once('p') {
            Some((mantissa, exponent)) => (
                mantissa,
                exponent
                    .parse::<i32>()
                    .map_err(|_| format!("malformed hex exponent in {spelling}"))?,
            ),
            None => (rest, 0i32),
        };
        let value = parse_hex_mantissa(mantissa)
            .map_err(|_| format!("malformed hex literal {spelling}"))?;
        return Ok(value * 2f64.powi(exponent));
    }
    if let Some(rest) = lowered.strip_prefix("0b") {
        let value = u64::from_str_radix(rest, 2)
            .map_err(|_| format!("malformed binary literal {spelling}"))?;
        return Ok(value as f64);
    }
    cleaned
        .parse::<f64>()
        .map_err(|_| format!("malformed numeric literal {spelling}"))
}

/// Lex Luau source into normalized tokens, skipping whitespace and comments
/// and decoding string/number literals to values. Static text analysis only.
fn tokenize_luau(source: &str) -> Result<Vec<TokenKind>, String> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            index += 1;
            continue;
        }
        if byte == b'-' && bytes.get(index + 1) == Some(&b'-') {
            if let Some((closer, consumed)) = long_bracket_open(&bytes[index + 2..]) {
                let start = index + 2 + consumed;
                match find_sub(&bytes[start..], closer.as_bytes()) {
                    Some(relative) => index = start + relative + closer.len(),
                    None => return Err("unterminated long comment".to_owned()),
                }
            } else {
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            continue;
        }
        if byte == b'[' {
            if let Some((closer, consumed)) = long_bracket_open(&bytes[index..]) {
                let start = index + consumed;
                let Some(relative) = find_sub(&bytes[start..], closer.as_bytes()) else {
                    return Err("unterminated long string".to_owned());
                };
                let mut content = &bytes[start..start + relative];
                // Lua skips one newline immediately after the opener.
                if content.starts_with(b"\r\n") {
                    content = &content[2..];
                } else if content.first() == Some(&b'\n') || content.first() == Some(&b'\r') {
                    content = &content[1..];
                }
                tokens.push(TokenKind::String(content.to_vec()));
                index = start + relative + closer.len();
                continue;
            }
        }
        if byte == b'"' || byte == b'\'' {
            let (value, after) = decode_quoted(source, index)?;
            tokens.push(TokenKind::String(value));
            index = after;
            continue;
        }
        let next_is_digit = bytes
            .get(index + 1)
            .is_some_and(|next| next.is_ascii_digit());
        if byte.is_ascii_digit() || (byte == b'.' && next_is_digit) {
            let spelling = scan_number_spelling(source, index);
            let value = parse_number_literal(&spelling)?;
            tokens.push(TokenKind::Number(value));
            index += spelling.len();
            continue;
        }
        if byte.is_ascii_alphabetic() || byte == b'_' {
            let mut end = index + 1;
            while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
                end += 1;
            }
            let word = &source[index..end];
            if LUAU_KEYWORDS.contains(&word) {
                tokens.push(TokenKind::Keyword(word.to_owned()));
            } else {
                tokens.push(TokenKind::Identifier(word.to_owned()));
            }
            index = end;
            continue;
        }
        let mut matched = false;
        for operator in LUAU_OPERATORS {
            if source[index..].starts_with(operator) {
                tokens.push(TokenKind::Operator(operator.to_owned()));
                index += operator.len();
                matched = true;
                break;
            }
        }
        if matched {
            continue;
        }
        // Fallback: consume one full character as a punctuation token.
        let length = utf8_char_len(byte);
        let chunk = source
            .get(index..index + length)
            .unwrap_or(&source[index..]);
        tokens.push(TokenKind::Operator(chunk.to_owned()));
        index += length;
    }
    Ok(tokens)
}

/// Compare two normalized Luau token streams under the checked-in comparison
/// rules (`T001-analyze.py`): equal token counts, every non-identifier token
/// exactly equal position-by-position, string and number literals equal by
/// decoded value, and identifiers differing only through one consistent
/// bijective rename. On success returns the baseline -> emitted rename map.
fn compare_token_streams(
    baseline: &[TokenKind],
    emitted: &[TokenKind],
) -> Result<BTreeMap<String, String>, String> {
    if baseline.len() != emitted.len() {
        return Err(format!(
            "token counts differ: baseline {} vs emitted {}",
            baseline.len(),
            emitted.len()
        ));
    }
    let mut forward: BTreeMap<String, String> = BTreeMap::new();
    let mut backward: BTreeMap<String, String> = BTreeMap::new();
    for (position, (baseline_token, emitted_token)) in baseline.iter().zip(emitted).enumerate() {
        match (baseline_token, emitted_token) {
            (TokenKind::Identifier(from), TokenKind::Identifier(to)) => {
                if let Some(existing) = forward.get(from) {
                    if existing != to {
                        return Err(format!(
                            "position {position}: identifier `{from}` maps to both \
                             `{existing}` and `{to}`; the rename is not consistent"
                        ));
                    }
                } else {
                    forward.insert(from.clone(), to.clone());
                }
                if let Some(existing) = backward.get(to) {
                    if existing != from {
                        return Err(format!(
                            "position {position}: emitted identifier `{to}` maps back to \
                             both `{existing}` and `{from}`; the rename is not injective"
                        ));
                    }
                } else {
                    backward.insert(to.clone(), from.clone());
                }
            }
            (TokenKind::Keyword(from), TokenKind::Keyword(to)) => {
                if from != to {
                    return Err(format!("position {position}: keyword `{from}` vs `{to}`"));
                }
            }
            (TokenKind::Operator(from), TokenKind::Operator(to)) => {
                if from != to {
                    return Err(format!("position {position}: operator `{from}` vs `{to}`"));
                }
            }
            (TokenKind::Number(from), TokenKind::Number(to)) => {
                if from.to_bits() != to.to_bits() {
                    return Err(format!(
                        "position {position}: number {from} vs {to} (values must match)"
                    ));
                }
            }
            (TokenKind::String(from), TokenKind::String(to)) => {
                if from != to {
                    return Err(format!(
                        "position {position}: string {} vs {}",
                        String::from_utf8_lossy(from),
                        String::from_utf8_lossy(to)
                    ));
                }
            }
            (from, to) => {
                return Err(format!(
                    "position {position}: token-kind mismatch: baseline {from:?} vs \
                     emitted {to:?}"
                ));
            }
        }
    }
    Ok(forward)
}

// =========================================================================
// Baseline markdown extractors (std-only, anchored on unique sentences)
// =========================================================================

/// The number immediately preceding `anchor` in `text`, skipping markdown
/// emphasis like `**`.
fn number_before(text: &str, anchor: &str) -> Option<u64> {
    let anchor_start = text.find(anchor)?;
    let bytes = text.as_bytes();
    let mut end = anchor_start;
    while end > 0 && !bytes[end - 1].is_ascii_digit() {
        end -= 1;
    }
    if end == 0 {
        return None;
    }
    let mut start = end;
    while start > 0 && bytes[start - 1].is_ascii_digit() {
        start -= 1;
    }
    text[start..end].parse::<u64>().ok()
}

/// The first number after `anchor`, accepting thousands separators like the
/// `2,276 bytes` in T001-VM-ANALYSIS.md.
fn number_after(text: &str, anchor: &str) -> Option<u64> {
    let start = text.find(anchor)? + anchor.len();
    let bytes = text.as_bytes();
    let mut index = start;
    while index < bytes.len() && !bytes[index].is_ascii_digit() {
        index += 1;
    }
    let mut digits = String::new();
    while index < bytes.len() && (bytes[index].is_ascii_digit() || bytes[index] == b',') {
        if bytes[index].is_ascii_digit() {
            digits.push(bytes[index] as char);
        }
        index += 1;
    }
    digits.parse::<u64>().ok()
}

/// All numbers between `start_anchor` and the next `terminator` character,
/// used for the `**55 reachable addresses** (5 entry, 50 parser)` sentence.
fn numbers_between(text: &str, start_anchor: &str, terminator: char) -> Option<Vec<u64>> {
    let start = text.find(start_anchor)? + start_anchor.len();
    let segment_end = text[start..].find(terminator)? + start;
    let segment = &text[start..segment_end];
    let mut numbers = Vec::new();
    let mut current = String::new();
    for character in segment.chars() {
        if character.is_ascii_digit() {
            current.push(character);
        } else if !current.is_empty() {
            numbers.push(current.parse().ok()?);
            current.clear();
        }
    }
    if !current.is_empty() {
        numbers.push(current.parse().ok()?);
    }
    Some(numbers)
}

/// The first standalone 64-character hex digest after `anchor`.
fn hex_digest_after(text: &str, anchor: &str) -> Option<String> {
    let start = text.find(anchor)? + anchor.len();
    let bytes = text.as_bytes();
    let is_hex = |byte: u8| byte.is_ascii_hexdigit();
    let mut index = start;
    while index + 64 <= bytes.len() {
        if bytes[index..index + 64].iter().all(|&byte| is_hex(byte))
            && (index == 0 || !is_hex(bytes[index - 1]))
            && (index + 64 >= bytes.len() || !is_hex(bytes[index + 64]))
        {
            return Some(
                bytes[index..index + 64]
                    .iter()
                    .map(|byte| (*byte as char).to_ascii_lowercase())
                    .collect(),
            );
        }
        index += 1;
    }
    None
}

/// The handler families named by "The three reached families are 6094, 1173,
/// and 6965." in T001-VM-ANALYSIS.md.
fn reached_families(text: &str) -> Option<BTreeSet<u32>> {
    const ANCHOR: &str = "reached families are";
    let start = text.find(ANCHOR)? + ANCHOR.len();
    let end = text[start..].find('.')? + start;
    let mut families = BTreeSet::new();
    let mut current = String::new();
    for character in text[start..end].chars() {
        if character.is_ascii_digit() {
            current.push(character);
        } else if !current.is_empty() {
            families.insert(current.parse().ok()?);
            current.clear();
        }
    }
    if !current.is_empty() {
        families.insert(current.parse().ok()?);
    }
    Some(families)
}

/// The dispatch token -> family map from the `var17` block in
/// T001-VM-ANALYSIS.md ("9179, 32310, 9024 -> handler 1173", ...).
fn dispatch_map(text: &str) -> BTreeMap<u32, u32> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let Some((left, right)) = line.split_once("->") else {
            continue;
        };
        let Some(handler_at) = right.find("handler") else {
            continue;
        };
        let family = right[handler_at + "handler".len()..]
            .split(|character: char| !character.is_ascii_digit())
            .find(|token| !token.is_empty())
            .and_then(|token| token.parse::<u32>().ok());
        let Some(family) = family else {
            continue;
        };
        for token in left.split(',') {
            if let Ok(token) = token.trim().parse::<u32>() {
                map.insert(token, family);
            }
        }
    }
    map
}

/// The instruction addresses listed in the VM-DISASSEMBLY.md tables: rows
/// shaped like `| 030 | 1173/1282 | ... |`. Zero-padded parser PCs normalize
/// to plain integers.
fn disassembly_pcs(text: &str) -> BTreeSet<usize> {
    let mut pcs = BTreeSet::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix('|') else {
            continue;
        };
        let rest = rest.trim_start();
        let digits_end = rest
            .find(|character: char| !character.is_ascii_digit())
            .unwrap_or(rest.len());
        if digits_end == 0 {
            continue;
        }
        let after = rest[digits_end..].trim_start();
        if !after.starts_with('|') {
            continue;
        }
        if let Ok(pc) = rest[..digits_end].parse::<usize>() {
            pcs.insert(pc);
        }
    }
    pcs
}

/// True when `word` appears delimited by non-identifier, non-numeric
/// characters on both sides, so `170` is not satisfied by `1170`.
fn has_number_word(source: &str, word: &str) -> bool {
    let bytes = source.as_bytes();
    let needle = word.as_bytes();
    if needle.is_empty() || bytes.len() < needle.len() {
        return false;
    }
    let is_word_byte = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.';
    (0..=bytes.len() - needle.len()).any(|index| {
        &bytes[index..index + needle.len()] == needle
            && (index == 0 || !is_word_byte(bytes[index - 1]))
            && (index + needle.len() == bytes.len() || !is_word_byte(bytes[index + needle.len()]))
    })
}

// =========================================================================
// Local syntax validator (parser/syntax validation, NOT bytecode compilation)
// =========================================================================

/// Resolve the locally built `luau-decompiler` CLI used for syntax
/// validation: the `LUAU_DEVIRT_VALIDATOR` override, else
/// `target/luau-validator/release/luau-decompiler(.exe)`.
fn validator_path() -> Option<PathBuf> {
    if let Some(path) = env_path("LUAU_DEVIRT_VALIDATOR") {
        if path.is_file() {
            return Some(path);
        }
        panic!(
            "LUAU_DEVIRT_VALIDATOR is set but does not point at the validator executable: {}",
            path.display()
        );
    }
    let exe_name = if cfg!(windows) {
        "luau-decompiler.exe"
    } else {
        "luau-decompiler"
    };
    let built = manifest_dir()
        .join("tools")
        .join("validator-build")
        .join("release")
        .join(exe_name);
    built.is_file().then_some(built)
}

/// Resolve the official compile-only Luau CLI used by the final output check.
fn compiler_path() -> Option<PathBuf> {
    if let Some(path) = env_path("LUAU_DEVIRT_COMPILER") {
        if path.is_file() {
            return Some(path);
        }
        panic!(
            "LUAU_DEVIRT_COMPILER is set but does not point at luau-compile: {}",
            path.display()
        );
    }
    let exe_name = if cfg!(windows) {
        "luau-compile.exe"
    } else {
        "luau-compile"
    };
    let built = manifest_dir()
        .join("tools")
        .join("luau-0.747")
        .join(exe_name);
    built.is_file().then_some(built)
}

// =========================================================================
// Tests that only exercise in-file helpers (safe to run before the merge)
// =========================================================================

#[test]
fn local_helpers_match_known_vectors() {
    // SHA-256 (FIPS 180-4 vectors).
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );

    // Adler-32, modulus 65,521 (verified against zlib).
    assert_eq!(adler32(b""), 0x1);
    assert_eq!(adler32(b"a"), 0x0062_0062);
    assert_eq!(adler32(b"Wikipedia"), 0x11e6_0398);

    // Minimal JSON parser against a representative baseline-shaped document.
    let parsed = parse_json(
        r#"{"a": 2276, "b": [null, 300973145, 4195674741], "c": {"d": -131.0, "e": "table"}, "f": true}"#,
    )
    .expect("embedded JSON should parse");
    assert_eq!(parsed.get("a").and_then(Json::as_u64), Some(2276));
    let array = parsed.get("b").and_then(Json::as_arr).expect("array field");
    assert_eq!(array.len(), 3);
    assert!(array[0].is_null());
    assert_eq!(array[1].as_u64(), Some(300973145));
    assert_eq!(array[2].as_u64(), Some(4195674741));
    assert_eq!(
        parsed
            .get("c")
            .and_then(|value| value.get("d"))
            .and_then(Json::as_f64),
        Some(-131.0)
    );
    assert_eq!(
        parsed
            .get("c")
            .and_then(|value| value.get("e"))
            .and_then(Json::as_str),
        Some("table")
    );
    assert_eq!(parsed.get("f").and_then(Json::as_bool), Some(true));

    // First-literal scanner with the escape forms used by the sample.
    let lua = r#"--[[don't extract this]] local s = "\65\66\67\x2c n\z ok" return s"#;
    let (bytes, _) = first_string_literal(lua).expect("embedded Lua should yield a literal");
    assert_eq!(bytes, b"ABC, nok");
    let (bytes, _) = first_string_literal("-- note\nlocal t = { [1] = [[payload]] }")
        .expect("long strings are literals too");
    assert_eq!(bytes, b"payload");
    assert!(first_string_literal("local x = 1 -- no strings").is_err());
}

/// Re-derive the protected payload straight from the sample with the in-file
/// scanner and check it against the checked-in Python baseline. This needs
/// no devirtualizer modules and is safe to run before the merge.
#[test]
fn local_baseline_extraction_from_sample() {
    let Some(source) = load_sample_source() else {
        skip_test(SAMPLE_SKIP);
        return;
    };
    let Some(meta) = load_metadata() else {
        skip_test(METADATA_SKIP);
        return;
    };

    let (payload, _) = first_string_literal(&source)
        .expect("the sample must contain the protected payload literal");

    let payload_bytes = meta
        .get("payload_bytes")
        .and_then(Json::as_usize)
        .expect("decoded-metadata.json payload_bytes");
    assert_eq!(
        payload.len(),
        payload_bytes,
        "first literal size vs decoded-metadata.json payload_bytes"
    );

    const ANCHOR: &str = "first escaped string parses to the same";
    if let Some(vm_analysis) = load_vm_analysis() {
        let md_size =
            number_after(&vm_analysis, ANCHOR).expect("T001-VM-ANALYSIS.md payload size sentence");
        assert_eq!(
            md_size, payload_bytes as u64,
            "T001-VM-ANALYSIS.md '2,276 bytes' vs decoded-metadata.json payload_bytes"
        );
        let digest =
            hex_digest_after(&vm_analysis, ANCHOR).expect("T001-VM-ANALYSIS.md payload SHA-256");
        assert_eq!(
            sha256_hex(&payload),
            digest,
            "first literal digest vs the baseline payload SHA-256"
        );
    } else {
        skip_test(
            "T001-VM-ANALYSIS.md unavailable; the payload digest cross-check was skipped \
             (the size check against decoded-metadata.json still ran)",
        );
    }
}

/// Pin the Luau tokenizer and the token-stream comparator against the
/// checked-in readable reconstruction, so the emitted-output comparison is
/// trustworthy before the emitter lands. The counts below were computed by
/// the same rules from the checked-in `T001-deobfuscated.luau`; if that file
/// is ever edited, update them alongside it. Needs no devirtualizer modules.
#[test]
fn local_baseline_output_lexes_cleanly() {
    let Some(baseline_source) = load_baseline_output() else {
        skip_test(BASELINE_OUTPUT_SKIP);
        return;
    };
    let tokens =
        tokenize_luau(&baseline_source).expect("the baseline reconstruction must lex cleanly");

    // Facts from the checked-in T001-deobfuscated.luau (static read).
    assert_eq!(tokens.len(), 211, "total token count");
    assert_eq!(
        tokens
            .iter()
            .filter(|token| matches!(token, TokenKind::Identifier(_)))
            .count(),
        66,
        "identifier token count"
    );
    assert_eq!(
        tokens
            .iter()
            .filter(|token| matches!(token, TokenKind::Operator(_)))
            .count(),
        78,
        "operator token count"
    );
    assert_eq!(
        tokens
            .iter()
            .filter(|token| matches!(token, TokenKind::String(_)))
            .count(),
        14,
        "string token count"
    );
    assert_eq!(
        tokens
            .iter()
            .filter(|token| matches!(token, TokenKind::Keyword(_)))
            .count(),
        38,
        "keyword token count"
    );
    assert_eq!(
        tokens
            .iter()
            .filter(|token| matches!(token, TokenKind::Number(_)))
            .count(),
        15,
        "number token count"
    );

    // Leading tokens of `type Input = { number } | string` and friends.
    assert_eq!(tokens[0], TokenKind::Identifier("type".into()));
    assert_eq!(tokens[1], TokenKind::Identifier("Input".into()));
    assert_eq!(tokens[2], TokenKind::Operator("=".into()));
    assert_eq!(tokens[3], TokenKind::Operator("{".into()));
    assert_eq!(tokens[4], TokenKind::Identifier("number".into()));
    assert_eq!(tokens[5], TokenKind::Operator("}".into()));
    assert_eq!(tokens[6], TokenKind::Operator("|".into()));
    assert_eq!(tokens[7], TokenKind::Identifier("string".into()));
    assert_eq!(tokens[9], TokenKind::Identifier("Phase".into()));
    assert_eq!(tokens[11], TokenKind::String(b"marker".to_vec()));

    // Decoded literal values: the frame marker is spelled 0xAA in the
    // baseline, the checksum modulus 256.
    let values: Vec<f64> = tokens
        .iter()
        .filter_map(|token| match token {
            TokenKind::Number(value) => Some(*value),
            _ => None,
        })
        .collect();
    assert_eq!(
        values[0].to_bits(),
        170.0f64.to_bits(),
        "0xAA decodes to 170"
    );
    assert_eq!(values[1].to_bits(), 256.0f64.to_bits(), "checksum modulus");
    assert!(values
        .iter()
        .all(|value| *value == 0.0 || *value == 1.0 || *value == 170.0 || *value == 256.0));

    let distinct_identifiers: BTreeSet<&String> = tokens
        .iter()
        .filter_map(|token| match token {
            TokenKind::Identifier(name) => Some(name),
            _ => None,
        })
        .collect();
    assert_eq!(
        distinct_identifiers.len(),
        21,
        "distinct identifier spellings"
    );
    for expected in [
        "scanFrames",
        "table",
        "concat",
        "type",
        "number",
        "string",
        "MARKER",
        "CHECKSUM_MODULUS",
    ] {
        assert!(
            distinct_identifiers
                .iter()
                .any(|name| name.as_str() == expected),
            "identifier {expected} must appear in the baseline"
        );
    }

    // Self-comparison passes with an identity rename.
    let identity = compare_token_streams(&tokens, &tokens).expect("self-comparison must pass");
    assert_eq!(identity.len(), 21, "identity rename covers every spelling");

    // A consistent bijective rename is accepted.
    let renamed: Vec<TokenKind> = tokens
        .iter()
        .map(|token| match token {
            TokenKind::Identifier(name) => TokenKind::Identifier(format!("{name}_r")),
            other => other.clone(),
        })
        .collect();
    let rename =
        compare_token_streams(&tokens, &renamed).expect("a consistent bijective rename must pass");
    assert_eq!(rename.len(), 21, "rename covers every baseline spelling");
    assert_eq!(rename.get("type").map(String::as_str), Some("type_r"));

    // An inconsistent rename is rejected: the baseline `type` spelling occurs
    // twice and must map to the same emitted identifier both times.
    let type_positions: Vec<usize> = tokens
        .iter()
        .enumerate()
        .filter(|(_, token)| matches!(token, TokenKind::Identifier(name) if name == "type"))
        .map(|(position, _)| position)
        .collect();
    assert_eq!(
        type_positions.len(),
        2,
        "`type` occurs twice in the baseline"
    );
    let mut inconsistent = tokens.clone();
    if let TokenKind::Identifier(name) = &mut inconsistent[type_positions[1]] {
        *name = "diverged".into();
    }
    let error = compare_token_streams(&tokens, &inconsistent)
        .expect_err("an inconsistent rename must be rejected");
    assert!(
        error.contains("not consistent"),
        "expected a consistency diagnostic, got: {error}"
    );

    // A non-injective rename is rejected: two distinct baseline identifiers
    // may not collapse into one emitted identifier.
    let input_position = tokens
        .iter()
        .position(|token| matches!(token, TokenKind::Identifier(name) if name == "Input"))
        .expect("Input occurs in the baseline");
    let phase_position = tokens
        .iter()
        .position(|token| matches!(token, TokenKind::Identifier(name) if name == "Phase"))
        .expect("Phase occurs in the baseline");
    let mut merged = tokens.clone();
    if let TokenKind::Identifier(name) = &mut merged[input_position] {
        *name = "merged".into();
    }
    if let TokenKind::Identifier(name) = &mut merged[phase_position] {
        *name = "merged".into();
    }
    let error = compare_token_streams(&tokens, &merged)
        .expect_err("a non-injective rename must be rejected");
    assert!(
        error.contains("not injective"),
        "expected an injectivity diagnostic, got: {error}"
    );

    // Value changes and kind changes are rejected.
    let number_position = tokens
        .iter()
        .position(|token| matches!(token, TokenKind::Number(_)))
        .expect("the baseline contains numbers");
    let mut value_changed = tokens.clone();
    if let TokenKind::Number(value) = &mut value_changed[number_position] {
        *value += 1.0;
    }
    assert!(
        compare_token_streams(&tokens, &value_changed).is_err(),
        "a changed number value must be rejected"
    );
    let mut kind_changed = tokens.clone();
    kind_changed[0] = TokenKind::Keyword("local".into());
    assert!(
        compare_token_streams(&tokens, &kind_changed).is_err(),
        "a keyword/identifier kind change must be rejected"
    );
}

// =========================================================================
// Decoder-level comparisons against the baseline
// =========================================================================

#[test]
fn decoded_payload_and_words_match_baseline() {
    let Some(source) = load_sample_source() else {
        skip_test(SAMPLE_SKIP);
        return;
    };
    let Some(meta) = load_metadata() else {
        skip_test(METADATA_SKIP);
        return;
    };
    let vm = decode_or_explain(&source);

    // --- Payload digest and size -----------------------------------------
    let expected_payload = first_string_literal(&source)
        .expect("the sample must contain the protected payload literal")
        .0;
    let payload_bytes = meta
        .get("payload_bytes")
        .and_then(Json::as_usize)
        .expect("decoded-metadata.json payload_bytes");
    assert_eq!(
        vm.payload.len(),
        payload_bytes,
        "decoded payload size vs decoded-metadata.json payload_bytes"
    );
    assert_eq!(
        vm.payload, expected_payload,
        "decoded payload must equal the sample's first string literal (both files' first \
         escaped string parses to the same 2,276 bytes per T001-VM-ANALYSIS.md)"
    );
    if let Some(vm_analysis) = load_vm_analysis() {
        let digest = hex_digest_after(&vm_analysis, "first escaped string parses to the same")
            .expect("T001-VM-ANALYSIS.md payload SHA-256");
        assert_eq!(
            sha256_hex(&vm.payload),
            digest,
            "decoded payload SHA-256 vs the baseline digest"
        );
    } else {
        eprintln!(
            "note: T001-VM-ANALYSIS.md unavailable; the payload digest cross-check was skipped"
        );
    }

    // --- Raw words --------------------------------------------------------
    let raw_u32_count = meta
        .get("raw_u32_count")
        .and_then(Json::as_usize)
        .expect("decoded-metadata.json raw_u32_count");
    assert_eq!(
        vm.raw_words.len(),
        raw_u32_count,
        "raw word count vs decoded-metadata.json raw_u32_count"
    );
    assert_eq!(
        raw_u32_count,
        payload_bytes / 4,
        "the 2,276-byte buffer contains 569 four-byte words"
    );
    let mut roundtrip = Vec::with_capacity(vm.payload.len());
    for word in &vm.raw_words {
        roundtrip.extend_from_slice(&word.to_le_bytes());
    }
    assert_eq!(
        roundtrip, vm.payload,
        "raw_words must be the little-endian u32 view of the payload"
    );

    // --- Key and populated word range ------------------------------------
    let initialization_argument = meta
        .get("initialization_argument")
        .and_then(Json::as_u32)
        .expect("decoded-metadata.json initialization_argument");
    assert_eq!(
        vm.initialization_argument, initialization_argument,
        "initialization argument vs decoded-metadata.json"
    );
    let master_key = meta
        .get("master_key")
        .and_then(Json::as_u32)
        .expect("decoded-metadata.json master_key");
    assert_eq!(
        vm.master_key, master_key,
        "master key vs decoded-metadata.json"
    );
    if let Some(vm_analysis) = load_vm_analysis() {
        assert_eq!(
            number_after(&vm_analysis, "The call argument is"),
            Some(u64::from(initialization_argument)),
            "T001-VM-ANALYSIS.md 'The call argument is 3935408727'"
        );
        assert_eq!(
            number_after(&vm_analysis, "`var15` is"),
            Some(u64::from(master_key)),
            "T001-VM-ANALYSIS.md 'the derived global key var15 is 2702369233'"
        );
    }

    let range = meta
        .get("decoded_range_inclusive")
        .and_then(Json::as_arr)
        .expect("decoded-metadata.json decoded_range_inclusive");
    let range_start = range[0].as_usize().expect("decoded range start");
    let range_end = range[1].as_usize().expect("decoded range end");
    assert_eq!(
        vm.decoded_range,
        (range_start, range_end),
        "decoded word range vs decoded-metadata.json decoded_range_inclusive"
    );

    // --- Full decoded word table -----------------------------------------
    let json_words = meta
        .get("words_1_based")
        .and_then(Json::as_arr)
        .expect("decoded-metadata.json words_1_based");
    assert_eq!(
        vm.decoded_words.len(),
        json_words.len(),
        "decoded_words length vs words_1_based (570 one-based entries)"
    );
    for (index, entry) in json_words.iter().enumerate() {
        assert_eq!(
            vm.decoded_words[index],
            entry.as_u32(),
            "decoded_words[{index}] vs words_1_based[{index}]"
        );
    }
    assert!(
        vm.decoded_words[0].is_none(),
        "index zero is always None (ir.rs)"
    );
    for index in 1..=4 {
        assert!(
            vm.decoded_words[index].is_some(),
            "decoded header words 1-4 must be populated"
        );
    }
    // "Other positions are absent from this table; they must not be treated
    // as zero." (T001-VM-ANALYSIS.md)
    for index in 5..range_start {
        assert!(
            vm.decoded_words[index].is_none(),
            "word {index} must be absent (None), not zero"
        );
    }
    for index in range_end + 1..vm.decoded_words.len() {
        assert!(
            vm.decoded_words[index].is_none(),
            "word {index} beyond the decoded range must be absent (None)"
        );
    }
    let populated_word_count = meta
        .get("populated_word_count")
        .and_then(Json::as_usize)
        .expect("decoded-metadata.json populated_word_count");
    let populated = vm
        .decoded_words
        .iter()
        .filter(|word| word.is_some())
        .count();
    assert_eq!(
        populated, populated_word_count,
        "populated word count vs decoded-metadata.json (4 header + 486 decoded)"
    );

    // --- Determinism and source bookkeeping ------------------------------
    let again = decode_or_explain(&source);
    assert_eq!(
        vm, again,
        "decode_source must be deterministic for the same input"
    );
    assert!(!vm.source_text.is_empty(), "source_text must be recorded");
    if let Some(recorded) = &vm.source_sha256 {
        assert_eq!(
            recorded.to_ascii_lowercase(),
            sha256_hex(vm.source_text.as_bytes()),
            "source_sha256 must be the SHA-256 of the recorded source_text"
        );
    }
}

#[test]
fn slot_map_and_immediate_biases_match_baseline() {
    let Some(source) = load_sample_source() else {
        skip_test(SAMPLE_SKIP);
        return;
    };
    let Some(meta) = load_metadata() else {
        skip_test(METADATA_SKIP);
        return;
    };
    let vm = decode_or_explain(&source);

    // --- 120-entry slot map ----------------------------------------------
    let json_slots = meta
        .get("slots_1_based")
        .and_then(Json::as_arr)
        .expect("decoded-metadata.json slots_1_based");
    assert_eq!(
        vm.slot_map.len(),
        json_slots.len(),
        "slot_map length vs slots_1_based (index zero plus 120 entries)"
    );
    for (index, entry) in json_slots.iter().enumerate() {
        let expected = if entry.is_null() {
            0
        } else {
            entry
                .as_u16()
                .unwrap_or_else(|| panic!("slots_1_based[{index}] must be an integer"))
        };
        assert_eq!(
            vm.slot_map[index], expected,
            "slot_map[{index}] vs slots_1_based[{index}]"
        );
    }
    assert_eq!(
        vm.slot_map.first(),
        Some(&0),
        "index zero is always zero (ir.rs)"
    );
    if let Some(vm_analysis) = load_vm_analysis() {
        let md_entries = number_before(&vm_analysis, "decrypted 16-bit entries")
            .expect("T001-VM-ANALYSIS.md slot-map entry count");
        assert_eq!(
            md_entries,
            json_slots.len().saturating_sub(1) as u64,
            "T001-VM-ANALYSIS.md '120 decrypted 16-bit entries' vs the baseline slot array"
        );
        let distinct_slots: BTreeSet<u16> = vm.slot_map.iter().skip(1).copied().collect();
        let md_distinct = number_before(&vm_analysis, "distinct physical frame slots")
            .expect("T001-VM-ANALYSIS.md distinct slot count");
        assert_eq!(
            md_distinct,
            distinct_slots.len() as u64,
            "T001-VM-ANALYSIS.md 'addresses 46 distinct physical frame slots'"
        );
    } else {
        eprintln!("note: T001-VM-ANALYSIS.md unavailable; slot-map narrative cross-checks skipped");
    }

    // --- Immediate-bias table --------------------------------------------
    let json_biases = meta
        .get("immediate_biases_1_based")
        .and_then(Json::as_arr)
        .expect("decoded-metadata.json immediate_biases_1_based");
    assert_eq!(
        vm.immediate_biases.len(),
        json_biases.len(),
        "immediate_biases length vs immediate_biases_1_based (index zero plus 64 entries)"
    );
    for (index, entry) in json_biases.iter().enumerate() {
        let expected = if entry.is_null() {
            0
        } else {
            entry
                .as_u32()
                .unwrap_or_else(|| panic!("immediate_biases_1_based[{index}] must be an integer"))
        };
        assert_eq!(
            vm.immediate_biases[index], expected,
            "immediate_biases[{index}] vs immediate_biases_1_based[{index}]"
        );
    }
    assert_eq!(
        vm.immediate_biases.first(),
        Some(&0),
        "index zero is always zero (ir.rs)"
    );
    if let Some(vm_analysis) = load_vm_analysis() {
        let md_biases = number_before(&vm_analysis, "immediate-bias table")
            .expect("T001-VM-ANALYSIS.md immediate-bias count");
        let populated = vm
            .immediate_biases
            .iter()
            .filter(|&&bias| bias != 0)
            .count();
        assert_eq!(
            md_biases, populated as u64,
            "T001-VM-ANALYSIS.md '64 immediate-bias table'"
        );
    }
}

#[test]
fn prototype_headers_match_baseline() {
    let Some(source) = load_sample_source() else {
        skip_test(SAMPLE_SKIP);
        return;
    };
    let Some(meta) = load_metadata() else {
        skip_test(METADATA_SKIP);
        return;
    };
    let vm = decode_or_explain(&source);

    let json_prototypes = meta
        .get("prototypes")
        .and_then(Json::as_arr)
        .expect("decoded-metadata.json prototypes");
    assert_eq!(
        vm.prototypes.len(),
        json_prototypes.len(),
        "the sample decodes exactly two prototypes"
    );

    let by_word: BTreeMap<usize, _> = vm
        .prototypes
        .iter()
        .map(|proto| (proto.word, proto))
        .collect();
    let vm_words: BTreeSet<usize> = vm.prototypes.iter().map(|proto| proto.word).collect();
    let json_words: BTreeSet<usize> = json_prototypes
        .iter()
        .map(|proto| {
            proto
                .get("word")
                .and_then(Json::as_usize)
                .expect("prototype word")
        })
        .collect();
    assert_eq!(
        vm_words, json_words,
        "prototype word indices (parser at 24, top-level record at 505)"
    );

    for json_proto in json_prototypes {
        let word = json_proto
            .get("word")
            .and_then(Json::as_usize)
            .expect("prototype word");
        let Some(&proto) = by_word.get(&word) else {
            panic!("no decoded prototype at word {word}");
        };
        let field = |name: &str| json_proto.get(name);

        assert_eq!(
            proto.byte_offset,
            field("byte_offset")
                .and_then(Json::as_usize)
                .expect("byte_offset"),
            "prototype {word} byte_offset"
        );
        assert_eq!(
            proto.encoded_reference,
            field("encoded_reference")
                .and_then(Json::as_u32)
                .expect("encoded_reference"),
            "prototype {word} encoded_reference"
        );
        assert_eq!(
            proto.entry_pc,
            field("entry_pc")
                .and_then(Json::as_usize)
                .expect("entry_pc"),
            "prototype {word} entry_pc"
        );
        assert_eq!(
            proto.initial_decode_state,
            field("initial_decode_state")
                .and_then(Json::as_u32)
                .expect("initial_decode_state"),
            "prototype {word} initial_decode_state"
        );
        assert_eq!(
            proto.dispatch_token,
            field("dispatch_token")
                .and_then(Json::as_u32)
                .expect("dispatch_token"),
            "prototype {word} dispatch_token"
        );
        assert_eq!(
            proto.frame_capacity,
            field("frame_capacity")
                .and_then(Json::as_u16)
                .expect("frame_capacity"),
            "prototype {word} frame_capacity"
        );
        assert_eq!(
            proto.bank_base,
            field("bank_base")
                .and_then(Json::as_u32)
                .expect("bank_base"),
            "prototype {word} bank_base"
        );
        assert_eq!(
            proto.prototype_salt,
            field("prototype_salt")
                .and_then(Json::as_u16)
                .expect("prototype_salt"),
            "prototype {word} prototype_salt"
        );
        assert_eq!(
            proto.fixed_parameter_mode,
            field("fixed_parameter_mode")
                .and_then(Json::as_bool)
                .expect("fixed_parameter_mode"),
            "prototype {word} fixed_parameter_mode"
        );
        assert_eq!(
            proto.fixed_parameter_count,
            field("fixed_parameter_count").and_then(Json::as_u16),
            "prototype {word} fixed_parameter_count (null/None for the vararg top-level record)"
        );
        let operands: Vec<u16> = field("parameter_operands")
            .and_then(Json::as_arr)
            .expect("parameter_operands")
            .iter()
            .map(|operand| operand.as_u16().expect("parameter operand"))
            .collect();
        assert_eq!(
            proto.parameter_operands, operands,
            "prototype {word} parameter_operands"
        );
        assert_eq!(
            proto.captures.len(),
            field("capture_count")
                .and_then(Json::as_usize)
                .expect("capture_count"),
            "prototype {word} capture_count"
        );
    }

    // The two decoded prototype entries (VM-DISASSEMBLY.md covers exactly
    // these two: the parser at PC 388 and the top-level record at PC 413).
    let entry_pcs: BTreeSet<usize> = vm.prototypes.iter().map(|proto| proto.entry_pc).collect();
    let expected_entry_pcs: BTreeSet<usize> = json_prototypes
        .iter()
        .map(|proto| {
            proto
                .get("entry_pc")
                .and_then(Json::as_usize)
                .expect("entry_pc")
        })
        .collect();
    assert_eq!(entry_pcs, expected_entry_pcs, "prototype entry PCs");
    assert!(
        entry_pcs.contains(&388) && entry_pcs.contains(&413),
        "the parser entry (388) and the top-level entry (413) must both be present"
    );
}

#[test]
fn string_and_number_constants_match_baseline() {
    let Some(source) = load_sample_source() else {
        skip_test(SAMPLE_SKIP);
        return;
    };
    let Some(meta) = load_metadata() else {
        skip_test(METADATA_SKIP);
        return;
    };
    let vm = decode_or_explain(&source);

    // --- String constants --------------------------------------------------
    let json_strings = meta
        .get("string_record_candidates")
        .and_then(Json::as_arr)
        .expect("decoded-metadata.json string_record_candidates");
    assert_eq!(
        vm.strings.len(),
        json_strings.len(),
        "exactly three decoded string records (table, concat, and the comma separator)"
    );
    let by_offset: BTreeMap<usize, _> = vm
        .strings
        .iter()
        .map(|record| (record.byte_offset, record))
        .collect();
    let vm_offsets: BTreeSet<usize> = vm.strings.iter().map(|record| record.byte_offset).collect();
    let json_offsets: BTreeSet<usize> = json_strings
        .iter()
        .map(|record| {
            record
                .get("byte_offset")
                .and_then(Json::as_usize)
                .expect("string byte_offset")
        })
        .collect();
    assert_eq!(vm_offsets, json_offsets, "string record byte offsets");

    for json_record in json_strings {
        let offset = json_record
            .get("byte_offset")
            .and_then(Json::as_usize)
            .expect("string byte_offset");
        let Some(&record) = by_offset.get(&offset) else {
            panic!("no decoded string record at byte offset {offset}");
        };
        let text = json_record
            .get("text")
            .and_then(Json::as_str)
            .expect("string text");
        assert_eq!(
            record.encoded_reference,
            json_record
                .get("encoded_reference")
                .and_then(Json::as_u32)
                .expect("string encoded_reference"),
            "string record at offset {offset} encoded_reference"
        );
        assert_eq!(
            record.value,
            text.as_bytes(),
            "string record at offset {offset} must decode to {text:?}"
        );
        let length = json_record
            .get("length")
            .and_then(Json::as_usize)
            .expect("string length");
        assert_eq!(
            record.value.len(),
            length,
            "baseline length self-consistency for the record at offset {offset}"
        );
        let hex = json_record
            .get("hex")
            .and_then(Json::as_str)
            .expect("string hex");
        let decoded_hex: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("valid hex byte"))
            .collect();
        assert_eq!(
            decoded_hex, record.value,
            "baseline hex self-consistency for the record at offset {offset}"
        );
        assert_eq!(
            json_record.get("printable").and_then(Json::as_bool),
            Some(true),
            "all three string records are printable text"
        );
    }

    // --- f64 number constants ------------------------------------------------
    let numeric_region = meta
        .get("numeric_region")
        .expect("decoded-metadata.json numeric_region");
    let json_numbers = numeric_region
        .get("records")
        .and_then(Json::as_arr)
        .expect("numeric_region.records");
    assert_eq!(
        vm.numbers.len(),
        json_numbers.len(),
        "exactly four decoded f64 records"
    );
    let by_offset: BTreeMap<usize, _> = vm
        .numbers
        .iter()
        .map(|record| (record.byte_offset, record))
        .collect();
    for json_record in json_numbers {
        let offset = json_record
            .get("byte_offset")
            .and_then(Json::as_usize)
            .expect("number byte_offset");
        let Some(&record) = by_offset.get(&offset) else {
            panic!("no decoded number record at byte offset {offset}");
        };
        assert_eq!(
            record.index,
            json_record
                .get("index")
                .and_then(Json::as_usize)
                .expect("number index"),
            "number record at offset {offset} index"
        );
        assert_eq!(
            record.encoded_reference,
            json_record
                .get("encoded_reference")
                .and_then(Json::as_u32)
                .expect("number encoded_reference"),
            "number record at offset {offset} encoded_reference"
        );
        let value = json_record
            .get("value")
            .and_then(Json::as_f64)
            .expect("number value");
        assert_eq!(
            record.value.to_bits(),
            value.to_bits(),
            "number record at offset {offset} must decode to the exact baseline double {value}"
        );
        assert_eq!(
            record.bits,
            record.value.to_bits(),
            "NumberConstant.bits must agree with NumberConstant.value"
        );
    }
}

#[test]
fn vm_dispatch_tables_and_integrity_match_baseline() {
    let Some(source) = load_sample_source() else {
        skip_test(SAMPLE_SKIP);
        return;
    };
    let Some(meta) = load_metadata() else {
        skip_test(METADATA_SKIP);
        return;
    };
    let Some(vm_analysis) = load_vm_analysis() else {
        skip_test(
            "T001-VM-ANALYSIS.md unavailable: the dispatch map and integrity narrative \
             comparisons need it (set LUAU_DEVIRT_ANALYSIS_DIR)",
        );
        return;
    };
    let vm = decode_or_explain(&source);

    // --- Dispatch token -> family map ---------------------------------------
    let expected_dispatch = dispatch_map(&vm_analysis);
    assert_eq!(
        expected_dispatch.len(),
        13,
        "the var17 dispatch map has 13 tokens across 7 unique families"
    );
    assert_eq!(
        vm.dispatch_families, expected_dispatch,
        "dispatch_families vs the T001-VM-ANALYSIS.md dispatch map"
    );

    // --- Permutation parity ---------------------------------------------------
    let branch_parity = meta
        .get("var35_checksum")
        .and_then(|value| value.get("branch_parity"))
        .expect("decoded-metadata.json var35_checksum.branch_parity");
    // The JSON baseline records only the probed branch indices, while the
    // decoder exposes the full permutation-parity table (16,384 entries for
    // this VM), so the baseline entries are compared as a subset:
    // 0 => 1 and 2 => 0.
    for (key, value) in branch_parity
        .as_pairs()
        .expect("branch_parity must be an object")
    {
        let key: u16 = key.parse().expect("branch parity key");
        let value = value.as_u8().expect("branch parity value");
        assert_eq!(
            vm.permutation_parity.get(&key),
            Some(&value),
            "permutation_parity[{key}] vs var35_checksum.branch_parity"
        );
    }

    // --- Initial strings and their integrity records ---------------------------
    let expected_initial =
        number_before(&vm_analysis, "initial strings").expect("initial strings sentence") as usize;
    assert_eq!(
        vm.initial_strings.len(),
        expected_initial,
        "the wrapper's leading integrity check covers all 13 initial strings"
    );
    assert!(
        vm.initial_strings
            .iter()
            .any(|bytes| bytes.as_slice() == vm.payload.as_slice()),
        "the 2,276-byte protected payload must be one of the initial strings \
         (var72 = buffer.fromstring(tbl1[1]))"
    );
    assert_eq!(
        vm.table_integrity.len(),
        expected_initial,
        "one integrity record per initial string"
    );
    let mut indices: Vec<usize> = vm.table_integrity.iter().map(|entry| entry.index).collect();
    indices.sort_unstable();
    indices.dedup();
    assert_eq!(
        indices.len(),
        vm.table_integrity.len(),
        "integrity record indices must be distinct"
    );
    let mut consumed = vec![false; vm.initial_strings.len()];
    for entry in &vm.table_integrity {
        let matched = vm
            .initial_strings
            .iter()
            .enumerate()
            .find(|(position, bytes)| {
                !consumed[*position]
                    && bytes.len() == entry.length
                    && adler32(bytes) == entry.adler32
            });
        let Some((position, _)) = matched else {
            panic!(
                "integrity record (index {}, length {}, adler32 {:#010x}) matches no initial \
                 string; the recorded data must describe the recorded strings",
                entry.index, entry.length, entry.adler32
            );
        };
        consumed[position] = true;
    }
}

// =========================================================================
// CFG-level comparisons against the baseline disassembly
// =========================================================================

#[test]
fn cfg_reachability_matches_baseline() {
    let Some(source) = load_sample_source() else {
        skip_test(SAMPLE_SKIP);
        return;
    };
    let Some(disassembly) = load_disassembly() else {
        skip_test(
            "VM-DISASSEMBLY.md unavailable: the 55-address reachability baseline needs it \
             (set LUAU_DEVIRT_ANALYSIS_DIR)",
        );
        return;
    };
    let Some(vm_analysis) = load_vm_analysis() else {
        skip_test(
            "T001-VM-ANALYSIS.md unavailable: the reachable-address and state-variant counts \
             need it (set LUAU_DEVIRT_ANALYSIS_DIR)",
        );
        return;
    };
    let vm = decode_or_explain(&source);
    let lifted = walk_or_explain(&vm);

    // --- The 55 reachable addresses ------------------------------------------
    let expected_pcs = disassembly_pcs(&disassembly);
    let md_intro_count = number_before(&disassembly, "instruction addresses reached")
        .expect("VM-DISASSEMBLY.md intro sentence count");
    assert_eq!(
        expected_pcs.len(),
        md_intro_count as usize,
        "VM-DISASSEMBLY.md table rows must match its own 'all 55 instruction addresses' intro"
    );
    let reach_sentence = numbers_between(&vm_analysis, "reduced this to", ')')
        .expect("T001-VM-ANALYSIS.md reachable-address sentence");
    assert_eq!(
        reach_sentence.as_slice(),
        &[55, 5, 50][..],
        "baseline sentence: 55 reachable addresses (5 entry, 50 parser)"
    );
    assert_eq!(
        reach_sentence[0],
        reach_sentence[1] + reach_sentence[2],
        "5 entry + 50 parser = 55"
    );

    assert_eq!(
        lifted.reachable_pcs.len(),
        expected_pcs.len(),
        "reachable_pcs count (55)"
    );
    assert_eq!(
        lifted.reachable_pcs, expected_pcs,
        "reachable_pcs must equal the 55 instruction addresses from VM-DISASSEMBLY.md"
    );

    // --- 109 retained state variants ------------------------------------------
    let state_variants =
        number_after(&vm_analysis, "retained").expect("T001-VM-ANALYSIS.md state-variant sentence");
    assert_eq!(
        lifted.state_variants, state_variants as usize,
        "state_variants vs the walk's 109 combinations of address, decode state, register \
         bank, and dispatch token"
    );

    // --- Entry points ------------------------------------------------------------
    for expected_entry in [388usize, 413usize] {
        assert!(
            lifted.entry_points.contains(&expected_entry),
            "entry_points must contain the decoded prototype entry PC {expected_entry}"
        );
    }

    // --- Only reached families may appear ---------------------------------------
    let reached =
        reached_families(&vm_analysis).expect("T001-VM-ANALYSIS.md reached-families sentence");
    assert_eq!(
        reached,
        BTreeSet::from([6094u32, 1173, 6965]),
        "the three reached families are 6094, 1173, and 6965"
    );
    for (start_pc, block) in &lifted.blocks {
        assert!(
            reached.contains(&block.handler_family),
            "block at PC {start_pc} uses handler family {}, which the baseline marks unreached",
            block.handler_family
        );
    }

    // --- Block structure -----------------------------------------------------------
    let spans: Vec<(usize, usize)> = lifted
        .blocks
        .values()
        .map(|block| (block.start_pc, block.end_pc))
        .collect();
    for pair in spans.windows(2) {
        assert!(
            pair[0].1 <= pair[1].0,
            "block spans must not overlap ({}..{} vs {}..{})",
            pair[0].0,
            pair[0].1,
            pair[1].0,
            pair[1].1
        );
    }
    for pc in lifted.reachable_pcs.iter().copied() {
        let covering = spans
            .iter()
            .filter(|(start, end)| *start <= pc && pc < *end)
            .count();
        assert_eq!(
            covering, 1,
            "reachable PC {pc} must belong to exactly one basic block"
        );
    }
    for start_pc in lifted.blocks.keys() {
        assert!(
            lifted.reachable_pcs.contains(start_pc),
            "block start PC {start_pc} must itself be a reachable address"
        );
    }

    // --- Entry states ------------------------------------------------------------
    let mut distinct_states: HashSet<VmState> = HashSet::new();
    for (start_pc, block) in &lifted.blocks {
        assert!(
            !block.entry_states.is_empty(),
            "block at PC {start_pc} must record at least one entry state"
        );
        distinct_states.extend(block.entry_states.iter().cloned());
    }
    assert_eq!(
        distinct_states.len(),
        lifted.state_variants,
        "the aggregate state_variants must equal the distinct VmStates across all blocks"
    );

    // --- Successors -----------------------------------------------------------------
    for (start_pc, block) in &lifted.blocks {
        for successor in &block.successors {
            if let Some(target) = successor.target_pc {
                assert!(
                    lifted.reachable_pcs.contains(&target),
                    "successor of PC {start_pc} targets unreachable PC {target}"
                );
            }
        }
    }
}

// =========================================================================
// Emitted-output markers and syntax validation
// =========================================================================

#[test]
fn emitted_luau_markers_match_baseline() {
    let Some(source) = load_sample_source() else {
        skip_test(SAMPLE_SKIP);
        return;
    };
    let vm = decode_or_explain(&source);
    let lifted = walk_or_explain(&vm);

    let emitted = emit_or_explain(
        &lifted,
        &CodegenOptions {
            strict: true,
            include_source_comments: false,
            pretty: false,
        },
    );
    assert!(
        !emitted.is_empty(),
        "emit_luau must produce a non-empty chunk"
    );

    // The readable reconstruction (T001-deobfuscated.luau, blessed by the
    // baseline analysis) is a --!strict chunk; the CLI defaults to strict.
    assert!(
        emitted.contains("--!strict"),
        "default (strict) emission must carry the --!strict header marker"
    );

    // "`170` (`0xAA`) is a marker only while waiting for a frame."
    let lowered = emitted.to_ascii_lowercase();
    assert!(
        has_number_word(&lowered, "170") || has_number_word(&lowered, "0xaa"),
        "emitted source must reference the frame marker 170 (0xAA)"
    );

    // "sums its values modulo 256"
    assert!(
        has_number_word(&emitted, "256") || has_number_word(&lowered, "0x100"),
        "emitted source must reference the checksum modulus 256"
    );

    // "the payload resolves env[\"table\"][\"concat\"]" and the decoded
    // string constants `table`, `concat`, and the separator `","`.
    assert!(
        tokenize_luau(&emitted)
            .expect("valid emitted tokens")
            .iter()
            .any(|token| matches!(token, TokenKind::Identifier(name) if name == "table")),
        "emitted source must reference table"
    );
    assert!(
        tokenize_luau(&emitted)
            .expect("valid emitted tokens")
            .iter()
            .any(|token| matches!(token, TokenKind::Identifier(name) if name == "concat")),
        "emitted source must call concat"
    );
    assert!(
        emitted.contains("\",\"") || emitted.contains("','"),
        "emitted source must materialize the decoded \",\" separator string constant"
    );

    // The --no-strict pipeline must not claim strict mode.
    let non_strict = emit_or_explain(
        &lifted,
        &CodegenOptions {
            strict: false,
            include_source_comments: false,
            pretty: false,
        },
    );
    assert!(
        !non_strict.contains("--!strict"),
        "--no-strict emission must not carry the --!strict marker"
    );

    // Commented emission stays non-empty.
    let commented = emit_or_explain(
        &lifted,
        &CodegenOptions {
            strict: true,
            include_source_comments: true,
            pretty: false,
        },
    );
    assert!(
        !commented.is_empty(),
        "commented emission must be non-empty"
    );
}

/// Compare the emitted chunk against the sibling readable reconstruction
/// `T001-deobfuscated.luau` after token normalization, mirroring the
/// checked-in comparison methodology (`T001-analyze.py`): comments and
/// whitespace are ignored, every non-identifier token must match exactly
/// position-by-position, string and number literals must decode to equal
/// values (`170` and `0xAA` are the same frame marker), and identifiers may
/// differ only through one consistent bijective rename. Static text
/// analysis only: neither source is ever executed.
#[test]
fn emitted_luau_matches_baseline_output_modulo_rename() {
    let Some(source) = load_sample_source() else {
        skip_test(SAMPLE_SKIP);
        return;
    };
    let Some(baseline_source) = load_baseline_output() else {
        skip_test(BASELINE_OUTPUT_SKIP);
        return;
    };
    let vm = decode_or_explain(&source);
    let lifted = walk_or_explain(&vm);
    let emitted = emit_or_explain(
        &lifted,
        &CodegenOptions {
            strict: true,
            include_source_comments: false,
            pretty: false,
        },
    );

    let baseline_tokens =
        tokenize_luau(&baseline_source).expect("the baseline reconstruction must lex cleanly");
    let emitted_tokens = tokenize_luau(&emitted).expect("the emitted chunk must lex cleanly");

    match compare_token_streams(&baseline_tokens, &emitted_tokens) {
        Ok(rename) => {
            eprintln!(
                "emitted output matches the baseline reconstruction modulo a bijective \
                 rename of {} identifiers across {} tokens (visible with --nocapture)",
                rename.len(),
                baseline_tokens.len()
            );
        }
        Err(error) => panic!(
            "emitted Luau does not match the baseline readable output after token \
             normalization (comments/whitespace ignored, exact non-identifier tokens, \
             decoded string/number values, one consistent bijective identifier rename): \
             {error}"
        ),
    }
}

/// Parser/syntax validation of GENERATED OUTPUT ONLY via the local
/// `luau-decompiler validate --builtin --no-color` subcommand. This is the
/// local syntax sanity validator, NOT official bytecode compilation. It never
/// runs the emitted source: `--builtin` skips the validator's external PATH
/// probe (the default probe finds the installed `luau.exe`, which executes
/// scripts, and calls an unsupported flag), and the child's PATH is scrubbed
/// to the validator's own directory as defense in depth so no external tool
/// can be spawned regardless. The `LUAU_DEVIRT_VALIDATOR` override only
/// selects the executable; the subcommand and its flags are always supplied
/// by this test. Skips clearly when no validator has been built.
#[test]
fn emitted_luau_passes_local_syntax_validation() {
    let Some(source) = load_sample_source() else {
        skip_test(SAMPLE_SKIP);
        return;
    };
    let Some(validator) = validator_path() else {
        skip_test(
            "no local Luau syntax validator: set LUAU_DEVIRT_VALIDATOR or build the \
             luau-decompiler CLI so that target/luau-validator/release/luau-decompiler(.exe) \
             exists (e.g. cargo build --release with CARGO_TARGET_DIR=target/luau-validator)",
        );
        return;
    };

    let vm = decode_or_explain(&source);
    let lifted = walk_or_explain(&vm);
    let emitted = emit_or_explain(
        &lifted,
        &CodegenOptions {
            strict: true,
            include_source_comments: false,
            pretty: false,
        },
    );

    let temp = manifest_dir().join("target").join(format!(
        "luau-devirt-verify-emitted-{}.luau",
        std::process::id()
    ));
    fs::write(&temp, emitted).unwrap_or_else(|error| {
        panic!(
            "failed to stage emitted output at {}: {error}",
            temp.display()
        )
    });
    let result = Command::new(&validator)
        .arg("validate")
        .arg("--builtin")
        .arg("--no-color")
        .arg(&temp)
        .env("PATH", validator.parent().unwrap_or_else(|| Path::new("")))
        .output();
    let _ = fs::remove_file(&temp);
    let output =
        result.unwrap_or_else(|error| panic!("failed to run {}: {error}", validator.display()));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "emitted Luau failed the local syntax sanity check (luau-decompiler validate \
         --builtin --no-color; parser/syntax validation, NOT official bytecode compilation):\
         \nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

/// Compile the GENERATED OUTPUT to Luau bytecode. `luau-compile` is a
/// compiler-only CLI: this does not load or execute the resulting bytecode.
#[test]
fn emitted_luau_compiles_without_execution() {
    let Some(source) = load_sample_source() else {
        skip_test(SAMPLE_SKIP);
        return;
    };
    let Some(compiler) = compiler_path() else {
        skip_test(
            "official Luau compiler unavailable: set LUAU_DEVIRT_COMPILER or install the \
             luau-compile executable at target/luau-compiler/0.747/luau-compile(.exe)",
        );
        return;
    };

    let vm = decode_or_explain(&source);
    let lifted = walk_or_explain(&vm);
    let emitted = emit_or_explain(
        &lifted,
        &CodegenOptions {
            strict: true,
            include_source_comments: false,
            pretty: false,
        },
    );

    let temp = manifest_dir().join("target").join(format!(
        "luau-devirt-compile-emitted-{}.luau",
        std::process::id()
    ));
    fs::write(&temp, emitted).unwrap_or_else(|error| {
        panic!(
            "failed to stage emitted output at {}: {error}",
            temp.display()
        )
    });
    let result = Command::new(&compiler).arg("--null").arg(&temp).output();
    let _ = fs::remove_file(&temp);
    let output = result.unwrap_or_else(|error| {
        panic!(
            "failed to run compile-only tool {}: {error}",
            compiler.display()
        )
    });
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "emitted Luau failed official compile-only validation (luau-compile):\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}
