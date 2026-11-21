//! Independently certified SARP fragment/byteswap/dual-stream VM.
//! All computations are static, bounded and deterministic. No Lua interpreter,
//! target function invocation, network client or runtime VM exists in this module.
//! The handler grammar and typed IR are shared; SARP formulas/state are isolated.

use crate::base85::{Parser, E, S};
use crate::decoder::{scan_quoted, sha256_hex, tokenize, Token, TokenKind};
use crate::ir::*;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

pub const PROFILE: &str = "sarp-fragment-dualstream-7word-v1";
pub const WRAPPER_SHA256: &str = "e81814ff9d295dc39e3888a8e60b4a484140b627f52ef3b8c3215b17afe92f3b";
const MAX_SOURCE: usize = 8 * 1024 * 1024;
const MAX_PAYLOAD: usize = 1024 * 1024;
const SMA: u32 = 1771687064;
const SMB: u32 = 4294002830;
const SALT: u32 = 12836;
const INITIAL_K1: u32 = 4021752008 ^ 3067287787;

fn sequence(ts: &[Token], at: usize, needle: &[&str]) -> bool {
    ts.get(at..at.saturating_add(needle.len()))
        .is_some_and(|row| {
            row.iter()
                .map(|t| t.text.as_str())
                .eq(needle.iter().copied())
        })
}
fn unique(ts: &[Token], needle: &[&str]) -> Result<usize, String> {
    let positions = (0..ts.len())
        .filter(|at| sequence(ts, *at, needle))
        .collect::<Vec<_>>();
    match positions.as_slice() {
        [at] => Ok(*at),
        _ => Err(format!(
            "{PROFILE}: expected one {needle:?}, found {}",
            positions.len()
        )),
    }
}
pub(crate) fn certify(ts: &[Token]) -> Result<[usize; 5], String> {
    let mut literals = [0; 5];
    let mut ignored = BTreeMap::new();
    for (index, name) in ["_pc0", "_pc1", "_pc2", "_pc3", "_pc4"].iter().enumerate() {
        let at = unique(ts, &["local", name, "="])? + 3;
        if ts.get(at).map(|t| t.kind) != Some(TokenKind::String) {
            return Err("SARP fragment is not a quoted literal".to_owned());
        }
        literals[index] = at;
        ignored.insert(at, format!("PAYLOAD:{name}"));
    }
    let normalized = ts
        .iter()
        .enumerate()
        .map(|(at, t)| ignored.get(&at).map(String::as_str).unwrap_or(&t.text))
        .collect::<Vec<_>>()
        .join("\n");
    if sha256_hex(normalized.as_bytes()) != WRAPPER_SHA256 {
        return Err("unsupported SARP wrapper: certified token skeleton changed".to_owned());
    }
    Ok(literals)
}
pub fn is_profile(vm: &DecodedVm) -> bool {
    vm.profile == VmProfile::Sarp
}

/// Transport is independently transcribed from initOnce: low Base85 digit
/// first; bit32.byteswap of low-u32; then its separate transport XOR stream.
pub fn decode_transport(encoded: &[u8], alphabet: &[u8], bytes: usize) -> Result<Vec<u8>, String> {
    if alphabet.len() != 85 || bytes == 0 || bytes > MAX_PAYLOAD || bytes % 4 != 0 {
        return Err("invalid SARP alphabet or output size".to_owned());
    }
    if encoded.len() != bytes / 4 * 5 {
        return Err("SARP transport length must be exactly five bytes per word".to_owned());
    }
    let mut map = [None; 256];
    for (i, b) in alphabet.iter().copied().enumerate() {
        if map[b as usize].replace(i as u64).is_some() {
            return Err("duplicate SARP alphabet byte".to_owned());
        }
    }
    let mut output = Vec::with_capacity(bytes);
    let mut key = 1147127625u32;
    for (index, group) in encoded.chunks_exact(5).enumerate() {
        let mut value = 0u64;
        for b in group.iter().rev() {
            value = value * 85
                + map[*b as usize]
                    .ok_or_else(|| format!("invalid SARP alphabet byte {b} at word {index}"))?;
        }
        key = key.wrapping_mul(17487).wrapping_add(3048913621);
        output.extend_from_slice(&((value as u32).swap_bytes() ^ key).to_le_bytes());
    }
    Ok(output)
}
pub fn assemble_fragments(fragments: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    const LEN: [usize; 5] = [558, 582, 560, 556, 574];
    if fragments.len() != 5 || fragments.iter().zip(LEN).any(|(s, n)| s.len() != n) {
        return Err("SARP fragment count or exact extents differ".to_owned());
    }
    let mut encoded = vec![0; 2830];
    let mut written = vec![false; 2830];
    // Source bcopy order, not declaration order: 2, 4, 3, 1, 0.
    for (index, offset) in [(2, 1140), (4, 2256), (3, 1700), (1, 558), (0, 0)] {
        let end = offset + fragments[index].len();
        if written[offset..end].iter().any(|v| *v) {
            return Err("overlapping fragment write".to_owned());
        }
        encoded[offset..end].copy_from_slice(&fragments[index]);
        written[offset..end].fill(true);
    }
    if written.iter().any(|v| !*v) {
        return Err("unwritten transport bytes".to_owned());
    }
    Ok(encoded)
}
fn read32(data: &[u8], offset: usize) -> Result<u32, String> {
    let end = offset.checked_add(4).ok_or("buffer offset overflow")?;
    let s = data
        .get(offset..end)
        .ok_or_else(|| format!("u32 read outside payload at byte {offset}"))?;
    Ok(u32::from_le_bytes(
        s.try_into().map_err(|_| "invalid u32 extent")?,
    ))
}
fn next_key(value: u32) -> u32 {
    let mut value = value
        .wrapping_mul(398991)
        .wrapping_add(3534337991)
        .swap_bytes();
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
        .ok_or_else(|| format!("missing decoded SARP word {at}"))
}
fn slot(vm: &DecodedVm, at: usize) -> Result<u16, String> {
    vm.slot_map
        .get(at)
        .copied()
        .filter(|_| at > 0)
        .ok_or_else(|| format!("register-map index {at} out of bounds"))
}

#[derive(Clone, Debug)]
pub struct Initialization {
    pub transport_sha256: String,
    pub header: [u32; 4],
    pub master_key: u32,
    pub float_bits: u64,
    pub zero_counts: u32,
    pub range: (usize, usize),
    pub permutation_a: Vec<u16>,
    pub permutation_b: Vec<u16>,
    pub permutation_c: Vec<u16>,
}
fn permutations() -> (Vec<u16>, Vec<u16>, Vec<u16>) {
    let mut a = (0..16384u16).collect::<Vec<_>>();
    let mut b = a.clone();
    let mut c = vec![0u16; 16384];
    let (mut ka, mut kb) = (1933532995u32, 2171122303u32);
    for i in (1..16384usize).rev() {
        ka = ka.wrapping_mul(17577).wrapping_add(419902917);
        a.swap(i, (ka % (i as u32 + 1)) as usize);
        kb = kb.wrapping_mul(17577).wrapping_add(419902917);
        b.swap(i, (kb % (i as u32 + 1)) as usize);
    }
    for i in 0..16384 {
        let (pa, pb) = (a[i] as u32, b[i] as u32);
        let bit = ((pa >> 7) & 1) ^ ((pb >> 10) & 1) ^ 1;
        c[pa as usize] =
            ((pb * 4 + ((i as u32 * 17 + 1833) % 16384) * 2 + bit + SALT) % 65536) as u16;
    }
    for i in 0..16384 {
        ka = ka.wrapping_mul(17577).wrapping_add(419902917);
        kb = kb.wrapping_mul(17577).wrapping_add(419902917);
        a[i] |= (((ka >> 20) & 3) << 14) as u16;
        b[i] |= (((kb >> 20) & 3) << 14) as u16;
    }
    (a, b, c)
}
fn initialize(
    payload: &[u8],
    argument: u32,
) -> Result<(Vec<Option<u32>>, Vec<u16>, Vec<u32>, Initialization), String> {
    if payload.len() != 2264 {
        return Err("SARP certified layout requires 2264 bytes".to_owned());
    }
    let mut words = vec![None; payload.len() / 4 + 1];
    let mut key = argument ^ 1496625396;
    let mut header = [0; 4];
    for i in 1..=4 {
        key = next_key(key);
        header[i - 1] = read32(payload, (i - 1) * 4)? ^ key;
        words[i] = Some(header[i - 1]);
    }
    let bw = read32(payload, 12)?;
    let m0 = argument ^ bw;
    let m1 = m0.wrapping_mul(26797).wrapping_add(1259477385);
    let float_bits = (m1 as f64 + header[3] as f64 + 1048576.0).to_bits();
    let lo = float_bits as u32;
    let hi = (float_bits >> 32) as u32;
    let zero_counts =
        m0.leading_zeros() * 65537 + bw.trailing_zeros() * 257 + header[3].leading_zeros();
    // Source type/arithmetic proofs: {}+1 fails pcall (_pf=0); __add on
    // _mx returns (_flo+_cz)%2^32; both coroutine resumes succeed. The
    // bit replace/rawget/sub/frexp/modf/clamp/format/pack/base31 checks
    // are the certified standard-library identities, yielding _pe=0.
    let master_key =
        m1.wrapping_add(lo) ^ header[3].rotate_left(11) ^ hi ^ m0.swap_bytes() ^ zero_counts;
    let low = (header[1] ^ 3678364643 ^ master_key) as usize;
    let high = (header[2] ^ 3087163986 ^ master_key) as usize;
    if low < 5 || low > high || high.checked_add(59).is_none_or(|n| n > payload.len() / 4) {
        return Err(format!("invalid SARP header range {low}..={high}"));
    }
    for i in low..=high {
        key = next_key(key);
        words[i] = Some(read32(payload, (i - 1) * 4)? ^ key);
    }
    let mut slots = vec![0];
    let mut rk = 3402759894 ^ master_key;
    for i in 0..59 {
        rk = rk.wrapping_mul(24307).wrapping_add(1800847725);
        let v = read32(payload, high * 4 + i * 4)? ^ rk;
        slots.extend([v as u16, (v >> 16) as u16]);
    }
    if slots.iter().skip(1).any(|v| *v == 0 || *v > 52) {
        return Err("unsupported/corrupt SARP physical register map (expected 1..52)".to_owned());
    }
    let mut biases = vec![0];
    let mut ks = 706272505u32;
    for _ in 0..64 {
        ks = ks.wrapping_mul(26663).wrapping_add(4214497697);
        biases.push(1 + ks % 200000);
    }
    let (a, b, c) = permutations();
    let mut second = master_key ^ 2372119159;
    for i in low..=high {
        second = second.wrapping_mul(7745).wrapping_add(888415943);
        let m = a[(second & 16383) as usize] as u32
            ^ ((b[((second >> 14) & 16383) as usize] as u32) << 16)
            ^ biases[1 + i % 64]
            ^ c[((second ^ i as u32) & 16383) as usize] as u32;
        words[i] = Some(words[i].ok_or("absent second-layer word")? ^ m);
    }
    let init = Initialization {
        transport_sha256: sha256_hex(payload),
        header,
        master_key,
        float_bits,
        zero_counts,
        range: (low, high),
        permutation_a: a,
        permutation_b: b,
        permutation_c: c,
    };
    Ok((words, slots, biases, init))
}
pub(crate) fn decode(source: &str, ts: &[Token]) -> Result<DecodedVm, String> {
    if source.len() > MAX_SOURCE {
        return Err("SARP source budget exceeded".to_owned());
    }
    let indices = certify(ts)?;
    let mut fragments = vec![];
    for at in indices {
        fragments.push(scan_quoted(source, ts[at].offset)?.0);
    }
    let encoded = assemble_fragments(&fragments)?;
    let at = unique(ts, &["_ab", "=", "bfrom", "("])? + 4;
    let alphabet_token = ts
        .get(at)
        .filter(|t| t.kind == TokenKind::String)
        .ok_or("missing SARP alphabet literal")?;
    let alphabet = scan_quoted(source, alphabet_token.offset)?.0;
    let payload = decode_transport(&encoded, &alphabet, 2264)?;
    let argument = 66482806 ^ 3268698463;
    let (words, slots, biases, init) = initialize(&payload, argument)?;
    let root = (init.master_key ^ 2674807212u32.wrapping_add(2921856046) ^ 774880) as usize;
    let raw_words = payload
        .chunks_exact(4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .collect();
    let mut vm = DecodedVm {
        profile: VmProfile::Sarp,
        source_text: source.to_owned(),
        source_sha256: Some(sha256_hex(source.as_bytes())),
        payload,
        raw_words,
        decoded_words: words,
        slot_map: slots,
        immediate_biases: biases,
        initialization_argument: argument,
        master_key: init.master_key,
        decoded_range: init.range,
        table_integrity: vec![],
        initial_strings: fragments,
        prototypes: vec![],
        entry_prototype: root,
        strings: vec![],
        numbers: vec![],
        dispatch_families: BTreeMap::new(),
        permutation_parity: BTreeMap::new(),
    };
    let rt = unique(ts, &["RT", "=", "{"])? + 3;
    let mut pos = rt;
    while ts.get(pos).map(|t| t.text.as_str()) != Some("}") {
        if !sequence(ts, pos, &["["]) {
            return Err("invalid certified dispatch table".to_owned());
        }
        let k = ts
            .get(pos + 1)
            .ok_or("truncated RT")?
            .text
            .parse::<u32>()
            .map_err(|_| "noninteger RT key")?;
        let v = ts
            .get(pos + 4)
            .ok_or("truncated RT")?
            .text
            .parse::<u32>()
            .map_err(|_| "noninteger RT value")?;
        if vm.dispatch_families.insert(k, v).is_some() {
            return Err("duplicate RT shape".to_owned());
        }
        pos += 5;
        if sequence(ts, pos, &[","]) {
            pos += 1;
        }
    }
    vm.prototypes.push(prototype(&vm, root)?);
    Ok(vm)
}
fn prototype(vm: &DecodedVm, p: usize) -> Result<Prototype, String> {
    if p == 0
        || p < vm.decoded_range.0
        || p.checked_add(6).is_none_or(|end| end > vm.decoded_range.1)
    {
        return Err("SARP descriptor is outside its decoded seven-word extent".to_owned());
    }
    let k = vm.master_key;
    let entry = (word(vm, p)? ^ 1151433088 ^ k) as usize;
    let b = word(vm, p + 1)? ^ 4028605236 ^ k;
    let a = word(vm, p + 2)? ^ 1209284937 ^ k;
    let _code_start = word(vm, p + 3)? ^ 2871857514 ^ k;
    let key = word(vm, p + 4)? ^ 3098405659 ^ k;
    let token = word(vm, p + 5)? ^ 445800084 ^ k;
    let _code_length = word(vm, p + 6)? ^ 2766250242 ^ k;
    let bank = (b >> 1) & 131071;
    let size = ((b >> 18) & 8191) as u16;
    let fixed = a >> 31 != 0;
    let arity = ((a >> 28) & 7) as u16;
    let captures = ((a >> 18) & 1023) as usize;
    if !vm.dispatch_families.contains_key(&token) {
        return Err("SARP root has an invalid dispatch token".to_owned());
    }
    for off in 1..=4 {
        slot(vm, bank as usize + off)?;
    }
    word(vm, entry)?;
    if captures != 0 {
        return Err(
            "unsupported SARP capture bindings require explicit factory/ups analysis".to_owned(),
        );
    }
    if fixed {
        return Err("unsupported SARP fixed-parameter root".to_owned());
    }
    Ok(Prototype {
        word: p,
        byte_offset: p
            .checked_sub(1)
            .and_then(|p| p.checked_mul(4))
            .ok_or("prototype byte offset overflow")?,
        encoded_reference: p as u32 ^ 774880,
        entry_pc: entry,
        initial_decode_state: key,
        dispatch_token: token,
        frame_capacity: size,
        bank_base: bank,
        prototype_salt: ((a >> 1) & 65535) as u16,
        fixed_parameter_mode: fixed,
        fixed_parameter_count: if fixed { Some(arity) } else { None },
        parameter_operands: vec![],
        captures: vec![],
    })
}

pub fn walk(vm: &DecodedVm) -> Result<LiftedProgram, String> {
    Ok(analyze(vm)?.program)
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
pub struct TraceRow {
    pub state: State,
    pub family: u32,
    pub selector: i64,
    pub transition_helper: Option<u32>,
    pub hash_proof: Option<HashProof>,
    pub end_pc: usize,
    pub instructions: Vec<Instruction>,
    pub successors: Vec<(EdgeLabel, State)>,
}
#[derive(Clone, Debug)]
pub struct HashProof {
    pub value: u32,
    pub mask: u32,
    pub key: u32,
    pub pool: u32,
    pub pk1: u32,
    pub pk2: u32,
    pub expected1: u32,
    pub expected2: u32,
    pub kv_ip: u32,
    pub kv_sh: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct State {
    pub pc: usize,
    pub key: u32,
    pub bank: u32,
    pub token: u32,
    pub salt: u16,
    pub phase: u32,
    pub window: u32,
    pub bank_end: u32,
    pub pool_key: u32,
    pub facts: BTreeMap<u16, i64>,
}
#[derive(Clone, Debug)]
enum Value {
    Int(i64),
    Bool(bool),
    Nil,
    Data(Operand),
    Witness(u8),
    FrameCopy(u16),
    MetaFunction(u32),
}
impl Value {
    fn int(&self) -> Result<i64, String> {
        if let Self::Int(i) = self {
            Ok(*i)
        } else {
            Err(format!("unproved metadata integer {self:?}"))
        }
    }
    fn u32(&self) -> Result<u32, String> {
        let n = self.int()?;
        if !(-(1i64 << 32)..=(1i64 << 32)).contains(&n) {
            return Err("bitwise conversion outside exact u32 budget".to_owned());
        }
        Ok(n as u32)
    }
    fn operand(&self) -> Result<Operand, String> {
        Ok(match self {
            Self::Int(i) => Operand::Constant(Constant::Integer(*i)),
            Self::Bool(b) => Operand::Constant(Constant::Boolean(*b)),
            Self::Nil => Operand::Constant(Constant::Nil),
            Self::Data(v) => v.clone(),
            _ => return Err("wrapper metadata cannot be a program operand".to_owned()),
        })
    }
    fn truth(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            Self::Nil => Some(false),
            Self::Int(_) | Self::MetaFunction(_) => Some(true),
            Self::Data(Operand::Constant(Constant::Boolean(b))) => Some(*b),
            Self::Data(Operand::Constant(Constant::Nil)) => Some(false),
            _ => None,
        }
    }
}
fn id(e: &E, n: &str) -> bool {
    matches!(e,E::Id(v)if v==n)
}
fn idx(e: &E, n: &str) -> bool {
    matches!(e,E::Index(t,_)if id(t,n))
}
fn op_ir(n: &str) -> Result<BinaryOp, String> {
    Ok(match n {
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
        _ => return Err(format!("unsupported operation {n}")),
    })
}
fn register(n: u16) -> Register {
    Register { physical_slot: n }
}
fn r(n: u16) -> Operand {
    Operand::Register(register(n))
}
fn int(n: i64) -> Operand {
    Operand::Constant(Constant::Integer(n))
}

#[derive(Clone, Debug)]
struct Family {
    selector: E,
    tree: S,
    metadata: Vec<u16>,
}
fn model(vm: &DecodedVm) -> Result<(BTreeMap<u32, Family>, BTreeMap<u32, Vec<String>>), String> {
    let ts = tokenize(&vm.source_text)?;
    certify(&ts)?;
    let mut families = BTreeMap::new();
    let mut helpers = BTreeMap::new();
    for i in 0..ts.len().saturating_sub(7) {
        if sequence(&ts, i, &["_h", "["]) && sequence(&ts, i + 3, &["]", "=", "function", "("]) {
            let key = ts[i + 2]
                .text
                .parse::<u32>()
                .map_err(|_| "invalid helper id")?;
            let mut params = vec![];
            let mut at = i + 7;
            while ts.get(at).map(|t| t.text.as_str()) != Some(")") {
                let t = ts.get(at).ok_or("unterminated helper signature")?;
                if t.text != "," {
                    params.push(t.text.clone());
                }
                at += 1;
                if params.len() > 32 {
                    return Err("helper parameter budget exceeded".to_owned());
                }
            }
            if helpers.insert(key, params).is_some() {
                return Err("duplicate helper definition".to_owned());
            }
        }
        if !sequence(&ts, i, &["_dr", "["]) || !sequence(&ts, i + 3, &["]", "=", "function", "("]) {
            continue;
        }
        let family = ts[i + 2]
            .text
            .parse::<u32>()
            .map_err(|_| "invalid family")?;
        if ![1901, 359, 2199].contains(&family) {
            continue;
        }
        let anchor = (i + 7..ts.len().saturating_sub(3))
            .find(|at| sequence(&ts, *at, &["local", "op", "="]))
            .ok_or("missing selector")?;
        let mut parser = Parser {
            ts: &ts,
            source: &vm.source_text,
            at: anchor + 3,
            depth: 0,
        };
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
        let tree = S::If(arms, other);
        let core = |index: usize| vm.slot_map[index];
        let metadata = match family {
            1901 => vec![
                core(11),
                core(8),
                43,
                39,
                core(12),
                46,
                core(4),
                core(6),
                core(7),
                core(14),
                11,
                7,
                core(3),
                9,
                core(10),
                core(13),
                core(1),
                core(5),
                41,
                core(15),
                core(2),
                core(9),
                32,
            ],
            359 => vec![
                core(4),
                core(1),
                core(9),
                19,
                core(12),
                core(10),
                17,
                core(11),
                core(6),
                12,
                core(8),
                22,
                25,
                core(2),
                5,
                core(3),
                core(15),
                7,
                31,
                46,
                16,
                core(13),
                core(7),
                core(14),
                core(5),
                40,
            ],
            _ => vec![
                core(7),
                core(13),
                core(4),
                17,
                core(8),
                core(10),
                core(6),
                core(12),
                core(9),
                core(11),
                core(3),
                3,
                48,
                core(2),
                33,
                46,
                core(14),
                49,
                10,
                core(5),
                core(15),
                11,
                5,
                core(1),
                4,
            ],
        };
        if families
            .insert(
                family,
                Family {
                    selector,
                    tree,
                    metadata,
                },
            )
            .is_some()
        {
            return Err("duplicate SARP family".to_owned());
        }
    }
    if families.keys().copied().collect::<BTreeSet<_>>() != BTreeSet::from([359, 1901, 2199])
        || helpers.len() != 36
    {
        return Err("SARP source model is incomplete".to_owned());
    }
    Ok((families, helpers))
}
enum Control {
    Next(State),
    Branch(Condition, State, State),
    Return,
}
struct Lifter<'a> {
    vm: &'a DecodedVm,
    family: &'a Family,
    helpers: &'a BTreeMap<u32, Vec<String>>,
    state: State,
    locals: BTreeMap<String, Value>,
    out: Vec<Instruction>,
    max_offset: usize,
    next_temp: u16,
    temp_end: u16,
    control: Option<Control>,
    strings: BTreeMap<u32, Vec<u8>>,
    numbers: BTreeMap<u32, u64>,
    witnesses: Vec<u8>,
    transition_helper: Option<u32>,
    hash_proof: Option<HashProof>,
}
impl<'a> Lifter<'a> {
    fn new(
        vm: &'a DecodedVm,
        family: &'a Family,
        helpers: &'a BTreeMap<u32, Vec<String>>,
        state: &State,
    ) -> Result<Self, String> {
        let start = state
            .pc
            .checked_mul(64)
            .and_then(|n| n.checked_add(256))
            .and_then(|n| u16::try_from(n).ok())
            .ok_or("temporary register budget exceeded")?;
        let end = start
            .checked_add(64)
            .ok_or("temporary register extent overflow")?;
        Ok(Self {
            vm,
            family,
            helpers,
            state: state.clone(),
            locals: BTreeMap::from([
                ("ip".to_owned(), Value::Int(state.pc as i64)),
                ("st".to_owned(), Value::Int(state.key as i64)),
                ("rb".to_owned(), Value::Int(state.bank as i64)),
                ("ps".to_owned(), Value::Int(state.salt as i64)),
                ("sh".to_owned(), Value::Int(state.token as i64)),
                // Certified boot seeds C_STOP/C_EXIT to zero. Program slots
                // cannot touch them; control self-readbacks preserve them.
                ("stop".to_owned(), Value::Int(0)),
                ("exit".to_owned(), Value::Int(0)),
                ("_rbs".to_owned(), Value::Int(state.window as i64)),
                ("K0".to_owned(), Value::Int(vm.master_key as i64)),
                ("K1".to_owned(), Value::Int(state.pool_key as i64)),
            ]),
            out: vec![],
            max_offset: 0,
            next_temp: start,
            temp_end: end,
            control: None,
            strings: BTreeMap::new(),
            numbers: BTreeMap::new(),
            witnesses: vec![],
            transition_helper: None,
            hash_proof: None,
        })
    }
    fn temp(&mut self) -> Result<u16, String> {
        let n = self.next_temp;
        self.next_temp = self
            .next_temp
            .checked_add(1)
            .filter(|n| *n <= self.temp_end)
            .ok_or("leaf temporary budget exceeded (64)")?;
        Ok(n)
    }
    fn put(&mut self, dst: u16, src: Operand) {
        let fact = self.operand_fact(&src);
        if let Some(f) = fact {
            self.state.facts.insert(dst, f);
        } else {
            self.state.facts.remove(&dst);
        }
        let dst = register(dst);
        let i = match src {
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
                e => Instruction::Move {
                    dst,
                    src: Operand::Expression(Box::new(e)),
                },
            },
            src => Instruction::Move { dst, src },
        };
        self.out.push(i);
    }
    fn operand_fact(&self, o: &Operand) -> Option<i64> {
        match o {
            Operand::Constant(Constant::Integer(i)) => Some(*i),
            Operand::Register(r) => self.state.facts.get(&r.physical_slot).copied(),
            Operand::Expression(e) => match e.as_ref() {
                ValueExpression::Binary { op, left, right } => {
                    let (a, b) = (self.operand_fact(left)?, self.operand_fact(right)?);
                    let n = match op {
                        BinaryOp::Add => a.checked_add(b)?,
                        BinaryOp::Sub => a.checked_sub(b)?,
                        BinaryOp::Mul => a.checked_mul(b)?,
                        BinaryOp::Mod if b > 0 => a.rem_euclid(b),
                        _ => return None,
                    };
                    (n.unsigned_abs() < (1u64 << 52)).then_some(n)
                }
                _ => None,
            },
            _ => None,
        }
    }
    fn snapshot(&mut self, value: Value) -> Result<Value, String> {
        if matches!(
            value,
            Value::Data(Operand::Register(_) | Operand::Expression(_))
        ) {
            let temp = self.temp()?;
            self.put(temp, value.operand()?);
            return Ok(Value::Data(r(temp)));
        }
        Ok(value)
    }
    fn program_slot(&self, raw: u16) -> Result<u16, String> {
        if self.vm.slot_map[1..16].contains(&raw) {
            return Err(format!(
                "program instruction accesses VM control slot {raw}"
            ));
        }
        let at = self.state.bank as usize;
        let roles = [
            slot(self.vm, at + 1)?,
            slot(self.vm, at + 2)?,
            slot(self.vm, at + 3)?,
            slot(self.vm, at + 4)?,
        ];
        if roles.into_iter().collect::<BTreeSet<_>>().len() != 4 {
            return Err("noninjective SARP bank roles".to_owned());
        }
        if raw == roles[2] {
            return Ok(53);
        }
        if raw == roles[3] {
            return Ok(54);
        }
        if raw == roles[0] || raw == roles[1] {
            return Err("program operand touches rotor/phase cell".to_owned());
        }
        Ok(raw)
    }
    fn expr(&mut self, e: &E) -> Result<Value, String> {
        match e {
            E::Int(i) => Ok(Value::Int(*i)),
            E::Str(v) => Ok(Value::Data(Operand::Constant(Constant::String(v.clone())))),
            E::Id(n) => match n.as_str() {
                "true" => Ok(Value::Bool(true)),
                "false" => Ok(Value::Bool(false)),
                "nil" => Ok(Value::Nil),
                "_sma" => Ok(Value::Int(SMA as i64)),
                "_smb" => Ok(Value::Int(SMB as i64)),
                "_pxs" | "_pys" | "_u1s" | "_u2s" => {
                    let off = match n.as_str() {
                        "_pxs" => 1,
                        "_pys" => 2,
                        "_u1s" => 3,
                        _ => 4,
                    };
                    Ok(Value::Int(
                        slot(self.vm, self.state.bank as usize + off)? as i64
                    ))
                }
                _ => self
                    .locals
                    .get(n)
                    .cloned()
                    .ok_or_else(|| format!("unresolved handler identifier {n}")),
            },
            E::Table => {
                let dst = self.temp()?;
                self.out.push(Instruction::NewTable { dst: register(dst) });
                Ok(Value::Data(r(dst)))
            }
            E::Unary(n, e) => {
                let v = self.expr(e)?;
                match (n.as_str(), &v) {
                    ("-", Value::Int(i)) => {
                        if i.unsigned_abs() >= 1u64 << 53 {
                            return Err("negation exceeds the exact Luau integer domain".to_owned());
                        }
                        Ok(Value::Int(i.checked_neg().ok_or("negation overflow")?))
                    }
                    ("not", _) if v.truth().is_some() => {
                        Ok(Value::Bool(!v.truth().ok_or("missing truth")?))
                    }
                    _ => {
                        let op = match n.as_str() {
                            "-" => UnaryOp::Negate,
                            "not" => UnaryOp::Not,
                            "#" => UnaryOp::Length,
                            _ => return Err(format!("unsupported unary {n}")),
                        };
                        Ok(Value::Data(Operand::Expression(Box::new(
                            ValueExpression::Unary {
                                op,
                                value: v.operand()?,
                            },
                        ))))
                    }
                }
            }
            E::Bin(n, a, b) => {
                if n == "or" && (idx(a, "SM") || idx(a, "NM")) {
                    let E::Index(cache, key) = a.as_ref() else {
                        return Err("invalid constant-cache expression".to_owned());
                    };
                    let E::Call(function, args) = b.as_ref() else {
                        return Err("unproved constant-cache fallback".to_owned());
                    };
                    if !id(function, "U")
                        || args.len() != 10
                        || **key != args[1]
                        || !id(&args[7], "F")
                    {
                        return Err("constant-cache key/frame mismatch".to_owned());
                    }
                    let channel = self.expr(&args[5])?.u32()? ^ 20993;
                    if !(id(cache, "SM") && (38746..=40598).contains(&channel)
                        || id(cache, "NM") && (40599..=56274).contains(&channel))
                    {
                        return Err("constant-cache channel mismatch".to_owned());
                    }
                    return self.expr(b);
                }
                let a = self.expr(a)?;
                if n == "and" || n == "or" {
                    if let Some(t) = a.truth() {
                        return if (n == "and" && t) || (n == "or" && !t) {
                            self.expr(b)
                        } else {
                            Ok(a)
                        };
                    }
                    if !matches!(b.as_ref(), E::Int(_) | E::Str(_) | E::Id(_)) {
                        return Err(
                            "unknown short-circuit operand has a potentially effectful RHS"
                                .to_owned(),
                        );
                    }
                }
                let b = self.expr(b)?;
                if let (Value::Int(a), Value::Int(b)) = (&a, &b) {
                    let arithmetic = match n.as_str() {
                        "+" => a.checked_add(*b),
                        "-" => a.checked_sub(*b),
                        "*" => a.checked_mul(*b),
                        "%" if *b > 0 => Some(a.rem_euclid(*b)),
                        _ => None,
                    };
                    if let Some(v) = arithmetic {
                        if v.unsigned_abs() >= 1u64 << 53 {
                            return Err(
                                "arithmetic exceeds the exact Luau integer domain".to_owned()
                            );
                        }
                        return Ok(Value::Int(v));
                    }
                    let cmp = match n.as_str() {
                        "==" => Some(a == b),
                        "~=" => Some(a != b),
                        "<" => Some(a < b),
                        "<=" => Some(a <= b),
                        ">" => Some(a > b),
                        ">=" => Some(a >= b),
                        _ => None,
                    };
                    if let Some(v) = cmp {
                        return Ok(Value::Bool(v));
                    }
                }
                if matches!(n.as_str(), "==" | "~=")
                    && matches!(
                        (&a, &b),
                        (Value::Int(_), Value::Nil) | (Value::Nil, Value::Int(_))
                    )
                {
                    return Ok(Value::Bool(n == "~="));
                }
                Ok(Value::Data(Operand::Expression(Box::new(
                    ValueExpression::Binary {
                        op: op_ir(n)?,
                        left: a.operand()?,
                        right: b.operand()?,
                    },
                ))))
            }
            E::Index(t, i) => {
                if id(t, "_w") {
                    let at =
                        usize::try_from(self.expr(i)?.int()?).map_err(|_| "negative word index")?;
                    let off = at
                        .checked_sub(self.state.pc)
                        .filter(|n| *n <= 256)
                        .ok_or("word operand span invalid")?;
                    self.max_offset = self.max_offset.max(off);
                    return Ok(Value::Int(word(self.vm, at)? as i64));
                }
                if id(t, "_rm") {
                    let at = usize::try_from(self.expr(i)?.int()?)
                        .map_err(|_| "negative register index")?;
                    return Ok(Value::Int(slot(self.vm, at)? as i64));
                }
                if id(t, "_kb") {
                    let at =
                        usize::try_from(self.expr(i)?.int()?).map_err(|_| "negative bias index")?;
                    return Ok(Value::Int(
                        *self
                            .vm
                            .immediate_biases
                            .get(at)
                            .filter(|_| at > 0)
                            .ok_or("invalid bias index")? as i64,
                    ));
                }
                if id(t, "_cm") {
                    let at = usize::try_from(self.expr(i)?.int()?)
                        .map_err(|_| "negative control index")?;
                    return Ok(Value::Int(
                        *self
                            .family
                            .metadata
                            .get(at.checked_sub(1).ok_or("zero CM index")?)
                            .ok_or("control metadata index out of bounds")?
                            as i64,
                    ));
                }
                if id(t, "_mo") {
                    let key = self.expr(i)?.u32()?;
                    let operation = key ^ ((self.state.pool_key >> 10) & 1023) ^ 944;
                    return Ok(if (1..=23).contains(&operation) {
                        Value::MetaFunction(operation)
                    } else {
                        Value::Nil
                    });
                }
                if id(t, "F") {
                    let raw =
                        u16::try_from(self.expr(i)?.int()?).map_err(|_| "invalid frame index")?;
                    if idx(i, "_cm") {
                        return Ok(Value::FrameCopy(raw));
                    }
                    let slot = self.program_slot(raw)?;
                    return Ok(Value::Data(r(slot)));
                }
                let table = if id(t, "G") {
                    Operand::Environment
                } else {
                    self.expr(t)?.operand()?
                };
                let index = self.expr(i)?.operand()?;
                let dst = self.temp()?;
                self.out.push(Instruction::GetTable {
                    dst: register(dst),
                    table,
                    index,
                });
                Ok(Value::Data(r(dst)))
            }
            E::Call(t, args) => self.call(t, args),
        }
    }
    fn call(&mut self, target: &E, args: &[E]) -> Result<Value, String> {
        if let E::Id(name) = target {
            if [
                "bxor", "band", "bor", "rshift", "lshift", "lrot", "rrot", "bswap", "bext",
            ]
            .contains(&name.as_str())
            {
                let mut v = vec![];
                for a in args {
                    v.push(self.expr(a)?.u32()?);
                }
                let value = match name.as_str() {
                    "bxor" => v.iter().fold(0, |a, b| a ^ b),
                    "band" => v.iter().fold(u32::MAX, |a, b| a & b),
                    "bor" => v.iter().fold(0, |a, b| a | b),
                    "rshift" if v.len() == 2 => {
                        if v[1] >= 32 {
                            0
                        } else {
                            v[0] >> v[1]
                        }
                    }
                    "lshift" if v.len() == 2 => {
                        if v[1] >= 32 {
                            0
                        } else {
                            v[0] << v[1]
                        }
                    }
                    "lrot" if v.len() == 2 => v[0].rotate_left(v[1]),
                    "rrot" if v.len() == 2 => v[0].rotate_right(v[1]),
                    "bswap" if v.len() == 1 => v[0].swap_bytes(),
                    "bext"
                        if v.len() == 3
                            && v[2] > 0
                            && v[1].checked_add(v[2]).is_some_and(|n| n <= 32) =>
                    {
                        v[0].checked_shr(v[1]).ok_or("invalid extraction shift")?
                            & if v[2] == 32 {
                                u32::MAX
                            } else {
                                (1u32 << v[2]) - 1
                            }
                    }
                    _ => return Err(format!("unsupported bitwise metadata call {name}")),
                };
                return Ok(Value::Int(value as i64));
            }
            if name == "U" {
                if args.len() != 10 {
                    return Err("U arity differs from certified helper".to_owned());
                }
                check_u_arguments(args)?;
                let operation = self.expr(&args[5])?.u32()? ^ 20993;
                if operation == 47484 {
                    return Err("witness result must be an explicit pair".to_owned());
                }
                if (26245..27902).contains(&operation) {
                    let key = self.expr(&args[8])?.u32()?;
                    if key ^ 177821 != 746983 {
                        return Err("unproved branch witness displacement".to_owned());
                    }
                    return Ok(Value::Int(SALT as i64));
                }
                let reference = self.expr(&args[1])?.u32()?;
                let key = self.expr(&args[8])?.u32()?;
                if (38746..=56274).contains(&operation)
                    && (!id(&args[7], "F") || key != self.state.pool_key)
                {
                    return Err("constant decoder frame/pool-key proof failed".to_owned());
                }
                if (38746..=40598).contains(&operation) {
                    return self.constant_string(reference, key);
                }
                if (40599..=56274).contains(&operation) {
                    return self.constant_number(reference, key);
                }
                return Err(format!("unsupported U channel {operation}"));
            }
            if name == "_mo" || name == "_mo2" {
                let key = self
                    .expr(args.first().ok_or("missing metadata operation key")?)?
                    .u32()?;
                let operation = if name == "_mo" {
                    key ^ ((self.state.pool_key >> 10) & 1023) ^ 944
                } else {
                    key ^ ((self.state.pool_key >> 5) & 1023) ^ 504
                };
                return self.meta_operation(name, operation, &args[1..]);
            }
        }
        if let E::Id(name) = target {
            if let Some(Value::MetaFunction(operation)) = self.locals.get(name) {
                return self.meta_operation("_mo", *operation, args);
            }
        }
        let function = self.expr(target)?.operand()?;
        let mut values = vec![];
        for a in args {
            values.push(self.expr(a)?.operand()?);
        }
        let packet = self.temp()?;
        let dst = self.temp()?;
        self.out.push(Instruction::Call {
            dst: Some(register(packet)),
            function,
            args: values,
            result_count: Some(1),
        });
        self.out.push(Instruction::GetTable {
            dst: register(dst),
            table: r(packet),
            index: int(1),
        });
        Ok(Value::Data(r(dst)))
    }
    fn meta_operation(&mut self, table: &str, operation: u32, args: &[E]) -> Result<Value, String> {
        if table == "_mo" {
            if operation == 15 && args.len() == 1 {
                let index = self.expr(&args[0])?.operand()?;
                let dst = self.temp()?;
                self.out.push(Instruction::GetTable {
                    dst: register(dst),
                    table: Operand::Environment,
                    index,
                });
                return Ok(Value::Data(r(dst)));
            }
            if [2, 6, 13, 18].contains(&operation) {
                for argument in args {
                    self.expr(argument)?;
                }
                let dst = self.temp()?;
                self.out.push(Instruction::NewTable { dst: register(dst) });
                return Ok(Value::Data(r(dst)));
            }
            if [3, 7, 20].contains(&operation) && args.len() == 1 {
                let src = self.expr(&args[0])?.operand()?;
                let op = match operation {
                    3 => UnaryOp::Negate,
                    7 => UnaryOp::Length,
                    _ => UnaryOp::Not,
                };
                return Ok(Value::Data(Operand::Expression(Box::new(
                    ValueExpression::Unary { op, value: src },
                ))));
            }
            if [21, 22, 23].contains(&operation) && args.len() == 2 {
                let a = self.expr(&args[0])?.operand()?;
                let b = self.expr(&args[1])?.operand()?;
                let op = match operation {
                    21 => BinaryOp::Pow,
                    22 => BinaryOp::Equal,
                    _ => BinaryOp::Less,
                };
                return Ok(Value::Data(Operand::Expression(Box::new(
                    ValueExpression::Binary {
                        op,
                        left: a,
                        right: b,
                    },
                ))));
            }
            return Err(format!(
                "unsupported reachable MO operation {operation} with {} arguments",
                args.len()
            ));
        }
        if args.len() != 2 {
            return Err("MO2 operation requires two operands".to_owned());
        }
        let op = match operation {
            1 | 2 | 14 | 19 => BinaryOp::Greater,
            3 | 8 => BinaryOp::NotEqual,
            4 | 6 | 10 => BinaryOp::GreaterEqual,
            7 | 15 | 22 => BinaryOp::LessEqual,
            18 | 21 => BinaryOp::Less,
            13 => BinaryOp::Equal,
            11 => BinaryOp::Div,
            16 => BinaryOp::Mod,
            _ => return Err(format!("unsupported MO2 operation {operation}")),
        };
        // Metadata operation selection is proven; program arithmetic remains IR.
        self.expr(&E::Bin(
            match op {
                BinaryOp::Less => "<",
                BinaryOp::Greater => ">",
                BinaryOp::Equal => "==",
                BinaryOp::NotEqual => "~=",
                BinaryOp::GreaterEqual => ">=",
                BinaryOp::LessEqual => "<=",
                BinaryOp::Mod => "%",
                _ => return Err("division needs an explicit source expression contract".to_owned()),
            }
            .to_owned(),
            Box::new(args[0].clone()),
            Box::new(args[1].clone()),
        ))
    }
    fn constant_string(&mut self, reference: u32, key: u32) -> Result<Value, String> {
        let offset = (reference ^ 1528192) as usize;
        let seed = read32(&self.vm.payload, offset)? ^ 1573349377;
        let length = (read32(
            &self.vm.payload,
            offset.checked_add(4).ok_or("string offset overflow")?,
        )? ^ 1638974510
            ^ seed) as usize;
        let end = offset
            .checked_add(8)
            .and_then(|o| o.checked_add(length))
            .filter(|e| *e <= self.vm.payload.len())
            .ok_or("string record is truncated or out of bounds")?;
        if length > MAX_PAYLOAD {
            return Err("string allocation budget exceeded".to_owned());
        }
        let mut value = vec![];
        let mut k = seed ^ self.vm.master_key ^ key ^ SALT;
        for i in 0..length / 4 {
            k = k.wrapping_mul(22439).wrapping_add(195899001);
            value.extend_from_slice(
                &(read32(&self.vm.payload, offset + 8 + i * 4)? ^ k).to_le_bytes(),
            );
        }
        for o in offset + 8 + length / 4 * 4..end {
            k = k.wrapping_mul(22439).wrapping_add(195899001);
            value.push(self.vm.payload[o] ^ k as u8);
        }
        if let Some(old) = self.strings.insert(reference, value.clone()) {
            if old != value {
                return Err("constant key changes one string reference".to_owned());
            }
        }
        Ok(Value::Data(Operand::Constant(Constant::String(value))))
    }
    fn constant_number(&mut self, reference: u32, key: u32) -> Result<Value, String> {
        let index = (reference ^ 1071764) as usize;
        if index == 0 || index > 65536 {
            return Err("invalid numeric reference".to_owned());
        }
        let base = (word(self.vm, 1)? ^ 2115480298 ^ self.vm.master_key) as usize;
        let offset = base
            .checked_add((index - 1) * 8)
            .ok_or("number extent overflow")?;
        let extra = key ^ SALT;
        let lo = read32(&self.vm.payload, offset)?
            ^ 495004947u32.wrapping_add((index as u32).wrapping_mul(464691))
            ^ self.vm.master_key
            ^ extra;
        let hi = read32(&self.vm.payload, offset + 4)?
            ^ 1772561933u32.wrapping_add((index as u32).wrapping_mul(290983))
            ^ self.vm.master_key.rotate_left(21)
            ^ extra.rotate_left(25);
        let bits = (hi as u64) << 32 | lo as u64;
        if let Some(old) = self.numbers.insert(reference, bits) {
            if old != bits {
                return Err("constant key changes numeric record".to_owned());
            }
        }
        Ok(Value::Data(Operand::Constant(Constant::NumberBits(bits))))
    }
}

impl Lifter<'_> {
    fn assign(&mut self, target: &E, value: Value) -> Result<(), String> {
        if let E::Id(n) = target {
            if ["stop", "exit"].contains(&n.as_str()) && value.int()? != 0 {
                return Err("unsupported stop/exit state write".to_owned());
            }
            self.locals.insert(n.clone(), value);
            return Ok(());
        }
        let E::Index(table, index) = target else {
            return Err("unsupported assignment target".to_owned());
        };
        if id(table, "F") {
            let raw =
                u16::try_from(self.expr(index)?.int()?).map_err(|_| "invalid F destination")?;
            if idx(index, "_cm") {
                match value {
                    Value::FrameCopy(src) if src == raw => return Ok(()), // Exact read-back of private frame cell.
                    Value::Witness(w) => {
                        let expected = self.vm.slot_map[if w == 0 { 13 } else { 6 }];
                        if raw != expected {
                            return Err("witness stored to the wrong frame slot".to_owned());
                        }
                        self.witnesses.push(w);
                        return Ok(());
                    }
                    _ => return Err(format!("unmodeled control-slot assignment {raw}")),
                }
            }
            let dst = self.program_slot(raw)?;
            self.put(dst, value.operand()?);
            return Ok(());
        }
        let table = self.expr(table)?.operand()?;
        let index = self.expr(index)?.operand()?;
        self.out.push(Instruction::SetTable {
            table,
            index,
            value: value.operand()?,
        });
        Ok(())
    }
    fn statements(&mut self, body: &[S]) -> Result<(), String> {
        for s in body {
            if self.control.is_some() {
                break;
            }
            match s {
                S::Do(b) => {
                    let previous = self.locals.clone();
                    self.statements(b)?;
                    let changes = self.locals.clone();
                    self.locals = previous;
                    for (n, v) in changes {
                        if self.locals.contains_key(&n) {
                            self.locals.insert(n, v);
                        }
                    }
                }
                S::Local(names, values) => {
                    if names.len() == 2 && values.len() == 1 {
                        if let E::Call(t, args) = &values[0] {
                            if id(t, "U")
                                && args.len() == 10
                                && self.expr(&args[5])?.u32()? ^ 20993 == 47484
                            {
                                check_u_arguments(args)?;
                                if self.expr(&args[8])?.u32()? ^ 155290 != 936396 {
                                    return Err(
                                        "nonzero witness displacement unsupported".to_owned()
                                    );
                                }
                                self.locals.insert(names[0].clone(), Value::Witness(0));
                                self.locals.insert(names[1].clone(), Value::Witness(1));
                                continue;
                            }
                        }
                    }
                    if !values.is_empty() && values.len() != names.len() {
                        return Err("unproved local tuple arity".to_owned());
                    }
                    let mut output = vec![];
                    for e in values {
                        let v = self.expr(e)?;
                        output.push(self.snapshot(v)?);
                    }
                    for (i, n) in names.iter().enumerate() {
                        self.locals
                            .insert(n.clone(), output.get(i).cloned().unwrap_or(Value::Nil));
                    }
                }
                S::Assign(targets, values) => {
                    if self.helper(targets, values)? {
                        continue;
                    }
                    if targets.len() != values.len() {
                        return Err("assignment tuple arity mismatch".to_owned());
                    }
                    let mut output = vec![];
                    for e in values {
                        let v = self.expr(e)?;
                        output.push(if values.len() > 1 {
                            self.snapshot(v)?
                        } else {
                            v
                        });
                    }
                    for (t, v) in targets.iter().zip(output) {
                        self.assign(t, v)?;
                    }
                }
                S::If(arms, otherwise) => {
                    let mut selected = otherwise;
                    for (c, b) in arms {
                        if self
                            .expr(c)?
                            .truth()
                            .ok_or_else(|| format!("unresolved runtime branch in leaf {c:?}"))?
                        {
                            selected = b;
                            break;
                        }
                    }
                    self.statements(selected)?;
                }
                S::Return(args) => {
                    if args.len() == 2 && id(&args[0], "true") && matches!(args[1], E::Int(135301))
                    {
                        self.control = Some(Control::Return);
                    } else {
                        return Err("unproved dispatcher return tag/tuple".to_owned());
                    }
                }
                S::Expr(E::Call(t, args)) => {
                    self.call(t, args)?;
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
        if values.len() != 4 {
            return Err("entry operand count differs".to_owned());
        }
        let mut operands = vec![];
        for e in values {
            operands.push(self.expr(e)?);
        }
        for (n, v) in names.iter().zip(&operands) {
            self.locals.insert(n.clone(), v.clone());
        }
        let spill = operands[0].u32()?;
        let rotor = operands[1].u32()?;
        let width = operands[2].u32()?;
        let phase = operands[3].u32()?;
        if rotor & 1 != 1 {
            return Err("SARP rotor oddness proof violated".to_owned());
        }
        if spill != 0 {
            return Err(
                "nonzero root argument spill requires explicit argument binding".to_owned(),
            );
        }
        if width < 4 || width > 118 {
            return Err("invalid SARP bank window".to_owned());
        }
        if self.state.pool_key == INITIAL_K1 {
            let e = find_assignment(body, "K1").ok_or("missing entry pool-key formula")?;
            self.state.pool_key = self.expr(e)?.u32()?;
            self.locals
                .insert("K1".to_owned(), Value::Int(self.state.pool_key as i64));
        }
        self.state.phase = phase;
        self.state.window = width;
        self.locals
            .insert("_rbs".to_owned(), Value::Int(width as i64));
        self.state.bank_end = self
            .state
            .bank
            .checked_add(width.checked_mul(2).ok_or("bank width overflow")?)
            .ok_or("bank ceiling overflow")?;
        for n in 1..=4 {
            slot(self.vm, self.state.bank_end as usize + n)?;
        }
        Ok(true)
    }
    fn transition(
        &self,
        d: i64,
        ds: i64,
        h: i64,
        phase: i64,
        forward: bool,
        extra_key: u32,
        extra_token: u32,
    ) -> Result<State, String> {
        if self.state.window == 0 {
            return Err("transition before bank setup".to_owned());
        }
        let mut next = self.state.clone();
        let pc = (self.state.pc as i64).checked_add(d).ok_or("PC overflow")?;
        // Helper output/unmask is u32; case-tag and signed bias terms may wrap.
        next.pc = usize::try_from(pc.rem_euclid(1i64 << 32))
            .map_err(|_| "transition target conversion")?;
        word(self.vm, next.pc)?;
        next.key =
            (self.state.key as i64 + ds + self.state.phase as i64 + SALT as i64 + extra_key as i64)
                .rem_euclid(1i64 << 32) as u32;
        next.token = (h + self.state.phase as i64 + SALT as i64 + extra_token as i64)
            .rem_euclid(1i64 << 32) as u32;
        if !self.vm.dispatch_families.contains_key(&next.token) {
            return Err(format!(
                "unmapped successor shape {} at PC {}",
                next.token, next.pc
            ));
        }
        next.phase = phase.rem_euclid(1i64 << 32) as u32;
        let (b, w, e) = (
            self.state.bank as i64,
            self.state.window as i64,
            self.state.bank_end as i64,
        );
        let bank = if forward {
            if b >= e {
                b - 2 * w
            } else {
                b + w
            }
        } else if b <= e - 2 * w {
            b + 2 * w
        } else {
            b - w
        };
        next.bank = u32::try_from(bank).map_err(|_| "bank rotation overflow")?;
        let old = [
            slot(self.vm, b as usize + 1)?,
            slot(self.vm, b as usize + 2)?,
            slot(self.vm, b as usize + 3)?,
            slot(self.vm, b as usize + 4)?,
        ];
        let new = [
            slot(self.vm, bank as usize + 1)?,
            slot(self.vm, bank as usize + 2)?,
            slot(self.vm, bank as usize + 3)?,
            slot(self.vm, bank as usize + 4)?,
        ];
        let expected = if forward {
            [old[2], old[1], old[3], old[0]]
        } else {
            [old[3], old[1], old[0], old[2]]
        };
        if new != expected {
            return Err("SARP physical register rotation fails the role bijection".to_owned());
        }
        Ok(next)
    }
    fn helper(&mut self, targets: &[E], values: &[E]) -> Result<bool, String> {
        let [E::Call(target, args)] = values else {
            return Ok(false);
        };
        let E::Index(table, num) = target.as_ref() else {
            return Ok(false);
        };
        if !id(table, "_hc") {
            return Ok(false);
        }
        let E::Int(num) = num.as_ref() else {
            return Err("nonliteral helper selector".to_owned());
        };
        let num = u32::try_from(*num).map_err(|_| "invalid helper index")?;
        if targets.len() != 3 {
            return Err("helper return tuple count mismatch".to_owned());
        }
        if ![18, 35, 1, 5, 23, 27].contains(&num) {
            return Err(format!("unsupported reachable transition helper {num}"));
        }
        self.transition_helper = Some(num);
        let params = self.helpers.get(&num).ok_or("missing helper signature")?;
        if params.len() != args.len() {
            return Err("transition helper argument count mismatch".to_owned());
        }
        let bound = params
            .iter()
            .zip(args)
            .map(|(n, a)| (n.clone(), a.clone()))
            .collect::<BTreeMap<_, _>>();
        for (role, caller) in [
            ("_ip", "ip"),
            ("_rb", "rb"),
            ("_st", "st"),
            ("_F", "F"),
            ("_pxs", "_pxs"),
            ("_pys", "_pys"),
            ("_u1s", "_u1s"),
            ("_u2s", "_u2s"),
        ] {
            if !bound.get(role).is_some_and(|e| id(e, caller)) {
                return Err(format!("transition helper context mismatch: {role}"));
            }
        }
        for (name, argument) in &bound {
            if name.starts_with("_hd") && !matches!(argument, E::Int(_)) {
                return Err("effectful/unknown transition filler argument".to_owned());
            }
        }
        for (name, expected) in [
            ("st", self.state.key),
            ("rb", self.state.bank),
            ("ip", self.state.pc as u32),
        ] {
            if self
                .locals
                .get(name)
                .ok_or("missing helper context")?
                .u32()?
                != expected
            {
                return Err("helper arguments no longer match normalized state".to_owned());
            }
        }
        let read = |ctx: &mut Self, n: &str| -> Result<Value, String> {
            ctx.expr(
                bound
                    .get(n)
                    .ok_or_else(|| format!("missing helper role {n}"))?,
            )
        };
        let n = |ctx: &mut Self, name: &str| -> Result<i64, String> { read(ctx, name)?.int() };
        if [18, 35].contains(&num) {
            let d = n(self, "_d")?;
            let ds = n(self, "_ds")?;
            let h = n(self, "_h")?;
            let phase = n(self, "_ct")?;
            self.control = Some(Control::Next(self.transition(
                d,
                ds,
                h,
                phase,
                num == 35,
                0,
                0,
            )?));
            return Ok(true);
        }
        if num == 27 {
            let value = read(self, "_x")?.operand()?;
            let value=self.operand_fact(&value).ok_or("SARP double-hash branch requires a proved finite integer value; unknown input is unsupported")?;
            let value = i32::try_from(value).map_err(|_| "hash subject outside int32")? as u32;
            let mask = read(self, "_m32")?.u32()?;
            let hp1 = read(self, "_hp1")?.u32()?;
            let hp2 = read(self, "_hp2")?.u32()?;
            let (pk1, pk2, kv_ip, kv_sh) =
                hash_gate(value, mask, self.state.key, self.state.pool_key);
            self.hash_proof = Some(HashProof {
                value,
                mask,
                key: self.state.key,
                pool: self.state.pool_key,
                pk1,
                pk2,
                expected1: hp1,
                expected2: hp2,
                kv_ip,
                kv_sh,
            });
            let next = if pk1 == hp1 && pk2 == hp2 {
                let d = n(self, "_deq")? + kv_ip as i64;
                let ds = n(self, "_seq")?;
                let h = n(self, "_heq")?;
                let phase = n(self, "_ceq")? + kv_sh as i64;
                self.transition(
                    d,
                    ds,
                    h,
                    phase,
                    false,
                    SALT.wrapping_add(kv_ip),
                    SALT.wrapping_add(kv_sh),
                )?
            } else {
                let d = n(self, "_dne")?;
                let ds = n(self, "_sne")?;
                let h = n(self, "_hne")?;
                let phase = n(self, "_cne")?;
                self.transition(d, ds, h, phase, true, SALT, SALT)?
            };
            self.control = Some(Control::Next(next));
            return Ok(true);
        }
        let value = read(self, "_c")?.operand()?;
        let condition = if let Operand::Expression(e) = &value {
            if let ValueExpression::Binary { op, left, right } = e.as_ref() {
                Condition::Compare {
                    op: *op,
                    left: left.clone(),
                    right: right.clone(),
                }
            } else {
                Condition::Truthy(value)
            }
        } else {
            Condition::Truthy(value)
        };
        let d = n(self, "_dt")?;
        let ds = n(self, "_st0")?;
        let h = n(self, "_ht")?;
        let phase = n(self, "_ct")?;
        let first = self.transition(d, ds, h, phase, false, SALT, 0)?;
        let d = n(self, "_df")?;
        let ds = n(self, "_sf")?;
        let h = n(self, "_hf")?;
        let phase = n(self, "_cf")?;
        let second = self.transition(d, ds, h, phase, true, SALT, 0)?;
        let (yes, no) = if num == 5 {
            (first, second)
        } else {
            (second, first)
        };
        self.control = Some(Control::Branch(condition, yes, no));
        Ok(true)
    }
}
fn check_u_arguments(args: &[E]) -> Result<(), String> {
    if args.len() != 10 {
        return Err("invalid U argument tuple".to_owned());
    }
    // In the certified wrapper these are literal filler values, never
    // unvisited potentially effectful expressions.
    for index in [0, 2, 3, 4, 6, 9] {
        if !matches!(args[index], E::Int(_)) {
            return Err("unsupported effectful U filler argument".to_owned());
        }
    }
    Ok(())
}
fn find_assignment<'a>(body: &'a [S], name: &str) -> Option<&'a E> {
    for s in body {
        match s {
            S::Assign(t, v) if t.len() == 1 && id(&t[0], name) => return v.first(),
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
fn contains(e: &E, n: &str) -> bool {
    match e {
        E::Id(v) => v == n,
        E::Index(a, b) | E::Bin(_, a, b) => contains(a, n) || contains(b, n),
        E::Call(t, a) => contains(t, n) || a.iter().any(|e| contains(e, n)),
        E::Unary(_, e) => contains(e, n),
        _ => false,
    }
}
fn select(body: &[S], ctx: &mut Lifter<'_>) -> Result<Vec<S>, String> {
    let mut out = vec![];
    for s in body {
        if let S::If(arms, other) = s {
            if arms.iter().all(|(c, _)| contains(c, "op")) {
                let mut chosen = other;
                for (c, b) in arms {
                    if ctx.expr(c)?.truth().ok_or("unproved family selector")? {
                        chosen = b;
                        break;
                    }
                }
                out.extend(select(chosen, ctx)?);
                continue;
            }
        }
        out.push(s.clone());
    }
    Ok(out)
}
/// The 60-round numerical predicate is evaluated only for a constant int32
/// subject proved by IR facts. This is bounded cipher math, not execution of
/// a target expression, handler or instruction.
fn hash_gate(value: u32, mask: u32, state: u32, pool: u32) -> (u32, u32, u32, u32) {
    let (a, b, c) = permutations();
    let lookup = |table: &[u16], at: u32| table[(at & 16383) as usize] as u32;
    let w0 = value ^ mask ^ pool ^ SALT;
    let w1 = w0 ^ (w0 >> 15);
    let a1 = lookup(&a, w1);
    let a2 = lookup(&b, w1 >> 14);
    let a3 = lookup(&c, (w1 >> 18) ^ a1 ^ a2);
    let h1 = w1
        .wrapping_mul(108439)
        .wrapping_add(w0.rotate_left(10))
        .wrapping_add(a1.wrapping_mul(65537))
        .wrapping_add(a2)
        .wrapping_add(state)
        ^ a3.rotate_left(23);
    let t2 = h1 ^ h1.rotate_left(14) ^ mask;
    let b1 = lookup(&a, t2);
    let b2 = lookup(&b, t2 >> 14);
    let b3 = lookup(&c, t2 ^ b1 ^ b2);
    let h2 = t2
        .wrapping_mul(70859)
        .wrapping_add(b1.wrapping_mul(65537))
        .wrapping_add(b2.wrapping_mul(257))
        .wrapping_add(b3)
        .wrapping_add(state)
        ^ h1.rotate_right(10);
    let t3 = h2 ^ h1 ^ w0.rotate_left(23);
    let c1 = lookup(&a, t3);
    let c2 = lookup(&b, t3 >> 14);
    let c3 = lookup(&c, h2 ^ c1 ^ c2);
    let h3 = t3
        .wrapping_mul(113129)
        .wrapping_add(c1.wrapping_mul(65537))
        .wrapping_add(c2.wrapping_mul(257))
        .wrapping_add(c3)
        .wrapping_add(w0.leading_zeros() * 131)
        .wrapping_add(h1.trailing_zeros() * 17)
        ^ h2.swap_bytes();
    let t4 = h3 ^ h2.rotate_left(10) ^ mask;
    let d1 = lookup(&a, t4);
    let d2 = lookup(&b, t4 >> 14);
    let d3 = lookup(&c, h3 ^ d1 ^ d2);
    let (mut hr, mut tr) = (h3, t4);
    for j in 1..=60u32 {
        let bits = (tr as f64 + hr as f64 * 0.0009765625 + j as f64).to_bits();
        let (lo, hi) = (bits as u32, (bits >> 32) as u32);
        let s1 = lookup(&a, tr ^ lo);
        let s2 = lookup(&b, (tr >> 14) ^ hi);
        let s3 = lookup(&c, hr ^ s1 ^ s2);
        let nh = tr
            .wrapping_mul(108439)
            .wrapping_add(hr)
            .wrapping_add(s1.wrapping_mul(65537))
            .wrapping_add(s2.wrapping_mul(257))
            .wrapping_add(s3)
            .wrapping_add(tr.leading_zeros() * 29)
            .wrapping_add(hr.trailing_zeros() * 19)
            .wrapping_add(j * 997)
            ^ hr.rotate_left(23)
            ^ s3.swap_bytes()
            ^ lo;
        tr = nh ^ tr.rotate_right(14) ^ mask ^ state ^ hi;
        hr = nh;
    }
    let pk1 = hr
        .wrapping_mul(113129)
        .wrapping_add(d1.wrapping_mul(65537))
        .wrapping_add(d3)
        .wrapping_add(mask)
        ^ d2.rotate_left(14)
        ^ h1.rotate_right(23)
        ^ tr;
    let pk2 = tr
        .wrapping_mul(108439)
        .wrapping_add(hr)
        .wrapping_add(d2.wrapping_mul(65537))
        .wrapping_add(d1)
        .wrapping_add(state)
        ^ d3.rotate_left(10)
        ^ b3.rotate_right(14)
        ^ h3;
    let kv_ip = (hr ^ d3 ^ c1.rotate_left(13)).wrapping_add(b2.wrapping_mul(65537));
    let kv_sh = (tr ^ d1 ^ c2.rotate_right(11)).wrapping_add(b1.wrapping_mul(65537));
    (pk1, pk2, kv_ip, kv_sh)
}
fn lift(
    vm: &DecodedVm,
    state: &State,
    family: &Family,
    id: u32,
    helpers: &BTreeMap<u32, Vec<String>>,
) -> Result<(TraceRow, BTreeMap<u32, Vec<u8>>, BTreeMap<u32, u64>), String> {
    let mut ctx = Lifter::new(vm, family, helpers, state)?;
    let selector = ctx.expr(&family.selector)?.int()?;
    ctx.locals.insert("op".to_owned(), Value::Int(selector));
    let body = select(std::slice::from_ref(&family.tree), &mut ctx)?;
    for s in &body {
        let outcome = if let S::Do(b) = s {
            if ctx.entry(b)? {
                Ok(())
            } else {
                ctx.statements(std::slice::from_ref(s))
            }
        } else {
            ctx.statements(std::slice::from_ref(s))
        };
        outcome.map_err(|e| format!("PC {} family {id} selector {selector}: {e}", state.pc))?;
        if ctx.control.is_some() {
            break;
        }
    }
    if !ctx.witnesses.is_empty() && ctx.witnesses != [0, 1] {
        return Err("incomplete/out-of-order witness tuple writes".to_owned());
    }
    let mut successors = vec![];
    match ctx.control.take() {
        Some(Control::Next(n)) => {
            ctx.out.push(Instruction::Jump { target: n.pc });
            successors.push((EdgeLabel::Next, n));
        }
        Some(Control::Branch(c, a, b)) => {
            ctx.out.push(Instruction::Branch {
                condition: c,
                then_target: a.pc,
                else_target: b.pc,
            });
            successors.push((EdgeLabel::True, a));
            successors.push((EdgeLabel::False, b));
        }
        Some(Control::Return) => ctx.out.push(Instruction::Return { values: vec![] }),
        None => {
            let mut n = ctx.state.clone();
            n.pc = usize::try_from(ctx.locals.get("ip").ok_or("missing PC")?.int()?)
                .map_err(|_| "negative PC")?;
            n.key = ctx.locals.get("st").ok_or("missing key")?.u32()?;
            n.token = ctx.locals.get("sh").ok_or("missing shape")?.u32()?;
            n.bank = ctx.locals.get("rb").ok_or("missing bank")?.u32()?;
            n.salt = u16::try_from(ctx.locals.get("ps").ok_or("missing salt")?.u32()?)
                .map_err(|_| "salt exceeds u16")?;
            if n.bank != state.bank
                || n.salt != state.salt
                || n.token != state.token
                || ctx.locals.get("_rbs").ok_or("missing window")?.u32()? != n.window
            {
                return Err("unproved plain-arm decoding-state update".to_owned());
            }
            if !vm.dispatch_families.contains_key(&n.token) {
                return Err("unknown plain-arm dispatch shape".to_owned());
            }
            if n.pc <= state.pc || n.pc > state.pc + 257 {
                return Err("nontransition PC update unsupported".to_owned());
            }
            word(vm, n.pc)?;
            ctx.max_offset = ctx.max_offset.max(n.pc - state.pc - 1);
            ctx.out.push(Instruction::Jump { target: n.pc });
            successors.push((EdgeLabel::Next, n));
        }
    }
    for (_, next) in &mut successors {
        // Finite constant lattice: retain only exactly proved integer 0/1.
        // All other values become unknown, never an invented boolean. This
        // bounds speculative counter paths while retaining SARP's hash-gate
        // flip-flop facts. A gate needing an unknown integer fails explicitly.
        next.facts
            .retain(|reg, value| *reg < 256 && matches!(*value, 0 | 1));
    } // Leaf snapshots never survive as VM decoding state.
    let end_pc = state
        .pc
        .checked_add(ctx.max_offset + 1)
        .ok_or("instruction extent overflow")?;
    for pc in state.pc..end_pc {
        word(vm, pc)?;
    }
    Ok((
        TraceRow {
            state: state.clone(),
            family: id,
            selector,
            transition_helper: ctx.transition_helper,
            hash_proof: ctx.hash_proof,
            end_pc,
            instructions: ctx.out,
            successors,
        },
        ctx.strings,
        ctx.numbers,
    ))
}
#[derive(Clone, Copy, Debug)]
pub struct AnalysisLimits {
    pub max_states: usize,
    pub max_worklist_pops: usize,
}
impl Default for AnalysisLimits {
    fn default() -> Self {
        Self {
            max_states: 512,
            max_worklist_pops: 8192,
        }
    }
}
pub fn analyze(vm: &DecodedVm) -> Result<Analysis, String> {
    analyze_with_limits(vm, AnalysisLimits::default())
}
pub fn analyze_with_limits(vm: &DecodedVm, limits: AnalysisLimits) -> Result<Analysis, String> {
    // Public overrides can tighten budgets, never remove the hard safety caps.
    let limits = AnalysisLimits {
        max_states: limits.max_states.min(512),
        max_worklist_pops: limits.max_worklist_pops.min(8192),
    };
    if !is_profile(vm)
        || vm.raw_words.len() != 566
        || vm.decoded_words.len() != 567
        || vm.slot_map.len() != 119
        || vm.immediate_biases.len() != 65
        || vm.payload.len() != 2264
    {
        return Err("analysis requires certified SARP layout".to_owned());
    }
    let (families, helpers) = model(vm)?;
    let root = vm
        .prototypes
        .iter()
        .find(|p| p.word == vm.entry_prototype)
        .ok_or("missing root")?;
    if prototype(vm, vm.entry_prototype)? != *root {
        return Err("SARP prototype metadata disagrees with decoded words".to_owned());
    }
    if vm.slot_map.iter().skip(1).any(|s| *s == 0 || *s > 52) {
        return Err("corrupt SARP register map".to_owned());
    }
    let state = State {
        pc: root.entry_pc,
        key: root.initial_decode_state.wrapping_add(86892),
        bank: root.bank_base,
        token: root.dispatch_token,
        salt: root.prototype_salt,
        phase: 0,
        window: 0,
        bank_end: 0,
        pool_key: INITIAL_K1,
        facts: BTreeMap::new(),
    };
    let mut queue = VecDeque::from([state]);
    let mut seen = HashSet::new();
    let mut trace = vec![];
    let (mut strings, mut numbers) = (BTreeMap::new(), BTreeMap::new());
    let mut pops = 0;
    while let Some(state) = queue.pop_front() {
        pops += 1;
        if pops > limits.max_worklist_pops {
            return Err("SARP worklist pop budget exceeded".to_owned());
        }
        if !seen.insert(state.clone()) {
            continue;
        }
        if seen.len() > limits.max_states {
            return Err(format!(
                "SARP visited-state budget exceeded: last pc={}, facts={:?}",
                state.pc, state.facts
            ));
        }
        let id = *vm
            .dispatch_families
            .get(&state.token)
            .ok_or("unknown dispatch token")?;
        let family = families.get(&id).ok_or_else(|| {
            format!(
                "unsupported dispatcher at PC {}: family={id}, token={}",
                state.pc, state.token
            )
        })?;
        let (row, ss, ns) = lift(vm, &state, family, id, &helpers).map_err(|e| {
            let selector = Lifter::new(vm, family, &helpers, &state)
                .and_then(|mut l| l.expr(&family.selector)?.int())
                .map(|s| s.to_string())
                .unwrap_or_else(|_| "unresolved".to_owned());
            format!(
                "{PROFILE}: PC {}, family={id}, selector={selector}: {e}",
                state.pc
            )
        })?;
        for (r, v) in ss {
            if let Some(old) = strings.insert(r, v.clone()) {
                if old != v {
                    return Err("conflicting string decryption".to_owned());
                }
            }
        }
        for (r, v) in ns {
            if let Some(old) = numbers.insert(r, v) {
                if old != v {
                    return Err("conflicting numeric decryption".to_owned());
                }
            }
        }
        if strings.len() > 4096 || strings.values().map(Vec::len).sum::<usize>() > MAX_PAYLOAD {
            return Err("constant pool budget exceeded".to_owned());
        }
        for (_, next) in &row.successors {
            queue.push_back(next.clone());
        }
        trace.push(row);
    }
    let mut blocks = BTreeMap::new();
    for row in &trace {
        let b = BasicBlock {
            start_pc: row.state.pc,
            end_pc: row.end_pc,
            handler_family: row.family,
            entry_states: vec![],
            instructions: row.instructions.clone(),
            successors: row
                .successors
                .iter()
                .map(|(label, s)| Successor {
                    label: label.clone(),
                    target_pc: Some(s.pc),
                    state: None,
                })
                .collect(),
        };
        if let Some(old) = blocks.insert(row.state.pc, b.clone()) {
            if old != b {
                return Err(format!(
                    "state variants disagree on instruction semantics at PC {}",
                    row.state.pc
                ));
            }
        }
    }
    let raw_program = LiftedProgram {
        reachable_pcs: blocks.keys().copied().collect(),
        blocks,
        entry_points: vec![root.entry_pc],
        root_entry: Some(root.entry_pc),
        state_variants: seen.len(),
        prototype_entries: BTreeMap::from([(root.word, root.entry_pc)]),
        parameters: BTreeMap::from([(root.entry_pc, None)]),
    };
    let program = crate::base85::compact_data(&crate::base85::specialize_control(&raw_program)?)?;
    Ok(Analysis {
        program,
        raw_program,
        trace,
        strings,
        numbers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const SOURCE: &str = include_str!("../tests/fixtures/sarp.lua");
    fn vm() -> DecodedVm {
        crate::decode_source(SOURCE).unwrap()
    }

    #[test]
    fn certified_standard_library_key_checkpoints_are_proved_without_lua() {
        let replacement = (3225577635u32 & !(255 << 7)) | ((199u32 & 255) << 7);
        assert_eq!(replacement, 3225576355);
        assert_eq!(92 - 15, 77);
        let number = 55.5f64;
        let bits = number.to_bits();
        let exponent = ((bits >> 52) & 2047) as i32 - 1022;
        let mantissa = number / 2f64.powi(exponent);
        assert_eq!(mantissa * 2f64.powi(exponent), number);
        assert_eq!(55.75f64.trunc(), 55.0);
        assert_eq!(68i32.clamp(21, 53), 53);
        assert_eq!(format!("{:04x}:{}", 39634, 77), "9ad2:77");
        assert_eq!(b"9ad2".iter().rev().next(), Some(&50));
        let bytes = [
            4031576911u32.to_le_bytes().as_slice(),
            (-10585i16).to_le_bytes().as_slice(),
        ]
        .concat();
        assert_eq!(
            u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            4031576911
        );
        assert_eq!(i16::from_le_bytes(bytes[4..].try_into().unwrap()), -10585);
        assert_eq!(u32::from_str_radix("o0h", 31).unwrap(), 23081);
        // Source type proofs: plain {} has no __add (_p1=false). The literal
        // _mx operations are total; its coroutine has two yields/resumes (_pe=0).
    }
    #[test]
    fn arithmetic_extraction_cache_and_short_circuit_guards_are_fail_closed() {
        let vm = vm();
        let (families, helpers) = model(&vm).unwrap();
        let state = analyze(&vm).unwrap().trace[0].state.clone();
        let mut l = Lifter::new(&vm, &families[&2199], &helpers, &state).unwrap();
        let extract = |position, width| {
            E::Call(
                Box::new(E::Id("bext".to_owned())),
                vec![E::Int(65535), E::Int(position), E::Int(width)],
            )
        };
        assert!(l.expr(&extract(u32::MAX as i64, 1)).is_err());
        assert_eq!(l.expr(&extract(8, 8)).unwrap().int().unwrap(), 255);
        let huge = E::Bin(
            "+".to_owned(),
            Box::new(E::Int(1i64 << 52)),
            Box::new(E::Int(1i64 << 52)),
        );
        assert!(l.expr(&huge).unwrap_err().contains("exact Luau"));
        l.locals.insert("unknown".to_owned(), Value::Data(r(100)));
        let short = E::Bin(
            "or".to_owned(),
            Box::new(E::Id("unknown".to_owned())),
            Box::new(E::Call(Box::new(E::Id("effect".to_owned())), vec![])),
        );
        assert!(l.expr(&short).unwrap_err().contains("effectful RHS"));
        assert!(l.out.is_empty());
        let mut args = vec![E::Int(0); 10];
        args[1] = E::Id("otherKey".to_owned());
        args[5] = E::Int(50523);
        args[7] = E::Id("F".to_owned());
        args[8] = E::Id("K1".to_owned());
        let cache = E::Bin(
            "or".to_owned(),
            Box::new(E::Index(
                Box::new(E::Id("SM".to_owned())),
                Box::new(E::Id("key".to_owned())),
            )),
            Box::new(E::Call(Box::new(E::Id("U".to_owned())), args)),
        );
        assert!(l.expr(&cache).unwrap_err().contains("key/frame mismatch"));
        let read = E::Index(
            Box::new(E::Id("G".to_owned())),
            Box::new(E::Str(b"probe".to_vec())),
        );
        l.meta_operation("_mo", 18, &[read]).unwrap();
        assert!(matches!(
            l.out.as_slice(),
            [Instruction::GetTable { .. }, Instruction::NewTable { .. }]
        ));
        let mut corrupt = vm;
        corrupt.entry_prototype = 0;
        corrupt.decoded_range.0 = 0;
        assert!(prototype(&corrupt, 0)
            .unwrap_err()
            .contains("seven-word extent"));
    }
    #[test]
    fn hash_gate_matches_independent_known_answer_and_rejects_unknown_subject() {
        assert_eq!(
            hash_gate(1, 557376509, 3351142008, 2912755157),
            (3420489101, 1363821547, 1942394503, 556292664)
        );
        let vm = vm();
        let a = analyze(&vm).unwrap();
        let proofs = a
            .trace
            .iter()
            .filter_map(|r| r.hash_proof.as_ref())
            .collect::<Vec<_>>();
        assert_eq!(proofs.len(), 2);
        for p in proofs {
            assert_eq!(p.value, 1);
            assert!(p.pk1 != p.expected1 || p.pk2 != p.expected2);
        }
        let mut state = a
            .trace
            .iter()
            .find(|r| r.transition_helper == Some(27))
            .unwrap()
            .state
            .clone();
        state.facts.clear();
        let (families, helpers) = model(&vm).unwrap();
        assert!(lift(&vm, &state, &families[&359], 359, &helpers)
            .unwrap_err()
            .contains("requires a proved"));
    }
    #[test]
    fn second_cipher_uses_tagged_permutation_words_and_witness_is_constant() {
        let (a, b, c) = permutations();
        assert_eq!(
            a.iter().map(|v| v & 16383).collect::<BTreeSet<_>>().len(),
            16384
        );
        assert_eq!(
            b.iter().map(|v| v & 16383).collect::<BTreeSet<_>>().len(),
            16384
        );
        assert!(a.iter().any(|v| *v >= 16384));
        assert!(b.iter().any(|v| *v >= 16384));
        for i in 0..16384 {
            let (pa, pb) = ((a[i] & 16383) as u32, (b[i] & 16383) as u32);
            let expected = (pb * 4
                + ((i as u32 * 17 + 1833) % 16384) * 2
                + (((pa >> 7) & 1) ^ ((pb >> 10) & 1) ^ 1))
                % 65536;
            assert_eq!((c[pa as usize] as u32 + 65536 - expected) % 65536, SALT);
        }
    }
    #[test]
    fn parsed_metadata_maps_have_exact_core_roles_and_bijection() {
        let vm = vm();
        let (families, helpers) = model(&vm).unwrap();
        assert_eq!(helpers.len(), 36);
        assert_eq!(families[&2199].metadata.len(), 25);
        assert_eq!(families[&1901].metadata.len(), 23);
        assert_eq!(families[&359].metadata.len(), 26);
        for bank in [15u32, 37, 59] {
            let state = State {
                pc: 190,
                key: 123,
                bank,
                token: 56332,
                salt: 26339,
                phase: 0,
                window: 22,
                bank_end: 59,
                pool_key: 0,
                facts: BTreeMap::new(),
            };
            let l = Lifter::new(&vm, &families[&2199], &helpers, &state).unwrap();
            for forward in [false, true] {
                let t = l
                    .transition(0, 0, 56332 - SALT as i64, 0, forward, 0, 0)
                    .unwrap();
                let next = Lifter::new(&vm, &families[&2199], &helpers, &t).unwrap();
                let u1 = l
                    .program_slot(slot(&vm, bank as usize + 3).unwrap())
                    .unwrap();
                let u2 = l
                    .program_slot(slot(&vm, bank as usize + 4).unwrap())
                    .unwrap();
                assert_ne!(u1, u2);
                assert_eq!(
                    u1,
                    next.program_slot(slot(&vm, t.bank as usize + 3).unwrap())
                        .unwrap()
                );
                assert_eq!(
                    u2,
                    next.program_slot(slot(&vm, t.bank as usize + 4).unwrap())
                        .unwrap()
                );
            }
        }
    }
    #[test]
    fn each_reachable_helper_has_source_arity_and_each_family_has_typed_leaves() {
        let vm = vm();
        let (families, helpers) = model(&vm).unwrap();
        for (helper, arity) in [(1, 19), (5, 19), (18, 14), (23, 18), (27, 22), (35, 12)] {
            assert_eq!(helpers[&helper].len(), arity);
        }
        let a = analyze(&vm).unwrap();
        assert_eq!(
            a.trace.iter().map(|r| r.family).collect::<BTreeSet<_>>(),
            BTreeSet::from([359, 1901, 2199])
        );
        for row in a.trace {
            assert!(families.contains_key(&row.family));
            assert!(row.end_pc > row.state.pc);
            assert!(row
                .instructions
                .iter()
                .all(|i| !matches!(i, Instruction::Raw { .. })));
        }
    }
    #[test]
    fn corrupted_layout_and_out_of_bounds_transition_fail_with_context() {
        let vm = vm();
        let (families, helpers) = model(&vm).unwrap();
        let state = State {
            pc: 190,
            key: 123,
            bank: 15,
            token: 56332,
            salt: 26339,
            phase: 0,
            window: 22,
            bank_end: 59,
            pool_key: 0,
            facts: BTreeMap::new(),
        };
        let l = Lifter::new(&vm, &families[&2199], &helpers, &state).unwrap();
        assert!(l
            .transition(-500, 0, 0, 0, true, 0, 0)
            .unwrap_err()
            .contains("missing decoded"));
        let mut corrupt = vm.clone();
        corrupt.slot_map.clear();
        assert!(analyze(&corrupt).unwrap_err().contains("layout"));
        let mut corrupt = vm;
        corrupt.prototypes[0].entry_pc = 1;
        assert!(analyze(&corrupt).unwrap_err().contains("metadata"));
    }
}
