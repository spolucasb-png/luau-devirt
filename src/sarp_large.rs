//! Independently certified four-fragment large SARP adapter.
//!
//! Transport, initialization and handler analysis remain static and fail
//! closed. This module does not run protected source, recovered functions,
//! coroutines, a VM, or a Roblox client. Old SARP formulas are not reused.

mod analysis;
mod control;
mod factory;
mod initialize;
mod lift;
mod metadata;
mod model;
pub use analysis::{analyze, analyze_with_limits, Analysis, AnalysisError, AnalysisLimits};
pub use control::HashProof;
pub use lift::{Fact, FactoryRequest, State, TraceRow};

use crate::decoder::{scan_quoted, sha256_hex, tokenize, Token, TokenKind};
use crate::ir::*;
use std::collections::{BTreeMap, BTreeSet};

pub use initialize::{initialize_data, Initialization};

pub const PROFILE: &str = "sarp-four-fragment-dualstream-large-v1";
pub const WRAPPER_SHA256: &str = "7dfe43e60fb3b1d70aba68dadebf59c35b88280e436681315eb7ebab67cbd105";
pub const MAX_SOURCE: usize = 8 * 1024 * 1024;
pub const MAX_TOKENS: usize = 300_000;
pub const MAX_PAYLOAD: usize = 1024 * 1024;
pub const TRANSPORT_BYTES: usize = 568_176;
pub const FRAGMENT_LENGTHS: [usize; 4] = [177562, 177551, 177559, 177548];
pub const FRAGMENT_OFFSETS: [usize; 4] = [0, 177562, 355113, 532672];
pub const ENCODED_BYTES: usize = 710_220;
pub const SALT: u32 = 43122;
pub const INITIAL_K1: u32 = 1030971814 ^ 355957541;
pub const BOOT_TAG: u32 = 24189 + SALT;

pub(crate) fn sequence(ts: &[Token], at: usize, needle: &[&str]) -> bool {
    ts.get(at..at.saturating_add(needle.len()))
        .is_some_and(|row| {
            row.iter()
                .map(|t| t.text.as_str())
                .eq(needle.iter().copied())
        })
}

pub(crate) fn unique(ts: &[Token], needle: &[&str]) -> Result<usize, String> {
    let mut found = None;
    for at in 0..ts.len() {
        if sequence(ts, at, needle) && found.replace(at).is_some() {
            return Err(format!("{PROFILE}: ambiguous token evidence {needle:?}"));
        }
    }
    found.ok_or_else(|| format!("{PROFILE}: missing certified token evidence {needle:?}"))
}

pub(crate) fn certify(ts: &[Token]) -> Result<[usize; 4], String> {
    if ts.len() > MAX_TOKENS {
        return Err(format!("{PROFILE}: token budget exceeded"));
    }
    let mut literals = [0; 4];
    let mut masked = BTreeMap::new();
    for (index, name) in ["_pc0", "_pc1", "_pc2", "_pc3"].iter().enumerate() {
        let at = unique(ts, &["local", name, "="])?
            .checked_add(3)
            .ok_or("fragment token offset overflow")?;
        if ts.get(at).map(|t| t.kind) != Some(TokenKind::String) {
            return Err(format!("{PROFILE}: {name} is not a literal"));
        }
        literals[index] = at;
        masked.insert(at, format!("PAYLOAD:{name}"));
    }
    let normalized = ts
        .iter()
        .enumerate()
        .map(|(at, token)| masked.get(&at).map(String::as_str).unwrap_or(&token.text))
        .collect::<Vec<_>>()
        .join("\n");
    if sha256_hex(normalized.as_bytes()) != WRAPPER_SHA256 {
        return Err(format!(
            "{PROFILE}: unsupported wrapper; certified token skeleton changed"
        ));
    }
    Ok(literals)
}

pub fn certify_source(source: &str) -> Result<(), String> {
    if source.len() > MAX_SOURCE {
        return Err(format!("{PROFILE}: source budget exceeded"));
    }
    certify(&tokenize(source)?)?;
    Ok(())
}

pub fn is_profile(vm: &DecodedVm) -> bool {
    vm.profile == VmProfile::SarpLarge
}

pub fn assemble_fragments(fragments: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    if fragments.len() != 4
        || fragments
            .iter()
            .zip(FRAGMENT_LENGTHS)
            .any(|(s, n)| s.len() != n)
    {
        return Err(format!(
            "{PROFILE}: four exact fragment extents are required"
        ));
    }
    let mut output = vec![0; ENCODED_BYTES];
    let mut covered = vec![false; ENCODED_BYTES];
    // Certified buffer.copy sequence, distinct from declaration order 2,1,0,3.
    for index in [2usize, 1, 3, 0] {
        let start = FRAGMENT_OFFSETS[index];
        let end = start
            .checked_add(fragments[index].len())
            .ok_or("fragment extent overflow")?;
        let marks = covered
            .get_mut(start..end)
            .ok_or("fragment outside encoded buffer")?;
        if marks.iter().any(|b| *b) {
            return Err("overlapping fragment writes".to_owned());
        }
        marks.fill(true);
        output
            .get_mut(start..end)
            .ok_or("invalid fragment destination")?
            .copy_from_slice(&fragments[index]);
    }
    if covered.iter().any(|b| !*b) {
        return Err("unwritten encoded bytes".to_owned());
    }
    Ok(output)
}

/// Exact low-digit-first Base85, low-u32 byteswap, and independent transport
/// LCG XOR. No invalid characters, padding, or shorthand are skipped.
pub fn decode_transport(encoded: &[u8], alphabet: &[u8], bytes: usize) -> Result<Vec<u8>, String> {
    if alphabet.len() != 85 || bytes == 0 || bytes > MAX_PAYLOAD || bytes % 4 != 0 {
        return Err(format!("{PROFILE}: invalid alphabet/output budget"));
    }
    if bytes.checked_div(4).and_then(|n| n.checked_mul(5)) != Some(encoded.len()) {
        return Err(format!("{PROFILE}: transport requires five bytes per u32"));
    }
    let mut digits = [None; 256];
    for (index, byte) in alphabet.iter().copied().enumerate() {
        if digits[byte as usize].replace(index as u64).is_some() {
            return Err(format!("{PROFILE}: duplicate alphabet byte"));
        }
    }
    let mut output = Vec::with_capacity(bytes);
    let mut state = 577177045u32;
    for (index, group) in encoded.chunks_exact(5).enumerate() {
        let mut value = 0u64;
        for byte in group.iter().rev() {
            value = value * 85
                + digits[*byte as usize].ok_or_else(|| {
                    format!("{PROFILE}: invalid alphabet byte {byte} at word {index}")
                })?;
        }
        state = state.wrapping_mul(15577).wrapping_add(3425539465);
        output.extend_from_slice(&((value as u32).swap_bytes() ^ state).to_le_bytes());
    }
    Ok(output)
}

pub(crate) fn read32(data: &[u8], offset: usize) -> Result<u32, String> {
    let end = offset.checked_add(4).ok_or("u32 extent overflow")?;
    let bytes: [u8; 4] = data
        .get(offset..end)
        .ok_or_else(|| format!("u32 read out of bounds at byte {offset}"))?
        .try_into()
        .map_err(|_| "invalid u32 extent")?;
    Ok(u32::from_le_bytes(bytes))
}

pub(crate) fn word(vm: &DecodedVm, at: usize) -> Result<u32, String> {
    vm.decoded_words
        .get(at)
        .copied()
        .flatten()
        .ok_or_else(|| format!("{PROFILE}: absent working word {at}"))
}

pub(crate) fn slot(vm: &DecodedVm, at: usize) -> Result<u16, String> {
    vm.slot_map
        .get(at)
        .copied()
        .filter(|s| at > 0 && *s > 0)
        .ok_or_else(|| format!("{PROFILE}: invalid register-map index {at}"))
}

pub(crate) fn decode(source: &str, ts: &[Token]) -> Result<DecodedVm, String> {
    if source.len() > MAX_SOURCE {
        return Err(format!("{PROFILE}: source budget exceeded"));
    }
    let indices = certify(ts)?;
    let fragments = indices
        .iter()
        .map(|at| {
            scan_quoted(source, ts.get(*at).ok_or("fragment token missing")?.offset).map(|v| v.0)
        })
        .collect::<Result<Vec<_>, String>>()?;
    let encoded = assemble_fragments(&fragments)?;
    let at = unique(ts, &["_ab", "=", "bfrom", "("])?
        .checked_add(4)
        .ok_or("alphabet offset overflow")?;
    let token = ts
        .get(at)
        .filter(|t| t.kind == TokenKind::String)
        .ok_or("alphabet literal missing")?;
    let alphabet = scan_quoted(source, token.offset)?.0;
    let payload = decode_transport(&encoded, &alphabet, TRANSPORT_BYTES)?;
    let argument = 263838302 ^ 153990597;
    let (words, slots, biases, init) = initialize_data(&payload, argument)?;
    let root = (init.master_key ^ 595533583u32.wrapping_add(2755699720) ^ 266632) as usize;
    let mut vm = DecodedVm {
        profile: VmProfile::SarpLarge,
        source_text: source.to_owned(),
        source_sha256: Some(sha256_hex(source.as_bytes())),
        raw_words: payload
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .collect(),
        payload,
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
    let mut at = unique(ts, &["RT", "=", "{"])?
        .checked_add(3)
        .ok_or("dispatch offset overflow")?;
    while !sequence(ts, at, &["}"]) {
        let key = ts
            .get(at + 1)
            .ok_or("truncated RT key")?
            .text
            .parse::<u32>()
            .map_err(|_| "noninteger RT key")?;
        let family = ts
            .get(at + 4)
            .ok_or("truncated RT value")?
            .text
            .parse::<u32>()
            .map_err(|_| "noninteger RT value")?;
        if !sequence(ts, at, &["["]) || !sequence(ts, at + 2, &["]", "="]) {
            return Err("invalid certified RT entry".to_owned());
        }
        if vm.dispatch_families.insert(key, family).is_some() {
            return Err("duplicate dispatch token".to_owned());
        }
        at = at.checked_add(5).ok_or("dispatch token overflow")?;
        if sequence(ts, at, &[","]) {
            at += 1;
        }
        if vm.dispatch_families.len() > 64 {
            return Err("dispatch map budget exceeded".to_owned());
        }
    }
    vm.prototypes.push(prototype(&vm, root, 0)?);
    Ok(vm)
}

pub(crate) fn prototype(vm: &DecodedVm, p: usize, mask: u32) -> Result<Prototype, String> {
    if p == 0
        || p < vm.decoded_range.0
        || p.checked_add(6).is_none_or(|end| end > vm.decoded_range.1)
    {
        return Err("large SARP descriptor outside seven-word extent".to_owned());
    }
    let key = vm.master_key ^ mask;
    let est = word(vm, p)? ^ 2305819396 ^ key;
    let entry = (word(vm, p + 2)? ^ 3146221740 ^ key) as usize;
    let aa = word(vm, p + 3)? ^ 1312544370 ^ key;
    let bb = word(vm, p + 4)? ^ 3129404073 ^ key;
    let token = word(vm, p + 5)? ^ 3545062758 ^ key;
    let bank = (aa >> 1) & 131071;
    let arity = ((aa >> 29) & 7) as usize;
    let captures = ((aa >> 19) & 1023) as usize;
    let fixed = aa & 1 != 0;
    let frame = ((bb >> 18) & 8191) as u16;
    if arity > 4 || frame == 0 || !vm.dispatch_families.contains_key(&token) {
        return Err("invalid large SARP descriptor arity/frame/dispatch".to_owned());
    }
    word(vm, entry)?;
    for off in [5, 6, 9, 10] {
        slot(vm, bank as usize + off)?;
    }
    let aw = if fixed { (arity + 1) / 2 } else { 0 };
    let end = p
        .checked_add(7)
        .and_then(|n| n.checked_add(aw))
        .and_then(|n| n.checked_add(captures))
        .ok_or("descriptor record extent overflow")?;
    if end > vm.decoded_range.1 + 1 {
        return Err("truncated parameter/capture records".to_owned());
    }
    let mut parameters = vec![];
    for index in 0..aw {
        let value = word(vm, p + 7 + index)? ^ 431712049 ^ key;
        parameters.extend([value as u16, (value >> 16) as u16]);
    }
    parameters.truncate(if fixed { arity } else { 0 });
    for offset in &parameters {
        slot(vm, bank as usize + *offset as usize)?;
    }
    // boot/make read the low half as the child destination. Helper 19 reads
    // the high half as an offset in the *parent* bank. Together they prove
    // both fields; the parent offset is validated at the actual creation site.
    let mut capture_descriptors = vec![];
    for index in 0..captures {
        let value = word(vm, p + 7 + aw + index)? ^ 1434732467 ^ key;
        let destination_operand = value as u16;
        let source_operand = (value >> 16) as u16;
        slot(vm, bank as usize + destination_operand as usize)?;
        capture_descriptors.push(CaptureDescriptor {
            destination_operand,
            source_operand,
        });
    }
    let control = [15usize, 3, 7, 9, 17, 18, 33, 21, 6, 29, 24, 2, 23, 5, 12]
        .into_iter()
        .map(|i| slot(vm, i))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if control.len() != 15 {
        return Err("noninjective control frame roles".to_owned());
    }
    Ok(Prototype {
        word: p,
        byte_offset: p
            .checked_sub(1)
            .and_then(|n| n.checked_mul(4))
            .ok_or("descriptor byte offset overflow")?,
        encoded_reference: p as u32 ^ 266632,
        entry_pc: entry,
        initial_decode_state: est,
        dispatch_token: token,
        frame_capacity: frame,
        bank_base: bank,
        prototype_salt: (bb & 65535) as u16,
        fixed_parameter_mode: fixed,
        fixed_parameter_count: if fixed { Some(arity as u16) } else { None },
        parameter_operands: parameters,
        captures: capture_descriptors,
    })
}

pub fn source_model_report(vm: &DecodedVm) -> Result<String, String> {
    let model = model::Model::read(vm)?;
    let mut output = String::new();
    use std::fmt::Write as _;
    writeln!(
        output,
        "Parsed source trees only; not an instruction semantics certification."
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        output,
        "CM={:?}\nCM2={:?}\nCM3={:?}",
        model.cm, model.cm2, model.cm3
    )
    .map_err(|e| e.to_string())?;
    for (id, family) in model.families {
        writeln!(
            output,
            "Family {id}: selector={:?}, metadata={:?}, source tokens={}..{}",
            family.selector, family.metadata, family.source_first, family.source_last
        )
        .map_err(|e| e.to_string())?;
    }
    for (id, helper) in model.helpers {
        writeln!(
            output,
            "Helper {id}: params={:?}, source tokens={}..{}",
            helper.params, helper.source_first, helper.source_last
        )
        .map_err(|e| e.to_string())?;
    }
    writeln!(output, "MO: {:#?}\nMO2: {:#?}", model.mo, model.mo2).map_err(|e| e.to_string())?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    const SOURCE: &str = include_str!("../tests/fixtures/protected.luau");
    #[test]
    fn large_source_certifies_and_has_a_complete_bounded_source_grammar() {
        let vm = crate::decode_source(SOURCE).unwrap();
        assert!(is_profile(&vm));
        let model = model::Model::read(&vm).unwrap();
        assert_eq!(model.families.len(), 7);
        assert_eq!(model.helpers.len(), 32);
        assert_eq!(vm.entry_prototype, 134628);
        assert_eq!(vm.prototypes[0].entry_pc, 138920);
        assert_eq!(vm.decoded_range, (134160, 141177));
        assert_eq!(vm.master_key, 3350847355);
        assert_eq!(
            sha256_hex(&vm.payload),
            "b56b453499598f203dc50ffc04d515dd907fd30ec79f23610cc740c17832f69a"
        );
    }
}
