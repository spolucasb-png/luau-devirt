//! Static regression tests for the independently certified SARP profile.
//!
//! Nothing here executes Lua/Luau, the wrapper, a target VM, or an external
//! tool. The tests read the bundled inert fixture, perform decoder/transport
//! arithmetic, inspect the lifted IR, and compare generated text only.
//!
//! The expected values below are from the checked-in independent static
//! reference diagnostics (`decompilation/sarp/diagnostics/reference.*`) and
//! the preserved wrapper listings. The tests do not read the golden
//! `target.deobfuscated.lua` as an input to the decoder.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use luau_devirt::ir::{CodegenOptions, DecodedVm, Instruction, LiftedProgram, VmProfile};
use luau_devirt::sarp::{self, Analysis, AnalysisLimits};
use luau_devirt::{decode_source, emit_luau, walk_cfg};

const SARP_SOURCE: &str = include_str!("../tests/fixtures/sarp.lua");
const SAMPLE_SOURCE: &str = include_str!("../tests/fixtures/sample.lua");
const ROTOR_SOURCE: &str = include_str!("../tests/fixtures/base85-rotor.lua");

/// The certified 85-byte SARP alphabet from `_ab`.
const ALPHABET: &[u8] =
    b"xUvtToqpzV^657!Ylsec>u@ib1Af:DmyI#[B;X<8k~?_aK20G+$F)9rQNZR|h=Wwgd4.HOCJM3%E&jP],nL(S";

const FRAGMENT_NAMES: [&str; 5] = ["_pc0", "_pc1", "_pc2", "_pc3", "_pc4"];
const FRAGMENT_OFFSETS: [usize; 5] = [0, 558, 1140, 1700, 2256];
const FRAGMENT_LENGTHS: [usize; 5] = [558, 582, 560, 556, 574];

const EXPECTED_SOURCE_SHA256: &str =
    "4518ff6626677a946e60b1f1fbf5e0e0bd6c2aa95a674c163864e763fff3d45f";
const EXPECTED_PAYLOAD_PREFIX: [u8; 16] = [
    0x39, 0x85, 0xef, 0xfc, 0xcf, 0x0d, 0xfd, 0xc4, 0xf0, 0x90, 0x28, 0x2a, 0x40, 0xca, 0x59, 0x62,
];
const EXPECTED_PAYLOAD_SUFFIX: [u8; 16] = [
    0x0e, 0x79, 0x7c, 0x4f, 0x46, 0xd1, 0xa2, 0x02, 0xfb, 0xc7, 0x49, 0xb8, 0xfa, 0x84, 0x9d, 0xb6,
];
const EXPECTED_RAW_WORDS_PREFIX: [u32; 4] = [4243555641, 3304918479, 707301616, 1650051648];
const EXPECTED_HEADER_WORDS: [u32; 4] = [864695349, 2527264146, 4120903014, 1056508129];

fn baseline_vm() -> DecodedVm {
    decode_source(SARP_SOURCE).expect("certified SARP fixture must decode")
}

fn transport_key(word_index: usize) -> u32 {
    let mut key = 1_147_127_625u32;
    for _ in 0..=word_index {
        key = key.wrapping_mul(17_487).wrapping_add(3_048_913_621);
    }
    key
}

/// Encode one transport word the way initOnce reads it: `_p` is the least
/// significant Base85 digit, followed by the transport LCG XOR.
fn encoded_word_with(value: u32, word_index: usize, alphabet: &[u8]) -> Vec<u8> {
    let mut value = (value ^ transport_key(word_index)).swap_bytes() as u64;
    let mut encoded = Vec::with_capacity(5);
    for _ in 0..5 {
        let digit = (value % 85) as usize;
        encoded.push(alphabet[digit]);
        value /= 85;
    }
    encoded
}

fn encoded_word(value: u32, word_index: usize) -> Vec<u8> {
    encoded_word_with(value, word_index, ALPHABET)
}

fn split_fragments(encoded: &[u8]) -> Vec<Vec<u8>> {
    assert_eq!(encoded.len(), 2_830);
    FRAGMENT_OFFSETS
        .iter()
        .zip(FRAGMENT_LENGTHS)
        .map(|(offset, length)| encoded[*offset..*offset + length].to_vec())
        .collect()
}

/// Replace one `local _pcN="..."` literal body without touching the certified
/// token skeleton. Fragment bytes are printable alphabet characters.
fn replace_fragment(source: &str, name: &str, bytes: &[u8]) -> String {
    let marker = format!("local {name}");
    let at = source
        .find(&marker)
        .unwrap_or_else(|| panic!("missing fragment marker {marker}"));
    let open = source[at..]
        .find('"')
        .map(|offset| at + offset)
        .expect("fragment opening quote");
    let close = source[open + 1..]
        .find('"')
        .map(|offset| open + 1 + offset)
        .expect("fragment closing quote");
    let body = std::str::from_utf8(bytes).expect("SARP fragments are ASCII");
    format!("{}{}{}", &source[..=open], body, &source[close..])
}

/// Re-encode one payload word back into the Base85 fragments. This is the
/// inverse of `decode_transport` for a single word, using values read from the
/// source fragments via the public decoded VM.
fn mutate_payload_word(source: &str, word_index: usize, new_word: u32) -> String {
    let vm = decode_source(source).expect("baseline decode");
    let mut encoded = sarp::assemble_fragments(&vm.initial_strings).expect("fragment assembly");
    let group = encoded_word(new_word, word_index);
    encoded[word_index * 5..word_index * 5 + 5].copy_from_slice(&group);
    let fragments = split_fragments(&encoded);
    FRAGMENT_NAMES
        .iter()
        .zip(fragments.iter())
        .fold(source.to_owned(), |current, (name, fragment)| {
            replace_fragment(&current, name, fragment)
        })
}

fn decode_returns_error_without_panic(source: &str) -> bool {
    match std::panic::catch_unwind(|| decode_source(source)) {
        Ok(Err(_)) => true,
        Ok(Ok(_)) => false,
        Err(_) => panic!("decode_source panicked on a mutated SARP source"),
    }
}

fn required_baseline_output(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("bundled baseline output missing {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

fn program_links(program: &LiftedProgram) {
    for (pc, block) in &program.blocks {
        assert_eq!(block.start_pc, *pc);
        for successor in &block.successors {
            if let Some(target) = successor.target_pc {
                assert!(
                    program.blocks.contains_key(&target),
                    "block {pc} has an out-of-range successor {target}"
                );
            }
        }
        for instruction in &block.instructions {
            match instruction {
                Instruction::Jump { target } => assert!(program.blocks.contains_key(target)),
                Instruction::Branch {
                    then_target,
                    else_target,
                    ..
                } => {
                    assert!(program.blocks.contains_key(then_target));
                    assert!(program.blocks.contains_key(else_target));
                }
                Instruction::ForPrep { target, .. } | Instruction::ForLoop { target, .. } => {
                    assert!(program.blocks.contains_key(target));
                }
                Instruction::Raw { .. } => panic!("unexpected Raw instruction at PC {pc}"),
                _ => {}
            }
        }
    }
}

#[test]
fn decoded_vm_matches_the_independent_sarp_reference() {
    let vm = baseline_vm();

    assert_eq!(sarp::PROFILE, "sarp-fragment-dualstream-7word-v1");
    assert_eq!(
        sarp::WRAPPER_SHA256,
        "e81814ff9d295dc39e3888a8e60b4a484140b627f52ef3b8c3215b17afe92f3b"
    );
    assert_eq!(vm.profile, VmProfile::Sarp);
    assert!(sarp::is_profile(&vm));

    assert_eq!(vm.source_text.len(), 118_433);
    assert_eq!(vm.source_sha256.as_deref(), Some(EXPECTED_SOURCE_SHA256));
    assert_eq!(vm.initialization_argument, 3_240_235_817);
    assert_eq!(vm.master_key, 1_302_175_439);
    assert_eq!(vm.decoded_range, (190, 507));
    assert_eq!(vm.entry_prototype, 501);
    assert_eq!(vm.payload.len(), 2_264);
    assert_eq!(vm.raw_words.len(), 566);
    assert_eq!(vm.decoded_words.len(), 567);
    assert_eq!(&vm.payload[..16], &EXPECTED_PAYLOAD_PREFIX);
    assert_eq!(&vm.payload[2_248..], &EXPECTED_PAYLOAD_SUFFIX);
    assert_eq!(&vm.raw_words[..4], &EXPECTED_RAW_WORDS_PREFIX);
    assert_eq!(
        &vm.decoded_words[1..=4],
        &[
            Some(EXPECTED_HEADER_WORDS[0]),
            Some(EXPECTED_HEADER_WORDS[1]),
            Some(EXPECTED_HEADER_WORDS[2]),
            Some(EXPECTED_HEADER_WORDS[3]),
        ]
    );
    assert_eq!(vm.decoded_words[0], None);
    assert_eq!(vm.decoded_words[5], None);
    assert_eq!(vm.decoded_words[189], None);
    assert_eq!(vm.decoded_words[190], Some(2_388_573_531));
    assert_eq!(vm.decoded_words[507], Some(3_917_234_125));
    assert_eq!(vm.decoded_words[508], None);

    // One zero entry plus the certified 118-entry register map.
    assert_eq!(vm.slot_map.len(), 119);
    assert_eq!(&vm.slot_map[1..=6], &[52, 50, 35, 21, 29, 28]);
    assert_eq!(vm.slot_map[118], 27);
    assert!(vm
        .slot_map
        .iter()
        .skip(1)
        .all(|slot| *slot != 0 && *slot <= 52));

    // One zero entry plus 64 KBOX biases.
    assert_eq!(vm.immediate_biases.len(), 65);
    assert_eq!(
        &vm.immediate_biases[1..=4],
        &[105_553, 21_586, 102_585, 4_074]
    );
    assert_eq!(vm.immediate_biases[64], 2_170);

    assert_eq!(vm.dispatch_families.len(), 34);
    assert_eq!(vm.dispatch_families.get(&56_332), Some(&2_199));
    assert_eq!(vm.prototypes.len(), 1);
    let root = &vm.prototypes[0];
    assert_eq!(
        (
            root.word,
            root.byte_offset,
            root.encoded_reference,
            root.entry_pc,
            root.initial_decode_state,
            root.dispatch_token,
            root.frame_capacity,
            root.bank_base,
            root.prototype_salt
        ),
        (
            501,
            2_000,
            774_933,
            442,
            1_234_081_515,
            56_332,
            52,
            15,
            26_339
        )
    );
    assert!(!root.fixed_parameter_mode);
    assert_eq!(root.fixed_parameter_count, None);
    assert!(root.parameter_operands.is_empty());
    assert!(root.captures.is_empty());

    assert!(vm.table_integrity.is_empty());
    assert!(vm.permutation_parity.is_empty());
    assert!(vm.strings.is_empty());
    assert!(vm.numbers.is_empty());
    assert_eq!(vm.initial_strings.len(), 5);
    assert_eq!(vm.initial_strings.len(), FRAGMENT_LENGTHS.len());
    for (fragment, expected) in vm.initial_strings.iter().zip(FRAGMENT_LENGTHS) {
        assert_eq!(fragment.len(), expected);
    }
}

#[test]
fn transport_vectors_cover_digit_order_byteswap_xor_and_bounds() {
    assert_eq!(ALPHABET.len(), 85);

    // Low digit first, bswap of the low u32, then one transport-LCG XOR per word.
    let one = encoded_word(0x1234_5678, 0);
    assert_eq!(one.len(), 5);
    assert_eq!(
        sarp::decode_transport(&one, ALPHABET, 4).expect("one transport word"),
        0x1234_5678u32.to_le_bytes()
    );

    let mut two = encoded_word(0x1234_5678, 0);
    two.extend(encoded_word(0xDEAD_BEEF, 1));
    let decoded = sarp::decode_transport(&two, ALPHABET, 8).expect("two transport words");
    assert_eq!(&decoded[..4], &0x1234_5678u32.to_le_bytes());
    assert_eq!(&decoded[4..], &0xDEAD_BEEFu32.to_le_bytes());

    // Five base-85 digits can exceed u32 before the source's low-u32 wrap.
    let overflow_value = 85u64.pow(5) - 1;
    let mut overflow = Vec::new();
    let mut value = overflow_value;
    for _ in 0..5 {
        overflow.push(ALPHABET[(value % 85) as usize]);
        value /= 85;
    }
    assert_eq!(value, 0);
    let expected_overflow = ((overflow_value as u32).swap_bytes() ^ transport_key(0)).to_le_bytes();
    assert_eq!(
        sarp::decode_transport(&overflow, ALPHABET, 4).expect("overflow wrap"),
        expected_overflow
    );

    // The transport is byte-oriented, including a full high-byte alphabet.
    let high_alphabet: Vec<u8> = (128u16..=212).map(|byte| byte as u8).collect();
    assert_eq!(high_alphabet.len(), 85);
    let high_word = encoded_word_with(0xC0FF_EE00, 0, &high_alphabet);
    assert_eq!(
        sarp::decode_transport(&high_word, &high_alphabet, 4).expect("high-byte alphabet"),
        0xC0FF_EE00u32.to_le_bytes()
    );

    for (alphabet, bytes) in [
        (ALPHABET[..84].to_vec(), 4usize),
        (
            {
                let mut alphabet = ALPHABET.to_vec();
                alphabet.push(85);
                alphabet
            },
            4,
        ),
        (ALPHABET.to_vec(), 0),
        (ALPHABET.to_vec(), 3),
        (ALPHABET.to_vec(), 8),
        (ALPHABET.to_vec(), 1_048_580),
    ] {
        assert!(
            sarp::decode_transport(&one, &alphabet, bytes).is_err(),
            "accepted invalid alphabet/size {bytes}"
        );
    }

    let mut duplicate = ALPHABET.to_vec();
    duplicate[84] = duplicate[0];
    assert!(sarp::decode_transport(&one, &duplicate, 4).is_err());

    let mut invalid = one.clone();
    invalid[0] = 0xFF;
    assert!(sarp::decode_transport(&invalid, ALPHABET, 4).is_err());

    assert!(sarp::decode_transport(&one[..4], ALPHABET, 4).is_err());
    let mut too_long = one;
    too_long.push(ALPHABET[0]);
    assert!(sarp::decode_transport(&too_long, ALPHABET, 4).is_err());
    assert!(sarp::decode_transport(&[], ALPHABET, 4).is_err());
}

#[test]
fn fragment_assembly_rejects_shape_errors_and_detects_wrong_order() {
    let vm = baseline_vm();
    let fragments = vm.initial_strings.clone();
    let encoded = sarp::assemble_fragments(&fragments).expect("certified fragment layout");
    assert_eq!(encoded.len(), 2_830);
    assert_eq!(
        sarp::decode_transport(&encoded, ALPHABET, 2_264).expect("certified payload"),
        vm.payload
    );

    assert!(sarp::assemble_fragments(&fragments[..4]).is_err());
    let mut short = fragments.clone();
    short[0].pop();
    assert!(sarp::assemble_fragments(&short).is_err());
    let mut long = fragments.clone();
    long[0].push(ALPHABET[0]);
    assert!(sarp::assemble_fragments(&long).is_err());

    // The five extents are unique, so swapping adjacent fragments is rejected
    // by exact-extent validation rather than silently decoding a shifted stream.
    let mut swapped = fragments.clone();
    swapped.swap(0, 1);
    assert!(
        sarp::assemble_fragments(&swapped).is_err(),
        "swapped SARP fragment vector was accepted"
    );

    // Swapping the source literal contents keeps the certified skeleton but
    // changes the assembled stream; the arithmetic must fail, not recover the
    // original program silently.
    let swapped_source = {
        let source = replace_fragment(SARP_SOURCE, "_pc0", &fragments[1]);
        replace_fragment(&source, "_pc1", &fragments[0])
    };
    assert!(
        decode_returns_error_without_panic(&swapped_source),
        "swapped SARP fragments were accepted"
    );
}

#[test]
fn wrapper_changes_fail_but_comments_and_whitespace_preserve_data() {
    let baseline = baseline_vm();

    for changed in [
        // initOnce transport/math
        SARP_SOURCE.replacen("1147127625", "1147127626", 1),
        // handler cipher math
        SARP_SOURCE.replacen("433233", "433234", 1),
        // key-derivation formula
        SARP_SOURCE.replacen("26797", "26798", 1),
        // appended wrapper code
        format!("{SARP_SOURCE}\nlocal sarp_extra = 1;"),
    ] {
        assert_ne!(changed, SARP_SOURCE);
        assert!(
            decode_source(&changed).is_err(),
            "a changed SARP wrapper was accepted"
        );
    }

    let mut changed_alphabet = ALPHABET.to_vec();
    changed_alphabet[0] = b'|';
    let changed_alphabet_source = SARP_SOURCE.replacen(
        std::str::from_utf8(ALPHABET).expect("alphabet text"),
        std::str::from_utf8(&changed_alphabet).expect("changed alphabet text"),
        1,
    );
    assert_ne!(changed_alphabet_source, SARP_SOURCE);
    assert!(
        decode_source(&changed_alphabet_source).is_err(),
        "a changed SARP alphabet was accepted"
    );

    let reformatted = SARP_SOURCE.replacen(
        "local _b85=bcreate(2830)",
        "local   _b85  =  bcreate ( 2830 )",
        1,
    );
    assert_ne!(reformatted, SARP_SOURCE);
    let with_comment =
        format!("-- SARP review copy; inert }} ] ] \" text and a fake _b85 token\n\n{reformatted}");
    let accepted = decode_source(&with_comment).expect("comments/whitespace are not formulas");
    assert_eq!(accepted.profile, VmProfile::Sarp);
    assert_eq!(accepted.payload, baseline.payload);
    assert_eq!(accepted.raw_words, baseline.raw_words);
    assert_eq!(accepted.decoded_words, baseline.decoded_words);
    assert_eq!(accepted.master_key, baseline.master_key);
    assert_eq!(accepted.decoded_range, baseline.decoded_range);
    assert_eq!(accepted.slot_map, baseline.slot_map);
    assert_eq!(accepted.immediate_biases, baseline.immediate_biases);
    assert_eq!(accepted.prototypes, baseline.prototypes);
}

#[test]
fn payload_header_slot_and_descriptor_mutations_fail_explicitly() {
    let vm = baseline_vm();
    assert_eq!(vm.raw_words[0], EXPECTED_RAW_WORDS_PREFIX[0]);

    // Header word 3 -> derived high bound zero. The source's `_dm` check is not
    // a general byte-integrity proof, so this deliberately tests a structural
    // range failure rather than assuming every payload byte change is rejected.
    let high_word_key = vm.raw_words[2] ^ EXPECTED_HEADER_WORDS[2];
    let zero_high_header = 3_087_163_986 ^ vm.master_key;
    let header = mutate_payload_word(SARP_SOURCE, 2, high_word_key ^ zero_high_header);
    assert!(
        decode_returns_error_without_panic(&header),
        "structurally invalid SARP header word was accepted"
    );

    // First RMAP word (byte 2028): a zero physical slot is explicitly invalid.
    let slot = mutate_payload_word(SARP_SOURCE, 507, 0);
    assert!(
        decode_returns_error_without_panic(&slot),
        "corrupted SARP slot-map word was accepted"
    );

    // Root descriptor entry word (p = 501 -> raw word index 500).
    let entry = mutate_payload_word(SARP_SOURCE, 500, 0);
    assert!(
        decode_returns_error_without_panic(&entry),
        "corrupted SARP descriptor entry was accepted"
    );

    // Root descriptor dispatch-token word (p + 5 = 506 -> raw word index 505).
    let token = mutate_payload_word(SARP_SOURCE, 505, 0);
    assert!(
        decode_returns_error_without_panic(&token),
        "corrupted SARP descriptor token was accepted"
    );

    // Mutating the already-decoded public model must also fail explicitly and
    // must not panic in the symbolic analyzer.
    let mut short = vm.clone();
    short.raw_words.pop();
    assert!(std::panic::catch_unwind(|| sarp::analyze(&short))
        .expect("analyzer must not panic")
        .is_err());

    let mut bad_entry = vm.clone();
    bad_entry.prototypes[0].entry_pc = 0;
    assert!(std::panic::catch_unwind(|| sarp::analyze(&bad_entry))
        .expect("analyzer must not panic")
        .is_err());

    let mut bad_family = vm.clone();
    let root_token = bad_family.prototypes[0].dispatch_token;
    bad_family.dispatch_families.insert(root_token, 9_999);
    assert!(std::panic::catch_unwind(|| sarp::analyze(&bad_family))
        .expect("analyzer must not panic")
        .is_err());
}

#[test]
fn analysis_matches_reference_counts_families_states_and_links() {
    let vm = baseline_vm();
    let analysis: Analysis = sarp::analyze(&vm).expect("SARP symbolic analysis");

    assert_eq!(analysis.trace.len(), 178);
    assert_eq!(analysis.raw_program.blocks.len(), 43);
    assert_eq!(analysis.program.blocks.len(), 30);
    assert_eq!(analysis.raw_program.reachable_pcs.len(), 43);
    assert_eq!(analysis.program.reachable_pcs.len(), 30);
    assert_eq!(analysis.raw_program.state_variants, 178);
    assert_eq!(analysis.program.state_variants, 178);

    assert_eq!(analysis.raw_program.entry_points, vec![442]);
    assert_eq!(analysis.program.entry_points, vec![442]);
    assert_eq!(analysis.raw_program.root_entry, Some(442));
    assert_eq!(analysis.program.root_entry, Some(442));
    assert_eq!(
        analysis.raw_program.prototype_entries,
        BTreeMap::from([(501, 442)])
    );
    assert_eq!(
        analysis.program.prototype_entries,
        BTreeMap::from([(501, 442)])
    );
    assert_eq!(
        analysis.raw_program.parameters,
        BTreeMap::from([(442, None)])
    );
    assert_eq!(analysis.program.parameters, BTreeMap::from([(442, None)]));

    // Only the three implemented dispatcher families may be reached.
    let mut trace_families = BTreeMap::new();
    for row in &analysis.trace {
        *trace_families.entry(row.family).or_insert(0usize) += 1;
        assert!(matches!(row.family, 359 | 1_901 | 2_199));
        assert!(row.end_pc > row.state.pc);
        assert!(row.end_pc <= vm.raw_words.len() + 1);
        assert!((row.state.bank as usize) < vm.slot_map.len());
        assert!(row.state.pc <= vm.raw_words.len());
        for (slot, value) in &row.state.facts {
            assert!(
                *slot < 256,
                "state fact slot {slot} escaped the finite lattice"
            );
            assert!(
                matches!(*value, 0 | 1),
                "state fact {slot}={value} is not a proved 0/1"
            );
        }
        for (_, successor) in &row.successors {
            assert!(analysis.raw_program.blocks.contains_key(&successor.pc));
            assert!((successor.bank as usize) < vm.slot_map.len());
            assert!(successor.pc <= vm.raw_words.len());
            for (slot, value) in &successor.facts {
                assert!(*slot < 256);
                assert!(matches!(*value, 0 | 1));
            }
        }
    }
    assert_eq!(
        trace_families,
        BTreeMap::from([(359, 170), (1_901, 6), (2_199, 2)])
    );

    let raw_families: BTreeSet<u32> = analysis
        .raw_program
        .blocks
        .values()
        .map(|block| block.handler_family)
        .collect();
    assert_eq!(raw_families, BTreeSet::from([359, 1_901, 2_199]));
    for (pc, family, selector) in [
        (442, 2_199, 1224),
        (448, 2_199, 1006),
        (453, 1_901, 971),
        (482, 1_901, 1359),
        (337, 359, 1582),
        (190, 359, 1070),
        (494, 359, 985),
    ] {
        assert!(
            analysis
                .trace
                .iter()
                .any(|row| row.state.pc == pc && row.family == family && row.selector == selector),
            "missing static listing row PC {pc} family {family} selector {selector}"
        );
        assert!(
            analysis.raw_program.blocks.contains_key(&pc),
            "missing raw block PC {pc}"
        );
    }

    program_links(&analysis.raw_program);
    program_links(&analysis.program);

    let raw_calls = analysis
        .raw_program
        .blocks
        .values()
        .flat_map(|block| &block.instructions)
        .filter(|instruction| matches!(instruction, Instruction::Call { .. }))
        .count();
    let final_calls = analysis
        .program
        .blocks
        .values()
        .flat_map(|block| &block.instructions)
        .filter(|instruction| matches!(instruction, Instruction::Call { .. }))
        .count();
    assert_eq!(raw_calls, 8);
    assert_eq!(final_calls, 8);
    assert_eq!(
        analysis
            .program
            .blocks
            .values()
            .flat_map(|block| &block.instructions)
            .filter(|instruction| matches!(instruction, Instruction::Return { .. }))
            .count(),
        1
    );
    for block in analysis
        .raw_program
        .blocks
        .values()
        .chain(analysis.program.blocks.values())
    {
        assert!(
            !block
                .instructions
                .iter()
                .any(|instruction| matches!(instruction, Instruction::Raw { .. })),
            "SARP analysis left a Raw instruction"
        );
        assert!(
            !block
                .instructions
                .iter()
                .any(|instruction| matches!(instruction, Instruction::HaltDispatch { .. })),
            "SARP analysis produced a dispatch halt"
        );
    }

    // On-demand constants: 35 string references and three numeric references.
    assert_eq!(analysis.strings.len(), 35);
    assert_eq!(analysis.numbers.len(), 3);
    let string_values: BTreeSet<&[u8]> = analysis.strings.values().map(Vec::as_slice).collect();
    assert_eq!(string_values.len(), 35);
    for expected in [
        b"MothDialogueBindable".as_slice(),
        b"hey its me its celestial".as_slice(),
        b"Color".as_slice(),
        b"Shaky".as_slice(),
        b"fromRGB".as_slice(),
        b"Fire".as_slice(),
    ] {
        assert!(
            string_values.contains(expected),
            "missing recovered SARP string {:?}",
            String::from_utf8_lossy(expected)
        );
    }
    assert_eq!(
        analysis.numbers.keys().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([1_071_760, 1_071_761, 1_071_767])
    );
    assert_eq!(
        analysis.numbers.values().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            0x401e_0000_0000_0000,
            0x3fe0_0000_0000_0000,
            0x3fee_6666_6666_6666
        ])
    );

    // Generated output only. No golden text is passed into the decoder.
    let emitted =
        emit_luau(&analysis.program, &CodegenOptions::default()).expect("emit recovered SARP Luau");
    assert!(emitted.starts_with("--!strict"));
    assert_eq!(emitted.lines().count(), 60);
    for expected in [
        "MothDialogueBindable",
        "hey its me its celestial",
        "dialogueOptions.Lifetime = 7.5",
        "fromScale(0.5, 0.95)",
        "fromRGB(255, 45, 45)",
        "colorMarkup.MarkupType = \"Color\"",
        "shakyMarkup.MarkupType = \"Shaky\"",
        "fireDialogue(dialogueEvent, dialogueOptions)",
    ] {
        assert!(
            emitted.contains(expected),
            "missing recovered SARP output marker: {expected}"
        );
    }
    for unresolved in [
        "_b85",
        "vm_unknown",
        "FIXME",
        "Raw",
        "loadstring",
        "buffer.",
    ] {
        assert!(
            !emitted.contains(unresolved),
            "unresolved SARP machinery in emitted output: {unresolved}"
        );
    }

    // `walk_cfg` must select the same isolated SARP pipeline.
    let walked = walk_cfg(&vm).expect("walk_cfg on SARP");
    assert_eq!(walked, analysis.program);
}

#[test]
fn analysis_limits_fail_explicitly() {
    let vm = baseline_vm();
    let one_state = sarp::analyze_with_limits(
        &vm,
        AnalysisLimits {
            max_states: 1,
            max_worklist_pops: usize::MAX,
        },
    )
    .expect_err("one-state budget must fail");
    assert!(
        one_state.to_ascii_lowercase().contains("budget"),
        "unexpected limit error: {one_state}"
    );

    let no_pops = sarp::analyze_with_limits(
        &vm,
        AnalysisLimits {
            max_states: usize::MAX,
            max_worklist_pops: 0,
        },
    )
    .expect_err("zero-pop budget must fail");
    assert!(
        no_pops.to_ascii_lowercase().contains("budget"),
        "unexpected limit error: {no_pops}"
    );
}

#[test]
fn all_three_profiles_select_isolated_pipelines_and_old_outputs_are_unchanged() {
    let adler = decode_source(SAMPLE_SOURCE).expect("old Adler fixture decodes");
    assert_eq!(adler.profile, VmProfile::Adler32Lcg5Word);
    let adler_program = walk_cfg(&adler).expect("old Adler fixture walks");
    let adler_output =
        emit_luau(&adler_program, &CodegenOptions::default()).expect("old Adler fixture emits");

    let rotor = decode_source(ROTOR_SOURCE).expect("old Base85 fixture decodes");
    assert_eq!(rotor.profile, VmProfile::Base85Rotor3Bank);
    let rotor_program = walk_cfg(&rotor).expect("old Base85 fixture walks");
    let rotor_output =
        emit_luau(&rotor_program, &CodegenOptions::default()).expect("old Base85 fixture emits");

    let sarp = decode_source(SARP_SOURCE).expect("SARP fixture decodes");
    assert_eq!(sarp.profile, VmProfile::Sarp);
    let sarp_program = walk_cfg(&sarp).expect("SARP fixture walks");
    let _sarp_output =
        emit_luau(&sarp_program, &CodegenOptions::default()).expect("SARP fixture emits");

    // These existing baseline artifacts are bundled in source releases. Do not
    // use excluded investigation logs or silently skip compatibility checks.
    assert_eq!(
        adler_output,
        required_baseline_output("examples/sample.recovered.luau"),
        "old Adler output changed"
    );
    assert_eq!(
        rotor_output,
        required_baseline_output("decompilation/message/target.deobfuscated.lua"),
        "old Base85 output changed"
    );
}
