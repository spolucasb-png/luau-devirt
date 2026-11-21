//! Static regression tests for the Base85 / rotor / three-bank transport profile.
//!
//! Nothing here executes Lua, Luau, the wrapper, or the target VM. The tests
//! only read fixture text, decode it arithmetically, and inspect lifted IR.
//! Expected constants were independently re-derived from the inspected wrapper
//! (`decode_payload.py` cross-checked against `initOnce.txt`, `make.txt`,
//! `boot.txt`, and `U.txt`); see `decompilation/message/diagnostics/decoder-review.md`.

use std::path::PathBuf;

use luau_devirt::base85::{analyze, decode_transport, is_profile};
use luau_devirt::ir::CodegenOptions;
use luau_devirt::{decode_source, emit_luau, walk_cfg};

const ROTOR_FIXTURE: &str = "base85-rotor.lua";
const OLDER_FIXTURE: &str = "sample.lua";
const SOURCE_SHA256: &str = "0e4d2588aaa6f118dcdfe9999ccb84c0115ad058b3f3c61bca5ced500757edd0";
const ENCODED_LEN: usize = 2810;
const ALPHABET_LEN: usize = 85;
const PAYLOAD_LEN: usize = 2248;
/// `RMAP` physical slots selected by `CM`: `CM[i] = RMAP[CM_INDEX[i - 1]]`.
const CM_INDEX: [usize; 15] = [13, 5, 11, 9, 2, 7, 4, 10, 8, 6, 15, 3, 14, 12, 1];
const CM_SLOT_VALUES: [u16; 15] = [44, 11, 35, 9, 30, 36, 23, 33, 41, 31, 32, 39, 38, 5, 43];

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("bundled fixture {} is unreadable: {error}", path.display()))
}

fn rotor_source() -> String {
    let source = fixture(ROTOR_FIXTURE);
    assert_eq!(source.len(), 83_951, "fixture is not the certified wrapper");
    source
}

fn rotor_vm() -> luau_devirt::DecodedVm {
    let source = rotor_source();
    let vm = decode_source(&source).expect("certified Base85 fixture must decode");
    assert_eq!(vm.source_sha256.as_deref(), Some(SOURCE_SHA256));
    vm
}

fn encoded_and_alphabet(vm: &luau_devirt::DecodedVm) -> (&[u8], &[u8]) {
    let encoded = vm
        .initial_strings
        .iter()
        .find(|value| value.len() == ENCODED_LEN)
        .expect("transport literal");
    let alphabet = vm
        .initial_strings
        .iter()
        .find(|value| value.len() == ALPHABET_LEN)
        .expect("alphabet literal");
    (encoded, alphabet)
}

/// Least-significant Base85 digit first, writing the low 32 bits little-endian.
fn encode_word(mut value: u32, alphabet: &[u8]) -> Vec<u8> {
    (0..5)
        .map(|_| {
            let digit = (value % 85) as usize;
            value /= 85;
            alphabet[digit]
        })
        .collect()
}

#[test]
fn transport_uses_low_digit_first_and_little_endian_words() {
    let alphabet: Vec<u8> = (0u8..85).collect();
    // Fixed digit vectors, independently derived: digit 0 is the least
    // significant Base85 place. The alphabet here is the byte identity.
    let cases: [([u8; 5], u32); 3] = [
        ([21, 55, 27, 72, 5], 0x1234_5678),
        ([0, 12, 54, 23, 82], 0xFFFF_FFFF),
        ([59, 45, 28, 48, 71], 0xDEAD_BEEF),
    ];
    let mut encoded = Vec::new();
    let mut expected = Vec::new();
    for (digits, value) in cases {
        encoded.extend_from_slice(&digits);
        expected.extend_from_slice(&value.to_le_bytes());
    }
    let decoded =
        decode_transport(&encoded, &alphabet, cases.len() * 4).expect("valid synthetic transport");
    assert_eq!(decoded, expected);

    // The first character is the *lowest* digit, not the highest.
    let one = decode_transport(&[1, 0, 0, 0, 0], &alphabet, 4).expect("word value one");
    assert_eq!(one, 1u32.to_le_bytes().to_vec());
    let high_place = decode_transport(&[0, 0, 0, 0, 1], &alphabet, 4).expect("85^4 place");
    assert_eq!(high_place, (85u32.pow(4)).to_le_bytes().to_vec());
}

#[test]
fn transport_accepts_a_full_alphabet_of_non_ascii_bytes() {
    // Exactly 85 distinct bytes above 0x7F: the transport is byte-oriented and
    // must not assume UTF-8 or ASCII.
    let alphabet: Vec<u8> = (128u16..=212).map(|byte| byte as u8).collect();
    assert_eq!(alphabet.len(), 85);
    for value in [0u32, 1, 84, 0x1234_5678, 0xDEAD_BEEF, u32::MAX] {
        let encoded = encode_word(value, &alphabet);
        assert!(encoded.iter().all(|byte| *byte >= 0x80));
        let decoded = decode_transport(&encoded, &alphabet, 4).expect("high-byte alphabet");
        assert_eq!(decoded, value.to_le_bytes().to_vec());
    }
}

#[test]
fn transport_rejects_malformed_alphabet_lengths_and_duplicates() {
    let alphabet: Vec<u8> = (0u8..85).collect();
    let word = encode_word(0x0102_0304, &alphabet);
    assert!(decode_transport(&word, &alphabet[..84], 4).is_err());
    let mut too_long = alphabet.clone();
    too_long.push(85);
    assert!(decode_transport(&word, &too_long, 4).is_err());

    let mut duplicate = alphabet.clone();
    duplicate[84] = duplicate[0];
    let error = decode_transport(&word, &duplicate, 4).expect_err("duplicate alphabet");
    assert!(error.to_ascii_lowercase().contains("duplicate"), "{error}");
}

#[test]
fn transport_rejects_invalid_characters_and_length_or_size_mismatches() {
    let alphabet: Vec<u8> = (0u8..85).collect();
    let mut invalid = encode_word(7, &alphabet);
    invalid[3] = 85; // one past the identity alphabet
    assert!(decode_transport(&invalid, &alphabet, 4).is_err());

    // Byte-length must be a nonzero multiple of four, and encoded length must
    // be exactly five characters per output word.
    assert!(decode_transport(&[], &alphabet, 0).is_err());
    assert!(decode_transport(&[], &alphabet, 3).is_err());
    assert!(decode_transport(&[], &alphabet, 8).is_err());
    assert!(decode_transport(&[0u8; 9], &alphabet, 8).is_err());
    assert!(decode_transport(&[0u8; 11], &alphabet, 8).is_err());
    assert!(decode_transport(&[], &alphabet, 1024 * 1024 + 4).is_err());

    // Truncating or extending a well-formed multiword transport is rejected.
    let two_words: Vec<u8> = encode_word(u32::MAX, &alphabet)
        .into_iter()
        .chain(encode_word(0xC0FF_EE00, &alphabet))
        .collect();
    assert!(decode_transport(&two_words[..9], &alphabet, 8).is_err());
    let mut extended = two_words;
    extended.push(alphabet[0]);
    assert!(decode_transport(&extended, &alphabet, 8).is_err());
}

#[test]
fn fixture_decodes_to_the_independently_reproduced_header_and_payload() {
    let vm = rotor_vm();
    assert_eq!(vm.initialization_argument, 1_754_244_686);
    assert_eq!(vm.master_key, 2_484_975_588);
    assert_eq!(vm.decoded_range, (194, 506));
    assert_eq!(vm.entry_prototype, 194);
    assert_eq!(vm.payload.len(), PAYLOAD_LEN);
    assert_eq!(vm.raw_words.len(), 562);
    assert_eq!(vm.decoded_words.len(), 563);
    assert_eq!(vm.slot_map.len(), 112);
    assert_eq!(vm.immediate_biases.len(), 65);
    assert_eq!(vm.dispatch_families.len(), 15);
    assert_eq!(vm.dispatch_families.get(&58_811), Some(&3080));

    // Raw transport, re-run through the public decoder, must reproduce the
    // certified payload byte for byte.
    let (encoded, alphabet) = encoded_and_alphabet(&vm);
    assert_eq!(encoded.len(), ENCODED_LEN);
    assert_eq!(alphabet.len(), ALPHABET_LEN);
    let payload = decode_transport(encoded, alphabet, PAYLOAD_LEN).expect("fixture transport");
    assert_eq!(payload, vm.payload);
    assert_eq!(
        &payload[..16],
        &[
            0xd1u8, 0x38, 0x5c, 0xaa, 0x1a, 0xa3, 0xc7, 0xa6, 0x5a, 0x80, 0x76, 0x95, 0xf9, 0xde,
            0xf4, 0x4a,
        ][..]
    );
    assert_eq!(
        &payload[PAYLOAD_LEN - 16..],
        &[
            0x83u8, 0x26, 0xcc, 0xf0, 0xdb, 0xb0, 0x5a, 0x7a, 0xf7, 0x2c, 0x30, 0x72, 0x6c, 0x6f,
            0x0a, 0xc2,
        ][..]
    );

    // CM binds fifteen RMAP slots. Their values pin the rolling-slot key
    // stream and the CM ordering.
    for (index, expected) in CM_INDEX.iter().zip(CM_SLOT_VALUES) {
        assert_eq!(vm.slot_map[*index], expected, "CM slot {index}");
    }
    assert_eq!(
        &vm.immediate_biases[..5],
        &[0u32, 151_011, 177_844, 177_885, 177_054][..]
    );
    assert_eq!(vm.immediate_biases[64], 131_370);
}

#[test]
fn fixture_root_prototype_matches_the_source_metadata() {
    let vm = rotor_vm();
    let roots: Vec<_> = vm
        .prototypes
        .iter()
        .filter(|prototype| prototype.word == 194)
        .collect();
    assert_eq!(roots.len(), 1, "root descriptor must be unique");
    let root = roots[0];
    assert_eq!(root.entry_pc, 243);
    assert_eq!(root.initial_decode_state, 394_436_979);
    assert_eq!(root.dispatch_token, 58_811);
    assert_eq!(root.bank_base, 15);
    assert_eq!(root.prototype_salt, 31_541);
    assert_eq!(root.frame_capacity, 48);
    assert!(!root.fixed_parameter_mode);
    assert_eq!(root.fixed_parameter_count, None);
    assert!(root.parameter_operands.is_empty());
    assert!(root.captures.is_empty());
}

#[test]
fn fixture_analysis_and_walk_agree_and_emit_readable_luau() {
    let vm = rotor_vm();
    let analysis = analyze(&vm).expect("Base85 rotor symbolic analysis");
    assert_eq!(analysis.trace.len(), 162);
    assert_eq!(analysis.raw_program.blocks.len(), 42);
    assert_eq!(analysis.program.blocks.len(), 29);
    assert_eq!(analysis.strings.len(), 35);
    assert_eq!(analysis.numbers.len(), 3);
    assert!(analysis.raw_program.blocks.values().all(|block| block
        .instructions
        .iter()
        .all(|i| !matches!(i, luau_devirt::ir::Instruction::Raw { .. }))));
    assert_eq!(
        analysis
            .program
            .blocks
            .values()
            .flat_map(|block| &block.instructions)
            .filter(|i| matches!(i, luau_devirt::ir::Instruction::Call { .. }))
            .count(),
        8
    );
    assert!(!analysis.trace.is_empty(), "analysis must trace the root");

    for row in &analysis.trace {
        // Compile-time pin of the public trace-row contract; values other than
        // the dispatch/frame invariants are deliberately not asserted.
        let _end_pc: usize = row.end_pc;
        let _selector: i64 = row.selector;
        let _instructions = &row.instructions;
        let family = vm
            .dispatch_families
            .get(&row.state.token)
            .unwrap_or_else(|| panic!("undispatched trace token {}", row.state.token));
        assert_eq!(*family, row.family, "trace family/token mismatch");
        assert!(
            (row.state.bank as usize) < vm.slot_map.len(),
            "trace bank {} outside the register map",
            row.state.bank
        );
        assert!(row.state.pc <= vm.raw_words.len());
        for (_, successor) in &row.successors {
            assert!((successor.bank as usize) < vm.slot_map.len());
            assert!(successor.pc <= vm.raw_words.len());
        }
    }

    // Compile-time pin of the remaining public analysis fields.
    let _strings: &std::collections::BTreeMap<u32, Vec<u8>> = &analysis.strings;
    let _numbers: &std::collections::BTreeMap<u32, u64> = &analysis.numbers;

    // `walk_cfg` routes this profile through the same analysis; both entry
    // points must produce one identical program.
    let walked = walk_cfg(&vm).expect("walk_cfg on the Base85 profile");
    assert_eq!(analysis.program, walked);
    assert!(
        !analysis.program.blocks.is_empty(),
        "analysis produced no basic blocks"
    );

    let emitted =
        emit_luau(&analysis.program, &CodegenOptions::default()).expect("emit readable Luau");
    assert!(!emitted.trim().is_empty(), "emitted Luau must not be empty");
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
            "missing recovered logic: {expected}\n{emitted}"
        );
    }
    for unresolved in [
        "buffer.",
        "_b85",
        "loadstring",
        "vm_unknown",
        "FIXME",
        "table.pack",
        "goto",
    ] {
        assert!(
            !emitted.contains(unresolved),
            "unresolved VM machinery: {unresolved}"
        );
    }
    for block in analysis.program.blocks.values() {
        for successor in &block.successors {
            if let Some(target) = successor.target_pc {
                assert!(analysis.program.blocks.contains_key(&target));
            }
        }
    }
}

#[test]
fn whitespace_and_comment_rewrites_are_accepted_with_identical_data() {
    let source = rotor_source();
    let baseline = decode_source(&source).expect("baseline decode");
    let needle = "local bw=r32(B,8);";
    assert_eq!(
        source.matches(needle).count(),
        1,
        "expected one unique rotor header statement"
    );
    let reformatted = source.replacen(needle, "local   bw  =  r32 ( B , 8 ) ;", 1);
    let changed = format!("-- reformatted review copy\n{reformatted}");
    let actual = decode_source(&changed).expect("comments and spacing are not formulas");

    assert_eq!(baseline.payload, actual.payload);
    assert_eq!(baseline.raw_words, actual.raw_words);
    assert_eq!(baseline.decoded_words, actual.decoded_words);
    assert_eq!(baseline.master_key, actual.master_key);
    assert_eq!(baseline.decoded_range, actual.decoded_range);
    assert_eq!(baseline.slot_map, actual.slot_map);
    assert_eq!(baseline.immediate_biases, actual.immediate_biases);
    assert_eq!(baseline.prototypes, actual.prototypes);
}

#[test]
fn changed_wrapper_formulas_and_alphabet_are_rejected() {
    let source = rotor_source();
    let baseline = decode_source(&source).expect("baseline decode");
    for (before, after) in [
        ("m0*28595+624331951", "m0*28594+624331951"),
        (
            "K1=bxor(1542308556,432963489)",
            "K1=bxor(1542308555,432963489)",
        ),
        ("rk*2185+3437004073", "rk*2186+3437004073"),
        ("g9I@0_~Xn;6", "g9I@0_~Xn;7"),
    ] {
        assert_eq!(
            source.matches(before).count(),
            1,
            "mutation target {before:?} must be unique"
        );
        let changed = source.replacen(before, after, 1);
        assert_ne!(changed, source);
        let error = decode_source(&changed)
            .expect_err("a changed certified wrapper token must fail closed");
        assert!(!error.is_empty());
    }
    // The baseline itself is unchanged by the loop above.
    assert_eq!(baseline.master_key, 2_484_975_588);
}

#[test]
fn truncated_fixture_inputs_fail_without_panicking() {
    let source = rotor_source();
    let (encoded, alphabet) = {
        let vm = decode_source(&source).expect("baseline decode");
        let (encoded, alphabet) = encoded_and_alphabet(&vm);
        (encoded.to_vec(), alphabet.to_vec())
    };
    for cut in [encoded.len() - 1, encoded.len() - 5, encoded.len() / 2] {
        assert!(decode_transport(&encoded[..cut], &alphabet, PAYLOAD_LEN).is_err());
    }

    // Removing characters only from the payload literal leaves the certified
    // wrapper skeleton intact, so the length/bounds checks must reject it.
    let marker = "_b85=bfrom(\"";
    let start = source.find(marker).expect("payload literal marker") + marker.len();
    let end = start
        + source[start..]
            .find('"')
            .expect("payload literal terminator");
    for drop in [1usize, 5] {
        let truncated = format!("{}{}", &source[..end - drop], &source[end..]);
        let result = std::panic::catch_unwind(|| decode_source(&truncated));
        assert!(
            result.is_ok(),
            "decoder panicked on a {drop}-byte truncation"
        );
        assert!(
            result.unwrap().is_err(),
            "a {drop}-byte transport truncation must be rejected"
        );
    }

    let mut cut = source.len() / 2;
    while !source.is_char_boundary(cut) {
        cut -= 1;
    }
    for truncated in ["", &source[..cut]] {
        let result = std::panic::catch_unwind(|| decode_source(truncated));
        assert!(result.is_ok(), "decoder panicked on truncated wrapper text");
        assert!(result.unwrap().is_err());
    }
}

#[test]
fn older_non_base85_sample_still_decodes_and_walks() {
    let source = fixture(OLDER_FIXTURE);
    let vm = decode_source(&source).expect("the pre-existing profile must keep decoding");
    assert!(
        !is_profile(&vm),
        "older sample must not take the Base85 route"
    );
    assert!(!vm.payload.is_empty());
    assert_eq!(vm.payload.len() % 4, 0);
    walk_cfg(&vm).expect("the older profile must keep walking");
}
