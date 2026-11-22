//! Fourth-profile regression/adversarial checks. Protected source is inert;
//! every operation here is Rust parsing, cipher arithmetic or IR inspection.
use luau_devirt::{decode_source, ir::VmProfile, sarp_large};
use std::panic::{catch_unwind, AssertUnwindSafe};

const SOURCE: &str = include_str!("fixtures/protected.luau");
const ALPHABET: &[u8] =
    b"XzO+#ig=Jk[1qYc:@K)yuaH;~jew6srV7b<n3ptMBdUF$NECQ]foZ,^mT4.!>&52(G09D_hPRW%lI8?SLAxv|";

fn encode(value: u64, alphabet: &[u8]) -> Vec<u8> {
    let mut value = value;
    (0..5)
        .map(|_| {
            let digit = alphabet[(value % 85) as usize];
            value /= 85;
            digit
        })
        .collect()
}
fn transport_state(index: usize) -> u32 {
    let mut state = 577177045u32;
    for _ in 0..=index {
        state = state.wrapping_mul(15577).wrapping_add(3425539465);
    }
    state
}
fn failure(source: &str) {
    let result = catch_unwind(AssertUnwindSafe(|| decode_source(source)));
    assert!(result.is_ok(), "malformed source panicked");
    assert!(result.unwrap().is_err(), "malformed source was accepted");
}

fn change_number(source: &str, before: &str, after: &str) -> String {
    let bytes = source.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'"' || bytes[at] == b'\'' {
            let quote = bytes[at];
            at += 1;
            while at < bytes.len() {
                let byte = bytes[at];
                at += 1;
                if byte == b'\\' {
                    at = at.saturating_add(1).min(bytes.len());
                } else if byte == quote {
                    break;
                }
            }
            continue;
        }
        if bytes[at].is_ascii_digit() {
            let start = at;
            while at < bytes.len() && bytes[at].is_ascii_digit() {
                at += 1;
            }
            if &source[start..at] == before {
                return format!("{}{after}{}", &source[..start], &source[at..]);
            }
        } else {
            at += 1;
        }
    }
    panic!("critical numeric token {before} not found outside literals");
}

#[test]
fn pinned_large_source_selects_only_the_fourth_profile_and_derives_metadata() {
    assert_eq!(SOURCE.as_bytes().len(), 1014109);
    let vm = decode_source(SOURCE).unwrap();
    assert_eq!(vm.profile, VmProfile::SarpLarge);
    assert_eq!(
        vm.source_sha256.as_deref(),
        Some("1496f231da48222f5aa52d84829e9ad4ef5481eb237f56c6be1b9645dd7136fe")
    );
    assert_eq!(vm.payload.len(), 568176);
    assert_eq!(vm.raw_words.len(), 142044);
    assert_eq!(
        &vm.raw_words[..8],
        &[
            0xe747ff55, 0x162cbeb3, 0xd51d7a23, 0xc6c2a9ca, 0xbcdda2dd, 0x77fc4197, 0x5e3d7d16,
            0x88503b0b
        ]
    );
    assert_eq!(vm.decoded_range, (134160, 141177));
    assert_eq!(vm.decoded_words.iter().flatten().count(), 7022);
    assert!(vm.decoded_words[0].is_none());
    assert_eq!(vm.initialization_argument, 110391195);
    assert_eq!(vm.master_key, 3350847355);
    assert_eq!(vm.slot_map.len(), 1735);
    assert!(vm.slot_map[1..].iter().all(|v| (1..=71).contains(v)));
    assert_eq!(
        vm.slot_map[1..]
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        71
    );
    assert_eq!(vm.immediate_biases.len(), 65);
    assert_eq!(vm.entry_prototype, 134628);
    let root = &vm.prototypes[0];
    assert_eq!(
        (
            root.entry_pc,
            root.bank_base,
            root.frame_capacity,
            root.prototype_salt
        ),
        (138920, 40, 71, 53417)
    );
    assert!(root.captures.is_empty());
    assert!(!root.fixed_parameter_mode);
    assert_eq!(root.fixed_parameter_count, None);
    assert_eq!(
        vm.initial_strings.iter().map(Vec::len).collect::<Vec<_>>(),
        sarp_large::FRAGMENT_LENGTHS
    );
}

#[test]
fn transport_checks_digit_order_byteswap_wrapping_and_each_xor_state() {
    for (index, value) in [0x12345678u32, 0xdeadbeef, 0, 0xffffffff]
        .into_iter()
        .enumerate()
    {
        let encoded = encode(
            ((value ^ transport_state(index)).swap_bytes()) as u64,
            ALPHABET,
        );
        let mut input = vec![];
        for previous in 0..index {
            input.extend(encode(
                transport_state(previous).swap_bytes() as u64,
                ALPHABET,
            ));
        }
        input.extend(encoded);
        let output = sarp_large::decode_transport(&input, ALPHABET, (index + 1) * 4).unwrap();
        assert_eq!(&output[index * 4..], &value.to_le_bytes());
    }
    let value = 85u64.pow(5) - 1;
    let encoded = encode(value, ALPHABET);
    let expected = (value as u32).swap_bytes() ^ transport_state(0);
    assert_eq!(
        sarp_large::decode_transport(&encoded, ALPHABET, 4).unwrap(),
        expected.to_le_bytes()
    );
    let high = (128u16..=212).map(|v| v as u8).collect::<Vec<_>>();
    let encoded = encode(0x01020304, &high);
    assert_eq!(
        sarp_large::decode_transport(&encoded, &high, 4).unwrap(),
        (0x04030201u32 ^ transport_state(0)).to_le_bytes()
    );
}

#[test]
fn transport_malformed_inputs_are_rejected_without_padding_or_skipping() {
    let encoded = encode(0, ALPHABET);
    let mut duplicate = ALPHABET.to_vec();
    duplicate[84] = duplicate[0];
    for alphabet in [&ALPHABET[..84], duplicate.as_slice()] {
        assert!(sarp_large::decode_transport(&encoded, alphabet, 4).is_err());
    }
    let mut invalid = encoded.clone();
    invalid[2] = 0xff;
    for input in [&invalid[..], &encoded[..4], &[]] {
        assert!(sarp_large::decode_transport(input, ALPHABET, 4).is_err());
    }
    for bytes in [0usize, 3, 8, sarp_large::MAX_PAYLOAD + 4] {
        assert!(sarp_large::decode_transport(&encoded, ALPHABET, bytes).is_err());
    }
    let mut oversized = encoded;
    oversized.push(ALPHABET[0]);
    assert!(sarp_large::decode_transport(&oversized, ALPHABET, 4).is_err());
}

#[test]
fn four_fragment_copy_order_and_extents_are_exact() {
    let vm = decode_source(SOURCE).unwrap();
    let encoded = sarp_large::assemble_fragments(&vm.initial_strings).unwrap();
    assert_eq!(encoded.len(), 710220);
    assert_eq!(
        sarp_large::decode_transport(&encoded, ALPHABET, 568176).unwrap(),
        vm.payload
    );
    for (i, (&offset, &length)) in sarp_large::FRAGMENT_OFFSETS
        .iter()
        .zip(&sarp_large::FRAGMENT_LENGTHS)
        .enumerate()
    {
        assert_eq!(&encoded[offset..offset + length], &vm.initial_strings[i]);
    }
    assert!(sarp_large::assemble_fragments(&vm.initial_strings[..3]).is_err());
    let mut fragments = vm.initial_strings.clone();
    fragments.push(vec![]);
    assert!(sarp_large::assemble_fragments(&fragments).is_err());
    let mut fragments = vm.initial_strings.clone();
    fragments[2].pop();
    assert!(sarp_large::assemble_fragments(&fragments).is_err());
    let mut fragments = vm.initial_strings;
    fragments.swap(0, 1);
    assert!(sarp_large::assemble_fragments(&fragments).is_err());
}

#[test]
fn changed_critical_tokens_offsets_sizes_and_ciphers_fail_closed() {
    sarp_large::certify_source(SOURCE).unwrap();
    for (before, after) in [
        ("710220", "710221"),
        ("568176", "568172"),
        ("355113", "355112"),
        ("532672", "532673"),
        ("177562", "177561"),
        ("577177045", "577177044"),
        ("15577", "15579"),
        ("3425539465", "3425539464"),
        ("411395", "411397"),
        ("479499883", "479499885"),
        ("29983", "29985"),
        ("43122", "43123"),
        ("16973", "16975"),
        ("6405", "6407"),
    ] {
        assert!(SOURCE.contains(before));
        let changed = change_number(SOURCE, before, after);
        assert!(
            sarp_large::certify_source(&changed).is_err(),
            "{before} was not certified"
        );
        failure(&changed);
    }
    let duplicate = SOURCE.replacen(
        std::str::from_utf8(ALPHABET).unwrap(),
        "XzO+#ig=Jk[1qYc:@K)yuaH;~jew6srV7b<n3ptMBdUF$NECQ]foZ,^mT4.!>&52(G09D_hPRW%lI8?SLAxX|",
        1,
    );
    failure(&duplicate);
    failure(&SOURCE.replacen("local _pc3", "local _pc4", 1));
    failure(&(SOURCE.to_owned() + "\nlocal _pc4 = \"decoy\""));
}

#[test]
fn comments_and_whitespace_preserve_certification_without_identifier_heuristics() {
    let baseline = decode_source(SOURCE).unwrap();
    let decorated = format!("-- inert comment: _pc4 _b85 SARP\n{SOURCE}\n-- trailing comment\n");
    let vm = decode_source(&decorated).unwrap();
    assert_eq!(vm.profile, VmProfile::SarpLarge);
    assert_eq!(vm.payload, baseline.payload);
    assert_eq!(vm.decoded_words, baseline.decoded_words);
    assert_eq!(vm.slot_map, baseline.slot_map);
    for decoy in [
        "local _b85 = 'SARP'",
        "local _pc0 = 'X'; local _pc1='Y'; local _pc2='Z'; local _pc3='Q'",
        "-- SARP\nreturn 0",
    ] {
        assert!(sarp_large::certify_source(decoy).is_err());
        failure(decoy);
    }
    assert_eq!(
        decode_source(include_str!("fixtures/sarp.lua"))
            .unwrap()
            .profile,
        VmProfile::Sarp
    );
    assert_eq!(
        decode_source(include_str!("fixtures/base85-rotor.lua"))
            .unwrap()
            .profile,
        VmProfile::Base85Rotor3Bank
    );
    assert_eq!(
        decode_source(include_str!("fixtures/sample.lua"))
            .unwrap()
            .profile,
        VmProfile::Adler32Lcg5Word
    );
}

#[test]
fn truncated_source_and_invalid_initialization_do_not_panic() {
    for length in [0usize, 1, 32, 1000, SOURCE.len() / 2, SOURCE.len() - 1] {
        let mut end = length;
        while !SOURCE.is_char_boundary(end) {
            end -= 1;
        }
        failure(&SOURCE[..end]);
    }
    for length in [0usize, 4, 568172, 568180] {
        assert!(sarp_large::initialize_data(&vec![0; length], 110391195).is_err());
    }
    let input = " ".repeat(sarp_large::MAX_SOURCE + 1);
    assert!(decode_source(&input).is_err());
}

#[test]
fn incomplete_lifting_retains_proofs_and_rejects_iteration_instead_of_clean_output() {
    let vm = decode_source(SOURCE).unwrap();
    let error = sarp_large::analyze(&vm)
        .err()
        .expect("generic iterator semantics are not yet certified");
    assert!(error
        .message
        .contains("unsupported helper 25 generic iteration"));
    assert!(error.message.contains("structured-loop IR contract"));
    let failed = error.failed_state.as_ref().unwrap();
    assert_eq!((failed.prototype, failed.pc), (140804, 140992));
    assert!(
        !failed
            .facts
            .values()
            .any(|fact| matches!(fact, sarp_large::Fact::Nil)),
        "cached child frames must not inherit fresh nil facts"
    );
    assert!(error.trace.len() > 100);
    assert!(error.remaining_worklist > 0);
    let first = &error.trace[0];
    assert_eq!(
        (
            first.state.pc,
            first.successors[0].1.pool_key,
            first.successors[0].1.window
        ),
        (138920, 1648390755, 18)
    );
    let request = error
        .trace
        .iter()
        .flat_map(|row| &row.factories)
        .find(|request| request.prototype.word == 140545)
        .unwrap();
    assert_eq!(
        (request.mask, request.code_start, request.code_length),
        (1648417297, 136680, 559)
    );
    assert!(error.trace.iter().all(|row| row
        .instructions
        .iter()
        .all(|instruction| !matches!(instruction, luau_devirt::ir::Instruction::Raw { .. }))));
}

#[test]
fn bounded_analysis_and_mutable_metadata_cannot_bypass_source_proofs() {
    let vm = decode_source(SOURCE).unwrap();
    for limits in [
        sarp_large::AnalysisLimits {
            max_states: 0,
            ..Default::default()
        },
        sarp_large::AnalysisLimits {
            max_blocks: 0,
            ..Default::default()
        },
        sarp_large::AnalysisLimits {
            max_worklist_pops: 0,
            ..Default::default()
        },
    ] {
        let result = catch_unwind(AssertUnwindSafe(|| {
            sarp_large::analyze_with_limits(&vm, limits)
        }));
        assert!(result.is_ok());
        assert!(result
            .unwrap()
            .err()
            .unwrap()
            .message
            .contains("budget exceeded"));
    }
    for change in 0..6 {
        let mut altered = vm.clone();
        match change {
            0 => altered.raw_words[0] ^= 1,
            1 => {
                altered.dispatch_families.insert(4515, 2094);
            }
            2 => altered.decoded_words[134160] = Some(0),
            3 => altered.slot_map[1] ^= 1,
            4 => altered.source_sha256 = Some("fabricated".to_owned()),
            _ => altered.payload[0] ^= 1,
        }
        assert!(sarp_large::analyze(&altered)
            .err()
            .unwrap()
            .message
            .contains("certified source reconstruction"));
    }
}
