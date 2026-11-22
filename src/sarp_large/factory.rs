//! Source-proved factory descriptor/code layer. No closure or coroutine is
//! invoked: AF's bounded word-key stream is transcribed as cipher arithmetic.
use super::lift::{Fact, FactoryRequest, State};
use super::{slot, BOOT_TAG};
use crate::ir::*;
use std::collections::BTreeMap;

pub(super) fn decrypt_code(vm: &mut DecodedVm, request: &FactoryRequest) -> Result<(), String> {
    if request.code_length == 0 {
        return Ok(());
    }
    let p = &request.prototype;
    let end = request
        .code_start
        .checked_add(request.code_length)
        .ok_or("lazy code extent overflow")?;
    let range_end = vm
        .decoded_range
        .1
        .checked_add(1)
        .ok_or("lazy cipher working range overflow")?;
    if request.code_start < vm.decoded_range.0 || end > range_end {
        return Err("lazy code outside initialized W range".to_owned());
    }
    let mut state = vm.master_key
        ^ request.mask
        ^ (p.prototype_salt as u32).wrapping_mul(65537)
        ^ p.initial_decode_state
        ^ 546595050
        ^ (p.initial_decode_state.leading_zeros()
            + (p.prototype_salt as u32).trailing_zeros() * 257);
    for index in request.code_start..end {
        state = state.wrapping_mul(6405).wrapping_add(483291509);
        state = state.rotate_left(6) ^ (state >> 13);
        let word = vm
            .decoded_words
            .get_mut(index)
            .and_then(Option::as_mut)
            .ok_or("lazy cipher references absent W word")?;
        *word ^= state;
    }
    Ok(())
}

pub(super) fn initial_state(
    vm: &DecodedVm,
    prototype: &Prototype,
    pool_key: u32,
) -> Result<State, String> {
    let controls = [15usize, 3, 7, 9, 17, 18, 33, 21, 6, 29, 24, 2, 23, 5, 12]
        .into_iter()
        .map(|index| slot(vm, index))
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    let mut facts = BTreeMap::new();
    let root = prototype.word == vm.entry_prototype;
    let mut initialized = std::collections::BTreeSet::new();
    if root {
        for raw in 1..=71u16 {
            if !controls.contains(&raw) {
                facts.insert(raw, Fact::Nil);
                initialized.insert(raw);
            }
        }
        facts.insert(72, Fact::Nil);
        facts.insert(73, Fact::Nil);
        initialized.extend([72, 73]);
    }
    for offset in [5, 6] {
        facts.remove(&slot(vm, prototype.bank_base as usize + offset)?);
    }
    for (index, offset) in prototype.parameter_operands.iter().enumerate() {
        if index == 0 && (root || *offset == 0) {
            continue;
        }
        let raw = logical_slot(
            vm,
            prototype,
            slot(vm, prototype.bank_base as usize + *offset as usize)?,
        )?;
        facts.remove(&raw);
        initialized.insert(raw);
    }
    for capture in &prototype.captures {
        let raw = logical_slot(
            vm,
            prototype,
            slot(
                vm,
                prototype.bank_base as usize + capture.destination_operand as usize,
            )?,
        )?;
        facts.remove(&raw);
        initialized.insert(raw);
    }
    Ok(State {
        prototype: prototype.word,
        pc: prototype.entry_pc,
        key: prototype.initial_decode_state.wrapping_add(BOOT_TAG),
        bank: prototype.bank_base,
        token: prototype.dispatch_token,
        salt: prototype.prototype_salt,
        phase: 0,
        window: 0,
        bank_end: 0,
        pool_key,
        facts,
        initialized,
    })
}

/// Only the root is known fresh. Child frames receive explicit parameter and
/// capture copies; read-before-write guards prove retained cached cells unused.
/// These are IR operations, never reconstructed original names.
pub(super) fn frame_prefix(
    vm: &DecodedVm,
    p: &Prototype,
    root: bool,
) -> Result<Vec<Instruction>, String> {
    let controls = [15usize, 3, 7, 9, 17, 18, 33, 21, 6, 29, 24, 2, 23, 5, 12]
        .into_iter()
        .map(|index| slot(vm, index))
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    let mut output = vec![];
    if root {
        for raw in 1..=71u16 {
            if !controls.contains(&raw) {
                output.push(Instruction::LoadConst {
                    dst: Register { physical_slot: raw },
                    value: Constant::Nil,
                });
            }
        }
        for raw in [72, 73] {
            output.push(Instruction::LoadConst {
                dst: Register { physical_slot: raw },
                value: Constant::Nil,
            });
        }
    }
    if !p.fixed_parameter_mode {
        output.push(Instruction::Move {
            dst: Register {
                physical_slot: slot(vm, 9)?,
            },
            src: Operand::SlotMapIndex(3),
        });
    }
    for (index, offset) in p.parameter_operands.iter().enumerate() {
        // boot seeds v0 in the raw rotor and copies only parameters 1..3;
        // AF's fixed-arity wrappers additionally copy positive a0.
        if index == 0 && (root || *offset == 0) {
            continue;
        }
        let raw = logical_slot(vm, p, slot(vm, p.bank_base as usize + *offset as usize)?)?;
        output.push(Instruction::Move {
            dst: Register { physical_slot: raw },
            src: Operand::Argument(index),
        });
    }
    for (index, capture) in p.captures.iter().enumerate() {
        let raw = logical_slot(
            vm,
            p,
            slot(
                vm,
                p.bank_base as usize + capture.destination_operand as usize,
            )?,
        )?;
        output.push(Instruction::Move {
            dst: Register { physical_slot: raw },
            src: Operand::Capture(index),
        });
    }
    Ok(output)
}

fn logical_slot(vm: &DecodedVm, p: &Prototype, raw: u16) -> Result<u16, String> {
    for index in [15usize, 3, 7, 9, 17, 18, 33, 21, 6, 29, 24, 2, 23, 5, 12] {
        if raw == slot(vm, index)? {
            return Err("parameter/capture aliases private frame metadata".to_owned());
        }
    }
    if raw == slot(vm, p.bank_base as usize + 9)? {
        return Ok(72);
    }
    if raw == slot(vm, p.bank_base as usize + 10)? {
        return Ok(73);
    }
    if raw == slot(vm, p.bank_base as usize + 5)? || raw == slot(vm, p.bank_base as usize + 6)? {
        return Err("parameter/capture aliases a rotor or phase cell".to_owned());
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lazy_code_and_descriptor_match_independent_source_reference() {
        let mut vm =
            crate::decode_source(include_str!("../../tests/fixtures/protected.luau")).unwrap();
        let p = super::super::prototype(&vm, 140545, 1648417297).unwrap();
        assert_eq!(
            (
                p.entry_pc,
                p.initial_decode_state,
                p.prototype_salt,
                p.bank_base
            ),
            (136924, 1528981884, 38408, 94)
        );
        assert_eq!(p.fixed_parameter_count, Some(1));
        assert!(p.captures.is_empty());
        let request = FactoryRequest {
            prototype: p,
            mask: 1648417297,
            code_start: 136680,
            code_length: 559,
            captured: vec![],
        };
        decrypt_code(&mut vm, &request).unwrap();
        assert_eq!(
            vm.decoded_words[136680..136688],
            [
                901804203, 3234662875, 3393843272, 2530519904, 476078138, 902908239, 1039459704,
                3896181562
            ]
            .map(Some)
        );
        let bytes = vm.decoded_words[136680..137239]
            .iter()
            .flat_map(|word| word.unwrap().to_le_bytes())
            .collect::<Vec<_>>();
        assert_eq!(
            crate::decoder::sha256_hex(&bytes),
            "75a889db15746511c3fcbfe5bcf159dc7d5f756c067076f02de1ba295837cc63"
        );
    }
    #[test]
    fn children_do_not_invent_fresh_cached_frame_nil_values() {
        let vm = crate::decode_source(include_str!("../../tests/fixtures/protected.luau")).unwrap();
        let p = super::super::prototype(&vm, 140545, 1648417297).unwrap();
        let state = initial_state(&vm, &p, 1648390755).unwrap();
        assert!(state.facts.is_empty());
        assert_eq!(state.initialized, std::collections::BTreeSet::from([72]));
        let prefix = frame_prefix(&vm, &p, false).unwrap();
        assert!(prefix.iter().all(|instruction| matches!(
            instruction,
            Instruction::Move {
                src: Operand::Argument(_) | Operand::Capture(_),
                ..
            }
        )));
        let root = initial_state(&vm, &vm.prototypes[0], super::super::INITIAL_K1).unwrap();
        assert_eq!(root.facts.get(&72), Some(&Fact::Nil));
    }
    #[test]
    fn retained_cached_data_is_rejected_until_a_local_write() {
        let vm = crate::decode_source(include_str!("../../tests/fixtures/protected.luau")).unwrap();
        let p = super::super::prototype(&vm, 140545, 1648417297).unwrap();
        let init = super::super::initialize_data(&vm.payload, vm.initialization_argument)
            .unwrap()
            .3;
        let model = super::super::model::Model::read(&vm).unwrap();
        let state = initial_state(&vm, &p, 1648390755).unwrap();
        let family = model.families.get(&2094).unwrap();
        let (mut strings, mut numbers) = (BTreeMap::new(), BTreeMap::new());
        let mut context = super::super::lift::Context::new(
            &vm,
            &model,
            family,
            &init,
            &state,
            256,
            &mut strings,
            &mut numbers,
        )
        .unwrap();
        let raw = slot(&vm, p.bank_base as usize + 10).unwrap();
        let expression = super::super::model::E::Index(
            Box::new(super::super::model::E::Id("F".to_owned())),
            Box::new(super::super::model::E::Int(raw as i64)),
        );
        let error = context.eval(&expression).unwrap_err();
        assert!(error.contains("cached-frame contents are unsupported"));
        context.put(73, Operand::Constant(Constant::Nil));
        assert!(context.eval(&expression).is_ok());
        assert_eq!(context.state.facts.get(&73), Some(&Fact::Nil));
    }
}
