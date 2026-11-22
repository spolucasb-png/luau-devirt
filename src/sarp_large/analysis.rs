//! Bounded worklist traversal through the fourth profile's proven lifter.
use super::lift::{lift, Numbers, Strings};
use super::model::Model;
use super::{initialize_data, is_profile, prototype, State, TraceRow, INITIAL_K1, PROFILE};
use crate::ir::*;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::time::Instant;

#[derive(Clone, Copy, Debug)]
pub struct AnalysisLimits {
    pub max_states: usize,
    pub max_worklist_pops: usize,
    pub max_blocks: usize,
    pub max_instructions: usize,
    pub max_literal_bytes: usize,
    pub max_seconds: u64,
}
impl Default for AnalysisLimits {
    fn default() -> Self {
        Self {
            max_states: 32768,
            max_worklist_pops: 262144,
            max_blocks: 8192,
            max_instructions: 131072,
            max_literal_bytes: 16 * 1024 * 1024,
            max_seconds: 120,
        }
    }
}
impl AnalysisLimits {
    fn bounded(self) -> Self {
        let caps = Self::default();
        Self {
            max_states: self.max_states.min(caps.max_states),
            max_worklist_pops: self.max_worklist_pops.min(caps.max_worklist_pops),
            max_blocks: self.max_blocks.min(caps.max_blocks),
            max_instructions: self.max_instructions.min(caps.max_instructions),
            max_literal_bytes: self.max_literal_bytes.min(caps.max_literal_bytes),
            max_seconds: self.max_seconds.min(caps.max_seconds),
        }
    }
}

pub struct AnalysisError {
    pub message: String,
    pub failed_state: Option<State>,
    pub trace: Vec<TraceRow>,
    pub remaining_worklist: usize,
}
impl std::fmt::Debug for AnalysisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnalysisError")
            .field("message", &self.message)
            .field("failed_state", &self.failed_state)
            .field("completed_states", &self.trace.len())
            .field("remaining_worklist", &self.remaining_worklist)
            .finish()
    }
}
impl std::fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{PROFILE}: {}; completed {} states; {} pending states",
            self.message,
            self.trace.len(),
            self.remaining_worklist
        )
    }
}
impl std::error::Error for AnalysisError {}

pub struct Analysis {
    pub program: LiftedProgram,
    pub raw_program: LiftedProgram,
    pub trace: Vec<TraceRow>,
    pub strings: BTreeMap<u32, Vec<u8>>,
    pub numbers: BTreeMap<u32, u64>,
    pub prototypes: Vec<Prototype>,
    pub decoded_words: Vec<Option<u32>>,
}

fn operand_bytes(operand: &Operand) -> usize {
    match operand {
        Operand::Constant(Constant::String(value)) => value.len(),
        Operand::Expression(value) => match value.as_ref() {
            ValueExpression::Unary { value, .. }
            | ValueExpression::PermutationParity { value, .. } => operand_bytes(value),
            ValueExpression::Binary { left, right, .. }
            | ValueExpression::Index {
                table: left,
                index: right,
            } => operand_bytes(left) + operand_bytes(right),
        },
        _ => 0,
    }
}
fn instruction_bytes(instruction: &Instruction) -> usize {
    match instruction {
        Instruction::LoadConst {
            value: Constant::String(value),
            ..
        } => value.len(),
        Instruction::Move { src, .. } | Instruction::Unary { src, .. } => operand_bytes(src),
        Instruction::Binary { left, right, .. } => operand_bytes(left) + operand_bytes(right),
        Instruction::GetTable { table, index, .. } => operand_bytes(table) + operand_bytes(index),
        Instruction::SetTable {
            table,
            index,
            value,
        } => operand_bytes(table) + operand_bytes(index) + operand_bytes(value),
        Instruction::Call { function, args, .. } => {
            operand_bytes(function) + args.iter().map(operand_bytes).sum::<usize>()
        }
        Instruction::CallWithPackedArgs {
            function,
            prefix,
            arguments,
            ..
        } => {
            operand_bytes(function)
                + prefix.iter().map(operand_bytes).sum::<usize>()
                + operand_bytes(arguments)
        }
        Instruction::Append { table, value } | Instruction::PushPacked { table, value } => {
            operand_bytes(table) + operand_bytes(value)
        }
        Instruction::AppendPacked { table, values } => operand_bytes(table) + operand_bytes(values),
        Instruction::ReturnPacked { values } => operand_bytes(values),
        Instruction::Concat { values, .. } | Instruction::Return { values } => {
            values.iter().map(operand_bytes).sum()
        }
        Instruction::NewClosure { captures, .. } => captures.iter().map(operand_bytes).sum(),
        Instruction::Tag { value } => operand_bytes(value),
        Instruction::Compare { condition } | Instruction::Branch { condition, .. } => {
            match condition {
                Condition::Truthy(value) | Condition::Falsey(value) => operand_bytes(value),
                Condition::Compare { left, right, .. } => {
                    operand_bytes(left) + operand_bytes(right)
                }
            }
        }
        _ => 0,
    }
}

pub fn analyze(vm: &DecodedVm) -> Result<Analysis, AnalysisError> {
    analyze_with_limits(vm, AnalysisLimits::default())
}
pub fn analyze_with_limits(
    vm: &DecodedVm,
    limits: AnalysisLimits,
) -> Result<Analysis, AnalysisError> {
    let start = Instant::now();
    let limits = limits.bounded();
    let initial_error = |message: String| AnalysisError {
        message,
        failed_state: None,
        trace: vec![],
        remaining_worklist: 0,
    };
    if !is_profile(vm)
        || vm.source_text.len() > super::MAX_SOURCE
        || vm.payload.len() != super::TRANSPORT_BYTES
        || vm.raw_words.len() != 142044
        || vm.decoded_words.len() != 142045
        || vm.slot_map.len() != 1735
    {
        return Err(initial_error(
            "analysis requires a certified large SARP layout".to_owned(),
        ));
    }
    // A public DecodedVm is mutable. Re-certify/re-decode the inert source so
    // altered RT mappings, payload bytes, hashes or descriptor fields cannot
    // inherit a certificate from the enum tag alone.
    let tokens = crate::decoder::tokenize(&vm.source_text).map_err(initial_error)?;
    let certified = super::decode(&vm.source_text, &tokens).map_err(initial_error)?;
    if &certified != vm {
        return Err(initial_error(
            "decoded VM disagrees with certified source reconstruction".to_owned(),
        ));
    }
    drop(certified);
    drop(tokens);
    let (words, slots, biases, init) =
        initialize_data(&vm.payload, vm.initialization_argument).map_err(initial_error)?;
    if words != vm.decoded_words
        || slots != vm.slot_map
        || biases != vm.immediate_biases
        || init.master_key != vm.master_key
        || init.range != vm.decoded_range
    {
        return Err(initial_error(
            "decoded VM metadata disagrees with initializer proof".to_owned(),
        ));
    }
    let model = Model::read(vm).map_err(initial_error)?;
    let root = prototype(vm, vm.entry_prototype, 0).map_err(initial_error)?;
    if vm.prototypes.as_slice() != [root.clone()] {
        return Err(initial_error("root prototype metadata mismatch".to_owned()));
    }
    let mut working_vm = vm.clone();
    let initial =
        super::factory::initial_state(&working_vm, &root, INITIAL_K1).map_err(initial_error)?;
    let mut prototypes = BTreeMap::from([(root.word, root.clone())]);
    let mut factory_masks = BTreeMap::from([(root.word, 0u32)]);
    let mut code_ranges = Vec::<(usize, usize, usize)>::new();
    let mut entry_owners = BTreeMap::from([(root.entry_pc, root.word)]);
    let mut queue = VecDeque::from([initial]);
    let mut seen = HashSet::new();
    let mut trace = vec![];
    let (mut strings, mut numbers) = (Strings::new(), Numbers::new());
    let mut temp_ranges = BTreeMap::<usize, (u32, usize)>::new();
    let mut next_temp = 256u32;
    let (mut pops, mut instructions, mut literal_bytes) = (0usize, 0usize, 0usize);
    let mut blocks = BTreeMap::new();
    let mut pc_owners = BTreeMap::new();
    while let Some(state) = queue.pop_front() {
        let pending = queue.len();
        let failure = |message: String, trace: Vec<TraceRow>| AnalysisError {
            message,
            failed_state: Some(state.clone()),
            trace,
            remaining_worklist: pending,
        };
        pops += 1;
        if pops > limits.max_worklist_pops || start.elapsed().as_secs() > limits.max_seconds {
            return Err(failure(
                "worklist/time analysis budget exceeded".to_owned(),
                trace,
            ));
        }
        if !seen.insert(state.clone()) {
            continue;
        }
        if pc_owners
            .insert(state.pc, state.prototype)
            .is_some_and(|owner| owner != state.prototype)
        {
            return Err(failure(
                "shared instruction address across prototypes requires contextual CFG IDs"
                    .to_owned(),
                trace,
            ));
        }
        if seen.len() > limits.max_states || state.facts.len() > 128 {
            return Err(failure(
                "state/fact memory budget exceeded".to_owned(),
                trace,
            ));
        }
        if state.prototype == root.word
            && !working_vm
                .dispatch_families
                .get(&state.token)
                .is_some_and(|family| matches!(*family, 2094 | 2880 | 8415))
        {
            return Err(failure("root exec cannot dispatch this handler family; factory/alternate-driver analysis is required".to_owned(), trace));
        }
        let allocation = temp_ranges
            .get(&state.pc)
            .map(|(start, _)| *start)
            .unwrap_or(next_temp);
        let row = match lift(
            &working_vm,
            &model,
            &init,
            &state,
            allocation,
            &mut strings,
            &mut numbers,
        ) {
            Ok(row) => row,
            Err(error) => return Err(failure(error, trace)),
        };
        if let Some((_, count)) = temp_ranges.get(&state.pc) {
            if *count != row.temps {
                return Err(failure(
                    "state variants disagree on temporary bindings".to_owned(),
                    trace,
                ));
            }
        } else {
            temp_ranges.insert(state.pc, (next_temp, row.temps));
            next_temp = next_temp
                .checked_add(row.temps as u32)
                .filter(|value| *value <= 65536)
                .ok_or_else(|| {
                    failure(
                        "aggregate temporary-register budget exceeded".to_owned(),
                        vec![],
                    )
                })?;
        }
        instructions = instructions
            .checked_add(row.instructions.len())
            .ok_or_else(|| failure("instruction count overflow".to_owned(), vec![]))?;
        literal_bytes = literal_bytes
            .checked_add(
                row.instructions
                    .iter()
                    .map(instruction_bytes)
                    .sum::<usize>(),
            )
            .ok_or_else(|| failure("IR literal byte count overflow".to_owned(), vec![]))?;
        if instructions > limits.max_instructions
            || literal_bytes > limits.max_literal_bytes
            || strings.len() > 4096
            || strings.values().map(|(_, s)| s.len()).sum::<usize>() > 1024 * 1024
        {
            return Err(failure(
                "IR/constant aggregate allocation budget exceeded".to_owned(),
                trace,
            ));
        }
        let block = BasicBlock {
            start_pc: state.pc,
            end_pc: row.end_pc,
            handler_family: row.family,
            entry_states: vec![],
            instructions: row.instructions.clone(),
            successors: row
                .successors
                .iter()
                .map(|(label, next)| Successor {
                    label: label.clone(),
                    target_pc: Some(next.pc),
                    state: None,
                })
                .collect(),
        };
        if let Some(previous) = blocks.get(&state.pc) {
            if previous != &block {
                return Err(failure(
                    format!("state variants disagree on linked IR at PC {}", state.pc),
                    trace,
                ));
            }
        } else {
            blocks.insert(state.pc, block);
        }
        if blocks.len() > limits.max_blocks {
            return Err(failure("CFG block budget exceeded".to_owned(), trace));
        }
        for request in &row.factories {
            let p = &request.prototype;
            if let Some(old) = prototypes.get(&p.word) {
                if old != p || factory_masks.get(&p.word) != Some(&request.mask) {
                    return Err(failure(
                        "factory descriptor/key changes across creation sites".to_owned(),
                        trace,
                    ));
                }
                let end = request
                    .code_start
                    .checked_add(request.code_length)
                    .ok_or_else(|| failure("factory extent overflow".to_owned(), vec![]))?;
                if p.word != root.word && !code_ranges.contains(&(request.code_start, end, p.word))
                {
                    return Err(failure(
                        "factory lazy-code extent changes across creation sites".to_owned(),
                        trace,
                    ));
                }
                continue;
            }
            if prototypes.len() >= 1024 {
                return Err(failure("prototype count budget exceeded".to_owned(), trace));
            }
            if entry_owners.insert(p.entry_pc, p.word).is_some() {
                return Err(failure(
                    "overlapping prototype entry addresses require contextual CFG IDs".to_owned(),
                    trace,
                ));
            }
            let end = request
                .code_start
                .checked_add(request.code_length)
                .ok_or_else(|| failure("factory extent overflow".to_owned(), vec![]))?;
            if request.code_length > 0
                && code_ranges
                    .iter()
                    .any(|(start, stop, _)| request.code_start < *stop && end > *start)
            {
                return Err(failure(
                    "overlapping lazy-code layers cannot be guessed".to_owned(),
                    trace,
                ));
            }
            if request.code_length > 0
                && blocks
                    .values()
                    .any(|block| block.start_pc < end && request.code_start < block.end_pc)
            {
                return Err(failure(
                    "lazy factory layer overlaps already lifted instructions".to_owned(),
                    trace,
                ));
            }
            if let Err(message) = super::factory::decrypt_code(&mut working_vm, request) {
                return Err(failure(message, trace));
            }
            code_ranges.push((request.code_start, end, p.word));
            let child =
                match super::factory::initial_state(&working_vm, p, request.mask ^ super::SALT) {
                    Ok(state) => state,
                    Err(message) => return Err(failure(message, trace)),
                };
            prototypes.insert(p.word, p.clone());
            factory_masks.insert(p.word, request.mask);
            queue.push_back(child);
        }
        for (_, next) in &row.successors {
            queue.push_back(next.clone());
        }
        if queue.len() > limits.max_states * 2 {
            return Err(failure(
                "pending-state memory budget exceeded".to_owned(),
                trace,
            ));
        }
        trace.push(row);
    }
    for prototype in prototypes.values() {
        let prefix =
            super::factory::frame_prefix(&working_vm, prototype, prototype.word == root.word)
                .map_err(initial_error)?;
        let block = blocks
            .get_mut(&prototype.entry_pc)
            .ok_or_else(|| initial_error("discovered prototype entry was not lifted".to_owned()))?;
        block.instructions.splice(0..0, prefix);
    }
    let raw_program = LiftedProgram {
        reachable_pcs: blocks.keys().copied().collect(),
        blocks,
        entry_points: prototypes.values().map(|p| p.entry_pc).collect(),
        root_entry: Some(root.entry_pc),
        state_variants: seen.len(),
        prototype_entries: prototypes.values().map(|p| (p.word, p.entry_pc)).collect(),
        parameters: prototypes
            .values()
            .map(|p| {
                (
                    p.entry_pc,
                    if p.fixed_parameter_mode {
                        p.fixed_parameter_count.map(usize::from)
                    } else {
                        None
                    },
                )
            })
            .collect(),
        ..LiftedProgram::default()
    };
    // Keep unsupported compaction cases intact; the ordinary IR validator and
    // emitter decide whether they can be emitted without inventing semantics.
    let program = raw_program.clone();
    Ok(Analysis {
        program,
        raw_program,
        trace,
        strings: strings
            .into_iter()
            .map(|(r, (_, s))| (r, s.as_ref().clone()))
            .collect(),
        numbers: numbers.into_iter().map(|(r, (_, n))| (r, n)).collect(),
        prototypes: prototypes.into_values().collect(),
        decoded_words: working_vm.decoded_words,
    })
}
