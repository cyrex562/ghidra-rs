//! Port of `ghidra.bitpatterns.info.FunctionBitPatternInfo`.

use std::collections::BTreeMap;

use crate::feature::bitpatterns::info::context_register_info::ContextRegisterInfo;
use crate::feature::bitpatterns::info::data_gathering_params::DataGatheringParams;
use crate::feature::seam_stubs::InstructionSequence;
use crate::program::model::address::address_set::AddressSetView;
use crate::program::model::address::Address;
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::function::Function;
use crate::program::model::listing::instruction::Instruction;
use crate::program::model::listing::listing::Listing;
use crate::program::model::listing::program::Program;
use crate::program::model::mem::memory::Memory;
use crate::program::model::symbol::ref_type::RefType;

/// XML element name used when serialising this type.
pub const XML_ELEMENT_NAME: &str = "FunctionBitPatternInfo";

/// Information about the small neighbourhoods around the start and the returns of a single
/// function.
///
/// Mirrors `ghidra.bitpatterns.info.FunctionBitPatternInfo`. Every Java field that is nullable
/// (`preBytes`, `firstBytes`, `address`, `firstInst`, `preInst`, `contextRegisters`) is an
/// `Option` here; the two list fields are always-present `Vec`s, matching the Java no-arg
/// constructor which allocates them eagerly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FunctionBitPatternInfo {
    first_inst: Option<InstructionSequence>,
    pre_inst: Option<InstructionSequence>,
    return_inst: Vec<InstructionSequence>,

    /// The (hexlified) bytes immediately preceding a function start.
    pre_bytes: Option<String>,
    /// The first bytes of a function.
    first_bytes: Option<String>,
    /// For each return in the function, the nearby bytes.
    return_bytes: Vec<String>,
    /// The offset of a function.
    address: Option<String>,

    /// The values for each of the specified context registers.
    context_registers: Option<Vec<ContextRegisterInfo>>,
}

/// Java: `FunctionBitPatternInfo.getBytesAsString(byte[])` - lowercase hex, two digits per byte.
fn get_bytes_as_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

impl FunctionBitPatternInfo {
    /// Java: the no-arg constructor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Gathers information about `func` using the supplied [`DataGatheringParams`].
    ///
    /// Mirrors `FunctionBitPatternInfo(Program, Function, DataGatheringParams)`. The function
    /// body is passed explicitly because `Function` does not yet expose `getBody()` in the ported
    /// trait; every other input is taken from `program`/`func` exactly as the Java constructor
    /// does.
    ///
    /// Java iterates the return sites over a `HashMap` key set, so their order is unspecified;
    /// this port walks them in ascending address order so that `return_bytes`/`return_inst` are
    /// reproducible.
    pub fn gather(
        program: &mut dyn Program,
        func: &dyn Function,
        body: &dyn AddressSetView,
        params: &DataGatheringParams,
    ) -> Self {
        let mut info = Self::new();

        // Java guards on `params.getContextRegisters() != null`; the ported params type returns an
        // empty slice where Java holds null, so an empty list means "no context registers asked
        // for" and leaves the field unset.
        if !params.get_context_registers().is_empty() {
            info.context_registers = Some(record_context_register_info(
                program,
                func,
                params.get_context_registers(),
            ));
        }

        let memory = program.get_memory();
        let start = func.get_entry_point();

        // Record the starting address. In case the name of the space is part of the address
        // string, keep only the part after the colon.
        let addr_string = start.to_string();
        info.address = Some(match addr_string.find(':') {
            Some(colon_index) => addr_string[colon_index + 1..].to_string(),
            None => addr_string,
        });

        let listing = match program.get_listing() {
            Some(listing) => listing,
            None => return info,
        };

        let first_inst = get_instructions_follow_flow(
            params.get_num_first_instructions(),
            &*listing,
            &start,
            body,
        );

        // Retreat to the address immediately before the function start.
        let pre_inst = match start.subtract_no_wrap(1) {
            Ok(pre) => Some(get_instructions_against_flow(
                params.get_num_pre_instructions(),
                &*listing,
                &pre,
                None,
            )),
            Err(_) => None,
        };

        // Get the return bytes and return instructions. First iterate through all the
        // instructions to find returns; the length of each return instruction is needed to know
        // where to start recording bytes.
        let mut returns_to_sizes: BTreeMap<Address, i32> = BTreeMap::new();
        for instruction in listing.get_instructions_in(body, true) {
            if is_return_flow(instruction.get_flow_type()) {
                returns_to_sizes.insert(instruction.get_min_address(), instruction.get_length());
            }
        }

        let mut return_inst = Vec::new();
        let mut return_bytes = Vec::new();
        for (current_address, length) in &returns_to_sizes {
            let return_instructions = get_instructions_against_flow(
                params.get_num_return_instructions(),
                &*listing,
                current_address,
                Some(body),
            );
            return_inst.push(return_instructions.clone());

            let Ok(adjusted_address) = current_address.add_no_wrap((*length - 1) as i64) else {
                continue;
            };
            let num_return_bytes = filled_size(&return_instructions).max(params.get_num_return_bytes());
            if let Some(memory) = memory.as_deref() {
                if let Some(bytes) =
                    get_bytes_against_flow(num_return_bytes, memory, &adjusted_address)
                {
                    return_bytes.push(get_bytes_as_string(&bytes));
                }
            }
        }

        if let Some(memory) = memory.as_deref() {
            // Get the first bytes: want enough bytes to capture all of the instructions, but
            // don't want to go outside of the function.
            let num_first_bytes = filled_size(&first_inst)
                .max(params.get_num_first_bytes())
                .min(body.num_addresses() as i32);
            info.first_bytes = Some(get_bytes_as_string(&get_bytes_with_flow(
                num_first_bytes,
                memory,
                &start,
            )));

            // Get the preBytes.
            if let (Some(pre_inst), Ok(adjusted_address)) = (&pre_inst, start.add_no_wrap(-1)) {
                let num_pre_bytes = filled_size(pre_inst).max(params.get_num_pre_bytes());
                if let Some(bytes) =
                    get_bytes_against_flow(num_pre_bytes, memory, &adjusted_address)
                {
                    info.pre_bytes = Some(get_bytes_as_string(&bytes));
                }
            }
        }

        info.first_inst = Some(first_inst);
        info.pre_inst = pre_inst;
        info.return_inst = return_inst;
        info.return_bytes = return_bytes;
        info
    }

    /// Get the sequence of first instructions of the function.
    pub fn get_first_inst(&self) -> Option<&InstructionSequence> {
        self.first_inst.as_ref()
    }

    /// Set the sequence of first instructions of the function.
    pub fn set_first_inst(&mut self, first_inst: Option<InstructionSequence>) {
        self.first_inst = first_inst;
    }

    /// Get the sequence of instructions immediately before the function.
    pub fn get_pre_inst(&self) -> Option<&InstructionSequence> {
        self.pre_inst.as_ref()
    }

    /// Set the sequence of instructions immediately before the function.
    pub fn set_pre_inst(&mut self, pre_inst: Option<InstructionSequence>) {
        self.pre_inst = pre_inst;
    }

    /// Get the list of sequences of instructions immediately before a return instruction.
    pub fn get_return_inst(&self) -> &[InstructionSequence] {
        &self.return_inst
    }

    /// Set the list of sequences of instructions immediately before a return instruction.
    pub fn set_return_inst(&mut self, return_inst: Vec<InstructionSequence>) {
        self.return_inst = return_inst;
    }

    /// Get the string representation of the bytes immediately before a function.
    pub fn get_pre_bytes(&self) -> Option<&str> {
        self.pre_bytes.as_deref()
    }

    /// Set the string representation of the bytes immediately before a function.
    pub fn set_pre_bytes(&mut self, pre_bytes: Option<String>) {
        self.pre_bytes = pre_bytes;
    }

    /// Get the string representation of the first bytes of a function.
    pub fn get_first_bytes(&self) -> Option<&str> {
        self.first_bytes.as_deref()
    }

    /// Set the string representation of the first bytes of a function.
    pub fn set_first_bytes(&mut self, first_bytes: Option<String>) {
        self.first_bytes = first_bytes;
    }

    /// Get the string representations of the bytes immediately before (and including) a return
    /// instruction.
    pub fn get_return_bytes(&self) -> &[String] {
        &self.return_bytes
    }

    /// Set the string representations of the bytes immediately before (and including) a return
    /// instruction.
    pub fn set_return_bytes(&mut self, return_bytes: Vec<String>) {
        self.return_bytes = return_bytes;
    }

    /// Get the string representation of the address of the entry point of the function.
    pub fn get_address(&self) -> Option<&str> {
        self.address.as_deref()
    }

    /// Set the string representation of the address of the entry point of the function.
    pub fn set_address(&mut self, address: Option<String>) {
        self.address = address;
    }

    /// Get the context register names and values for a function.
    pub fn get_context_registers(&self) -> Option<&[ContextRegisterInfo]> {
        self.context_registers.as_deref()
    }

    /// Set the context register names and values for a function.
    pub fn set_context_registers(&mut self, context_registers: Option<Vec<ContextRegisterInfo>>) {
        self.context_registers = context_registers;
    }
}

impl std::fmt::Display for FunctionBitPatternInfo {
    /// Mirrors `FunctionBitPatternInfo.toString()`. Java renders unset (null) strings as the
    /// literal text `null`, which this reproduces.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(context_registers) = &self.context_registers {
            write!(f, "Registers: ")?;
            for info in context_registers {
                write!(f, "{}: ", info.get_context_register())?;
                match info.get_value() {
                    Some(value) => write!(f, "{} ", value)?,
                    None => write!(f, "null ")?,
                }
            }
            writeln!(f)?;
        }
        writeln!(f, "Prebytes: {}", self.pre_bytes.as_deref().unwrap_or("null"))?;
        if let Some(pre_inst) = &self.pre_inst {
            write!(f, "preInstructions: {}", pre_inst)?;
        }
        write!(f, "\nAddress: {}", self.address.as_deref().unwrap_or("null"))?;
        write!(f, "\nfirstInstructions: ")?;
        match &self.first_inst {
            Some(first_inst) => write!(f, "{}", first_inst)?,
            None => write!(f, "null")?,
        }
        write!(
            f,
            "\nfirstBytes: {}",
            self.first_bytes.as_deref().unwrap_or("null")
        )?;
        write!(f, "\nreturns:")?;
        for (i, bytes) in self.return_bytes.iter().enumerate() {
            write!(f, "\n  bytes:\n   {}", bytes)?;
            write!(f, "\n  inst:\n   ")?;
            match self.return_inst.get(i) {
                Some(inst) => write!(f, "{}", inst)?,
                None => write!(f, "null")?,
            }
        }
        Ok(())
    }
}

/// Sums the recorded instruction sizes, stopping at the first slot that was never filled.
///
/// Java writes this loop out three times (`for (Integer size : ...) { if (size == null) break; }`).
fn filled_size(sequence: &InstructionSequence) -> i32 {
    let mut total = 0;
    for size in sequence.get_sizes() {
        match size {
            Some(size) => total += *size,
            None => break,
        }
    }
    total
}

/// The flow types that Java's constructor treats as function returns.
fn is_return_flow(flow_type: RefType) -> bool {
    matches!(
        flow_type,
        RefType::CallTerminator
            | RefType::Terminator
            | RefType::ConditionalCallTerminator
            | RefType::ConditionalTerminator
    )
}

/// Java: `getBytesAgainstFlow`. Returns `None` when there are no bytes immediately before the
/// start address, when reading them would cross into another memory block, or when the read
/// fails (Java's `MemoryAccessException` path).
fn get_bytes_against_flow(num_bytes: i32, memory: &dyn Memory, start: &Address) -> Option<Vec<u8>> {
    if num_bytes < 0 {
        return None;
    }
    let current_block = memory.get_block(start)?;
    let pre = start.subtract_no_wrap((num_bytes - 1) as i64).ok()?;
    // Don't want to extend into another section.
    let pre_block = memory.get_block(&pre)?;
    if current_block.get_start() != pre_block.get_start() {
        return None;
    }
    let mut bytes = vec![0u8; num_bytes as usize];
    if memory.get_bytes(&pre, &mut bytes) != bytes.len() {
        return None;
    }
    Some(bytes)
}

/// Java: `getBytesWithFlow`. Java swallows `MemoryAccessException` and returns the (partially
/// zero-filled) buffer, which this reproduces.
fn get_bytes_with_flow(num_bytes: i32, memory: &dyn Memory, start: &Address) -> Vec<u8> {
    let mut bytes = vec![0u8; num_bytes.max(0) as usize];
    memory.get_bytes(start, &mut bytes);
    bytes
}

/// Java: `getInstructionsAgainstFlow`. Walks backwards from the instruction containing
/// `start_address`, stopping early at a memory-access failure or at the first instruction outside
/// `valid_addresses` (when that set is supplied).
fn get_instructions_against_flow(
    num_instructions: i32,
    listing: &dyn Listing,
    start_address: &Address,
    valid_addresses: Option<&dyn AddressSetView>,
) -> InstructionSequence {
    let num_instructions = num_instructions.max(0) as usize;
    let mut instructions = InstructionSequence::with_length(num_instructions);

    let mut current = listing.get_instruction_containing(start_address);
    for j in 0..num_instructions {
        let Some(pre_instruction) = current else {
            break;
        };
        if let Some(valid_addresses) = valid_addresses {
            if !valid_addresses.contains(&pre_instruction.get_min_address()) {
                break;
            }
        }
        let Ok(bytes) = CodeUnit::get_bytes(&*pre_instruction) else {
            break;
        };
        instructions.instructions_mut()[j] = Some(pre_instruction.get_mnemonic_string());
        instructions.sizes_mut()[j] = Some(bytes.len() as i32);
        instructions.comma_separated_operands_mut()[j] = Some(operands_csv(&*pre_instruction));
        current = pre_instruction.get_previous();
    }
    instructions
}

/// Java: `getInstructionsFollowFlow`. Java re-fetches the function from the entry point; this
/// port takes the already-resolved entry point and body instead.
fn get_instructions_follow_flow(
    num_instructions: i32,
    listing: &dyn Listing,
    entry_point: &Address,
    body: &dyn AddressSetView,
) -> InstructionSequence {
    let num_instructions = num_instructions.max(0) as usize;
    let mut instructions = InstructionSequence::with_length(num_instructions);
    let mut inst_iter = listing.get_instructions_in(body, true);

    for i in 0..num_instructions {
        // Out of instructions, stop.
        let Some(mut current_inst) = inst_iter.next() else {
            break;
        };

        // If a function contains a jump to a section of code which comes before its entry point
        // in memory, advance the iterator to the entry point.
        while current_inst.get_min_address() < *entry_point {
            match inst_iter.next() {
                Some(next) => current_inst = next,
                None => return instructions,
            }
        }

        let Ok(bytes) = CodeUnit::get_bytes(&*current_inst) else {
            break;
        };
        instructions.instructions_mut()[i] = Some(current_inst.get_mnemonic_string());
        instructions.sizes_mut()[i] = Some(bytes.len() as i32);
        instructions.comma_separated_operands_mut()[i] = Some(operands_csv(&*current_inst));
    }
    instructions
}

/// Builds the comma-separated string of default operand representations for an instruction.
fn operands_csv(instruction: &dyn Instruction) -> String {
    let num_operands = instruction.get_num_operands();
    let mut out = String::new();
    for k in 0..num_operands {
        out.push_str(&instruction.get_default_operand_representation(k));
        if k != num_operands - 1 {
            out.push(',');
        }
    }
    out
}

/// Java: `recordContextRegisterInfo`. Registers that the program does not know about keep a
/// `None` value (Java logs and continues).
fn record_context_register_info(
    program: &mut dyn Program,
    func: &dyn Function,
    context_regs: &[String],
) -> Vec<ContextRegisterInfo> {
    let mut context_register_info: Vec<ContextRegisterInfo> = context_regs
        .iter()
        .map(ContextRegisterInfo::with_register)
        .collect();

    let entry_point = func.get_entry_point();
    let registers: Vec<_> = context_register_info
        .iter()
        .map(|info| program.get_register(info.get_context_register()))
        .collect();

    let Some(program_context) = program.get_program_context() else {
        return context_register_info;
    };
    for (info, register) in context_register_info.iter_mut().zip(registers) {
        if let Some(register) = register {
            let value = program_context.get_value(&register.borrow(), &entry_point, false);
            info.set_value(value);
        }
    }
    context_register_info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_bytes_as_string_pads_single_hex_digits() {
        // Java: Integer.toHexString(b & 0xff), zero-padded to two characters.
        assert_eq!(get_bytes_as_string(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }

    #[test]
    fn test_get_bytes_as_string_treats_bytes_as_unsigned() {
        // Java's byte is signed; `b & 0xff` is what makes -1 render as "ff".
        assert_eq!(get_bytes_as_string(&[0x80, 0xff, 0x7f]), "80ff7f");
    }

    #[test]
    fn test_get_bytes_as_string_empty() {
        assert_eq!(get_bytes_as_string(&[]), "");
    }

    #[test]
    fn test_new_has_empty_lists_and_unset_fields() {
        let info = FunctionBitPatternInfo::new();
        assert!(info.get_return_bytes().is_empty());
        assert!(info.get_return_inst().is_empty());
        assert_eq!(info.get_pre_bytes(), None);
        assert_eq!(info.get_first_bytes(), None);
        assert_eq!(info.get_address(), None);
        assert!(info.get_context_registers().is_none());
    }

    #[test]
    fn test_accessors_round_trip() {
        let mut info = FunctionBitPatternInfo::new();
        info.set_pre_bytes(Some("90".to_string()));
        info.set_first_bytes(Some("554889e5".to_string()));
        info.set_address(Some("00401000".to_string()));
        info.set_return_bytes(vec!["c3".to_string(), "5dc3".to_string()]);

        let mut first = InstructionSequence::with_length(2);
        first.instructions_mut()[0] = Some("PUSH".to_string());
        first.sizes_mut()[0] = Some(1);
        first.comma_separated_operands_mut()[0] = Some("RBP".to_string());
        info.set_first_inst(Some(first));

        assert_eq!(info.get_pre_bytes(), Some("90"));
        assert_eq!(info.get_first_bytes(), Some("554889e5"));
        assert_eq!(info.get_address(), Some("00401000"));
        assert_eq!(info.get_return_bytes(), ["c3", "5dc3"]);
        assert_eq!(
            info.get_first_inst().unwrap().get_instructions()[0].as_deref(),
            Some("PUSH")
        );
        assert_eq!(info.get_first_inst().unwrap().get_sizes()[1], None);
    }

    #[test]
    fn test_filled_size_stops_at_first_unset_slot() {
        // Java sums sizes until it hits a null entry, so trailing sizes past a gap don't count.
        let mut seq = InstructionSequence::with_length(4);
        seq.sizes_mut()[0] = Some(1);
        seq.sizes_mut()[1] = Some(3);
        seq.sizes_mut()[3] = Some(100);
        assert_eq!(filled_size(&seq), 4);
    }

    #[test]
    fn test_is_return_flow_matches_java_flow_types() {
        assert!(is_return_flow(RefType::CallTerminator));
        assert!(is_return_flow(RefType::Terminator));
        assert!(is_return_flow(RefType::ConditionalCallTerminator));
        assert!(is_return_flow(RefType::ConditionalTerminator));
        // Not treated as returns by the Java constructor.
        assert!(!is_return_flow(RefType::UnconditionalJump));
        assert!(!is_return_flow(RefType::UnconditionalCall));
        assert!(!is_return_flow(RefType::ComputedCallTerminator));
        assert!(!is_return_flow(RefType::JumpTerminator));
    }

    #[test]
    fn test_display_matches_java_to_string_layout() {
        let mut info = FunctionBitPatternInfo::new();
        info.set_pre_bytes(Some("90".to_string()));
        info.set_first_bytes(Some("55".to_string()));
        info.set_address(Some("00401000".to_string()));
        info.set_return_bytes(vec!["c3".to_string()]);

        let mut first = InstructionSequence::with_length(1);
        first.instructions_mut()[0] = Some("PUSH".to_string());
        first.sizes_mut()[0] = Some(1);
        first.comma_separated_operands_mut()[0] = Some("RBP".to_string());
        info.set_first_inst(Some(first));

        let mut ret = InstructionSequence::with_length(1);
        ret.instructions_mut()[0] = Some("RET".to_string());
        ret.sizes_mut()[0] = Some(1);
        ret.comma_separated_operands_mut()[0] = Some(String::new());
        info.set_return_inst(vec![ret]);

        let mut cr = ContextRegisterInfo::with_register("TMode");
        cr.set_value(Some(1));
        info.set_context_registers(Some(vec![cr]));

        assert_eq!(
            info.to_string(),
            "Registers: TMode: 1 \n\
             Prebytes: 90\n\
             \nAddress: 00401000\
             \nfirstInstructions: PUSH:1 (RBP)\
             \nfirstBytes: 55\
             \nreturns:\
             \n  bytes:\n   c3\
             \n  inst:\n   RET:1 ()"
        );
    }

    #[test]
    fn test_display_renders_unset_fields_as_null() {
        // Java appends a null String as the text "null".
        let info = FunctionBitPatternInfo::new();
        let text = info.to_string();
        assert!(text.starts_with("Prebytes: null\n"));
        assert!(text.contains("\nAddress: null"));
        assert!(text.ends_with("\nreturns:"));
    }

    #[test]
    fn test_xml_element_name_constant() {
        assert_eq!(XML_ELEMENT_NAME, "FunctionBitPatternInfo");
    }
}
