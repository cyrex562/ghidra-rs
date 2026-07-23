//! Port of `ghidra.program.util.InstructionUtils`.
//!
//! `InstructionUtils` was selected as a dependency-cycle cut-point, so its public API is ported as
//! the [`InstructionUtils`] trait rather than a plain struct with an `impl` block -- callers can
//! depend on the trait instead of importing a concrete implementation directly. Following the
//! precedent set by [`StringUtilities`](crate::util::string_utilities::StringUtilities) (another
//! cut-point static-utility class), the trait is blanket-implemented for every
//! [`Instruction`], since every public method except `getFormattedRegisterValueBits` takes an
//! `Instruction` as its leading parameter -- that parameter becomes `&self`.
//!
//! `getFormattedRegisterValueBits(RegisterValue, String)` has no `Instruction` receiver, so it is
//! ported as the free function [`get_formatted_register_value_bits`] instead (mirroring how
//! `SleighDebugLogger.getFormattedBytes` was ported as a free function alongside that trait).
//!
//! Two spots in the Java source reach through `Instruction` to state that is unreachable (or not
//! yet ported) in the same shape here, and are adapted rather than transliterated:
//! - `getFormattedContextRegisterValueBreakout` fetches the base context register via
//!   `instr.getProgram().getProgramContext().getBaseContextRegister()`.
//!   [`Program::get_program_context`](crate::program::model::listing::Program::get_program_context)
//!   requires `&mut self`, which is unreachable through the `Arc<dyn Program>` returned by
//!   `CodeUnit::get_program`. `Instruction` (via its `ProcessorContext`/`ProcessorContextView`
//!   supertraits) already exposes the same base context register and register-value lookups
//!   directly, so those are used instead.
//! - `getFormattedInstructionDetails` logs
//!   `Integer.toHexString(instruction.getPrototype().hashCode())`, relying on the JVM's arbitrary
//!   object identity hash purely for diagnostic display. Since `InstructionPrototype` is a trait
//!   object with no `Hash` port, the backing `Arc`'s data pointer address is used as an equivalent
//!   opaque identity value.
//! - `getFormattedInstructionDetails` also guards its flow-override note with
//!   `instruction.getPrototype().getFlowType(instruction.getInstructionContext()) != flowType`.
//!   [`Instruction::get_instruction_context`](crate::program::model::listing::Instruction::get_instruction_context)
//!   returns `Arc<dyn seam_stubs::InstructionContext>` (an empty placeholder predating the later,
//!   unrelated port of the real `ghidra.program.model.lang.InstructionContext` at
//!   `crate::program::model::lang::instruction_context`), while
//!   [`InstructionPrototype::get_flow_type`](crate::program::model::lang::instruction_prototype::InstructionPrototype::get_flow_type)
//!   takes the latter -- a pre-existing seam mismatch well outside this cut-point's scope. Rather
//!   than reconcile the two `InstructionContext` traits here, the note is instead shown whenever a
//!   flow override is set, without additionally checking whether it actually changed the effective
//!   flow type.
//!
//! `debug`, the `SleighDebugLogger` parameter of `getFormattedInstructionDetails`, is documented in
//! Java as accepting `null`, but the method body dereferences it unconditionally (it is never
//! null-checked before use) -- so passing `None` here panics, mirroring the
//! `NullPointerException` Java would throw.

use std::collections::HashSet;
use std::sync::Arc;

use crate::app::plugin::processors::sleigh::sleigh_debug_logger::{
    get_formatted_bytes, SleighDebugLogger,
};
use crate::program::model::lang::Register;
use crate::program::model::listing::{Instruction, OperandValue};
use crate::program::seam_stubs::{FlowOverride, RegisterValue};
use crate::util::string_utilities::StringUtilities;

/// Static instruction-formatting helpers, ported from `ghidra.program.util.InstructionUtils` as a
/// trait blanket-implemented for every [`Instruction`]. See the module docs for rationale.
pub trait InstructionUtils: Instruction {
    /// Get detailed instruction info as formatted text.
    ///
    /// # Panics
    /// Panics if `debug` is `None`, mirroring the `NullPointerException` the Java method throws
    /// when passed a `null` `SleighDebugLogger` (see the module docs).
    ///
    /// Port of `InstructionUtils.getFormattedInstructionDetails(Instruction, SleighDebugLogger)`.
    fn get_formatted_instruction_details(
        &self,
        debug: Option<&mut dyn SleighDebugLogger>,
    ) -> String {
        let mut text = String::from("Instruction Summary");
        text.push_str("\n-------------------");
        text.push_str(&format!("\nMnemonic          : {}", self.get_mnemonic_string()));
        text.push_str(&format!("\nNumber of Operands: {}", self.get_num_operands()));
        text.push_str(&format!(
            "\nAddress           : {}",
            self.get_min_address().format(true, 8)
        ));

        let flow_type = self.get_flow_type();
        text.push_str(&format!("\nFlow Type         : {}", flow_type));

        // See the module docs: the Java source additionally guards this note with a
        // prototype/instruction-context flow-type comparison that can't be ported as-is due to a
        // pre-existing seam mismatch, so the note is shown whenever an override is set.
        let flow_override = self.get_flow_override();
        if flow_override != FlowOverride::None {
            text.push_str(&format!(
                "\n  >>> reflects {} flow override",
                flow_override_name(flow_override)
            ));
        }

        let fall_addr = self.get_fall_through();
        text.push_str(&format!(
            "\nFallthrough       : {}",
            fall_addr
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "<none>".to_string())
        ));
        if self.is_fall_through_overridden() {
            text.push_str("\n  >>> reflects fallthrough override");
        }

        text.push_str(&format!(
            "\nDelay slot depth  : {}{}",
            self.get_delay_slot_depth(),
            if self.is_in_delay_slot() { " in slot" } else { "" }
        ));

        let prototype = self.get_prototype();
        let identity = Arc::as_ptr(&prototype) as *const () as usize;
        text.push_str(&format!("\nHash              : {:x}\n", identity));

        text.push_str(&format!(
            "\nInput Objects:\n{}",
            format_multiline(&self.get_formatted_instruction_objects(true))
        ));
        text.push_str(&format!(
            "\nResult Objects:\n{}",
            format_multiline(&self.get_formatted_instruction_objects(false))
        ));

        let debug = debug.expect("debug must not be null (mirrors Java NullPointerException)");
        text.push_str(&format!(
            "\nConstructor Line #'s:\n{}\n",
            format_multiline(&debug.get_constructor_line_numbers())
        ));

        let len = self.get_length();
        text.push_str(&format!("\nByte Length : {}", len));
        if self.is_length_overridden() {
            text.push_str(&format!(
                "\n  >>> reflects length override, actual length is {}",
                self.get_parsed_length()
            ));
        }

        if let Ok(bytes) = self.get_parsed_bytes() {
            text.push_str(&format!("\nInstr Bytes : {}", get_formatted_bytes(&bytes)));
            text.push_str(&format!(
                "\nMask        : {}",
                debug.get_formatted_instruction_mask(-1)
            ));
            text.push_str(&format!(
                "\nMasked Bytes: {}\n",
                debug.get_formatted_masked_value(-1)
            ));
        }

        text.push_str("\nInstr Context:\n");
        text.push_str(&self.get_formatted_context_register_value_breakout("   "));

        text
    }

    /// Get formatted context register as list of child register values.
    ///
    /// Port of `InstructionUtils.getFormattedContextRegisterValueBreakout(Instruction, String)`.
    /// See the module docs for why this reaches the context register through `Instruction` itself
    /// rather than `instr.getProgram().getProgramContext()`.
    fn get_formatted_context_register_value_breakout(&self, indent: &str) -> String {
        let context_reg = match self.get_base_context_register() {
            Some(reg) if *reg.borrow() != *Register::no_context().borrow() => reg,
            _ => return format!("{indent}[Instruction context not defined]"),
        };
        let value = self.get_register_value(&context_reg.borrow());
        get_formatted_register_value_bits(value.as_deref(), indent)
    }

    /// Format instruction input or result objects.
    ///
    /// Port of `InstructionUtils.getFormatedInstructionObjects(Instruction, boolean)`.
    fn get_formatted_instruction_objects(&self, input: bool) -> Vec<String> {
        let objs = if input {
            self.get_input_objects()
        } else {
            self.get_result_objects()
        };
        format_operand_values(&objs)
    }

    /// Format instruction operand objects.
    ///
    /// Port of `InstructionUtils.getFormatedOperandObjects(Instruction, int)`.
    fn get_formatted_operand_objects(&self, op_index: i32) -> Vec<String> {
        format_operand_values(&self.get_op_objects(op_index))
    }
}

impl<T: Instruction + ?Sized> InstructionUtils for T {}

/// Get formatted `RegisterValue` as list of child register values.
///
/// Ported as a free function rather than a trait method because -- unlike every other
/// `InstructionUtils` method -- its leading parameter is a `RegisterValue`, not an `Instruction`
/// (see the module docs).
///
/// Port of `InstructionUtils.getFormattedRegisterValueBits(RegisterValue, String)`.
pub fn get_formatted_register_value_bits(value: Option<&dyn RegisterValue>, indent: &str) -> String {
    let value = match value {
        Some(value) if value.has_any_value() => value,
        _ => return format!("{indent}[Instruction context has not been set]"),
    };

    let base_reg = value.get_register();
    let base_reg_ref = base_reg.borrow();
    if !base_reg_ref.has_children() {
        return format!(
            "{indent}{} == 0x{:x}",
            base_reg_ref.name(),
            value.get_unsigned_value_ignore_mask()
        );
    }

    let base_reg_size = base_reg_ref.minimum_byte_size() * 8;
    let children = base_reg_ref.child_registers();
    let padded_len = children
        .iter()
        .map(|reg| reg.borrow().name().len())
        .max()
        .unwrap_or(0);

    let mut buf = String::new();
    for reg_ref in &children {
        let reg = reg_ref.borrow();
        let child_value = value.get_register_value(&reg);
        if !child_value.has_any_value() {
            continue;
        }
        let pad = padded_len - reg.name().len();
        let actual = child_value.get_unsigned_value_ignore_mask();
        let msb = base_reg_size - reg.least_significant_bit_in_base_register() - 1;
        let lsb = msb - reg.bit_length() + 1;

        if !buf.is_empty() {
            buf.push('\n');
        }
        buf.push_str(indent);
        let lsb_str = lsb.to_string().pad('0', 2);
        let msb_str = msb.to_string().pad('0', 2);
        let left_str = format!("{}({},{})", reg.name(), lsb_str, msb_str);
        let left_str = left_str.pad(' ', -(left_str.len() as i32) - pad as i32);
        buf.push_str(&format!("{left_str} == 0x{:x}", actual));
    }
    buf
}

/// Java enum `toString()` names for `FlowOverride`, used only for diagnostic display in
/// [`InstructionUtils::get_formatted_instruction_details`].
fn flow_override_name(flow_override: FlowOverride) -> &'static str {
    match flow_override {
        FlowOverride::None => "NONE",
        FlowOverride::Branch => "BRANCH",
        FlowOverride::Call => "CALL",
        FlowOverride::CallReturn => "CALL_RETURN",
        FlowOverride::Return => "RETURN",
    }
}

/// Port of the private `OBJSTRING_COMPARATOR`: registers (no `:`) sort before addresses/scalars,
/// then lexicographically.
fn objstring_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let is_register_a = !a.contains(':');
    let is_register_b = !b.contains(':');
    if is_register_a != is_register_b {
        return if is_register_a {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        };
    }
    a.cmp(b)
}

/// Port of the private `getFormatedInstructionObjects(Object[])` overload.
fn format_operand_values(objs: &[OperandValue]) -> Vec<String> {
    let mut set = HashSet::new();
    for obj in objs {
        match obj {
            OperandValue::Scalar(scalar) => {
                set.insert(format!("const:{}", scalar));
            }
            OperandValue::Register(reg) => {
                set.insert(reg.borrow().to_string());
            }
            OperandValue::Address(addr) => {
                set.insert(addr.format(true, 8));
            }
            OperandValue::Character(_) | OperandValue::Text(_) => {}
        }
    }
    let mut list: Vec<String> = set.into_iter().collect();
    list.sort_by(|a, b| objstring_cmp(a, b));
    list
}

/// Port of the private `getString(List<String>, boolean)` overload with `multiline` fixed to
/// `true` -- the only variant this class's own call sites ever invoke.
fn format_multiline(items: &[String]) -> String {
    let mut buf = String::from("   ");
    let mut line_len = 0usize;
    for item in items {
        if line_len != 0 {
            buf.push_str(", ");
            line_len += 2;
        }
        if line_len >= 40 {
            buf.push_str("\n   ");
            line_len = 0;
        }
        line_len += item.len();
        buf.push_str(item);
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::RegisterRef;
    use crate::program::model::listing::instruction::tests::mock_instruction;
    use std::rc::Rc;

    fn register_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0)
    }

    struct MockRegisterValue {
        register: RegisterRef,
        has_value: bool,
        value: u128,
    }

    impl RegisterValue for MockRegisterValue {
        fn get_register(&self) -> RegisterRef {
            self.register.clone()
        }

        fn get_register_value(&self, register: &Register) -> Box<dyn RegisterValue> {
            Box::new(MockRegisterValue {
                register: Register::from_register(register),
                has_value: self.has_value,
                value: self.value,
            })
        }

        fn has_any_value(&self) -> bool {
            self.has_value
        }

        fn get_unsigned_value_ignore_mask(&self) -> u128 {
            self.value
        }
    }

    #[test]
    fn get_formatted_register_value_bits_reports_unset_context() {
        assert_eq!(
            get_formatted_register_value_bits(None, "  "),
            "  [Instruction context has not been set]"
        );
    }

    #[test]
    fn get_formatted_register_value_bits_formats_register_without_children() {
        let space = register_space();
        let pc = Register::new("PC", "", space.address(0x0), 4, false, Register::TYPE_NONE);
        let value = MockRegisterValue {
            register: Rc::clone(&pc),
            has_value: true,
            value: 0x1000,
        };
        assert_eq!(
            get_formatted_register_value_bits(Some(&value), ">"),
            ">PC == 0x1000"
        );
    }

    #[test]
    fn get_formatted_register_value_bits_formats_child_register_bit_range() {
        let space = register_space();
        let base = Register::new("CTX", "", space.address(0x0), 4, false, Register::TYPE_NONE);
        let field = Register::with_bit_range(
            "FIELD",
            "",
            space.address(0x0),
            1,
            0,
            8,
            false,
            Register::TYPE_NONE,
        );
        base.borrow_mut().set_child_registers(vec![Rc::clone(&field)]);

        let value = MockRegisterValue {
            register: Rc::clone(&base),
            has_value: true,
            value: 0x2A,
        };
        assert_eq!(
            get_formatted_register_value_bits(Some(&value), "  "),
            "  FIELD(24,31) == 0x2a"
        );
    }

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn instruction_utils_is_usable_through_an_instruction_trait_object() {
        let instr = mock_instruction(mock_address(0x400000), mock_address(0x400000));

        assert_eq!(
            instr.get_formatted_operand_objects(0),
            vec!["const:0x1".to_string()]
        );
        assert!(instr.get_formatted_instruction_objects(true).is_empty());
        assert_eq!(
            instr.get_formatted_context_register_value_breakout("  "),
            "  [Instruction context not defined]"
        );
    }
}
