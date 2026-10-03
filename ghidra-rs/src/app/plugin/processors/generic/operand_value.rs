//! Port of `ghidra.app.plugin.processors.generic.OperandValue`.

use crate::app::plugin::processors::generic::constructor_info::ConstructorInfo;
use crate::app::plugin::processors::generic::handle::Handle;
use crate::app::plugin::processors::generic::position::Position;
use crate::app::plugin::processors::generic::sled_exception::SledException;
use crate::program::model::mem::MemBuffer;
use crate::program::model::pcode::PcodeOp;

/// A value (constant, expression, handle-producing operand, ...) that can appear as an operand of
/// a SLED/SSL instruction pattern.
///
/// Port of `ghidra.app.plugin.processors.generic.OperandValue`.
///
/// # Deviations from Java
///
/// * Java's interface `extends Serializable`; this crate has no equivalent marker trait, so it is
///   simply not modeled (matching the established rationale on
///   [`Handle`](crate::app::plugin::processors::generic::Handle)'s docs for the same situation).
/// * Every Java method declares a broad `throws Exception`, with no more specific checked
///   exception type. This port uses [`SledException`] as the concrete error type, matching this
///   crate's existing convention in this same package (`SledException` is already used as the
///   generic "something went wrong parsing/evaluating a SLED/SSL construct" error for exactly this
///   situation).
/// * Java overloads `getHandle` on argument shape (`getHandle(ArrayList<PcodeOp>, Position, int)`
///   vs `getHandle(Position, int)`). Rust has no method overloading, so the two are ported as
///   [`OperandValue::get_handle_with_pcode`] (the 3-arg overload that also collects emitted p-code)
///   and [`OperandValue::get_handle`] (the 2-arg overload).
/// * Java's `toString(MemBuffer, int)` shares a name with `Object.toString()` but is an entirely
///   different, unrelated method (an overload of the same identifier, not an override -- it takes
///   arguments, `Object.toString()` does not). Naming it `to_string` here would make it ambiguous
///   with Rust's own blanket `ToString::to_string(&self)` for any implementor that also derives
///   `Display` (see this project's "same-named-method ambiguity" pitfall), so it is named
///   [`OperandValue::to_string_at`] instead.
pub trait OperandValue {
    /// Java: `int length(MemBuffer buf, int offset) throws Exception`.
    fn length(&self, buf: &dyn MemBuffer, offset: i32) -> Result<i32, SledException>;

    /// Java: `ConstructorInfo getInfo(MemBuffer buf, int offset) throws Exception`.
    fn get_info(&self, buf: &dyn MemBuffer, offset: i32) -> Result<ConstructorInfo, SledException>;

    /// Java: `String toString(MemBuffer buf, int offset) throws Exception`. See the trait docs for
    /// why this is not named `to_string`.
    fn to_string_at(&self, buf: &dyn MemBuffer, offset: i32) -> Result<String, SledException>;

    /// Java: `Handle getHandle(ArrayList<PcodeOp> pcode, Position position, int off) throws
    /// Exception`.
    fn get_handle_with_pcode(
        &self,
        pcode: &mut Vec<PcodeOp>,
        position: &Position,
        off: i32,
    ) -> Result<Handle, SledException>;

    /// Java: `Handle getHandle(Position position, int off) throws Exception`.
    fn get_handle(&self, position: &Position, off: i32) -> Result<Handle, SledException>;

    /// Java: `void getAllHandles(ArrayList<Handle> handles, Position position, int offset) throws
    /// Exception`.
    fn get_all_handles(
        &self,
        handles: &mut Vec<Handle>,
        position: &Position,
        offset: i32,
    ) -> Result<(), SledException>;

    /// Construct operand representation as a list of objects.
    ///
    /// Java: `void toList(ArrayList<Handle> list, Position position, int off) throws Exception`.
    fn to_list(
        &self,
        list: &mut Vec<Handle>,
        position: &Position,
        off: i32,
    ) -> Result<(), SledException>;

    /// Get the size in bits of the value used in the instruction to create this value.
    ///
    /// Java: `int getSize()`.
    fn get_size(&self) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::processor_context::ProcessorContext;
    use crate::program::model::lang::processor_context_view::ProcessorContextView;
    use crate::program::model::lang::register::Register;
    use crate::program::model::listing::context_change_exception::ContextChangeException;
    use crate::program::model::pcode::Varnode;

    /// Mock implementation of `MemBuffer` for testing, mirroring the pattern already used by
    /// [`Position`]'s own tests.
    struct TestMemBuffer {
        addr_offset: i64,
    }

    impl MemBuffer for TestMemBuffer {
        fn get_byte(&self, _offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
            Address::new(space, self.addr_offset)
        }
        fn is_initialized_memory(&self) -> bool {
            true
        }
        fn is_at_initialized_memory_address(&self) -> bool {
            true
        }
    }

    /// Mock implementation of `ProcessorContext` for testing, mirroring the pattern already used
    /// by [`Position`]'s own tests.
    struct TestProcessorContext;

    impl ProcessorContextView for TestProcessorContext {
        fn get_base_context_register(
            &self,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }
        fn get_register(
            &self,
            _name: &str,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_value(&self, _register: &Register, _signed: bool) -> Option<i128> {
            None
        }
        fn get_register_value(
            &self,
            _register: &Register,
        ) -> Option<crate::program::model::lang::register_value::RegisterValue> {
            None
        }
        fn has_value(&self, _register: &Register) -> bool {
            false
        }
    }

    impl ProcessorContext for TestProcessorContext {
        fn set_value(
            &mut self,
            _register: &Register,
            _value: i128,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn set_register_value(
            &mut self,
            _value: crate::program::model::lang::register_value::RegisterValue,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn clear_register(&mut self, _register: &Register) -> Result<(), ContextChangeException> {
            Ok(())
        }
    }

    fn make_position(addr_offset: i64) -> Position {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let start = Address::new(space.clone(), addr_offset);
        let next = Address::new(space, addr_offset + 4);
        Position::new(
            Box::new(TestMemBuffer { addr_offset }),
            start,
            next,
            Box::new(TestProcessorContext),
        )
    }

    /// A minimal, deterministic [`OperandValue`] implementor exercising every method with values
    /// threaded through from its arguments, similar in spirit to `ExpressionValue`'s own
    /// `SimpleExpression` test mock.
    struct FixedOperandValue {
        size: i32,
    }

    impl OperandValue for FixedOperandValue {
        fn length(&self, _buf: &dyn MemBuffer, offset: i32) -> Result<i32, SledException> {
            Ok(offset + self.size)
        }

        fn get_info(&self, _buf: &dyn MemBuffer, _offset: i32) -> Result<ConstructorInfo, SledException> {
            Ok(ConstructorInfo::new(self.size, ConstructorInfo::CALL))
        }

        fn to_string_at(&self, _buf: &dyn MemBuffer, offset: i32) -> Result<String, SledException> {
            if offset < 0 {
                return Err(SledException::with_message("negative offset"));
            }
            Ok(format!("op@{offset}"))
        }

        fn get_handle_with_pcode(
            &self,
            _pcode: &mut Vec<PcodeOp>,
            _position: &Position,
            off: i32,
        ) -> Result<Handle, SledException> {
            let space = AddressSpace::new("const", 32, 1, AddressSpaceType::Constant, 0);
            let vn = Varnode::new(Address::new(space, off as i64), self.size);
            Ok(Handle::new(vn, 0, self.size))
        }

        fn get_handle(&self, position: &Position, off: i32) -> Result<Handle, SledException> {
            let mut pcode = Vec::new();
            self.get_handle_with_pcode(&mut pcode, position, off)
        }

        fn get_all_handles(
            &self,
            handles: &mut Vec<Handle>,
            position: &Position,
            offset: i32,
        ) -> Result<(), SledException> {
            handles.push(self.get_handle(position, offset)?);
            Ok(())
        }

        fn to_list(
            &self,
            list: &mut Vec<Handle>,
            position: &Position,
            off: i32,
        ) -> Result<(), SledException> {
            self.get_all_handles(list, position, off)
        }

        fn get_size(&self) -> i32 {
            self.size
        }
    }

    #[test]
    fn length_adds_offset_and_size() {
        let value = FixedOperandValue { size: 4 };
        let buf = TestMemBuffer { addr_offset: 0 };
        assert_eq!(value.length(&buf, 10).unwrap(), 14);
    }

    #[test]
    fn get_info_reports_length_and_flow_flags() {
        let value = FixedOperandValue { size: 8 };
        let buf = TestMemBuffer { addr_offset: 0 };
        let info = value.get_info(&buf, 0).unwrap();
        assert_eq!(info.get_length(), 8);
        assert_eq!(info.get_flow_flags(), ConstructorInfo::CALL);
    }

    #[test]
    fn to_string_at_renders_the_offset() {
        let value = FixedOperandValue { size: 4 };
        let buf = TestMemBuffer { addr_offset: 0 };
        assert_eq!(value.to_string_at(&buf, 5).unwrap(), "op@5");
    }

    #[test]
    fn to_string_at_propagates_errors() {
        let value = FixedOperandValue { size: 4 };
        let buf = TestMemBuffer { addr_offset: 0 };
        assert!(value.to_string_at(&buf, -1).is_err());
    }

    #[test]
    fn get_handle_reports_the_configured_size() {
        let value = FixedOperandValue { size: 4 };
        let position = make_position(0x1000);
        let handle = value.get_handle(&position, 3).unwrap();
        assert_eq!(handle.get_size(), 4);
    }

    #[test]
    fn get_handle_with_pcode_matches_get_handle() {
        let value = FixedOperandValue { size: 4 };
        let position = make_position(0x1000);
        let mut pcode = Vec::new();
        let via_pcode = value.get_handle_with_pcode(&mut pcode, &position, 3).unwrap();
        let via_plain = value.get_handle(&position, 3).unwrap();
        assert_eq!(via_pcode, via_plain);
    }

    #[test]
    fn get_all_handles_appends_a_single_handle() {
        let value = FixedOperandValue { size: 2 };
        let position = make_position(0x2000);
        let mut handles = Vec::new();
        value.get_all_handles(&mut handles, &position, 0).unwrap();
        assert_eq!(handles.len(), 1);
        assert_eq!(handles[0].get_size(), 2);
    }

    #[test]
    fn to_list_delegates_to_get_all_handles() {
        let value = FixedOperandValue { size: 2 };
        let position = make_position(0x2000);
        let mut list = Vec::new();
        value.to_list(&mut list, &position, 0).unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn get_size_returns_the_configured_size() {
        let value = FixedOperandValue { size: 16 };
        assert_eq!(value.get_size(), 16);
    }

    #[test]
    fn operand_value_is_object_safe() {
        let value: Box<dyn OperandValue> = Box::new(FixedOperandValue { size: 4 });
        assert_eq!(value.get_size(), 4);
    }
}
