//! Port of `ghidra.app.plugin.core.function.editor.VarnodeInfo`.

use std::sync::Arc;

use crate::app::plugin::core::function::editor::VarnodeType;
use crate::program::model::address::Address;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::listing::Program;
use crate::program::model::pcode::Varnode;

/// Represents the type/address/size/register of a varnode being edited in the function editor.
///
/// Port of `ghidra.app.plugin.core.function.editor.VarnodeInfo`. Package-private in Java; kept
/// `pub` since Rust has no package-private visibility tier narrower than the crate (matching the
/// convention already used elsewhere in this port, e.g.
/// [`FunctionVariableData`](crate::app::plugin::core::function::editor::FunctionVariableData)).
pub struct VarnodeInfo {
    var_type: Option<VarnodeType>,
    address: Option<Address>,
    size: Option<i32>,
    register: Option<RegisterRef>,
    program: Arc<dyn Program>,
}

impl VarnodeInfo {
    /// Java: `VarnodeInfo(Program program, VarnodeType type)`.
    pub fn new(program: Arc<dyn Program>, var_type: VarnodeType) -> Self {
        VarnodeInfo { var_type: Some(var_type), address: None, size: None, register: None, program }
    }

    /// Java: `VarnodeInfo(Program program, Varnode varnode)`. Named distinctly from
    /// [`new`](Self::new) since Rust does not support overloading by parameter type.
    pub fn from_varnode(program: Arc<dyn Program>, varnode: &Varnode) -> Self {
        let mut info =
            VarnodeInfo { var_type: None, address: None, size: None, register: None, program };
        info.set_varnode_from(varnode);
        info
    }

    /// Java: `getType()`.
    pub fn get_type(&self) -> Option<VarnodeType> {
        self.var_type
    }

    /// Java: `getAddress()`.
    pub fn get_address(&self) -> Option<&Address> {
        self.address.as_ref()
    }

    /// Java: `getSize()`.
    pub fn get_size(&self) -> Option<i32> {
        self.size
    }

    /// Java: `setVarnodeType(VarnodeType type)`.
    pub fn set_varnode_type(&mut self, var_type: VarnodeType) {
        self.var_type = Some(var_type);
        self.address = None;
        self.register = None;
        if var_type == VarnodeType::Register {
            self.size = None;
        }
    }

    /// Java: `setVarnode(Address address, Integer size)`.
    ///
    /// # Panics
    ///
    /// Panics if `address` is present but is neither a register, stack, nor memory address.
    /// Java: `IllegalArgumentException("Illegal varnode address type")`.
    pub fn set_varnode(&mut self, address: Option<Address>, size: Option<i32>) {
        self.address = address.clone();
        self.size = size;
        self.register = Self::resolve_register(self.program.as_ref(), address.as_ref(), size);
        let Some(address) = address else {
            return;
        };
        if address.is_register_address() || self.register.is_some() {
            self.var_type = Some(VarnodeType::Register);
        } else if address.is_stack_address() {
            self.var_type = Some(VarnodeType::Stack);
        } else if address.is_memory_address() {
            self.var_type = Some(VarnodeType::Memory);
        } else {
            panic!("Illegal varnode address type");
        }
    }

    /// Java: `setVarnode(Varnode varnode)`.
    pub fn set_varnode_from(&mut self, varnode: &Varnode) {
        self.set_varnode(Some(varnode.get_address().clone()), Some(varnode.get_size()));
    }

    /// Java: `getRegister()`.
    pub fn get_register(&self) -> Option<&RegisterRef> {
        self.register.as_ref()
    }

    /// Java: `static Register getRegister(Program program, Address address, Integer size)`.
    /// Named `resolve_register` rather than `get_register` since Rust does not support
    /// overloading by parameter list, and the instance accessor above already claims that name.
    ///
    /// Java's `if (!address.isRegisterAddress() && !address.getAddressSpace().hasMappedRegisters())
    /// return null;` guard is dropped here: it is purely a fast-path short-circuit (avoiding a
    /// call into `program.getRegister` for addresses that obviously cannot be registers) that
    /// never changes the final answer for a well-behaved `Program` -- such a `Program` already
    /// returns nothing for those same addresses from `getRegister` itself. `AddressSpace` doesn't
    /// implement `has_mapped_registers` in this port anyway (only declared as a defaulted method
    /// on the separate, unimplemented `AbstractAddressSpace` trait), so reproducing half the guard
    /// (`is_register_address()` alone) would incorrectly reject legitimate memory-mapped-register
    /// addresses instead of just skipping an optimization; delegating unconditionally to
    /// [`Program::get_register_at`] is both simpler and strictly more correct here.
    ///
    /// The Java overload `Program.getRegister(Address, int size)` this consults when `size` is
    /// given is not ported (only the size-independent `Program.getRegister(Address)`, i.e.
    /// [`Program::get_register_at`], exists in this port); the size-aware branch therefore falls
    /// back to the same size-independent lookup as the `size == null` branch, rather than being
    /// able to distinguish a size mismatch.
    pub fn resolve_register(
        program: &dyn Program,
        address: Option<&Address>,
        _size: Option<i32>,
    ) -> Option<RegisterRef> {
        program.get_register_at(address?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::register::Register;

    fn space(space_type: AddressSpaceType) -> Arc<AddressSpace> {
        AddressSpace::new("s", 32, 1, space_type, 0)
    }

    fn addr(space_type: AddressSpaceType, offset: i64) -> Address {
        Address::new(space(space_type), offset)
    }

    // `RegisterRef` is `Rc<RefCell<Register>>`, which is not `Send`/`Sync`; `Program: Send +
    // Sync` therefore forbids storing one as a struct field on a `Program` implementor.
    // `MockProgram` instead stores the one `Address` (if any) that should resolve to a register
    // and builds a fresh `RegisterRef` on demand inside `get_register_at` when queried for it --
    // the *return value* of a `&self` method has no such restriction, only the implementing
    // struct's own fields do. Address-sensitive (rather than an unconditional flag) so it models a
    // well-behaved `Program` that only reports a register for the address that actually has one.
    struct MockProgram {
        register_at: Option<Address>,
    }

    impl DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        fn get_register_at(&self, address: &Address) -> Option<RegisterRef> {
            if self.register_at.as_ref() == Some(address) {
                Some(mock_register())
            } else {
                None
            }
        }
    }

    fn program(register_at: Option<Address>) -> Arc<dyn Program> {
        Arc::new(MockProgram { register_at })
    }

    fn mock_register() -> RegisterRef {
        Register::new("EAX", "", addr(AddressSpaceType::Register, 0), 4, false, 0)
    }

    #[test]
    fn new_stores_program_and_type_with_no_address() {
        let info = VarnodeInfo::new(program(None), VarnodeType::Stack);
        assert_eq!(info.get_type(), Some(VarnodeType::Stack));
        assert!(info.get_address().is_none());
        assert!(info.get_size().is_none());
    }

    #[test]
    fn set_varnode_type_clears_address_and_register_and_size_for_register() {
        let mut info = VarnodeInfo::new(program(None), VarnodeType::Memory);
        info.set_varnode(Some(addr(AddressSpaceType::Ram, 0x100)), Some(4));
        assert!(info.get_address().is_some());

        info.set_varnode_type(VarnodeType::Register);
        assert_eq!(info.get_type(), Some(VarnodeType::Register));
        assert!(info.get_address().is_none());
        assert!(info.get_register().is_none());
        assert!(info.get_size().is_none());
    }

    #[test]
    fn set_varnode_type_keeps_size_for_non_register_types() {
        let mut info = VarnodeInfo::new(program(None), VarnodeType::Register);
        info.set_varnode(Some(addr(AddressSpaceType::Ram, 0x100)), Some(4));

        info.set_varnode_type(VarnodeType::Memory);
        assert_eq!(info.get_type(), Some(VarnodeType::Memory));
        assert_eq!(info.get_size(), Some(4));
    }

    #[test]
    fn set_varnode_detects_register_address() {
        let mut info = VarnodeInfo::new(program(None), VarnodeType::Memory);
        info.set_varnode(Some(addr(AddressSpaceType::Register, 0x10)), Some(4));
        assert_eq!(info.get_type(), Some(VarnodeType::Register));
    }

    #[test]
    fn set_varnode_detects_stack_address() {
        let mut info = VarnodeInfo::new(program(None), VarnodeType::Memory);
        info.set_varnode(Some(addr(AddressSpaceType::Stack, 0x10)), Some(4));
        assert_eq!(info.get_type(), Some(VarnodeType::Stack));
    }

    #[test]
    fn set_varnode_detects_memory_address() {
        let mut info = VarnodeInfo::new(program(None), VarnodeType::Register);
        info.set_varnode(Some(addr(AddressSpaceType::Ram, 0x1000)), Some(4));
        assert_eq!(info.get_type(), Some(VarnodeType::Memory));
    }

    #[test]
    #[should_panic(expected = "Illegal varnode address type")]
    fn set_varnode_panics_on_unrecognized_address_type() {
        let mut info = VarnodeInfo::new(program(None), VarnodeType::Memory);
        // Constant addresses are neither register, stack, nor memory.
        info.set_varnode(Some(addr(AddressSpaceType::Constant, 5)), Some(4));
    }

    #[test]
    fn set_varnode_type_becomes_register_when_program_reports_a_mapped_register() {
        // A RAM address that the program nonetheless reports as backed by a register (e.g. a
        // memory-mapped register): mirrors the `register != null` half of Java's OR condition.
        let mapped = addr(AddressSpaceType::Ram, 0x1000);
        let mut info = VarnodeInfo::new(program(Some(mapped.clone())), VarnodeType::Memory);
        info.set_varnode(Some(mapped), Some(4));
        assert_eq!(info.get_type(), Some(VarnodeType::Register));
        assert!(info.get_register().is_some());
    }

    #[test]
    fn from_varnode_constructor_derives_state_from_the_varnode() {
        let v = Varnode::new(addr(AddressSpaceType::Ram, 0x2000), 8);
        let info = VarnodeInfo::from_varnode(program(None), &v);
        assert_eq!(info.get_type(), Some(VarnodeType::Memory));
        assert_eq!(info.get_address(), Some(&addr(AddressSpaceType::Ram, 0x2000)));
        assert_eq!(info.get_size(), Some(8));
    }

    #[test]
    fn set_varnode_from_matches_direct_address_size_call() {
        let mut info = VarnodeInfo::new(program(None), VarnodeType::Memory);
        let v = Varnode::new(addr(AddressSpaceType::Stack, 0x8), 4);
        info.set_varnode_from(&v);
        assert_eq!(info.get_type(), Some(VarnodeType::Stack));
        assert_eq!(info.get_size(), Some(4));
    }

    #[test]
    fn static_get_register_returns_none_without_address() {
        let p = program(Some(addr(AddressSpaceType::Register, 0x100)));
        assert!(VarnodeInfo::resolve_register(p.as_ref(), None, None).is_none());
    }

    #[test]
    fn static_get_register_returns_none_for_a_different_address() {
        // The program only has a register at 0x100; querying a different address returns None.
        let p = program(Some(addr(AddressSpaceType::Register, 0x100)));
        let a = addr(AddressSpaceType::Ram, 0x200);
        assert!(VarnodeInfo::resolve_register(p.as_ref(), Some(&a), None).is_none());
    }

    #[test]
    fn static_get_register_returns_program_register_for_register_address() {
        let a = addr(AddressSpaceType::Register, 0x100);
        let p = program(Some(a.clone()));
        assert!(VarnodeInfo::resolve_register(p.as_ref(), Some(&a), Some(4)).is_some());
    }
}
