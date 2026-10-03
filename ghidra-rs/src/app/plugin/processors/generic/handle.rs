//! Port of `ghidra.app.plugin.processors.generic.Handle`.

use crate::program::model::address::AddressSpaceType;
use crate::program::model::pcode::Varnode;

/// A handle onto a pattern-expression-matched varnode, carrying its own (possibly synthetic)
/// address-space id and size alongside the varnode itself.
///
/// Port of `ghidra.app.plugin.processors.generic.Handle`.
///
/// # Deviations from Java
///
/// * Java implements `Serializable`; this crate has no equivalent marker trait, so it is simply
///   not modeled (nothing in this port serializes a `Handle`).
/// * `isCodeAddress()` is `@Deprecated` in Java and unconditionally `throw new
///   UnsupportedOperationException()`. Preserved faithfully as [`Handle::is_code_address`], which
///   panics.
#[derive(Debug, Clone, PartialEq)]
pub struct Handle {
    ptr: Varnode,
    space_id: i32,
    size: i32,
}

impl Handle {
    /// Selector for [`Handle::get_long`]'s first argument: the handle's own space id.
    pub const SPACE: i32 = 0;
    /// Selector for [`Handle::get_long`]'s first argument: a property of [`Handle::ptr`].
    pub const OFFSET: i32 = 1;
    /// Selector for [`Handle::get_long`]'s first argument: the handle's own size.
    pub const SIZE: i32 = 2;

    /// Java: `Handle(Varnode p, int sp, int sz)`.
    pub fn new(p: Varnode, sp: i32, sz: i32) -> Self {
        Self { ptr: p, space_id: sp, size: sz }
    }

    /// Java: `getLong(int select1, int select2)`.
    ///
    /// `select2` is only consulted when `select1 == OFFSET`, to further select which property of
    /// [`Handle::ptr`] to report. An unrecognized `select2` (or `select1`) reports `0`, matching
    /// Java's `// Should never occur` fallbacks -- including the one behind a `catch (Exception
    /// e)` that, in this port, can never actually trigger (there is nothing in the `OFFSET` arm
    /// that can throw), but is preserved as dead code for parity with Java's defensive shape.
    pub fn get_long(&self, select1: i32, select2: i32) -> i64 {
        match select1 {
            Self::SPACE => self.space_id as i64,
            Self::OFFSET => match select2 {
                Self::SPACE => self.ptr.get_space_id() as i64,
                Self::OFFSET => self.ptr.get_offset(),
                Self::SIZE => self.ptr.get_size() as i64,
                _ => 0, // Should never occur
            },
            Self::SIZE => self.size as i64,
            _ => 0, // Should never occur
        }
    }

    /// Java: `getSpace()`.
    pub fn get_space(&self) -> i64 {
        self.space_id as i64
    }

    /// Java: `getSize()`.
    pub fn get_size(&self) -> i64 {
        self.size as i64
    }

    /// Java: `getPtr()`.
    pub fn get_ptr(&self) -> &Varnode {
        &self.ptr
    }

    /// Java: `isAddress()`.
    pub fn is_address(&self) -> bool {
        space_type_of(self.space_id) == AddressSpaceType::Ram
    }

    /// Java: `@Deprecated isCodeAddress()`, which unconditionally throws
    /// `UnsupportedOperationException`. See the struct docs.
    #[deprecated]
    pub fn is_code_address(&self) -> ! {
        panic!("isCodeAddress is not supported")
    }

    /// Java: `isDataAddress()`.
    pub fn is_data_address(&self) -> bool {
        space_type_of(self.space_id) == AddressSpaceType::Ram
    }

    /// Java: `isConstant()`.
    pub fn is_constant(&self) -> bool {
        space_type_of(self.space_id) == AddressSpaceType::Constant
    }

    /// Java: `isRegister()`.
    pub fn is_register(&self) -> bool {
        space_type_of(self.space_id) == AddressSpaceType::Register
    }

    /// Java: `isUnique()`.
    pub fn is_unique(&self) -> bool {
        space_type_of(self.space_id) == AddressSpaceType::Unique
    }

    /// Java: `dynamic()`.
    pub fn dynamic(&self) -> bool {
        !self.ptr.is_constant()
    }
}

/// Decode the [`AddressSpaceType`] packed into the low 4 bits of a raw space id, mirroring Java's
/// `AddressSpace.ID_TYPE_MASK & spaceID` (`ID_TYPE_MASK == 0x000f`).
///
/// `Handle`'s `spaceID` is a bare `int` -- not a real `AddressSpace` this crate's
/// [`crate::program::model::address::AddressSpace`] wraps -- so decoding it needs the same bit
/// layout [`AddressSpace::new`](crate::program::model::address::AddressSpace::new) already uses
/// to *build* a real space's id (`(unique << 7) | (logsize << 4) | (space_type as i32)`), read
/// back out here. Any low-nibble value without a matching [`AddressSpaceType`] discriminant (i.e.
/// not one of Java's `TYPE_*` constants) has no faithful mapping; this falls back to
/// [`AddressSpaceType::Unknown`], which none of `Handle`'s `is_*` predicates match, so such an id
/// behaves as "none of the above" -- the same outcome Java's own bitmask comparisons give for an
/// id whose low nibble doesn't match a known `TYPE_*` constant either.
fn space_type_of(space_id: i32) -> AddressSpaceType {
    const ID_TYPE_MASK: i32 = 0x000f;
    match space_id & ID_TYPE_MASK {
        0 => AddressSpaceType::Constant,
        1 => AddressSpaceType::Ram,
        2 => AddressSpaceType::Code,
        3 => AddressSpaceType::Unique,
        4 => AddressSpaceType::Register,
        5 => AddressSpaceType::Stack,
        6 => AddressSpaceType::Join,
        7 => AddressSpaceType::Other,
        9 => AddressSpaceType::Symbol,
        10 => AddressSpaceType::External,
        11 => AddressSpaceType::Variable,
        13 => AddressSpaceType::Deleted,
        14 => AddressSpaceType::Unknown,
        15 => AddressSpaceType::None,
        _ => AddressSpaceType::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace};

    fn varnode(space_type: AddressSpaceType, offset: i64, size: i32) -> (Varnode, i32) {
        let space = AddressSpace::new("s", 32, 1, space_type, 0);
        let space_id = space.space_id();
        (Varnode::new(Address::new(space, offset), size), space_id)
    }

    #[test]
    fn get_long_space_selector_reports_the_handles_own_space_id() {
        let (ptr, ram_id) = varnode(AddressSpaceType::Ram, 0x100, 4);
        let handle = Handle::new(ptr, ram_id, 4);
        assert_eq!(handle.get_long(Handle::SPACE, 0), ram_id as i64);
    }

    #[test]
    fn get_long_size_selector_reports_the_handles_own_size() {
        let (ptr, ram_id) = varnode(AddressSpaceType::Ram, 0x100, 4);
        let handle = Handle::new(ptr, ram_id, 8);
        assert_eq!(handle.get_long(Handle::SIZE, 0), 8);
    }

    #[test]
    fn get_long_offset_selector_dispatches_on_select2_to_the_varnode() {
        let (ptr, ram_id) = varnode(AddressSpaceType::Ram, 0x1234, 4);
        let handle = Handle::new(ptr, ram_id, 4);

        assert_eq!(handle.get_long(Handle::OFFSET, Handle::SPACE), ram_id as i64);
        assert_eq!(handle.get_long(Handle::OFFSET, Handle::OFFSET), 0x1234);
        assert_eq!(handle.get_long(Handle::OFFSET, Handle::SIZE), 4);
    }

    #[test]
    fn get_long_falls_back_to_zero_for_unrecognized_selectors() {
        let (ptr, ram_id) = varnode(AddressSpaceType::Ram, 0x1234, 4);
        let handle = Handle::new(ptr, ram_id, 4);

        assert_eq!(handle.get_long(Handle::OFFSET, 99), 0);
        assert_eq!(handle.get_long(99, 0), 0);
    }

    #[test]
    fn accessors_report_the_handles_own_fields() {
        let (ptr, ram_id) = varnode(AddressSpaceType::Ram, 0x2000, 4);
        let handle = Handle::new(ptr.clone(), ram_id, 4);

        assert_eq!(handle.get_space(), ram_id as i64);
        assert_eq!(handle.get_size(), 4);
        assert_eq!(handle.get_ptr(), &ptr);
    }

    #[test]
    fn is_address_and_is_data_address_agree_and_use_the_handles_own_space_id() {
        let (ptr, ram_id) = varnode(AddressSpaceType::Ram, 0x3000, 4);
        let handle = Handle::new(ptr, ram_id, 4);

        assert!(handle.is_address());
        assert!(handle.is_data_address());
        assert!(!handle.is_constant());
        assert!(!handle.is_register());
        assert!(!handle.is_unique());
    }

    #[test]
    fn is_constant_uses_the_handles_own_space_id_not_the_varnodes() {
        let (const_ptr, const_id) = varnode(AddressSpaceType::Constant, 5, 4);
        // Deliberately mismatch: the ptr is a RAM varnode, but the handle's own spaceID says
        // constant -- `isConstant`/`isRegister`/`isUnique`/`isAddress` all key off the handle's
        // `spaceID` field, never the varnode's own space.
        let (ram_ptr, _) = varnode(AddressSpaceType::Ram, 5, 4);
        let handle = Handle::new(ram_ptr, const_id, 4);

        assert!(handle.is_constant());
        assert!(!handle.is_address());
        let _ = const_ptr;
    }

    #[test]
    fn is_register_and_is_unique_check_the_handles_own_space_id() {
        let (reg_ptr, reg_id) = varnode(AddressSpaceType::Register, 0, 4);
        let reg_handle = Handle::new(reg_ptr, reg_id, 4);
        assert!(reg_handle.is_register());
        assert!(!reg_handle.is_unique());

        let (uniq_ptr, uniq_id) = varnode(AddressSpaceType::Unique, 0, 4);
        let uniq_handle = Handle::new(uniq_ptr, uniq_id, 4);
        assert!(uniq_handle.is_unique());
        assert!(!uniq_handle.is_register());
    }

    #[test]
    fn dynamic_reflects_whether_the_varnode_itself_is_constant() {
        let (const_ptr, const_id) = varnode(AddressSpaceType::Constant, 5, 4);
        let handle = Handle::new(const_ptr, const_id, 4);
        assert!(!handle.dynamic());

        let (ram_ptr, ram_id) = varnode(AddressSpaceType::Ram, 5, 4);
        let handle = Handle::new(ram_ptr, ram_id, 4);
        assert!(handle.dynamic());
    }

    #[test]
    #[should_panic(expected = "isCodeAddress is not supported")]
    #[allow(deprecated)]
    fn is_code_address_panics() {
        let (ptr, ram_id) = varnode(AddressSpaceType::Ram, 0, 4);
        let handle = Handle::new(ptr, ram_id, 4);
        let _ = handle.is_code_address();
    }
}
