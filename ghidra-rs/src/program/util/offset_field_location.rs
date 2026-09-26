//! Port of `ghidra.program.util.OffsetFieldLocation`.
//!
//! The Java class is a thin data holder that extends
//! [`CodeUnitLocation`](crate::program::util::code_unit_location::CodeUnitLocation) (itself a
//! subclass of `ProgramLocation`) and adds a single [`OffsetFieldType`] field. It was selected as
//! a dependency-cycle cut-point, so it is ported here as an object-safe trait rather than a
//! concrete struct: implementors provide whatever `Program`/`Address`/component-path state the
//! Java constructors captured, and expose it (plus the one accessor, `getType()`) through trait
//! methods. Java's two constructors (populating vs. XML-restore) don't map onto trait methods and
//! are left to implementors.

use crate::program::seam_stubs::OffsetFieldType;
use crate::program::util::code_unit_location::CodeUnitLocation;

/// Provides specific information about a program location within an offset field.
///
/// Port of `ghidra.program.util.OffsetFieldLocation`.
pub trait OffsetFieldLocation: CodeUnitLocation {
    /// Returns the type of offset field.
    ///
    /// Port of `OffsetFieldLocation.getType()`.
    fn get_type(&self) -> OffsetFieldType;
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Program;
    use crate::program::util::ProgramLocation;

    /// A minimal implementor proving the trait is object-safe and that `get_type` round-trips
    /// the value it was built with, exercising both non-default and default `OffsetFieldType`
    /// variants through a `dyn OffsetFieldLocation`.
    struct FixedOffsetFieldLocation {
        address: Address,
        field_type: OffsetFieldType,
    }

    impl ProgramLocation for FixedOffsetFieldLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_byte_address(&self) -> Address {
            self.address.clone()
        }
    }

    impl CodeUnitLocation for FixedOffsetFieldLocation {}

    impl OffsetFieldLocation for FixedOffsetFieldLocation {
        fn get_type(&self) -> OffsetFieldType {
            self.field_type
        }
    }

    #[test]
    fn trait_object_reports_its_offset_field_type() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let memoryblock: Box<dyn OffsetFieldLocation> = Box::new(FixedOffsetFieldLocation {
            address: Address::new(ram.clone(), 0x400),
            field_type: OffsetFieldType::MemoryBlock,
        });
        let file: Box<dyn OffsetFieldLocation> = Box::new(FixedOffsetFieldLocation {
            address: Address::new(ram, 0x400),
            field_type: OffsetFieldType::File,
        });

        assert_eq!(memoryblock.get_type(), OffsetFieldType::MemoryBlock);
        assert_eq!(file.get_type(), OffsetFieldType::File);
    }
}
