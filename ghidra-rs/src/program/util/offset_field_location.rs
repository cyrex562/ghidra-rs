//! Port of `ghidra.program.util.OffsetFieldLocation`.
//!
//! The Java class is a thin data holder that extends `CodeUnitLocation` (itself a subclass of
//! `ProgramLocation`) and adds a single [`OffsetFieldType`] field. It was selected as a
//! dependency-cycle cut-point, so it is ported here as an object-safe trait rather than a
//! concrete struct: implementors provide whatever `Program`/`Address`/component-path state the
//! Java constructors captured, and expose it (plus the one accessor, `getType()`) through trait
//! methods. `CodeUnitLocation` is not yet ported, so this trait bounds on a minimal placeholder
//! supertrait, [`CodeUnitLocation`](crate::program::seam_stubs::CodeUnitLocation), instead.
//! Java's two constructors (populating vs. XML-restore) don't map onto trait methods and are
//! left to implementors.

use crate::program::seam_stubs::{CodeUnitLocation, OffsetFieldType};

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
    use super::*;

    /// A minimal implementor proving the trait is object-safe and that `get_type` round-trips
    /// the value it was built with, exercising both non-default and default `OffsetFieldType`
    /// variants through a `dyn OffsetFieldLocation`.
    struct FixedOffsetFieldLocation {
        field_type: OffsetFieldType,
    }

    impl CodeUnitLocation for FixedOffsetFieldLocation {}

    impl OffsetFieldLocation for FixedOffsetFieldLocation {
        fn get_type(&self) -> OffsetFieldType {
            self.field_type
        }
    }

    #[test]
    fn trait_object_reports_its_offset_field_type() {
        let memoryblock: Box<dyn OffsetFieldLocation> =
            Box::new(FixedOffsetFieldLocation { field_type: OffsetFieldType::MemoryBlock });
        let file: Box<dyn OffsetFieldLocation> =
            Box::new(FixedOffsetFieldLocation { field_type: OffsetFieldType::File });

        assert_eq!(memoryblock.get_type(), OffsetFieldType::MemoryBlock);
        assert_eq!(file.get_type(), OffsetFieldType::File);
    }
}
