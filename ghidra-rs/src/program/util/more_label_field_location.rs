//! Port of `ghidra.program.util.MoreLabelFieldLocation`.
//!
//! The Java class represents the `[more]` text used by the label field factory. It is a subclass
//! of [`CodeUnitLocation`](crate::program::util::code_unit_location::CodeUnitLocation) that adds
//! no new fields, but does add real (state-independent) behavior: a `toString()` override that
//! always returns the `MORE_LABELS_STRING` constant, regardless of the location's address/row/
//! char-offset. That constant is also referenced from outside this class —
//! `ghidra.app.util.viewer.field.LabelFieldMouseHandler` and `LabelFieldFactory` both compare
//! clicked/rendered text against `MoreLabelFieldLocation.MORE_LABELS_STRING` — so unlike the
//! `equals`/`hashCode`/`toString` boilerplate omitted from sibling cut-points (which is genuine
//! `Object`-identity boilerplate implementors can derive themselves), this override is ported as a
//! default trait method: it carries meaningful, reusable behavior rather than identity plumbing.
//!
//! The populating constructor, `MoreLabelFieldLocation(p, addr, row, charOffset)`, forwards to
//! `CodeUnitLocation`'s public `(program, addr, row, col, charOffset)` constructor as
//! `super(p, addr, row, 0, charOffset)` — `col` is always fixed to `0`; `row` and `charOffset` are
//! variable. Following the same approach as its sibling `*FieldLocation`/`*Location` cut-points,
//! it is ported here as an object-safe trait: the two constructors (populating vs. XML-restore)
//! don't map onto trait methods and are left to implementors, which are expected to zero `col` as
//! the Java constructor does.

use crate::program::util::code_unit_location::CodeUnitLocation;

/// The text always displayed by a `MoreLabelFieldLocation`, matching Java's
/// `MoreLabelFieldLocation.MORE_LABELS_STRING`.
pub const MORE_LABELS_STRING: &str = "[more]";

/// Represents the `[more]` text used by the label field factory.
///
/// Port of `ghidra.program.util.MoreLabelFieldLocation`.
pub trait MoreLabelFieldLocation: CodeUnitLocation {
    /// Returns the fixed `[more]` display text for this location.
    ///
    /// Port of `MoreLabelFieldLocation.toString()`, which unconditionally returns
    /// [`MORE_LABELS_STRING`] regardless of any instance state.
    fn more_label_text(&self) -> &'static str {
        MORE_LABELS_STRING
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Program;
    use crate::program::util::ProgramLocation;

    /// A minimal implementor proving the trait is object-safe, that `more_label_text` always
    /// returns the fixed constant regardless of instance state (the real Java `toString()`
    /// behavior), and that Java's constructor always zeroes `col`.
    struct FixedMoreLabelFieldLocation {
        address: Address,
        row: i32,
        char_offset: i32,
    }

    impl ProgramLocation for FixedMoreLabelFieldLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_byte_address(&self) -> Address {
            self.address.clone()
        }
        fn get_row(&self) -> i32 {
            self.row
        }
        fn get_char_offset(&self) -> i32 {
            self.char_offset
        }
        // col keeps the supertrait's zero default, matching `super(p, addr, row, 0, charOffset)`.
    }

    impl CodeUnitLocation for FixedMoreLabelFieldLocation {}

    impl MoreLabelFieldLocation for FixedMoreLabelFieldLocation {}

    #[test]
    fn more_label_text_is_always_the_fixed_constant() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);

        let loc_a: Box<dyn MoreLabelFieldLocation> = Box::new(FixedMoreLabelFieldLocation {
            address: Address::new(ram.clone(), 0x400),
            row: 3,
            char_offset: 5,
        });
        let loc_b: Box<dyn MoreLabelFieldLocation> = Box::new(FixedMoreLabelFieldLocation {
            address: Address::new(ram, 0x800),
            row: 0,
            char_offset: 0,
        });

        // Different addresses/rows/offsets, but toString() ignores all of it.
        assert_eq!(loc_a.more_label_text(), "[more]");
        assert_eq!(loc_b.more_label_text(), "[more]");
        assert_eq!(loc_a.more_label_text(), loc_b.more_label_text());
    }

    #[test]
    fn column_is_always_zero_matching_the_java_constructor() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let loc: Box<dyn MoreLabelFieldLocation> = Box::new(FixedMoreLabelFieldLocation {
            address: Address::new(ram, 0x400),
            row: 7,
            char_offset: 2,
        });

        assert_eq!(loc.get_column(), 0);
        assert_eq!(loc.get_row(), 7);
        assert_eq!(loc.get_char_offset(), 2);
    }
}
