//! Port of `ghidra.program.util.SourceMapFieldLocation`.
//!
//! The Java class is a thin data holder that extends
//! [`ProgramLocation`](crate::program::util::program_location::ProgramLocation) directly and
//! adds a single [`SourceMapEntry`] field (built via `super(program, addr, row, 0, charOffset)`,
//! i.e. always with column `0`). Following the same approach as its sibling `*FieldLocation`
//! cycle cut-points
//! ([`AddressFieldLocation`](crate::program::util::address_field_location::AddressFieldLocation),
//! [`OffsetFieldLocation`](crate::program::util::offset_field_location::OffsetFieldLocation),
//! [`XRefFieldLocation`](crate::program::util::xref_field_location::XRefFieldLocation)), it is
//! ported here as an object-safe trait rather than a concrete struct: implementors provide
//! whatever `Program`/`Address`/row/`charOffset` state the Java constructor captured, and expose
//! it through the supertrait's accessors plus the one accessor this class adds,
//! `get_source_map_entry`. Java's two constructors (populating vs. XML-restore) don't map onto
//! trait methods and are left to implementors.

use std::sync::Arc;

use crate::program::model::sourcemap::SourceMapEntry;
use crate::program::util::program_location::ProgramLocation;

/// A [`ProgramLocation`] for source map information.
///
/// Port of `ghidra.program.util.SourceMapFieldLocation`.
pub trait SourceMapFieldLocation: ProgramLocation {
    /// Returns the [`SourceMapEntry`] associated with this location.
    ///
    /// Port of `SourceMapFieldLocation.getSourceMapEntry()`.
    fn get_source_map_entry(&self) -> Arc<dyn SourceMapEntry>;
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use super::*;
    use crate::program::model::address::{Address, AddressRange, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Program;

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(ram, offset)
    }

    struct FixedSourceMapEntry {
        line_number: i32,
        base_address: Address,
    }

    impl SourceMapEntry for FixedSourceMapEntry {
        fn get_line_number(&self) -> i32 {
            self.line_number
        }
        fn get_source_file(&self) -> crate::program::database::sourcemap::SourceFile {
            crate::program::database::sourcemap::SourceFile::new("/src/main.c")
                .expect("valid source file")
        }
        fn get_base_address(&self) -> Address {
            self.base_address.clone()
        }
        fn get_length(&self) -> i64 {
            4
        }
        fn get_range(&self) -> Option<AddressRange> {
            Some(
                AddressRange::from_start_len(self.base_address.clone(), 4)
                    .expect("no overflow in test"),
            )
        }
        fn compare_to(&self, other: &dyn SourceMapEntry) -> Ordering {
            self.base_address.cmp(&other.get_base_address())
        }
    }

    /// A minimal implementor proving the trait is object-safe and that `get_source_map_entry`
    /// round-trips the entry it was built with, exercised through a `dyn SourceMapFieldLocation`.
    struct FixedSourceMapFieldLocation {
        address: Address,
        row: i32,
        char_offset: i32,
        entry: Arc<dyn SourceMapEntry>,
    }

    impl ProgramLocation for FixedSourceMapFieldLocation {
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
        fn get_column(&self) -> i32 {
            // Java always constructs this with column 0: `super(program, addr, row, 0, charOffset)`.
            0
        }
        fn get_char_offset(&self) -> i32 {
            self.char_offset
        }
    }

    impl SourceMapFieldLocation for FixedSourceMapFieldLocation {
        fn get_source_map_entry(&self) -> Arc<dyn SourceMapEntry> {
            Arc::clone(&self.entry)
        }
    }

    #[test]
    fn trait_object_reports_its_source_map_entry() {
        let entry: Arc<dyn SourceMapEntry> = Arc::new(FixedSourceMapEntry {
            line_number: 42,
            base_address: ram_address(0x400),
        });
        let loc: Box<dyn SourceMapFieldLocation> = Box::new(FixedSourceMapFieldLocation {
            address: ram_address(0x400),
            row: 3,
            char_offset: 7,
            entry: Arc::clone(&entry),
        });

        assert_eq!(loc.get_source_map_entry().get_line_number(), 42);
        assert_eq!(loc.get_row(), 3);
        assert_eq!(loc.get_char_offset(), 7);
    }

    #[test]
    fn column_is_always_zero_matching_the_java_constructor() {
        let entry: Arc<dyn SourceMapEntry> = Arc::new(FixedSourceMapEntry {
            line_number: 1,
            base_address: ram_address(0x800),
        });
        let loc: Box<dyn SourceMapFieldLocation> = Box::new(FixedSourceMapFieldLocation {
            address: ram_address(0x800),
            row: 0,
            char_offset: 0,
            entry,
        });

        assert_eq!(loc.get_column(), 0);
    }
}
