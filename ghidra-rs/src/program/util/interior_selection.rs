//! Port of `ghidra.program.util.InteriorSelection`.
//!
//! `InteriorSelection` is a plain data holder (not selected as a dependency-cycle cut point), so
//! it is ported as a concrete struct rather than a trait. It holds two
//! [`ProgramLocation`](crate::program::util::program_location::ProgramLocation) trait objects
//! (`from`/`to`) plus the two [`Address`]es (`start`/`end`) delimiting the selected interior
//! range.
//!
//! `ProgramLocation.equals()`/`hashCode()` are real, concrete, value-based methods on the Java
//! base class (comparing `getClass()`, the owning `Program`'s identity, `addr`, `refAddr`,
//! `byteAddr`, `componentPath`, `row`, and `col`) -- but this crate's port of `ProgramLocation`
//! (see its module docs) intentionally omits them as "Object-identity boilerplate ... implementors
//! can derive/implement directly on their concrete type," since they don't map cleanly onto an
//! object-safe trait. `InteriorSelection.equals()`/`hashCode()` are themselves defined purely in
//! terms of `from.equals(...)`/`to.equals(...)`, so to give `InteriorSelection` real (rather than
//! stubbed) equality/hashing, [`program_locations_match`] reimplements the value-based part of
//! that comparison directly against `ProgramLocation`'s object-safe accessors (`get_program`,
//! `get_address`, `get_byte_address`, `get_ref_address`, `get_component_path`, `get_row`,
//! `get_column`, `get_char_offset`). Two divergences from the real Java `ProgramLocation.equals`:
//! - It skips the `getClass() != obj.getClass()` check (no generic "same concrete type" test is
//!   available through an object-safe trait), so two different concrete `ProgramLocation` types
//!   with identical field values will compare equal here where Java would consider them unequal.
//! - `get_program()` identity is compared via `Arc::ptr_eq`, which mirrors Java's `program !=
//!   other.program` reference check only if implementors return the *same* cloned `Arc` each
//!   call (rather than constructing a fresh one), matching this trait's established convention
//!   elsewhere in the crate.
//!
//! `InteriorSelection.equals()` itself has a genuine quirk, faithfully reproduced here: it
//! compares only `from`/`to`, never `start`/`end`, even though `start`/`end` are separate
//! constructor-supplied fields that need not be derivable from `from`/`to`. Two selections with
//! matching `from`/`to` but different `start`/`end` therefore compare equal. See
//! `equal_ignores_differing_start_and_end_addresses` below.
//!
//! `getByteLength()` narrows a `long` difference (`end.subtract(start) + 1`) to an `int` via a
//! plain Java narrowing cast, which silently truncates/wraps for a selection spanning more than
//! `Integer.MAX_VALUE` bytes. This port reproduces that with Rust's equivalent `as i32` truncating
//! cast rather than a checked or saturating conversion; see
//! `byte_length_wraps_for_a_selection_larger_than_i32_max` below.

use std::hash::{Hash, Hasher};

use crate::program::model::address::Address;
use crate::program::util::program_location::ProgramLocation;

/// Compares two [`ProgramLocation`] trait objects field-by-field, reimplementing the value-based
/// part of Java's real `ProgramLocation.equals()` against this crate's object-safe accessors. See
/// the module docs for the two known divergences from the Java original.
fn program_locations_match(a: &dyn ProgramLocation, b: &dyn ProgramLocation) -> bool {
    std::sync::Arc::ptr_eq(&a.get_program(), &b.get_program())
        && a.get_address() == b.get_address()
        && a.get_byte_address() == b.get_byte_address()
        && a.get_ref_address() == b.get_ref_address()
        && a.get_component_path() == b.get_component_path()
        && a.get_row() == b.get_row()
        && a.get_column() == b.get_column()
        && a.get_char_offset() == b.get_char_offset()
}

/// Feeds the same fields [`program_locations_match`] compares into `state`, so
/// [`InteriorSelection`]'s `Hash` impl stays consistent with its `PartialEq` impl.
fn hash_program_location(loc: &dyn ProgramLocation, state: &mut impl Hasher) {
    // `Address` doesn't implement `std::hash::Hash`, so its `Display` output is hashed instead
    // (it's already used as the equality/`Display` representation elsewhere in this file).
    (std::sync::Arc::as_ptr(&loc.get_program()) as *const () as usize).hash(state);
    loc.get_address().to_string().hash(state);
    loc.get_byte_address().to_string().hash(state);
    loc.get_ref_address().map(|a| a.to_string()).hash(state);
    loc.get_component_path().hash(state);
    loc.get_row().hash(state);
    loc.get_column().hash(state);
    loc.get_char_offset().hash(state);
}

/// Specifies a selection that consists of components inside a structure.
///
/// Port of `ghidra.program.util.InteriorSelection`. See the module docs for the faithfully
/// reproduced `equals`/`hashCode`/`getByteLength` quirks.
pub struct InteriorSelection {
    from: Box<dyn ProgramLocation>,
    to: Box<dyn ProgramLocation>,
    start: Address,
    end: Address,
}

impl InteriorSelection {
    /// Construct a new interior selection.
    ///
    /// Port of `InteriorSelection(ProgramLocation from, ProgramLocation to, Address start,
    /// Address end)`.
    pub fn new(from: Box<dyn ProgramLocation>, to: Box<dyn ProgramLocation>, start: Address, end: Address) -> Self {
        Self { from, to, start, end }
    }

    /// Get the start location.
    ///
    /// Port of `InteriorSelection.getFrom()`.
    pub fn get_from(&self) -> &dyn ProgramLocation {
        self.from.as_ref()
    }

    /// Get the end location.
    ///
    /// Port of `InteriorSelection.getTo()`.
    pub fn get_to(&self) -> &dyn ProgramLocation {
        self.to.as_ref()
    }

    /// Get the start address of this selection.
    ///
    /// Port of `InteriorSelection.getStartAddress()`.
    pub fn get_start_address(&self) -> &Address {
        &self.start
    }

    /// Get the end address of this selection.
    ///
    /// Port of `InteriorSelection.getEndAddress()`.
    pub fn get_end_address(&self) -> &Address {
        &self.end
    }

    /// Get the number of bytes contained in the selection.
    ///
    /// Port of `InteriorSelection.getByteLength()`. See the module docs: this truncates to `i32`
    /// exactly like Java's narrowing `(int)` cast, silently wrapping for very large selections.
    pub fn get_byte_length(&self) -> i32 {
        let diff = self.end.subtract(&self.start);
        (diff + 1) as i32
    }
}

impl PartialEq for InteriorSelection {
    fn eq(&self, other: &Self) -> bool {
        program_locations_match(self.from.as_ref(), other.from.as_ref())
            && program_locations_match(self.to.as_ref(), other.to.as_ref())
    }
}

impl Eq for InteriorSelection {}

impl Hash for InteriorSelection {
    fn hash<H: Hasher>(&self, state: &mut H) {
        hash_program_location(self.from.as_ref(), state);
        hash_program_location(self.to.as_ref(), state);
    }
}

impl std::fmt::Debug for InteriorSelection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `ProgramLocation` trait objects don't implement `Debug`, so this reports the pieces of
        // an `InteriorSelection` that are always available: the from/to addresses and the
        // start/end range, rather than deriving straight through the boxed trait objects.
        f.debug_struct("InteriorSelection")
            .field("from_address", &self.from.get_address())
            .field("to_address", &self.to.get_address())
            .field("start", &self.start)
            .field("end", &self.end)
            .finish()
    }
}

impl std::fmt::Display for InteriorSelection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "From = {}, To = {}",
            self.from.get_address(),
            self.to.get_address()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Program;
    use std::sync::Arc;

    struct MockProgram;
    impl DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "test".to_string()
        }
    }

    #[derive(Clone)]
    struct FixedLocation {
        program: Arc<dyn Program>,
        address: Address,
    }

    impl ProgramLocation for FixedLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::clone(&self.program)
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_byte_address(&self) -> Address {
            self.address.clone()
        }
    }

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 1);
        Address::new(ram, offset)
    }

    fn fixed_location(program: &Arc<dyn Program>, offset: i64) -> Box<dyn ProgramLocation> {
        Box::new(FixedLocation {
            program: Arc::clone(program),
            address: ram_address(offset),
        })
    }

    #[test]
    fn accessors_round_trip_constructor_arguments() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let from = fixed_location(&program, 0x1000);
        let to = fixed_location(&program, 0x1010);
        let start = ram_address(0x1000);
        let end = ram_address(0x1010);

        let selection = InteriorSelection::new(from, to, start.clone(), end.clone());

        assert_eq!(selection.get_from().get_address(), ram_address(0x1000));
        assert_eq!(selection.get_to().get_address(), ram_address(0x1010));
        assert_eq!(selection.get_start_address(), &start);
        assert_eq!(selection.get_end_address(), &end);
    }

    #[test]
    fn byte_length_is_inclusive_of_both_endpoints() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let selection = InteriorSelection::new(
            fixed_location(&program, 0x1000),
            fixed_location(&program, 0x1010),
            ram_address(0x1000),
            ram_address(0x100f),
        );

        // 0x100f - 0x1000 + 1 = 16 bytes.
        assert_eq!(selection.get_byte_length(), 16);
    }

    #[test]
    fn byte_length_wraps_for_a_selection_larger_than_i32_max() {
        // Faithfully reproduces Java's `(int) (end.subtract(start) + 1)` narrowing cast, which
        // silently truncates/wraps rather than saturating or panicking.
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let start = ram_address(0);
        let end = ram_address(i64::from(i32::MAX) + 10); // diff + 1 overflows i32.
        let selection = InteriorSelection::new(
            fixed_location(&program, 0),
            fixed_location(&program, 0),
            start.clone(),
            end.clone(),
        );

        let diff = end.subtract(&start);
        let expected_wrapped = (diff + 1) as i32;
        assert!(expected_wrapped < 0, "sanity check: this should have wrapped negative");
        assert_eq!(selection.get_byte_length(), expected_wrapped);
    }

    #[test]
    fn equal_when_from_and_to_match() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let s1 = InteriorSelection::new(
            fixed_location(&program, 0x1000),
            fixed_location(&program, 0x1010),
            ram_address(0x1000),
            ram_address(0x1010),
        );
        let s2 = InteriorSelection::new(
            fixed_location(&program, 0x1000),
            fixed_location(&program, 0x1010),
            ram_address(0x1000),
            ram_address(0x1010),
        );

        assert_eq!(s1, s2);
    }

    #[test]
    fn equal_ignores_differing_start_and_end_addresses() {
        // Faithfully reproduces the Java quirk: InteriorSelection.equals() only ever compares
        // `from`/`to`, never `start`/`end`, even though they're independent constructor fields.
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let s1 = InteriorSelection::new(
            fixed_location(&program, 0x1000),
            fixed_location(&program, 0x1010),
            ram_address(0x1000),
            ram_address(0x1010),
        );
        let s2 = InteriorSelection::new(
            fixed_location(&program, 0x1000),
            fixed_location(&program, 0x1010),
            // Deliberately different start/end from s1.
            ram_address(0x9999),
            ram_address(0xaaaa),
        );

        assert_eq!(s1, s2, "equals() should ignore start/end and only compare from/to");
        assert_ne!(s1.get_start_address(), s2.get_start_address());
        assert_ne!(s1.get_end_address(), s2.get_end_address());
    }

    #[test]
    fn not_equal_when_from_differs() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let s1 = InteriorSelection::new(
            fixed_location(&program, 0x1000),
            fixed_location(&program, 0x1010),
            ram_address(0x1000),
            ram_address(0x1010),
        );
        let s2 = InteriorSelection::new(
            fixed_location(&program, 0x2000),
            fixed_location(&program, 0x1010),
            ram_address(0x1000),
            ram_address(0x1010),
        );

        assert_ne!(s1, s2);
    }

    #[test]
    fn equal_selections_hash_the_same() {
        use std::collections::hash_map::DefaultHasher;

        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let s1 = InteriorSelection::new(
            fixed_location(&program, 0x1000),
            fixed_location(&program, 0x1010),
            ram_address(0x1000),
            ram_address(0x1010),
        );
        let s2 = InteriorSelection::new(
            fixed_location(&program, 0x1000),
            fixed_location(&program, 0x1010),
            ram_address(0x1000),
            ram_address(0x1010),
        );

        let hash_of = |s: &InteriorSelection| {
            let mut hasher = DefaultHasher::new();
            s.hash(&mut hasher);
            hasher.finish()
        };

        assert_eq!(hash_of(&s1), hash_of(&s2));
    }

    #[test]
    fn display_uses_from_and_to_addresses_not_start_and_end() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let selection = InteriorSelection::new(
            fixed_location(&program, 0x1000),
            fixed_location(&program, 0x1010),
            ram_address(0x9999),
            ram_address(0xaaaa),
        );

        let s = selection.to_string();
        assert!(s.contains(&ram_address(0x1000).to_string()), "expected from address in: {s}");
        assert!(s.contains(&ram_address(0x1010).to_string()), "expected to address in: {s}");
        assert!(!s.contains(&ram_address(0x9999).to_string()), "start address should not appear: {s}");
    }
}
