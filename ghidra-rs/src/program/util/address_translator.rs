//! Port of `ghidra.program.util.AddressTranslator`.
//!
//! A genuine open extension point: translates addresses/address ranges/address sets between a
//! "source" program and a "destination" program, with implementations differing in how they
//! decide what counts as an equivalent address (e.g. same offset, same relative distance from a
//! function, etc).
//!
//! Note: an unrelated, differently-scoped `AddressTranslator` trait already exists at
//! [`crate::program::util::address_translation_exception::AddressTranslator`] -- a minimal local
//! seam (`source_program_name`/`destination_program_name`) invented before this, the real
//! six-method interface, was ported. That seam is intentionally left alone (its doc comment
//! already anticipates this file and says a future concrete `AddressTranslator` implementation
//! can implement both without changing `AddressTranslationException`'s public API); it is not
//! merged into this trait here since doing so is out of scope for this port and would touch code
//! this session did not otherwise need to change.
//!
//! There is also an unrelated `ghidra.app.util.viewer.multilisting.AddressTranslator` (a
//! different interface, single `translate` method) already ported at
//! [`crate::app::util::viewer::multilisting::address_translator`]; that is a different Java type
//! entirely and is untouched here.

use std::sync::Arc;

use crate::program::model::address::{Address, AddressRange, AddressSet, AddressSetView};
use crate::program::model::listing::Program;
use crate::program::util::address_translation_exception::AddressTranslationException;

/// Translates addresses from a "source" program into equivalent addresses in a "destination"
/// program.
///
/// Mirrors `ghidra.program.util.AddressTranslator`.
pub trait AddressTranslator {
    /// Gets the destination program for addresses that have been translated.
    ///
    /// Mirrors `getDestinationProgram()`.
    fn destination_program(&self) -> Arc<dyn Program>;

    /// Gets the source program for obtaining the addresses that need to be translated.
    ///
    /// Mirrors `getSourceProgram()`.
    fn source_program(&self) -> Arc<dyn Program>;

    /// Converts the given source address to the returned destination address.
    ///
    /// How the address is equivalent depends upon the particular translator. Returns an
    /// [`AddressTranslationException`] if `source_address` can't be translated to an equivalent
    /// address in the other program.
    ///
    /// Mirrors `getAddress(Address)`.
    fn get_address(&self, source_address: &Address) -> Result<Address, AddressTranslationException>;

    /// Returns true if this translator can translate an address set from the source program to
    /// an address set for the destination program with a one-to-one correspondence between the
    /// two programs' addresses -- i.e. two addresses that make up the start and end of an address
    /// range are at the same distance and relative location from each other as the equivalent two
    /// individually-translated addresses.
    ///
    /// Mirrors `isOneForOneTranslator()`.
    fn is_one_for_one_translator(&self) -> bool;

    /// Converts the given source address range to the returned destination address range.
    ///
    /// Should be implemented if [`is_one_for_one_translator`](Self::is_one_for_one_translator)
    /// returns true. Returns an [`AddressTranslationException`] if the range can't be translated
    /// to an equivalent range in the other program.
    ///
    /// Mirrors `getAddressRange(AddressRange)`.
    fn get_address_range(
        &self,
        source_address_range: &AddressRange,
    ) -> Result<AddressRange, AddressTranslationException>;

    /// Converts the given source address set to the returned destination address set.
    ///
    /// Should be implemented if [`is_one_for_one_translator`](Self::is_one_for_one_translator)
    /// returns true. Returns an [`AddressTranslationException`] if the set can't be translated to
    /// an equivalent set in the other program.
    ///
    /// Mirrors `getAddressSet(AddressSetView)`.
    fn get_address_set(
        &self,
        source_address_set: &dyn AddressSetView,
    ) -> Result<AddressSet, AddressTranslationException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(ram, offset)
    }

    /// A trivial one-for-one translator that shifts every offset by a fixed delta.
    struct ShiftTranslator {
        delta: i64,
    }

    impl AddressTranslator for ShiftTranslator {
        fn destination_program(&self) -> Arc<dyn Program> {
            unimplemented!("not needed by this test")
        }

        fn source_program(&self) -> Arc<dyn Program> {
            unimplemented!("not needed by this test")
        }

        fn get_address(
            &self,
            source_address: &Address,
        ) -> Result<Address, AddressTranslationException> {
            Ok(Address::new(
                source_address.space().clone(),
                source_address.offset() + self.delta,
            ))
        }

        fn is_one_for_one_translator(&self) -> bool {
            true
        }

        fn get_address_range(
            &self,
            source_address_range: &AddressRange,
        ) -> Result<AddressRange, AddressTranslationException> {
            let min = self.get_address(source_address_range.min_address())?;
            let max = self.get_address(source_address_range.max_address())?;
            Ok(AddressRange::new(min, max))
        }

        fn get_address_set(
            &self,
            source_address_set: &dyn AddressSetView,
        ) -> Result<AddressSet, AddressTranslationException> {
            let mut result = AddressSet::new();
            for range in source_address_set.address_ranges() {
                let translated = self.get_address_range(&range)?;
                result.add_range(translated.min_address(), translated.max_address());
            }
            Ok(result)
        }
    }

    #[test]
    fn get_address_shifts_by_delta() {
        let t = ShiftTranslator { delta: 0x10 };
        let src = ram_address(0x100);
        let dst = t.get_address(&src).unwrap();
        assert_eq!(dst.offset(), 0x110);
    }

    #[test]
    fn is_one_for_one_translator_reports_true() {
        let t = ShiftTranslator { delta: 0 };
        assert!(t.is_one_for_one_translator());
    }

    #[test]
    fn get_address_range_translates_both_endpoints() {
        let t = ShiftTranslator { delta: 0x4 };
        let range = AddressRange::new(ram_address(0x0), ram_address(0x10));
        let translated = t.get_address_range(&range).unwrap();
        assert_eq!(translated.min_address().offset(), 0x4);
        assert_eq!(translated.max_address().offset(), 0x14);
    }
}
