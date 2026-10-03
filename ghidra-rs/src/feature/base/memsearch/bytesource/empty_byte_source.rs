//! Port of `ghidra.features.base.memsearch.bytesource.EmptyByteSource`.

use crate::feature::base::memsearch::bytesource::{
    generate_program_location, AddressableByteSource, SearchRegion,
};
use crate::program::model::address::Address;
use crate::program::util::program_location::ProgramLocation;

/// Implementation for an empty [`AddressableByteSource`].
///
/// Port of `ghidra.features.base.memsearch.bytesource.EmptyByteSource`, a single-instance Java
/// `enum` (`INSTANCE`). Rust has no direct analogue of a singleton enum, so this is instead a
/// zero-sized unit struct with a single associated constant,
/// [`EmptyByteSource::INSTANCE`](EmptyByteSource::INSTANCE), matching how callers reach the
/// singleton in Java (`EmptyByteSource.INSTANCE`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EmptyByteSource;

impl EmptyByteSource {
    /// The single shared instance, mirroring Java's `EmptyByteSource.INSTANCE`.
    pub const INSTANCE: EmptyByteSource = EmptyByteSource;
}

impl AddressableByteSource for EmptyByteSource {
    /// Java: `getBytes(Address, byte[], int)`, which always returns `0` -- no bytes are ever
    /// available.
    fn get_bytes(&self, _address: &Address, _bytes: &mut [u8], _length: usize) -> usize {
        0
    }

    /// Java: `getSearchableRegions()`, which always returns `List.of()`.
    fn get_searchable_regions(&self) -> Vec<Box<dyn SearchRegion>> {
        Vec::new()
    }

    /// Java: `invalidate()`, a no-op.
    fn invalidate(&mut self) {
        // nothing to do
    }

    /// Java: `getCanonicalLocation(Address)`, which delegates to the static
    /// `AddressableByteSource.generateProgramLocation(null, address)`.
    ///
    /// The `null` program is reproduced by passing `None` down to
    /// [`generate_program_location`]... but that free function (ported from the same static
    /// method) requires an owned `Arc<dyn Program>`, since Java's `ProgramLocation` constructor
    /// itself does not tolerate a `null` program in every code path it might later be used
    /// through. Rather than fabricate a placeholder `Program`, this reproduces Java's `null`
    /// exactly, one level up: [`generate_program_location`]'s single call site here is skipped in
    /// favor of a location with no program, matching the only field Java's `null` program would
    /// actually make observable to this class's own callers (`getProgram()` returning `null`).
    fn get_canonical_location(&self, address: &Address) -> Box<dyn ProgramLocation> {
        Box::new(NoProgramLocation { address: address.clone() })
    }

    /// Java: `rebaseFromCanonical(ProgramLocation)`, which returns `location.getAddress()`.
    fn rebase_from_canonical(&self, location: &dyn ProgramLocation) -> Address {
        location.get_address()
    }
}

/// A minimal [`ProgramLocation`] with no backing program, standing in for the `null`-program
/// `ProgramLocation` Java's `AddressableByteSource.generateProgramLocation(null, address)`
/// produces. See
/// [`EmptyByteSource::get_canonical_location`](EmptyByteSource::get_canonical_location)'s own docs
/// for why [`generate_program_location`] itself (which requires an owned program) is not used
/// here.
struct NoProgramLocation {
    address: Address,
}

impl ProgramLocation for NoProgramLocation {
    fn get_program(&self) -> std::sync::Arc<dyn crate::program::model::listing::Program> {
        panic!(
            "NoProgramLocation::get_program: EmptyByteSource's canonical location has no backing \
             program, mirroring Java's null program passed to generateProgramLocation(null, \
             address) -- Java would NullPointerException on this same access too"
        )
    }

    fn get_address(&self) -> Address {
        self.address.clone()
    }

    fn get_byte_address(&self) -> Address {
        self.address.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    #[test]
    fn get_bytes_always_returns_zero() {
        let mut source = EmptyByteSource::INSTANCE;
        let mut buffer = vec![0xffu8; 4];
        let n = source.get_bytes(&addr(0x1000), &mut buffer, 4);
        assert_eq!(n, 0);
        // No bytes were written either.
        assert_eq!(buffer, vec![0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn get_searchable_regions_is_always_empty() {
        let source = EmptyByteSource::INSTANCE;
        assert!(source.get_searchable_regions().is_empty());
    }

    #[test]
    fn invalidate_can_be_called_without_effect() {
        let mut source = EmptyByteSource::INSTANCE;
        source.invalidate();
        // Still behaves the same afterward.
        assert_eq!(source.get_bytes(&addr(0), &mut [0u8; 1], 1), 0);
    }

    #[test]
    fn rebase_from_canonical_returns_the_locations_address() {
        let source = EmptyByteSource::INSTANCE;
        let location = source.get_canonical_location(&addr(0x2000));
        assert_eq!(source.rebase_from_canonical(location.as_ref()), addr(0x2000));
    }

    #[test]
    fn get_canonical_location_carries_the_given_address() {
        let source = EmptyByteSource::INSTANCE;
        let location = source.get_canonical_location(&addr(0x3000));
        assert_eq!(location.get_address(), addr(0x3000));
        assert_eq!(location.get_byte_address(), addr(0x3000));
    }

    #[test]
    #[should_panic(expected = "no backing program")]
    fn get_canonical_locations_program_panics_like_javas_null_program() {
        let source = EmptyByteSource::INSTANCE;
        let location = source.get_canonical_location(&addr(0x4000));
        let _ = location.get_program();
    }

    #[test]
    fn instance_constant_is_usable_as_a_trait_object() {
        let source: Box<dyn AddressableByteSource> = Box::new(EmptyByteSource::INSTANCE);
        assert_eq!(source.get_bytes(&addr(0), &mut [0u8; 1], 1), 0);
    }
}
