//! Port of `ghidra.app.util.bin.format.pe.dvrt.AbstractImageDynamicRelocationHeader`.
//!
//! The Java class is `abstract`: it `implements StructConverter, PeMarkupable` but supplies no
//! bodies for either interface's methods, leaving them for its concrete subclasses
//! (`ImageArm64XDynamicRelocation`, `ImageBddDynamicRelocation`,
//! `ImageFunctionOverrideDynamicRelocation`, `ImageImportControlTransferDynamicRelocation`,
//! `ImageIndirControlTransferDynamicRelocation`, `ImageSwitchtableBranchDynamicRelocation`, ...
//! all in this same `ghidra.app.util.bin.format.pe.dvrt` package). None of those subclasses are
//! ported yet, so -- following this crate's composition-over-inheritance convention -- this port
//! is a plain data-holding struct meant to be embedded as a `base` field by whichever concrete
//! `dvrt` header is ported next; it does not itself implement `StructConverter` or
//! `PeMarkupable`, mirroring the fact that the Java class leaves both abstract.

/// Common base state for a PE dynamic value relocation table header entry: just the RVA
/// (relative virtual address) of the structure.
///
/// Port of `ghidra.app.util.bin.format.pe.dvrt.AbstractImageDynamicRelocationHeader`.
pub struct AbstractImageDynamicRelocationHeader {
    rva: i64,
}

impl AbstractImageDynamicRelocationHeader {
    /// Creates a new [`AbstractImageDynamicRelocationHeader`].
    ///
    /// Port of `AbstractImageDynamicRelocationHeader(long)`. The Java constructor declares
    /// `throws IOException` but its body never actually performs I/O (it just stores `rva`), so
    /// this port is infallible.
    ///
    /// # Arguments
    ///
    /// * `rva` - The relative virtual address of the structure
    pub fn new(rva: i64) -> Self {
        AbstractImageDynamicRelocationHeader { rva }
    }

    /// The relative virtual address of the structure.
    ///
    /// Java exposes `rva` only as a `protected` field (no getter), reachable by subclasses in
    /// the same package; this crate's composing `dvrt` header types are expected to call this
    /// through their own `base` field.
    pub fn rva(&self) -> i64 {
        self.rva
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_rva() {
        let header = AbstractImageDynamicRelocationHeader::new(0x1000);
        assert_eq!(header.rva(), 0x1000);
    }

    #[test]
    fn rva_round_trips_negative_and_large_values() {
        let header = AbstractImageDynamicRelocationHeader::new(-1);
        assert_eq!(header.rva(), -1);

        let header = AbstractImageDynamicRelocationHeader::new(i64::MAX);
        assert_eq!(header.rva(), i64::MAX);
    }

    #[test]
    fn zero_rva() {
        let header = AbstractImageDynamicRelocationHeader::new(0);
        assert_eq!(header.rva(), 0);
    }

    /// A hypothetical concrete `dvrt` header composing over the abstract base, demonstrating the
    /// intended usage pattern for future subclasses (`ImageArm64XDynamicRelocation`, etc.) that
    /// aren't ported yet.
    struct ConcreteRelocationHeader {
        base: AbstractImageDynamicRelocationHeader,
        extra_field: i32,
    }

    impl ConcreteRelocationHeader {
        fn new(rva: i64, extra_field: i32) -> Self {
            ConcreteRelocationHeader {
                base: AbstractImageDynamicRelocationHeader::new(rva),
                extra_field,
            }
        }
    }

    #[test]
    fn composing_subclass_can_reach_base_rva() {
        let concrete = ConcreteRelocationHeader::new(0x2000, 42);
        assert_eq!(concrete.base.rva(), 0x2000);
        assert_eq!(concrete.extra_field, 42);
    }
}
