//! Port of `ghidra.program.util.AddressCorrelationRange`.
//!
//! The Java class is a small immutable data holder: an [`AddressRange`] plus the name of the
//! [`AddressCorrelation`](crate::program::util::address_correlation::AddressCorrelation) that
//! produced it.
//!
//! A lightweight placeholder trait already exists at
//! [`crate::program::seam_stubs::AddressCorrelationRangeLike`], used in the return type of
//! [`AddressCorrelation::get_correlated_destination_range`](crate::program::util::address_correlation::AddressCorrelation::get_correlated_destination_range)
//! before this real class was ported (mirroring the precedent set by
//! [`LanguageCompilerSpecPair`](crate::program::model::lang::language_compiler_spec_pair::LanguageCompilerSpecPair)
//! for [`crate::program::seam_stubs::LanguageCompilerSpecPair`)]. Rewiring that trait's existing
//! call sites to this concrete type is out of scope for this port; instead this type implements
//! the seam trait directly, so it can be returned from any `AddressCorrelation` implementor as a
//! `Box<dyn AddressCorrelationRangeLike>` exactly like the Java class would flow through
//! `getCorrelatedDestinationRange`.

use crate::program::model::address::{Address, AddressRange};
use crate::program::seam_stubs::AddressCorrelationRangeLike;

/// A simple object that holds an [`AddressCorrelation`](crate::program::util::address_correlation::AddressCorrelation)
/// address range and the name of the correlation.
///
/// Port of `ghidra.program.util.AddressCorrelationRange`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressCorrelationRange {
    range: AddressRange,
    correlator_name: String,
}

impl AddressCorrelationRange {
    /// Port of `AddressCorrelationRange(AddressRange, String)`.
    ///
    /// Java null-checks both arguments via `Objects.requireNonNull`; that has no port since
    /// neither `AddressRange` nor `String` can be null in Rust -- the type system already rules
    /// it out.
    pub fn new(range: AddressRange, correlator_name: impl Into<String>) -> Self {
        Self { range, correlator_name: correlator_name.into() }
    }

    /// Port of `AddressCorrelationRange.getMinAddress()`.
    pub fn get_min_address(&self) -> Address {
        self.range.min_address().clone()
    }

    /// Port of `AddressCorrelationRange.getRange()`.
    pub fn get_range(&self) -> &AddressRange {
        &self.range
    }

    /// Port of `AddressCorrelationRange.getCorrelatorName()`.
    pub fn get_correlator_name(&self) -> &str {
        &self.correlator_name
    }
}

/// Bridges this real type into the pre-existing seam-stub trait (see the module docs), so it can
/// be handed back from any `AddressCorrelation::get_correlated_destination_range` implementation.
impl AddressCorrelationRangeLike for AddressCorrelationRange {
    fn min_address(&self) -> Address {
        self.get_min_address()
    }

    fn range(&self) -> AddressRange {
        self.range.clone()
    }

    fn correlator_name(&self) -> String {
        self.correlator_name.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn ram_range(start: u64, end: u64) -> AddressRange {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        AddressRange::new(Address::new(ram.clone(), start as i64), Address::new(ram, end as i64))
    }

    #[test]
    fn accessors_round_trip_constructor_arguments() {
        let range = ram_range(0x1000, 0x1010);
        let correlation = AddressCorrelationRange::new(range.clone(), "MyCorrelator");

        assert_eq!(correlation.get_min_address(), *range.min_address());
        assert_eq!(correlation.get_range(), &range);
        assert_eq!(correlation.get_correlator_name(), "MyCorrelator");
    }

    #[test]
    fn accepts_owned_string_or_str_slice_for_correlator_name() {
        let range = ram_range(0, 4);
        let from_str = AddressCorrelationRange::new(range.clone(), "literal");
        let from_string = AddressCorrelationRange::new(range, "owned".to_string());

        assert_eq!(from_str.get_correlator_name(), "literal");
        assert_eq!(from_string.get_correlator_name(), "owned");
    }

    #[test]
    fn implements_the_seam_stub_trait_as_a_trait_object() {
        let range = ram_range(0x2000, 0x2020);
        let boxed: Box<dyn AddressCorrelationRangeLike> =
            Box::new(AddressCorrelationRange::new(range.clone(), "seam"));

        assert_eq!(boxed.min_address(), *range.min_address());
        assert_eq!(boxed.range(), range);
        assert_eq!(boxed.correlator_name(), "seam");
    }

    #[test]
    fn equality_and_clone_compare_by_value() {
        let range = ram_range(0x3000, 0x3004);
        let a = AddressCorrelationRange::new(range.clone(), "same");
        let b = AddressCorrelationRange::new(range.clone(), "same");
        let c = AddressCorrelationRange::new(range, "different");

        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.clone(), a);
    }
}
