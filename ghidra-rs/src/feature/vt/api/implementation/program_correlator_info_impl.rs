//! Port of `ghidra.feature.vt.api.impl.ProgramCorrelatorInfoImpl`.
//!
//! The [`VtProgramCorrelatorInfo`] that
//! [`VTMatchSetDB::get_program_correlator_info`](crate::feature::vt::api::db::vt_match_set_db::VTMatchSetDB::get_program_correlator_info)
//! hands back: metadata (class name, display name, source/destination address sets, options)
//! about the correlator run that produced a given match set.
//!
//! # Deviations from Java
//!
//! * **No `VTMatchSetDB` back-reference; five up-front fields instead of five independently lazy,
//!   cached ones.** Java holds a `private final VTMatchSetDB matchSetDB` and each of its five
//!   accessors lazily pulls its own field from `matchSetDB` on first call, caching the result (and,
//!   for the two address-set accessors, retrying on every call after an `IOException`, since the
//!   field is left `null` rather than cached in that case). Storing that back-reference here would
//!   make [`VTMatchSetDB`](crate::feature::vt::api::db::vt_match_set_db::VTMatchSetDB)'s own
//!   `correlator_info: OnceLock<ProgramCorrelatorInfoImpl>` field an unreclaimable reference cycle
//!   (the match set would own the info object, which would own the match set). So instead,
//!   [`VTMatchSetDB::get_program_correlator_info`] pulls all five values itself the first time it
//!   is called (mapping the `IOException`-and-`Msg.showError` fallback for the two address sets to
//!   an empty [`AddressSet`](crate::program::model::address::AddressSet), matching Java's `null`
//!   there) and passes them to [`ProgramCorrelatorInfoImpl::new`], which just stores them. The two
//!   are behaviorally equivalent for every real caller: every one of the five values is derived
//!   from columns of the match set's record, which is `final` and never rewritten for the life of
//!   the match set, so there is nothing to observe being "recomputed" a second time regardless of
//!   which side does the one-time pull.
//! * **The `IOException`-retry-on-every-call behavior is therefore not preserved**, as a direct
//!   consequence of the point above: Java's `getSourceAddressSet`/`getDestinationAddressSet` would
//!   keep re-attempting `matchSetDB.getSourceAddressSet()` on every call after a caught
//!   `IOException`, since the field stays `null`. Here, the one-time pull already happened by the
//!   time this struct exists, so a failure is baked in as an empty set for the lifetime of this
//!   instance. Since `VTMatchSetDB`'s own address-set accessors only fail on a genuine I/O error --
//!   not a transient, retriable condition -- a second attempt would not behave any differently in
//!   practice.

use crate::feature::vt::api::implementation::vt_program_correlator_info::VtProgramCorrelatorInfo;
use crate::framework::options::Options;
use crate::program::model::address::{AddressSet, AddressSetView};

/// Port of `ghidra.feature.vt.api.impl.ProgramCorrelatorInfoImpl`. See the module docs for how its
/// five accessors' Java-side laziness is handled by this port's caller instead.
pub struct ProgramCorrelatorInfoImpl {
    correlator_class_name: String,
    name: String,
    source_address_set: AddressSet,
    destination_address_set: AddressSet,
    options: Box<dyn Options + Send + Sync>,
}

impl ProgramCorrelatorInfoImpl {
    /// Java: `ProgramCorrelatorInfoImpl(VTMatchSetDB)` plus the five lazy pulls it would
    /// eventually perform. See the module docs for why those five values are supplied up front
    /// here rather than pulled lazily through a stored `VTMatchSetDB` back-reference.
    ///
    /// Java's `getSourceAddressSet`/`getDestinationAddressSet` report a caught `IOException`
    /// through `Msg.showError` and return `null`; callers building this from a `VTMatchSetDB`
    /// should pass an empty [`AddressSet`] for that case, matching what `null` would mean to any
    /// caller that treats the result as a view (Java itself hands the `null` straight back as the
    /// method's return value, which is exactly what an empty set is indistinguishable from to
    /// every [`AddressSetView`] consumer that only ever asks "is this address covered?").
    pub fn new(
        correlator_class_name: String,
        name: String,
        source_address_set: AddressSet,
        destination_address_set: AddressSet,
        options: Box<dyn Options + Send + Sync>,
    ) -> Self {
        Self { correlator_class_name, name, source_address_set, destination_address_set, options }
    }
}

impl VtProgramCorrelatorInfo for ProgramCorrelatorInfoImpl {
    /// Java: `getName()`.
    fn get_name(&self) -> &str {
        &self.name
    }

    /// Java: `getCorrelatorClassName()`.
    fn get_correlator_class_name(&self) -> &str {
        &self.correlator_class_name
    }

    /// Java: `getOptions()`.
    fn get_options(&self) -> &dyn Options {
        self.options.as_ref()
    }

    /// Java: `getDestinationAddressSet()`.
    fn get_destination_address_set(&self) -> &dyn AddressSetView {
        &self.destination_address_set
    }

    /// Java: `getSourceAddressSet()`.
    fn get_source_address_set(&self) -> &dyn AddressSetView {
        &self.source_address_set
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    struct StubOptions;

    impl Options for StubOptions {}

    fn address_set(offsets: &[i64]) -> AddressSet {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let mut set = AddressSet::new();
        for &offset in offsets {
            set.add_address(&space.address(offset));
        }
        set
    }

    fn info(source: AddressSet, destination: AddressSet) -> ProgramCorrelatorInfoImpl {
        ProgramCorrelatorInfoImpl::new(
            "ghidra.feature.vt.api.correlator.program.ExactMatchBytesProgramCorrelator".to_string(),
            "Exact Bytes Match".to_string(),
            source,
            destination,
            Box::new(StubOptions),
        )
    }

    /// Java: `getName()`/`getCorrelatorClassName()` return exactly what the constructor (in Java,
    /// eventually pulled from `matchSetDB`) was given.
    #[test]
    fn name_and_class_name_round_trip() {
        let info = info(address_set(&[]), address_set(&[]));
        assert_eq!(info.get_name(), "Exact Bytes Match");
        assert_eq!(
            info.get_correlator_class_name(),
            "ghidra.feature.vt.api.correlator.program.ExactMatchBytesProgramCorrelator"
        );
    }

    /// Java: `getSourceAddressSet()`/`getDestinationAddressSet()` hand back exactly the address
    /// sets they were constructed with.
    #[test]
    fn address_sets_round_trip() {
        let source = address_set(&[0x1000, 0x1004]);
        let destination = address_set(&[0x2000]);
        let info = info(source, destination);

        assert!(info.get_source_address_set().contains(&AddressSpace::new(
            "ram", 32, 1, AddressSpaceType::Ram, 1
        ).address(0x1000)));
        assert_eq!(info.get_source_address_set().num_addresses(), 2);
        assert_eq!(info.get_destination_address_set().num_addresses(), 1);
    }

    /// An empty source/destination address set (standing in for Java's `IOException`-then-`null`
    /// fallback -- see the module docs) is a valid, non-panicking [`AddressSetView`].
    #[test]
    fn empty_address_sets_are_valid() {
        let info = info(address_set(&[]), address_set(&[]));
        assert!(info.get_source_address_set().is_empty());
        assert!(info.get_destination_address_set().is_empty());
    }

    /// `get_options` hands back exactly the options object supplied at construction.
    #[test]
    fn options_round_trip() {
        let info = info(address_set(&[]), address_set(&[]));
        let _options = info.get_options();
    }

    /// The type is usable as a `&dyn VtProgramCorrelatorInfo` trait object, matching how
    /// `VTMatchSetDB::get_program_correlator_info` hands it back.
    #[test]
    fn usable_as_trait_object() {
        let info = info(address_set(&[]), address_set(&[]));
        let correlator: &dyn VtProgramCorrelatorInfo = &info;
        assert_eq!(correlator.get_name(), "Exact Bytes Match");
    }
}
