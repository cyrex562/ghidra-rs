//! Port of `ghidra.pcode.emu.symz3.trace.SymZ3TraceSpace`.

use std::sync::Arc;

use crate::pcode::emu::symz3::state::SymZ3Space;
use crate::pcode::exec::trace::data::pcode_trace_property_access::PcodeTracePropertyAccess;
use crate::program::model::address::AddressSpace;

/// The constructor-assigned fields of `SymZ3TraceSpace`: the address space, and the trace
/// property used to store and retrieve serialized values.
///
/// Port of the `protected final AddressSpace space`/`protected final
/// PcodeTracePropertyAccess<String> property` fields. Following this crate's composition-over-
/// inheritance convention, a concrete `SymZ3TraceSpace` implementor embeds this struct as a
/// `base` field and reaches its two fields through [`space`](Self::space)/
/// [`property`](Self::property)/[`property_mut`](Self::property_mut) rather than direct field
/// access, mirroring how [`SwiftSourceLanguageBase`
/// ](crate::app::util::sourcelanguage::swift_source_language::SwiftSourceLanguageBase) and
/// similar `*Base` structs elsewhere in this crate hold constructor-assigned state for an
/// otherwise-fieldless trait.
pub struct SymZ3TraceSpaceBase {
    space: Arc<AddressSpace>,
    property: Box<dyn PcodeTracePropertyAccess<String>>,
}

impl SymZ3TraceSpaceBase {
    /// Port of `SymZ3TraceSpace(AddressSpace space, PcodeTracePropertyAccess<String> property)`.
    pub fn new(space: Arc<AddressSpace>, property: Box<dyn PcodeTracePropertyAccess<String>>) -> Self {
        SymZ3TraceSpaceBase { space, property }
    }

    /// The address space this cache covers.
    pub fn space(&self) -> &Arc<AddressSpace> {
        &self.space
    }

    /// The trace property used to store and retrieve serialized values.
    pub fn property(&self) -> &dyn PcodeTracePropertyAccess<String> {
        self.property.as_ref()
    }

    /// The trace property used to store and retrieve serialized values, mutably.
    pub fn property_mut(&mut self) -> &mut dyn PcodeTracePropertyAccess<String> {
        self.property.as_mut()
    }
}

/// The storage space for symbolic values in a trace's address space.
///
/// Port of the abstract class `ghidra.pcode.emu.symz3.trace.SymZ3TraceSpace`, marked `TODO:
/// Delete me` in the Java source itself. This adds to [`SymZ3Space`] the ability to load symbolic
/// values from a trace and the ability to save them back into a trace.
///
/// Per this crate's composition-over-inheritance convention, a concrete implementor embeds
/// [`SymZ3TraceSpaceBase`] (standing in for the two inherited fields) and implements both this
/// trait and [`SymZ3Space`] directly.
pub trait SymZ3TraceSpace: SymZ3Space {
    /// Write this cache back down into a trace.
    ///
    /// Here we simply iterate over every entry in this space, serialize the value, and store it
    /// into the property map at the entry's offset. Because a backing object may not have existed
    /// when creating this space, we must re-fetch the backing object, creating it if it does not
    /// exist.
    ///
    /// Mirrors `SymZ3TraceSpace.writeDown(PcodeTracePropertyAccess<String>)`.
    fn write_down(&self, into: &mut dyn PcodeTracePropertyAccess<String>);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::symz3::model::sym_value_z3::SymValueZ3;
    use crate::pcode::exec::pcode_executor_state_piece::Reason;
    use crate::pcode::exec::pcode_state_callbacks::{PcodeStateCallbacks, NONE};
    use crate::program::model::address::{Address, AddressRange, AddressSpaceType};
    use crate::program::model::lang::language::Language;
    use std::collections::BTreeMap;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    /// A minimal, real `SymZ3TraceSpace` implementor. Following the same documented workaround
    /// already established by `SymZ3Space`'s own tests (`FlatSpace`), the in-memory `SymZ3Space`
    /// surface (`set`/`get`) is keyed by the serialized form of the symbolic offset, since this
    /// crate's `SymValueZ3` has no numeric identity outside of Z3 (see that module's own docs).
    /// For [`write_down`](SymZ3TraceSpace::write_down) specifically -- which needs a real
    /// concrete `Address` per entry, something no `SymValueZ3` can currently produce -- a
    /// dedicated `insert_at_offset` populates a *separate*, genuinely numeric-offset-keyed map,
    /// standing in for whatever backing store a real implementation would use once numeric
    /// concretion of `SymValueZ3` offsets is available.
    struct TestTraceSpace {
        base: SymZ3TraceSpaceBase,
        cells: BTreeMap<String, SymValueZ3>,
        by_offset: BTreeMap<i64, SymValueZ3>,
    }

    impl TestTraceSpace {
        fn new(space: Arc<AddressSpace>, property: Box<dyn PcodeTracePropertyAccess<String>>) -> Self {
            TestTraceSpace {
                base: SymZ3TraceSpaceBase::new(space, property),
                cells: BTreeMap::new(),
                by_offset: BTreeMap::new(),
            }
        }

        fn insert_at_offset(&mut self, offset: i64, val: SymValueZ3) {
            self.by_offset.insert(offset, val);
        }
    }

    impl SymZ3Space for TestTraceSpace {
        fn set<CB: PcodeStateCallbacks>(
            &mut self,
            offset: &SymValueZ3,
            _size: i32,
            val: &SymValueZ3,
            _cb: &CB,
        ) {
            let key = offset.serialize().unwrap_or_default();
            self.cells.insert(key, val.clone());
        }

        fn get<CB: PcodeStateCallbacks>(
            &self,
            offset: &SymValueZ3,
            _size: i32,
            _reason: Reason,
            _cb: &CB,
        ) -> SymValueZ3 {
            let key = offset.serialize().unwrap_or_default();
            self.cells.get(&key).cloned().unwrap_or_default()
        }

        fn printable_summary(&self) -> String {
            format!("{} entries", self.cells.len())
        }

        fn stream_valuations(
            &self,
            _ctx: &dyn crate::feature::seam_stubs::Z3Context,
            _z3p: &crate::pcode::emu::symz3::lib::z3_infix_printer::Z3InfixPrinter,
        ) -> Vec<(String, String)> {
            Vec::new()
        }

        fn get_next_entry(&self, offset: i64) -> Option<(i64, SymValueZ3)> {
            self.by_offset.range(offset..).next().map(|(&k, v)| (k, v.clone()))
        }
    }

    impl SymZ3TraceSpace for TestTraceSpace {
        fn write_down(&self, into: &mut dyn PcodeTracePropertyAccess<String>) {
            let space = self.base.space().clone();
            for (&offset, val) in &self.by_offset {
                let addr = Address::new(space.clone(), offset);
                into.put(&addr, val.serialize().unwrap_or_default());
            }
        }
    }

    /// Records what was written, keyed by address offset, standing in for a real trace's
    /// property storage.
    #[derive(Default)]
    struct RecordingPropertyAccess {
        written: BTreeMap<i64, String>,
    }

    impl PcodeTracePropertyAccess<String> for RecordingPropertyAccess {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }
        fn get(&self, address: &Address) -> Option<String> {
            self.written.get(&address.offset()).cloned()
        }
        fn get_entry(&self, _address: &Address) -> Option<(AddressRange, String)> {
            unimplemented!("not exercised by these tests")
        }
        fn put(&mut self, address: &Address, value: String) {
            self.written.insert(address.offset(), value);
        }
        fn put_range(&mut self, _range: &AddressRange, _value: String) {
            unimplemented!("not exercised by these tests")
        }
        fn clear(&mut self, _range: &AddressRange) {
            unimplemented!("not exercised by these tests")
        }
        fn has_space(&self, _space: &Arc<AddressSpace>) -> bool {
            true
        }
    }

    #[test]
    fn base_accessors_return_constructed_space_and_property() {
        let space = ram_space();
        let property: Box<dyn PcodeTracePropertyAccess<String>> =
            Box::new(RecordingPropertyAccess::default());
        let trace_space = TestTraceSpace::new(space.clone(), property);
        assert_eq!(trace_space.base.space().name(), space.name());
    }

    #[test]
    fn set_then_get_round_trips_through_symz3space() {
        let space = ram_space();
        let property: Box<dyn PcodeTracePropertyAccess<String>> =
            Box::new(RecordingPropertyAccess::default());
        let mut trace_space = TestTraceSpace::new(space, property);

        let offset = SymValueZ3::default();
        let value = SymValueZ3::default();
        trace_space.set(&offset, 4, &value, &NONE);
        let fetched = trace_space.get(&offset, 4, Reason::Inspect, &NONE);
        assert_eq!(fetched, value);
    }

    #[test]
    fn write_down_stores_every_entry_at_its_offset() {
        let space = ram_space();
        let property: Box<dyn PcodeTracePropertyAccess<String>> =
            Box::new(RecordingPropertyAccess::default());
        let mut trace_space = TestTraceSpace::new(space, property);

        trace_space.insert_at_offset(0x10, SymValueZ3::default());
        trace_space.insert_at_offset(0x20, SymValueZ3::default());

        let mut sink = RecordingPropertyAccess::default();
        trace_space.write_down(&mut sink);

        assert_eq!(sink.written.len(), 2);
        assert!(sink.written.contains_key(&0x10));
        assert!(sink.written.contains_key(&0x20));
    }

    #[test]
    fn write_down_with_no_entries_writes_nothing() {
        let space = ram_space();
        let property: Box<dyn PcodeTracePropertyAccess<String>> =
            Box::new(RecordingPropertyAccess::default());
        let trace_space = TestTraceSpace::new(space, property);

        let mut sink = RecordingPropertyAccess::default();
        trace_space.write_down(&mut sink);
        assert!(sink.written.is_empty());
    }

    #[test]
    fn printable_summary_reports_entry_count() {
        let space = ram_space();
        let property: Box<dyn PcodeTracePropertyAccess<String>> =
            Box::new(RecordingPropertyAccess::default());
        let mut trace_space = TestTraceSpace::new(space, property);
        assert_eq!(trace_space.printable_summary(), "0 entries");

        let offset = SymValueZ3::default();
        trace_space.set(&offset, 4, &SymValueZ3::default(), &NONE);
        assert_eq!(trace_space.printable_summary(), "1 entries");
    }
}
