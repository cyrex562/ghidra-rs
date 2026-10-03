//! A location where a breakpoint's specification has resolved to a concrete address range.
//!
//! Port of `ghidra.trace.model.breakpoint.TraceBreakpointLocation`.
//!
//! Java's `setEmuEnabled(Lifespan, boolean)`/`setEmuEnabled(long, boolean)` and
//! `setEmuSleigh(Lifespan, String)`/`setEmuSleigh(long, String)` overload pairs are given
//! distinct names, following the convention used throughout this module (see
//! [`TraceBreakpointCommon`](crate::trace::model::breakpoint::trace_breakpoint_common::TraceBreakpointCommon)):
//! the lifespan form keeps the base name, while the single-snap form gets an `_at` suffix.

use std::collections::HashSet;

use crate::program::model::address::{Address, AddressRange};
use crate::trace::model::breakpoint::trace_breakpoint_common::TraceBreakpointCommon;
use crate::trace::model::breakpoint::trace_breakpoint_kind::TraceBreakpointKind;
use crate::trace::model::breakpoint::trace_breakpoint_spec::TraceBreakpointSpec;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
use crate::trace::model::thread::TraceThread;

/// Key for the breakpoint location's address range attribute.
pub const KEY_RANGE: &str = "_range";
/// Key for whether the location is enabled for emulation.
pub const KEY_EMU_ENABLED: &str = "_emu_enabled";
/// Key for the Sleigh source that replaces the breakpointed instruction in emulation.
pub const KEY_EMU_SLEIGH: &str = "_emu_sleigh";

/// A location where a breakpoint's specification has resolved to a concrete address range.
pub trait TraceBreakpointLocation: TraceBreakpointCommon {
    /// Returns the `@TraceObjectInfo` metadata mirrored from the Java annotation on
    /// `TraceBreakpointLocation`.
    fn trace_object_info() -> TraceObjectInfo
    where
        Self: Sized,
    {
        TraceObjectInfo::new(
            "BreakpointLocation",
            "breakpoint location",
            [KEY_RANGE, KEY_EMU_ENABLED, KEY_EMU_SLEIGH],
            [KEY_RANGE],
        )
    }

    /// Get the specification that caused this location to exist.
    fn get_specification(&self) -> Box<dyn TraceBreakpointSpec>;

    /// See [`TraceBreakpointSpec::get_kinds`](crate::trace::model::breakpoint::trace_breakpoint_spec::TraceBreakpointSpec::get_kinds).
    fn get_kinds(&self, snap: i64) -> HashSet<TraceBreakpointKind> {
        self.get_specification().get_kinds(snap)
    }

    /// Get the set of threads to which this breakpoint's application is limited.
    ///
    /// Note, an empty set here implies all contemporary live threads, i.e., the process.
    #[deprecated(since = "12.0", note = "for removal")]
    fn get_threads(&self, snap: i64) -> Vec<Box<dyn TraceThread>>;

    /// Set the range covered by this breakpoint location.
    fn set_range(&mut self, lifespan: Lifespan, range: AddressRange);

    /// Get the range covered by this breakpoint location.
    ///
    /// Most often, esp. for execution breakpoints, this is a single address.
    fn get_range(&self, snap: i64) -> AddressRange;

    /// Get the minimum address in this breakpoint's range.
    ///
    /// See [`Self::get_range`].
    fn get_min_address(&self, snap: i64) -> Address;

    /// Get the maximum address in this breakpoint's range.
    ///
    /// See [`Self::get_range`].
    fn get_max_address(&self, snap: i64) -> Address;

    /// Get the length of this breakpoint, usually 1.
    fn get_length(&self, snap: i64) -> u64;

    /// Set whether this breakpoint is enabled or disabled for emulation, across the given span
    /// of time.
    fn set_emu_enabled(&mut self, lifespan: Lifespan, enabled: bool);

    /// Set whether this breakpoint is enabled or disabled for emulation, from the given snap on.
    fn set_emu_enabled_at(&mut self, snap: i64, enabled: bool);

    /// Check whether this breakpoint is enabled or disabled for emulation at the given snap.
    fn is_emu_enabled(&self, snap: i64) -> bool;

    /// Set Sleigh source to replace the breakpointed instruction in emulation, across the given
    /// span of time.
    ///
    /// The default is simply `emu_swi(); emu_exec_decoded();` -- a non-conditional breakpoint
    /// followed by execution of the actual instruction. Modifying this allows clients to create
    /// conditional breakpoints or simply override or inject additional logic into an emulated
    /// target.
    ///
    /// NOTE: This currently has no effect on access breakpoints, but only execution breakpoints.
    ///
    /// If the specified source fails to compile during emulator set-up, this falls back to
    /// `emu_swi()`.
    fn set_emu_sleigh(&mut self, lifespan: Lifespan, sleigh: &str);

    /// As in [`Self::set_emu_sleigh`], but from a given snap on.
    fn set_emu_sleigh_at(&mut self, snap: i64, sleigh: &str);

    /// Get the Sleigh source that replaces the breakpointed instruction in emulation.
    fn get_emu_sleigh(&self, snap: i64) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::trace::model::target::iface::TraceObjectInterface;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_unique_object::TraceUniqueObject;
    use crate::trace::seam_stubs::ObjectKey;
    use std::sync::Mutex;

    struct MockObjectKey(i32);

    impl ObjectKey for MockObjectKey {
        fn equals(&self, obj: &dyn std::any::Any) -> bool {
            obj.downcast_ref::<MockObjectKey>()
                .is_some_and(|other| other.0 == self.0)
        }

        fn hash_code(&self) -> i32 {
            self.0
        }

        fn compare_to(&self, that: &dyn ObjectKey) -> i32 {
            self.hash_code() - that.hash_code()
        }
    }

    struct MockBreakpointSpec;

    impl TraceUniqueObject for MockBreakpointSpec {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            Box::new(MockObjectKey(1))
        }

        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl TraceObjectInterface for MockBreakpointSpec {
        fn get_object(&self) -> Box<dyn crate::trace::model::target::trace_object::TraceObject> {
            unimplemented!("mock")
        }
    }

    impl TraceBreakpointCommon for MockBreakpointSpec {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_path(&self) -> String {
            "Breakpoints[0]".to_string()
        }

        fn set_name(&mut self, _lifespan: Lifespan, _name: &str) {}
        fn set_name_at(&mut self, _snap: i64, _name: &str) {}

        fn get_name(&self, _snap: i64) -> String {
            "Breakpoints[0]".to_string()
        }

        fn set_enabled(&mut self, _lifespan: Lifespan, _enabled: bool) {}
        fn set_enabled_at(&mut self, _snap: i64, _enabled: bool) {}

        fn is_enabled(&self, _snap: i64) -> bool {
            true
        }

        fn set_comment(&mut self, _lifespan: Lifespan, _comment: Option<&str>) {}
        fn set_comment_at(&mut self, _snap: i64, _comment: Option<&str>) {}

        fn get_comment(&self, _snap: i64) -> Option<String> {
            None
        }

        fn remove(&mut self, _snap: i64) {}
        fn delete(&mut self) {}

        fn is_valid(&self, _snap: i64) -> bool {
            true
        }

        fn is_alive(&self, _span: Lifespan) -> bool {
            true
        }
    }

    impl TraceBreakpointSpec for MockBreakpointSpec {
        fn get_expression(&self, _snap: i64) -> String {
            "*0x1234".to_string()
        }

        fn set_kinds(&mut self, _lifespan: Lifespan, _kinds: &[TraceBreakpointKind]) {}
        fn set_kinds_at(&mut self, _snap: i64, _kinds: &[TraceBreakpointKind]) {}

        fn get_kinds(&self, _snap: i64) -> HashSet<TraceBreakpointKind> {
            [TraceBreakpointKind::SwExecute].into_iter().collect()
        }

        fn get_locations(&self, _snap: i64) -> Vec<Box<dyn TraceBreakpointLocation>> {
            Vec::new()
        }
    }

    /// A minimal in-memory breakpoint location, used to prove the trait is object-safe and
    /// behaves as expected.
    struct MockLocation {
        range: Mutex<AddressRange>,
        emu_enabled: Mutex<bool>,
        emu_sleigh: Mutex<String>,
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    fn make_location() -> MockLocation {
        MockLocation {
            range: Mutex::new(AddressRange::new(addr(0x1000), addr(0x1000))),
            emu_enabled: Mutex::new(true),
            emu_sleigh: Mutex::new(String::new()),
        }
    }

    impl TraceUniqueObject for MockLocation {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            Box::new(MockObjectKey(2))
        }

        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl TraceObjectInterface for MockLocation {
        fn get_object(&self) -> Box<dyn crate::trace::model::target::trace_object::TraceObject> {
            unimplemented!("mock")
        }
    }

    impl TraceBreakpointCommon for MockLocation {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_path(&self) -> String {
            "Breakpoints[0][0]".to_string()
        }

        fn set_name(&mut self, _lifespan: Lifespan, _name: &str) {}
        fn set_name_at(&mut self, _snap: i64, _name: &str) {}

        fn get_name(&self, _snap: i64) -> String {
            "Breakpoints[0][0]".to_string()
        }

        fn set_enabled(&mut self, _lifespan: Lifespan, _enabled: bool) {}
        fn set_enabled_at(&mut self, _snap: i64, _enabled: bool) {}

        fn is_enabled(&self, _snap: i64) -> bool {
            true
        }

        fn set_comment(&mut self, _lifespan: Lifespan, _comment: Option<&str>) {}
        fn set_comment_at(&mut self, _snap: i64, _comment: Option<&str>) {}

        fn get_comment(&self, _snap: i64) -> Option<String> {
            None
        }

        fn remove(&mut self, _snap: i64) {}
        fn delete(&mut self) {}

        fn is_valid(&self, _snap: i64) -> bool {
            true
        }

        fn is_alive(&self, _span: Lifespan) -> bool {
            true
        }
    }

    impl TraceBreakpointLocation for MockLocation {
        fn get_specification(&self) -> Box<dyn TraceBreakpointSpec> {
            Box::new(MockBreakpointSpec)
        }

        fn get_threads(&self, _snap: i64) -> Vec<Box<dyn TraceThread>> {
            Vec::new()
        }

        fn set_range(&mut self, _lifespan: Lifespan, range: AddressRange) {
            *self.range.lock().unwrap() = range;
        }

        fn get_range(&self, _snap: i64) -> AddressRange {
            self.range.lock().unwrap().clone()
        }

        fn get_min_address(&self, snap: i64) -> Address {
            self.get_range(snap).min_address().clone()
        }

        fn get_max_address(&self, snap: i64) -> Address {
            self.get_range(snap).max_address().clone()
        }

        fn get_length(&self, snap: i64) -> u64 {
            self.get_range(snap).length()
        }

        fn set_emu_enabled(&mut self, _lifespan: Lifespan, enabled: bool) {
            *self.emu_enabled.lock().unwrap() = enabled;
        }

        fn set_emu_enabled_at(&mut self, _snap: i64, enabled: bool) {
            *self.emu_enabled.lock().unwrap() = enabled;
        }

        fn is_emu_enabled(&self, _snap: i64) -> bool {
            *self.emu_enabled.lock().unwrap()
        }

        fn set_emu_sleigh(&mut self, _lifespan: Lifespan, sleigh: &str) {
            *self.emu_sleigh.lock().unwrap() = sleigh.to_string();
        }

        fn set_emu_sleigh_at(&mut self, _snap: i64, sleigh: &str) {
            *self.emu_sleigh.lock().unwrap() = sleigh.to_string();
        }

        fn get_emu_sleigh(&self, _snap: i64) -> String {
            self.emu_sleigh.lock().unwrap().clone()
        }
    }

    #[test]
    fn is_object_safe() {
        let loc = make_location();
        let _dyn_ref: &dyn TraceBreakpointLocation = &loc;
    }

    #[test]
    fn get_kinds_delegates_to_specification() {
        let loc = make_location();
        let kinds = loc.get_kinds(0);
        assert_eq!(kinds.len(), 1);
        assert!(kinds.contains(&TraceBreakpointKind::SwExecute));
    }

    #[test]
    fn set_and_get_range_roundtrip() {
        let mut loc = make_location();
        let range = AddressRange::new(addr(0x2000), addr(0x2010));
        loc.set_range(Lifespan::span(0, 10), range.clone());
        assert_eq!(loc.get_range(0), range);
        assert_eq!(loc.get_min_address(0), addr(0x2000));
        assert_eq!(loc.get_max_address(0), addr(0x2010));
        assert_eq!(loc.get_length(0), 17);
    }

    #[test]
    fn set_and_check_emu_enabled() {
        let mut loc = make_location();
        assert!(loc.is_emu_enabled(0));
        loc.set_emu_enabled_at(0, false);
        assert!(!loc.is_emu_enabled(0));
    }

    #[test]
    fn set_and_get_emu_sleigh_roundtrip() {
        let mut loc = make_location();
        assert_eq!(loc.get_emu_sleigh(0), "");
        loc.set_emu_sleigh_at(0, "emu_swi(); emu_exec_decoded();");
        assert_eq!(loc.get_emu_sleigh(0), "emu_swi(); emu_exec_decoded();");
    }

    #[test]
    fn trace_object_info_matches_java_annotation() {
        let info = <MockLocation as TraceBreakpointLocation>::trace_object_info();
        assert_eq!(info.schema_name, "BreakpointLocation");
        assert_eq!(info.short_name, "breakpoint location");
        assert_eq!(
            info.attributes,
            vec![
                KEY_RANGE.to_string(),
                KEY_EMU_ENABLED.to_string(),
                KEY_EMU_SLEIGH.to_string(),
            ]
        );
        assert_eq!(info.fixed_keys, vec![KEY_RANGE.to_string()]);
    }
}
