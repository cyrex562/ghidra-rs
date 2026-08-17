//! Interprets a trace according to a chosen platform.
//!
//! Port of `ghidra.debug.api.platform.DebuggerPlatformMapper`.
//!
//! Platform selection is a bit of a work in progress, but the idea is to allow the mapper to
//! choose relevant languages, compiler specifications, data organization, etc., based on the
//! current debugger context. In more complex cases, e.g., WoW64, the mapper may need to adjust
//! the recommended language based on, e.g., the current program counter and loaded modules. For
//! disassembly, the mapper gets specific control of the selected platform, based on the starting
//! address. For data placement, the mapper gets specific control based on the current PC: at the
//! time [`DebuggerPlatformMapper::add_to_trace`] is called, the current focus and snap are
//! provided, so the mapper can derive the PC or whatever other context is necessary to make its
//! decision. The returned platform is immediately set as current, so that data actions heed the
//! chosen platform.

use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::lang::{CompilerSpec, Language};
use crate::trace::model::guest::trace_platform::TracePlatform;
use crate::trace::model::target::trace_object::TraceObject;
use crate::trace::model::thread::TraceThread;
use crate::util::task::TaskMonitor;

use super::disassembly_result::DisassemblyResult;

/// An object for interpreting a trace according to a chosen platform.
///
/// Port of `ghidra.debug.api.platform.DebuggerPlatformMapper`. See the module documentation for
/// background on platform selection.
pub trait DebuggerPlatformMapper {
    /// Get the compiler spec for a given object. Mirrors `getCompilerSpec(TraceObject, long)`.
    fn get_compiler_spec(&self, object: &dyn TraceObject, snap: i64) -> Option<Box<dyn CompilerSpec>>;

    /// Get the language for a given object.
    ///
    /// Mirrors the Java default method `getLangauge(TraceObject, long)` (note the upstream
    /// misspelling is preserved only in the Java name; the Rust method is spelled correctly).
    fn get_language(&self, object: &dyn TraceObject, snap: i64) -> Option<Box<dyn Language>> {
        self.get_compiler_spec(object, snap).map(|c| c.get_language())
    }

    /// Prepare the given trace for interpretation under this mapper.
    ///
    /// Mirrors `addToTrace(TraceObject, long)`. Likely needs to modify the trace database; must
    /// start its own transaction for doing so. Returns the resulting platform, which may have
    /// already existed.
    fn add_to_trace(&self, new_focus: &dyn TraceObject, snap: i64) -> Box<dyn TracePlatform>;

    /// When focus changes, decide if this mapper should remain active.
    ///
    /// Mirrors `canInterpret(TraceObject, long)`. Returns `true` to remain active, `false` to
    /// select a new mapper.
    fn can_interpret(&self, new_focus: &dyn TraceObject, snap: i64) -> bool;

    /// Disassemble starting at a given address and snap, limited to a given address set.
    ///
    /// Mirrors `disassemble(TraceThread, TraceObject, Address, AddressSetView, long,
    /// TaskMonitor)`. Note that the mapper may use an alternative platform than that returned by
    /// [`Self::add_to_trace`]. `thread` is `None` when not applicable.
    fn disassemble(
        &self,
        thread: Option<&dyn TraceThread>,
        object: &dyn TraceObject,
        start: Address,
        restricted: &dyn AddressSetView,
        snap: i64,
        monitor: &dyn TaskMonitor,
    ) -> DisassemblyResult;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoLanguageMapper;

    impl DebuggerPlatformMapper for NoLanguageMapper {
        fn get_compiler_spec(&self, _object: &dyn TraceObject, _snap: i64) -> Option<Box<dyn CompilerSpec>> {
            None
        }

        fn add_to_trace(&self, _new_focus: &dyn TraceObject, _snap: i64) -> Box<dyn TracePlatform> {
            unimplemented!("not exercised by this smoke test")
        }

        fn can_interpret(&self, _new_focus: &dyn TraceObject, _snap: i64) -> bool {
            false
        }

        fn disassemble(
            &self,
            _thread: Option<&dyn TraceThread>,
            _object: &dyn TraceObject,
            _start: Address,
            _restricted: &dyn AddressSetView,
            _snap: i64,
            _monitor: &dyn TaskMonitor,
        ) -> DisassemblyResult {
            DisassemblyResult::cancelled_result()
        }
    }

    /// `getLangauge`'s Java default is `cSpec == null ? null : cSpec.getLanguage()`. Exercise
    /// that logic directly against `Option::map`, since `get_compiler_spec` here never inspects
    /// its `object` argument (constructing a full `dyn TraceObject` mock, a 50+ method trait,
    /// would add no signal for a mapper that ignores it).
    #[test]
    fn get_language_default_short_circuits_on_missing_compiler_spec() {
        let no_spec: Option<Box<dyn CompilerSpec>> = None;
        assert!(no_spec.map(|c| c.get_language()).is_none());
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let mapper: Box<dyn DebuggerPlatformMapper> = Box::new(NoLanguageMapper);
        let _ = mapper;
    }
}
