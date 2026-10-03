//! Port of `ghidra.app.plugin.core.debug.disassemble.DisassemblyInject`.
//!
//! A configuration inject for automatic disassembly at the program counter: the debugger's
//! platform mapper invokes every applicable inject, ordered by priority, just before and just
//! after it auto-disassembles.
//!
//! # Shape
//!
//! Java is an `interface extends ExtensionPoint` whose methods are all defaults, with two in-repo
//! implementors, so it is a genuine open extension point and becomes a `trait`.
//!
//! # Deviations
//!
//! * **`getInfo()`.** Java's default reads the implementor's class annotation reflectively
//!   (`getClass().getAnnotation(DisassemblyInjectInfo.class)`) and, if it is missing, logs a
//!   warning and falls back to the annotation on the interface itself
//!   (`@DisassemblyInjectInfo(platforms = {})`). Per the project's annotation (R4) decision, the
//!   annotation is a [`DisassemblyInjectInfo`] value that each implementor supplies, so
//!   [`DisassemblyInject::get_info`] is a required method: a "missing annotation" can no longer
//!   happen at runtime. An implementor that genuinely wants Java's fallback returns
//!   [`DisassemblyInjectInfo::DEFAULT`].
//! * **`TraceDisassembleCommand`.** Not yet ported; [`DisassemblyInject::pre`] takes the
//!   forward-reference placeholder [`crate::app::seam_stubs::TraceDisassembleCommand`] by `&mut`,
//!   since Java's contract is that the inject configures the command before it executes.

use crate::app::plugin::core::debug::disassemble::DisassemblyInjectInfo;
use crate::app::seam_stubs::TraceDisassembleCommand;
use crate::framework::seam_stubs::PluginTool;
use crate::program::model::address::AddressSetView;
use crate::trace::model::guest::trace_platform::TracePlatform;
use crate::trace::model::thread::TraceThread;
use crate::util::classfinder::ExtensionPoint;

/// Port of the Java interface `ghidra.app.plugin.core.debug.disassemble.DisassemblyInject`.
pub trait DisassemblyInject: ExtensionPoint {
    /// Get the information annotation on this inject. Mirrors `getInfo()`; see the module docs
    /// for why this is required rather than reflective.
    fn get_info(&self) -> &'static DisassemblyInjectInfo;

    /// Check if this inject applies to the given trace platform. Mirrors
    /// `isApplicable(TracePlatform)`.
    ///
    /// True if any of [`DisassemblyInjectInfo::platforms`] names the platform's language ID and
    /// either leaves the compiler ID blank or names the platform's compiler-spec ID.
    fn is_applicable(&self, platform: &dyn TracePlatform) -> bool {
        let info = self.get_info();
        if info.platforms.is_empty() {
            return false;
        }
        let lang_id = platform.platform_language().get_language_id().to_string();
        // Java evaluates getCompilerSpec() only once a language matches; do the same so a
        // platform whose language never matches is never asked for its compiler spec.
        let mut compiler_spec_id: Option<String> = None;
        info.platforms.iter().any(|p| {
            if p.lang_id != lang_id {
                return false;
            }
            let cid = compiler_spec_id.get_or_insert_with(|| {
                platform
                    .platform_compiler_spec()
                    .get_compiler_spec_id()
                    .to_string()
            });
            p.matches(&lang_id, cid)
        })
    }

    /// Get this inject's position in the invocation order. Mirrors `getPriority()`:
    /// `getInfo().priority()`.
    fn get_priority(&self) -> i32 {
        self.get_info().priority
    }

    /// A pre-auto disassembly hook. Mirrors `pre(PluginTool, TraceDisassembleCommand,
    /// TracePlatform, long, TraceThread, AddressSetView, AddressSetView)`.
    ///
    /// Invoked by the debugger platform mapper before disassembly actually begins, within the
    /// command's background thread. In general, the inject should limit its operation to
    /// inspecting the trace database and configuring the command.
    ///
    /// * `tool` - the tool that will execute the command
    /// * `command` - the command to be configured, which is about to execute
    /// * `platform` - the trace platform for the disassembler
    /// * `snap` - the snap at which to disassemble
    /// * `thread` - the thread whose PC is being disassembled
    /// * `start_set` - the starting address set, usually just the PC
    /// * `restricted` - the set of disassemblable addresses
    ///
    /// The default does nothing, as in Java.
    #[allow(clippy::too_many_arguments)]
    fn pre(
        &self,
        _tool: &dyn PluginTool,
        _command: &mut TraceDisassembleCommand,
        _platform: &dyn TracePlatform,
        _snap: i64,
        _thread: &dyn TraceThread,
        _start_set: &dyn AddressSetView,
        _restricted: &dyn AddressSetView,
    ) {
    }

    /// A post-auto disassembly hook. Mirrors `post(PluginTool, TracePlatform, long,
    /// AddressSetView)`.
    ///
    /// Invoked by the debugger platform mapper after disassembly completes, within the command's
    /// background thread.
    ///
    /// * `tool` - the tool that just executed the disassembly command
    /// * `platform` - the trace platform for the disassembler
    /// * `snap` - the snap at which disassembly was performed
    /// * `disassembled` - the addresses that were actually disassembled
    ///
    /// The default does nothing, as in Java.
    fn post(
        &self,
        _tool: &dyn PluginTool,
        _platform: &dyn TracePlatform,
        _snap: i64,
        _disassembled: &dyn AddressSetView,
    ) {
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::core::debug::disassemble::PlatformInfo;
    use crate::program::model::address::AddressSet;
    use crate::program::model::lang::cspec_test_support::{TestCompilerSpec, TestCspecLanguage};
    use crate::program::model::lang::{CompilerSpec, Language};
    use std::cell::Cell;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A platform whose language is `x86:LE:64:default` and compiler spec is `gcc`, counting how
    /// often its compiler spec is requested.
    #[derive(Default)]
    struct X86GccPlatform {
        cspec_requests: AtomicUsize,
    }

    impl TracePlatform for X86GccPlatform {
        fn platform_language(&self) -> Box<dyn Language> {
            Box::new(TestCspecLanguage { big_endian: false })
        }
        fn platform_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            self.cspec_requests.fetch_add(1, Ordering::SeqCst);
            Box::new(TestCompilerSpec::x86_64())
        }
    }

    struct Inject(&'static DisassemblyInjectInfo);
    impl ExtensionPoint for Inject {}
    impl DisassemblyInject for Inject {
        fn get_info(&self) -> &'static DisassemblyInjectInfo {
            self.0
        }
    }

    static ANY_X86_64: DisassemblyInjectInfo =
        DisassemblyInjectInfo::new(&[PlatformInfo::for_language("x86:LE:64:default")]);
    static X86_64_WINDOWS: DisassemblyInjectInfo = DisassemblyInjectInfo::with_priority(
        &[PlatformInfo::new("x86:LE:64:default", "windows")],
        50,
    );
    static X86_64_GCC: DisassemblyInjectInfo =
        DisassemblyInjectInfo::new(&[PlatformInfo::new("x86:LE:64:default", "gcc")]);
    static ARM_ONLY: DisassemblyInjectInfo =
        DisassemblyInjectInfo::new(&[PlatformInfo::for_language("ARM:LE:32:v8")]);

    #[test]
    fn applicable_when_language_matches_and_compiler_blank() {
        assert!(Inject(&ANY_X86_64).is_applicable(&X86GccPlatform::default()));
    }

    #[test]
    fn applicable_when_compiler_matches() {
        assert!(Inject(&X86_64_GCC).is_applicable(&X86GccPlatform::default()));
    }

    #[test]
    fn not_applicable_when_compiler_differs() {
        assert!(!Inject(&X86_64_WINDOWS).is_applicable(&X86GccPlatform::default()));
    }

    #[test]
    fn not_applicable_when_language_differs_and_cspec_not_consulted() {
        let platform = X86GccPlatform::default();
        assert!(!Inject(&ARM_ONLY).is_applicable(&platform));
        assert_eq!(platform.cspec_requests.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn interface_default_info_applies_nowhere() {
        let inject = Inject(&DisassemblyInjectInfo::DEFAULT);
        assert!(!inject.is_applicable(&X86GccPlatform::default()));
        assert_eq!(inject.get_priority(), 100);
    }

    #[test]
    fn priority_comes_from_info() {
        assert_eq!(Inject(&X86_64_WINDOWS).get_priority(), 50);
        assert_eq!(Inject(&ANY_X86_64).get_priority(), 100);
    }

    #[test]
    fn injects_sort_lowest_priority_first() {
        let mut injects: Vec<Box<dyn DisassemblyInject>> =
            vec![Box::new(Inject(&ANY_X86_64)), Box::new(Inject(&X86_64_WINDOWS))];
        injects.sort_by_key(|i| i.get_priority());
        assert_eq!(injects[0].get_priority(), 50);
    }

    struct PluginToolImpl;
    impl PluginTool for PluginToolImpl {}

    struct PostRecorder {
        post_snap: Cell<Option<i64>>,
    }
    impl ExtensionPoint for PostRecorder {}
    impl DisassemblyInject for PostRecorder {
        fn get_info(&self) -> &'static DisassemblyInjectInfo {
            &ANY_X86_64
        }
        fn post(
            &self,
            _tool: &dyn PluginTool,
            _platform: &dyn TracePlatform,
            snap: i64,
            _disassembled: &dyn AddressSetView,
        ) {
            self.post_snap.set(Some(snap));
        }
    }

    #[test]
    fn post_hook_can_be_overridden() {
        let recorder = PostRecorder {
            post_snap: Cell::new(None),
        };
        recorder.post(&PluginToolImpl, &X86GccPlatform::default(), 7, &AddressSet::new());
        assert_eq!(recorder.post_snap.get(), Some(7));
        // The default hook is a no-op.
        Inject(&ANY_X86_64).post(&PluginToolImpl, &X86GccPlatform::default(), 7, &AddressSet::new());
    }
}
