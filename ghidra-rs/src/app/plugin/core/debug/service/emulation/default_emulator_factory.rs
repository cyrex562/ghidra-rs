//! Port of `ghidra.app.plugin.core.debug.service.emulation.DefaultEmulatorFactory`.

use crate::app::seam_stubs::Writer;
use crate::debug::api::emulation::emulator_factory::EmulatorFactory;
use crate::debug::api::emulation::pcode_debugger_access::PcodeDebuggerAccess;
use crate::pcode::emu::pcode_machine::ErasedPcodeMachine;
use crate::util::classfinder::extension_point::ExtensionPoint;

/// The title shown in menus and dialogs for this factory.
///
/// Mirrors the public constant `DefaultEmulatorFactory.TITLE`.
pub const TITLE: &str = "Default Concrete P-code Emulator";

/// The Debugger's default emulator factory.
///
/// Port of `ghidra.app.plugin.core.debug.service.emulation.DefaultEmulatorFactory`, a concrete
/// class implementing [`EmulatorFactory`]. Java's own `// TODO: Config options: 1) userop
/// library` comment is preserved as-is; no config options are modeled here either.
///
/// # `create`: blocked on an unported `Language` <-> `SleighLanguage` bridge
///
/// Java's `create` is `new PcodeEmulator(access.getLanguage(), writer.callbacks())`. In this
/// crate, [`PcodeDebuggerAccess::get_language`] (inherited from `PcodeTraceAccess`) returns
/// `Box<dyn Language>`, but
/// [`PcodeEmulator::new`](crate::pcode::emu::pcode_emulator::PcodeEmulator::new) requires an
/// `Arc<SleighLanguage>` -- and `SleighLanguage` deliberately does *not* implement `Language` in
/// this crate (see
/// [`AbstractPcodeMachine`](crate::pcode::emu::abstract_pcode_machine)'s own module docs: "
/// `assertSleigh(Language)` has no Rust analogue... enforced ... at compile time" in place of
/// Java's runtime downcast/assertion). There is therefore no way to bridge
/// `access.get_language()`'s result into the `Arc<SleighLanguage>` `PcodeEmulator::new` requires
/// without inventing a general `Language` downcast mechanism spanning far more of this crate than
/// this one class's port -- out of scope here. [`create`](Self::create)
/// therefore documents and panics at exactly that bridging step, rather than silently returning a
/// bogus machine.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultEmulatorFactory;

impl ExtensionPoint for DefaultEmulatorFactory {}

impl EmulatorFactory for DefaultEmulatorFactory {
    /// Mirrors `DefaultEmulatorFactory.getTitle()`.
    fn get_title(&self) -> String {
        TITLE.to_string()
    }

    /// Mirrors `DefaultEmulatorFactory.create(PcodeDebuggerAccess, TraceEmulationIntegration.Writer)`.
    /// See the struct's own docs for why this panics rather than constructing a real
    /// [`PcodeEmulator`](crate::pcode::emu::pcode_emulator::PcodeEmulator).
    fn create(
        &self,
        access: &dyn PcodeDebuggerAccess,
        _writer: &dyn Writer,
    ) -> Box<dyn ErasedPcodeMachine> {
        // Java: `access.getLanguage()`. Fetched here (even though it is never used) to mirror
        // the real call chain as closely as this crate's ported types allow.
        let _language = access.get_language();
        panic!(
            "DefaultEmulatorFactory::create: cannot bridge PcodeDebuggerAccess::get_language()'s \
             `Box<dyn Language>` into the `Arc<SleighLanguage>` that PcodeEmulator::new requires; \
             SleighLanguage deliberately does not implement Language in this crate yet (see \
             AbstractPcodeMachine's module docs)."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_title_matches_the_java_constant() {
        let factory = DefaultEmulatorFactory;
        assert_eq!(factory.get_title(), "Default Concrete P-code Emulator");
        assert_eq!(EmulatorFactory::get_title(&factory), TITLE);
    }

    #[test]
    fn trait_object_is_usable_for_get_title() {
        let factory: Box<dyn EmulatorFactory> = Box::new(DefaultEmulatorFactory);
        assert_eq!(factory.get_title(), TITLE);
    }

    // `create` cannot be exercised end-to-end without a full `PcodeDebuggerAccess`/`Writer`
    // implementation, which in turn requires the same unported `Language`<->`SleighLanguage`
    // bridge documented on `DefaultEmulatorFactory` itself; see that struct's own docs. Its
    // documented, deliberate panic is exactly the kind of "faithful port forced into a stub by an
    // upstream unported dependency" already established elsewhere in this crate, not a
    // placeholder this port silently skips.
}
