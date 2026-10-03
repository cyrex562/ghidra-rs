//! A factory for configuring and creating a Debugger-integrated emulator.
//!
//! Port of `ghidra.debug.api.emulation.EmulatorFactory`.

use crate::app::seam_stubs::Writer;
use crate::debug::api::emulation::pcode_debugger_access::PcodeDebuggerAccess;
use crate::pcode::emu::pcode_machine::ErasedPcodeMachine;
use crate::util::classfinder::extension_point::ExtensionPoint;

/// A factory for configuring and creating a Debugger-integrated emulator.
pub trait EmulatorFactory: ExtensionPoint {
    /// Get the title, to appear in menus and dialogs.
    fn get_title(&self) -> String;

    /// Create the emulator.
    ///
    /// # Arguments
    /// * `access` - the trace-and-debugger access shim
    /// * `writer` - the Debugger's emulation callbacks for UI integration
    ///
    /// # Returns
    /// The emulator with callbacks installed.
    fn create(
        &self,
        access: &dyn PcodeDebuggerAccess,
        writer: &dyn Writer,
    ) -> Box<dyn ErasedPcodeMachine>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestFactory;

    impl ExtensionPoint for TestFactory {}

    impl EmulatorFactory for TestFactory {
        fn get_title(&self) -> String {
            "Test Factory".to_string()
        }

        fn create(
            &self,
            _access: &dyn PcodeDebuggerAccess,
            _writer: &dyn Writer,
        ) -> Box<dyn ErasedPcodeMachine> {
            panic!("not implemented for testing");
        }
    }

    #[test]
    fn test_emulator_factory_get_title() {
        let factory = TestFactory;
        assert_eq!(factory.get_title(), "Test Factory");
    }
}
