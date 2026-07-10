use crate::app::plugin::core::format::ByteEditInfo;
use crate::framework::plugintool::{PluginEvent, PluginEventBehavior};
use crate::framework::plugintool::ToolEventName;
use crate::program::model::listing::Program;
use std::sync::Weak;

const NAME: &str = "ByteBlockChange";

/// Plugin event for notification of byte block changes that the Byte Viewer produces.
///
/// Mirrors `ghidra.app.plugin.core.byteviewer.ByteBlockChangePluginEvent`.
pub struct ByteBlockChangePluginEvent {
    event: PluginEvent,
    program_ref: Weak<dyn Program>,
    edit: ByteEditInfo,
}

struct ByteBlockChangeEventBehavior {
    edit: ByteEditInfo,
    tool_event_name: ToolEventName,
}

impl PluginEventBehavior for ByteBlockChangeEventBehavior {
    fn details(&self) -> Option<String> {
        let details = format!(
            "Address of Block Change==> {}, offset ==> {}",
            self.edit.block_address(),
            self.edit.offset()
        );
        Some(details)
    }

    fn tool_event_name(&self) -> Option<&ToolEventName> {
        Some(&self.tool_event_name)
    }
}

impl ByteBlockChangePluginEvent {
    /// Creates a new byte block change event.
    ///
    /// # Arguments
    ///
    /// * `source` - Name of the plugin that generated this event
    /// * `edit` - Byte block edit information
    /// * `program` - The domain object (wrapped in Arc) for which the change affects
    pub fn new(
        source: impl Into<String>,
        edit: ByteEditInfo,
        program: std::sync::Arc<dyn Program>,
    ) -> Self {
        let program_ref = std::sync::Arc::downgrade(&program);
        let behavior = ByteBlockChangeEventBehavior {
            edit: edit.clone(),
            tool_event_name: ToolEventName::new(NAME),
        };

        let event = PluginEvent::with_behavior(
            source,
            NAME,
            Box::new(behavior),
        );

        Self {
            event,
            program_ref,
            edit,
        }
    }

    /// Returns the domain object that the change refers to, or `None` if it has been dropped.
    ///
    /// Mirrors `getProgram()`.
    pub fn get_program(&self) -> Option<std::sync::Arc<dyn Program>> {
        self.program_ref.upgrade()
    }

    /// Returns the byte edit information for the change.
    ///
    /// Mirrors `getByteEditInfo()`.
    pub fn get_byte_edit_info(&self) -> &ByteEditInfo {
        &self.edit
    }

    /// Returns a reference to the underlying `PluginEvent`.
    pub fn event(&self) -> &PluginEvent {
        &self.event
    }

    /// Returns a mutable reference to the underlying `PluginEvent`.
    pub fn event_mut(&mut self) -> &mut PluginEvent {
        &mut self.event
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    struct MockProgram;

    impl crate::framework::model::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "MockProgram".to_string()
        }

        fn get_language_id(&self) -> String {
            "x86".to_string()
        }
    }

    fn create_test_edit() -> ByteEditInfo {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x1000);
        ByteEditInfo::new(addr, 100, vec![0xAA, 0xBB], vec![0xCC, 0xDD])
    }

    #[test]
    fn new_stores_source() {
        let program = std::sync::Arc::new(MockProgram);
        let edit = create_test_edit();
        let event = ByteBlockChangePluginEvent::new("TestPlugin", edit, program);

        assert_eq!(event.event().source_name(), "TestPlugin");
    }

    #[test]
    fn new_stores_program() {
        let program = std::sync::Arc::new(MockProgram);
        let edit = create_test_edit();
        let event = ByteBlockChangePluginEvent::new("TestPlugin", edit, program.clone());

        assert!(event.get_program().is_some());
    }

    #[test]
    fn event_name_is_correct() {
        let program = std::sync::Arc::new(MockProgram);
        let edit = create_test_edit();
        let event = ByteBlockChangePluginEvent::new("TestPlugin", edit, program);

        assert_eq!(event.event().event_name(), "ByteBlockChange");
    }

    #[test]
    fn name_constant_is_correct() {
        assert_eq!(NAME, "ByteBlockChange");
    }

    #[test]
    fn get_byte_edit_info_returns_edit() {
        let program = std::sync::Arc::new(MockProgram);
        let edit = create_test_edit();
        let event = ByteBlockChangePluginEvent::new("TestPlugin", edit.clone(), program);

        assert_eq!(event.get_byte_edit_info(), &edit);
    }

    #[test]
    fn get_program_returns_program_while_arc_alive() {
        let program = std::sync::Arc::new(MockProgram);
        let edit = create_test_edit();
        let event = ByteBlockChangePluginEvent::new("TestPlugin", edit, program.clone());

        assert!(event.get_program().is_some());
    }

    #[test]
    fn get_program_returns_none_after_arc_dropped() {
        let program = std::sync::Arc::new(MockProgram);
        let edit = create_test_edit();
        let event = ByteBlockChangePluginEvent::new("TestPlugin", edit, program.clone());

        drop(program);

        assert!(event.get_program().is_none());
    }

    #[test]
    fn event_mut_allows_modification() {
        let program = std::sync::Arc::new(MockProgram);
        let edit = create_test_edit();
        let mut event = ByteBlockChangePluginEvent::new("TestPlugin", edit, program);

        event.event_mut().set_source_name("NewSource");
        assert_eq!(event.event().source_name(), "NewSource");
    }

    #[test]
    fn is_tool_event_returns_true() {
        let program = std::sync::Arc::new(MockProgram);
        let edit = create_test_edit();
        let event = ByteBlockChangePluginEvent::new("TestPlugin", edit, program);

        assert!(event.event().is_tool_event());
    }

    #[test]
    fn tool_event_name_is_set() {
        let program = std::sync::Arc::new(MockProgram);
        let edit = create_test_edit();
        let event = ByteBlockChangePluginEvent::new("TestPlugin", edit, program);

        let tool_event_name = event.event().tool_event_name();
        assert!(tool_event_name.is_some());
        assert_eq!(tool_event_name.unwrap().event_name(), "ByteBlockChange");
    }

    #[test]
    fn details_includes_address_and_offset() {
        let program = std::sync::Arc::new(MockProgram);
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x2000);
        let edit = ByteEditInfo::new(addr.clone(), 256, vec![0x11], vec![0x22]);
        let event = ByteBlockChangePluginEvent::new("TestPlugin", edit, program);

        let details_str = event.event().to_string();
        assert!(details_str.contains("Address of Block Change"));
        assert!(details_str.contains("offset"));
    }
}
