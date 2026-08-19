use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use std::sync::Arc;

/// Callback interface for address selection events in the label history table.
///
/// Implementations of this trait are notified when an address is selected
/// in the Label History table, allowing other components to react to these
/// selections.
pub trait LabelHistoryListener: Send + Sync {
    /// Notification that the given address was selected in the label history.
    fn address_selected(&self, program: Arc<dyn Program>, addr: Address);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    struct MockProgram {
        name: String,
    }

    impl MockProgram {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
            }
        }
    }

    impl crate::framework::model::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_language_id(&self) -> String {
            "test_lang".to_string()
        }
    }

    struct RecordingListener {
        calls: Mutex<Vec<(String, i64)>>,
    }

    impl RecordingListener {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }

        fn get_call(&self, index: usize) -> Option<(String, i64)> {
            self.calls.lock().unwrap().get(index).cloned()
        }
    }

    impl LabelHistoryListener for RecordingListener {
        fn address_selected(&self, program: Arc<dyn Program>, addr: Address) {
            self.calls
                .lock()
                .unwrap()
                .push((Program::get_name(program.as_ref()).to_string(), addr.offset()));
        }
    }

    #[test]
    fn test_address_selected_single_call() {
        let space = crate::program::model::address::AddressSpace::new(
            "RAM",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        );
        let program = Arc::new(MockProgram::new("test_program"));
        let addr = Address::new(space, 0x1000);

        let listener = RecordingListener::new();
        listener.address_selected(program.clone(), addr.clone());

        assert_eq!(listener.call_count(), 1);
        assert_eq!(listener.get_call(0), Some(("test_program".to_string(), 0x1000)));
    }

    #[test]
    fn test_address_selected_multiple_calls() {
        let space = crate::program::model::address::AddressSpace::new(
            "RAM",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        );
        let program = Arc::new(MockProgram::new("test_program"));

        let listener = RecordingListener::new();
        let addr1 = Address::new(space.clone(), 0x1000);
        let addr2 = Address::new(space.clone(), 0x2000);
        let addr3 = Address::new(space.clone(), 0x3000);

        listener.address_selected(program.clone(), addr1);
        listener.address_selected(program.clone(), addr2);
        listener.address_selected(program.clone(), addr3);

        assert_eq!(listener.call_count(), 3);
        assert_eq!(listener.get_call(0), Some(("test_program".to_string(), 0x1000)));
        assert_eq!(listener.get_call(1), Some(("test_program".to_string(), 0x2000)));
        assert_eq!(listener.get_call(2), Some(("test_program".to_string(), 0x3000)));
    }

    #[test]
    fn test_address_selected_different_programs() {
        let space = crate::program::model::address::AddressSpace::new(
            "RAM",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        );
        let program1 = Arc::new(MockProgram::new("program1"));
        let program2 = Arc::new(MockProgram::new("program2"));

        let listener = RecordingListener::new();
        let addr = Address::new(space.clone(), 0x5000);

        listener.address_selected(program1.clone(), addr.clone());
        listener.address_selected(program2.clone(), addr.clone());

        assert_eq!(listener.call_count(), 2);
        assert_eq!(listener.get_call(0), Some(("program1".to_string(), 0x5000)));
        assert_eq!(listener.get_call(1), Some(("program2".to_string(), 0x5000)));
    }

    #[test]
    fn test_address_selected_zero_offset() {
        let space = crate::program::model::address::AddressSpace::new(
            "RAM",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        );
        let program = Arc::new(MockProgram::new("test_program"));
        let addr = Address::new(space, 0);

        let listener = RecordingListener::new();
        listener.address_selected(program, addr);

        assert_eq!(listener.call_count(), 1);
        assert_eq!(listener.get_call(0), Some(("test_program".to_string(), 0)));
    }

    #[test]
    fn test_address_selected_large_offset() {
        let space = crate::program::model::address::AddressSpace::new(
            "RAM",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        );
        let program = Arc::new(MockProgram::new("test_program"));
        let addr = Address::new(space, 0xFFFFFF00);

        let listener = RecordingListener::new();
        listener.address_selected(program, addr);

        assert_eq!(listener.call_count(), 1);
        assert_eq!(listener.get_call(0), Some(("test_program".to_string(), 0xFFFFFF00)));
    }

    #[test]
    fn test_as_trait_object() {
        let space = crate::program::model::address::AddressSpace::new(
            "RAM",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        );
        let program = Arc::new(MockProgram::new("test_program"));
        let addr = Address::new(space, 0x1000);

        let listener: Arc<dyn LabelHistoryListener> = Arc::new(RecordingListener::new());
        listener.address_selected(program, addr);
    }
}
