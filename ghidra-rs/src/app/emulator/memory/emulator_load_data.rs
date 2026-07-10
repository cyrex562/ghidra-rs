use crate::app::emulator::memory::MemoryLoadImage;
use crate::app::emulator::state::RegisterState;
use crate::program::model::address::AddressSetView;

/// Interface providing initial emulator state and memory load information.
///
/// Provides access to the memory load image and initial register state for emulation.
/// The optional address set view defines which addresses should be included in the emulation.
///
/// Corresponds to `ghidra.app.emulator.memory.EmulatorLoadData`.
#[deprecated(since = "12.1", note = "for removal")]
pub trait EmulatorLoadData {
    /// Returns the memory load image for emulation.
    fn get_memory_load_image(&self) -> Box<dyn MemoryLoadImage>;

    /// Returns the initial register state for emulation.
    fn get_initial_register_state(&self) -> Box<dyn RegisterState>;

    /// Returns an optional address set view defining emulation scope.
    ///
    /// Returns `None` if all addresses should be included (default behavior).
    fn get_view(&self) -> Option<Box<dyn AddressSetView>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::load_image::LoadImage;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use std::collections::{HashMap, HashSet};

    struct TestMemoryLoadImage {
        data: Vec<u8>,
    }

    impl TestMemoryLoadImage {
        fn new(data: Vec<u8>) -> Self {
            Self { data }
        }
    }

    impl LoadImage for TestMemoryLoadImage {
        fn load_fill(
            &self,
            buf: &mut [u8],
            size: i32,
            _addr: &Address,
            buf_offset: i32,
            _generate_initialized_mask: bool,
        ) -> Option<Vec<u8>> {
            let offset = buf_offset as usize;
            let len = (size as usize).min(buf.len() - offset).min(self.data.len());
            if len > 0 {
                buf[offset..offset + len].copy_from_slice(&self.data[..len]);
            }
            None
        }
    }

    impl MemoryLoadImage for TestMemoryLoadImage {
        fn write_back(&mut self, _bytes: &[u8], _size: i32, _addr: &Address, _offset: i32) {}

        fn dispose(&mut self) {
            self.data.clear();
        }
    }

    struct TestRegisterState {
        vals: HashMap<String, Vec<u8>>,
        initialized: HashMap<String, bool>,
    }

    impl TestRegisterState {
        fn new() -> Self {
            Self {
                vals: HashMap::new(),
                initialized: HashMap::new(),
            }
        }
    }

    impl RegisterState for TestRegisterState {
        fn keys(&self) -> HashSet<String> {
            self.vals.keys().cloned().collect()
        }

        fn vals(&self, key: &str) -> Option<Vec<u8>> {
            self.vals.get(key).cloned()
        }

        fn is_initialized(&self, key: &str) -> Option<bool> {
            self.initialized.get(key).copied()
        }

        fn set_vals(&mut self, key: &str, vals: &[u8], set_initialized: bool) {
            self.vals.insert(key.to_string(), vals.to_vec());
            if set_initialized {
                self.initialized.insert(key.to_string(), true);
            }
        }

        fn set_vals_long(&mut self, key: &str, val: i64, size: usize, set_initialized: bool) {
            let bytes = val.to_be_bytes();
            let start = bytes.len().saturating_sub(size);
            self.set_vals(key, &bytes[start..], set_initialized);
        }

        fn dispose(&mut self) {
            self.vals.clear();
            self.initialized.clear();
        }
    }

    struct TestEmulatorLoadData;

    impl EmulatorLoadData for TestEmulatorLoadData {
        fn get_memory_load_image(&self) -> Box<dyn MemoryLoadImage> {
            Box::new(TestMemoryLoadImage::new(vec![0x11, 0x22, 0x33, 0x44]))
        }

        fn get_initial_register_state(&self) -> Box<dyn RegisterState> {
            let mut state = TestRegisterState::new();
            state.set_vals("eax", &[0x01, 0x02, 0x03, 0x04], true);
            Box::new(state)
        }

        fn get_view(&self) -> Option<Box<dyn AddressSetView>> {
            None
        }
    }

    #[test]
    fn test_emulator_load_data_get_memory_load_image() {
        let load_data = TestEmulatorLoadData;
        let _image = load_data.get_memory_load_image();
    }

    #[test]
    fn test_emulator_load_data_get_initial_register_state() {
        let load_data = TestEmulatorLoadData;
        let state = load_data.get_initial_register_state();
        assert_eq!(state.vals("eax"), Some(vec![0x01, 0x02, 0x03, 0x04]));
    }

    #[test]
    fn test_emulator_load_data_get_view_default_none() {
        let load_data = TestEmulatorLoadData;
        assert!(load_data.get_view().is_none());
    }

    #[test]
    fn test_emulator_load_data_register_state_initialized() {
        let load_data = TestEmulatorLoadData;
        let state = load_data.get_initial_register_state();
        assert_eq!(state.is_initialized("eax"), Some(true));
    }
}
