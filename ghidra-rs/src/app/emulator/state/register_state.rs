use std::collections::HashSet;

/// Interface for accessing and modifying register state during emulation.
///
/// Java `List<T>` return values used as optionals are mapped to `Option<T>`.
///
/// Deprecated since Ghidra 12.1; scheduled for removal.
pub trait RegisterState {
    /// Returns the set of register names that have stored state.
    fn keys(&self) -> HashSet<String>;

    /// Returns the byte array value for the given register, or `None` if unspecified.
    fn vals(&self, key: &str) -> Option<Vec<u8>>;

    /// Returns the initialization state for the given register, or `None` if unspecified.
    ///
    /// `Some(true)` means initialized; `Some(false)` means explicitly uninitialized.
    fn is_initialized(&self, key: &str) -> Option<bool>;

    /// Sets the byte array value for a register.
    ///
    /// # Arguments
    /// * `key` - Register name
    /// * `vals` - Byte array value
    /// * `set_initialized` - Whether to mark the register as initialized
    fn set_vals(&mut self, key: &str, vals: &[u8], set_initialized: bool);

    /// Sets the register value from an integer, using `size` bytes of `val`.
    ///
    /// # Arguments
    /// * `key` - Register name
    /// * `val` - Integer value (big-endian, low `size` bytes used)
    /// * `size` - Number of bytes
    /// * `set_initialized` - Whether to mark the register as initialized
    fn set_vals_long(&mut self, key: &str, val: i64, size: usize, set_initialized: bool);

    /// Releases any resources held by this register state.
    fn dispose(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct SimpleRegisterState {
        vals: HashMap<String, Vec<u8>>,
        initialized: HashMap<String, bool>,
    }

    impl SimpleRegisterState {
        fn new() -> Self {
            Self {
                vals: HashMap::new(),
                initialized: HashMap::new(),
            }
        }
    }

    impl RegisterState for SimpleRegisterState {
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

    #[test]
    fn test_keys_empty_initially() {
        let state = SimpleRegisterState::new();
        assert!(state.keys().is_empty());
    }

    #[test]
    fn test_set_and_get_vals() {
        let mut state = SimpleRegisterState::new();
        state.set_vals("eax", &[0x01, 0x02, 0x03, 0x04], true);
        assert_eq!(state.vals("eax"), Some(vec![0x01, 0x02, 0x03, 0x04]));
    }

    #[test]
    fn test_vals_unspecified_returns_none() {
        let state = SimpleRegisterState::new();
        assert_eq!(state.vals("rbx"), None);
    }

    #[test]
    fn test_keys_contains_set_register() {
        let mut state = SimpleRegisterState::new();
        state.set_vals("ecx", &[0x00], false);
        assert!(state.keys().contains("ecx"));
    }

    #[test]
    fn test_is_initialized_set_true() {
        let mut state = SimpleRegisterState::new();
        state.set_vals("edx", &[0x00], true);
        assert_eq!(state.is_initialized("edx"), Some(true));
    }

    #[test]
    fn test_is_initialized_not_set_when_flag_false() {
        let mut state = SimpleRegisterState::new();
        state.set_vals("esi", &[0xFF], false);
        assert_eq!(state.is_initialized("esi"), None);
    }

    #[test]
    fn test_is_initialized_unspecified_returns_none() {
        let state = SimpleRegisterState::new();
        assert_eq!(state.is_initialized("edi"), None);
    }

    #[test]
    fn test_set_vals_long_single_byte() {
        let mut state = SimpleRegisterState::new();
        state.set_vals_long("al", 0xAB, 1, true);
        assert_eq!(state.vals("al"), Some(vec![0xAB]));
    }

    #[test]
    fn test_set_vals_long_four_bytes() {
        let mut state = SimpleRegisterState::new();
        state.set_vals_long("eax", 0x0102_0304, 4, true);
        assert_eq!(state.vals("eax"), Some(vec![0x01, 0x02, 0x03, 0x04]));
    }

    #[test]
    fn test_dispose_clears_state() {
        let mut state = SimpleRegisterState::new();
        state.set_vals("rax", &[0x00, 0x01], true);
        state.dispose();
        assert!(state.keys().is_empty());
        assert_eq!(state.vals("rax"), None);
        assert_eq!(state.is_initialized("rax"), None);
    }
}
