use std::collections::HashMap;
use std::fmt;

use super::macho_prelink_constants as constants;

/// Value types that can be stored in a [`MachoPrelinkMap`] entry.
#[derive(Debug, Clone)]
pub enum MachoPrelinkValue {
    String(String),
    /// 64-bit integer (Java `Long`).
    Long(i64),
    /// 32-bit integer (Java `Integer`); kept for plist-parser compatibility.
    Int(i32),
    Bool(bool),
    Map(MachoPrelinkMap),
}

/// A property-list map parsed from a Mach-O prelink segment.
///
/// Mirrors `MachoPrelinkMap` from the Java source: a heterogeneous key/value store
/// with typed accessors for well-known prelink plist keys.
#[derive(Debug, Clone, Default)]
pub struct MachoPrelinkMap {
    map: HashMap<String, MachoPrelinkValue>,
}

impl MachoPrelinkMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put_string(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.map
            .insert(key.into(), MachoPrelinkValue::String(value.into()));
    }

    pub fn put_long(&mut self, key: impl Into<String>, value: i64) {
        self.map.insert(key.into(), MachoPrelinkValue::Long(value));
    }

    /// Store a 32-bit integer value. The typed getters apply the same integer-widening
    /// arithmetic as the Java source: `(int_val as i64) + 0xFFFF_FFFF`.
    pub fn put_int(&mut self, key: impl Into<String>, value: i32) {
        self.map.insert(key.into(), MachoPrelinkValue::Int(value));
    }

    pub fn put_bool(&mut self, key: impl Into<String>, value: bool) {
        self.map.insert(key.into(), MachoPrelinkValue::Bool(value));
    }

    pub fn put_map(&mut self, key: impl Into<String>, value: MachoPrelinkMap) {
        self.map.insert(key.into(), MachoPrelinkValue::Map(value));
    }

    /// Returns the bundle path string, or `None` if absent or not a string.
    pub fn get_prelink_bundle_path(&self) -> Option<&str> {
        match self.map.get(constants::K_PRELINK_BUNDLE_PATH_KEY) {
            Some(MachoPrelinkValue::String(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Returns the interface UUID string, or `None` if absent or not a string.
    pub fn get_prelink_uuid(&self) -> Option<&str> {
        match self.map.get(constants::K_PRELINK_INTERFACE_UUID_KEY) {
            Some(MachoPrelinkValue::String(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Returns the kmod-info address, or `-1` if absent or wrong type.
    pub fn get_prelink_kmod_info(&self) -> i64 {
        self.get_long_value(constants::K_PRELINK_KMOD_INFO_KEY)
    }

    /// Returns the executable address, or `-1` if absent or wrong type.
    pub fn get_prelink_executable(&self) -> i64 {
        self.get_long_value(constants::K_PRELINK_EXECUTABLE_KEY)
    }

    /// Returns the executable size, or `-1` if absent or wrong type.
    pub fn get_prelink_executable_size(&self) -> i64 {
        self.get_long_value(constants::K_PRELINK_EXECUTABLE_SIZE_KEY)
    }

    /// Returns the executable load address, or `-1` if absent or wrong type.
    pub fn get_prelink_executable_load_addr(&self) -> i64 {
        self.get_long_value(constants::K_PRELINK_EXECUTABLE_LOAD_KEY)
    }

    /// Returns the module index, or `-1` if absent or wrong type.
    pub fn get_prelink_module_index(&self) -> i64 {
        self.get_long_value(constants::K_PRELINK_MODULE_INDEX_KEY)
    }

    /// Shared long-value extractor. For `Int` entries, applies the same widening
    /// arithmetic as the Java source: `(int_val as i64) + 0xFFFF_FFFF`.
    fn get_long_value(&self, key: &str) -> i64 {
        match self.map.get(key) {
            Some(MachoPrelinkValue::Long(v)) => *v,
            Some(MachoPrelinkValue::Int(v)) => (*v as i64) + 0xFFFF_FFFFi64,
            _ => -1,
        }
    }
}

impl fmt::Display for MachoPrelinkMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut keys: Vec<&String> = self.map.keys().collect();
        keys.sort();
        for key in keys {
            match &self.map[key] {
                MachoPrelinkValue::Long(v) => writeln!(f, "{}=0x{:x}", key, v)?,
                MachoPrelinkValue::Int(v) => writeln!(f, "{}={}", key, v)?,
                MachoPrelinkValue::String(s) => writeln!(f, "{}={}", key, s)?,
                MachoPrelinkValue::Bool(b) => writeln!(f, "{}={}", key, b)?,
                MachoPrelinkValue::Map(m) => writeln!(f, "{}={}", key, m)?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_map_is_empty() {
        let m = MachoPrelinkMap::new();
        assert!(m.get_prelink_bundle_path().is_none());
        assert!(m.get_prelink_uuid().is_none());
        assert_eq!(m.get_prelink_kmod_info(), -1);
        assert_eq!(m.get_prelink_executable(), -1);
        assert_eq!(m.get_prelink_executable_size(), -1);
        assert_eq!(m.get_prelink_executable_load_addr(), -1);
        assert_eq!(m.get_prelink_module_index(), -1);
    }

    #[test]
    fn put_and_get_string_values() {
        let mut m = MachoPrelinkMap::new();
        m.put_string(constants::K_PRELINK_BUNDLE_PATH_KEY, "/path/to/kext");
        m.put_string(constants::K_PRELINK_INTERFACE_UUID_KEY, "DEADBEEF-1234");
        assert_eq!(m.get_prelink_bundle_path(), Some("/path/to/kext"));
        assert_eq!(m.get_prelink_uuid(), Some("DEADBEEF-1234"));
    }

    #[test]
    fn wrong_type_for_string_returns_none() {
        let mut m = MachoPrelinkMap::new();
        m.put_long(constants::K_PRELINK_BUNDLE_PATH_KEY, 42);
        assert!(m.get_prelink_bundle_path().is_none());
    }

    #[test]
    fn put_and_get_long_values() {
        let mut m = MachoPrelinkMap::new();
        m.put_long(constants::K_PRELINK_KMOD_INFO_KEY, 0x1234_5678_9ABC_DEF0);
        m.put_long(constants::K_PRELINK_EXECUTABLE_KEY, 0x1000);
        m.put_long(constants::K_PRELINK_EXECUTABLE_SIZE_KEY, 0x2000);
        m.put_long(constants::K_PRELINK_EXECUTABLE_LOAD_KEY, 0x3000);
        m.put_long(constants::K_PRELINK_MODULE_INDEX_KEY, 7);

        assert_eq!(m.get_prelink_kmod_info(), 0x1234_5678_9ABC_DEF0u64 as i64);
        assert_eq!(m.get_prelink_executable(), 0x1000);
        assert_eq!(m.get_prelink_executable_size(), 0x2000);
        assert_eq!(m.get_prelink_executable_load_addr(), 0x3000);
        assert_eq!(m.get_prelink_module_index(), 7);
    }

    #[test]
    fn wrong_type_for_long_returns_minus_one() {
        let mut m = MachoPrelinkMap::new();
        m.put_string(constants::K_PRELINK_KMOD_INFO_KEY, "not-a-number");
        assert_eq!(m.get_prelink_kmod_info(), -1);
    }

    #[test]
    fn int_value_widening_arithmetic() {
        // Java source: `return (Integer)value + 0xffffffffL`
        // For int value 0:  0 + 4294967295 = 4294967295
        // For int value -1: -1 + 4294967295 = 4294967294
        // For int value 1:   1 + 4294967295 = 4294967296
        let mut m = MachoPrelinkMap::new();

        m.put_int(constants::K_PRELINK_EXECUTABLE_KEY, 0);
        assert_eq!(m.get_prelink_executable(), 0xFFFF_FFFFi64);

        m.put_int(constants::K_PRELINK_EXECUTABLE_KEY, -1);
        assert_eq!(m.get_prelink_executable(), 0xFFFF_FFFEi64);

        m.put_int(constants::K_PRELINK_EXECUTABLE_KEY, 1);
        assert_eq!(m.get_prelink_executable(), 0x1_0000_0000i64);
    }

    #[test]
    fn put_bool_does_not_affect_long_getters() {
        let mut m = MachoPrelinkMap::new();
        m.put_bool(constants::K_PRELINK_KMOD_INFO_KEY, true);
        assert_eq!(m.get_prelink_kmod_info(), -1);
    }

    #[test]
    fn display_sorts_keys_and_formats_long_as_hex() {
        let mut m = MachoPrelinkMap::new();
        m.put_long(constants::K_PRELINK_EXECUTABLE_KEY, 0xDEAD);
        m.put_string(constants::K_PRELINK_BUNDLE_PATH_KEY, "/kext");
        m.put_bool("_ZFlag", true);

        let s = m.to_string();
        let lines: Vec<&str> = s.lines().collect();
        // Keys are sorted: _PrelinkBundlePath, _PrelinkExecutable, _ZFlag
        assert_eq!(lines[0], "_PrelinkBundlePath=/kext");
        assert_eq!(lines[1], "_PrelinkExecutable=0xdead");
        assert_eq!(lines[2], "_ZFlag=true");
    }

    #[test]
    fn display_nested_map() {
        let mut inner = MachoPrelinkMap::new();
        inner.put_string(constants::K_PRELINK_BUNDLE_PATH_KEY, "/inner");

        let mut outer = MachoPrelinkMap::new();
        outer.put_map("nested", inner);

        let s = outer.to_string();
        assert!(s.contains("nested="));
        assert!(s.contains("_PrelinkBundlePath=/inner"));
    }

    #[test]
    fn put_map_value() {
        let mut inner = MachoPrelinkMap::new();
        inner.put_long(constants::K_PRELINK_MODULE_INDEX_KEY, 3);

        let mut outer = MachoPrelinkMap::new();
        outer.put_map("child", inner);

        // The outer map does not expose inner via long getters
        assert_eq!(outer.get_prelink_module_index(), -1);
    }

    #[test]
    fn overwrite_key() {
        let mut m = MachoPrelinkMap::new();
        m.put_string(constants::K_PRELINK_BUNDLE_PATH_KEY, "first");
        m.put_string(constants::K_PRELINK_BUNDLE_PATH_KEY, "second");
        assert_eq!(m.get_prelink_bundle_path(), Some("second"));
    }
}
