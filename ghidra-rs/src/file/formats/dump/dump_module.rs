/// Represents a module loaded in a memory dump.
///
/// Mirrors `ghidra.file.formats.dump.DumpModule`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpModule {
    name: String,
    index: i32,
    base: i64,
    size: i64,
}

impl DumpModule {
    pub fn new(name: String, index: i32, base: i64, size: i64) -> Self {
        Self { name, index, base, size }
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    pub fn get_index(&self) -> i32 {
        self.index
    }

    pub fn set_index(&mut self, index: i32) {
        self.index = index;
    }

    pub fn get_base(&self) -> i64 {
        self.base
    }

    pub fn set_base(&mut self, base: i64) {
        self.base = base;
    }

    pub fn get_size(&self) -> i64 {
        self.size
    }

    pub fn set_size(&mut self, size: i64) {
        self.size = size;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_fields() {
        let m = DumpModule::new("ntdll.dll".to_string(), 3, 0x7ff0_0000, 0x10_0000);
        assert_eq!(m.get_name(), "ntdll.dll");
        assert_eq!(m.get_index(), 3);
        assert_eq!(m.get_base(), 0x7ff0_0000);
        assert_eq!(m.get_size(), 0x10_0000);
    }

    #[test]
    fn setters_update_fields() {
        let mut m = DumpModule::new("a.dll".to_string(), 0, 0, 0);
        m.set_name("b.dll".to_string());
        m.set_index(7);
        m.set_base(0x1000);
        m.set_size(0x2000);
        assert_eq!(m.get_name(), "b.dll");
        assert_eq!(m.get_index(), 7);
        assert_eq!(m.get_base(), 0x1000);
        assert_eq!(m.get_size(), 0x2000);
    }

    #[test]
    fn zero_base_and_size() {
        let m = DumpModule::new(String::new(), 0, 0, 0);
        assert_eq!(m.get_base(), 0);
        assert_eq!(m.get_size(), 0);
    }

    #[test]
    fn negative_base_allowed() {
        let m = DumpModule::new("x".to_string(), 0, -1_i64, 4096);
        assert_eq!(m.get_base(), -1);
    }
}
