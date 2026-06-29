/// Parsed entry from an apport `/proc/maps`-style memory map line.
///
/// Mirrors `ghidra.file.formats.dump.apport.MemoryInfo`.
pub struct MemoryInfo {
    base_address: u64,
    region_size: u64,
    permissions: String,
    rva: u64,
    description: Option<String>,
}

pub const NAME: &str = "MINIDUMP_MEMORY_INFO";

impl MemoryInfo {
    /// Parse a single `/proc/maps` line.
    ///
    /// Returns `Err` if the line is malformed.
    pub fn new(text: &str) -> Result<Self, String> {
        let split: Vec<&str> = text.trim().split_whitespace().collect();
        if split.len() < 3 {
            return Err(format!("too few fields: {}", split.len()));
        }
        let range_parts: Vec<&str> = split[0].split('-').collect();
        if range_parts.len() != 2 {
            return Err(format!("invalid range: {}", split[0]));
        }
        let start = u64::from_str_radix(range_parts[0], 16)
            .map_err(|e| format!("invalid start: {e}"))?;
        let stop = u64::from_str_radix(range_parts[1], 16)
            .map_err(|e| format!("invalid stop: {e}"))?;
        let rva = u64::from_str_radix(split[2], 16)
            .map_err(|e| format!("invalid rva: {e}"))?;
        Ok(Self {
            base_address: start,
            region_size: stop.wrapping_sub(start),
            permissions: split[1].to_string(),
            rva,
            description: if split.len() > 5 { Some(split[5].to_string()) } else { None },
        })
    }

    pub fn get_base_address(&self) -> u64 {
        self.base_address
    }

    pub fn set_base_address(&mut self, base_address: u64) {
        self.base_address = base_address;
    }

    pub fn get_region_size(&self) -> u64 {
        self.region_size
    }

    pub fn set_region_size(&mut self, region_size: u64) {
        self.region_size = region_size;
    }

    pub fn get_permissions(&self) -> &str {
        &self.permissions
    }

    pub fn set_permissions(&mut self, permissions: String) {
        self.permissions = permissions;
    }

    pub fn get_rva(&self) -> u64 {
        self.rva
    }

    pub fn set_rva(&mut self, rva: u64) {
        self.rva = rva;
    }

    pub fn get_description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    pub fn set_description(&mut self, description: String) {
        self.description = Some(description);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE_WITH_DESC: &str =
        "7f1234000000-7f1234001000 r-xp 00000000 08:01 12345 /lib/libfoo.so";
    const LINE_NO_DESC: &str =
        "7f1234000000-7f1234001000 ---p 00000000 00:00 0";

    #[test]
    fn parse_with_description() {
        let m = MemoryInfo::new(LINE_WITH_DESC).unwrap();
        assert_eq!(m.get_base_address(), 0x7f1234000000u64);
        assert_eq!(m.get_region_size(), 0x1000u64);
        assert_eq!(m.get_permissions(), "r-xp");
        assert_eq!(m.get_rva(), 0u64);
        assert_eq!(m.get_description(), Some("/lib/libfoo.so"));
    }

    #[test]
    fn parse_without_description() {
        let m = MemoryInfo::new(LINE_NO_DESC).unwrap();
        assert_eq!(m.get_base_address(), 0x7f1234000000u64);
        assert_eq!(m.get_region_size(), 0x1000u64);
        assert_eq!(m.get_permissions(), "---p");
        assert_eq!(m.get_rva(), 0u64);
        assert_eq!(m.get_description(), None);
    }

    #[test]
    fn setters_override_parsed_values() {
        let mut m = MemoryInfo::new(LINE_NO_DESC).unwrap();
        m.set_base_address(0xdeadbeef);
        m.set_region_size(0x4000);
        m.set_permissions("rwxp".to_string());
        m.set_rva(0x100);
        m.set_description("[stack]".to_string());
        assert_eq!(m.get_base_address(), 0xdeadbeef);
        assert_eq!(m.get_region_size(), 0x4000);
        assert_eq!(m.get_permissions(), "rwxp");
        assert_eq!(m.get_rva(), 0x100);
        assert_eq!(m.get_description(), Some("[stack]"));
    }

    #[test]
    fn error_on_too_few_fields() {
        assert!(MemoryInfo::new("").is_err());
        assert!(MemoryInfo::new("7f0000-7f1000 r-xp").is_err());
    }

    #[test]
    fn error_on_bad_range() {
        assert!(MemoryInfo::new("7f0000 r-xp 00000000 08:01 0").is_err());
    }

    #[test]
    fn name_constant() {
        assert_eq!(NAME, "MINIDUMP_MEMORY_INFO");
    }

    #[test]
    fn parse_leading_trailing_whitespace() {
        let line = "  7f1234000000-7f1234001000 r-xp 00000000 08:01 0 /lib/x.so  ";
        let m = MemoryInfo::new(line).unwrap();
        assert_eq!(m.get_base_address(), 0x7f1234000000u64);
        assert_eq!(m.get_description(), Some("/lib/x.so"));
    }
}
