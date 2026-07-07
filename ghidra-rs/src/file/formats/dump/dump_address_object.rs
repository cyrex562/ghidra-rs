use crate::program::model::address::Address;

/// Describes a single address range within a memory dump.
///
/// Mirrors `ghidra.file.formats.dump.DumpAddressObject`.
#[derive(Debug, Clone)]
pub struct DumpAddressObject {
    provider_id: String,
    rva: i64,
    base: i64,
    length: i64,
    is_read: bool,
    is_write: bool,
    is_exec: bool,
    comment: Option<String>,
    address: Option<Address>,
    range_name: Option<String>,
}

impl DumpAddressObject {
    pub fn new(provider_id: String, rva: i64, base: i64, length: i64) -> Self {
        Self {
            provider_id,
            rva,
            base,
            length,
            is_read: true,
            is_write: true,
            is_exec: true,
            comment: None,
            address: None,
            range_name: None,
        }
    }

    pub fn get_provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn set_provider_id(&mut self, provider_id: String) {
        self.provider_id = provider_id;
    }

    pub fn get_rva(&self) -> i64 {
        self.rva
    }

    pub fn set_rva(&mut self, rva: i64) {
        self.rva = rva;
    }

    pub fn get_base(&self) -> i64 {
        self.base
    }

    pub fn set_base(&mut self, base: i64) {
        self.base = base;
    }

    pub fn set_length(&mut self, length: i64) {
        self.length = length;
    }

    pub fn get_length(&self) -> i64 {
        self.length
    }

    pub fn get_adjusted_address(&self, addr: i64) -> i64 {
        addr - self.get_base() + self.get_rva()
    }

    pub fn get_copy_len(&self, addr: i64, size: i64) -> i64 {
        if addr - self.get_rva() + size > self.get_length() {
            return self.get_length() - (addr - self.get_rva());
        }
        size
    }

    pub fn is_read(&self) -> bool {
        self.is_read
    }

    pub fn is_write(&self) -> bool {
        self.is_write
    }

    pub fn is_exec(&self) -> bool {
        self.is_exec
    }

    pub fn set_read(&mut self, is_read: bool) {
        self.is_read = is_read;
    }

    pub fn set_write(&mut self, is_write: bool) {
        self.is_write = is_write;
    }

    pub fn set_exec(&mut self, is_exec: bool) {
        self.is_exec = is_exec;
    }

    pub fn get_comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    pub fn set_comment(&mut self, comment: String) {
        self.comment = Some(comment);
    }

    pub fn get_address(&self) -> Option<Address> {
        self.address.clone()
    }

    pub fn set_address(&mut self, address: Address) {
        self.address = Some(address);
    }

    pub fn get_range_name(&self) -> Option<&str> {
        self.range_name.as_deref()
    }

    pub fn set_range_name(&mut self, name: String) {
        self.range_name = Some(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpace;

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new(
            "ram",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        );
        Address::new(space, offset)
    }

    #[test]
    fn new_sets_defaults() {
        let obj = DumpAddressObject::new("provider".to_string(), 0x10, 0x1000, 0x2000);
        assert_eq!(obj.get_provider_id(), "provider");
        assert_eq!(obj.get_rva(), 0x10);
        assert_eq!(obj.get_base(), 0x1000);
        assert_eq!(obj.get_length(), 0x2000);
        assert!(obj.is_read());
        assert!(obj.is_write());
        assert!(obj.is_exec());
        assert_eq!(obj.get_comment(), None);
        assert!(obj.get_address().is_none());
        assert_eq!(obj.get_range_name(), None);
    }

    #[test]
    fn setters_update_fields() {
        let mut obj = DumpAddressObject::new("p".to_string(), 0, 0, 0);
        obj.set_provider_id("other".to_string());
        obj.set_rva(0x20);
        obj.set_base(0x100);
        obj.set_length(0x400);
        obj.set_read(false);
        obj.set_write(false);
        obj.set_exec(false);
        obj.set_comment("a comment".to_string());
        obj.set_range_name("range".to_string());
        obj.set_address(test_address(0x1234));

        assert_eq!(obj.get_provider_id(), "other");
        assert_eq!(obj.get_rva(), 0x20);
        assert_eq!(obj.get_base(), 0x100);
        assert_eq!(obj.get_length(), 0x400);
        assert!(!obj.is_read());
        assert!(!obj.is_write());
        assert!(!obj.is_exec());
        assert_eq!(obj.get_comment(), Some("a comment"));
        assert_eq!(obj.get_range_name(), Some("range"));
        assert_eq!(obj.get_address().unwrap().offset(), 0x1234);
    }

    #[test]
    fn get_adjusted_address_offsets_by_base_and_rva() {
        let obj = DumpAddressObject::new("p".to_string(), 0x10, 0x1000, 0x2000);
        assert_eq!(obj.get_adjusted_address(0x1500), 0x510);
    }

    #[test]
    fn get_copy_len_returns_size_when_within_bounds() {
        let obj = DumpAddressObject::new("p".to_string(), 0x10, 0x1000, 0x100);
        assert_eq!(obj.get_copy_len(0x20, 0x10), 0x10);
    }

    #[test]
    fn get_copy_len_truncates_when_exceeding_length() {
        let obj = DumpAddressObject::new("p".to_string(), 0x10, 0x1000, 0x100);
        // addr - rva + size = 0xf0 - 0x10 + 0x40 = 0x120 > length (0x100)
        let result = obj.get_copy_len(0xf0, 0x40);
        assert_eq!(result, 0x100 - (0xf0 - 0x10));
    }
}
