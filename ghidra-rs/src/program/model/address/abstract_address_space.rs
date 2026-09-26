use std::sync::Arc;

use super::{unsigned_lt, Address, AddressFormatException, AddressOutOfBoundsException,
    AddressOverflowException, AddressSpace, AddressSpaceType};

/// Trait mirroring Java's `abstract class AbstractAddressSpace implements AddressSpace`.
///
/// The field-backed data (name/size/unit-size/type/id/bounds) and its associated math already
/// live on the concrete [`AddressSpace`] struct in this port, so implementors just wrap an
/// [`AddressSpace`] and supply the handful of methods Java left for concrete subclasses to
/// override: `getUncheckedAddress`, `computeHashCode`, `getAddress` and
/// `getAddressInThisSpaceOnly` (the latter two are abstract on the `AddressSpace` interface and
/// were never implemented by `AbstractAddressSpace` itself).
pub trait AbstractAddressSpace {
    /// The address-space descriptor (name/size/unit-size/type/id) this instance wraps.
    fn base_space(&self) -> &Arc<AddressSpace>;

    /// Instantiates an address within this space. No offset validation is performed.
    fn get_unchecked_address(&self, offset: i64) -> Address;

    /// Computes the fixed hash code for this address space.
    fn compute_hash_code(&self) -> i32;

    /// Returns the address for the given byte offset, validating that it lies in this space.
    fn get_address(&self, byte_offset: i64) -> Result<Address, AddressOutOfBoundsException>;

    /// Like [`Self::get_address`] but never redirected to an overlay/base space.
    fn get_address_in_this_space_only(
        &self,
        byte_offset: i64,
    ) -> Result<Address, AddressOutOfBoundsException>;

    fn has_signed_offset(&self) -> bool {
        self.base_space().is_signed()
    }

    fn get_size(&self) -> i32 {
        self.base_space().size()
    }

    fn get_addressable_unit_size(&self) -> i32 {
        self.base_space().unit_size()
    }

    fn get_pointer_size(&self) -> i32 {
        self.base_space().pointer_size()
    }

    fn get_type(&self) -> AddressSpaceType {
        self.base_space().space_type()
    }

    fn get_space_id(&self) -> i32 {
        self.base_space().space_id()
    }

    fn get_unique(&self) -> i32 {
        self.base_space().unique()
    }

    fn get_addressable_word_offset(&self, byte_offset: i64) -> i64 {
        self.base_space().addressable_word_offset(byte_offset)
    }

    fn make_valid_offset(&self, offset: i64) -> Result<i64, AddressOutOfBoundsException> {
        self.base_space().make_valid_offset(offset)
    }

    fn truncate_offset(&self, offset: i64) -> i64 {
        self.base_space().truncate_offset(offset)
    }

    fn truncate_addressable_word_offset(&self, word_offset: i64) -> i64 {
        self.base_space().truncate_addressable_word_offset(word_offset)
    }

    /// Number of address locations in this space (2^size * unitSize); 0 for a full 64-bit space.
    fn space_size(&self) -> i64 {
        if self.base_space().size() == 64 {
            0
        } else {
            (self.base_space().unit_size() as i64) << self.base_space().size()
        }
    }

    fn get_max_address(&self) -> Address {
        self.base_space().max_address()
    }

    fn get_min_address(&self) -> Address {
        self.base_space().min_address()
    }

    /// No overlay translation necessary; base address spaces return the address unchanged.
    fn get_overlay_address(&self, addr: &Address) -> Address {
        addr.clone()
    }

    fn is_overlay_space(&self) -> bool {
        false
    }

    fn get_physical_space(&self) -> Arc<AddressSpace> {
        self.base_space().clone()
    }

    fn has_mapped_registers(&self) -> bool {
        false
    }

    fn is_memory_space(&self) -> bool {
        self.base_space().is_memory_space()
    }

    fn is_loaded_memory_space(&self) -> bool {
        self.base_space().is_loaded_memory_space()
    }

    fn is_non_loaded_memory_space(&self) -> bool {
        self.get_type() == AddressSpaceType::Other
    }

    fn is_register_space(&self) -> bool {
        self.get_type() == AddressSpaceType::Register
    }

    fn is_stack_space(&self) -> bool {
        self.get_type() == AddressSpaceType::Stack
    }

    fn is_unique_space(&self) -> bool {
        self.get_type() == AddressSpaceType::Unique
    }

    fn is_constant_space(&self) -> bool {
        self.get_type() == AddressSpaceType::Constant
    }

    fn is_variable_space(&self) -> bool {
        self.get_type() == AddressSpaceType::Variable
    }

    fn is_external_space(&self) -> bool {
        self.get_type() == AddressSpaceType::External
    }

    fn show_space_name(&self) -> bool {
        self.get_type() != AddressSpaceType::Ram || self.is_overlay_space()
    }

    fn hash_code(&self) -> i32 {
        self.compute_hash_code()
    }

    fn test_address_space(&self, addr: &Address) {
        if addr.space() != self.base_space() {
            panic!(
                "Address space for {} ({}) does not match {}",
                addr,
                addr.space().name(),
                self.base_space().name()
            );
        }
    }

    fn add_wrap(&self, addr: &Address, displacement: i64) -> Address {
        self.test_address_space(addr);
        self.get_unchecked_address(self.truncate_offset(addr.offset().wrapping_add(displacement)))
    }

    fn add_wrap_space(&self, addr: &Address, displacement: i64) -> Address {
        self.add_wrap(addr, displacement)
    }

    fn subtract_wrap(&self, addr: &Address, displacement: i64) -> Address {
        self.test_address_space(addr);
        self.get_unchecked_address(self.truncate_offset(addr.offset().wrapping_sub(displacement)))
    }

    fn subtract_wrap_space(&self, addr: &Address, displacement: i64) -> Address {
        self.subtract_wrap(addr, displacement)
    }

    fn add_no_wrap(
        &self,
        addr: &Address,
        displacement: i64,
    ) -> Result<Address, AddressOverflowException> {
        if displacement == 0 {
            return Ok(addr.clone());
        }
        if displacement < 0 {
            return self.subtract_no_wrap(addr, displacement.wrapping_neg());
        }

        self.test_address_space(addr);
        let space_size = self.space_size();
        if displacement > space_size && space_size != 0 {
            return Err(AddressOverflowException::new(format!(
                "Address Overflow in add: {} 0x{:x}",
                addr, displacement
            )));
        }
        let addr_off = addr.offset();
        let result = addr_off.wrapping_add(displacement);
        let max_offset = self.base_space().max_offset();
        let overflowed = if self.has_signed_offset() {
            result < addr_off || result > max_offset
        } else {
            unsigned_lt(max_offset, result) || unsigned_lt(result, addr_off)
        };
        if overflowed {
            return Err(AddressOverflowException::new(format!(
                "Address Overflow in add: {} 0x{:x}",
                addr, displacement
            )));
        }
        Ok(self.get_unchecked_address(result))
    }

    fn subtract_no_wrap(
        &self,
        addr: &Address,
        displacement: i64,
    ) -> Result<Address, AddressOverflowException> {
        if displacement < 0 {
            if displacement == i64::MIN {
                return Err(AddressOverflowException::new(format!(
                    "Address Overflow in subtract: {} - 0x{:x}",
                    addr, displacement
                )));
            }
            return self.add_no_wrap(addr, -displacement);
        }

        self.test_address_space(addr);
        let space_size = self.space_size();
        if displacement > space_size && space_size != 0 {
            return Err(AddressOverflowException::new(format!(
                "Address Overflow in subtract: {} - 0x{:x}",
                addr, displacement
            )));
        }
        let addr_off = addr.offset();
        let result = addr_off.wrapping_sub(displacement);
        let min_offset = self.base_space().min_offset();
        let overflowed = if self.has_signed_offset() {
            result < min_offset || result > addr_off
        } else {
            unsigned_lt(addr_off, result)
        };
        if overflowed {
            return Err(AddressOverflowException::new(format!(
                "Address Overflow in subtract: {} - 0x{:x}",
                addr, displacement
            )));
        }
        Ok(self.get_unchecked_address(result))
    }

    fn add(&self, addr: &Address, displacement: i64) -> Result<Address, AddressOutOfBoundsException> {
        self.add_no_wrap(addr, displacement)
            .map_err(|e| AddressOutOfBoundsException::new(e.message().to_string()))
    }

    fn subtract(
        &self,
        addr: &Address,
        displacement: i64,
    ) -> Result<Address, AddressOutOfBoundsException> {
        self.subtract_no_wrap(addr, displacement)
            .map_err(|e| AddressOutOfBoundsException::new(e.message().to_string()))
    }

    /// Byte-offset distance between two addresses in this space (Java's `subtract(Address,
    /// Address)`); panics if the addresses belong to different spaces, matching the panic-based
    /// mismatch handling already used by [`Address::subtract`] elsewhere in this port.
    fn distance(&self, addr1: &Address, addr2: &Address) -> i64 {
        addr1.subtract(addr2)
    }

    fn is_valid_range(&self, byte_offset: i64, length: i64) -> bool {
        let start = match self.get_address(byte_offset) {
            Ok(addr) => addr,
            Err(_) => return false,
        };
        if length == 0 {
            return false;
        }
        self.add_no_wrap(&start, length - 1).is_ok()
    }

    fn is_successor(&self, addr1: &Address, addr2: &Address) -> bool {
        if addr1.space() != addr2.space() {
            return false;
        }
        if self.base_space().max_offset() == addr1.offset() {
            return false;
        }
        addr1.offset() == addr2.offset().wrapping_sub(1)
    }

    fn get_address_word_or_byte(
        &self,
        offset: i64,
        is_addressable_word_offset: bool,
    ) -> Result<Address, AddressOutOfBoundsException> {
        let byte_offset = if is_addressable_word_offset {
            offset.wrapping_mul(self.base_space().unit_size() as i64)
        } else {
            offset
        };
        self.get_address(byte_offset)
    }

    fn get_truncated_address(&self, offset: i64, is_addressable_word_offset: bool) -> Address {
        let truncated_offset = if is_addressable_word_offset {
            self.truncate_addressable_word_offset(offset)
        } else {
            self.truncate_offset(offset)
        };
        self.get_address_word_or_byte(truncated_offset, is_addressable_word_offset)
            .expect("offset should be valid after truncation")
    }

    fn get_address_from_string(
        &self,
        addr_string: &str,
        case_sensitive: bool,
    ) -> Result<Option<Address>, AddressFormatException> {
        let mut off_str = addr_string;
        if let Some(colon_pos) = addr_string.rfind(':') {
            let addr_space_str = &addr_string[..colon_pos];
            let matches = if case_sensitive {
                addr_space_str == self.base_space().name()
            } else {
                addr_space_str.eq_ignore_ascii_case(self.base_space().name())
            };
            if !matches {
                return Ok(None);
            }
            off_str = &addr_string[colon_pos + 1..];
        }

        let off = self.parse_offset_string(off_str).map_err(|_| {
            AddressFormatException::new(format!(
                "{} contains invalid address hex offset",
                addr_string
            ))
        })?;
        self.get_address_in_this_space_only(off)
            .map(Some)
            .map_err(|e| AddressFormatException::new(e.message().to_string()))
    }

    fn parse_offset_string(&self, addr: &str) -> Result<i64, ()> {
        let mut addr = addr;
        if let Some(stripped) = addr.strip_prefix("0x").or_else(|| addr.strip_prefix("0X")) {
            addr = stripped;
        }

        let unit_size = self.base_space().unit_size() as i64;
        let mut modv: i64 = 0;
        let mut hex_part = addr;
        if unit_size > 1 {
            if let Some(dot_ix) = addr.find('.') {
                if dot_ix > 0 {
                    let unit_offset = &addr[dot_ix + 1..];
                    let bi = i64::from_str_radix(unit_offset, 16).map_err(|_| ())?;
                    if unit_offset.len() > 2 || bi >= unit_size {
                        return Err(());
                    }
                    modv = bi;
                    hex_part = &addr[..dot_ix];
                }
            }
        }

        let value = i64::from_str_radix(hex_part, 16).map_err(|_| ())?;
        Ok(unit_size.wrapping_mul(value).wrapping_add(modv))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockAddressSpace {
        space: Arc<AddressSpace>,
    }

    impl AbstractAddressSpace for MockAddressSpace {
        fn base_space(&self) -> &Arc<AddressSpace> {
            &self.space
        }

        fn get_unchecked_address(&self, offset: i64) -> Address {
            Address::new(self.space.clone(), offset)
        }

        fn compute_hash_code(&self) -> i32 {
            self.space.space_id()
        }

        fn get_address(&self, byte_offset: i64) -> Result<Address, AddressOutOfBoundsException> {
            self.space.checked_address(byte_offset)
        }

        fn get_address_in_this_space_only(
            &self,
            byte_offset: i64,
        ) -> Result<Address, AddressOutOfBoundsException> {
            self.get_address(byte_offset)
        }
    }

    fn mock(
        name: &str,
        size: i32,
        unit_size: i32,
        ty: AddressSpaceType,
        unique: i32,
    ) -> MockAddressSpace {
        MockAddressSpace {
            space: AddressSpace::new(name, size, unit_size, ty, unique),
        }
    }

    #[test]
    fn trait_object_supports_wrap_and_no_wrap_arithmetic() {
        let space: Box<dyn AbstractAddressSpace> =
            Box::new(mock("ram", 8, 1, AddressSpaceType::Ram, 0));
        let addr = space.get_unchecked_address(5);

        assert_eq!(space.add_wrap(&addr, 3).offset(), 8);
        assert_eq!(space.add_wrap(&addr, 1024).offset(), 5); // wraps around the 2^8 space
        assert_eq!(space.add_no_wrap(&addr, 3).unwrap().offset(), 8);
        assert!(space.add_no_wrap(&addr, 1024).is_err());
        assert!(space.subtract_no_wrap(&addr, 1024).is_err());
    }

    #[test]
    fn is_valid_range_and_is_successor_match_java_semantics() {
        let space: Box<dyn AbstractAddressSpace> =
            Box::new(mock("ram", 8, 1, AddressSpaceType::Ram, 0));

        assert!(space.is_valid_range(0, 10));
        assert!(!space.is_valid_range(0, 0));
        assert!(!space.is_valid_range(250, 100)); // would overflow past the max offset

        let a = space.get_unchecked_address(5);
        let b = space.get_unchecked_address(6);
        assert!(space.is_successor(&a, &b));
        assert!(!space.is_successor(&b, &a));
    }

    #[test]
    fn get_address_from_string_round_trips_hex_offsets() {
        let space: Box<dyn AbstractAddressSpace> =
            Box::new(mock("ram", 16, 1, AddressSpaceType::Ram, 0));

        let addr = space
            .get_address_from_string("ram:0x10", true)
            .unwrap()
            .unwrap();
        assert_eq!(addr.offset(), 0x10);
        assert!(space
            .get_address_from_string("other:0x10", true)
            .unwrap()
            .is_none());
    }

    #[test]
    fn show_space_name_matches_constructor_formula() {
        let ram: Box<dyn AbstractAddressSpace> =
            Box::new(mock("ram", 8, 1, AddressSpaceType::Ram, 0));
        let register: Box<dyn AbstractAddressSpace> =
            Box::new(mock("reg", 8, 1, AddressSpaceType::Register, 0));

        assert!(!ram.show_space_name());
        assert!(register.show_space_name());
    }
}
