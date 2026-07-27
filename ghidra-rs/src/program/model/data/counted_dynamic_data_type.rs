use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::dynamic_data_type::DynamicDataType;
use crate::program::model::mem::Memory;
use crate::program::seam_stubs::{self, MemBuffer};

/// A dynamic data type that changes the number of elements it contains based on a count found in
/// a header data type. The data type has a header data type which will contain the number of
/// base data types following the header data type.
///
/// NOTE: This is a special Dynamic data-type which can only appear as a component created by a
/// Dynamic data-type.
///
/// Port of `ghidra.program.model.data.CountedDynamicDataType`.
///
/// The Java class is `abstract class CountedDynamicDataType extends DynamicDataType`, so this
/// trait carries [`DynamicDataType`] (and transitively `Dynamic`/`BuiltInDataType`/[`DataType`])
/// as its supertrait chain. The Java constructor's fields (`description`, `header`, `baseStruct`,
/// `counterOffset`, `counterSize`, `mask`) become the accessor methods below, which a concrete
/// implementation supplies from its own storage; [`normalize_mask`] reproduces the constructor's
/// `mask == 0 ? 0xFFFFFFFF : mask` substitution for implementors to apply when storing the mask.
///
/// The Java class's `getValue`/`getRepresentation`/`getMnemonic` overrides (`null`, `""`, and
/// `name` respectively) are not repeated here: they already match
/// [`DataType`]'s default implementations of `get_value`, `get_representation`, and
/// `get_mnemonic` (which delegates to `get_name`), so a concrete implementation gets them for
/// free. `getDescription()` and `clone(DataTypeManager)` (which returns `this`, unrepresentable
/// as a generic dyn-safe default given `dyn DataType` has no `Clone` bound) are genuinely
/// instance-specific and are left for a concrete implementation to override directly on
/// [`DataType`].
///
/// `DynamicDataType::get_all_components` is the method Java's `getAllComponents(MemBuffer)`
/// overrides; since a Rust subtrait cannot redeclare a supertrait method of the same name (see
/// [`DynamicDataType`]'s docs for why), the template implementation is exposed here under
/// [`counted_all_components`](Self::counted_all_components); a concrete type implementing both
/// traits should have its `DynamicDataType::get_all_components` delegate to it.
pub trait CountedDynamicDataType: DynamicDataType {
    /// Header data type that will contain the number of following elements.
    fn header(&self) -> Arc<dyn DataType>;

    /// Base data type for each of the following elements.
    fn base_struct(&self) -> Arc<dyn DataType>;

    /// Offset of the number of following elements from the start of the header.
    fn counter_offset(&self) -> i64;

    /// Size of the count in bytes.
    fn counter_size(&self) -> i32;

    /// Mask applied to the raw count value to obtain the actual number of following elements.
    /// Implementors should store [`normalize_mask`]`(mask)` from their constructor argument, per
    /// the Java constructor's `mask == 0 ? 0xFFFFFFFF : mask` substitution.
    fn mask(&self) -> i64;

    /// Template implementation backing the Java class's override of
    /// `DynamicDataType.getAllComponents(MemBuffer)`.
    ///
    /// Returns all components, or `None` if memory data is not valid for this data type (no
    /// backing [`Memory`], the counter address overflows the address space, the header's data
    /// type instance could not be determined, or (mid-loop) a base-struct data type instance
    /// could not be determined).
    fn counted_all_components(
        &self,
        buf: &dyn MemBuffer,
    ) -> Option<Vec<Option<Box<dyn DataTypeComponent>>>> {
        let memory = buf.get_memory()?;
        let start = buf.get_address();

        // Find count
        let counter_addr = start.add(self.counter_offset()).ok()?;
        let n = self.get_count(memory.as_ref(), &counter_addr) as i32;

        let header = self.header();
        let base_struct = self.base_struct();

        let mut comps: Vec<Option<Box<dyn DataTypeComponent>>> = Vec::with_capacity(n as usize + 1);
        let header_instance = seam_stubs::get_data_type_instance(header.clone(), buf, false)?;
        let count_size = header_instance.get_length();
        comps.push(Some(Box::new(seam_stubs::ReadOnlyDataTypeComponent::new(
            header_instance.get_data_type(),
            count_size,
            0,
            0,
            format!("{}_{}", header.get_name(), buf.get_address()),
        ))));

        let mut offset = count_size;
        let mut cur_addr = buf.get_address().add(count_size as i64).ok()?;
        for i in 1..=n {
            let base_instance = seam_stubs::get_data_type_instance(base_struct.clone(), buf, false)?;
            let len = base_instance.get_length();
            comps.push(Some(Box::new(seam_stubs::ReadOnlyDataTypeComponent::new(
                base_instance.get_data_type(),
                len,
                i,
                offset,
                format!("{}_{}", base_struct.get_name(), cur_addr),
            ))));
            offset += len;
            cur_addr = cur_addr.add(len as i64).ok()?;
        }
        Some(comps)
    }

    /// Extract the count of following elements from the given location in memory, applying
    /// [`mask`](Self::mask).
    ///
    /// Mirrors the Java private `getCount` helper: an unsupported [`counter_size`](Self::counter_size)
    /// (not 1, 2, 4, or 8) or a failed memory read both report `0` rather than propagating an
    /// error, matching the Java method's log-and-return-0 behavior.
    fn get_count(&self, memory: &dyn Memory, loc: &Address) -> i64 {
        let size = self.counter_size();
        if !matches!(size, 1 | 2 | 4 | 8) {
            return 0;
        }
        let mut bytes = [0u8; 8];
        if memory.get_bytes(loc, &mut bytes[..size as usize]) != size as usize {
            return 0;
        }
        let mut value: u64 = 0;
        if memory.is_big_endian() {
            for &b in &bytes[..size as usize] {
                value = (value << 8) | b as u64;
            }
        } else {
            for &b in bytes[..size as usize].iter().rev() {
                value = (value << 8) | b as u64;
            }
        }
        (value as i64) & self.mask()
    }
}

/// Port of the Java constructor's `mask == 0 ? 0xFFFFFFFF : mask` substitution: a caller-supplied
/// mask of `0` is treated as "no mask" (all 32 count bits significant).
pub fn normalize_mask(mask: i64) -> i64 {
    if mask == 0 {
        0xFFFFFFFF
    } else {
        mask
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::dynamic::Dynamic;
    use crate::program::model::mem::MemoryAccessException;
    use crate::docking::settings::settings::Settings;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    struct MockMemory {
        base: Address,
        bytes: Vec<u8>,
        big_endian: bool,
    }

    impl Memory for MockMemory {
        fn is_big_endian(&self) -> bool {
            self.big_endian
        }

        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            let idx = (addr.offset() - self.base.offset()) as usize;
            self.bytes
                .get(idx)
                .copied()
                .ok_or_else(MemoryAccessException::default)
        }

        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            let idx = (addr.offset() - self.base.offset()) as usize;
            if idx >= self.bytes.len() {
                return 0;
            }
            let n = dest.len().min(self.bytes.len() - idx);
            dest[..n].copy_from_slice(&self.bytes[idx..idx + n]);
            n
        }

        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Ok(())
        }
    }

    struct MockMemBuffer {
        address: Address,
        memory: Arc<dyn Memory>,
    }

    impl MemBuffer for MockMemBuffer {
        fn get_address(&self) -> Address {
            self.address.clone()
        }

        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            Some(self.memory.clone())
        }
    }

    struct MockSettings;
    impl Settings for MockSettings {}

    struct FixedLengthDataType {
        name: &'static str,
        length: i32,
    }

    impl DataType for FixedLengthDataType {
        fn get_name(&self) -> String {
            self.name.to_string()
        }

        fn get_length(&self) -> i32 {
            self.length
        }
    }

    struct MockCounted {
        header: Arc<dyn DataType>,
        base_struct: Arc<dyn DataType>,
        counter_offset: i64,
        counter_size: i32,
        mask: i64,
    }

    impl DataType for MockCounted {
        fn get_length(&self) -> i32 {
            -1
        }
    }

    impl BuiltInDataType for MockCounted {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            None
        }

        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl Dynamic for MockCounted {
        fn get_dynamic_length(&self, buf: &dyn MemBuffer, max_length: i32) -> i32 {
            self.dynamic_length_from_components(buf, max_length)
        }

        fn get_replacement_base_type(&self) -> Box<dyn DataType> {
            self.default_replacement_base_type()
        }
    }

    impl DynamicDataType for MockCounted {
        fn get_all_components(
            &self,
            buf: &dyn MemBuffer,
        ) -> Option<Vec<Option<Box<dyn DataTypeComponent>>>> {
            self.counted_all_components(buf)
        }
    }

    impl CountedDynamicDataType for MockCounted {
        fn header(&self) -> Arc<dyn DataType> {
            self.header.clone()
        }

        fn base_struct(&self) -> Arc<dyn DataType> {
            self.base_struct.clone()
        }

        fn counter_offset(&self) -> i64 {
            self.counter_offset
        }

        fn counter_size(&self) -> i32 {
            self.counter_size
        }

        fn mask(&self) -> i64 {
            self.mask
        }
    }

    #[test]
    fn usable_as_trait_object_and_builds_components_from_memory() {
        let space = ram_space();
        let base_addr = Address::new(space.clone(), 0x1000);

        // Header (2 bytes: big-endian count) followed by 2 base-struct elements (3 bytes each).
        let memory = Arc::new(MockMemory {
            base: base_addr.clone(),
            bytes: vec![0x00, 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            big_endian: true,
        });
        let buf = MockMemBuffer {
            address: base_addr.clone(),
            memory,
        };

        let dt = MockCounted {
            header: Arc::new(FixedLengthDataType { name: "header", length: 2 }),
            base_struct: Arc::new(FixedLengthDataType { name: "elem", length: 3 }),
            counter_offset: 0,
            counter_size: 2,
            mask: normalize_mask(0),
        };
        let dyn_dt: &dyn CountedDynamicDataType = &dt;

        let comps = dyn_dt.counted_all_components(&buf).expect("components");
        assert_eq!(comps.len(), 3);

        let header_comp = comps[0].as_ref().unwrap();
        assert_eq!(header_comp.get_ordinal(), 0);
        assert_eq!(header_comp.get_offset(), 0);
        assert_eq!(header_comp.get_length(), 2);
        assert_eq!(
            header_comp.get_field_name(),
            Some(format!("header_{base_addr}"))
        );

        let elem0 = comps[1].as_ref().unwrap();
        assert_eq!(elem0.get_ordinal(), 1);
        assert_eq!(elem0.get_offset(), 2);
        assert_eq!(elem0.get_length(), 3);

        let elem1 = comps[2].as_ref().unwrap();
        assert_eq!(elem1.get_ordinal(), 2);
        assert_eq!(elem1.get_offset(), 5);
        assert_eq!(elem1.get_length(), 3);

        // DynamicDataType's derived query methods work through the same trait object.
        let dyn_ddt: &dyn DynamicDataType = &dt;
        assert_eq!(dyn_ddt.get_num_components(&buf), 3);
    }

    #[test]
    fn unsupported_counter_size_reports_zero_count() {
        let space = ram_space();
        let base_addr = Address::new(space, 0x2000);
        let memory = Arc::new(MockMemory {
            base: base_addr.clone(),
            bytes: vec![0xFF, 0xFF, 0xFF],
            big_endian: true,
        });
        let buf = MockMemBuffer {
            address: base_addr,
            memory,
        };

        let dt = MockCounted {
            header: Arc::new(FixedLengthDataType { name: "header", length: 3 }),
            base_struct: Arc::new(FixedLengthDataType { name: "elem", length: 1 }),
            counter_offset: 0,
            counter_size: 3, // unsupported: not 1, 2, 4, or 8
            mask: normalize_mask(0),
        };

        // Only the header component is emitted, since the count is treated as 0.
        let comps = dt.counted_all_components(&buf).expect("components");
        assert_eq!(comps.len(), 1);
    }

    #[test]
    fn mask_limits_extracted_count() {
        let space = ram_space();
        let addr = Address::new(space, 0x3000);
        let memory = MockMemory {
            base: addr.clone(),
            bytes: vec![0x00, 0xFF],
            big_endian: true,
        };

        let dt = MockCounted {
            header: Arc::new(FixedLengthDataType { name: "header", length: 2 }),
            base_struct: Arc::new(FixedLengthDataType { name: "elem", length: 1 }),
            counter_offset: 0,
            counter_size: 2,
            mask: 0x0F,
        };

        assert_eq!(dt.get_count(&memory, &addr), 0x0F);
    }

    #[test]
    fn normalize_mask_substitutes_default_for_zero() {
        assert_eq!(normalize_mask(0), 0xFFFFFFFF);
        assert_eq!(normalize_mask(0xFF), 0xFF);
    }
}
