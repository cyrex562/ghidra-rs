use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::data_type_manager::DataTypeManager;

/// The structure interface.
///
/// NOTE: A zero-length Structure will report a length of 1 which will result in improper code
/// unit sizing since we are unable to support a defined data of length 0.
///
/// NOTE: The use of zero-length bitfields within non-packed structures is discouraged since they
/// have no real affect and are easily misplaced. Their use should be reserved for packed
/// structures.
///
/// Port of `ghidra.program.model.data.Structure`.
///
/// This trait was promoted from a minimal placeholder (see `seam_stubs.rs`) that declared no
/// methods, so there is nothing to retain as a superset here.
///
/// Every method is given a default so that the existing bare `impl Structure for MockStructure
/// {}` in
/// [`StructureInternal`](super::structure_internal::StructureInternal)'s tests keeps compiling
/// unmodified. Concrete implementations (`StructureDB`, `StructureDataType`, etc.) will override
/// these with real behavior once they are ported.
///
/// The nested `BitOffsetComparator` utility class is not ported here: its `compare` method
/// depends on casting a component's data type to `BitFieldDataType`, which is not yet part of
/// the Rust crate. Its pure static helper,
/// [`get_normalized_bitfield_offset`], has no such dependency and is ported as a free function
/// below.
pub trait Structure: Composite {
    /// Returns a copy of this structure, associated with the given data type manager. Mirrors
    /// the covariant override of `Composite.clone(DataTypeManager)`.
    fn clone_structure(&self, dtm: &dyn DataTypeManager) -> Box<dyn Structure> {
        let _ = dtm;
        Box::new(EmptyStructure)
    }

    /// Returns the component of this structure with the indicated ordinal.
    ///
    /// # Errors
    /// Returns `Err` if `ordinal` is out of bounds (mirrors `IndexOutOfBoundsException`).
    fn get_component(&self, ordinal: i32) -> Result<Box<dyn DataTypeComponent>, String> {
        Err(format!(
            "IndexOutOfBoundsException: ordinal {ordinal} out of bounds"
        ))
    }

    /// Gets the first defined component located at or after the specified offset. If a
    /// component contains the specified offset that component will be returned. The returned
    /// component may be a zero-length component.
    fn get_defined_component_at_or_after_offset(
        &self,
        offset: i32,
    ) -> Option<Box<dyn DataTypeComponent>> {
        let _ = offset;
        None
    }

    /// Gets the first non-zero-length component that contains the byte at the specified offset.
    /// Returns `None` if the offset only corresponds to a zero-length component or padding
    /// byte within a packed structure, or if the offset is at or beyond the structure length.
    fn get_component_containing(&self, offset: i32) -> Option<Box<dyn DataTypeComponent>> {
        let _ = offset;
        None
    }

    /// Gets the first non-zero-length component that starts at the specified offset. Returns
    /// `None` if no component starts exactly at that offset.
    fn get_component_at(&self, offset: i32) -> Option<Box<dyn DataTypeComponent>> {
        let mut dtc = self.get_component_containing(offset);
        loop {
            let advance = match &dtc {
                Some(d) => {
                    d.is_bit_field_component()
                        && d.get_offset() < offset
                        && d.get_ordinal() < self.get_num_components() - 1
                }
                None => false,
            };
            if !advance {
                break;
            }
            let next_ordinal = dtc.as_ref().unwrap().get_ordinal() + 1;
            dtc = Structure::get_component(self, next_ordinal).ok();
        }
        match dtc {
            Some(d) if d.get_offset() == offset => Some(d),
            _ => None,
        }
    }

    /// Get an ordered list of components that contain the byte at the specified offset,
    /// including zero-length components at that offset.
    fn get_components_containing(&self, offset: i32) -> Vec<Box<dyn DataTypeComponent>> {
        let _ = offset;
        Vec::new()
    }

    /// Returns the lowest-level component that contains the specified offset. Useful for
    /// structures with sub-structures.
    fn get_data_type_at(&self, offset: i32) -> Option<Box<dyn DataTypeComponent>> {
        let _ = offset;
        None
    }

    /// Inserts a new bitfield at the specified ordinal position in this structure.
    ///
    /// # Errors
    /// Returns `Err` if `base_data_type` is not a valid base type for bitfields (mirrors
    /// `InvalidDataTypeException`), or if `ordinal` is out of bounds (mirrors
    /// `IndexOutOfBoundsException`).
    fn insert_bit_field(
        &mut self,
        ordinal: i32,
        byte_width: i32,
        bit_offset: i32,
        base_data_type: Box<dyn DataType>,
        bit_size: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        let (_, _, _, _, _, _) = (
            byte_width,
            bit_offset,
            base_data_type,
            bit_size,
            component_name,
            comment,
        );
        Err(format!(
            "IndexOutOfBoundsException: ordinal {ordinal} out of bounds"
        ))
    }

    /// Inserts a new bitfield at the specified byte offset in this structure. Intended for use
    /// with structures with packing disabled where the bitfield will be precisely placed.
    ///
    /// # Errors
    /// Returns `Err` if `base_data_type` is not a valid base type for bitfields (mirrors
    /// `InvalidDataTypeException`).
    fn insert_bit_field_at(
        &mut self,
        byte_offset: i32,
        byte_width: i32,
        bit_offset: i32,
        base_data_type: Box<dyn DataType>,
        bit_size: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        let (_, _, _, _, _, _, _) = (
            byte_offset,
            byte_width,
            bit_offset,
            base_data_type,
            bit_size,
            component_name,
            comment,
        );
        Err("InvalidDataTypeException: not a valid bitfield base type".to_string())
    }

    /// Inserts a new datatype at the specified offset into this structure, shifting any
    /// conflicting components down as necessary.
    ///
    /// # Errors
    /// Returns `Err` if `data_type` is not allowed to be inserted or an invalid length is
    /// specified (mirrors `IllegalArgumentException`).
    fn insert_at_offset(
        &mut self,
        offset: i32,
        data_type: Box<dyn DataType>,
        length: i32,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        let (_, _, _) = (offset, data_type, length);
        Err("IllegalArgumentException: data type not allowed at offset".to_string())
    }

    /// Inserts a new datatype at the specified offset into this structure, with an explicit
    /// field name and comment.
    ///
    /// # Errors
    /// Returns `Err` if `data_type` is not allowed to be inserted or an invalid length is
    /// specified (mirrors `IllegalArgumentException`).
    fn insert_at_offset_with_name(
        &mut self,
        offset: i32,
        data_type: Box<dyn DataType>,
        length: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        let (_, _, _, _, _) = (offset, data_type, length, component_name, comment);
        Err("IllegalArgumentException: data type not allowed at offset".to_string())
    }

    /// Deletes all defined components containing the specified offset in this structure.
    ///
    /// # Errors
    /// Returns `Err` if a negative offset is specified (mirrors `IllegalArgumentException`).
    fn delete_at_offset(&mut self, offset: i32) -> Result<(), String> {
        if offset < 0 {
            return Err("IllegalArgumentException: negative offset specified".to_string());
        }
        Ok(())
    }

    /// Remove all components from this structure, effectively setting the length to zero.
    /// Packing and minimum alignment settings are unaffected.
    fn delete_all(&mut self) {}

    /// Clears all defined components containing the specified offset, preserving the structure
    /// length and placement of other components.
    fn clear_at_offset(&mut self, offset: i32) {
        let _ = offset;
    }

    /// Clears the defined component at the specified component ordinal.
    ///
    /// # Errors
    /// Returns `Err` if `ordinal` is out of bounds (mirrors `IndexOutOfBoundsException`).
    fn clear_component(&mut self, ordinal: i32) -> Result<(), String> {
        Err(format!(
            "IndexOutOfBoundsException: ordinal {ordinal} out of bounds"
        ))
    }

    /// Replaces the component at the specified ordinal with a new component using the
    /// specified datatype and length.
    ///
    /// # Errors
    /// Returns `Err` if `ordinal` is out of bounds (mirrors `IndexOutOfBoundsException`) or the
    /// replacement is otherwise invalid (mirrors `IllegalArgumentException`).
    fn replace(
        &mut self,
        ordinal: i32,
        data_type: Box<dyn DataType>,
        length: i32,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        let (_, _) = (data_type, length);
        Err(format!(
            "IndexOutOfBoundsException: ordinal {ordinal} out of bounds"
        ))
    }

    /// Replaces the component at the specified ordinal with a new component using the
    /// specified datatype, length, name and comment.
    ///
    /// # Errors
    /// Returns `Err` if `ordinal` is out of bounds (mirrors `IndexOutOfBoundsException`) or the
    /// replacement is otherwise invalid (mirrors `IllegalArgumentException`).
    fn replace_with_name(
        &mut self,
        ordinal: i32,
        data_type: Box<dyn DataType>,
        length: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        let (_, _, _, _) = (data_type, length, component_name, comment);
        Err(format!(
            "IndexOutOfBoundsException: ordinal {ordinal} out of bounds"
        ))
    }

    /// Replaces all components containing the specified byte offset with a new component using
    /// the specified datatype, length, name and comment.
    ///
    /// # Errors
    /// Returns `Err` if the replacement is invalid (mirrors `IllegalArgumentException`).
    fn replace_at_offset(
        &mut self,
        offset: i32,
        data_type: Box<dyn DataType>,
        length: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        let (_, _, _, _, _) = (offset, data_type, length, component_name, comment);
        Err("IllegalArgumentException: invalid replacement".to_string())
    }

    /// Increases the size of the structure by the specified positive amount by adding undefined
    /// filler at the end of the structure. Only has an effect on non-packed structures.
    ///
    /// # Errors
    /// Returns `Err` if `amount` is negative (mirrors `IllegalArgumentException`).
    fn grow_structure(&mut self, amount: i32) -> Result<(), String> {
        if amount < 0 {
            return Err("IllegalArgumentException: amount < 0".to_string());
        }
        Ok(())
    }

    /// Set the size of the structure to the specified byte length. Only has an effect on
    /// non-packed structures.
    ///
    /// # Errors
    /// Returns `Err` if `length` is negative (mirrors `IllegalArgumentException`).
    fn set_length(&mut self, length: i32) -> Result<(), String> {
        if length < 0 {
            return Err("IllegalArgumentException: length < 0".to_string());
        }
        Ok(())
    }
}

/// Trivial fallback used by [`Structure::clone_structure`]'s default implementation.
struct EmptyStructure;
impl DataType for EmptyStructure {}
impl Composite for EmptyStructure {}
impl Structure for EmptyStructure {}

/// Port of the static utility `Structure.BitOffsetComparator.getNormalizedBitfieldOffset`.
///
/// Computes the normalized bit offset of a bitfield relative to the start of a structure. A
/// normalized component bit numbering establishes the footprint of each component with an
/// ordinal-based ordering (assumes specific LE/BE allocation rules): the first allocated bit of
/// the structure is numbered 0 and the last allocated bit is numbered `(8 * struct_length) - 1`.
/// For big-endian bitfields the msb of the bitfield is assigned the lower bit-number, while
/// little-endian numbering assumes byte-swap and bit-reversal of the storage unit; both result in
/// a normalized view where normalized bit-0 is allocated first.
///
/// # Arguments
/// * `byte_offset` - byte offset within structure of storage unit
/// * `storage_size` - storage unit size (i.e., component length)
/// * `effective_bit_size` - size of bitfield in bits
/// * `bit_offset` - left shift amount for bitfield based upon a big-endian view of the storage
///   unit
/// * `big_endian` - true if big-endian packing applies
pub fn get_normalized_bitfield_offset(
    byte_offset: i32,
    storage_size: i32,
    effective_bit_size: i32,
    bit_offset: i32,
    big_endian: bool,
) -> i32 {
    let mut offset = 8 * byte_offset;
    let mut effective_bit_size = effective_bit_size;
    let mut bit_offset = bit_offset;
    if effective_bit_size == 0 {
        // force zero-length bitfield placement
        effective_bit_size = 1;
        if big_endian {
            bit_offset |= 7;
        } else {
            bit_offset &= -8;
        }
    }
    if big_endian {
        offset += (8 * storage_size) - effective_bit_size - bit_offset;
    } else {
        offset += bit_offset;
    }
    offset
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType;
    impl DataType for MockDataType {}

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    struct MockDataTypeComponent {
        ordinal: i32,
        offset: i32,
    }

    impl DataTypeComponent for MockDataTypeComponent {
        fn get_ordinal(&self) -> i32 {
            self.ordinal
        }
        fn get_offset(&self) -> i32 {
            self.offset
        }
    }

    struct MockStructure {
        components: Vec<(i32, i32)>,
    }

    impl DataType for MockStructure {}

    impl Composite for MockStructure {
        fn get_num_components(&self) -> i32 {
            self.components.len() as i32
        }
    }

    impl Structure for MockStructure {
        fn get_component(&self, ordinal: i32) -> Result<Box<dyn DataTypeComponent>, String> {
            self.components
                .iter()
                .find(|(o, _)| *o == ordinal)
                .map(|&(ordinal, offset)| -> Box<dyn DataTypeComponent> {
                    Box::new(MockDataTypeComponent { ordinal, offset })
                })
                .ok_or_else(|| "IndexOutOfBoundsException: ordinal out of bounds".to_string())
        }

        fn get_component_containing(&self, offset: i32) -> Option<Box<dyn DataTypeComponent>> {
            self.components
                .iter()
                .find(|(_, o)| *o == offset)
                .map(|&(ordinal, offset)| -> Box<dyn DataTypeComponent> {
                    Box::new(MockDataTypeComponent { ordinal, offset })
                })
        }

        fn insert_at_offset(
            &mut self,
            offset: i32,
            _data_type: Box<dyn DataType>,
            _length: i32,
        ) -> Result<Box<dyn DataTypeComponent>, String> {
            let ordinal = self.components.len() as i32;
            self.components.push((ordinal, offset));
            Ok(Box::new(MockDataTypeComponent { ordinal, offset }))
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let mut s = MockStructure {
            components: Vec::new(),
        };
        s.insert_at_offset(0, Box::new(MockDataType), 4).unwrap();
        s.insert_at_offset(4, Box::new(MockDataType), 4).unwrap();

        let dyn_struct: &dyn Structure = &s;
        assert_eq!(Structure::get_component(dyn_struct, 1).unwrap().get_offset(), 4);
        assert!(dyn_struct.get_component_at(4).is_some());
        assert!(dyn_struct.get_component_at(2).is_none());

        let dtm = MockDataTypeManager;
        let cloned = dyn_struct.clone_structure(&dtm);
        assert!(Structure::get_component(&cloned, 0).is_err());
    }

    #[test]
    fn bare_impl_stays_object_safe() {
        struct BareStructure;
        impl DataType for BareStructure {}
        impl Composite for BareStructure {}
        impl Structure for BareStructure {}

        let s = BareStructure;
        let dyn_struct: &dyn Structure = &s;
        assert!(Structure::get_component(dyn_struct, 0).is_err());
        assert!(dyn_struct.get_component_at(0).is_none());
        assert!(dyn_struct.get_components_containing(0).is_empty());
        assert!(dyn_struct.grow_structure(-1).is_err());
        assert!(dyn_struct.set_length(-1).is_err());
    }

    #[test]
    fn get_normalized_bitfield_offset_matches_documented_example() {
        // From the BitOffsetComparator javadoc example: storage-size 2 bytes, bit-offset 6,
        // bit-size 3.
        assert_eq!(get_normalized_bitfield_offset(0, 2, 3, 6, true), 7);
        assert_eq!(get_normalized_bitfield_offset(0, 2, 3, 6, false), 6);
    }

    #[test]
    fn get_normalized_bitfield_offset_forces_zero_length_alignment() {
        assert_eq!(get_normalized_bitfield_offset(0, 2, 0, 5, true), 8);
        assert_eq!(get_normalized_bitfield_offset(0, 2, 0, 5, false), 0);
    }
}
