use crate::program::model::data::bit_field_packing::BitFieldPacking;
use crate::program::seam_stubs::DataType;

/// Value returned by [`DataOrganization::get_absolute_max_alignment`] when the data
/// organization does not specifically limit the maximum alignment.
pub const NO_MAXIMUM_ALIGNMENT: i32 = 0;

/// Describes how primitive and composite data types are sized and aligned for a
/// particular target machine/compiler ABI.
///
/// Port of `ghidra.program.model.data.DataOrganization`.
pub trait DataOrganization {
    /// Returns `true` if data is stored in big-endian byte order.
    fn is_big_endian(&self) -> bool;

    /// Returns the size of a pointer data type in bytes.
    fn get_pointer_size(&self) -> i32;

    /// Returns the left shift amount for shifted-pointers. A value of zero
    /// indicates that shifted-pointers are not supported.
    fn get_pointer_shift(&self) -> i32;

    /// Returns `true` if the "char" type is signed.
    fn is_signed_char(&self) -> bool;

    /// Returns the size of a char primitive data type in bytes.
    fn get_char_size(&self) -> i32;

    /// Returns the size of a wide-char (wchar_t) primitive data type in bytes.
    fn get_wide_char_size(&self) -> i32;

    /// Returns the size of a short primitive data type in bytes.
    fn get_short_size(&self) -> i32;

    /// Returns the size of an int primitive data type in bytes.
    fn get_integer_size(&self) -> i32;

    /// Returns the size of a long primitive data type in bytes.
    fn get_long_size(&self) -> i32;

    /// Returns the size of a long long primitive data type in bytes.
    fn get_long_long_size(&self) -> i32;

    /// Returns the encoding size of a float primitive data type in bytes.
    fn get_float_size(&self) -> i32;

    /// Returns the encoding size of a double primitive data type in bytes.
    fn get_double_size(&self) -> i32;

    /// Returns the encoding size of a long double primitive data type in bytes.
    fn get_long_double_size(&self) -> i32;

    /// Returns the absolute maximum alignment allowed by this data organization,
    /// or [`NO_MAXIMUM_ALIGNMENT`] if the data organization isn't specifically limited.
    fn get_absolute_max_alignment(&self) -> i32;

    /// Returns the maximum useful alignment for the target machine.
    fn get_machine_alignment(&self) -> i32;

    /// Returns the default alignment to use for a data type that isn't a
    /// structure, union, array, pointer, or type definition, and whose size
    /// isn't in the size/alignment map.
    fn get_default_alignment(&self) -> i32;

    /// Returns the default alignment to use for a pointer that doesn't have size.
    fn get_default_pointer_alignment(&self) -> i32;

    /// Returns the primitive data alignment defined for the specified size. If no
    /// entry has been defined for the specified size, the alignment of the next
    /// smaller map entry is returned; the result will not exceed
    /// [`get_absolute_max_alignment`](DataOrganization::get_absolute_max_alignment).
    fn get_size_alignment(&self, size: i32) -> i32;

    /// Returns the composite bitfield packing information associated with this
    /// data organization.
    fn get_bit_field_packing(&self) -> Box<dyn BitFieldPacking>;

    /// Returns the number of sizes that have an alignment specified.
    fn get_size_alignment_count(&self) -> i32;

    /// Returns the ordered list of sizes that have an alignment specified.
    fn get_sizes(&self) -> Vec<i32>;

    /// Returns the best fitting integer C-type whose size is less-than-or-equal
    /// to the specified size. "long long" is returned for any size larger than
    /// "long long"; if `signed` is `false` the unsigned modifier is prepended.
    fn get_integer_c_type_approximation(&self, size: i32, signed: bool) -> String;

    /// Determines the alignment value for the indicated data type (i.e. how the
    /// data type gets aligned within other data types).
    fn get_alignment(&self, data_type: &dyn DataType) -> i32;

    /// Determines if this data organization is equivalent to another specific instance.
    fn is_equivalent(&self, other: &dyn DataOrganization) -> bool {
        if self.get_absolute_max_alignment() != other.get_absolute_max_alignment() {
            return false;
        }
        if self.is_big_endian() != other.is_big_endian() {
            return false;
        }
        if !self
            .get_bit_field_packing()
            .is_equivalent(&*other.get_bit_field_packing())
        {
            return false;
        }
        if self.get_char_size() != other.get_char_size()
            || self.get_wide_char_size() != other.get_wide_char_size()
        {
            return false;
        }
        if self.get_default_alignment() != other.get_default_alignment() {
            return false;
        }
        if self.get_default_pointer_alignment() != other.get_default_pointer_alignment() {
            return false;
        }
        if self.get_double_size() != other.get_double_size()
            || self.get_float_size() != other.get_float_size()
        {
            return false;
        }
        if self.get_integer_size() != other.get_integer_size()
            || self.get_long_long_size() != other.get_long_long_size()
        {
            return false;
        }
        if self.get_short_size() != other.get_short_size() {
            return false;
        }
        if self.get_long_size() != other.get_long_size()
            || self.get_long_double_size() != other.get_long_double_size()
        {
            return false;
        }
        if self.is_signed_char() != other.is_signed_char() {
            return false;
        }
        if self.get_machine_alignment() != other.get_machine_alignment() {
            return false;
        }
        if self.get_pointer_size() != other.get_pointer_size()
            || self.get_pointer_shift() != other.get_pointer_shift()
        {
            return false;
        }
        let keys = self.get_sizes();
        let other_keys = other.get_sizes();
        if keys != other_keys {
            return false;
        }
        for k in keys {
            if self.get_size_alignment(k) != other.get_size_alignment(k) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBitFieldPacking;

    impl BitFieldPacking for MockBitFieldPacking {
        fn use_ms_convention(&self) -> bool {
            false
        }

        fn is_type_alignment_enabled(&self) -> bool {
            true
        }

        fn get_zero_length_boundary(&self) -> i32 {
            0
        }
    }

    struct MockDataOrganization {
        big_endian: bool,
        pointer_size: i32,
        sizes: Vec<i32>,
    }

    impl DataOrganization for MockDataOrganization {
        fn is_big_endian(&self) -> bool {
            self.big_endian
        }

        fn get_pointer_size(&self) -> i32 {
            self.pointer_size
        }

        fn get_pointer_shift(&self) -> i32 {
            0
        }

        fn is_signed_char(&self) -> bool {
            true
        }

        fn get_char_size(&self) -> i32 {
            1
        }

        fn get_wide_char_size(&self) -> i32 {
            2
        }

        fn get_short_size(&self) -> i32 {
            2
        }

        fn get_integer_size(&self) -> i32 {
            4
        }

        fn get_long_size(&self) -> i32 {
            8
        }

        fn get_long_long_size(&self) -> i32 {
            8
        }

        fn get_float_size(&self) -> i32 {
            4
        }

        fn get_double_size(&self) -> i32 {
            8
        }

        fn get_long_double_size(&self) -> i32 {
            8
        }

        fn get_absolute_max_alignment(&self) -> i32 {
            NO_MAXIMUM_ALIGNMENT
        }

        fn get_machine_alignment(&self) -> i32 {
            8
        }

        fn get_default_alignment(&self) -> i32 {
            1
        }

        fn get_default_pointer_alignment(&self) -> i32 {
            8
        }

        fn get_size_alignment(&self, size: i32) -> i32 {
            size
        }

        fn get_bit_field_packing(&self) -> Box<dyn BitFieldPacking> {
            Box::new(MockBitFieldPacking)
        }

        fn get_size_alignment_count(&self) -> i32 {
            self.sizes.len() as i32
        }

        fn get_sizes(&self) -> Vec<i32> {
            self.sizes.clone()
        }

        fn get_integer_c_type_approximation(&self, size: i32, signed: bool) -> String {
            let base = if size <= 4 { "int" } else { "long long" };
            if signed {
                base.to_string()
            } else {
                format!("unsigned {base}")
            }
        }

        fn get_alignment(&self, _data_type: &dyn DataType) -> i32 {
            1
        }
    }

    fn little_endian_64() -> MockDataOrganization {
        MockDataOrganization {
            big_endian: false,
            pointer_size: 8,
            sizes: vec![1, 2, 4, 8],
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let org = little_endian_64();
        let dyn_org: &dyn DataOrganization = &org;
        assert_eq!(dyn_org.get_pointer_size(), 8);
        assert!(!dyn_org.is_big_endian());
    }

    #[test]
    fn is_equivalent_same_settings() {
        let a = little_endian_64();
        let b = little_endian_64();
        assert!(a.is_equivalent(&b));
    }

    #[test]
    fn is_equivalent_differs_on_endianness() {
        let a = little_endian_64();
        let mut b = little_endian_64();
        b.big_endian = true;
        assert!(!a.is_equivalent(&b));
    }

    #[test]
    fn is_equivalent_differs_on_sizes() {
        let a = little_endian_64();
        let mut b = little_endian_64();
        b.sizes = vec![1, 2, 4];
        assert!(!a.is_equivalent(&b));
    }

    #[test]
    fn get_integer_c_type_approximation_signed() {
        let org = little_endian_64();
        assert_eq!(org.get_integer_c_type_approximation(4, true), "int");
        assert_eq!(
            org.get_integer_c_type_approximation(8, false),
            "unsigned long long"
        );
    }
}
