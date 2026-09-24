//! Port of `ghidra.program.model.data.DataOrganizationImpl`: how primitive and composite data
//! types are sized and aligned for a particular target machine/compiler ABI.
//!
//! Java's `DataOrganization` interface has this one implementation, so callers take this
//! concrete type (the interface's `NO_MAXIMUM_ALIGNMENT` constant stays in
//! [`data_organization`](super::data_organization)).
//!
//! Persistence into a program's `DBStringMapAdapter` ([`DataOrganizationImpl::save`]/
//! [`DataOrganizationImpl::restore`]) is written against the
//! [`DbStringMapAdapter`](crate::program::seam_stubs::DbStringMapAdapter) seam, since that class is
//! not ported yet.

use std::collections::BTreeMap;
use std::io;

use crate::program::model::data::bit_field_packing::BitFieldPacking;
use crate::program::model::data::bit_field_packing_impl::BitFieldPackingImpl;
use crate::program::model::data::data_organization::NO_MAXIMUM_ALIGNMENT;
use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::language::Language;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{
    ATTRIB_ALIGNMENT, ATTRIB_SIGNED, ATTRIB_SIZE, ATTRIB_VALUE, ELEM_ABSOLUTE_MAX_ALIGNMENT,
    ELEM_BITFIELD_PACKING, ELEM_CHAR_SIZE, ELEM_CHAR_TYPE, ELEM_DATA_ORGANIZATION,
    ELEM_DEFAULT_ALIGNMENT, ELEM_DEFAULT_POINTER_ALIGNMENT, ELEM_DOUBLE_SIZE, ELEM_ENTRY,
    ELEM_FLOAT_SIZE, ELEM_INTEGER_SIZE, ELEM_LONG_DOUBLE_SIZE, ELEM_LONG_LONG_SIZE, ELEM_LONG_SIZE,
    ELEM_MACHINE_ALIGNMENT, ELEM_POINTER_SHIFT, ELEM_POINTER_SIZE, ELEM_SHORT_SIZE,
    ELEM_SIZE_ALIGNMENT_MAP, ELEM_WCHAR_SIZE,
};
use crate::program::seam_stubs::DbStringMapAdapter;
use crate::util::xml::spec_xml_utils::{decode_boolean_default, decode_int};
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_exception::XmlException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

// NOTE: it is important that these defaults match Decompiler defaults.
pub const DEFAULT_MACHINE_ALIGNMENT: i32 = 8;
pub const DEFAULT_DEFAULT_ALIGNMENT: i32 = 1;
pub const DEFAULT_DEFAULT_POINTER_ALIGNMENT: i32 = 4;
pub const DEFAULT_POINTER_SHIFT: i32 = 0;
pub const DEFAULT_POINTER_SIZE: i32 = 4;
pub const DEFAULT_CHAR_SIZE: i32 = 1;
pub const DEFAULT_CHAR_IS_SIGNED: bool = true;
pub const DEFAULT_WIDE_CHAR_SIZE: i32 = 2;
pub const DEFAULT_SHORT_SIZE: i32 = 2;
pub const DEFAULT_INT_SIZE: i32 = 4;
pub const DEFAULT_LONG_SIZE: i32 = 4;
pub const DEFAULT_LONG_LONG_SIZE: i32 = 8;
/// Encoding size only.
pub const DEFAULT_FLOAT_SIZE: i32 = 4;
/// Encoding size only.
pub const DEFAULT_DOUBLE_SIZE: i32 = 8;
/// Encoding size only.
pub const DEFAULT_LONG_DOUBLE_SIZE: i32 = 8;

const BIG_ENDIAN_NAME: &str = "big_endian";
const SIGNED_CHAR_TYPE_NAME: &str = "signed_char_type";

/// Size and alignment rules for primitive and composite data types.
///
/// Port of `ghidra.program.model.data.DataOrganizationImpl` (and its `DataOrganization`
/// interface). Java's `equals`/`hashCode` are the derived `PartialEq`/`Hash`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DataOrganizationImpl {
    absolute_max_alignment: i32,
    machine_alignment: i32,
    default_alignment: i32,
    default_pointer_alignment: i32,
    pointer_shift: i32,
    pointer_size: i32,
    char_size: i32,
    is_signed_char: bool,
    wide_char_size: i32,
    short_size: i32,
    integer_size: i32,
    long_size: i32,
    long_long_size: i32,
    float_size: i32,
    double_size: i32,
    long_double_size: i32,
    big_endian: bool,
    bit_field_packing: BitFieldPackingImpl,
    /// Primitive size to alignment, ordered by size (Java's `TreeMap`).
    size_alignment_map: BTreeMap<i32, i32>,
}

impl DataOrganizationImpl {
    /// Port of the private no-arg constructor: every field at its default, empty size map.
    fn new() -> Self {
        DataOrganizationImpl {
            absolute_max_alignment: NO_MAXIMUM_ALIGNMENT,
            machine_alignment: DEFAULT_MACHINE_ALIGNMENT,
            default_alignment: DEFAULT_DEFAULT_ALIGNMENT,
            default_pointer_alignment: DEFAULT_DEFAULT_POINTER_ALIGNMENT,
            pointer_shift: DEFAULT_POINTER_SHIFT,
            pointer_size: DEFAULT_POINTER_SIZE,
            char_size: DEFAULT_CHAR_SIZE,
            is_signed_char: DEFAULT_CHAR_IS_SIGNED,
            wide_char_size: DEFAULT_WIDE_CHAR_SIZE,
            short_size: DEFAULT_SHORT_SIZE,
            integer_size: DEFAULT_INT_SIZE,
            long_size: DEFAULT_LONG_SIZE,
            long_long_size: DEFAULT_LONG_LONG_SIZE,
            float_size: DEFAULT_FLOAT_SIZE,
            double_size: DEFAULT_DOUBLE_SIZE,
            long_double_size: DEFAULT_LONG_DOUBLE_SIZE,
            big_endian: false,
            bit_field_packing: BitFieldPackingImpl::new(),
            size_alignment_map: BTreeMap::new(),
        }
    }

    /// A default data organization, optionally seeded with `language`'s default pointer size and
    /// endianness. The size/alignment map starts as 1->1, 2->2, 4->4, 8->8.
    ///
    /// Port of `DataOrganizationImpl.getDefaultOrganization(Language)` (and the no-argument
    /// overload, which passes `null`).
    pub fn get_default_organization(language: Option<&dyn Language>) -> Self {
        let mut data_organization = DataOrganizationImpl::new();
        data_organization.set_size_alignment(1, 1);
        data_organization.set_size_alignment(2, 2);
        data_organization.set_size_alignment(4, 4);
        data_organization.set_size_alignment(8, 8);
        if let Some(language) = language {
            data_organization.set_pointer_size(language.get_default_space().pointer_size());
            data_organization.set_big_endian(language.is_big_endian());
        }
        data_organization
    }

    /// True if data is stored in big-endian byte order.
    pub fn is_big_endian(&self) -> bool {
        self.big_endian
    }

    /// The size of a pointer data type in bytes.
    pub fn get_pointer_size(&self) -> i32 {
        self.pointer_size
    }

    /// The left shift amount for shifted pointers; 0 if they are not supported.
    pub fn get_pointer_shift(&self) -> i32 {
        self.pointer_shift
    }

    /// True if the "char" type is signed.
    pub fn is_signed_char(&self) -> bool {
        self.is_signed_char
    }

    /// The size of a char in bytes.
    pub fn get_char_size(&self) -> i32 {
        self.char_size
    }

    /// The size of a wide-char (`wchar_t`) in bytes.
    pub fn get_wide_char_size(&self) -> i32 {
        self.wide_char_size
    }

    /// The size of a short in bytes.
    pub fn get_short_size(&self) -> i32 {
        self.short_size
    }

    /// The size of an int in bytes.
    pub fn get_integer_size(&self) -> i32 {
        self.integer_size
    }

    /// The size of a long in bytes.
    pub fn get_long_size(&self) -> i32 {
        self.long_size
    }

    /// The size of a long long in bytes.
    pub fn get_long_long_size(&self) -> i32 {
        self.long_long_size
    }

    /// The encoding size of a float in bytes.
    pub fn get_float_size(&self) -> i32 {
        self.float_size
    }

    /// The encoding size of a double in bytes.
    pub fn get_double_size(&self) -> i32 {
        self.double_size
    }

    /// The encoding size of a long double in bytes.
    pub fn get_long_double_size(&self) -> i32 {
        self.long_double_size
    }

    /// The bitfield packing rules.
    pub fn get_bit_field_packing(&self) -> &BitFieldPackingImpl {
        &self.bit_field_packing
    }

    /// Set data endianness.
    pub fn set_big_endian(&mut self, big_endian: bool) {
        self.big_endian = big_endian;
    }

    /// Set the size of a pointer data type in bytes.
    pub fn set_pointer_size(&mut self, pointer_size: i32) {
        self.pointer_size = pointer_size;
    }

    /// Set the left shift amount for shifted pointers.
    pub fn set_pointer_shift(&mut self, pointer_shift: i32) {
        self.pointer_shift = pointer_shift;
    }

    /// Set whether the "char" type is signed.
    pub fn set_char_is_signed(&mut self, signed: bool) {
        self.is_signed_char = signed;
    }

    /// Set the size of a char in bytes.
    pub fn set_char_size(&mut self, char_size: i32) {
        self.char_size = char_size;
    }

    /// Set the size of a wide-char in bytes.
    pub fn set_wide_char_size(&mut self, wide_char_size: i32) {
        self.wide_char_size = wide_char_size;
    }

    /// Set the size of a short; grows int to at least this size.
    ///
    /// Port of `DataOrganizationImpl.setShortSize`.
    pub fn set_short_size(&mut self, short_size: i32) {
        self.short_size = short_size;
        if self.integer_size < short_size {
            self.set_integer_size(short_size);
        }
    }

    /// Set the size of an int; grows long / shrinks short to keep `short <= int <= long`.
    ///
    /// Port of `DataOrganizationImpl.setIntegerSize`.
    pub fn set_integer_size(&mut self, integer_size: i32) {
        self.integer_size = integer_size;
        if self.long_size < integer_size {
            self.set_long_size(integer_size);
        }
        if self.short_size > integer_size {
            self.set_short_size(integer_size);
        }
    }

    /// Set the size of a long; grows long long / shrinks int to keep `int <= long <= long long`.
    ///
    /// Port of `DataOrganizationImpl.setLongSize`.
    pub fn set_long_size(&mut self, long_size: i32) {
        self.long_size = long_size;
        if self.long_long_size < long_size {
            self.set_long_long_size(long_size);
        }
        if self.integer_size > long_size {
            self.set_integer_size(long_size);
        }
    }

    /// Set the size of a long long; shrinks long to at most this size.
    ///
    /// Port of `DataOrganizationImpl.setLongLongSize`.
    pub fn set_long_long_size(&mut self, long_long_size: i32) {
        self.long_long_size = long_long_size;
        if self.long_size > long_long_size {
            self.set_long_size(long_long_size);
        }
    }

    /// Set the encoding size of a float; grows double to at least this size.
    ///
    /// Port of `DataOrganizationImpl.setFloatSize`.
    pub fn set_float_size(&mut self, float_size: i32) {
        self.float_size = float_size;
        if self.double_size < float_size {
            self.set_double_size(float_size);
        }
    }

    /// Set the encoding size of a double; grows long double / shrinks float to keep
    /// `float <= double <= long double`.
    ///
    /// Port of `DataOrganizationImpl.setDoubleSize`.
    pub fn set_double_size(&mut self, double_size: i32) {
        self.double_size = double_size;
        if self.long_double_size < double_size {
            self.set_long_double_size(double_size);
        }
        if self.float_size > double_size {
            self.set_float_size(double_size);
        }
    }

    /// Set the encoding size of a long double; shrinks double to at most this size.
    ///
    /// Port of `DataOrganizationImpl.setLongDoubleSize`.
    pub fn set_long_double_size(&mut self, long_double_size: i32) {
        self.long_double_size = long_double_size;
        if self.double_size > long_double_size {
            self.set_double_size(long_double_size);
        }
    }

    /// The maximum alignment any data type may have, or `NO_MAXIMUM_ALIGNMENT`.
    pub fn get_absolute_max_alignment(&self) -> i32 {
        self.absolute_max_alignment
    }

    /// The machine alignment: the largest alignment a data type can have.
    pub fn get_machine_alignment(&self) -> i32 {
        self.machine_alignment
    }

    /// The alignment of a data type with no other specified alignment.
    pub fn get_default_alignment(&self) -> i32 {
        self.default_alignment
    }

    /// The alignment of a pointer whose size has no size/alignment entry.
    pub fn get_default_pointer_alignment(&self) -> i32 {
        self.default_pointer_alignment
    }

    /// Set the maximum alignment any data type may have.
    pub fn set_absolute_max_alignment(&mut self, absolute_max_alignment: i32) {
        self.absolute_max_alignment = absolute_max_alignment;
    }

    /// Set the machine alignment.
    pub fn set_machine_alignment(&mut self, machine_alignment: i32) {
        self.machine_alignment = machine_alignment;
    }

    /// Set the default alignment.
    pub fn set_default_alignment(&mut self, default_alignment: i32) {
        self.default_alignment = default_alignment;
    }

    /// Set the default pointer alignment.
    pub fn set_default_pointer_alignment(&mut self, default_pointer_alignment: i32) {
        self.default_pointer_alignment = default_pointer_alignment;
    }

    /// The alignment for a primitive of `size` bytes: the entry for the largest mapped size not
    /// above `size` (else the default alignment), capped at the absolute maximum alignment.
    ///
    /// Port of `DataOrganizationImpl.getSizeAlignment`.
    pub fn get_size_alignment(&self, size: i32) -> i32 {
        let alignment = self
            .size_alignment_map
            .range(..=size)
            .next_back()
            .map_or(self.default_alignment, |(_, &alignment)| alignment);
        if self.absolute_max_alignment != 0 {
            return alignment.min(self.absolute_max_alignment);
        }
        alignment
    }

    /// Set the alignment for primitives of `size` bytes.
    pub fn set_size_alignment(&mut self, size: i32, alignment: i32) {
        self.size_alignment_map.insert(size, alignment);
    }

    /// Set the bitfield packing rules.
    pub fn set_bit_field_packing(&mut self, bit_field_packing: BitFieldPackingImpl) {
        self.bit_field_packing = bit_field_packing;
    }

    /// Remove every size/alignment entry.
    pub fn clear_size_alignment_map(&mut self) {
        self.size_alignment_map.clear();
    }

    /// The number of size/alignment entries.
    pub fn get_size_alignment_count(&self) -> i32 {
        self.size_alignment_map.len() as i32
    }

    /// The sizes with an alignment entry, ascending.
    pub fn get_sizes(&self) -> Vec<i32> {
        self.size_alignment_map.keys().copied().collect()
    }

    /// The C integer type name approximating an integer of `size` bytes.
    ///
    /// Port of `DataOrganizationImpl.getIntegerCTypeApproximation`.
    pub fn get_integer_c_type_approximation(&self, size: i32, signed: bool) -> String {
        let ctype = if size <= 1 {
            "char"
        } else if size <= self.get_short_size() && self.get_short_size() != self.get_integer_size() {
            "short"
        } else if size <= self.get_integer_size() {
            "int"
        } else if size <= self.get_long_size() {
            "long"
        } else {
            "long long"
        };
        if signed {
            ctype.to_string()
        } else {
            format!("unsigned {ctype}")
        }
    }

    /// The alignment of `data_type` within other data types.
    ///
    /// Port of `DataOrganizationImpl.getAlignment(DataType)`.
    pub fn get_alignment(&self, data_type: &dyn DataType) -> i32 {
        let dt_size = data_type.get_aligned_length();
        if data_type.is_dynamic_type() || data_type.is_factory_type() || dt_size <= 0 {
            return 1;
        }
        // Typedef is aligned the same as its underlying data type is aligned.
        if let Some(base) = data_type.typedef_base_data_type() {
            return self.get_alignment(base.as_ref());
        }
        // Array alignment is the alignment of its element data type.
        if let Some(array) = data_type.as_array() {
            return self.get_alignment(array.get_data_type().as_ref());
        }
        // Composites are responsible for computing their own alignment.
        if let Some(composite) = data_type.as_composite() {
            return composite.get_alignment();
        }
        // Bit field alignment must be determined within the context of the containing structure.
        if let Some(bit_field) = data_type.as_bit_field() {
            return self.get_alignment(bit_field.get_base_data_type().as_ref());
        }
        // If pointer size not found in size alignment map use default pointer alignment.
        if !self.size_alignment_map.contains_key(&dt_size) && data_type.is_pointer() {
            return self.get_default_pointer_alignment();
        }
        // Otherwise get the alignment based on the size.
        self.get_size_alignment(dt_size)
    }

    /// Determine if this data organization is equivalent to another: same settings, bitfield
    /// packing and size/alignment entries.
    ///
    /// Port of the default `DataOrganization.isEquivalent(DataOrganization)`.
    pub fn is_equivalent(&self, obj: &DataOrganizationImpl) -> bool {
        if self.get_absolute_max_alignment() != obj.get_absolute_max_alignment() {
            return false;
        }
        if self.is_big_endian() != obj.is_big_endian() {
            return false;
        }
        if !self.get_bit_field_packing().is_equivalent(obj.get_bit_field_packing()) {
            return false;
        }
        if self.get_char_size() != obj.get_char_size() || self.get_wide_char_size() != obj.get_wide_char_size() {
            return false;
        }
        if self.get_default_alignment() != obj.get_default_alignment() {
            return false;
        }
        if self.get_default_pointer_alignment() != obj.get_default_pointer_alignment() {
            return false;
        }
        if self.get_double_size() != obj.get_double_size() || self.get_float_size() != obj.get_float_size() {
            return false;
        }
        if self.get_integer_size() != obj.get_integer_size() || self.get_long_long_size() != obj.get_long_long_size() {
            return false;
        }
        if self.get_short_size() != obj.get_short_size() {
            return false;
        }
        if self.get_long_size() != obj.get_long_size() || self.get_long_double_size() != obj.get_long_double_size() {
            return false;
        }
        if self.is_signed_char() != obj.is_signed_char() {
            return false;
        }
        if self.get_machine_alignment() != obj.get_machine_alignment() {
            return false;
        }
        if self.get_pointer_size() != obj.get_pointer_size() || self.get_pointer_shift() != obj.get_pointer_shift() {
            return false;
        }
        let keys = self.get_sizes();
        if keys != obj.get_sizes() {
            return false;
        }
        keys.iter().all(|&k| self.get_size_alignment(k) == obj.get_size_alignment(k))
    }

    /// Save the non-default settings of `data_org` into `data_map` under `key_prefix`,
    /// replacing anything previously stored under that prefix.
    ///
    /// Port of `DataOrganizationImpl.save(DataOrganization, DBStringMapAdapter, String)`.
    ///
    /// # Errors
    /// Returns an error if the map cannot be read or written.
    pub fn save(data_org: &DataOrganizationImpl, data_map: &mut dyn DbStringMapAdapter, key_prefix: &str) -> io::Result<()> {
        for key in data_map.key_set()? {
            if key.starts_with(key_prefix) {
                data_map.delete(&key)?;
            }
        }
        let put_int = |data_map: &mut dyn DbStringMapAdapter, name: &str, value: i32, default: i32| -> io::Result<()> {
            if value != default {
                data_map.put(&format!("{key_prefix}{name}"), &value.to_string())?;
            }
            Ok(())
        };
        if data_org.is_big_endian() {
            // default is little-endian
            data_map.put(&format!("{key_prefix}{BIG_ENDIAN_NAME}"), "true")?;
        }
        put_int(data_map, ELEM_ABSOLUTE_MAX_ALIGNMENT.name, data_org.get_absolute_max_alignment(), NO_MAXIMUM_ALIGNMENT)?;
        put_int(data_map, ELEM_MACHINE_ALIGNMENT.name, data_org.get_machine_alignment(), DEFAULT_MACHINE_ALIGNMENT)?;
        put_int(data_map, ELEM_DEFAULT_ALIGNMENT.name, data_org.get_default_alignment(), DEFAULT_DEFAULT_ALIGNMENT)?;
        put_int(
            data_map,
            ELEM_DEFAULT_POINTER_ALIGNMENT.name,
            data_org.get_default_pointer_alignment(),
            DEFAULT_DEFAULT_POINTER_ALIGNMENT,
        )?;
        put_int(data_map, ELEM_POINTER_SIZE.name, data_org.get_pointer_size(), DEFAULT_POINTER_SIZE)?;
        put_int(data_map, ELEM_POINTER_SHIFT.name, data_org.get_pointer_shift(), DEFAULT_POINTER_SHIFT)?;
        if !data_org.is_signed_char() {
            data_map.put(&format!("{key_prefix}{SIGNED_CHAR_TYPE_NAME}"), "false")?;
        }
        put_int(data_map, ELEM_CHAR_SIZE.name, data_org.get_char_size(), DEFAULT_CHAR_SIZE)?;
        put_int(data_map, ELEM_WCHAR_SIZE.name, data_org.get_wide_char_size(), DEFAULT_WIDE_CHAR_SIZE)?;
        put_int(data_map, ELEM_SHORT_SIZE.name, data_org.get_short_size(), DEFAULT_SHORT_SIZE)?;
        put_int(data_map, ELEM_INTEGER_SIZE.name, data_org.get_integer_size(), DEFAULT_INT_SIZE)?;
        put_int(data_map, ELEM_LONG_SIZE.name, data_org.get_long_size(), DEFAULT_LONG_SIZE)?;
        put_int(data_map, ELEM_LONG_LONG_SIZE.name, data_org.get_long_long_size(), DEFAULT_LONG_LONG_SIZE)?;
        put_int(data_map, ELEM_FLOAT_SIZE.name, data_org.get_float_size(), DEFAULT_FLOAT_SIZE)?;
        put_int(data_map, ELEM_DOUBLE_SIZE.name, data_org.get_double_size(), DEFAULT_DOUBLE_SIZE)?;
        put_int(data_map, ELEM_LONG_DOUBLE_SIZE.name, data_org.get_long_double_size(), DEFAULT_LONG_DOUBLE_SIZE)?;
        for size in data_org.get_sizes() {
            let key = format!("{key_prefix}{}.{size}", ELEM_SIZE_ALIGNMENT_MAP.name);
            data_map.put(&key, &data_org.get_size_alignment(size).to_string())?;
        }
        BitFieldPackingImpl::save(
            data_org.get_bit_field_packing(),
            data_map,
            &format!("{key_prefix}{}.", ELEM_BITFIELD_PACKING.name),
        )
    }

    /// Restore a data organization saved by [`save`](Self::save), or `None` if `data_map` holds
    /// nothing under `key_prefix`.
    ///
    /// Port of `DataOrganizationImpl.restore(DBStringMapAdapter, String)`.
    ///
    /// # Errors
    /// Returns an error if the map cannot be read.
    pub fn restore(data_map: &dyn DbStringMapAdapter, key_prefix: &str) -> io::Result<Option<DataOrganizationImpl>> {
        let keys = data_map.key_set()?;
        if !keys.iter().any(|key| key.starts_with(key_prefix)) {
            return Ok(None);
        }
        let mut data_org = DataOrganizationImpl::new();
        let get_int = |name: &str, default: i32| data_map.get_int(&format!("{key_prefix}{name}"), default);
        data_org.big_endian = data_map.get_boolean(&format!("{key_prefix}{BIG_ENDIAN_NAME}"), false)?;
        data_org.absolute_max_alignment = get_int(ELEM_ABSOLUTE_MAX_ALIGNMENT.name, data_org.absolute_max_alignment)?;
        data_org.machine_alignment = get_int(ELEM_MACHINE_ALIGNMENT.name, data_org.machine_alignment)?;
        data_org.default_alignment = get_int(ELEM_DEFAULT_ALIGNMENT.name, data_org.default_alignment)?;
        data_org.default_pointer_alignment = get_int(ELEM_DEFAULT_POINTER_ALIGNMENT.name, data_org.default_pointer_alignment)?;
        data_org.pointer_size = get_int(ELEM_POINTER_SIZE.name, data_org.pointer_size)?;
        data_org.pointer_shift = get_int(ELEM_POINTER_SHIFT.name, data_org.pointer_shift)?;
        data_org.is_signed_char = data_map.get_boolean(&format!("{key_prefix}{SIGNED_CHAR_TYPE_NAME}"), data_org.is_signed_char)?;
        data_org.char_size = get_int(ELEM_CHAR_SIZE.name, data_org.char_size)?;
        data_org.wide_char_size = get_int(ELEM_WCHAR_SIZE.name, data_org.wide_char_size)?;
        data_org.short_size = get_int(ELEM_SHORT_SIZE.name, data_org.short_size)?;
        data_org.integer_size = get_int(ELEM_INTEGER_SIZE.name, data_org.integer_size)?;
        data_org.long_size = get_int(ELEM_LONG_SIZE.name, data_org.long_size)?;
        data_org.long_long_size = get_int(ELEM_LONG_LONG_SIZE.name, data_org.long_long_size)?;
        data_org.float_size = get_int(ELEM_FLOAT_SIZE.name, data_org.float_size)?;
        data_org.double_size = get_int(ELEM_DOUBLE_SIZE.name, data_org.double_size)?;
        data_org.long_double_size = get_int(ELEM_LONG_DOUBLE_SIZE.name, data_org.long_double_size)?;
        let alignment_map_key_prefix = format!("{key_prefix}{}.", ELEM_SIZE_ALIGNMENT_MAP.name);
        let mut first_entry = true;
        for key in &keys {
            let Some(size_str) = key.strip_prefix(&alignment_map_key_prefix) else {
                continue;
            };
            // Java ignores entries whose size or alignment fails to parse
            let (Ok(size), Some(Ok(alignment))) =
                (size_str.parse::<i32>(), data_map.get(key)?.map(|v| v.parse::<i32>()))
            else {
                continue;
            };
            if first_entry {
                data_org.size_alignment_map.clear();
                first_entry = false;
            }
            data_org.size_alignment_map.insert(size, alignment);
        }
        data_org.bit_field_packing =
            BitFieldPackingImpl::restore(data_map, &format!("{key_prefix}{}.", ELEM_BITFIELD_PACKING.name))?;
        Ok(Some(data_org))
    }

    /// Encode this data organization as a `<data_organization>` element (non-default settings
    /// only, plus the pointer size).
    ///
    /// Port of `DataOrganizationImpl.encode(Encoder)`.
    ///
    /// # Errors
    /// Returns an error for problems writing to the stream.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        fn value_element(encoder: &mut dyn Encoder, elem: crate::program::model::pcode::ids::ElementId, value: i32) -> io::Result<()> {
            encoder.open_element(elem)?;
            encoder.write_signed_integer(ATTRIB_VALUE, value as i64)?;
            encoder.close_element(elem)
        }
        encoder.open_element(ELEM_DATA_ORGANIZATION)?;
        // NOTE: endianness intentionally omitted from output
        if self.absolute_max_alignment != NO_MAXIMUM_ALIGNMENT {
            value_element(encoder, ELEM_ABSOLUTE_MAX_ALIGNMENT, self.absolute_max_alignment)?;
        }
        if self.machine_alignment != DEFAULT_MACHINE_ALIGNMENT {
            value_element(encoder, ELEM_MACHINE_ALIGNMENT, self.machine_alignment)?;
        }
        if self.default_alignment != DEFAULT_DEFAULT_ALIGNMENT {
            value_element(encoder, ELEM_DEFAULT_ALIGNMENT, self.default_alignment)?;
        }
        if self.default_pointer_alignment != DEFAULT_DEFAULT_POINTER_ALIGNMENT {
            value_element(encoder, ELEM_DEFAULT_POINTER_ALIGNMENT, self.default_pointer_alignment)?;
        }
        // Always output pointer size
        value_element(encoder, ELEM_POINTER_SIZE, self.pointer_size)?;
        if self.pointer_shift != DEFAULT_POINTER_SHIFT {
            value_element(encoder, ELEM_POINTER_SHIFT, self.pointer_shift)?;
        }
        if self.is_signed_char != DEFAULT_CHAR_IS_SIGNED {
            encoder.open_element(ELEM_CHAR_TYPE)?;
            encoder.write_bool(ATTRIB_SIGNED, self.is_signed_char)?;
            encoder.close_element(ELEM_CHAR_TYPE)?;
        }
        if self.char_size != DEFAULT_CHAR_SIZE {
            value_element(encoder, ELEM_CHAR_SIZE, self.char_size)?;
        }
        if self.wide_char_size != DEFAULT_WIDE_CHAR_SIZE {
            value_element(encoder, ELEM_WCHAR_SIZE, self.wide_char_size)?;
        }
        if self.short_size != DEFAULT_SHORT_SIZE {
            value_element(encoder, ELEM_SHORT_SIZE, self.short_size)?;
        }
        if self.integer_size != DEFAULT_INT_SIZE {
            value_element(encoder, ELEM_INTEGER_SIZE, self.integer_size)?;
        }
        if self.long_size != DEFAULT_LONG_SIZE {
            value_element(encoder, ELEM_LONG_SIZE, self.long_size)?;
        }
        if self.long_long_size != DEFAULT_LONG_LONG_SIZE {
            value_element(encoder, ELEM_LONG_LONG_SIZE, self.long_long_size)?;
        }
        if self.float_size != DEFAULT_FLOAT_SIZE {
            value_element(encoder, ELEM_FLOAT_SIZE, self.float_size)?;
        }
        if self.double_size != DEFAULT_DOUBLE_SIZE {
            value_element(encoder, ELEM_DOUBLE_SIZE, self.double_size)?;
        }
        if self.long_double_size != DEFAULT_LONG_DOUBLE_SIZE {
            value_element(encoder, ELEM_LONG_DOUBLE_SIZE, self.long_double_size)?;
        }
        if !self.size_alignment_map.is_empty() {
            encoder.open_element(ELEM_SIZE_ALIGNMENT_MAP)?;
            for (&size, &alignment) in &self.size_alignment_map {
                encoder.open_element(ELEM_ENTRY)?;
                encoder.write_signed_integer(ATTRIB_SIZE, size as i64)?;
                encoder.write_signed_integer(ATTRIB_ALIGNMENT, alignment as i64)?;
                encoder.close_element(ELEM_ENTRY)?;
            }
            encoder.close_element(ELEM_SIZE_ALIGNMENT_MAP)?;
        }
        self.bit_field_packing.encode(encoder)?;
        encoder.close_element(ELEM_DATA_ORGANIZATION)
    }

    /// Restore settings from a `<data_organization>` element. The XML is designed to override
    /// existing settings (typically from [`get_default_organization`](Self::get_default_organization)),
    /// not to fully repopulate them; sizes are stored without the setters' cascading.
    ///
    /// Port of `DataOrganizationImpl.restoreXml(XmlPullParser)`.
    ///
    /// # Errors
    /// Returns an error if the parser is out of sync with the expected element structure.
    pub(crate) fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), XmlException> {
        // NOTE: endianness intentionally omitted from XML
        parser.start(&[])?;
        while parser.peek().is_start() {
            let name = parser.peek().get_name().to_string();
            if name == ELEM_CHAR_TYPE.name {
                let subel = parser.start(&[])?;
                let bool_str = subel.get_attribute(ATTRIB_SIGNED.name).unwrap_or_default();
                self.is_signed_char = decode_boolean_default(&bool_str, self.is_signed_char);
                parser.end_matching(&subel)?;
                continue;
            } else if name == ELEM_BITFIELD_PACKING.name {
                self.bit_field_packing.restore_xml(parser)?;
                continue;
            } else if name == ELEM_SIZE_ALIGNMENT_MAP.name {
                let subel = parser.start(&[])?;
                while parser.peek().is_start() {
                    let subsubel = parser.start(&[])?;
                    let size = decode_int(subsubel.get_attribute(ATTRIB_SIZE.name).as_deref());
                    let alignment = decode_int(subsubel.get_attribute(ATTRIB_ALIGNMENT.name).as_deref());
                    self.size_alignment_map.insert(size, alignment);
                    parser.end_matching(&subsubel)?;
                }
                parser.end_matching(&subel)?;
                continue;
            }
            let subel = parser.start(&[])?;
            let value = decode_int(subel.get_attribute(ATTRIB_VALUE.name).as_deref());
            if name == ELEM_ABSOLUTE_MAX_ALIGNMENT.name {
                self.absolute_max_alignment = value;
            } else if name == ELEM_MACHINE_ALIGNMENT.name {
                self.machine_alignment = value;
            } else if name == ELEM_DEFAULT_ALIGNMENT.name {
                self.default_alignment = value;
            } else if name == ELEM_DEFAULT_POINTER_ALIGNMENT.name {
                self.default_pointer_alignment = value;
            } else if name == ELEM_POINTER_SIZE.name {
                self.pointer_size = value;
            } else if name == ELEM_POINTER_SHIFT.name {
                self.pointer_shift = value;
            } else if name == ELEM_CHAR_SIZE.name {
                self.char_size = value;
            } else if name == ELEM_WCHAR_SIZE.name {
                self.wide_char_size = value;
            } else if name == ELEM_SHORT_SIZE.name {
                self.short_size = value;
            } else if name == ELEM_INTEGER_SIZE.name {
                self.integer_size = value;
            } else if name == ELEM_LONG_SIZE.name {
                self.long_size = value;
            } else if name == ELEM_LONG_LONG_SIZE.name {
                self.long_long_size = value;
            } else if name == ELEM_FLOAT_SIZE.name {
                self.float_size = value;
            } else if name == ELEM_DOUBLE_SIZE.name {
                self.double_size = value;
            } else if name == ELEM_LONG_DOUBLE_SIZE.name {
                self.long_double_size = value;
            }
            parser.end_matching(&subel)?;
        }
        parser.end()?;
        Ok(())
    }
}

/// The first offset at or after `minimum_offset` with the given `alignment`; `minimum_offset`
/// itself for a non-positive alignment.
///
/// Port of the static `DataOrganizationImpl.getAlignedOffset`.
pub fn get_aligned_offset(alignment: i32, minimum_offset: i32) -> i32 {
    if alignment <= 0 {
        return minimum_offset;
    }
    if (alignment & (alignment - 1)) == 0 {
        return alignment + ((minimum_offset - 1) & !(alignment - 1));
    }
    let offcut = minimum_offset % alignment;
    let adj = if offcut != 0 { alignment - offcut } else { 0 };
    minimum_offset + adj
}

/// Port of the static `DataOrganizationImpl.getLeastCommonMultiple`.
pub fn get_least_common_multiple(value1: i32, value2: i32) -> i32 {
    let gcd = get_greatest_common_denominator(value1, value2);
    if gcd != 0 {
        (value1 / gcd) * value2
    } else {
        0
    }
}

/// Port of the static `DataOrganizationImpl.getGreatestCommonDenominator`.
pub fn get_greatest_common_denominator(value1: i32, value2: i32) -> i32 {
    if value2 != 0 {
        get_greatest_common_denominator(value2, value1 % value2)
    } else {
        value1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::array::Array;
    use crate::program::model::data::composite::Composite;
    use crate::program::model::lang::cspec_test_support::{parser, TestCspecLanguage};
    use crate::program::seam_stubs::BitFieldDataType;
    use std::collections::HashMap;

    /// The `<data_organization>` of `x86-64-gcc.cspec`.
    const X86_64_GCC: &str = r#"<data_organization>
        <absolute_max_alignment value="0" />
        <machine_alignment value="2" />
        <default_alignment value="1" />
        <default_pointer_alignment value="8" />
        <pointer_size value="8" />
        <wchar_size value="4" />
        <short_size value="2" />
        <integer_size value="4" />
        <long_size value="8" />
        <long_long_size value="8" />
        <float_size value="4" />
        <double_size value="8" />
        <long_double_size value="16" />
        <size_alignment_map>
          <entry size="1" alignment="1" />
          <entry size="2" alignment="2" />
          <entry size="4" alignment="4" />
          <entry size="8" alignment="8" />
          <entry size="16" alignment="16" />
        </size_alignment_map>
        <bitfield_packing>
          <use_MS_convention value="true"/>
        </bitfield_packing>
      </data_organization>"#;

    fn x86_64_gcc() -> DataOrganizationImpl {
        let mut org = DataOrganizationImpl::get_default_organization(None);
        org.restore_xml(&mut parser(X86_64_GCC)).unwrap();
        org
    }

    struct PlainDataType {
        length: i32,
    }
    impl DataType for PlainDataType {
        fn get_length(&self) -> i32 {
            self.length
        }
    }

    struct DynamicDataType;
    impl DataType for DynamicDataType {
        fn get_length(&self) -> i32 {
            16
        }
        fn is_dynamic_type(&self) -> bool {
            true
        }
    }

    struct PointerDataType {
        length: i32,
    }
    impl DataType for PointerDataType {
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_pointer(&self) -> bool {
            true
        }
    }

    struct TypedefDataType {
        base: i32,
    }
    impl DataType for TypedefDataType {
        fn get_length(&self) -> i32 {
            4
        }
        fn typedef_base_data_type(&self) -> Option<Box<dyn DataType>> {
            Some(Box::new(PlainDataType { length: self.base }))
        }
    }

    struct ArrayDataType {
        element_length: i32,
    }
    impl DataType for ArrayDataType {
        fn get_length(&self) -> i32 {
            self.element_length * 3
        }
        fn as_array(&self) -> Option<&dyn Array> {
            Some(self)
        }
    }
    impl Array for ArrayDataType {
        fn get_num_elements(&self) -> i32 {
            3
        }
        fn get_element_length(&self) -> i32 {
            self.element_length
        }
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(PlainDataType {
                length: self.element_length,
            })
        }
    }

    struct CompositeDataType {
        alignment: i32,
    }
    impl DataType for CompositeDataType {
        fn get_length(&self) -> i32 {
            12
        }
        fn get_alignment(&self) -> i32 {
            self.alignment
        }
        fn as_composite(&self) -> Option<&dyn Composite> {
            Some(self)
        }
    }
    impl Composite for CompositeDataType {}

    struct BitFieldMarker {
        base_length: i32,
    }
    impl BitFieldDataType for BitFieldMarker {
        fn get_base_data_type(&self) -> Box<dyn DataType> {
            Box::new(PlainDataType {
                length: self.base_length,
            })
        }
    }

    struct BitFieldDataTypeMock {
        marker: BitFieldMarker,
    }
    impl DataType for BitFieldDataTypeMock {
        fn get_length(&self) -> i32 {
            1
        }
        fn as_bit_field(&self) -> Option<&dyn BitFieldDataType> {
            Some(&self.marker)
        }
    }

    #[test]
    fn default_organization_matches_java() {
        let org = DataOrganizationImpl::get_default_organization(None);
        assert_eq!(org.get_pointer_size(), DEFAULT_POINTER_SIZE);
        assert_eq!(org.get_machine_alignment(), 8);
        assert_eq!(org.get_integer_size(), 4);
        assert_eq!(org.get_long_size(), 4);
        assert!(org.is_signed_char());
        assert!(!org.is_big_endian());
        assert_eq!(org.get_sizes(), vec![1, 2, 4, 8]);
        assert_eq!(org.get_size_alignment_count(), 4);
        assert_eq!(*org.get_bit_field_packing(), BitFieldPackingImpl::new());

        let language = TestCspecLanguage { big_endian: true };
        let org = DataOrganizationImpl::get_default_organization(Some(&language));
        assert_eq!(org.get_pointer_size(), 8); // 64-bit ram space
        assert!(org.is_big_endian());
    }

    #[test]
    fn restore_x86_64_gcc_data_organization() {
        let org = x86_64_gcc();
        assert_eq!(org.get_machine_alignment(), 2);
        assert_eq!(org.get_default_pointer_alignment(), 8);
        assert_eq!(org.get_pointer_size(), 8);
        assert_eq!(org.get_wide_char_size(), 4);
        assert_eq!(org.get_long_size(), 8);
        assert_eq!(org.get_long_double_size(), 16);
        assert_eq!(org.get_sizes(), vec![1, 2, 4, 8, 16]);
        assert_eq!(org.get_size_alignment(16), 16);
        assert!(org.get_bit_field_packing().use_ms_convention());
        assert_eq!(org.get_integer_c_type_approximation(8, false), "unsigned long");
        assert_eq!(org.get_integer_c_type_approximation(2, true), "short");
        assert_eq!(org.get_integer_c_type_approximation(16, true), "long long");
        assert_eq!(org.get_integer_c_type_approximation(1, false), "unsigned char");
    }

    #[test]
    fn restore_xml_stores_sizes_without_cascading() {
        let mut org = DataOrganizationImpl::get_default_organization(None);
        org.restore_xml(&mut parser(r#"<data_organization><short_size value="8"/><char_type signed="false"/></data_organization>"#))
            .unwrap();
        assert_eq!(org.get_short_size(), 8);
        assert_eq!(org.get_integer_size(), DEFAULT_INT_SIZE);
        assert!(!org.is_signed_char());
    }

    #[test]
    fn setters_cascade_to_keep_size_ordering() {
        let mut org = DataOrganizationImpl::get_default_organization(None);
        org.set_short_size(8);
        assert_eq!((org.get_integer_size(), org.get_long_size(), org.get_long_long_size()), (8, 8, 8));
        org.set_integer_size(2);
        assert_eq!((org.get_short_size(), org.get_integer_size(), org.get_long_size()), (2, 2, 8));
        org.set_long_long_size(1);
        assert_eq!((org.get_short_size(), org.get_integer_size(), org.get_long_size()), (1, 1, 1));
        org.set_double_size(16);
        assert_eq!((org.get_float_size(), org.get_long_double_size()), (4, 16));
        org.set_long_double_size(2);
        assert_eq!((org.get_float_size(), org.get_double_size()), (2, 2));
    }

    #[test]
    fn size_alignment_uses_floor_entry_and_absolute_cap() {
        let mut org = x86_64_gcc();
        assert_eq!(org.get_size_alignment(12), 8); // floor entry is 8
        assert_eq!(org.get_size_alignment(0), 1); // below every entry: default alignment
        org.set_absolute_max_alignment(4);
        assert_eq!(org.get_size_alignment(16), 4);
        org.clear_size_alignment_map();
        assert_eq!(org.get_size_alignment(16), 1);
    }

    #[test]
    fn get_alignment_cases() {
        let mut org = DataOrganizationImpl::get_default_organization(None);
        assert_eq!(org.get_alignment(&DynamicDataType), 1);
        assert_eq!(org.get_alignment(&PlainDataType { length: 0 }), 1);
        assert_eq!(org.get_alignment(&PlainDataType { length: 4 }), 4);
        assert_eq!(org.get_alignment(&TypedefDataType { base: 8 }), 8);
        assert_eq!(org.get_alignment(&ArrayDataType { element_length: 2 }), 2);
        assert_eq!(org.get_alignment(&CompositeDataType { alignment: 16 }), 16);
        assert_eq!(org.get_alignment(&BitFieldDataTypeMock { marker: BitFieldMarker { base_length: 2 } }), 2);
        assert_eq!(org.get_alignment(&PointerDataType { length: 8 }), 8); // mapped size
        org.set_default_pointer_alignment(16);
        assert_eq!(org.get_alignment(&PointerDataType { length: 6 }), 16); // unmapped size
    }

    #[test]
    fn is_equivalent_and_equality() {
        assert!(x86_64_gcc().is_equivalent(&x86_64_gcc()));
        assert_eq!(x86_64_gcc(), x86_64_gcc());
        let mut other = x86_64_gcc();
        other.set_size_alignment(16, 8);
        assert!(!x86_64_gcc().is_equivalent(&other));
        let mut other = x86_64_gcc();
        other.set_big_endian(true);
        assert!(!x86_64_gcc().is_equivalent(&other));
        assert_ne!(x86_64_gcc(), other);
    }

    #[derive(Default)]
    struct MemoryStringMap(HashMap<String, String>);
    impl DbStringMapAdapter for MemoryStringMap {
        fn put(&mut self, key: &str, value: &str) -> io::Result<()> {
            self.0.insert(key.to_string(), value.to_string());
            Ok(())
        }
        fn get(&self, key: &str) -> io::Result<Option<String>> {
            Ok(self.0.get(key).cloned())
        }
        fn key_set(&self) -> io::Result<Vec<String>> {
            Ok(self.0.keys().cloned().collect())
        }
        fn delete(&mut self, key: &str) -> io::Result<()> {
            self.0.remove(key);
            Ok(())
        }
    }

    #[test]
    fn save_and_restore_round_trip() {
        let mut map = MemoryStringMap::default();
        map.put("dataOrg.stale", "x").unwrap();
        map.put("other.key", "kept").unwrap();
        let mut org = x86_64_gcc();
        org.set_big_endian(true);
        org.set_char_is_signed(false);
        DataOrganizationImpl::save(&org, &mut map, "dataOrg.").unwrap();
        assert!(map.get("dataOrg.stale").unwrap().is_none());
        assert_eq!(map.get("other.key").unwrap().as_deref(), Some("kept"));
        assert_eq!(map.get("dataOrg.pointer_size").unwrap().as_deref(), Some("8"));
        assert_eq!(map.get("dataOrg.big_endian").unwrap().as_deref(), Some("true"));
        assert_eq!(map.get("dataOrg.size_alignment_map.16").unwrap().as_deref(), Some("16"));
        assert_eq!(map.get("dataOrg.bitfield_packing.use_MS_convention").unwrap().as_deref(), Some("true"));
        assert!(map.get("dataOrg.integer_size").unwrap().is_none()); // default not written

        let restored = DataOrganizationImpl::restore(&map, "dataOrg.").unwrap().unwrap();
        assert_eq!(restored, org);
        assert!(DataOrganizationImpl::restore(&map, "missing.").unwrap().is_none());
    }

    #[derive(Default)]
    struct MockEncoder {
        events: Vec<String>,
    }
    impl Encoder for MockEncoder {
        fn open_element(&mut self, elem_id: crate::program::model::pcode::ids::ElementId) -> io::Result<()> {
            self.events.push(format!("open:{}", elem_id.name));
            Ok(())
        }
        fn close_element(&mut self, elem_id: crate::program::model::pcode::ids::ElementId) -> io::Result<()> {
            self.events.push(format!("close:{}", elem_id.name));
            Ok(())
        }
        fn write_bool(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            val: bool,
        ) -> io::Result<()> {
            self.events.push(format!("bool:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_signed_integer(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            val: i64,
        ) -> io::Result<()> {
            self.events.push(format!("int:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_unsigned_integer(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            val: u64,
        ) -> io::Result<()> {
            self.events.push(format!("uint:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_string(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            val: &str,
        ) -> io::Result<()> {
            self.events.push(format!("str:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_string_indexed(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            index: i32,
            val: &str,
        ) -> io::Result<()> {
            self.events
                .push(format!("str[{}]:{}={}", index, attrib_id.name, val));
            Ok(())
        }
        fn write_space(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _spc: &crate::program::model::address::AddressSpace,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_space_indexed(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _index: i32,
            _name: &str,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_opcode(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _opcode: crate::decompiler::opcodes::op_code::OpCode,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_opcode_ordinal(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _opcode: i32,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn encode_writes_non_default_fields_plus_pointer_size() {
        let org = DataOrganizationImpl::get_default_organization(None);
        let mut encoder = MockEncoder::default();
        org.encode(&mut encoder).unwrap();
        assert_eq!(&encoder.events[..4], &["open:data_organization", "open:pointer_size", "int:value=4", "close:pointer_size"]);
        assert!(encoder.events.contains(&"open:size_alignment_map".to_string()));
        assert!(!encoder.events.iter().any(|e| e.contains("bitfield_packing")));
        assert_eq!(encoder.events.last().map(String::as_str), Some("close:data_organization"));

        let mut encoder = MockEncoder::default();
        x86_64_gcc().encode(&mut encoder).unwrap();
        for event in ["int:value=2", "int:value=16", "int:size=16", "int:alignment=16", "open:bitfield_packing", "bool:value=true"] {
            assert!(encoder.events.iter().any(|e| e == event), "missing {event}");
        }
    }

    #[test]
    fn get_aligned_offset_matches_java_semantics() {
        assert_eq!(get_aligned_offset(0, 5), 5);
        assert_eq!(get_aligned_offset(4, 5), 8);
        assert_eq!(get_aligned_offset(4, 8), 8);
        assert_eq!(get_aligned_offset(3, 4), 6);
    }

    #[test]
    fn least_common_multiple_and_gcd() {
        assert_eq!(get_greatest_common_denominator(12, 18), 6);
        assert_eq!(get_least_common_multiple(4, 6), 12);
        assert_eq!(get_least_common_multiple(0, 6), 0);
    }
}
