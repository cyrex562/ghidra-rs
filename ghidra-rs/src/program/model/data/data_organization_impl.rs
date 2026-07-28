//! Port of `ghidra.program.model.data.DataOrganizationImpl`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! [`DataOrganization`] (already ported) is the read-only *interface*: it exposes getters plus the
//! abstract `get_alignment(&self, data_type: &dyn DataType) -> i32`. `DataOrganizationImpl` is
//! Java's one concrete implementation of that interface, adding mutable setters, the concrete
//! `getAlignment` algorithm, and (de)serialization helpers. Since `DataOrganization` already
//! declares `get_alignment` as a required (non-default) method, a subtrait cannot supply a default
//! body for it -- Rust does not allow a subtrait to override a supertrait's required method.
//! Instead, the real algorithm lives here as the default method
//! [`compute_alignment`](DataOrganizationImpl::compute_alignment); a concrete implementor's
//! `DataOrganization::get_alignment` is expected to simply delegate to it (see the test mock
//! below).
//!
//! A handful of Java setters (`setShortSize`/`setIntegerSize`/`setLongSize`/`setLongLongSize`, and
//! the analogous `setFloatSize`/`setDoubleSize`/`setLongDoubleSize`) do more than store a field --
//! they cascade into neighboring size fields to maintain `short <= integer <= long <= longLong`
//! and `float <= double <= longDouble` invariants, and those neighbors may themselves cascade
//! further. To preserve that behavior as trait *defaults* (rather than forcing every implementor to
//! reimplement the cascade), each of those seven setters is split into a required `*_raw` primitive
//! (store this one field, no cascade) and a default public method (store via the raw primitive,
//! then cascade by calling the *other* default setters, which are also visible on `&mut self`).
//! Every other setter has no cross-field cascade in Java, so it is simply a required trait method.
//!
//! `getAlignment` needs `instanceof` checks against `Dynamic`, `FactoryDataType`, `TypeDef`,
//! `Array`, `Composite`, `BitFieldDataType`, and `Pointer`. The first five (plus `Pointer`) already
//! have downcast stand-ins on [`DataType`] (`is_dynamic_type`/`is_factory_type`/
//! `typedef_base_data_type`/`as_array`/`is_pointer`) except for `Composite` and `BitFieldDataType`,
//! which this port adds: [`DataType::as_composite`] (mirroring the existing `as_structure`) and
//! [`DataType::as_bit_field`]. `BitFieldDataType` itself is not yet ported (it depends on
//! not-yet-ported bitfield allocation machinery), so `as_bit_field` downcasts to the minimal
//! [`seam_stubs::BitFieldDataType`](crate::program::seam_stubs::BitFieldDataType) placeholder
//! instead; see `STUBS.tsv`.
//!
//! `encode`/`restoreXml` are included since the infrastructure they need (`Encoder`,
//! `XmlPullParser`, `SpecXmlUtils`) is already ported. `encode` is a default trait method (the
//! `Encoder` trait is object-safe). `restoreXml` cannot be: `XmlPullParser` carries an associated
//! `Element` type and is only `dyn`-safe once that type is fixed, so it is exposed as the free
//! generic function [`restore_xml`] taking `&mut dyn DataOrganizationImpl` instead of a trait
//! method -- this keeps `DataOrganizationImpl` itself fully object-safe while still supporting any
//! concrete parser. Both skip `bitFieldPacking`'s own (de)serialization: `BitFieldPackingImpl`
//! (which supplies `BitFieldPacking.encode`/`restoreXml` in Java) is not yet ported, so `encode`
//! omits writing bitfield-packing details and `restore_xml` discards that subtree unread rather
//! than losing parser sync. `encode`'s size-alignment-map entries are written via
//! [`DataOrganization::get_size_alignment`], which (unlike Java's raw `sizeAlignmentMap.get`) also
//! applies the `absoluteMaxAlignment` clamp; the two differ only when a stored entry's alignment
//! exceeds that cap, a narrow edge case not worth a dedicated accessor.
//!
//! The static factory `getDefaultOrganization(Language)` is represented here as the free function
//! [`populate_default_organization`], taking an existing `&mut dyn DataOrganizationImpl` to
//! configure (since a trait cannot construct "a new `Self`" generically) rather than returning one.
//! Only the no-`Language` overload's behavior (populating the 1/2/4/8-byte size/alignment entries)
//! is included; the `Language`-parameterized overload additionally seeds pointer size from
//! `language.getDefaultSpace().getPointerSize()`, but the Rust `AddressSpace` struct has no
//! `get_pointer_size` accessor yet (out of scope for this port -- it belongs to `AddressSpace`, not
//! `DataOrganizationImpl`), so that overload is omitted.
//!
//! `save`/`restore` (the `DBStringMapAdapter`-based persistence pair) and `equals`/`hashCode` are
//! left out entirely: the former would need a placeholder for `DBStringMapAdapter` for a code path
//! nothing in the crate currently calls, and the latter's semantic-equivalence role is already
//! filled by [`DataOrganization::is_equivalent`].

use std::io;

use crate::program::model::data::bit_field_packing::BitFieldPacking;
use crate::program::model::data::data_organization::{DataOrganization, NO_MAXIMUM_ALIGNMENT};
use crate::program::model::data::data_type::DataType;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{
    ATTRIB_ALIGNMENT, ATTRIB_SIGNED, ATTRIB_SIZE, ATTRIB_VALUE, ELEM_ABSOLUTE_MAX_ALIGNMENT,
    ELEM_BITFIELD_PACKING, ELEM_CHAR_SIZE, ELEM_CHAR_TYPE, ELEM_DATA_ORGANIZATION,
    ELEM_DEFAULT_ALIGNMENT, ELEM_DEFAULT_POINTER_ALIGNMENT, ELEM_DOUBLE_SIZE, ELEM_ENTRY,
    ELEM_FLOAT_SIZE, ELEM_INTEGER_SIZE, ELEM_LONG_DOUBLE_SIZE, ELEM_LONG_LONG_SIZE, ELEM_LONG_SIZE,
    ELEM_MACHINE_ALIGNMENT, ELEM_POINTER_SHIFT, ELEM_POINTER_SIZE, ELEM_SHORT_SIZE,
    ELEM_SIZE_ALIGNMENT_MAP, ELEM_WCHAR_SIZE,
};
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
pub const DEFAULT_FLOAT_SIZE: i32 = 4;
pub const DEFAULT_DOUBLE_SIZE: i32 = 8;
pub const DEFAULT_LONG_DOUBLE_SIZE: i32 = 8;

/// Port of `ghidra.program.model.data.DataOrganizationImpl`.
///
/// See the module docs for the rationale behind the raw/cascading setter split, the free-function
/// `restore_xml`/`populate_default_organization`, and the excluded `save`/`restore`/`equals`/
/// `hashCode` members.
pub trait DataOrganizationImpl: DataOrganization {
    /// Port of `DataOrganizationImpl.setBigEndian(boolean)`.
    fn set_big_endian(&mut self, big_endian: bool);

    /// Port of `DataOrganizationImpl.setPointerSize(int)`.
    fn set_pointer_size(&mut self, pointer_size: i32);

    /// Port of `DataOrganizationImpl.setPointerShift(int)`.
    fn set_pointer_shift(&mut self, pointer_shift: i32);

    /// Port of `DataOrganizationImpl.setCharIsSigned(boolean)`.
    fn set_char_is_signed(&mut self, signed: bool);

    /// Port of `DataOrganizationImpl.setCharSize(int)`.
    fn set_char_size(&mut self, char_size: i32);

    /// Port of `DataOrganizationImpl.setWideCharSize(int)`.
    fn set_wide_char_size(&mut self, wide_char_size: i32);

    /// Port of `DataOrganizationImpl.setAbsoluteMaxAlignment(int)`.
    fn set_absolute_max_alignment(&mut self, absolute_max_alignment: i32);

    /// Port of `DataOrganizationImpl.setMachineAlignment(int)`.
    fn set_machine_alignment(&mut self, machine_alignment: i32);

    /// Port of `DataOrganizationImpl.setDefaultAlignment(int)`.
    fn set_default_alignment(&mut self, default_alignment: i32);

    /// Port of `DataOrganizationImpl.setDefaultPointerAlignment(int)`.
    fn set_default_pointer_alignment(&mut self, default_pointer_alignment: i32);

    /// Port of `DataOrganizationImpl.setSizeAlignment(int, int)`.
    fn set_size_alignment(&mut self, size: i32, alignment: i32);

    /// Port of `DataOrganizationImpl.setBitFieldPacking(BitFieldPackingImpl)`.
    fn set_bit_field_packing(&mut self, bit_field_packing: Box<dyn BitFieldPacking>);

    /// Port of `DataOrganizationImpl.clearSizeAlignmentMap()`.
    fn clear_size_alignment_map(&mut self);

    /// Stores `short_size` without cascading into `integer_size`. Required primitive backing
    /// [`set_short_size`](Self::set_short_size); see the module docs.
    fn set_short_size_raw(&mut self, short_size: i32);

    /// Stores `integer_size` without cascading into `long_size`/`short_size`. Required primitive
    /// backing [`set_integer_size`](Self::set_integer_size); see the module docs.
    fn set_integer_size_raw(&mut self, integer_size: i32);

    /// Stores `long_size` without cascading into `long_long_size`/`integer_size`. Required
    /// primitive backing [`set_long_size`](Self::set_long_size); see the module docs.
    fn set_long_size_raw(&mut self, long_size: i32);

    /// Stores `long_long_size` without cascading into `long_size`. Required primitive backing
    /// [`set_long_long_size`](Self::set_long_long_size); see the module docs.
    fn set_long_long_size_raw(&mut self, long_long_size: i32);

    /// Stores `float_size` without cascading into `double_size`. Required primitive backing
    /// [`set_float_size`](Self::set_float_size); see the module docs.
    fn set_float_size_raw(&mut self, float_size: i32);

    /// Stores `double_size` without cascading into `long_double_size`/`float_size`. Required
    /// primitive backing [`set_double_size`](Self::set_double_size); see the module docs.
    fn set_double_size_raw(&mut self, double_size: i32);

    /// Stores `long_double_size` without cascading into `double_size`. Required primitive backing
    /// [`set_long_double_size`](Self::set_long_double_size); see the module docs.
    fn set_long_double_size_raw(&mut self, long_double_size: i32);

    /// Port of `DataOrganizationImpl.setShortSize(int)`: stores the value, then grows
    /// `integer_size` to match if it was smaller.
    fn set_short_size(&mut self, short_size: i32) {
        self.set_short_size_raw(short_size);
        if self.get_integer_size() < short_size {
            self.set_integer_size(short_size);
        }
    }

    /// Port of `DataOrganizationImpl.setIntegerSize(int)`: stores the value, then grows
    /// `long_size` (if smaller) and shrinks `short_size` (if larger) to match.
    fn set_integer_size(&mut self, integer_size: i32) {
        self.set_integer_size_raw(integer_size);
        if self.get_long_size() < integer_size {
            self.set_long_size(integer_size);
        }
        if self.get_short_size() > integer_size {
            self.set_short_size(integer_size);
        }
    }

    /// Port of `DataOrganizationImpl.setLongSize(int)`: stores the value, then grows
    /// `long_long_size` (if smaller) and shrinks `integer_size` (if larger) to match.
    fn set_long_size(&mut self, long_size: i32) {
        self.set_long_size_raw(long_size);
        if self.get_long_long_size() < long_size {
            self.set_long_long_size(long_size);
        }
        if self.get_integer_size() > long_size {
            self.set_integer_size(long_size);
        }
    }

    /// Port of `DataOrganizationImpl.setLongLongSize(int)`: stores the value, then shrinks
    /// `long_size` (if larger) to match.
    fn set_long_long_size(&mut self, long_long_size: i32) {
        self.set_long_long_size_raw(long_long_size);
        if self.get_long_size() > long_long_size {
            self.set_long_size(long_long_size);
        }
    }

    /// Port of `DataOrganizationImpl.setFloatSize(int)`: stores the value, then grows
    /// `double_size` (if smaller) to match.
    fn set_float_size(&mut self, float_size: i32) {
        self.set_float_size_raw(float_size);
        if self.get_double_size() < float_size {
            self.set_double_size(float_size);
        }
    }

    /// Port of `DataOrganizationImpl.setDoubleSize(int)`: stores the value, then grows
    /// `long_double_size` (if smaller) and shrinks `float_size` (if larger) to match.
    fn set_double_size(&mut self, double_size: i32) {
        self.set_double_size_raw(double_size);
        if self.get_long_double_size() < double_size {
            self.set_long_double_size(double_size);
        }
        if self.get_float_size() > double_size {
            self.set_float_size(double_size);
        }
    }

    /// Port of `DataOrganizationImpl.setLongDoubleSize(int)`: stores the value, then shrinks
    /// `double_size` (if larger) to match.
    fn set_long_double_size(&mut self, long_double_size: i32) {
        self.set_long_double_size_raw(long_double_size);
        if self.get_double_size() > long_double_size {
            self.set_double_size(long_double_size);
        }
    }

    /// Port of `DataOrganizationImpl.getAlignment(DataType)`. A concrete type implementing both
    /// this trait and [`DataOrganization`] is expected to implement
    /// `DataOrganization::get_alignment` by delegating here (see the module docs for why the two
    /// methods can't share a name).
    fn compute_alignment(&self, data_type: &dyn DataType) -> i32 {
        let dt_size = data_type.get_aligned_length();
        if data_type.is_dynamic_type() || data_type.is_factory_type() || dt_size <= 0 {
            return 1;
        }
        // Typedef is aligned the same as its underlying data type is aligned.
        if let Some(base) = data_type.typedef_base_data_type() {
            return self.compute_alignment(base.as_ref());
        }
        // Array alignment is the alignment of its element data type.
        if let Some(array) = data_type.as_array() {
            return self.compute_alignment(array.get_data_type().as_ref());
        }
        // Structure's or Union's alignment is a multiple of the least common multiple of the
        // components. It can also be adjusted by packing and alignment attributes.
        // IMPORTANT: composites are responsible for computing their own alignment!
        if let Some(composite) = data_type.as_composite() {
            return composite.get_alignment();
        }
        // Bit field alignment must be determined within the context of the containing structure.
        // See AlignedStructurePacker.
        if let Some(bit_field) = data_type.as_bit_field() {
            return self.compute_alignment(bit_field.get_base_data_type().as_ref());
        }
        // If pointer size not found in size alignment map use default pointer alignment.
        // TODO: this should probably be re-evaluated for its necessity.
        if data_type.is_pointer() && !self.get_sizes().contains(&dt_size) {
            return self.get_default_pointer_alignment();
        }
        // Otherwise get the alignment based on the size.
        self.get_size_alignment(dt_size)
    }

    /// Port of `DataOrganizationImpl.encode(Encoder)`. See the module docs for why
    /// `bitFieldPacking`'s own encoding is omitted.
    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_DATA_ORGANIZATION)?;

        // NOTE: endianness intentionally omitted from output.

        if self.get_absolute_max_alignment() != NO_MAXIMUM_ALIGNMENT {
            encoder.open_element(ELEM_ABSOLUTE_MAX_ALIGNMENT)?;
            encoder.write_signed_integer(ATTRIB_VALUE, self.get_absolute_max_alignment() as i64)?;
            encoder.close_element(ELEM_ABSOLUTE_MAX_ALIGNMENT)?;
        }
        if self.get_machine_alignment() != DEFAULT_MACHINE_ALIGNMENT {
            encoder.open_element(ELEM_MACHINE_ALIGNMENT)?;
            encoder.write_signed_integer(ATTRIB_VALUE, self.get_machine_alignment() as i64)?;
            encoder.close_element(ELEM_MACHINE_ALIGNMENT)?;
        }
        if self.get_default_alignment() != DEFAULT_DEFAULT_ALIGNMENT {
            encoder.open_element(ELEM_DEFAULT_ALIGNMENT)?;
            encoder.write_signed_integer(ATTRIB_VALUE, self.get_default_alignment() as i64)?;
            encoder.close_element(ELEM_DEFAULT_ALIGNMENT)?;
        }
        if self.get_default_pointer_alignment() != DEFAULT_DEFAULT_POINTER_ALIGNMENT {
            encoder.open_element(ELEM_DEFAULT_POINTER_ALIGNMENT)?;
            encoder
                .write_signed_integer(ATTRIB_VALUE, self.get_default_pointer_alignment() as i64)?;
            encoder.close_element(ELEM_DEFAULT_POINTER_ALIGNMENT)?;
        }

        // Always output pointer size.
        encoder.open_element(ELEM_POINTER_SIZE)?;
        encoder.write_signed_integer(ATTRIB_VALUE, self.get_pointer_size() as i64)?;
        encoder.close_element(ELEM_POINTER_SIZE)?;

        if self.get_pointer_shift() != DEFAULT_POINTER_SHIFT {
            encoder.open_element(ELEM_POINTER_SHIFT)?;
            encoder.write_signed_integer(ATTRIB_VALUE, self.get_pointer_shift() as i64)?;
            encoder.close_element(ELEM_POINTER_SHIFT)?;
        }
        if self.is_signed_char() != DEFAULT_CHAR_IS_SIGNED {
            encoder.open_element(ELEM_CHAR_TYPE)?;
            encoder.write_bool(ATTRIB_SIGNED, self.is_signed_char())?;
            encoder.close_element(ELEM_CHAR_TYPE)?;
        }
        if self.get_char_size() != DEFAULT_CHAR_SIZE {
            encoder.open_element(ELEM_CHAR_SIZE)?;
            encoder.write_signed_integer(ATTRIB_VALUE, self.get_char_size() as i64)?;
            encoder.close_element(ELEM_CHAR_SIZE)?;
        }
        if self.get_wide_char_size() != DEFAULT_WIDE_CHAR_SIZE {
            encoder.open_element(ELEM_WCHAR_SIZE)?;
            encoder.write_signed_integer(ATTRIB_VALUE, self.get_wide_char_size() as i64)?;
            encoder.close_element(ELEM_WCHAR_SIZE)?;
        }
        if self.get_short_size() != DEFAULT_SHORT_SIZE {
            encoder.open_element(ELEM_SHORT_SIZE)?;
            encoder.write_signed_integer(ATTRIB_VALUE, self.get_short_size() as i64)?;
            encoder.close_element(ELEM_SHORT_SIZE)?;
        }
        if self.get_integer_size() != DEFAULT_INT_SIZE {
            encoder.open_element(ELEM_INTEGER_SIZE)?;
            encoder.write_signed_integer(ATTRIB_VALUE, self.get_integer_size() as i64)?;
            encoder.close_element(ELEM_INTEGER_SIZE)?;
        }
        if self.get_long_size() != DEFAULT_LONG_SIZE {
            encoder.open_element(ELEM_LONG_SIZE)?;
            encoder.write_signed_integer(ATTRIB_VALUE, self.get_long_size() as i64)?;
            encoder.close_element(ELEM_LONG_SIZE)?;
        }
        if self.get_long_long_size() != DEFAULT_LONG_LONG_SIZE {
            encoder.open_element(ELEM_LONG_LONG_SIZE)?;
            encoder.write_signed_integer(ATTRIB_VALUE, self.get_long_long_size() as i64)?;
            encoder.close_element(ELEM_LONG_LONG_SIZE)?;
        }
        if self.get_float_size() != DEFAULT_FLOAT_SIZE {
            encoder.open_element(ELEM_FLOAT_SIZE)?;
            encoder.write_signed_integer(ATTRIB_VALUE, self.get_float_size() as i64)?;
            encoder.close_element(ELEM_FLOAT_SIZE)?;
        }
        if self.get_double_size() != DEFAULT_DOUBLE_SIZE {
            encoder.open_element(ELEM_DOUBLE_SIZE)?;
            encoder.write_signed_integer(ATTRIB_VALUE, self.get_double_size() as i64)?;
            encoder.close_element(ELEM_DOUBLE_SIZE)?;
        }
        if self.get_long_double_size() != DEFAULT_LONG_DOUBLE_SIZE {
            encoder.open_element(ELEM_LONG_DOUBLE_SIZE)?;
            encoder.write_signed_integer(ATTRIB_VALUE, self.get_long_double_size() as i64)?;
            encoder.close_element(ELEM_LONG_DOUBLE_SIZE)?;
        }
        if self.get_size_alignment_count() != 0 {
            encoder.open_element(ELEM_SIZE_ALIGNMENT_MAP)?;
            for size in self.get_sizes() {
                encoder.open_element(ELEM_ENTRY)?;
                let alignment = self.get_size_alignment(size);
                encoder.write_signed_integer(ATTRIB_SIZE, size as i64)?;
                encoder.write_signed_integer(ATTRIB_ALIGNMENT, alignment as i64)?;
                encoder.close_element(ELEM_ENTRY)?;
            }
            encoder.close_element(ELEM_SIZE_ALIGNMENT_MAP)?;
        }
        // bitFieldPacking.encode(encoder) omitted -- see module docs.
        encoder.close_element(ELEM_DATA_ORGANIZATION)?;
        Ok(())
    }
}

/// Port of `DataOrganizationImpl.restoreXml(XmlPullParser)`. A free generic function rather than a
/// trait method; see the module docs for why. `org` should generally already carry
/// language-specific defaults (e.g. from [`populate_default_organization`]) since the XML is
/// designed to override rather than fully repopulate a data organization.
pub fn restore_xml<P: XmlPullParser>(
    org: &mut dyn DataOrganizationImpl,
    parser: &mut P,
) -> Result<(), XmlException> {
    // NOTE: endianness intentionally omitted from XML.

    parser.start(&[])?;
    while parser.has_next() && parser.peek().is_start() {
        let name = parser.peek().get_name().to_string();

        if name == ELEM_CHAR_TYPE.name {
            let subel = parser.start(&[])?;
            let bool_str = subel.get_attribute(ATTRIB_SIGNED.name).unwrap_or_default();
            let signed = decode_boolean_default(&bool_str, org.is_signed_char());
            org.set_char_is_signed(signed);
            parser.end()?;
            continue;
        } else if name == ELEM_BITFIELD_PACKING.name {
            // BitFieldPackingImpl.restoreXml is not yet ported; discard the subtree unread
            // rather than losing parser sync -- see module docs.
            parser.discard_sub_tree_named(&name)?;
            continue;
        } else if name == ELEM_SIZE_ALIGNMENT_MAP.name {
            parser.start(&[])?;
            while parser.has_next() && parser.peek().is_start() {
                let subsubel = parser.start(&[])?;
                let size = decode_int(subsubel.get_attribute(ATTRIB_SIZE.name).as_deref());
                let alignment =
                    decode_int(subsubel.get_attribute(ATTRIB_ALIGNMENT.name).as_deref());
                org.set_size_alignment(size, alignment);
                parser.end()?;
            }
            parser.end()?;
            continue;
        }

        let subel = parser.start(&[])?;
        let value = subel.get_attribute(ATTRIB_VALUE.name);
        let decoded = decode_int(value.as_deref());

        if name == ELEM_ABSOLUTE_MAX_ALIGNMENT.name {
            org.set_absolute_max_alignment(decoded);
        } else if name == ELEM_MACHINE_ALIGNMENT.name {
            org.set_machine_alignment(decoded);
        } else if name == ELEM_DEFAULT_ALIGNMENT.name {
            org.set_default_alignment(decoded);
        } else if name == ELEM_DEFAULT_POINTER_ALIGNMENT.name {
            org.set_default_pointer_alignment(decoded);
        } else if name == ELEM_POINTER_SIZE.name {
            org.set_pointer_size(decoded);
        } else if name == ELEM_POINTER_SHIFT.name {
            org.set_pointer_shift(decoded);
        } else if name == ELEM_CHAR_SIZE.name {
            org.set_char_size(decoded);
        } else if name == ELEM_WCHAR_SIZE.name {
            org.set_wide_char_size(decoded);
        } else if name == ELEM_SHORT_SIZE.name {
            // Direct field assignment in Java (bypasses the cascading public setter).
            org.set_short_size_raw(decoded);
        } else if name == ELEM_INTEGER_SIZE.name {
            org.set_integer_size_raw(decoded);
        } else if name == ELEM_LONG_SIZE.name {
            org.set_long_size_raw(decoded);
        } else if name == ELEM_LONG_LONG_SIZE.name {
            org.set_long_long_size_raw(decoded);
        } else if name == ELEM_FLOAT_SIZE.name {
            org.set_float_size_raw(decoded);
        } else if name == ELEM_DOUBLE_SIZE.name {
            org.set_double_size_raw(decoded);
        } else if name == ELEM_LONG_DOUBLE_SIZE.name {
            org.set_long_double_size_raw(decoded);
        }
        parser.end()?;
    }

    parser.end()?;
    Ok(())
}

/// Port of the size/alignment portion of `DataOrganizationImpl.getDefaultOrganization(Language)`
/// (and its no-argument overload `getDefaultOrganization()`), applied to an already-constructed
/// `org` rather than returning a new instance. See the module docs for why the `Language`-seeded
/// pointer size/endianness half of the overload is omitted.
pub fn populate_default_organization(org: &mut dyn DataOrganizationImpl) {
    org.set_size_alignment(1, 1);
    org.set_size_alignment(2, 2);
    org.set_size_alignment(4, 4);
    org.set_size_alignment(8, 8);
}

/// Port of `DataOrganizationImpl.getAlignedOffset(int, int)`: determines the first offset that is
/// equal to or greater than `minimum_offset` which has the specified `alignment`. If a
/// non-positive alignment is specified, `minimum_offset` is returned unchanged.
pub fn get_aligned_offset(alignment: i32, minimum_offset: i32) -> i32 {
    if alignment <= 0 {
        return minimum_offset;
    }
    let is_power_of_two = (alignment & (alignment - 1)) == 0;
    if is_power_of_two {
        return alignment + ((minimum_offset - 1) & !(alignment - 1));
    }
    let offcut = minimum_offset % alignment;
    let adj = if offcut != 0 { alignment - offcut } else { 0 };
    minimum_offset + adj
}

/// Port of `DataOrganizationImpl.getLeastCommonMultiple(int, int)`.
pub fn get_least_common_multiple(value1: i32, value2: i32) -> i32 {
    let gcd = get_greatest_common_denominator(value1, value2);
    if gcd != 0 {
        (value1 / gcd) * value2
    } else {
        0
    }
}

/// Port of `DataOrganizationImpl.getGreatestCommonDenominator(int, int)`.
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
    use crate::program::seam_stubs::BitFieldDataType;
    use std::collections::HashMap;

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

    #[derive(Default)]
    struct MockOrganization {
        big_endian: bool,
        absolute_max_alignment: i32,
        machine_alignment: i32,
        default_alignment: i32,
        default_pointer_alignment: i32,
        pointer_size: i32,
        pointer_shift: i32,
        char_size: i32,
        signed_char: bool,
        wide_char_size: i32,
        short_size: i32,
        integer_size: i32,
        long_size: i32,
        long_long_size: i32,
        float_size: i32,
        double_size: i32,
        long_double_size: i32,
        sizes: std::collections::BTreeMap<i32, i32>,
        bit_field_packing: Option<Box<dyn BitFieldPacking>>,
    }

    impl MockOrganization {
        fn defaults() -> Self {
            Self {
                machine_alignment: DEFAULT_MACHINE_ALIGNMENT,
                default_alignment: DEFAULT_DEFAULT_ALIGNMENT,
                default_pointer_alignment: DEFAULT_DEFAULT_POINTER_ALIGNMENT,
                pointer_size: DEFAULT_POINTER_SIZE,
                char_size: DEFAULT_CHAR_SIZE,
                signed_char: DEFAULT_CHAR_IS_SIGNED,
                wide_char_size: DEFAULT_WIDE_CHAR_SIZE,
                short_size: DEFAULT_SHORT_SIZE,
                integer_size: DEFAULT_INT_SIZE,
                long_size: DEFAULT_LONG_SIZE,
                long_long_size: DEFAULT_LONG_LONG_SIZE,
                float_size: DEFAULT_FLOAT_SIZE,
                double_size: DEFAULT_DOUBLE_SIZE,
                long_double_size: DEFAULT_LONG_DOUBLE_SIZE,
                bit_field_packing: Some(Box::new(MockBitFieldPacking)),
                ..Default::default()
            }
        }
    }

    impl DataOrganization for MockOrganization {
        fn is_big_endian(&self) -> bool {
            self.big_endian
        }
        fn get_pointer_size(&self) -> i32 {
            self.pointer_size
        }
        fn get_pointer_shift(&self) -> i32 {
            self.pointer_shift
        }
        fn is_signed_char(&self) -> bool {
            self.signed_char
        }
        fn get_char_size(&self) -> i32 {
            self.char_size
        }
        fn get_wide_char_size(&self) -> i32 {
            self.wide_char_size
        }
        fn get_short_size(&self) -> i32 {
            self.short_size
        }
        fn get_integer_size(&self) -> i32 {
            self.integer_size
        }
        fn get_long_size(&self) -> i32 {
            self.long_size
        }
        fn get_long_long_size(&self) -> i32 {
            self.long_long_size
        }
        fn get_float_size(&self) -> i32 {
            self.float_size
        }
        fn get_double_size(&self) -> i32 {
            self.double_size
        }
        fn get_long_double_size(&self) -> i32 {
            self.long_double_size
        }
        fn get_absolute_max_alignment(&self) -> i32 {
            self.absolute_max_alignment
        }
        fn get_machine_alignment(&self) -> i32 {
            self.machine_alignment
        }
        fn get_default_alignment(&self) -> i32 {
            self.default_alignment
        }
        fn get_default_pointer_alignment(&self) -> i32 {
            self.default_pointer_alignment
        }
        fn get_size_alignment(&self, size: i32) -> i32 {
            let alignment = self
                .sizes
                .range(..=size)
                .next_back()
                .map(|(_, v)| *v)
                .unwrap_or(self.default_alignment);
            if self.absolute_max_alignment != 0 {
                alignment.min(self.absolute_max_alignment)
            } else {
                alignment
            }
        }
        fn get_bit_field_packing(&self) -> Box<dyn BitFieldPacking> {
            self.bit_field_packing
                .as_ref()
                .map(|_| Box::new(MockBitFieldPacking) as Box<dyn BitFieldPacking>)
                .unwrap_or_else(|| Box::new(MockBitFieldPacking))
        }
        fn get_size_alignment_count(&self) -> i32 {
            self.sizes.len() as i32
        }
        fn get_sizes(&self) -> Vec<i32> {
            self.sizes.keys().copied().collect()
        }
        fn get_integer_c_type_approximation(&self, _size: i32, _signed: bool) -> String {
            String::new()
        }
        fn get_alignment(&self, data_type: &dyn DataType) -> i32 {
            self.compute_alignment(data_type)
        }
    }

    impl DataOrganizationImpl for MockOrganization {
        fn set_big_endian(&mut self, big_endian: bool) {
            self.big_endian = big_endian;
        }
        fn set_pointer_size(&mut self, pointer_size: i32) {
            self.pointer_size = pointer_size;
        }
        fn set_pointer_shift(&mut self, pointer_shift: i32) {
            self.pointer_shift = pointer_shift;
        }
        fn set_char_is_signed(&mut self, signed: bool) {
            self.signed_char = signed;
        }
        fn set_char_size(&mut self, char_size: i32) {
            self.char_size = char_size;
        }
        fn set_wide_char_size(&mut self, wide_char_size: i32) {
            self.wide_char_size = wide_char_size;
        }
        fn set_absolute_max_alignment(&mut self, absolute_max_alignment: i32) {
            self.absolute_max_alignment = absolute_max_alignment;
        }
        fn set_machine_alignment(&mut self, machine_alignment: i32) {
            self.machine_alignment = machine_alignment;
        }
        fn set_default_alignment(&mut self, default_alignment: i32) {
            self.default_alignment = default_alignment;
        }
        fn set_default_pointer_alignment(&mut self, default_pointer_alignment: i32) {
            self.default_pointer_alignment = default_pointer_alignment;
        }
        fn set_size_alignment(&mut self, size: i32, alignment: i32) {
            self.sizes.insert(size, alignment);
        }
        fn set_bit_field_packing(&mut self, bit_field_packing: Box<dyn BitFieldPacking>) {
            self.bit_field_packing = Some(bit_field_packing);
        }
        fn clear_size_alignment_map(&mut self) {
            self.sizes.clear();
        }
        fn set_short_size_raw(&mut self, short_size: i32) {
            self.short_size = short_size;
        }
        fn set_integer_size_raw(&mut self, integer_size: i32) {
            self.integer_size = integer_size;
        }
        fn set_long_size_raw(&mut self, long_size: i32) {
            self.long_size = long_size;
        }
        fn set_long_long_size_raw(&mut self, long_long_size: i32) {
            self.long_long_size = long_long_size;
        }
        fn set_float_size_raw(&mut self, float_size: i32) {
            self.float_size = float_size;
        }
        fn set_double_size_raw(&mut self, double_size: i32) {
            self.double_size = double_size;
        }
        fn set_long_double_size_raw(&mut self, long_double_size: i32) {
            self.long_double_size = long_double_size;
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let mut org = MockOrganization::defaults();
        org.set_size_alignment(1, 1);
        let dyn_org: &mut dyn DataOrganizationImpl = &mut org;
        dyn_org.set_pointer_size(8);
        assert_eq!(dyn_org.get_pointer_size(), 8);
    }

    #[test]
    fn set_short_size_grows_integer_size() {
        let mut org = MockOrganization::defaults();
        assert_eq!(org.get_integer_size(), 4);
        org.set_short_size(8);
        assert_eq!(org.get_short_size(), 8);
        // integer_size was smaller than the new short_size, so it grows to match.
        assert_eq!(org.get_integer_size(), 8);
    }

    #[test]
    fn set_integer_size_shrinks_short_size_and_grows_long_size() {
        let mut org = MockOrganization::defaults();
        org.set_short_size(2);
        org.set_long_size(4);
        org.set_integer_size(1);
        // short_size (2) was larger than the new integer_size (1), so it shrinks to match.
        assert_eq!(org.get_short_size(), 1);
        assert_eq!(org.get_integer_size(), 1);
        // long_size (4) was already >= integer_size, so it is left alone.
        assert_eq!(org.get_long_size(), 4);
    }

    #[test]
    fn set_long_long_size_shrinks_long_size_chain() {
        let mut org = MockOrganization::defaults();
        org.set_integer_size(4);
        org.set_long_size(8);
        org.set_long_long_size(8);
        org.set_long_long_size(2);
        // long_size (8) was larger than the new long_long_size (2), so the whole chain shrinks.
        assert_eq!(org.get_long_long_size(), 2);
        assert_eq!(org.get_long_size(), 2);
        assert_eq!(org.get_integer_size(), 2);
    }

    #[test]
    fn set_double_size_cascades_float_and_long_double() {
        let mut org = MockOrganization::defaults();
        org.set_float_size(4);
        org.set_long_double_size(8);
        org.set_double_size(2);
        // float_size (4) was larger than the new double_size, so it shrinks to match.
        assert_eq!(org.get_float_size(), 2);
        assert_eq!(org.get_double_size(), 2);
        // long_double_size (8) was already >= double_size, so it is left alone.
        assert_eq!(org.get_long_double_size(), 8);

        org.set_double_size(16);
        // long_double_size (8) was smaller than the new double_size, so it grows to match.
        assert_eq!(org.get_long_double_size(), 16);
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

    fn org_with_sizes() -> MockOrganization {
        let mut org = MockOrganization::defaults();
        org.set_size_alignment(1, 1);
        org.set_size_alignment(2, 2);
        org.set_size_alignment(4, 4);
        org.set_size_alignment(8, 8);
        org
    }

    #[test]
    fn compute_alignment_dynamic_type_is_one() {
        let org = org_with_sizes();
        assert_eq!(org.compute_alignment(&DynamicDataType), 1);
    }

    #[test]
    fn compute_alignment_zero_length_is_one() {
        let org = org_with_sizes();
        assert_eq!(org.compute_alignment(&PlainDataType { length: 0 }), 1);
    }

    #[test]
    fn compute_alignment_plain_size_uses_size_alignment_map() {
        let org = org_with_sizes();
        assert_eq!(org.compute_alignment(&PlainDataType { length: 4 }), 4);
    }

    #[test]
    fn compute_alignment_typedef_recurses_into_base_type() {
        let org = org_with_sizes();
        assert_eq!(org.compute_alignment(&TypedefDataType { base: 8 }), 8);
    }

    #[test]
    fn compute_alignment_array_uses_element_type_alignment() {
        let org = org_with_sizes();
        assert_eq!(
            org.compute_alignment(&ArrayDataType { element_length: 4 }),
            4
        );
    }

    #[test]
    fn compute_alignment_composite_delegates_to_its_own_alignment() {
        let org = org_with_sizes();
        // Composite's own alignment (16) is used verbatim, ignoring the size-alignment map even
        // though its length (12) isn't in it.
        assert_eq!(
            org.compute_alignment(&CompositeDataType { alignment: 16 }),
            16
        );
    }

    #[test]
    fn compute_alignment_bit_field_recurses_into_base_type() {
        let org = org_with_sizes();
        let bit_field = BitFieldDataTypeMock {
            marker: BitFieldMarker { base_length: 2 },
        };
        assert_eq!(org.compute_alignment(&bit_field), 2);
    }

    #[test]
    fn compute_alignment_pointer_falls_back_to_default_pointer_alignment_when_size_unmapped() {
        let mut org = org_with_sizes();
        org.set_default_pointer_alignment(16);
        // Length 6 isn't a key in the size-alignment map.
        assert_eq!(org.compute_alignment(&PointerDataType { length: 6 }), 16);
    }

    #[test]
    fn compute_alignment_pointer_uses_size_alignment_map_when_size_mapped() {
        let org = org_with_sizes();
        // Length 8 *is* a key in the size-alignment map, so that takes precedence.
        assert_eq!(org.compute_alignment(&PointerDataType { length: 8 }), 8);
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
    fn encode_only_writes_non_default_fields_plus_mandatory_pointer_size() {
        let org = MockOrganization::defaults();
        let mut encoder = MockEncoder::default();
        org.encode(&mut encoder).unwrap();

        assert_eq!(
            encoder.events,
            vec![
                "open:data_organization".to_string(),
                "open:pointer_size".to_string(),
                "int:value=4".to_string(),
                "close:pointer_size".to_string(),
                "close:data_organization".to_string(),
            ]
        );
    }

    #[test]
    fn encode_writes_changed_fields_and_size_alignment_map() {
        let mut org = MockOrganization::defaults();
        org.set_pointer_size(8);
        org.set_char_is_signed(false);
        org.set_size_alignment(1, 1);
        org.set_size_alignment(4, 4);
        let mut encoder = MockEncoder::default();
        org.encode(&mut encoder).unwrap();

        assert!(encoder.events.contains(&"int:value=8".to_string()));
        assert!(encoder.events.contains(&"bool:signed=false".to_string()));
        assert!(encoder.events.contains(&"open:size_alignment_map".to_string()));
        assert!(encoder.events.contains(&"open:entry".to_string()));
        assert!(encoder.events.contains(&"int:size=4".to_string()));
        assert!(encoder.events.contains(&"int:alignment=4".to_string()));
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

    #[test]
    fn populate_default_organization_sets_standard_size_alignment_entries() {
        let mut org = MockOrganization::defaults();
        populate_default_organization(&mut org);
        assert_eq!(org.get_sizes(), vec![1, 2, 4, 8]);
        assert_eq!(org.get_size_alignment(8), 8);
    }

    #[derive(Clone)]
    struct MockXmlElement {
        name: String,
        is_start: bool,
        is_end: bool,
        level: i32,
        attributes: HashMap<String, String>,
    }
    impl MockXmlElement {
        fn start(name: &str, level: i32, attrs: &[(&str, &str)]) -> Self {
            Self {
                name: name.to_string(),
                is_start: true,
                is_end: false,
                level,
                attributes: attrs
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            }
        }
        fn end(name: &str, level: i32) -> Self {
            Self {
                name: name.to_string(),
                is_start: false,
                is_end: true,
                level,
                attributes: HashMap::new(),
            }
        }
    }
    impl XmlElement for MockXmlElement {
        fn get_level(&self) -> i32 {
            self.level
        }
        fn is_start(&self) -> bool {
            self.is_start
        }
        fn is_end(&self) -> bool {
            self.is_end
        }
        fn is_content(&self) -> bool {
            !self.is_start && !self.is_end
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_attributes(&self) -> HashMap<String, String> {
            self.attributes.clone()
        }
        fn get_attribute_iter(&self) -> Box<dyn Iterator<Item = (String, String)> + '_> {
            Box::new(self.attributes.iter().map(|(k, v)| (k.clone(), v.clone())))
        }
        fn has_attribute(&self, key: &str) -> bool {
            self.attributes.contains_key(key)
        }
        fn get_attribute(&self, key: &str) -> Option<String> {
            self.attributes.get(key).cloned()
        }
        fn get_text(&self) -> &str {
            ""
        }
        fn get_column_number(&self) -> i32 {
            0
        }
        fn get_line_number(&self) -> i32 {
            0
        }
        fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
            self.attributes.insert(key.into(), value.into());
        }
        fn is_start_with(&self, name: &str) -> bool {
            self.is_start && self.name == name
        }
    }

    struct QueueParser {
        elements: Vec<MockXmlElement>,
        pos: usize,
    }
    impl QueueParser {
        fn new(elements: Vec<MockXmlElement>) -> Self {
            Self { elements, pos: 0 }
        }
    }
    impl XmlPullParser for QueueParser {
        type Element = MockXmlElement;
        fn get_name(&self) -> &str {
            "queue"
        }
        fn get_processing_instruction(&self, _name: &str, _attribute: &str) -> Option<String> {
            None
        }
        fn is_pulling_content(&self) -> bool {
            false
        }
        fn set_pulling_content(&mut self, _pulling_content: bool) {}
        fn has_next(&self) -> bool {
            self.pos < self.elements.len()
        }
        fn peek(&self) -> MockXmlElement {
            self.elements[self.pos].clone()
        }
        fn next(&mut self) -> MockXmlElement {
            let elem = self.elements[self.pos].clone();
            self.pos += 1;
            elem
        }
        fn dispose(&mut self) {}
    }

    #[test]
    fn restore_xml_overrides_defaults_and_populates_size_alignment_map() {
        let mut org = MockOrganization::defaults();
        populate_default_organization(&mut org);

        let mut parser = QueueParser::new(vec![
            MockXmlElement::start("data_organization", 0, &[]),
            MockXmlElement::start("pointer_size", 1, &[("value", "8")]),
            MockXmlElement::end("pointer_size", 1),
            MockXmlElement::start("char_type", 1, &[("signed", "false")]),
            MockXmlElement::end("char_type", 1),
            MockXmlElement::start("size_alignment_map", 1, &[]),
            MockXmlElement::start("entry", 2, &[("size", "16"), ("alignment", "8")]),
            MockXmlElement::end("entry", 2),
            MockXmlElement::end("size_alignment_map", 1),
            MockXmlElement::end("data_organization", 0),
        ]);

        restore_xml(&mut org, &mut parser).unwrap();

        assert_eq!(org.get_pointer_size(), 8);
        assert!(!org.is_signed_char());
        assert_eq!(org.get_size_alignment(16), 8);
        // Pre-populated defaults survive since restoreXml only overrides, never clears.
        assert_eq!(org.get_size_alignment(1), 1);
    }

    #[test]
    fn restore_xml_discards_unported_bitfield_packing_subtree_without_losing_sync() {
        let mut org = MockOrganization::defaults();

        let mut parser = QueueParser::new(vec![
            MockXmlElement::start("data_organization", 0, &[]),
            MockXmlElement::start("bitfield_packing", 1, &[]),
            MockXmlElement::start("use_MS_convention", 2, &[("value", "true")]),
            MockXmlElement::end("use_MS_convention", 2),
            MockXmlElement::end("bitfield_packing", 1),
            MockXmlElement::start("short_size", 1, &[("value", "8")]),
            MockXmlElement::end("short_size", 1),
            MockXmlElement::end("data_organization", 0),
        ]);

        restore_xml(&mut org, &mut parser).unwrap();

        // The bitfield_packing subtree was skipped, but parsing stayed in sync well enough to
        // pick up the sibling element that followed it -- note this uses the raw setter (no
        // cascade into integer_size), matching restoreXml's direct-field-assignment semantics.
        assert_eq!(org.get_short_size(), 8);
        assert_eq!(org.get_integer_size(), DEFAULT_INT_SIZE);
    }
}
