//! Port of `ghidra.app.util.bin.format.dwarf.attribs.DWARFForm`.
//!
//! # Departures from the Java enum
//!
//! * Java attaches constant-specific bodies to the handful of forms that override `getSize` /
//!   `readValue`, and handles the rest in a `switch (this)` inside the base implementation. Both
//!   collapse here into a single `match self` per method, which is the same closed dispatch.
//! * `DW_FORM_string` reads its inline string as UTF-8 rather than through
//!   `DWARFProgram.getCharset()`; the charset plumbing isn't ported yet, matching what
//!   [`DWARFFile::read_v4`](crate::format::dwarf::line::dwarf_file::DWARFFile::read_v4) already
//!   does.
//! * Java's `of()` returns `null` for an unknown form code; this returns [`None`]. The two call
//!   sites inside `DW_FORM_indirect` that would then throw a `NullPointerException` in Java report
//!   an `InvalidData` error naming the unrecognized code instead.
//! * The attribute-class membership of each form is a `&'static [DWARFAttributeClass]` rather than
//!   Java's `EnumSet`; the sets are compile-time constants, and the only query made of them
//!   (`isClass`) is a single-element containment check.

use std::fmt;
use std::io;

use crate::app::util::bin::leb128_info::LEB128Info;
use crate::format::dwarf::attribs::dwarf_attribute_class::DWARFAttributeClass;
use crate::format::dwarf::attribs::dwarf_attribute_value::DWARFAttributeValue;
use crate::format::dwarf::attribs::dwarf_form_context::DWARFFormContext;
use crate::format::seam_stubs::{
    DWARFBlobAttribute, DWARFBooleanAttribute, DWARFIndirectAttribute, DWARFNumericAttribute,
    DWARFStringAttribute,
};

/// Value used as the end of an attribute-spec list. Mirrors `DWARFForm.EOL`.
pub const EOL: i32 = 0;

/// Largest block a `DW_FORM_block*` / `DW_FORM_exprloc` value is allowed to declare. Mirrors
/// `DWARFForm.MAX_BLOCK4_SIZE`.
pub const MAX_BLOCK4_SIZE: u32 = 1024 * 1024;

/// Sentinel [`DWARFForm::raw_size`] value: the size is a LEB128 encoded in the stream.
const LEB128_SIZE: i32 = -3;
/// Sentinel [`DWARFForm::raw_size`] value: the size is the context's DWARF int size.
const DWARF_INTSIZE: i32 = -2;
/// Sentinel [`DWARFForm::raw_size`] value: the size can only be determined by decoding the value.
const DYNAMIC_SIZE: i32 = -1;

use DWARFAttributeClass::{
    AddrPtr, Address, Block, Constant, ExprLoc, Flag, LinePtr, LocList, LocListsPtr, MacPtr,
    Reference, RngList, RngListsPtr, StrOffsetsPtr, String as StringClass,
};

/// DWARF attribute encodings.
///
/// Unknown encodings will prevent deserialization of DIE records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DWARFForm {
    DwFormAddr,
    DwFormBlock2,
    DwFormBlock4,
    DwFormData2,
    DwFormData4,
    DwFormData8,
    DwFormString,
    DwFormBlock,
    DwFormBlock1,
    DwFormData1,
    DwFormFlag,
    DwFormSdata,
    DwFormStrp,
    DwFormUdata,
    DwFormRefAddr,
    DwFormRef1,
    DwFormRef2,
    DwFormRef4,
    DwFormRef8,
    DwFormRefUdata,
    DwFormIndirect,
    DwFormSecOffset,
    DwFormExprloc,
    DwFormFlagPresent,
    DwFormStrx,
    DwFormAddrx,
    DwFormRefSup4,
    DwFormStrpSup,
    DwFormData16,
    DwFormLineStrp,
    DwFormRefSig8,
    DwFormImplicitConst,
    DwFormLoclistx,
    DwFormRnglistx,
    DwFormRefSup8,
    DwFormStrx1,
    DwFormStrx2,
    DwFormStrx3,
    DwFormStrx4,
    DwFormAddrx1,
    DwFormAddrx2,
    DwFormAddrx3,
    DwFormAddrx4,
    DwFormGnuAddrIndex,
    DwFormGnuStrIndex,
    DwFormGnuRefAlt,
    DwFormGnuStrpAlt,
}

impl DWARFForm {
    /// Every form, in Java enum declaration order. Mirrors `DWARFForm.values()`.
    pub const VALUES: [DWARFForm; 47] = [
        Self::DwFormAddr,
        Self::DwFormBlock2,
        Self::DwFormBlock4,
        Self::DwFormData2,
        Self::DwFormData4,
        Self::DwFormData8,
        Self::DwFormString,
        Self::DwFormBlock,
        Self::DwFormBlock1,
        Self::DwFormData1,
        Self::DwFormFlag,
        Self::DwFormSdata,
        Self::DwFormStrp,
        Self::DwFormUdata,
        Self::DwFormRefAddr,
        Self::DwFormRef1,
        Self::DwFormRef2,
        Self::DwFormRef4,
        Self::DwFormRef8,
        Self::DwFormRefUdata,
        Self::DwFormIndirect,
        Self::DwFormSecOffset,
        Self::DwFormExprloc,
        Self::DwFormFlagPresent,
        Self::DwFormStrx,
        Self::DwFormAddrx,
        Self::DwFormRefSup4,
        Self::DwFormStrpSup,
        Self::DwFormData16,
        Self::DwFormLineStrp,
        Self::DwFormRefSig8,
        Self::DwFormImplicitConst,
        Self::DwFormLoclistx,
        Self::DwFormRnglistx,
        Self::DwFormRefSup8,
        Self::DwFormStrx1,
        Self::DwFormStrx2,
        Self::DwFormStrx3,
        Self::DwFormStrx4,
        Self::DwFormAddrx1,
        Self::DwFormAddrx2,
        Self::DwFormAddrx3,
        Self::DwFormAddrx4,
        Self::DwFormGnuAddrIndex,
        Self::DwFormGnuStrIndex,
        Self::DwFormGnuRefAlt,
        Self::DwFormGnuStrpAlt,
    ];

    /// Returns the id of this `DWARFForm`. Mirrors `DWARFForm.getId()`.
    pub fn get_id(&self) -> i32 {
        self.id_and_name().0
    }

    /// The `DW_FORM_*` spelling Java's `Enum.toString()` yields, used in error messages.
    pub fn name(&self) -> &'static str {
        self.id_and_name().1
    }

    fn id_and_name(&self) -> (i32, &'static str) {
        match self {
            Self::DwFormAddr => (0x1, "DW_FORM_addr"),
            Self::DwFormBlock2 => (0x3, "DW_FORM_block2"),
            Self::DwFormBlock4 => (0x4, "DW_FORM_block4"),
            Self::DwFormData2 => (0x5, "DW_FORM_data2"),
            Self::DwFormData4 => (0x6, "DW_FORM_data4"),
            Self::DwFormData8 => (0x7, "DW_FORM_data8"),
            Self::DwFormString => (0x8, "DW_FORM_string"),
            Self::DwFormBlock => (0x9, "DW_FORM_block"),
            Self::DwFormBlock1 => (0xa, "DW_FORM_block1"),
            Self::DwFormData1 => (0xb, "DW_FORM_data1"),
            Self::DwFormFlag => (0xc, "DW_FORM_flag"),
            Self::DwFormSdata => (0xd, "DW_FORM_sdata"),
            Self::DwFormStrp => (0xe, "DW_FORM_strp"),
            Self::DwFormUdata => (0xf, "DW_FORM_udata"),
            Self::DwFormRefAddr => (0x10, "DW_FORM_ref_addr"),
            Self::DwFormRef1 => (0x11, "DW_FORM_ref1"),
            Self::DwFormRef2 => (0x12, "DW_FORM_ref2"),
            Self::DwFormRef4 => (0x13, "DW_FORM_ref4"),
            Self::DwFormRef8 => (0x14, "DW_FORM_ref8"),
            Self::DwFormRefUdata => (0x15, "DW_FORM_ref_udata"),
            Self::DwFormIndirect => (0x16, "DW_FORM_indirect"),
            Self::DwFormSecOffset => (0x17, "DW_FORM_sec_offset"),
            Self::DwFormExprloc => (0x18, "DW_FORM_exprloc"),
            Self::DwFormFlagPresent => (0x19, "DW_FORM_flag_present"),
            Self::DwFormStrx => (0x1a, "DW_FORM_strx"),
            Self::DwFormAddrx => (0x1b, "DW_FORM_addrx"),
            Self::DwFormRefSup4 => (0x1c, "DW_FORM_ref_sup4"),
            Self::DwFormStrpSup => (0x1d, "DW_FORM_strp_sup"),
            Self::DwFormData16 => (0x1e, "DW_FORM_data16"),
            Self::DwFormLineStrp => (0x1f, "DW_FORM_line_strp"),
            Self::DwFormRefSig8 => (0x20, "DW_FORM_ref_sig8"),
            Self::DwFormImplicitConst => (0x21, "DW_FORM_implicit_const"),
            Self::DwFormLoclistx => (0x22, "DW_FORM_loclistx"),
            Self::DwFormRnglistx => (0x23, "DW_FORM_rnglistx"),
            Self::DwFormRefSup8 => (0x24, "DW_FORM_ref_sup8"),
            Self::DwFormStrx1 => (0x25, "DW_FORM_strx1"),
            Self::DwFormStrx2 => (0x26, "DW_FORM_strx2"),
            Self::DwFormStrx3 => (0x27, "DW_FORM_strx3"),
            Self::DwFormStrx4 => (0x28, "DW_FORM_strx4"),
            Self::DwFormAddrx1 => (0x29, "DW_FORM_addrx1"),
            Self::DwFormAddrx2 => (0x2a, "DW_FORM_addrx2"),
            Self::DwFormAddrx3 => (0x2b, "DW_FORM_addrx3"),
            Self::DwFormAddrx4 => (0x2c, "DW_FORM_addrx4"),
            Self::DwFormGnuAddrIndex => (0x1f01, "DW_FORM_gnu_addr_index"),
            Self::DwFormGnuStrIndex => (0x1f02, "DW_FORM_gnu_str_index"),
            Self::DwFormGnuRefAlt => (0x1f20, "DW_FORM_gnu_ref_alt"),
            Self::DwFormGnuStrpAlt => (0x1f21, "DW_FORM_gnu_strp_alt"),
        }
    }

    /// The static size of values of this form, or one of the sentinels [`DYNAMIC_SIZE`],
    /// [`DWARF_INTSIZE`], [`LEB128_SIZE`]. Mirrors the private Java `size` field.
    fn raw_size(&self) -> i32 {
        match self {
            Self::DwFormAddr
            | Self::DwFormBlock2
            | Self::DwFormBlock4
            | Self::DwFormString
            | Self::DwFormBlock
            | Self::DwFormBlock1
            | Self::DwFormIndirect
            | Self::DwFormExprloc => DYNAMIC_SIZE,

            Self::DwFormSdata
            | Self::DwFormUdata
            | Self::DwFormRefUdata
            | Self::DwFormStrx
            | Self::DwFormAddrx
            | Self::DwFormLoclistx
            | Self::DwFormRnglistx
            | Self::DwFormGnuAddrIndex
            | Self::DwFormGnuStrIndex => LEB128_SIZE,

            Self::DwFormStrp
            | Self::DwFormRefAddr
            | Self::DwFormSecOffset
            | Self::DwFormStrpSup
            | Self::DwFormLineStrp
            | Self::DwFormGnuRefAlt
            | Self::DwFormGnuStrpAlt => DWARF_INTSIZE,

            Self::DwFormFlagPresent | Self::DwFormImplicitConst => 0,

            Self::DwFormData1
            | Self::DwFormFlag
            | Self::DwFormRef1
            | Self::DwFormStrx1
            | Self::DwFormAddrx1 => 1,

            Self::DwFormData2 | Self::DwFormRef2 | Self::DwFormStrx2 | Self::DwFormAddrx2 => 2,

            Self::DwFormStrx3 | Self::DwFormAddrx3 => 3,

            Self::DwFormData4
            | Self::DwFormRef4
            | Self::DwFormRefSup4
            | Self::DwFormStrx4
            | Self::DwFormAddrx4 => 4,

            Self::DwFormData8 | Self::DwFormRef8 | Self::DwFormRefSig8 | Self::DwFormRefSup8 => 8,

            Self::DwFormData16 => 16,
        }
    }

    /// The attribute classes this form may encode. Mirrors `DWARFForm.getFormClasses()`.
    pub fn get_form_classes(&self) -> &'static [DWARFAttributeClass] {
        match self {
            Self::DwFormAddr
            | Self::DwFormAddrx
            | Self::DwFormAddrx1
            | Self::DwFormAddrx2
            | Self::DwFormAddrx3
            | Self::DwFormAddrx4
            | Self::DwFormGnuAddrIndex => &[Address],

            Self::DwFormBlock2 | Self::DwFormBlock4 | Self::DwFormBlock | Self::DwFormBlock1 => {
                &[Block]
            }

            Self::DwFormData1
            | Self::DwFormData2
            | Self::DwFormData4
            | Self::DwFormData8
            | Self::DwFormData16
            | Self::DwFormSdata
            | Self::DwFormUdata => &[Constant],

            Self::DwFormString
            | Self::DwFormStrp
            | Self::DwFormStrx
            | Self::DwFormStrpSup
            | Self::DwFormLineStrp
            | Self::DwFormStrx1
            | Self::DwFormStrx2
            | Self::DwFormStrx3
            | Self::DwFormStrx4
            | Self::DwFormGnuStrIndex
            | Self::DwFormGnuStrpAlt => &[StringClass],

            Self::DwFormRefAddr
            | Self::DwFormRef1
            | Self::DwFormRef2
            | Self::DwFormRef4
            | Self::DwFormRef8
            | Self::DwFormRefSup4
            | Self::DwFormRefSig8
            | Self::DwFormRefSup8
            | Self::DwFormGnuRefAlt => &[Reference],

            Self::DwFormFlag | Self::DwFormFlagPresent => &[Flag],

            Self::DwFormRefUdata => &[Constant, Reference],

            Self::DwFormExprloc => &[ExprLoc],
            Self::DwFormLoclistx => &[LocList],
            Self::DwFormRnglistx => &[RngList],

            Self::DwFormSecOffset => &[
                AddrPtr,
                LinePtr,
                LocList,
                LocListsPtr,
                MacPtr,
                RngList,
                RngListsPtr,
                StrOffsetsPtr,
            ],

            // The value class of an indirect form depends on the form it forwards to, and an
            // implicit const carries its value in the abbreviation rather than the stream.
            Self::DwFormIndirect | Self::DwFormImplicitConst => &[],
        }
    }

    /// Returns true if `attr_class` is the *only* class this form can encode. Mirrors
    /// `DWARFForm.isClass(DWARFAttributeClass)`, which deliberately rejects ambiguous forms such
    /// as `DW_FORM_ref_udata` (constant *and* reference).
    pub fn is_class(&self, attr_class: DWARFAttributeClass) -> bool {
        let classes = self.get_form_classes();
        classes.len() == 1 && classes[0] == attr_class
    }

    /// Find the form given its raw int id. Mirrors `DWARFForm.of(int)`, returning `None` where
    /// Java returns `null`.
    pub fn of(key: i32) -> Option<DWARFForm> {
        Self::VALUES.into_iter().find(|form| form.get_id() == key)
    }

    /// Returns the size the attribute value occupies in the stream, mirroring
    /// `DWARFForm.getSize(DWARFFormContext)`.
    ///
    /// Forms whose size can only be known by decoding part of the value read from `context`; the
    /// rest answer from the static size, the context's DWARF int size, or a LEB128 in the stream.
    pub fn get_size(&self, context: &mut DWARFFormContext) -> io::Result<i64> {
        match self {
            Self::DwFormAddr => Ok(context.comp_unit.get_pointer_size() as i64),

            Self::DwFormBlock2 => {
                let array_size = context.reader.read_next_unsigned_short()?;
                Ok(2 /* sizeof short */ + array_size as i64)
            }

            Self::DwFormBlock4 => {
                let array_size = context.reader.read_next_unsigned_int_exact()?;
                Ok(4 /* sizeof int */ + array_size as i64)
            }

            Self::DwFormString => {
                let start = context.reader.get_pointer_index();
                context.reader.read_next_utf8_string()?;
                Ok((context.reader.get_pointer_index() - start) as i64)
            }

            Self::DwFormBlock => {
                let uleb128 = LEB128Info::unsigned(&mut *context.reader)?;
                Ok(uleb128.get_length() as i64 + uleb128.as_u_int32()? as i64)
            }

            Self::DwFormBlock1 => {
                let length = context.reader.read_next_unsigned_byte()?;
                Ok(1 /* sizeof byte */ + length as i64)
            }

            Self::DwFormIndirect => {
                let start = context.reader.get_pointer_index();
                let indirect_form = Self::read_indirect_form(context)?;
                let first_size = context.reader.get_pointer_index() - start;

                let indirect_def = context.def.with_form(indirect_form);
                let mut indirect_context = DWARFFormContext::new(
                    &mut *context.reader,
                    context.comp_unit,
                    indirect_def.as_ref(),
                    context.dwarf_int_size,
                );
                let indirect_size = indirect_form.get_size(&mut indirect_context)?;

                Ok(first_size as i64 + indirect_size)
            }

            Self::DwFormExprloc => {
                let uleb128 = LEB128Info::unsigned(&mut *context.reader)?;
                Ok(uleb128.get_length() as i64 + uleb128.as_int32()? as i64)
            }

            _ => match self.raw_size() {
                DWARF_INTSIZE => Ok(context.dwarf_int_size as i64),
                LEB128_SIZE => Ok(LEB128Info::unsigned(&mut *context.reader)?.get_length() as i64),
                DYNAMIC_SIZE => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unimplemented size for {self}"),
                )),
                size => Ok(size as i64),
            },
        }
    }

    /// Reads a DIE attribute value from a stream. Mirrors
    /// `DWARFForm.readValue(DWARFFormContext)`.
    pub fn read_value(
        &self,
        context: &mut DWARFFormContext,
    ) -> io::Result<Box<dyn DWARFAttributeValue>> {
        // Only meaningful for the fixed-size forms below, which is exactly where Java's base
        // `readValue` reads the private `size` field.
        let size = self.raw_size();

        match self {
            Self::DwFormAddr => {
                let ptr_size = context.comp_unit.get_pointer_size();
                let value = context.reader.read_next_unsigned_value(ptr_size as usize)?;
                Ok(Box::new(DWARFNumericAttribute::with_bit_length(
                    ptr_size as i32 * 8,
                    value as i64,
                    false,
                )))
            }

            Self::DwFormBlock2 => {
                let length = context.reader.read_next_unsigned_short()?;
                Self::read_blob(context, length)
            }

            Self::DwFormBlock4 => {
                let length = context.reader.read_next_unsigned_int_exact()?;
                Self::check_block_size(length, "dw_form_block4")?;
                Self::read_blob(context, length)
            }

            Self::DwFormString => {
                let s = context.reader.read_next_utf8_string()?;
                Ok(Box::new(DWARFStringAttribute::new(s)))
            }

            Self::DwFormBlock => {
                let length = LEB128Info::unsigned(&mut *context.reader)?.as_u_int32()?;
                Self::check_block_size(length, "dw_form_block")?;
                Self::read_blob(context, length)
            }

            Self::DwFormBlock1 => {
                let length = context.reader.read_next_unsigned_byte()?;
                Self::read_blob(context, length as u32)
            }

            Self::DwFormFlag => Ok(Box::new(DWARFBooleanAttribute::new(
                context.reader.read_next_byte()? != 0,
            ))),

            Self::DwFormSdata => {
                let value = LEB128Info::signed(&mut *context.reader)?.as_long();
                Ok(Box::new(DWARFNumericAttribute::with_bit_length(64, value, true)))
            }

            Self::DwFormUdata => {
                let value = LEB128Info::unsigned(&mut *context.reader)?.as_long();
                Ok(Box::new(DWARFNumericAttribute::with_bit_length(64, value, false)))
            }

            Self::DwFormIndirect => {
                let indirect_form = Self::read_indirect_form(context)?;
                let indirect_def = context.def.with_form(indirect_form);
                let mut indirect_context = DWARFFormContext::new(
                    &mut *context.reader,
                    context.comp_unit,
                    indirect_def.as_ref(),
                    context.dwarf_int_size,
                );
                indirect_form.read_value(&mut indirect_context)
            }

            // Offset in a section other than .debug_info or .debug_str.
            Self::DwFormSecOffset => {
                let int_size = context.dwarf_int_size;
                let addr = context.reader.read_next_unsigned_value(int_size as usize)?;
                Ok(Box::new(DWARFNumericAttribute::with_bit_length(
                    int_size * 8,
                    addr as i64,
                    false,
                )))
            }

            Self::DwFormExprloc => {
                let length = LEB128Info::unsigned(&mut *context.reader)?.as_u_int32()?;
                Self::check_block_size(length, "dw_form_exprloc")?;
                Self::read_blob(context, length)
            }

            Self::DwFormFlagPresent => Ok(Box::new(DWARFBooleanAttribute::new(true))),

            Self::DwFormData16 => {
                let bytes = context.reader.read_next_byte_array(16)?;
                Ok(Box::new(DWARFBlobAttribute::new(bytes)))
            }

            Self::DwFormImplicitConst => Ok(Box::new(DWARFNumericAttribute::with_bit_length(
                64,
                context.def.get_implicit_value(),
                true,
            ))),

            Self::DwFormLoclistx | Self::DwFormRnglistx => {
                let index = LEB128Info::unsigned(&mut *context.reader)?.as_long();
                Ok(Box::new(DWARFIndirectAttribute::new(index)))
            }

            Self::DwFormAddrx1 | Self::DwFormAddrx2 | Self::DwFormAddrx3 | Self::DwFormAddrx4 => {
                let index = context.reader.read_next_unsigned_value(size as usize)?;
                Ok(Box::new(DWARFIndirectAttribute::new(index as i64)))
            }

            Self::DwFormAddrx | Self::DwFormGnuAddrIndex => {
                let index = LEB128Info::unsigned(&mut *context.reader)?.as_u_int32()?;
                Ok(Box::new(DWARFIndirectAttribute::new(index as i64)))
            }

            Self::DwFormData1 | Self::DwFormData2 | Self::DwFormData4 | Self::DwFormData8 => {
                let value = context.reader.read_next_value(size as usize)?;
                Ok(Box::new(DWARFNumericAttribute::with_ambiguous_signedness(
                    size * 8,
                    value,
                    true,
                    true,
                )))
            }

            Self::DwFormRef1 | Self::DwFormRef2 | Self::DwFormRef4 | Self::DwFormRef8 => {
                let uoffset = context.reader.read_next_unsigned_value(size as usize)?;
                Ok(Box::new(DWARFNumericAttribute::with_bit_length(
                    size * 8,
                    uoffset as i64,
                    false,
                )))
            }

            Self::DwFormRefAddr | Self::DwFormGnuRefAlt => {
                let int_size = context.dwarf_int_size;
                let addr = context.reader.read_next_unsigned_value(int_size as usize)?;
                Ok(Box::new(DWARFNumericAttribute::with_bit_length(
                    int_size * 8,
                    addr as i64,
                    false,
                )))
            }

            Self::DwFormRefUdata => {
                let uoffset = LEB128Info::unsigned(&mut *context.reader)?.as_long();
                Ok(Box::new(DWARFNumericAttribute::with_bit_length(64, uoffset, false)))
            }

            Self::DwFormStrx1 | Self::DwFormStrx2 | Self::DwFormStrx3 | Self::DwFormStrx4 => {
                let index = context.reader.read_next_unsigned_value(size as usize)?;
                Self::read_string(context, *self, index)
            }

            Self::DwFormStrp | Self::DwFormLineStrp | Self::DwFormGnuStrpAlt => {
                let offset =
                    context.reader.read_next_unsigned_value(context.dwarf_int_size as usize)?;
                Self::read_string(context, *self, offset)
            }

            Self::DwFormStrx | Self::DwFormGnuStrIndex => {
                let index = LEB128Info::unsigned(&mut *context.reader)?.as_u_int32()?;
                Self::read_string(context, *self, index as u64)
            }

            // Mirrors the `default:` arm of Java's switch, which throws
            // IllegalArgumentException for the forms Ghidra has not implemented reading yet.
            Self::DwFormRefSup4
            | Self::DwFormStrpSup
            | Self::DwFormRefSig8
            | Self::DwFormRefSup8 => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unsupported DWARF Form: {self}"),
            )),
        }
    }

    /// Reads the form code that a `DW_FORM_indirect` value forwards to.
    fn read_indirect_form(context: &mut DWARFFormContext) -> io::Result<DWARFForm> {
        let indirect_form_int = LEB128Info::unsigned(&mut *context.reader)?.as_u_int32()?;
        DWARFForm::of(indirect_form_int as i32).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unknown DWARF Form referenced by DW_FORM_indirect: {indirect_form_int:#x}"),
            )
        })
    }

    fn check_block_size(length: u32, form_name: &str) -> io::Result<()> {
        if length > MAX_BLOCK4_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid/bad {form_name} size: {length}"),
            ));
        }
        Ok(())
    }

    fn read_blob(
        context: &mut DWARFFormContext,
        length: u32,
    ) -> io::Result<Box<dyn DWARFAttributeValue>> {
        let bytes = context.reader.read_next_byte_array(length as usize)?;
        Ok(Box::new(DWARFBlobAttribute::new(bytes)))
    }

    /// Resolves a string offset/index through the compilation unit's DIE container.
    ///
    /// # Panics
    /// Panics if the compilation unit has no DIE container, mirroring the Java
    /// `NullPointerException` from `context.dieContainer().getString(...)`.
    fn read_string(
        context: &mut DWARFFormContext,
        form: DWARFForm,
        offset: u64,
    ) -> io::Result<Box<dyn DWARFAttributeValue>> {
        let container = context.die_container().expect(
            "DWARFFormContext.dieContainer: cu has no DIE container (mirrors a Java \
             NullPointerException)",
        );
        let s = container.get_string(form, offset, context.comp_unit)?;
        Ok(Box::new(DWARFStringAttribute::new(s)))
    }
}

impl fmt::Display for DWARFForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::bin::binary_reader::BinaryReader;
    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use crate::format::seam_stubs::{DIEContainer, DWARFAttributeDef, DWARFCompilationUnit};
    use std::cell::RefCell;
    use std::rc::Rc;

    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start.checked_add(length).unwrap_or(usize::MAX);
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
    }

    struct TestReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        index: u64,
    }

    impl TestReader {
        fn new(bytes: Vec<u8>) -> Self {
            TestReader { provider: Rc::new(RefCell::new(VecProvider(bytes))), index: 0 }
        }
    }

    impl BinaryReader for TestReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn get_pointer_index(&self) -> u64 {
            self.index
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let prev = self.index;
            self.index = index;
            prev
        }
        fn is_little_endian(&self) -> bool {
            true
        }
        fn set_little_endian(&mut self, _is_little_endian: bool) {}
        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }
        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            Rc::clone(&self.provider)
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(TestReader { provider: Rc::clone(&self.provider), index: new_index })
        }
    }

    /// A DIE container whose string table is a fixed list, indexed/offset by the value the form
    /// read out of the stream.
    struct MockDIEContainer {
        strings: Vec<(u64, String)>,
    }

    impl DIEContainer for MockDIEContainer {
        fn get_debug_line_reader(&self) -> Option<Box<dyn BinaryReader>> {
            None
        }
        fn get_string(
            &self,
            _form: DWARFForm,
            offset: u64,
            _cu: &dyn DWARFCompilationUnit,
        ) -> io::Result<String> {
            self.strings
                .iter()
                .find(|(key, _)| *key == offset)
                .map(|(_, s)| s.clone())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no such string"))
        }
    }

    struct MockCompUnit {
        pointer_size: i8,
        container: Option<MockDIEContainer>,
    }

    impl MockCompUnit {
        fn new() -> Self {
            MockCompUnit { pointer_size: 4, container: None }
        }
        fn with_strings(strings: Vec<(u64, &str)>) -> Self {
            MockCompUnit {
                pointer_size: 4,
                container: Some(MockDIEContainer {
                    strings: strings.into_iter().map(|(k, s)| (k, s.to_string())).collect(),
                }),
            }
        }
    }

    impl DWARFCompilationUnit for MockCompUnit {
        fn get_dwarf_version(&self) -> i16 {
            5
        }
        fn get_pointer_size(&self) -> i8 {
            self.pointer_size
        }
        fn get_die_container(&self) -> Option<&dyn DIEContainer> {
            self.container.as_ref().map(|c| c as &dyn DIEContainer)
        }
    }

    struct MockAttrDef {
        form: DWARFForm,
        implicit_value: i64,
    }

    impl MockAttrDef {
        fn new(form: DWARFForm) -> Self {
            MockAttrDef { form, implicit_value: -1 }
        }
    }

    impl DWARFAttributeDef for MockAttrDef {
        fn get_attribute_form(&self) -> DWARFForm {
            self.form
        }
        fn get_implicit_value(&self) -> i64 {
            self.implicit_value
        }
    }

    fn numeric_value(value: &dyn DWARFAttributeValue) -> i64 {
        value
            .as_any()
            .downcast_ref::<DWARFNumericAttribute>()
            .expect("expected a DWARFNumericAttribute")
            .get_value()
    }

    #[test]
    fn ids_match_the_dwarf_spec_and_of_round_trips() {
        // Spot-check ids against the DWARF standard / the Java enum's declarations.
        assert_eq!(DWARFForm::DwFormAddr.get_id(), 0x1);
        assert_eq!(DWARFForm::DwFormStrp.get_id(), 0xe);
        assert_eq!(DWARFForm::DwFormSecOffset.get_id(), 0x17);
        assert_eq!(DWARFForm::DwFormAddrx4.get_id(), 0x2c);
        assert_eq!(DWARFForm::DwFormGnuStrpAlt.get_id(), 0x1f21);

        for form in DWARFForm::VALUES {
            assert_eq!(DWARFForm::of(form.get_id()), Some(form), "of() round trip for {form}");
        }

        // 0x2 is the DWARF v1 DW_FORM_ref, which Ghidra's enum deliberately omits.
        assert_eq!(DWARFForm::of(0x2), None);
        assert_eq!(DWARFForm::of(0x7fff), None);
    }

    #[test]
    fn is_class_only_holds_for_unambiguous_forms() {
        assert!(DWARFForm::DwFormAddr.is_class(DWARFAttributeClass::Address));
        assert!(!DWARFForm::DwFormAddr.is_class(DWARFAttributeClass::Constant));
        assert!(DWARFForm::DwFormExprloc.is_class(DWARFAttributeClass::ExprLoc));

        // DW_FORM_ref_udata is declared as both constant and reference, so isClass() is false for
        // each of them.
        assert!(!DWARFForm::DwFormRefUdata.is_class(DWARFAttributeClass::Constant));
        assert!(!DWARFForm::DwFormRefUdata.is_class(DWARFAttributeClass::Reference));

        // DW_FORM_sec_offset carries eight classes, so no single one identifies it either.
        assert!(!DWARFForm::DwFormSecOffset.is_class(DWARFAttributeClass::LinePtr));
    }

    #[test]
    fn get_size_handles_static_dwarf_int_and_leb128_sizes() {
        let cu = MockCompUnit::new();
        let def = MockAttrDef::new(DWARFForm::DwFormData4);

        // Static size: no bytes are consumed.
        let mut reader = TestReader::new(vec![]);
        let mut ctx = DWARFFormContext::new(&mut reader, &cu, &def, 4);
        assert_eq!(DWARFForm::DwFormData4.get_size(&mut ctx).unwrap(), 4);
        assert_eq!(DWARFForm::DwFormFlagPresent.get_size(&mut ctx).unwrap(), 0);

        // DWARF_INTSIZE forms report the context's int size, not their own.
        let mut reader = TestReader::new(vec![]);
        let mut ctx = DWARFFormContext::new(&mut reader, &cu, &def, 8);
        assert_eq!(DWARFForm::DwFormStrp.get_size(&mut ctx).unwrap(), 8);

        // LEB128_SIZE forms report the *encoded length* of the value in the stream: 0x80 0x01 is
        // a two byte ULEB128.
        let mut reader = TestReader::new(vec![0x80, 0x01]);
        let mut ctx = DWARFFormContext::new(&mut reader, &cu, &def, 4);
        assert_eq!(DWARFForm::DwFormUdata.get_size(&mut ctx).unwrap(), 2);
        assert_eq!(reader.get_pointer_index(), 2);

        // DW_FORM_addr's size is the compilation unit's pointer size.
        let mut reader = TestReader::new(vec![]);
        let mut ctx = DWARFFormContext::new(&mut reader, &cu, &def, 4);
        assert_eq!(DWARFForm::DwFormAddr.get_size(&mut ctx).unwrap(), 4);
    }

    #[test]
    fn get_size_of_block_forms_includes_the_length_prefix() {
        let cu = MockCompUnit::new();
        let def = MockAttrDef::new(DWARFForm::DwFormBlock2);

        // block2: 2 byte length prefix + 3 payload bytes.
        let mut reader = TestReader::new(vec![0x03, 0x00, 0xaa, 0xbb, 0xcc]);
        let mut ctx = DWARFFormContext::new(&mut reader, &cu, &def, 4);
        assert_eq!(DWARFForm::DwFormBlock2.get_size(&mut ctx).unwrap(), 5);

        // block1: 1 byte length prefix + 3 payload bytes.
        let mut reader = TestReader::new(vec![0x03, 0xaa, 0xbb, 0xcc]);
        let mut ctx = DWARFFormContext::new(&mut reader, &cu, &def, 4);
        assert_eq!(DWARFForm::DwFormBlock1.get_size(&mut ctx).unwrap(), 4);

        // block: 1 byte ULEB128 length prefix + 3 payload bytes.
        let mut reader = TestReader::new(vec![0x03, 0xaa, 0xbb, 0xcc]);
        let mut ctx = DWARFFormContext::new(&mut reader, &cu, &def, 4);
        assert_eq!(DWARFForm::DwFormBlock.get_size(&mut ctx).unwrap(), 4);

        // string: the size is the whole NUL terminated string.
        let mut reader = TestReader::new(b"abc\0rest".to_vec());
        let mut ctx = DWARFFormContext::new(&mut reader, &cu, &def, 4);
        assert_eq!(DWARFForm::DwFormString.get_size(&mut ctx).unwrap(), 4);
    }

    #[test]
    fn read_value_decodes_numeric_forms() {
        let cu = MockCompUnit::new();
        let def = MockAttrDef::new(DWARFForm::DwFormData4);

        let mut reader = TestReader::new(vec![0x78, 0x56, 0x34, 0x12]);
        let mut ctx = DWARFFormContext::new(&mut reader, &cu, &def, 4);
        let value = DWARFForm::DwFormData4.read_value(&mut ctx).unwrap();
        assert_eq!(numeric_value(value.as_ref()), 0x1234_5678);
        assert_eq!(reader.get_pointer_index(), 4);

        // DW_FORM_sec_offset reads dwarfIntSize bytes, so the same 4 bytes read as 8 under a
        // 64-bit-DWARF context would run off the end.
        let mut reader = TestReader::new(vec![0x04, 0x00, 0x00, 0x00]);
        let mut ctx = DWARFFormContext::new(&mut reader, &cu, &def, 4);
        let value = DWARFForm::DwFormSecOffset.read_value(&mut ctx).unwrap();
        assert_eq!(numeric_value(value.as_ref()), 4);

        // DW_FORM_sdata is a signed LEB128: 0x7f encodes -1.
        let mut reader = TestReader::new(vec![0x7f]);
        let mut ctx = DWARFFormContext::new(&mut reader, &cu, &def, 4);
        let value = DWARFForm::DwFormSdata.read_value(&mut ctx).unwrap();
        assert_eq!(numeric_value(value.as_ref()), -1);

        // ...while DW_FORM_udata reads the same byte as unsigned 127.
        let mut reader = TestReader::new(vec![0x7f]);
        let mut ctx = DWARFFormContext::new(&mut reader, &cu, &def, 4);
        let value = DWARFForm::DwFormUdata.read_value(&mut ctx).unwrap();
        assert_eq!(numeric_value(value.as_ref()), 127);
    }

    #[test]
    fn read_value_decodes_flags_blobs_and_strings() {
        let cu = MockCompUnit::new();
        let def = MockAttrDef::new(DWARFForm::DwFormFlag);

        let mut reader = TestReader::new(vec![0x01]);
        let mut ctx = DWARFFormContext::new(&mut reader, &cu, &def, 4);
        let value = DWARFForm::DwFormFlag.read_value(&mut ctx).unwrap();
        assert!(value.as_any().downcast_ref::<DWARFBooleanAttribute>().unwrap().get_value());

        // DW_FORM_flag_present consumes nothing and is always true.
        let mut reader = TestReader::new(vec![]);
        let mut ctx = DWARFFormContext::new(&mut reader, &cu, &def, 4);
        let value = DWARFForm::DwFormFlagPresent.read_value(&mut ctx).unwrap();
        assert!(value.as_any().downcast_ref::<DWARFBooleanAttribute>().unwrap().get_value());
        assert_eq!(reader.get_pointer_index(), 0);

        // DW_FORM_block1: 1 byte length prefix, then that many payload bytes.
        let mut reader = TestReader::new(vec![0x02, 0xde, 0xad, 0xbe]);
        let mut ctx = DWARFFormContext::new(&mut reader, &cu, &def, 4);
        let value = DWARFForm::DwFormBlock1.read_value(&mut ctx).unwrap();
        assert_eq!(
            value.as_any().downcast_ref::<DWARFBlobAttribute>().unwrap().get_bytes(),
            &[0xde, 0xad]
        );
        assert_eq!(reader.get_pointer_index(), 3);

        // DW_FORM_string is an inline NUL terminated string.
        let mut reader = TestReader::new(b"main.c\0".to_vec());
        let mut ctx = DWARFFormContext::new(&mut reader, &cu, &def, 4);
        let value = DWARFForm::DwFormString.read_value(&mut ctx).unwrap();
        assert_eq!(
            value.as_any().downcast_ref::<DWARFStringAttribute>().unwrap().get_value(&cu),
            "main.c"
        );
    }

    #[test]
    fn read_value_resolves_indexed_strings_through_the_die_container() {
        let cu = MockCompUnit::with_strings(vec![(0x10, "hello")]);
        let def = MockAttrDef::new(DWARFForm::DwFormStrp);

        // DW_FORM_strp reads a dwarfIntSize offset and hands it to the DIE container.
        let mut reader = TestReader::new(vec![0x10, 0x00, 0x00, 0x00]);
        let mut ctx = DWARFFormContext::new(&mut reader, &cu, &def, 4);
        let value = DWARFForm::DwFormStrp.read_value(&mut ctx).unwrap();
        assert_eq!(
            value.as_any().downcast_ref::<DWARFStringAttribute>().unwrap().get_value(&cu),
            "hello"
        );

        // DW_FORM_strx1 reads a single byte index instead.
        let mut reader = TestReader::new(vec![0x10]);
        let mut ctx = DWARFFormContext::new(&mut reader, &cu, &def, 4);
        let value = DWARFForm::DwFormStrx1.read_value(&mut ctx).unwrap();
        assert_eq!(
            value.as_any().downcast_ref::<DWARFStringAttribute>().unwrap().get_value(&cu),
            "hello"
        );
        assert_eq!(reader.get_pointer_index(), 1);
    }

    #[test]
    fn implicit_const_takes_its_value_from_the_attribute_def() {
        let cu = MockCompUnit::new();
        let def = MockAttrDef { form: DWARFForm::DwFormImplicitConst, implicit_value: 42 };

        let mut reader = TestReader::new(vec![]);
        let mut ctx = DWARFFormContext::new(&mut reader, &cu, &def, 4);
        let value = DWARFForm::DwFormImplicitConst.read_value(&mut ctx).unwrap();

        assert_eq!(numeric_value(value.as_ref()), 42);
        // Nothing was consumed from the stream.
        assert_eq!(reader.get_pointer_index(), 0);
    }

    #[test]
    fn indirect_form_delegates_to_the_form_it_names() {
        let cu = MockCompUnit::new();
        let def = MockAttrDef::new(DWARFForm::DwFormIndirect);

        // ULEB128 0x0b (DW_FORM_data1), then the data1 payload.
        let mut reader = TestReader::new(vec![0x0b, 0x2a]);
        let mut ctx = DWARFFormContext::new(&mut reader, &cu, &def, 4);
        let value = DWARFForm::DwFormIndirect.read_value(&mut ctx).unwrap();
        assert_eq!(numeric_value(value.as_ref()), 42);
        assert_eq!(reader.get_pointer_index(), 2);

        // getSize sums the form code's own length and the delegated form's size.
        let mut reader = TestReader::new(vec![0x0b, 0x2a]);
        let mut ctx = DWARFFormContext::new(&mut reader, &cu, &def, 4);
        assert_eq!(DWARFForm::DwFormIndirect.get_size(&mut ctx).unwrap(), 2);

        // An unrecognized indirect form code is reported rather than silently skipped.
        let mut reader = TestReader::new(vec![0x02]);
        let mut ctx = DWARFFormContext::new(&mut reader, &cu, &def, 4);
        assert!(DWARFForm::DwFormIndirect.read_value(&mut ctx).is_err());
    }

    #[test]
    fn oversized_blocks_and_unimplemented_forms_are_rejected() {
        let cu = MockCompUnit::new();
        let def = MockAttrDef::new(DWARFForm::DwFormBlock4);

        // A block4 declaring more than MAX_BLOCK4_SIZE bytes is refused before any read.
        let mut reader = TestReader::new(vec![0x00, 0x00, 0xff, 0x00]);
        let mut ctx = DWARFFormContext::new(&mut reader, &cu, &def, 4);
        let err = DWARFForm::DwFormBlock4
            .read_value(&mut ctx)
            .err()
            .expect("a block4 larger than MAX_BLOCK4_SIZE must be rejected");
        assert!(err.to_string().contains("dw_form_block4"), "{err}");

        // Ghidra does not implement reading the supplementary-object forms.
        let mut reader = TestReader::new(vec![0; 8]);
        let mut ctx = DWARFFormContext::new(&mut reader, &cu, &def, 4);
        let err = DWARFForm::DwFormRefSig8
            .read_value(&mut ctx)
            .err()
            .expect("DW_FORM_ref_sig8 reading is not implemented");
        assert!(err.to_string().contains("DW_FORM_ref_sig8"), "{err}");
    }
}
