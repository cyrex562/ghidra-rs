//! Port of `ghidra.program.database.data.BitFieldDBDataType`, "for `DataTypeManagerDB` use".
//!
//! The Java class `extends BitFieldDataType` (the already-ported
//! [`BitFieldDataType`](crate::program::model::data::bit_field_data_type::BitFieldDataType)) and
//! adds exactly two capabilities on top of it: encoding a bit-field's base type/bit-size/bit-offset
//! into a compact `long` ID ([`get_id`]), and reconstructing a bit-field from that ID
//! ([`get_bit_field_data_type`]). It overrides **no** [`DataType`] method at all -- every other
//! behavior (`getName`, `getLength`, `isEquivalent`, `clone`, `getRepresentation`, ...) is
//! inherited from `BitFieldDataType` completely unchanged.
//!
//! Per this session's established "extends X" convention (see `data_type_proxy_component_db.rs`,
//! `typedef_db.rs`), this is ported as composition -- a `base: BitFieldDataType` field -- rather
//! than inheritance, with [`DataType`] re-implemented by delegating every method to `self.base`.
//!
//! # `clone`/`copy` are inherited **unchanged**, and downgrade to a plain `BitFieldDataType`
//!
//! This is the "inherited-not-overridden" subtlety this session's driver prompt calls out by name
//! (see `data_type_proxy_component_db.rs`'s module docs for the identical class of issue).
//! `BitFieldDataType.clone(DataTypeManager)`/`.copy(DataTypeManager)` are written in Java to
//! construct a `new BitFieldDataType(...)` **by that literal class name**, not
//! `getClass().getConstructor(...)` or any other `this`-relative mechanism. Since
//! `BitFieldDBDataType` does not override `clone`/`copy`, calling either on a live
//! `BitFieldDBDataType` in Java returns a plain `BitFieldDataType` object -- **not** another
//! `BitFieldDBDataType` -- silently losing the ID-encoding capability. This port reproduces that
//! faithfully: [`DataType::clone_data_type`]/[`DataType::copy_data_type`] on
//! [`BitFieldDbDataType`] delegate to `self.base.clone_data_type(dtm)`, which returns a
//! `Box<dyn DataType>` wrapping a plain [`BitFieldDataType`], not a [`BitFieldDbDataType`]. A
//! caller that needs a DB-resolvable clone must re-derive one by calling [`get_id`]/
//! [`get_bit_field_data_type`] again through the owning `DataTypeManagerDB`, exactly as Java
//! requires.
//!
//! # `as_bit_field_data_type`/`is_equivalent` delegate to a *real*, owned `&BitFieldDataType`
//!
//! Unlike [`DataTypeComponentDB`](super::data_type_component_db::DataTypeComponentDB)'s
//! documented "no live back-reference" limitation (an *owned Vec element* cannot also hold a live
//! handle back to its owner), [`BitFieldDbDataType::base`] is a plain, fully-owned field -- there
//! is no aliasing hazard in handing back `&self.base`. [`DataType::as_bit_field_data_type`]
//! therefore returns `Some(&self.base)` for real, and [`DataType::is_equivalent`] simply forwards
//! to `self.base.is_equivalent(...)`, giving exactly the same behavior a plain `BitFieldDataType`
//! would (matching Java, which inherits `isEquivalent` unchanged).
//!
//! # `DataTypeManagerDB`'s un-ported table-id encoding constants
//!
//! `getId`/`getBitFieldDataType` reconstruct/consult raw `DataTypeManagerDB` row IDs via three
//! `DataTypeManagerDB`-internal `static final int` constants (`TYPEDEF = 5`, `ENUM = 8`,
//! `BUILT_IN = 0`) and `DATA_TYPE_KIND_SHIFT = 56`. None of these have a ported home yet --
//! [`DataTypeManagerDb`](super::data_type_manager_db::DataTypeManagerDb) (this crate's promoted
//! cut-point trait for `DataTypeManagerDB`) does not declare them, and no other file in
//! `program/database/data` reproduces this ID-encoding scheme yet either. Rather than editing that
//! shared, already-ported trait to add table-id plumbing no other port currently needs, this
//! module defines its own private mirrors of the four Java constants (see
//! [`DTM_TYPEDEF`]/[`DTM_ENUM`]/[`DTM_BUILT_IN`]/[`DTM_DATA_TYPE_KIND_SHIFT`]), with their exact
//! Java values, scoped to this file only.
//!
//! # `IntegerDataType.dataType` fallback has no concrete singleton yet
//!
//! `getBitFieldDataType`'s failure-to-resolve fallback constructs
//! `IntegerDataType.dataType.clone(dtm)` -- but `IntegerDataType` was itself promoted to a
//! trait-only cut-point in this crate with **no concrete singleton** (see `integer_data_type.rs`'s
//! own module docs: "Static state not translated: the `dataType` singleton (needs a concrete
//! struct)"). [`IntegerFallbackDataType`] is a small, local stand-in reproducing just the surface
//! that call site and [`is_valid_base_data_type`](crate::program::model::data::bit_field_data_type::is_valid_base_data_type)
//! actually need (`get_name() == "int"`, `get_length()` from the manager's
//! `DataOrganization::get_integer_size()`, `is_integer_type()`/`is_signed_integer_type()` both
//! `true`) -- mirroring the `DefaultDataTypeStandIn`/`MissingDataType`/`BadDataTypeStandIn`
//! precedent already established throughout `program/database/data` for exactly this class of gap.

use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::database::data::data_type_manager_db::DataTypeManagerDb;
use crate::program::model::data::bit_field_data_type::{
    get_minimum_storage_size_no_offset, BitFieldDataType,
};
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::{DataTypeManager, NULL_DATATYPE_ID};
use crate::program::model::data::invalid_data_type_exception::InvalidDataTypeException;
use crate::program::model::mem::MemBuffer;

/// Mirrors `DataTypeManagerDB.TYPEDEF`. See the module docs for why this is a private local copy
/// rather than a shared constant.
const DTM_TYPEDEF: i32 = 5;
/// Mirrors `DataTypeManagerDB.ENUM`.
const DTM_ENUM: i32 = 8;
/// Mirrors `DataTypeManagerDB.BUILT_IN`.
const DTM_BUILT_IN: i32 = 0;
/// Mirrors `DataTypeManagerDB.DATA_TYPE_KIND_SHIFT`.
const DTM_DATA_TYPE_KIND_SHIFT: u32 = 56;

// Bit Field ID Encoding (expressed as the following 4-bit nibble fields):  XXTTTTTTTTBBOOSS
//
// XX - reserved for datatype manager table ID
// TTTTTTTT - TypeDef/Enum ID (32-bits, excludes table ID, applies to resolved TypeDef/Enum only)
// BB - Encoded base type (8-bits, consists of the following bit fields: xttsbbbb)
//      x - 1-bit, unused
//      t - 2-bit, =0: base type only, =1:TypeDef used, =2: enum used, =3: abstract-int
//      s - 1-bit, storage +1 (NOT-USED! - may be re-purposed by future schema change)
//      xxxx - 4-bits, unused
// OO - bit offset (i.e., right-shift factor, relative to packing base type)
// SS - bit field size in bits

const BIT_OFFSET_SHIFT: u32 = 8;
const BASE_TYPE_SHIFT: u32 = 16;
const DATATYPE_INDEX_SHIFT: u32 = 24;

/// Port of `BitFieldDBDataType.MAX_DATATYPE_INDEX`.
pub const MAX_DATATYPE_INDEX: i64 = 0xffffffff;

/// Port of the private `BitFieldDBDataType.ID_TO_INDEX_MASK`.
const ID_TO_INDEX_MASK: i64 = (1i64 << DTM_DATA_TYPE_KIND_SHIFT) - 1;

/// Port of the private `BitFieldDBDataType.BaseDatatypeKind` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BaseDatatypeKind {
    None,
    Typedef,
    Enum,
    Integer,
}

impl BaseDatatypeKind {
    fn id(self) -> i64 {
        match self {
            BaseDatatypeKind::None => 0,
            BaseDatatypeKind::Typedef => 1,
            BaseDatatypeKind::Enum => 2,
            BaseDatatypeKind::Integer => 3,
        }
    }

    /// Port of `BaseDatatypeKind.getKind(int)`.
    fn get_kind(value: i64) -> BaseDatatypeKind {
        match value {
            1 => BaseDatatypeKind::Typedef,
            2 => BaseDatatypeKind::Enum,
            3 => BaseDatatypeKind::Integer,
            _ => BaseDatatypeKind::None,
        }
    }
}

/// Stands in for `IntegerDataType.dataType`. See the module documentation for why no concrete
/// singleton exists yet in this crate.
#[derive(Debug, Clone, Copy)]
struct IntegerFallbackDataType {
    length: i32,
}
impl DataType for IntegerFallbackDataType {
    fn get_name(&self) -> String {
        "int".to_string()
    }
    fn get_length(&self) -> i32 {
        self.length
    }
    fn is_integer_type(&self) -> bool {
        true
    }
    fn is_signed_integer_type(&self) -> bool {
        true
    }
    fn clone_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        Box::new(IntegerFallbackDataType { length: dtm.get_data_organization().get_integer_size() })
    }
}

/// `BitFieldDBDataType` extends [`BitFieldDataType`] for `DataTypeManagerDB` use. This class
/// provides the ability to generate a datatype ID and reconstruct a bit-field datatype from an
/// ID.
///
/// Port of `ghidra.program.database.data.BitFieldDBDataType`. See the module documentation for
/// what was ported, and for the `clone`/`copy` inherited-behavior subtlety.
pub struct BitFieldDbDataType {
    base: BitFieldDataType,
}

impl BitFieldDbDataType {
    /// Construct DB resident bitfield. Minimal storage size and effective bit size will be
    /// computed based upon specified parameters.
    ///
    /// `base_data_type` is the base data type (integer/enum type or typedef to same); this
    /// bitfield adopts the same datatype manager as this base type. `bit_size` is the size of the
    /// bit-field expressed as number of bits (0..255); the effective bit size may be reduced
    /// based upon the specified base datatype size. `bit_offset` is the right shift factor within
    /// the storage unit when viewed as a big-endian scalar value; based upon minimal storage,
    /// `bit_offset` should be in the range 0 to 7.
    ///
    /// Port of `BitFieldDBDataType(DataType, int, int)`.
    ///
    /// # Errors
    /// Returns `Err` if an invalid base datatype, `bit_size`, or `bit_offset` has been specified.
    pub fn new(
        base_data_type: Box<dyn DataType>,
        bit_size: i32,
        bit_offset: i32,
    ) -> Result<Self, InvalidDataTypeException> {
        Ok(BitFieldDbDataType { base: BitFieldDataType::new(base_data_type, bit_size, bit_offset)? })
    }

    /// The wrapped [`BitFieldDataType`] behavior this type inherits unchanged.
    pub fn base(&self) -> &BitFieldDataType {
        &self.base
    }

    /// Get a generated ID for this bit-field which is suitable for reconstruction via
    /// [`get_bit_field_data_type`]. This ID encodes the base datatype (including typedef/enum and
    /// packing data), bit-size and bit-offset. The upper byte of the ID is always zero and is
    /// reserved for use by the DataTypeManager.
    ///
    /// The ability to reference base datatypes (e.g. TypeDef, Enum) is currently limited (i.e.
    /// 32-bit base datatype ID).
    ///
    /// `bitfield_dt` is the resolved bitfield datatype whose ID is needed; `dtm` is the owning
    /// `DataTypeManagerDB` it was resolved against. Unlike Java (which derives `dtm` from
    /// `bitfieldDt.getDataTypeManager()` and throws `AssertException` if it is not a
    /// `DataTypeManagerDB`), this port takes `dtm` explicitly: this crate's [`DataType::get_data_type_manager`]
    /// returns a generic [`DataTypeManager`], with no generic downcast to
    /// [`DataTypeManagerDb`] available, so the "must first be resolved by a `DataTypeManagerDB`"
    /// precondition is enforced by the type system at the call site instead of at runtime.
    ///
    /// Port of `BitFieldDBDataType.getId(BitFieldDataType)`.
    pub fn get_id(bitfield_dt: &BitFieldDataType, dtm: &dyn DataTypeManagerDb) -> i64 {
        let base_data_type = bitfield_dt.referenced_base_data_type();

        let mut data_type_kind = BaseDatatypeKind::None;
        let mut data_type_index: i64 = 0;
        if base_data_type.is_typedef() {
            data_type_kind = BaseDatatypeKind::Typedef;
        } else if base_data_type.as_enum().is_some() {
            data_type_kind = BaseDatatypeKind::Enum;
        } else if base_data_type.is_integer_type() {
            data_type_kind = BaseDatatypeKind::Integer;
        }

        if data_type_kind != BaseDatatypeKind::None {
            data_type_index = get_resolved_data_type_index(base_data_type, dtm);
            if data_type_index == NULL_DATATYPE_ID {
                data_type_index = MAX_DATATYPE_INDEX;
                data_type_kind = BaseDatatypeKind::None;
            } else if data_type_index >= MAX_DATATYPE_INDEX {
                // TypeDef index exceeds 32-bit limit
                data_type_index = MAX_DATATYPE_INDEX;
                data_type_kind = BaseDatatypeKind::None;
            }
        }

        (data_type_index << DATATYPE_INDEX_SHIFT)
            | (get_base_type_encoded_field(bitfield_dt, data_type_kind) << BASE_TYPE_SHIFT)
            | ((bitfield_dt.get_bit_offset() as i64) << BIT_OFFSET_SHIFT)
            | (bitfield_dt.get_declared_bit_size() as i64)
    }

    /// Get a bit-field datatype instance for a given ID. The upper byte of the ID is ignored.
    ///
    /// Port of `BitFieldDBDataType.getBitFieldDataType(long, DataTypeManagerDB)`.
    pub fn get_bit_field_data_type(id: i64, dtm: &dyn DataTypeManagerDb) -> Option<BitFieldDbDataType> {
        let bit_size = (id & 0xff) as i32;
        let bit_offset = ((id >> BIT_OFFSET_SHIFT) & 0xff) as i32;
        let base_type_info = (id >> BASE_TYPE_SHIFT) & 0xff;

        let base_data_type_kind = BaseDatatypeKind::get_kind((base_type_info >> 5) & 3);

        let mut base_data_type: Option<Box<dyn DataType>> = None;
        let data_type_index = (id >> DATATYPE_INDEX_SHIFT) & MAX_DATATYPE_INDEX;
        if base_data_type_kind != BaseDatatypeKind::None && data_type_index != MAX_DATATYPE_INDEX {
            base_data_type = match base_data_type_kind {
                BaseDatatypeKind::Typedef => get_typedef(data_type_index, dtm),
                BaseDatatypeKind::Enum => get_enum(data_type_index, dtm),
                _ => get_integer_type(data_type_index, dtm),
            };
        }

        let base_data_type = base_data_type.unwrap_or_else(|| {
            // use integer datatype on failure
            Box::new(IntegerFallbackDataType { length: dtm.get_data_organization().get_integer_size() })
        });

        BitFieldDbDataType::new(base_data_type, bit_size, bit_offset).ok()
    }
}

/// Port of the private `BitFieldDBDataType.getBaseTypeEncodedField(BitFieldDataType,
/// BaseDatatypeKind)`.
fn get_base_type_encoded_field(bitfield_dt: &BitFieldDataType, data_type_kind: BaseDatatypeKind) -> i64 {
    let nominal_storage_size = get_minimum_storage_size_no_offset(bitfield_dt.get_bit_size());
    let extra_storage_used = bitfield_dt.get_storage_size() > nominal_storage_size;
    (data_type_kind.id() << 5) | if extra_storage_used { 0x10 } else { 0 }
}

/// Port of the private `BitFieldDBDataType.getResolvedDataTypeIndex(DataType, DataTypeManagerDB)`.
fn get_resolved_data_type_index(data_type: &dyn DataType, dtm: &dyn DataTypeManagerDb) -> i64 {
    let data_type_id = dtm.get_id(data_type);
    if data_type_id == NULL_DATATYPE_ID {
        return NULL_DATATYPE_ID;
    }
    data_type_id & ID_TO_INDEX_MASK
}

/// Get the TypeDef which corresponds to the specified `typedef_index` and the specified data type
/// manager, or `None` if not found.
///
/// Port of the private `BitFieldDBDataType.getTypeDef(long, DataTypeManager)`.
fn get_typedef(typedef_index: i64, dtm: &dyn DataTypeManagerDb) -> Option<Box<dyn DataType>> {
    let data_type_id = ((DTM_TYPEDEF as i64) << DTM_DATA_TYPE_KIND_SHIFT) | typedef_index;
    let data_type = dtm.get_data_type_by_id(data_type_id)?;
    if !data_type.is_typedef() {
        return None;
    }
    let base = data_type.typedef_base_data_type()?;
    if base.as_enum().is_some() || base.is_integer_type() {
        // TODO(port): how restrictive should we be on matching enum size? (matches the Java
        // TODO left on `getTypeDef`)
        return Some(data_type);
    }
    None // unsupported typedef
}

/// Get the Enum which corresponds to the specified `enum_index` and the specified data type
/// manager, or `None` if not found.
///
/// Port of the private `BitFieldDBDataType.getEnum(long, DataTypeManager)`.
fn get_enum(enum_index: i64, dtm: &dyn DataTypeManagerDb) -> Option<Box<dyn DataType>> {
    let data_type_id = ((DTM_ENUM as i64) << DTM_DATA_TYPE_KIND_SHIFT) | enum_index;
    let data_type = dtm.get_data_type_by_id(data_type_id)?;
    if data_type.as_enum().is_none() {
        return None;
    }
    Some(data_type)
}

/// Get the integer base type which corresponds to the specified `int_type_index` and the
/// specified data type manager, or `None` if not found.
///
/// Port of the private `BitFieldDBDataType.getIntegerType(long, DataTypeManager)`.
fn get_integer_type(int_type_index: i64, dtm: &dyn DataTypeManagerDb) -> Option<Box<dyn DataType>> {
    let data_type_id = ((DTM_BUILT_IN as i64) << DTM_DATA_TYPE_KIND_SHIFT) | int_type_index;
    let data_type = dtm.get_data_type_by_id(data_type_id)?;
    if !data_type.is_integer_type() {
        return None;
    }
    Some(data_type)
}

impl DataType for BitFieldDbDataType {
    fn get_name(&self) -> String {
        DataType::get_name(&self.base)
    }

    fn get_category_path(&self) -> CategoryPath {
        DataType::get_category_path(&self.base)
    }

    fn get_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>> {
        DataType::get_data_type_manager(&self.base)
    }

    fn get_data_organization(&self) -> Box<dyn crate::program::model::data::data_organization::DataOrganization> {
        DataType::get_data_organization(&self.base)
    }

    fn get_default_abbreviated_label_prefix(&self) -> Option<String> {
        DataType::get_default_abbreviated_label_prefix(&self.base)
    }

    fn is_zero_length(&self) -> bool {
        DataType::is_zero_length(&self.base)
    }

    fn get_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        DataType::get_settings_definitions(&self.base)
    }

    /// Port of the inherited (not overridden) `BitFieldDataType.isEquivalent(DataType)`. See the
    /// module docs for why this is sound to implement directly against `self.base` (no live
    /// back-reference limitation applies here).
    fn is_equivalent(&self, dt: &dyn DataType) -> bool {
        self.base.is_equivalent(dt)
    }

    fn is_bit_field_type(&self) -> bool {
        true
    }

    fn as_bit_field(&self) -> Option<&dyn crate::program::seam_stubs::BitFieldDataType> {
        Some(&self.base)
    }

    fn as_bit_field_data_type(&self) -> Option<&BitFieldDataType> {
        Some(&self.base)
    }

    fn get_default_settings(&self) -> Box<dyn Settings> {
        DataType::get_default_settings(&self.base)
    }

    /// Port of the inherited (not overridden) `BitFieldDataType.copy(DataTypeManager)`. See the
    /// module docs: this downgrades to a plain [`BitFieldDataType`], exactly matching Java.
    fn copy_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        DataType::copy_data_type(&self.base, dtm)
    }

    /// Port of the inherited (not overridden) `BitFieldDataType.clone(DataTypeManager)`. See the
    /// module docs: this downgrades to a plain [`BitFieldDataType`], exactly matching Java.
    fn clone_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        DataType::clone_data_type(&self.base, dtm)
    }

    fn get_length(&self) -> i32 {
        DataType::get_length(&self.base)
    }

    fn get_aligned_length(&self) -> i32 {
        DataType::get_aligned_length(&self.base)
    }

    fn get_description(&self) -> String {
        DataType::get_description(&self.base)
    }

    fn get_value(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Option<Box<dyn std::any::Any>> {
        DataType::get_value(&self.base, buf, settings, length)
    }

    fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        DataType::get_representation(&self.base, buf, settings, length)
    }

    fn get_value_class(&self, settings: &dyn Settings) -> Option<std::any::TypeId> {
        DataType::get_value_class(&self.base, settings)
    }

    fn get_alignment(&self) -> i32 {
        DataType::get_alignment(&self.base)
    }
}

impl std::fmt::Display for BitFieldDbDataType {
    /// Port of the inherited (not overridden) `BitFieldDataType.toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::category_path::ROOT;
    use crate::program::model::data::data_organization::DataOrganization;
    use std::io;

    #[derive(Debug, Clone, Copy)]
    struct MockDataOrganization;
    impl DataOrganization for MockDataOrganization {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_pointer_size(&self) -> i32 {
            8
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
            4
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
            0
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
        fn get_size_alignment(&self, _size: i32) -> i32 {
            1
        }
        fn get_bit_field_packing(&self) -> Box<dyn crate::program::model::data::bit_field_packing::BitFieldPacking> {
            struct P;
            impl crate::program::model::data::bit_field_packing::BitFieldPacking for P {
                fn use_ms_convention(&self) -> bool {
                    false
                }
                fn is_type_alignment_enabled(&self) -> bool {
                    false
                }
                fn get_zero_length_boundary(&self) -> i32 {
                    0
                }
            }
            Box::new(P)
        }
        fn get_size_alignment_count(&self) -> i32 {
            0
        }
        fn get_sizes(&self) -> Vec<i32> {
            Vec::new()
        }
        fn get_integer_c_type_approximation(&self, _size: i32, _signed: bool) -> String {
            String::new()
        }
        fn get_alignment(&self, data_type: &dyn DataType) -> i32 {
            data_type.get_alignment()
        }
    }

    struct MockManager {
        id: i64,
        types: std::collections::HashMap<i64, Box<dyn DataType>>,
    }
    impl MockManager {
        fn new(id: i64) -> Self {
            MockManager { id, types: std::collections::HashMap::new() }
        }
        fn insert(&mut self, id: i64, dt: Box<dyn DataType>) {
            self.types.insert(id, dt);
        }
    }
    impl DataTypeManager for MockManager {
        fn get_universal_id(&self) -> crate::util::UniversalID {
            crate::util::UniversalID::new(self.id)
        }
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            Box::new(MockDataOrganization)
        }
        fn get_id(&self, dt: &dyn DataType) -> i64 {
            for (id, existing) in self.types.iter() {
                if existing.get_name() == dt.get_name() {
                    return *id;
                }
            }
            NULL_DATATYPE_ID
        }
        fn get_data_type_by_id(&self, data_type_id: i64) -> Option<Box<dyn DataType>> {
            self.types.get(&data_type_id).map(|dt| dt.clone_data_type(self))
        }
    }
    impl DataTypeManagerDb for MockManager {
        fn db_error(&mut self, _error: io::Error) {}
        fn add_data_type_to_replace(&mut self, _data_type_id: i64, _replacement: Box<dyn DataType>) {}
        fn add_data_type_to_delete(&mut self, _data_type_id: i64) {}
    }

    #[derive(Clone)]
    struct MockInt {
        name: String,
        length: i32,
        manager_id: i64,
    }
    impl DataType for MockInt {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn is_integer_type(&self) -> bool {
            true
        }
        fn is_signed_integer_type(&self) -> bool {
            true
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.name == dt.get_name() && self.length == dt.get_length()
        }
        fn clone_data_type(&self, _dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
            Box::new(self.clone())
        }
        fn get_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>> {
            Some(Box::new(MockManager::new(self.manager_id)))
        }
        fn get_alignment(&self) -> i32 {
            self.length
        }
    }

    fn int_type(manager_id: i64) -> Box<dyn DataType> {
        Box::new(MockInt { name: "int".to_string(), length: 4, manager_id })
    }

    #[test]
    fn new_computes_effective_size_and_storage() {
        let bf = BitFieldDbDataType::new(int_type(1), 4, 2).unwrap();
        assert_eq!(bf.base().get_declared_bit_size(), 4);
        assert_eq!(bf.base().get_bit_offset(), 2);
        assert_eq!(DataType::get_length(&bf), 1);
    }

    #[test]
    fn new_rejects_invalid_bit_size_and_offset() {
        assert!(BitFieldDbDataType::new(int_type(1), 256, 0).is_err());
        assert!(BitFieldDbDataType::new(int_type(1), 4, 8).is_err());
    }

    #[test]
    fn get_name_length_and_representation_delegate_to_base() {
        let bf = BitFieldDbDataType::new(int_type(1), 5, 0).unwrap();
        assert_eq!(DataType::get_name(&bf), "int:5");
        assert_eq!(DataType::get_length(&bf), 1);
        assert!(DataType::is_bit_field_type(&bf));
        assert!(DataType::as_bit_field(&bf).is_some());
    }

    #[test]
    fn as_bit_field_data_type_returns_real_owned_reference() {
        let bf = BitFieldDbDataType::new(int_type(1), 40, 0).unwrap();
        let real = DataType::as_bit_field_data_type(&bf).expect("downcast should succeed");
        assert_eq!(real.get_declared_bit_size(), 40);
    }

    #[test]
    fn is_equivalent_matches_wrapped_base_type_semantics() {
        let a = BitFieldDbDataType::new(int_type(1), 5, 1).unwrap();
        let b = BitFieldDbDataType::new(int_type(1), 5, 3).unwrap(); // offset ignored by isEquivalent
        assert!(DataType::is_equivalent(&a, &b));

        let c = BitFieldDbDataType::new(int_type(1), 6, 0).unwrap();
        assert!(!DataType::is_equivalent(&a, &c));
    }

    #[test]
    fn clone_data_type_downgrades_to_plain_bit_field_data_type() {
        let bf = BitFieldDbDataType::new(int_type(1), 5, 2).unwrap();
        let mgr = MockManager::new(1);
        let cloned = DataType::clone_data_type(&bf, &mgr);
        // Downcast to the *real* BitFieldDataType is still possible (the value is genuinely one),
        // but the concrete Rust type is no longer BitFieldDbDataType -- see the module docs.
        let as_bitfield = cloned.as_bit_field_data_type().expect("still reports as a bitfield");
        assert_eq!(as_bitfield.get_declared_bit_size(), 5);
    }

    #[test]
    fn display_matches_base_to_string() {
        let bf = BitFieldDbDataType::new(int_type(1), 5, 2).unwrap();
        let shown = format!("{bf}");
        assert!(shown.contains("storage:"));
        assert!(shown.contains("bitOffset:2"));
    }

    #[test]
    fn get_id_encodes_bit_offset_and_declared_bit_size() {
        let mgr = MockManager::new(1);
        let base = BitFieldDataType::new(int_type(1), 5, 2).unwrap();
        let id = BitFieldDbDataType::get_id(&base, &mgr);
        assert_eq!(id & 0xff, 5); // declared bit size
        assert_eq!((id >> BIT_OFFSET_SHIFT) & 0xff, 2); // bit offset
    }

    #[test]
    fn get_id_marks_unresolved_base_type_with_max_index_and_none_kind() {
        // int_type's manager never actually contains "int" (MockManager starts empty), so
        // get_id() (dtm.getID) returns NULL_DATATYPE_ID, and the base-type kind collapses to
        // NONE / MAX_DATATYPE_INDEX, matching `BitFieldDBDataType.getId`'s "not resolved" branch.
        let mgr = MockManager::new(1);
        let base = BitFieldDataType::new(int_type(1), 5, 0).unwrap();
        let id = BitFieldDbDataType::get_id(&base, &mgr);
        let data_type_index = (id >> DATATYPE_INDEX_SHIFT) & MAX_DATATYPE_INDEX;
        assert_eq!(data_type_index, MAX_DATATYPE_INDEX);
    }

    #[test]
    fn get_id_then_get_bit_field_data_type_round_trips_a_resolvable_base_type() {
        let mut mgr = MockManager::new(1);
        let builtin_id = (DTM_BUILT_IN as i64) << DTM_DATA_TYPE_KIND_SHIFT | 77;
        mgr.insert(builtin_id, Box::new(MockInt { name: "myint".to_string(), length: 4, manager_id: 1 }));

        let base = BitFieldDataType::new(
            Box::new(MockInt { name: "myint".to_string(), length: 4, manager_id: 1 }),
            6,
            2,
        )
        .unwrap();
        let id = BitFieldDbDataType::get_id(&base, &mgr);

        let reconstructed = BitFieldDbDataType::get_bit_field_data_type(id, &mgr)
            .expect("reconstruction should succeed");
        assert_eq!(reconstructed.base().referenced_base_data_type().get_name(), "myint");
        assert_eq!(reconstructed.base().get_declared_bit_size(), 6);
        assert_eq!(reconstructed.base().get_bit_offset(), 2);
    }

    #[test]
    fn get_bit_field_data_type_round_trips_through_get_id_for_unresolved_base() {
        let mgr = MockManager::new(1);
        let base = BitFieldDataType::new(int_type(1), 6, 3).unwrap();
        let id = BitFieldDbDataType::get_id(&base, &mgr);

        let reconstructed = BitFieldDbDataType::get_bit_field_data_type(id, &mgr)
            .expect("reconstruction should succeed via the integer fallback");
        assert_eq!(reconstructed.base().get_declared_bit_size(), 6);
        assert_eq!(reconstructed.base().get_bit_offset(), 3);
        // Unresolved base type falls back to the "int" stand-in, at the manager's integer size.
        assert_eq!(reconstructed.base().get_base_type_size(), 4);
    }

    #[test]
    fn get_bit_field_data_type_resolves_via_builtin_integer_lookup() {
        let mut mgr = MockManager::new(1);
        // BUILT_IN table id (0) at index 42.
        let builtin_id = (DTM_BUILT_IN as i64) << DTM_DATA_TYPE_KIND_SHIFT | 42;
        mgr.insert(builtin_id, Box::new(MockInt { name: "uint".to_string(), length: 4, manager_id: 1 }));

        // Manually build an id encoding BaseDatatypeKind::Integer (3) at index 42, bit_size 7,
        // bit_offset 1 -- mirroring what get_id would produce had dtm.getID resolved "uint".
        let base_type_encoded = (BaseDatatypeKind::Integer.id()) << 5;
        let id = (42i64 << DATATYPE_INDEX_SHIFT)
            | (base_type_encoded << BASE_TYPE_SHIFT)
            | (1i64 << BIT_OFFSET_SHIFT)
            | 7;

        let reconstructed = BitFieldDbDataType::get_bit_field_data_type(id, &mgr)
            .expect("reconstruction should succeed via the builtin integer lookup");
        assert_eq!(reconstructed.base().referenced_base_data_type().get_name(), "uint");
        assert_eq!(reconstructed.base().get_declared_bit_size(), 7);
        assert_eq!(reconstructed.base().get_bit_offset(), 1);
    }

    struct MockTypedefType {
        base_length: i32,
    }
    impl DataType for MockTypedefType {
        fn get_name(&self) -> String {
            "MyTypedef".to_string()
        }
        fn get_length(&self) -> i32 {
            self.base_length
        }
        fn is_typedef(&self) -> bool {
            true
        }
        fn typedef_base_data_type(&self) -> Option<Box<dyn DataType>> {
            Some(int_type(1))
        }
        fn clone_data_type(&self, _dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
            Box::new(MockTypedefType { base_length: self.base_length })
        }
    }

    #[test]
    fn get_bit_field_data_type_resolves_via_typedef_lookup() {
        let mut mgr = MockManager::new(1);
        let typedef_id = (DTM_TYPEDEF as i64) << DTM_DATA_TYPE_KIND_SHIFT | 5;
        mgr.insert(typedef_id, Box::new(MockTypedefType { base_length: 4 }));

        let base_type_encoded = (BaseDatatypeKind::Typedef.id()) << 5;
        let id = (5i64 << DATATYPE_INDEX_SHIFT) | (base_type_encoded << BASE_TYPE_SHIFT) | 6;

        let reconstructed = BitFieldDbDataType::get_bit_field_data_type(id, &mgr)
            .expect("reconstruction should succeed via the typedef lookup");
        assert_eq!(reconstructed.base().referenced_base_data_type().get_name(), "MyTypedef");
        assert_eq!(reconstructed.base().get_declared_bit_size(), 6);
    }

    #[test]
    fn get_typedef_rejects_typedef_of_unsupported_base_type() {
        struct UnsupportedBase;
        impl DataType for UnsupportedBase {
            fn get_name(&self) -> String {
                "unsupported".to_string()
            }
        }
        struct TypedefOfUnsupported;
        impl DataType for TypedefOfUnsupported {
            fn get_name(&self) -> String {
                "BadTypedef".to_string()
            }
            fn is_typedef(&self) -> bool {
                true
            }
            fn typedef_base_data_type(&self) -> Option<Box<dyn DataType>> {
                Some(Box::new(UnsupportedBase))
            }
            fn clone_data_type(&self, _dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
                Box::new(TypedefOfUnsupported)
            }
        }
        let mut mgr = MockManager::new(1);
        let typedef_id = (DTM_TYPEDEF as i64) << DTM_DATA_TYPE_KIND_SHIFT | 7;
        mgr.insert(typedef_id, Box::new(TypedefOfUnsupported));

        let base_type_encoded = (BaseDatatypeKind::Typedef.id()) << 5;
        let id = (7i64 << DATATYPE_INDEX_SHIFT) | (base_type_encoded << BASE_TYPE_SHIFT) | 2;

        // The stored typedef's base type is neither an Enum nor an integer type, so `get_typedef`
        // rejects it (mirrors `getTypeDef`'s "unsupported typedef" `return null`) and
        // reconstruction falls back to the integer stand-in.
        let reconstructed = BitFieldDbDataType::get_bit_field_data_type(id, &mgr)
            .expect("reconstruction still succeeds via the integer fallback");
        assert_eq!(reconstructed.base().referenced_base_data_type().get_name(), "int");
    }

    struct MockEnumType {
        length: i32,
    }
    impl DataType for MockEnumType {
        fn get_name(&self) -> String {
            "MyEnum".to_string()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn as_enum(&self) -> Option<&dyn crate::program::model::data::enum_::Enum> {
            Some(self)
        }
        fn clone_data_type(&self, _dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
            Box::new(MockEnumType { length: self.length })
        }
    }
    impl crate::program::model::data::enum_::Enum for MockEnumType {
        fn get_value_for_name(&self, _name: &str) -> Option<i64> {
            None
        }
        fn get_name_for_value(&self, _value: i64) -> Option<String> {
            None
        }
        fn get_names_for_value(&self, _value: i64) -> Option<Vec<String>> {
            None
        }
        fn get_comment(&self, _name: &str) -> String {
            String::new()
        }
        fn get_values(&self) -> Vec<i64> {
            Vec::new()
        }
        fn get_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_count(&self) -> i32 {
            0
        }
        fn add(&mut self, _name: &str, _value: i64) {}
        fn add_with_comment(&mut self, _name: &str, _value: i64, _comment: &str) {}
        fn remove(&mut self, _name: &str) {}
        fn set_description(&mut self, _description: &str) {}
        fn get_enum_representation(&self, big_int: i128, _settings: &dyn Settings, _bit_length: i32) -> String {
            format!("ENUM({big_int})")
        }
        fn contains_name(&self, _name: &str) -> bool {
            false
        }
        fn contains_value(&self, _value: i64) -> bool {
            false
        }
        fn is_signed(&self) -> bool {
            false
        }
        fn get_signed_state(&self) -> crate::program::database::data::EnumSignedState {
            crate::program::database::data::EnumSignedState::None
        }
        fn get_max_possible_value(&self) -> i64 {
            0
        }
        fn get_min_possible_value(&self) -> i64 {
            0
        }
        fn get_minimum_possible_length(&self) -> i32 {
            1
        }
        fn clone_enum(&self, _dtm: &dyn DataTypeManager) -> Box<dyn crate::program::model::data::enum_::Enum> {
            Box::new(MockEnumType { length: self.length })
        }
    }

    #[test]
    fn get_bit_field_data_type_resolves_via_enum_lookup() {
        let mut mgr = MockManager::new(1);
        let enum_id = (DTM_ENUM as i64) << DTM_DATA_TYPE_KIND_SHIFT | 9;
        mgr.insert(enum_id, Box::new(MockEnumType { length: 4 }));

        let base_type_encoded = (BaseDatatypeKind::Enum.id()) << 5;
        let id = (9i64 << DATATYPE_INDEX_SHIFT) | (base_type_encoded << BASE_TYPE_SHIFT) | 3;

        let reconstructed = BitFieldDbDataType::get_bit_field_data_type(id, &mgr)
            .expect("reconstruction should succeed via the enum lookup");
        assert_eq!(reconstructed.base().referenced_base_data_type().get_name(), "MyEnum");
        assert_eq!(reconstructed.base().get_declared_bit_size(), 3);
    }

    #[test]
    fn get_bit_field_data_type_falls_back_when_stored_row_is_wrong_kind() {
        // The row stored at the ENUM-encoded id is actually a plain integer (not an Enum), so
        // `get_enum`'s `as_enum().is_some()` check fails and reconstruction falls back to the
        // integer stand-in, matching `getEnum`'s own `!(dataType instanceof Enum)` rejection.
        let mut mgr = MockManager::new(1);
        let enum_id = (DTM_ENUM as i64) << DTM_DATA_TYPE_KIND_SHIFT | 9;
        mgr.insert(enum_id, int_type(1));

        let base_type_encoded = (BaseDatatypeKind::Enum.id()) << 5;
        let id = (9i64 << DATATYPE_INDEX_SHIFT) | (base_type_encoded << BASE_TYPE_SHIFT) | 3;

        let reconstructed = BitFieldDbDataType::get_bit_field_data_type(id, &mgr)
            .expect("reconstruction still succeeds via the integer fallback");
        assert_eq!(reconstructed.base().referenced_base_data_type().get_name(), "int");
    }

    #[test]
    fn get_id_then_get_bit_field_data_type_falls_back_when_index_too_large() {
        let mgr = MockManager::new(1);
        // An id with a Typedef kind but MAX_DATATYPE_INDEX as its index should be treated as
        // "unresolved" and fall back to the integer stand-in, matching `getId`'s own MAX-index
        // rejection branch.
        let base_type_encoded = (BaseDatatypeKind::Typedef.id()) << 5;
        let id = (MAX_DATATYPE_INDEX << DATATYPE_INDEX_SHIFT) | (base_type_encoded << BASE_TYPE_SHIFT) | 4;
        let reconstructed = BitFieldDbDataType::get_bit_field_data_type(id, &mgr).unwrap();
        assert_eq!(reconstructed.base().referenced_base_data_type().get_name(), "int");
    }
}
