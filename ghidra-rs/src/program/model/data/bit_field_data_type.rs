//! Port of `ghidra.program.model.data.BitFieldDataType`.
//!
//! The Java class `extends AbstractDataType` (a plain field-owning base class contributing no
//! interface beyond [`DataType`], already ported here as the [`AbstractDataType`] cut-point
//! trait). This is the first concrete, field-owning struct built on top of that trait -- see its
//! module docs for the accessor-delegation convention this port follows
//! ([`abstract_data_type_get_name`](AbstractDataType::abstract_data_type_get_name), etc.).
//!
//! NOTE: Instantiation of this datatype is intended for internal use only (the Java constructors
//! are `protected`; only `Structure`/`Union`'s bitfield-insertion methods are meant to call them).
//! This port keeps the constructors `pub` -- matching this crate's established convention for
//! every other concrete `DataType` struct (e.g. [`TypedefDataType`](super::typedef_data_type::TypedefDataType))
//! -- rather than trying to replicate Java's package-private access control, which Rust's module
//! system cannot express at the same granularity without awkward wrapper types.
//!
//! ## Storage strategy for the wrapped base `DataType`
//!
//! Exactly [`TypedefDataType`](super::typedef_data_type::TypedefDataType)'s strategy: `base_data_type`
//! is stored as `Arc<dyn DataType>` (since `dyn DataType` has no `Clone` bound, so a
//! `Box<dyn DataType>` field could not be handed back out more than once), and
//! [`get_base_data_type`](BitFieldDataType::get_base_data_type) hands back a fresh
//! [`share_data_type`] handle. `name`/`effective_bit_size`/`storage_size` are computed once at
//! construction (as the Java constructor does) and cached as plain fields.
//!
//! ## Dropped/simplified pieces
//!
//! - **`addParent(DataType)`**: conditionally forwards to `baseDataType.addParent(this)` in Java
//!   when the base is a `TypeDef` or `Enum`. Not ported, for the same reason
//!   [`TypedefDataType`](super::typedef_data_type::TypedefDataType)'s module docs give for
//!   dropping its own parent-notification wiring: [`DataType::add_parent`] needs `&mut self` on
//!   the target, but `base_data_type` is a (possibly multiply-owned) `Arc<dyn DataType>`, from
//!   which a mutable reference cannot soundly be recovered in general.
//! - **`getDefaultSettings()`**: Java captures `baseDataType.getDefaultSettings()` *once* at
//!   construction and returns that identical object forever. This port instead recomputes
//!   `self.base_data_type.get_default_settings()` on every call, since a `Box<dyn Settings>`
//!   can't be cached as a plain field and handed out repeatedly (no `Clone` bound). This is the
//!   same "fresh value each call" limitation already accepted elsewhere in this crate (e.g.
//!   `DataType::get_data_type_manager`'s own doc comment, and `DataTypeUtilities`'s module docs).
//! - **`getPrimitiveBaseDataType()`**: when the (typedef-resolved) base is an `Enum`, Java
//!   synthesizes a fresh `AbstractIntegerDataType.getUnsignedDataType(enumLength, dataMgr)` to
//!   answer `isSigned()`/carry the value. That static factory is a documented, pre-existing gap in
//!   this crate (see `abstract_integer_data_type.rs`'s module docs: "omitted entirely... build a
//!   registry keyed off concrete sibling singletons... not yet ported"). Since every call site
//!   here only ever needs the *signedness* of that synthesized type (never the type object
//!   itself), and `getUnsignedDataType` unconditionally produces an *unsigned* type by
//!   construction, this port skips synthesizing a placeholder type entirely: an `Enum`-based base
//!   is simply treated as unsigned (see [`effective_is_signed`]), matching the exact behavior the
//!   missing factory would have produced.
//! - **`hashCode()`/`equals(Object)`**: Java's `equals` compares `baseDataType.equals(...)`
//!   (a second `Object.equals` call this crate has no generic equivalent for -- only
//!   [`DataType::is_equivalent`] is available as the crate-wide "sameness" contract). Ported as
//!   the inherent [`BitFieldDataType::bit_field_equals`]/[`BitFieldDataType::bit_field_hash_code`]
//!   rather than `DataType` overrides (Java's own `equals`/`hashCode` have no `DataType`-trait
//!   home in this port either, matching [`DataTypeImpl`](super::data_type_impl::DataTypeImpl)'s
//!   precedent of exposing them only as `data_type_impl_equals`/`data_type_impl_hash_code`), using
//!   `is_equivalent` in place of the nested `baseDataType.equals(...)` call.
//! - **CHAR-format representation**: `getRepresentation`'s `FormatSettingsDefinition.CHAR` branch
//!   (rendering the bitfield's bytes as a character) is simplified away exactly like
//!   [`AbstractIntegerDataType::integer_representation`](super::abstract_integer_data_type::AbstractIntegerDataType::integer_representation)
//!   already does, for the identical documented reason: the static
//!   `StringDataInstance.getCharRepresentation(DataType, byte[], Settings)` factory those branches
//!   need is not ported, and that gap is *specifically called out* in
//!   [`string_data_instance`](super::string_data_instance)'s module docs as needing
//!   "`BitFieldDataType`-aware charset/size derivation from a bare `DataType`" -- i.e. this exact
//!   class. [`BitFieldDataType::get_representation`] always falls through to the standard numeric
//!   rendering instead.
//!
//! ## Wiring into the pre-existing `seam_stubs::BitFieldDataType` placeholder
//!
//! [`DataType::as_bit_field`](super::data_type::DataType::as_bit_field) already downcasts to a
//! minimal `seam_stubs::BitFieldDataType` placeholder trait, used by
//! [`DataOrganizationImpl::compute_alignment`](super::data_organization_impl::DataOrganizationImpl::compute_alignment),
//! [`DataTypeComponentImpl`](super::data_type_component_impl::DataTypeComponentImpl), and
//! [`ReadOnlyDataTypeComponent`](super::read_only_data_type_component::ReadOnlyDataTypeComponent).
//! This struct implements that placeholder trait too (delegating to the real fields) and overrides
//! `as_bit_field`/`is_bit_field_type` so those existing call sites now see real bitfield behavior
//! instead of only their test mocks. A *second*, full-fidelity downcast --
//! [`DataType::as_bit_field_data_type`](super::data_type::DataType::as_bit_field_data_type) -- was
//! added for this port's own [`is_equivalent`](BitFieldDataType::get_declared_bit_size) use, since
//! the placeholder trait only exposes the *effective* bit size, not the declared one Java's
//! `isEquivalent` actually compares.

use std::sync::Arc;

use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::model::data::abstract_data_type::{
    check_new_abstract_data_type_args, default_data_organization, AbstractDataType,
};
use crate::program::model::data::category_path::{CategoryPath, ROOT};
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::data_utilities::DataUtilities;
use crate::program::model::data::endian_settings_definition::EndianSettingsDefinition;
use crate::program::model::data::invalid_data_type_exception::InvalidDataTypeException;
use crate::program::model::data::structure::get_normalized_bitfield_offset;
use crate::program::model::mem::MemBuffer;
use crate::program::seam_stubs::share_data_type;

/// Port of the private static final `BitFieldDataType.MAX_BIT_LENGTH`.
pub const MAX_BIT_LENGTH: i32 = 255;

/// Zero-sized marker used purely to call the defaulted trait methods of [`DataUtilities`] (a
/// `&dyn Trait`-object seam -- see its own module docs -- rather than a free-function module).
/// Mirrors [`TypedefDataType`](super::typedef_data_type::TypedefDataType)'s identical `Utils`
/// marker.
#[derive(Debug, Default, Clone, Copy)]
struct Utils;
impl DataUtilities for Utils {}

/// Saturating `2^bits` as an `i128`, standing in for `BigInteger.valueOf(2).pow(bits)`. Mirrors
/// [`AbstractIntegerDataType`](super::abstract_integer_data_type::AbstractIntegerDataType)'s
/// private `pow2_i128` helper (not reused directly since that one is private to its own module and
/// this bitfield-specific copy needs no other part of that module).
fn pow2_saturating(bits: i32) -> i128 {
    if bits <= 0 {
        1
    } else if bits >= 127 {
        i128::MAX
    } else {
        1i128 << bits
    }
}

/// Provides a means of defining a minimally sized bit-field for use within data structures.
///
/// Port of `ghidra.program.model.data.BitFieldDataType`. See the module-level documentation for
/// what was dropped, simplified, or exposed under a different (inherent, non-trait) name.
pub struct BitFieldDataType {
    base_data_type: Arc<dyn DataType>,
    name: String,
    /// Number of bits, reflecting the declaration, which may exceed the base type's size.
    bit_size: i32,
    /// Number of bits, constrained by the size of the base type.
    effective_bit_size: i32,
    /// Right-shift within the big-endian view of the component storage (range 0..7).
    bit_offset: i32,
    /// Minimal component storage size (bytes) to which `bit_offset` applies.
    storage_size: i32,
}

impl BitFieldDataType {
    /// Construct a bit-field type based upon a specified base type, at a given `bit_offset`.
    ///
    /// Port of the 3-arg Java constructor `BitFieldDataType(DataType, int, int)`.
    ///
    /// # Errors
    /// Returns `Err` if `base_data_type` is not a supported bitfield base type (see
    /// [`is_valid_base_data_type`]), or if `bit_size`/`bit_offset` is out of range.
    pub fn new(
        base_data_type: Box<dyn DataType>,
        bit_size: i32,
        bit_offset: i32,
    ) -> Result<Self, InvalidDataTypeException> {
        check_base_data_type(base_data_type.as_ref())?;
        if !(0..=MAX_BIT_LENGTH).contains(&bit_size) {
            return Err(InvalidDataTypeException::with_message(format!(
                "unsupported bit size: {bit_size}"
            )));
        }
        if !(0..=7).contains(&bit_offset) {
            return Err(InvalidDataTypeException::with_message(format!(
                "unsupported minimal bit offset: {bit_offset}"
            )));
        }
        let name = format!("{}:{}", base_data_type.get_name(), bit_size);
        // Port of the `super(CategoryPath.ROOT, name, ...)` call's `AbstractDataType` constructor
        // validation; panics exactly where the Java constructor throws `IllegalArgumentException`
        // (see `check_new_abstract_data_type_args`'s own doc comment).
        check_new_abstract_data_type_args(&name, &Utils);
        let effective_bit_size = get_effective_bit_size(bit_size, base_data_type.get_length());
        let storage_size = get_minimum_storage_size(effective_bit_size, bit_offset);
        Ok(BitFieldDataType {
            base_data_type: Arc::from(base_data_type),
            name,
            bit_size,
            effective_bit_size,
            bit_offset,
            storage_size,
        })
    }

    /// Construct a bit-field type based upon a supported base type, at bit-offset 0.
    ///
    /// Port of the 2-arg Java constructor `BitFieldDataType(DataType, int)`.
    ///
    /// # Errors
    /// See [`BitFieldDataType::new`].
    pub fn new_at_offset_zero(
        base_data_type: Box<dyn DataType>,
        bit_size: i32,
    ) -> Result<Self, InvalidDataTypeException> {
        Self::new(base_data_type, bit_size, 0)
    }

    /// Port of `BitFieldDataType.isZeroLength()`.
    pub fn is_zero_length(&self) -> bool {
        self.bit_size == 0
    }

    /// Port of `BitFieldDataType.getBaseTypeSize()`.
    pub fn get_base_type_size(&self) -> i32 {
        self.base_data_type.get_length()
    }

    /// Port of `BitFieldDataType.getStorageSize()`. Same value as [`DataType::get_length`].
    pub fn get_storage_size(&self) -> i32 {
        self.storage_size
    }

    /// Port of `BitFieldDataType.getBitSize()` (the *effective* bit size, capped by the base
    /// type's size).
    pub fn get_bit_size(&self) -> i32 {
        self.effective_bit_size
    }

    /// Port of `BitFieldDataType.getDeclaredBitSize()` (the bit size as declared/constructed,
    /// which may exceed the effective size).
    pub fn get_declared_bit_size(&self) -> i32 {
        self.bit_size
    }

    /// Port of `BitFieldDataType.getBitOffset()`.
    pub fn get_bit_offset(&self) -> i32 {
        self.bit_offset
    }

    /// Port of `BitFieldDataType.getBaseDataType()`. Returns a [`share_data_type`] handle over the
    /// stored base type -- see the module docs for why this only forwards a handful of
    /// [`DataType`] methods.
    pub fn get_base_data_type(&self) -> Box<dyn DataType> {
        share_data_type(&self.base_data_type)
    }

    /// The real, fully-faithful wrapped base data type (as opposed to
    /// [`get_base_data_type`](Self::get_base_data_type)'s partially-forwarding handle). Mirrors
    /// [`TypedefDataType::referenced_data_type`](super::typedef_data_type::TypedefDataType::referenced_data_type).
    pub fn referenced_base_data_type(&self) -> &dyn DataType {
        self.base_data_type.as_ref()
    }

    /// Port of `BitFieldDataType.getPrimitiveBaseDataType()`, narrowed to just the signedness bit
    /// every real call site actually needs -- see the module docs for why the full `Enum ->
    /// synthesized unsigned integer` substitution isn't performed.
    fn effective_is_signed(&self) -> bool {
        let resolved_owned;
        let resolved: &dyn DataType = if self.base_data_type.is_typedef() {
            resolved_owned = self.base_data_type.typedef_base_data_type();
            resolved_owned.as_deref().unwrap_or(self.base_data_type.as_ref())
        } else {
            self.base_data_type.as_ref()
        };
        if resolved.as_enum().is_some() {
            // AbstractIntegerDataType.getUnsignedDataType(...) always synthesizes an unsigned
            // type; see the module docs.
            return false;
        }
        resolved.is_signed_integer_type()
    }

    /// Port of the private `BitFieldDataType.getBigIntegerValue(MemBuffer, boolean, Settings)`.
    /// `settings` is accepted (matching the Java signature) but unused, exactly as in the original
    /// (only `isSigned` and the raw bytes matter).
    fn get_big_integer_value(&self, buf: &dyn MemBuffer, is_signed: bool) -> Option<i128> {
        if self.effective_bit_size == 0 {
            return Some(0);
        }
        let mut bytes = vec![0u8; self.storage_size as usize];
        if buf.get_bytes_into(&mut bytes, 0) != self.storage_size {
            return None;
        }
        let big_endian = buf.is_big_endian();
        let mut big = crate::pcode::utils::utils::bytes_to_big_integer(
            &bytes,
            self.storage_size as usize,
            big_endian,
            false,
        );
        let pow = pow2_saturating(self.effective_bit_size);
        let mask = pow.saturating_sub(1);
        big = (big >> self.bit_offset) & mask;
        if is_signed && big & (1i128 << (self.effective_bit_size - 1).max(0)) != 0 {
            big -= pow;
        }
        Some(big)
    }

    /// Port of `BitFieldDataType.hashCode()`. Uses `base_data_type.get_name()` in place of the
    /// Java `Object.hashCode()` call this crate has no generic equivalent for -- see the module
    /// docs.
    pub fn bit_field_hash_code(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.base_data_type.get_name().hash(&mut hasher);
        self.bit_offset.hash(&mut hasher);
        self.bit_size.hash(&mut hasher);
        hasher.finish()
    }

    /// Port of `BitFieldDataType.equals(Object)`. `baseDataType.equals(...)` is approximated with
    /// [`DataType::is_equivalent`] -- see the module docs.
    pub fn bit_field_equals(&self, other: &BitFieldDataType) -> bool {
        let self_mgr = self.base_data_type.get_data_type_manager().map(|m| m.get_universal_id());
        let other_mgr = other.base_data_type.get_data_type_manager().map(|m| m.get_universal_id());
        self_mgr == other_mgr
            && DataType::is_equivalent(self, other)
            && self.bit_offset == other.bit_offset
            && self.storage_size == other.storage_size
            && self.base_data_type.is_equivalent(other.base_data_type.as_ref())
    }

    /// Port of the static `BitFieldDataType.getEffectiveBitSize(int, int)`.
    pub fn effective_bit_size_of(declared_bit_size: i32, base_type_byte_size: i32) -> i32 {
        get_effective_bit_size(declared_bit_size, base_type_byte_size)
    }
}

/// Port of the static `BitFieldDataType.getEffectiveBitSize(int, int)`.
pub fn get_effective_bit_size(declared_bit_size: i32, base_type_byte_size: i32) -> i32 {
    (8 * base_type_byte_size).min(declared_bit_size)
}

/// Port of the static `BitFieldDataType.getMinimumStorageSize(int)`.
pub fn get_minimum_storage_size_no_offset(bit_size: i32) -> i32 {
    get_minimum_storage_size(bit_size, 0)
}

/// Port of the static `BitFieldDataType.getMinimumStorageSize(int, int)`.
pub fn get_minimum_storage_size(bit_size: i32, bit_offset: i32) -> i32 {
    if bit_size == 0 {
        return 1;
    }
    (bit_size + (bit_offset % 8) + 7) / 8
}

/// Port of the static `BitFieldDataType.isValidBaseDataType(DataType)`.
pub fn is_valid_base_data_type(base_data_type: &dyn DataType) -> bool {
    let resolved_owned;
    let dt: &dyn DataType = if base_data_type.is_typedef() {
        resolved_owned = base_data_type.typedef_base_data_type();
        match resolved_owned.as_deref() {
            Some(d) => d,
            None => base_data_type,
        }
    } else {
        base_data_type
    };
    dt.as_enum().is_some() || dt.is_integer_type()
}

/// Port of the static `BitFieldDataType.checkBaseDataType(DataType)`.
///
/// # Errors
/// Returns [`InvalidDataTypeException`] if `base_data_type` is not valid as a bitfield base type.
pub fn check_base_data_type(base_data_type: &dyn DataType) -> Result<(), InvalidDataTypeException> {
    if !is_valid_base_data_type(base_data_type) {
        return Err(InvalidDataTypeException::with_message(format!(
            "Unsupported base data type for bitfield: {}",
            base_data_type.get_name()
        )));
    }
    Ok(())
}

/// Port of the static `BitFieldDataType.intersects(BitFieldDataType, BitFieldDataType, int, int)`.
pub fn intersects(
    bit_field_data_type_1: &BitFieldDataType,
    bit_field_data_type_2: &BitFieldDataType,
    offset_1: i32,
    offset_2: i32,
) -> bool {
    let bit_start_1 = get_normalized_bit_offset(bit_field_data_type_1, offset_1);
    let bit_start_2 = get_normalized_bit_offset(bit_field_data_type_2, offset_2);
    let bit_size_1 = bit_field_data_type_1.get_bit_size();
    let bit_size_2 = bit_field_data_type_2.get_bit_size();

    if bit_start_1 < bit_start_2 {
        bit_start_1 + bit_size_1 > bit_start_2
    } else {
        bit_start_2 + bit_size_2 > bit_start_1
    }
}

/// Port of the static `BitFieldDataType.getNormalizedBitOffset(BitFieldDataType, int)`.
pub fn get_normalized_bit_offset(bit_field_data_type: &BitFieldDataType, byte_offset: i32) -> i32 {
    let is_big_endian = bit_field_data_type.get_data_organization().is_big_endian();
    let bit_size = bit_field_data_type.get_bit_size();
    let bit_offset = bit_field_data_type.get_bit_offset();
    let base_dt_size = bit_field_data_type.get_base_type_size();
    let effective_bit_size = get_effective_bit_size(bit_size, base_dt_size);
    get_normalized_bitfield_offset(
        byte_offset,
        bit_field_data_type.get_storage_size(),
        effective_bit_size,
        bit_offset,
        is_big_endian,
    )
}

impl AbstractDataType for BitFieldDataType {
    fn stored_name(&self) -> String {
        self.name.clone()
    }

    fn stored_category_path(&self) -> CategoryPath {
        ROOT.clone()
    }

    fn stored_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>> {
        self.base_data_type.get_data_type_manager()
    }
}

impl DataType for BitFieldDataType {
    fn get_name(&self) -> String {
        self.abstract_data_type_get_name()
    }

    fn get_category_path(&self) -> CategoryPath {
        self.abstract_data_type_get_category_path()
    }

    fn get_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>> {
        self.abstract_data_type_get_data_type_manager()
    }

    fn get_data_organization(&self) -> Box<dyn DataOrganization> {
        // Port of the final `AbstractDataType.getDataOrganization()`, called directly via the
        // free function rather than `abstract_data_type_get_data_organization` since the latter
        // is equivalent but this avoids an extra indirection through the trait's default.
        default_data_organization(self.stored_data_type_manager().as_deref())
    }

    fn get_default_abbreviated_label_prefix(&self) -> Option<String> {
        self.abstract_data_type_get_default_abbreviated_label_prefix()
    }

    fn is_zero_length(&self) -> bool {
        BitFieldDataType::is_zero_length(self)
    }

    /// Port of `BitFieldDataType.getSettingsDefinitions()`: the base type's settings definitions,
    /// excluding any `EndianSettingsDefinition`.
    fn get_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        let endian_key = EndianSettingsDefinition::DEF.get_storage_key();
        self.base_data_type
            .get_settings_definitions()
            .into_iter()
            .filter(|def| def.get_storage_key() != endian_key)
            .collect()
    }

    /// Port of `BitFieldDataType.isEquivalent(DataType)`. See the module docs for
    /// [`DataType::as_bit_field_data_type`] on why a dedicated (non-seam) downcast was needed.
    fn is_equivalent(&self, dt: &dyn DataType) -> bool {
        let Some(other) = dt.as_bit_field_data_type() else {
            return false;
        };
        other.bit_size == self.bit_size
            && self.base_data_type.is_equivalent(other.base_data_type.as_ref())
    }

    fn is_bit_field_type(&self) -> bool {
        true
    }

    fn as_bit_field(&self) -> Option<&dyn crate::program::seam_stubs::BitFieldDataType> {
        Some(self)
    }

    fn as_bit_field_data_type(&self) -> Option<&BitFieldDataType> {
        Some(self)
    }

    fn get_default_settings(&self) -> Box<dyn Settings> {
        // See the module docs: Java caches this once at construction; this port recomputes it.
        self.base_data_type.get_default_settings()
    }

    fn copy_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        self.clone_data_type(dtm)
    }

    /// Port of `BitFieldDataType.clone(DataTypeManager)`.
    fn clone_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        let same_mgr = self
            .base_data_type
            .get_data_type_manager()
            .map(|m| m.get_universal_id())
            == Some(dtm.get_universal_id());
        if same_mgr {
            return Box::new(BitFieldDataType {
                base_data_type: Arc::clone(&self.base_data_type),
                name: self.name.clone(),
                bit_size: self.bit_size,
                effective_bit_size: self.effective_bit_size,
                bit_offset: self.bit_offset,
                storage_size: self.storage_size,
            });
        }
        let cloned_base = self.base_data_type.clone_data_type(dtm);
        match BitFieldDataType::new(cloned_base, self.bit_size, self.bit_offset) {
            Ok(bf) => Box::new(bf),
            // Mirrors the Java `catch (InvalidDataTypeException e) { throw new
            // AssertException(...) }`: unreachable in practice since `clone_data_type` on an
            // already-valid base type cannot turn it into an invalid one.
            Err(e) => unreachable!("BitFieldDataType::clone produced an invalid base type: {e}"),
        }
    }

    /// See [`BitFieldDataType::get_storage_size`].
    fn get_length(&self) -> i32 {
        self.storage_size
    }

    fn get_aligned_length(&self) -> i32 {
        self.get_length()
    }

    fn get_description(&self) -> String {
        let mut description = format!("{}-bit ", self.effective_bit_size);
        description.push_str(&self.base_data_type.get_display_name());
        description.push_str(" bitfield");
        if self.effective_bit_size != self.bit_size {
            description.push_str(&format!(" (declared as {}-bits)", self.bit_size));
        }
        description
    }

    fn get_value(
        &self,
        buf: &dyn MemBuffer,
        _settings: &dyn Settings,
        _length: i32,
    ) -> Option<Box<dyn std::any::Any>> {
        if self.effective_bit_size == 0 {
            return Some(Box::new(crate::program::model::scalar::Scalar::new(0, 0)));
        }
        let is_signed = self.effective_is_signed();
        let big = self.get_big_integer_value(buf, is_signed)?;
        if self.effective_bit_size <= 64 {
            return Some(Box::new(crate::program::model::scalar::Scalar::new_with_signedness(
                self.effective_bit_size as u8,
                big as i64,
                is_signed,
            )));
        }
        Some(Box::new(big))
    }

    /// Port of `BitFieldDataType.getRepresentation(MemBuffer, Settings, int)`. See the module docs
    /// for the dropped CHAR-format special case.
    fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, _length: i32) -> String {
        if self.bit_size == 0 {
            return String::new();
        }
        let is_signed = self.effective_is_signed();
        let Some(big) = self.get_big_integer_value(buf, is_signed) else {
            return "??".to_string();
        };

        let resolved_owned;
        let dt: &dyn DataType = if self.base_data_type.is_typedef() {
            resolved_owned = self.base_data_type.typedef_base_data_type();
            resolved_owned.as_deref().unwrap_or(self.base_data_type.as_ref())
        } else {
            self.base_data_type.as_ref()
        };

        if let Some(enum_dt) = dt.as_enum() {
            return enum_dt.get_enum_representation(big, settings, self.effective_bit_size);
        }
        if dt.is_boolean_type() {
            // Inlined equivalent of `BooleanDataType.getRepresentation(BigInteger, Settings,
            // int)`: `BigInteger.ZERO.equals(bigInt) ? "FALSE" : "TRUE"`. No downcast from a bare
            // `&dyn DataType` to `&dyn BooleanDataType` exists yet, but that override never reads
            // any instance state, so it is safe to inline directly.
            return if big == 0 { "FALSE" } else { "TRUE" }.to_string();
        }

        // Falls through to the standard `AbstractIntegerDataType` numeric formatting for every
        // other valid base type (plain integers and their typedefs).
        crate::program::model::data::abstract_integer_data_type::format_integer_representation(
            big,
            settings,
            self.effective_bit_size,
            is_signed,
        )
    }

    fn get_value_class(&self, settings: &dyn Settings) -> Option<std::any::TypeId> {
        self.base_data_type.get_value_class(settings)
    }

    fn get_alignment(&self) -> i32 {
        self.base_data_type.get_alignment()
    }
}

impl crate::program::seam_stubs::BitFieldDataType for BitFieldDataType {
    fn get_base_data_type(&self) -> Box<dyn DataType> {
        BitFieldDataType::get_base_data_type(self)
    }

    fn get_bit_size(&self) -> i32 {
        self.effective_bit_size
    }

    fn get_bit_offset(&self) -> i32 {
        self.bit_offset
    }
}

impl std::fmt::Display for BitFieldDataType {
    /// Port of `BitFieldDataType.toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}(storage:{},bitOffset:{})",
            self.get_display_name(),
            self.storage_size,
            self.bit_offset
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::data::enum_::Enum;

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
            struct MockPacking;
            impl crate::program::model::data::bit_field_packing::BitFieldPacking for MockPacking {
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
            Box::new(MockPacking)
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

    struct MockDtm {
        id: i64,
    }
    impl DataTypeManager for MockDtm {
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            Box::new(MockDataOrganization)
        }
        fn get_universal_id(&self) -> crate::util::UniversalID {
            crate::util::UniversalID::new(self.id)
        }
    }

    #[derive(Clone)]
    struct MockInt {
        name: String,
        length: i32,
        signed: bool,
        manager_id: Option<i64>,
    }

    impl DataType for MockInt {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_integer_type(&self) -> bool {
            true
        }
        fn is_signed_integer_type(&self) -> bool {
            self.signed
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.get_name() == dt.get_name() && self.get_length() == dt.get_length()
        }
        fn get_alignment(&self) -> i32 {
            self.length
        }
        fn clone_data_type(&self, _dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
            Box::new(self.clone())
        }
        fn get_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>> {
            self.manager_id.map(|id| Box::new(MockDtm { id }) as Box<dyn DataTypeManager>)
        }
    }

    fn int_type(name: &str, length: i32, signed: bool) -> Box<dyn DataType> {
        Box::new(MockInt { name: name.to_string(), length, signed, manager_id: None })
    }

    fn int_type_with_manager(name: &str, length: i32, signed: bool, manager_id: i64) -> Box<dyn DataType> {
        Box::new(MockInt { name: name.to_string(), length, signed, manager_id: Some(manager_id) })
    }

    struct NotAnInteger;
    impl DataType for NotAnInteger {
        fn get_name(&self) -> String {
            "not_an_int".to_string()
        }
        fn get_length(&self) -> i32 {
            4
        }
    }

    struct MockBuf {
        bytes: Vec<u8>,
        big_endian: bool,
    }
    impl MemBuffer for MockBuf {
        fn get_address(&self) -> crate::program::model::address::Address {
            crate::program::model::address::SpecialAddress::no_address()
        }
        fn get_byte(&self, offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            self.bytes
                .get(offset as usize)
                .copied()
                .ok_or_else(|| crate::program::model::mem::MemoryAccessException::new("out of range"))
        }
        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            if offset < 0 {
                return 0;
            }
            let o = offset as usize;
            if o >= self.bytes.len() {
                return 0;
            }
            let n = buf.len().min(self.bytes.len() - o);
            buf[..n].copy_from_slice(&self.bytes[o..o + n]);
            n
        }
        fn is_big_endian(&self) -> bool {
            self.big_endian
        }
    }

    struct NoSettings;
    impl Settings for NoSettings {}

    #[test]
    fn new_computes_effective_size_and_storage() {
        let bf = BitFieldDataType::new(int_type("int", 4, true), 3, 2).unwrap();
        assert_eq!(bf.get_declared_bit_size(), 3);
        assert_eq!(bf.get_bit_size(), 3);
        assert_eq!(bf.get_bit_offset(), 2);
        assert_eq!(bf.get_storage_size(), 1); // (3 + 2 + 7) / 8 == 1
        assert_eq!(DataType::get_length(&bf), 1);
    }

    #[test]
    fn new_truncates_declared_size_to_base_type_size() {
        // 40 declared bits against a 1-byte base type truncates to 8 effective bits.
        let bf = BitFieldDataType::new_at_offset_zero(int_type("char", 1, true), 40).unwrap();
        assert_eq!(bf.get_declared_bit_size(), 40);
        assert_eq!(bf.get_bit_size(), 8);
    }

    #[test]
    fn new_rejects_invalid_base_data_type() {
        let err = match BitFieldDataType::new_at_offset_zero(Box::new(NotAnInteger), 4) {
            Err(e) => e,
            Ok(_) => panic!("expected an invalid-base-type error"),
        };
        assert!(err.message().contains("Unsupported base data type"));
    }

    #[test]
    fn new_rejects_out_of_range_bit_size() {
        assert!(BitFieldDataType::new_at_offset_zero(int_type("int", 4, true), -1).is_err());
        assert!(BitFieldDataType::new_at_offset_zero(int_type("int", 4, true), 256).is_err());
    }

    #[test]
    fn new_rejects_out_of_range_bit_offset() {
        assert!(BitFieldDataType::new(int_type("int", 4, true), 4, 8).is_err());
        assert!(BitFieldDataType::new(int_type("int", 4, true), 4, -1).is_err());
    }

    #[test]
    fn is_zero_length_reflects_declared_bit_size() {
        let bf = BitFieldDataType::new_at_offset_zero(int_type("int", 4, true), 0).unwrap();
        assert!(BitFieldDataType::is_zero_length(&bf));
        assert!(DataType::is_zero_length(&bf));
        assert_eq!(bf.get_storage_size(), 1); // still reports a 1-byte storage size
    }

    #[test]
    fn get_name_matches_java_naming_convention() {
        let bf = BitFieldDataType::new_at_offset_zero(int_type("int", 4, true), 5).unwrap();
        assert_eq!(DataType::get_name(&bf), "int:5");
    }

    #[test]
    fn get_description_reports_truncation() {
        let bf = BitFieldDataType::new_at_offset_zero(int_type("char", 1, true), 40).unwrap();
        let desc = bf.get_description();
        assert!(desc.starts_with("8-bit"));
        assert!(desc.contains("declared as 40-bits"));
    }

    #[test]
    fn get_description_omits_truncation_note_when_not_truncated() {
        let bf = BitFieldDataType::new_at_offset_zero(int_type("int", 4, true), 5).unwrap();
        assert_eq!(bf.get_description(), "5-bit int bitfield");
    }

    #[test]
    fn is_equivalent_true_for_same_bit_size_and_base_type() {
        let a = BitFieldDataType::new(int_type("int", 4, true), 5, 1).unwrap();
        let b = BitFieldDataType::new(int_type("int", 4, true), 5, 3).unwrap(); // offset ignored
        assert!(DataType::is_equivalent(&a, &b));
    }

    #[test]
    fn is_equivalent_false_for_different_declared_bit_size() {
        let a = BitFieldDataType::new_at_offset_zero(int_type("int", 4, true), 5).unwrap();
        let b = BitFieldDataType::new_at_offset_zero(int_type("int", 4, true), 6).unwrap();
        assert!(!DataType::is_equivalent(&a, &b));
    }

    #[test]
    fn is_equivalent_false_against_non_bit_field() {
        let a = BitFieldDataType::new_at_offset_zero(int_type("int", 4, true), 5).unwrap();
        assert!(!DataType::is_equivalent(&a, int_type("int", 4, true).as_ref()));
    }

    #[test]
    fn as_bit_field_and_seam_placeholder_are_wired() {
        let bf = BitFieldDataType::new(int_type("int", 4, true), 5, 2).unwrap();
        assert!(DataType::is_bit_field_type(&bf));
        let seam = DataType::as_bit_field(&bf).expect("as_bit_field should be Some");
        assert_eq!(seam.get_bit_size(), 5);
        assert_eq!(seam.get_bit_offset(), 2);
        assert_eq!(seam.get_base_data_type().get_name(), "int");
    }

    #[test]
    fn as_bit_field_data_type_downcast_exposes_declared_bit_size() {
        let bf = BitFieldDataType::new_at_offset_zero(int_type("char", 1, true), 40).unwrap();
        let real = DataType::as_bit_field_data_type(&bf).expect("downcast should succeed");
        assert_eq!(real.get_declared_bit_size(), 40);
        assert_eq!(real.get_bit_size(), 8);
    }

    #[test]
    fn get_value_reads_masked_and_shifted_unsigned_bits() {
        // 4-bit unsigned field at bit-offset 2 within a little-endian byte 0b0011_1100 == 0x3C:
        // shifting right by 2 gives 0b0000_1111, masked to 4 bits == 0b1111 == 15.
        let bf = BitFieldDataType::new(int_type("byte", 1, false), 4, 2).unwrap();
        let buf = MockBuf { bytes: vec![0x3C], big_endian: false };
        let value = DataType::get_value(&bf, &buf, &NoSettings, 1).expect("value expected");
        let scalar = value
            .downcast_ref::<crate::program::model::scalar::Scalar>()
            .expect("expected a Scalar");
        assert_eq!(scalar.get_unsigned_value(), 15);
    }

    #[test]
    fn get_value_sign_extends_signed_field() {
        // 4-bit signed field, raw nibble 0b1111 (== -1 in 4-bit two's complement).
        let bf = BitFieldDataType::new(int_type("byte", 1, true), 4, 0).unwrap();
        let buf = MockBuf { bytes: vec![0x0F], big_endian: false };
        let value = DataType::get_value(&bf, &buf, &NoSettings, 1).expect("value expected");
        let scalar = value
            .downcast_ref::<crate::program::model::scalar::Scalar>()
            .expect("expected a Scalar");
        assert_eq!(scalar.get_signed_value(), -1);
    }

    #[test]
    fn get_value_zero_length_returns_zero_scalar() {
        let bf = BitFieldDataType::new_at_offset_zero(int_type("int", 4, true), 0).unwrap();
        let buf = MockBuf { bytes: vec![0xFF, 0xFF, 0xFF, 0xFF], big_endian: false };
        let value = DataType::get_value(&bf, &buf, &NoSettings, 1).expect("value expected");
        let scalar = value
            .downcast_ref::<crate::program::model::scalar::Scalar>()
            .expect("expected a Scalar");
        assert_eq!(scalar.get_unsigned_value(), 0);
    }

    #[test]
    fn get_representation_zero_size_is_empty() {
        let bf = BitFieldDataType::new_at_offset_zero(int_type("int", 4, true), 0).unwrap();
        let buf = MockBuf { bytes: vec![0, 0, 0, 0], big_endian: false };
        assert_eq!(DataType::get_representation(&bf, &buf, &NoSettings, 1), "");
    }

    #[test]
    fn get_representation_falls_back_to_numeric_hex_by_default() {
        let bf = BitFieldDataType::new(int_type("byte", 1, false), 4, 0).unwrap();
        let buf = MockBuf { bytes: vec![0x0F], big_endian: false };
        let repr = DataType::get_representation(&bf, &buf, &NoSettings, 1);
        assert!(repr.ends_with('h'));
    }

    #[test]
    fn get_representation_read_failure_reports_placeholder() {
        let bf = BitFieldDataType::new_at_offset_zero(int_type("int", 4, true), 8).unwrap();
        let buf = MockBuf { bytes: vec![], big_endian: false }; // too short to satisfy storage_size
        assert_eq!(DataType::get_representation(&bf, &buf, &NoSettings, 1), "??");
    }

    struct MockBoolLike;
    impl DataType for MockBoolLike {
        fn get_name(&self) -> String {
            "bool".to_string()
        }
        fn get_length(&self) -> i32 {
            1
        }
        fn is_integer_type(&self) -> bool {
            true
        }
        fn is_boolean_type(&self) -> bool {
            true
        }
    }

    #[test]
    fn get_representation_boolean_base_type_reports_true_false() {
        let bf = BitFieldDataType::new(Box::new(MockBoolLike), 1, 0).unwrap();
        let true_buf = MockBuf { bytes: vec![0x01], big_endian: false };
        let false_buf = MockBuf { bytes: vec![0x00], big_endian: false };
        assert_eq!(DataType::get_representation(&bf, &true_buf, &NoSettings, 1), "TRUE");
        assert_eq!(DataType::get_representation(&bf, &false_buf, &NoSettings, 1), "FALSE");
    }

    struct MockEnum {
        length: i32,
    }
    impl DataType for MockEnum {
        fn get_name(&self) -> String {
            "MyEnum".to_string()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn as_enum(&self) -> Option<&dyn Enum> {
            Some(self)
        }
    }
    impl Enum for MockEnum {
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
        fn clone_enum(&self, _dtm: &dyn DataTypeManager) -> Box<dyn Enum> {
            Box::new(MockEnum { length: self.length })
        }
    }

    #[test]
    fn get_representation_enum_base_type_delegates_to_enum() {
        let bf = BitFieldDataType::new(Box::new(MockEnum { length: 4 }), 4, 0).unwrap();
        let buf = MockBuf { bytes: vec![0x05, 0, 0, 0], big_endian: false };
        assert_eq!(DataType::get_representation(&bf, &buf, &NoSettings, 1), "ENUM(5)");
    }

    #[test]
    fn valid_base_data_type_accepts_integer_and_enum_rejects_other() {
        assert!(is_valid_base_data_type(int_type("int", 4, true).as_ref()));
        assert!(is_valid_base_data_type(&MockEnum { length: 4 }));
        assert!(!is_valid_base_data_type(&NotAnInteger));
    }

    #[test]
    fn clone_data_type_different_manager_rebuilds_via_base_clone() {
        let bf = BitFieldDataType::new(int_type("int", 4, true), 5, 2).unwrap();
        struct NoMgr;
        impl DataTypeManager for NoMgr {}
        let cloned = bf.clone_data_type(&NoMgr);
        // Base type has no data type manager (None) and `NoMgr`'s ID is the zero sentinel, so the
        // `same_mgr` fast path is not taken (None != Some(0)); this exercises the "different
        // manager -> rebuild via base clone_data_type" path instead.
        assert_eq!(DataType::get_length(cloned.as_ref()), 1);
        assert_eq!(cloned.as_bit_field_data_type().unwrap().get_declared_bit_size(), 5);
    }

    #[test]
    fn clone_data_type_same_manager_takes_fast_path() {
        let bf = BitFieldDataType::new(int_type_with_manager("int", 4, true, 7), 5, 2).unwrap();
        let dtm = MockDtm { id: 7 };
        let cloned = bf.clone_data_type(&dtm);
        assert_eq!(cloned.as_bit_field_data_type().unwrap().get_declared_bit_size(), 5);
        assert_eq!(cloned.as_bit_field_data_type().unwrap().get_bit_offset(), 2);
    }

    #[test]
    fn display_matches_java_to_string_format() {
        let bf = BitFieldDataType::new(int_type("int", 4, true), 5, 2).unwrap();
        let shown = format!("{bf}");
        assert!(shown.contains("storage:"));
        assert!(shown.contains("bitOffset:2"));
    }

    #[test]
    fn get_settings_definitions_excludes_endian() {
        struct WithEndian;
        impl DataType for WithEndian {
            fn get_name(&self) -> String {
                "with_endian".to_string()
            }
            fn get_length(&self) -> i32 {
                4
            }
            fn is_integer_type(&self) -> bool {
                true
            }
            fn get_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
                vec![Box::new(EndianSettingsDefinition::DEF)]
            }
        }
        let bf = BitFieldDataType::new_at_offset_zero(Box::new(WithEndian), 4).unwrap();
        assert!(DataType::get_settings_definitions(&bf).is_empty());
    }

    #[test]
    fn bit_field_hash_code_consistent_for_equal_fields() {
        let a = BitFieldDataType::new_at_offset_zero(int_type("int", 4, true), 5).unwrap();
        let b = BitFieldDataType::new_at_offset_zero(int_type("int", 4, true), 5).unwrap();
        assert_eq!(a.bit_field_hash_code(), b.bit_field_hash_code());
    }

    #[test]
    fn bit_field_equals_true_for_matching_fields() {
        let a = BitFieldDataType::new(int_type("int", 4, true), 5, 1).unwrap();
        let b = BitFieldDataType::new(int_type("int", 4, true), 5, 1).unwrap();
        assert!(a.bit_field_equals(&b));
    }

    #[test]
    fn bit_field_equals_false_for_different_offset() {
        let a = BitFieldDataType::new(int_type("int", 4, true), 5, 1).unwrap();
        let b = BitFieldDataType::new(int_type("int", 4, true), 5, 2).unwrap();
        assert!(!a.bit_field_equals(&b));
    }

    #[test]
    fn intersects_detects_overlap_and_non_overlap() {
        // `intersects`/`get_normalized_bit_offset` need a real `DataOrganization`, which requires
        // the base type to actually have a `DataTypeManager` (`AbstractDataType`'s
        // `getDataOrganization()` has no default-constructing fallback -- see the module docs).
        let a = BitFieldDataType::new(int_type_with_manager("int", 4, true, 1), 4, 0).unwrap(); // bits [0,4)
        let b = BitFieldDataType::new(int_type_with_manager("int", 4, true, 1), 4, 0).unwrap(); // bits [0,4) at a different offset
        assert!(intersects(&a, &b, 0, 0));
        assert!(!intersects(&a, &b, 0, 1)); // second byte over, no overlap
    }

    #[test]
    fn get_base_data_type_and_referenced_base_data_type_report_base_name() {
        let bf = BitFieldDataType::new_at_offset_zero(int_type("int", 4, true), 5).unwrap();
        assert_eq!(bf.get_base_data_type().get_name(), "int");
        assert_eq!(bf.referenced_base_data_type().get_name(), "int");
        assert_eq!(bf.get_base_type_size(), 4);
    }

    #[test]
    fn free_function_helpers_match_static_java_methods() {
        assert_eq!(get_effective_bit_size(10, 1), 8);
        assert_eq!(get_effective_bit_size(4, 4), 4);
        assert_eq!(get_minimum_storage_size_no_offset(9), 2);
        assert_eq!(get_minimum_storage_size(9, 0), 2);
        assert_eq!(get_minimum_storage_size(8, 1), 2);
        assert_eq!(get_minimum_storage_size(0, 5), 1);
        assert_eq!(BitFieldDataType::effective_bit_size_of(10, 1), 8);
    }
}
