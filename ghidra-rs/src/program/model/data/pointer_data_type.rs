//! Port of `ghidra.program.model.data.PointerDataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class `extends BuiltIn implements Pointer`. `BuiltIn` (itself extending the unported
//! `DataTypeImpl`) contributes no interface beyond [`BuiltInDataType`](crate::program::model::data::built_in_data_type::BuiltInDataType)/
//! [`DataType`] -- it only adds protected field storage and constructor plumbing this class
//! never overrides beyond what is modeled below -- so, mirroring
//! [`FunctionDefinitionDataType`](crate::program::model::data::function_definition_data_type::FunctionDefinitionDataType)'s
//! identical treatment of its own `GenericDataType` superclass, this trait extends
//! [`Pointer`] directly (which already pulls in [`DataType`]).
//!
//! The private fields `referencedDataType` and `length` have no home on a trait, so they are
//! exposed via required accessor methods ([`PointerDataType::stored_referenced_data_type`]/
//! [`PointerDataType::set_stored_referenced_data_type`], etc.), mirroring
//! [`FunctionDefinitionDataType`]'s accessor convention. The private `deleted` field is exposed
//! the same way; the private `displayName` cache and the `isEquivalentActive` `ThreadLocal`
//! recursion guard are *not* given accessors -- see below for why.
//!
//! Several Java methods share a name with an already-provided default method on [`DataType`]
//! (`hasLanguageDependantLength`, `getLength`, `getAlignedLength`, `getDefaultLabelPrefix`,
//! `getDisplayName`/`getName` (via `get_name`), `getDescription`, `getMnemonic`, `getValue`,
//! `getValueClass`, `getTypeDefSettingsDefinitions`, `isEquivalent`, `dataTypeDeleted`,
//! `isDeleted`, `dataTypeReplaced`, `getCategoryPath`, `dependsOn`, `getRepresentation`) or on
//! [`Pointer`] (`getDataType`); mirroring [`FunctionDefinitionDataType`]'s
//! `function_definition_data_type_impl_*` convention, those bodies are exposed here under
//! distinct `pointer_data_type_impl_*` names. A concrete `impl Pointer`/`impl DataType for ...`
//! is expected to delegate to these.
//!
//! `dataTypeNameChanged(DataType, String)` overrides [`DataType::data_type_name_changed`] only to
//! invalidate the private `displayName` cache and recompute `name`; since neither is cached by
//! this port (see below), the override would be byte-for-byte identical to
//! [`DataType::data_type_name_changed`]'s existing no-op default, so -- mirroring
//! [`FunctionDefinitionDataType`]'s module-level precedent for identical-to-default overrides --
//! it is intentionally not re-declared here.
//!
//! `getDisplayName()`/`getName()` cache their computed string in the private `displayName`/`name`
//! fields (invalidated on rename/replace notifications) purely as a performance optimization; this
//! port recomputes them from [`PointerDataType::stored_referenced_data_type`]/
//! [`PointerDataType::stored_length`] on every call instead (via
//! [`construct_unique_name`]), which is behaviorally equivalent and needs no extra accessor or
//! cache-invalidation bookkeeping.
//!
//! `clone(DataTypeManager)` (the `final` override of `Pointer`'s covariant `DataType.clone`),
//! the static factory methods `getPointer(DataType, DataTypeManager)`/`getPointer(DataType, int)`,
//! and [`Pointer::new_pointer`]/[`Pointer::typedef_builder`] (both abstract on [`Pointer`] itself)
//! all construct a `new PointerDataType(...)` directly, which requires calling a concrete
//! constructor this trait has no way to name generically (there is no `Self: Default`/factory
//! bound). They are left unmodeled, exactly like
//! [`DataType::clone_data_type`]/[`DataType::copy_data_type`]'s own generic
//! (placeholder-returning) defaults and [`FunctionDefinitionDataType`]'s identical treatment of
//! `copy`/`clone`; a concrete implementor overrides `Pointer::new_pointer`/`Pointer::typedef_builder`
//! and supplies its own `getPointer`-equivalent factory functions directly.
//!
//! `isEquivalent(DataType)` needs a `dyn DataType -> dyn Pointer` downcast to recover the other
//! side's referenced-datatype accessor, modeled via [`DataType::as_pointer`] (a concrete
//! implementor is expected to override that to return `Some(self)`, same as
//! [`NoisyStructureBuilder`](crate::program::model::data::noisy_structure_builder::NoisyStructureBuilder)'s
//! existing use of the same downcast). The deep "same id, else path-equal-and-deep-`isEquivalent`"
//! check `DataTypeUtilities.isSameDataType` + `equalsIgnoreConflict` + recursive
//! `getDataType().isEquivalent(otherDataType)` performs (guarded by the private
//! `isEquivalentActive` `ThreadLocal` against infinite recursion on cyclic pointer graphs) is
//! collapsed to a single call to
//! [`is_same_or_equivalent_data_type`](crate::program::model::data::parameter_definition_impl::is_same_or_equivalent_data_type)
//! (`a.is_equivalent(b) || b.is_equivalent(a)`), the same `DataTypeUtilities.isSameDataType`
//! stand-in [`FunctionDefinitionDataType`] already relies on. This drops the explicit recursion
//! guard (a truly self-referential pointer chain could stack-overflow here, same as it would
//! without a guard in Java); adding one back would need a `Cell<bool>` field with no natural home
//! on a trait, so it is left as a known limitation rather than invented accessor plumbing.
//!
//! `dataTypeReplaced`/`dataTypeDeleted` delegate to `DataTypeUtilities.checkValidReplacement` and
//! compare datatypes by Java reference identity (`==`). Neither `DataTypeUtilities` nor a
//! `DataTypeDB` marker it special-cases is ported yet, so -- mirroring
//! [`FunctionDefinitionDataType`]'s identical treatment -- the identity comparison is
//! approximated with [`DataType::get_data_type_path`] equality, and the `checkValidReplacement`
//! validation call is dropped entirely (this class's own override does not call
//! `notifyDeleted()`/emit any error the validation would have caught differently). Producing an
//! independent replacement copy needs [`DataType::clone_data_type`], which needs a live
//! `DataTypeManager`; when this pointer has none, no replacement happens, mirroring
//! [`FunctionDefinitionDataType`]'s identical fallback.
//!
//! `getDefaultLabelPrefix(MemBuffer, Settings, int, DataTypeDisplayOptions)` delegates to the
//! static `getLabelString`, which walks `buf.getMemory().getProgram().getReferenceManager()` /
//! `.getSymbolTable()` / `.getListing()` to render a symbol-derived label (e.g. `PTR_foo`,
//! `PTR_LOOP`, or a deep-pointer prefix). Those three accessors
//! ([`Program::get_reference_manager`](crate::program::model::listing::Program::get_reference_manager),
//! [`Program::get_symbol_table`](crate::program::model::listing::Program::get_symbol_table),
//! [`Program::get_listing`](crate::program::model::listing::Program::get_listing)) are all
//! `&mut self` in this port (reflecting how their backing subsystems are reached elsewhere), but
//! this call chain only ever has a shared `Arc<dyn Program>` (reached via
//! [`MemBuffer::get_memory`](crate::program::model::mem::MemBuffer::get_memory) `->`
//! [`Memory::get_program`](crate::program::model::mem::Memory::get_program)) -- there is no way to
//! get `&mut` access through it without interior mutability those traits don't yet offer. Rather
//! than inventing that plumbing here, `getLabelString`/the private `getPointerClassification`/
//! `getDataAt` helpers are left unported; the default label-prefix-for-data body falls back to the
//! constant [`POINTER_LABEL_PREFIX`], matching every early-return branch already present in the
//! Java source (no program, no reference, no symbol, `SourceType.DEFAULT` name).
//!
//! `getAddressValue(MemBuffer, int, Settings, Consumer<String>)` (and its two overloads) *are*
//! modeled as free functions ([`get_address_value`], [`get_address_value_default`],
//! [`get_address_value_for_space`]) since none of their logic needs the unavailable `&mut`
//! accessors above -- only [`Program::get_address_factory`](crate::program::model::listing::Program::get_address_factory)
//! (already `&self`) and two newly-grown, defaulted `&self` accessors,
//! [`Program::get_image_base`](crate::program::model::listing::Program::get_image_base) and
//! [`Memory::get_program`](crate::program::model::mem::Memory::get_program)/
//! [`Memory::locate_addresses_for_file_offset`](crate::program::model::mem::Memory::locate_addresses_for_file_offset)/
//! [`Memory::has_file_bytes`](crate::program::model::mem::Memory::has_file_bytes). One genuinely
//! new placeholder was needed: [`PointerTypeSettingsDefinition`](crate::program::seam_stubs::PointerTypeSettingsDefinition)
//! (see `STUBS.tsv`), since that settings-definition class is not ported yet.
//!
//! The Java source's `instanceof SegmentedAddressSpace` branch (used by both `getAddressValue`
//! overloads and by the private `getSegmentedAddressValue`/`normalize` helpers) has no
//! counterpart in this port: [`AddressSpace`](crate::program::model::address::AddressSpace) and
//! [`SegmentedAddressSpace`](crate::program::model::address::SegmentedAddressSpace) are unrelated
//! concrete structs here (composition, not the Java subclassing relationship), so there is no way
//! to detect at runtime that a given `Arc<AddressSpace>` is "really" a segmented space. That
//! branch, and the two private helpers that only exist to serve it, are intentionally not ported.
//! `DataConverter`'s `getInstance(boolean)` factory is also not ported yet (its
//! `BigEndianDataConverter`/`LittleEndianDataConverter` singletons don't exist), so the private
//! `getStoredOffset` helper is reimplemented directly as [`read_stored_offset`] rather than
//! routing through that trait.

use std::any::{Any, TypeId};

use crate::docking::settings::number_settings_definition::NumberSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::string_settings_definition::StringSettingsDefinition;
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::data::address_space_settings_definition::AddressSpaceSettingsDefinition;
use crate::program::model::data::category_path::{CategoryPath, ROOT};
use crate::program::model::data::component_offset_settings_definition::ComponentOffsetSettingsDefinition;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::offset_mask_settings_definition::{self, OffsetMaskSettingsDefinition};
use crate::program::model::data::offset_shift_settings_definition::OffsetShiftSettingsDefinition;
use crate::program::model::data::parameter_definition_impl::is_same_or_equivalent_data_type;
use crate::program::model::data::pointer::{Pointer, NAP};
use crate::program::model::data::typedef_settings_definition::TypeDefSettingsDefinition;
use crate::program::seam_stubs::{PointerType, PointerTypeSettingsDefinition};
use crate::program::model::mem::MemBuffer;
use std::sync::Arc;

/// Maximum encoded pointer length, in bytes.
///
/// Port of `PointerDataType.MAX_POINTER_SIZE_BYTES`.
pub const MAX_POINTER_SIZE_BYTES: i32 = 8;

/// Port of `PointerDataType.POINTER_NAME`.
pub const POINTER_NAME: &str = "pointer";

/// Port of `PointerDataType.POINTER_LABEL_PREFIX`.
pub const POINTER_LABEL_PREFIX: &str = "PTR";

/// Port of `PointerDataType.POINTER_LABEL_PREFIX_U`.
pub const POINTER_LABEL_PREFIX_U: &str = "PTR_";

/// Port of `PointerDataType.POINTER_LOOP_LABEL`.
pub const POINTER_LOOP_LABEL: &str = "PTR_LOOP";

/// Basic implementation for a pointer dataType.
///
/// Port of `ghidra.program.model.data.PointerDataType`. See the module-level documentation for
/// the conventions used to resolve name clashes with [`DataType`]/[`Pointer`], for the required
/// accessors standing in for private fields, and for what was left required (rather than
/// defaulted) or intentionally omitted.
pub trait PointerDataType: Pointer {
    /// Backing storage for the private `referencedDataType` field.
    fn stored_referenced_data_type(&self) -> Option<Box<dyn DataType>>;
    /// Mutator for the private `referencedDataType` field's backing storage.
    fn set_stored_referenced_data_type(&mut self, referenced_data_type: Option<Box<dyn DataType>>);
    /// Backing storage for the private `length` field. Values `<= 0` mean a dynamically-sized
    /// pointer, matching the Java field's own convention.
    fn stored_length(&self) -> i32;
    /// Mutator for the private `length` field's backing storage.
    fn set_stored_length(&mut self, length: i32);
    /// Backing storage for the private `deleted` field.
    fn stored_deleted(&self) -> bool;
    /// Mutator for the private `deleted` field's backing storage.
    fn set_stored_deleted(&mut self, deleted: bool);

    /// Default body for [`Pointer::get_data_type`].
    fn pointer_data_type_impl_get_data_type(&self) -> Option<Box<dyn DataType>> {
        self.stored_referenced_data_type()
    }

    /// Default body for [`DataType::has_language_dependant_length`].
    fn pointer_data_type_impl_has_language_dependant_length(&self) -> bool {
        self.stored_length() <= 0
    }

    /// Default body for [`DataType::get_length`].
    fn pointer_data_type_impl_length(&self) -> i32 {
        let length = self.stored_length();
        if length <= 0 {
            self.get_data_organization().get_pointer_size()
        } else {
            length
        }
    }

    /// Default body for [`DataType::get_aligned_length`].
    fn pointer_data_type_impl_aligned_length(&self) -> i32 {
        self.pointer_data_type_impl_length()
    }

    /// Default body for [`DataType::get_default_label_prefix`].
    fn pointer_data_type_impl_default_label_prefix(&self) -> String {
        POINTER_LABEL_PREFIX.to_string()
    }

    /// Default body for [`DataType::get_default_label_prefix_for_data`]. See the module-level
    /// documentation for why the symbol-derived label (`getLabelString`) is not ported.
    fn pointer_data_type_impl_default_label_prefix_for_data(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
    ) -> String {
        let _ = (buf, settings);
        POINTER_LABEL_PREFIX.to_string()
    }

    /// Default body for `DataType.getDisplayName()`/`get_display_name`. NOTE: Pointer display
    /// name only specifies length if the base type is `None`.
    fn pointer_data_type_impl_display_name(&self) -> String {
        match self.stored_referenced_data_type() {
            None => {
                let mut s = POINTER_NAME.to_string();
                let length = self.stored_length();
                if length > 0 {
                    s.push_str(&(8 * length).to_string());
                }
                s
            }
            Some(dt) => format!("{} *", dt.get_display_name()),
        }
    }

    /// Default body for `DataType.getName()`/`get_name`.
    fn pointer_data_type_impl_name(&self) -> String {
        construct_unique_name(
            self.stored_referenced_data_type().as_deref(),
            self.stored_length(),
        )
    }

    /// Default body for [`DataType::get_description`].
    fn pointer_data_type_impl_description(&self) -> String {
        let mut sbuf = String::new();
        let length = self.stored_length();
        if length > 0 {
            sbuf.push_str(&(8 * length).to_string());
            sbuf.push_str("-bit ");
        }
        sbuf.push_str(POINTER_NAME);
        if let Some(dt) = self.stored_referenced_data_type() {
            sbuf.push_str(" to ");
            if dt.is_pointer() {
                sbuf.push_str(&dt.get_description());
            } else {
                sbuf.push_str(&dt.get_display_name());
            }
        }
        sbuf
    }

    /// Default body for [`DataType::get_mnemonic`].
    fn pointer_data_type_impl_mnemonic(&self, settings: &dyn Settings) -> String {
        match self.stored_referenced_data_type() {
            None => "addr".to_string(),
            Some(dt) if dt.is_default_data_type() => "addr".to_string(),
            Some(dt) => format!("{} *", dt.get_mnemonic(settings)),
        }
    }

    /// Default body for [`DataType::get_value`].
    fn pointer_data_type_impl_value(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
    ) -> Option<Box<dyn Any>> {
        get_address_value_default(buf, self.pointer_data_type_impl_length(), settings)
            .map(|addr| Box::new(addr) as Box<dyn Any>)
    }

    /// Default body for [`DataType::get_value_class`].
    fn pointer_data_type_impl_value_class(&self) -> Option<TypeId> {
        Some(TypeId::of::<Address>())
    }

    /// Default body for [`DataType::get_type_def_settings_definitions`].
    fn pointer_data_type_impl_type_def_settings_definitions(&self) -> Vec<Box<dyn TypeDefSettingsDefinition>> {
        // NOTE: order dictates auto-name attribute ordering (order should not be changed).
        vec![
            Box::new(PointerTypeSettingsDefinition::DEF),
            Box::new(AddressSpaceSettingsDefinition::DEF),
            Box::new(OffsetMaskSettingsDefinition::DEF),
            Box::new(OffsetShiftSettingsDefinition::DEF),
            Box::new(ComponentOffsetSettingsDefinition::DEF),
        ]
    }

    /// Default body for [`DataType::get_representation`].
    fn pointer_data_type_impl_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings) -> String {
        match get_address_value_default(buf, self.pointer_data_type_impl_length(), settings) {
            Some(addr) => addr.to_string(),
            None => NAP.to_string(),
        }
    }

    /// Default body for [`DataType::is_equivalent`]. See the module-level documentation for how
    /// this diverges from `PointerDataType.isEquivalent`.
    fn pointer_data_type_impl_is_equivalent(&self, dt: &dyn DataType) -> bool {
        let Some(other) = dt.as_pointer() else {
            return false;
        };
        if self.pointer_data_type_impl_has_language_dependant_length()
            != other.has_language_dependant_length()
        {
            return false;
        }
        if !self.pointer_data_type_impl_has_language_dependant_length()
            && self.pointer_data_type_impl_length() != other.get_length()
        {
            return false;
        }
        match (self.stored_referenced_data_type(), other.get_data_type()) {
            (None, None) => true,
            (None, Some(_)) | (Some(_), None) => false,
            (Some(mine), Some(theirs)) => is_same_or_equivalent_data_type(mine.as_ref(), theirs.as_ref()),
        }
    }

    /// Default body for [`DataType::data_type_deleted`]. See the module-level documentation for
    /// how this diverges from `PointerDataType.dataTypeDeleted` (`notifyDeleted()` has no
    /// counterpart here and is dropped).
    fn pointer_data_type_impl_data_type_deleted(&mut self, dt: &dyn DataType) {
        if let Some(referenced) = self.stored_referenced_data_type() {
            if referenced.get_data_type_path() == dt.get_data_type_path() {
                self.set_stored_deleted(true);
            }
        }
    }

    /// Default body for [`DataType::is_deleted`].
    fn pointer_data_type_impl_is_deleted(&self) -> bool {
        self.stored_deleted()
    }

    /// Default body for [`DataType::data_type_replaced`]. See the module-level documentation for
    /// how this diverges from `PointerDataType.dataTypeReplaced`.
    fn pointer_data_type_impl_data_type_replaced(&mut self, old_dt: &dyn DataType, new_dt: &dyn DataType) {
        let Some(referenced) = self.stored_referenced_data_type() else {
            return;
        };
        if referenced.get_data_type_path() != old_dt.get_data_type_path() {
            return;
        }
        let Some(dtm) = self.get_data_type_manager() else {
            return;
        };
        let replacement = new_dt.clone_data_type(dtm.as_ref());
        self.set_stored_referenced_data_type(Some(replacement));
    }

    /// Default body for [`DataType::get_category_path`].
    fn pointer_data_type_impl_category_path(&self) -> CategoryPath {
        match self.stored_referenced_data_type() {
            None => ROOT.clone(),
            Some(dt) => dt.get_category_path(),
        }
    }

    /// Default body for [`DataType::depends_on`]. See the module-level documentation for how the
    /// Java reference-identity comparison (`referencedDataType == dt`) is approximated here.
    fn pointer_data_type_impl_depends_on(&self, dt: &dyn DataType) -> bool {
        match self.stored_referenced_data_type() {
            None => false,
            Some(referenced) => {
                referenced.get_data_type_path() == dt.get_data_type_path() || referenced.depends_on(dt)
            }
        }
    }
}

/// Get a unique name for a pointer to the given (optional) referenced data type and length.
///
/// Port of the private static `PointerDataType.constructUniqueName(DataType, int)`.
pub fn construct_unique_name(referenced_data_type: Option<&dyn DataType>, ptr_length: i32) -> String {
    match referenced_data_type {
        None => {
            let mut s = POINTER_NAME.to_string();
            if ptr_length > 0 {
                s.push_str(&(8 * ptr_length).to_string());
            }
            s
        }
        Some(dt) => {
            let mut s = format!("{} *", dt.get_name());
            if ptr_length > 0 {
                s.push_str(&(8 * ptr_length).to_string());
            }
            s
        }
    }
}

/// Read a `size`-byte stored offset from `buf`, standing in for the private static
/// `PointerDataType.getStoredOffset(MemBuffer, int, boolean, Consumer)`. Returns `None` if fewer
/// than `size` bytes were available (mirroring the Java method's `null` return; the
/// `errorHandler.accept("Insufficient data")` notification is dropped since this port has no
/// error-handler plumbed through at this layer -- callers that need it inspect the `None`
/// themselves).
fn read_stored_offset(buf: &dyn MemBuffer, size: i32, signed: bool) -> Option<i64> {
    if size <= 0 || size > 8 {
        return None;
    }
    let mut bytes = vec![0u8; size as usize];
    let count = buf.get_bytes_into(&mut bytes, 0);
    if count != size {
        return None;
    }
    if !buf.is_big_endian() {
        bytes.reverse();
    }
    let mut value: u64 = 0;
    for b in &bytes {
        value = (value << 8) | (*b as u64);
    }
    if signed {
        let bits = (size as u32) * 8;
        if bits < 64 && (value & (1u64 << (bits - 1))) != 0 {
            value |= !0u64 << bits;
        }
    }
    Some(value as i64)
}

/// Format `offset` as lower-case hex, zero-padded to a multiple of 4 digits.
///
/// Port of the private static `PointerDataType.formatOffset(long)`.
fn format_offset(offset: i64) -> String {
    let hex = format!("{:x}", offset as u64);
    let len = hex.len();
    let padded_len = len - (len % 4) + 4;
    format!("{hex:0>padded_len$}")
}

/// Generate an address value based upon bytes stored at the specified buf location, ignoring any
/// error that occurs.
///
/// Port of the public static `PointerDataType.getAddressValue(MemBuffer, int, Settings)`.
pub fn get_address_value_default(buf: &dyn MemBuffer, size: i32, settings: &dyn Settings) -> Option<Address> {
    get_address_value(buf, size, settings, &mut |_msg: String| {})
}

/// Generate an address value based upon bytes stored at the specified buf location.
///
/// Port of the public static `PointerDataType.getAddressValue(MemBuffer, int, Settings,
/// Consumer<String>)`. See the module-level documentation for why the `instanceof
/// SegmentedAddressSpace` branch of the Java source is not ported.
pub fn get_address_value(
    buf: &dyn MemBuffer,
    size: i32,
    settings: &dyn Settings,
    error_handler: &mut dyn FnMut(String),
) -> Option<Address> {
    let space_name = AddressSpaceSettingsDefinition::DEF.get_value(settings);
    let mem = buf.get_memory();

    let pointer_type = PointerTypeSettingsDefinition::DEF.get_type(settings);
    let signed_offset = pointer_type == PointerType::Relative;

    let mut addr_offset = read_stored_offset(buf, size, signed_offset)?;

    let mask = OffsetMaskSettingsDefinition::DEF.get_value(settings);
    if mask == 0 {
        error_handler("Invalid pointer mask: 0".to_string());
        return None;
    }
    if mask != offset_mask_settings_definition::DEFAULT {
        addr_offset &= mask;
    }

    let shift = OffsetShiftSettingsDefinition::DEF.get_value(settings);
    if shift < 0 {
        if signed_offset {
            addr_offset >>= -shift;
        } else {
            addr_offset = ((addr_offset as u64) >> (-shift) as u32) as i64;
        }
    } else if shift > 0 {
        addr_offset <<= shift;
    }

    if pointer_type != PointerType::Default && space_name.is_some() {
        error_handler("Address Space and Pointer Type settings conflict".to_string());
        return None;
    }

    match pointer_type {
        PointerType::ImageBaseRelative => {
            if addr_offset == 0 {
                // Done for consistency with old ImageBaseOffsetDataType.
                // A 0 relative offset is considered invalid (NaP).
                return None;
            }
            let Some(program) = mem.as_ref().and_then(|m| m.get_program()) else {
                error_handler("Memory not specified".to_string());
                return None;
            };
            let image_base = program.get_image_base()?;
            let unit_size = image_base.space().unit_size() as i64;
            return Some(image_base.add_wrap(addr_offset * unit_size));
        }
        PointerType::Relative => {
            if addr_offset == 0 {
                return None;
            }
            let base = buf.get_address();
            let unit_size = base.space().unit_size() as i64;
            return Some(base.add_wrap(addr_offset * unit_size));
        }
        PointerType::FileOffset => {
            let Some(mem) = mem.as_ref() else {
                error_handler("Memory not specified".to_string());
                return None;
            };
            if !mem.has_file_bytes() {
                error_handler("No File bytes used".to_string());
                return None;
            }
            let matches = mem.locate_addresses_for_file_offset(addr_offset);
            return match matches.len() {
                1 => Some(matches[0].clone()),
                n if n > 1 => {
                    error_handler(format!("Non-unique File offset mapping: 0x{addr_offset:x}"));
                    None
                }
                _ => {
                    error_handler(format!("File offset mapping not found: 0x{addr_offset:x}"));
                    None
                }
            };
        }
        PointerType::Default => {}
    }

    let target_space = match &space_name {
        Some(space_name) => {
            let Some(program) = mem.as_ref().and_then(|m| m.get_program()) else {
                error_handler("Memory not specified".to_string());
                return None;
            };
            let space = program
                .get_address_factory()
                .and_then(|factory| factory.get_address_space_by_name(space_name));
            match space {
                Some(space) => space,
                None => {
                    error_handler(format!(
                        "Address space not defined: {space_name}:{}",
                        format_offset(addr_offset)
                    ));
                    return None;
                }
            }
        }
        None => buf.get_address().space().clone(),
    };

    // NOTE: addrOffset treated as word offset when targetSpace addressable unitsize > 1.
    target_space.address_from_word_offset(addr_offset).ok()
}

/// Generate an address value based upon bytes stored at the specified buf location. The stored
/// bytes are interpreted as an unsigned byte offset into the specified `target_space`.
///
/// Port of the public static `PointerDataType.getAddressValue(MemBuffer, int, AddressSpace)`.
/// See the module-level documentation for why the `instanceof SegmentedAddressSpace` branch of
/// the Java source is not ported.
pub fn get_address_value_for_space(
    buf: &dyn MemBuffer,
    size: i32,
    target_space: &Arc<AddressSpace>,
) -> Option<Address> {
    if size <= 0 || size > 8 {
        return None;
    }
    let offset = read_stored_offset(buf, size, false)?;
    target_space.address_from_word_offset(offset).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::data_type_manager::DataTypeManager;

    #[derive(Debug, Clone, Default)]
    struct MockDataType {
        name: String,
        length: i32,
        is_pointer: bool,
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_pointer(&self) -> bool {
            self.is_pointer
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.get_name() == dt.get_name() && self.get_length() == dt.get_length()
        }
        fn clone_data_type(&self, _dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
            Box::new(self.clone())
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    struct MockBitFieldPacking;
    impl crate::program::model::data::bit_field_packing::BitFieldPacking for MockBitFieldPacking {
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

    struct MockDataOrganization;
    impl DataOrganization for MockDataOrganization {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_pointer_size(&self) -> i32 {
            4
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
            4
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
            crate::program::model::data::data_organization::NO_MAXIMUM_ALIGNMENT
        }
        fn get_machine_alignment(&self) -> i32 {
            4
        }
        fn get_default_alignment(&self) -> i32 {
            1
        }
        fn get_default_pointer_alignment(&self) -> i32 {
            4
        }
        fn get_size_alignment(&self, size: i32) -> i32 {
            size
        }
        fn get_bit_field_packing(&self) -> Box<dyn crate::program::model::data::bit_field_packing::BitFieldPacking> {
            Box::new(MockBitFieldPacking)
        }
        fn get_size_alignment_count(&self) -> i32 {
            4
        }
        fn get_sizes(&self) -> Vec<i32> {
            vec![1, 2, 4, 8]
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

    struct MockSettings;
    impl Settings for MockSettings {}

    struct MockMemMockPointerDataType {
        referenced: Option<Box<dyn DataType>>,
        length: i32,
        deleted: bool,
        has_manager: bool,
    }

    impl MockMemMockPointerDataType {
        fn new(referenced: Option<Box<dyn DataType>>, length: i32) -> Self {
            MockMemMockPointerDataType {
                referenced,
                length,
                deleted: false,
                has_manager: false,
            }
        }
    }

    impl DataType for MockMemMockPointerDataType {
        fn get_name(&self) -> String {
            self.pointer_data_type_impl_name()
        }
        fn get_display_name(&self) -> String {
            self.pointer_data_type_impl_display_name()
        }
        fn get_description(&self) -> String {
            self.pointer_data_type_impl_description()
        }
        fn get_mnemonic(&self, settings: &dyn Settings) -> String {
            self.pointer_data_type_impl_mnemonic(settings)
        }
        fn has_language_dependant_length(&self) -> bool {
            self.pointer_data_type_impl_has_language_dependant_length()
        }
        fn get_length(&self) -> i32 {
            self.pointer_data_type_impl_length()
        }
        fn get_aligned_length(&self) -> i32 {
            self.pointer_data_type_impl_aligned_length()
        }
        fn get_category_path(&self) -> CategoryPath {
            self.pointer_data_type_impl_category_path()
        }
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            Box::new(MockDataOrganization)
        }
        fn get_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>> {
            self.has_manager.then(|| Box::new(MockDataTypeManager) as Box<dyn DataTypeManager>)
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.pointer_data_type_impl_is_equivalent(dt)
        }
        fn data_type_deleted(&mut self, dt: &dyn DataType) {
            self.pointer_data_type_impl_data_type_deleted(dt)
        }
        fn is_deleted(&self) -> bool {
            self.pointer_data_type_impl_is_deleted()
        }
        fn data_type_replaced(&mut self, old_dt: &dyn DataType, new_dt: &dyn DataType) {
            self.pointer_data_type_impl_data_type_replaced(old_dt, new_dt)
        }
        fn depends_on(&self, dt: &dyn DataType) -> bool {
            self.pointer_data_type_impl_depends_on(dt)
        }
        fn is_pointer(&self) -> bool {
            true
        }
        fn as_pointer(&self) -> Option<&dyn Pointer> {
            Some(self)
        }
    }

    impl Pointer for MockMemMockPointerDataType {
        fn get_data_type(&self) -> Option<Box<dyn DataType>> {
            self.pointer_data_type_impl_get_data_type()
        }
        fn new_pointer(&self, data_type: Box<dyn DataType>) -> Box<dyn Pointer> {
            Box::new(MockMemMockPointerDataType::new(Some(data_type), self.length))
        }
        fn typedef_builder(&self) -> Box<dyn crate::program::model::data::pointer_typedef_builder::PointerTypedefBuilder> {
            struct StubBuilder;
            impl crate::program::model::data::pointer_typedef_builder::PointerTypedefBuilder for StubBuilder {}
            Box::new(StubBuilder)
        }
    }

    impl PointerDataType for MockMemMockPointerDataType {
        fn stored_referenced_data_type(&self) -> Option<Box<dyn DataType>> {
            self.referenced.as_ref().map(|dt| dt.clone_data_type(&MockDataTypeManager))
        }
        fn set_stored_referenced_data_type(&mut self, referenced_data_type: Option<Box<dyn DataType>>) {
            self.referenced = referenced_data_type;
        }
        fn stored_length(&self) -> i32 {
            self.length
        }
        fn set_stored_length(&mut self, length: i32) {
            self.length = length;
        }
        fn stored_deleted(&self) -> bool {
            self.deleted
        }
        fn set_stored_deleted(&mut self, deleted: bool) {
            self.deleted = deleted;
        }
    }

    struct MockMemBuffer {
        bytes: Vec<u8>,
        big_endian: bool,
        address: Address,
    }

    impl MemBuffer for MockMemBuffer {
        fn get_byte(&self, _offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn is_big_endian(&self) -> bool {
            self.big_endian
        }
        fn get_bytes(&self, buffer: &mut [u8], offset: i32) -> usize {
            let offset = offset as usize;
            if offset >= self.bytes.len() {
                return 0;
            }
            let n = buffer.len().min(self.bytes.len() - offset);
            buffer[..n].copy_from_slice(&self.bytes[offset..offset + n]);
            n
        }
    }

    fn ram_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let mut p: Box<dyn PointerDataType> = Box::new(MockMemMockPointerDataType::new(None, -1));
        assert_eq!(p.get_length(), 4); // dynamic size, from MockDataOrganization
        assert!(p.get_data_type().is_none());
        p.set_stored_length(8);
        assert_eq!(p.get_length(), 8);
    }

    #[test]
    fn display_name_without_referenced_type_includes_bit_length() {
        let p = MockMemMockPointerDataType::new(None, 8);
        assert_eq!(p.get_display_name(), "pointer64");
    }

    #[test]
    fn display_name_with_referenced_type_appends_star() {
        let referenced = MockDataType {
            name: "int".to_string(),
            length: 4,
            ..Default::default()
        };
        let p = MockMemMockPointerDataType::new(Some(Box::new(referenced)), -1);
        assert_eq!(p.get_display_name(), "int *");
    }

    #[test]
    fn description_recurses_into_pointer_to_pointer() {
        let inner = MockDataType {
            name: "int".to_string(),
            length: 4,
            is_pointer: false,
        };
        let inner_ptr = MockMemMockPointerDataType::new(Some(Box::new(inner)), -1);
        assert_eq!(inner_ptr.get_description(), "pointer to int");

        let outer = MockMemMockPointerDataType::new(
            Some(Box::new(MockDataType {
                name: "int *".to_string(),
                length: 4,
                is_pointer: true,
            })),
            -1,
        );
        assert!(outer.get_description().starts_with("pointer to"));
    }

    #[test]
    fn mnemonic_defaults_to_addr_when_no_referenced_type() {
        let p = MockMemMockPointerDataType::new(None, -1);
        let settings = MockSettings;
        assert_eq!(p.get_mnemonic(&settings), "addr");
    }

    #[test]
    fn is_equivalent_matches_same_referenced_type_and_length() {
        let a = MockMemMockPointerDataType::new(
            Some(Box::new(MockDataType {
                name: "int".to_string(),
                length: 4,
                is_pointer: false,
            })),
            4,
        );
        let b = MockMemMockPointerDataType::new(
            Some(Box::new(MockDataType {
                name: "int".to_string(),
                length: 4,
                is_pointer: false,
            })),
            4,
        );
        assert!(a.is_equivalent(&b));

        let c = MockMemMockPointerDataType::new(None, 4);
        assert!(!a.is_equivalent(&c));
    }

    #[test]
    fn data_type_deleted_marks_deleted_flag() {
        let referenced = MockDataType {
            name: "int".to_string(),
            length: 4,
            is_pointer: false,
        };
        let mut p = MockMemMockPointerDataType::new(Some(Box::new(referenced.clone())), 4);
        assert!(!p.is_deleted());
        p.data_type_deleted(&referenced);
        assert!(p.is_deleted());
    }

    #[test]
    fn data_type_replaced_swaps_referenced_type_when_manager_present() {
        let old_dt = MockDataType {
            name: "int".to_string(),
            length: 4,
            is_pointer: false,
        };
        let new_dt = MockDataType {
            name: "long".to_string(),
            length: 8,
            is_pointer: false,
        };
        let mut p = MockMemMockPointerDataType::new(Some(Box::new(old_dt.clone())), 4);
        p.has_manager = true;
        p.data_type_replaced(&old_dt, &new_dt);
        assert_eq!(p.get_data_type().unwrap().get_name(), "long");
    }

    #[test]
    fn construct_unique_name_smoke() {
        assert_eq!(construct_unique_name(None, -1), "pointer");
        assert_eq!(construct_unique_name(None, 8), "pointer64");
        let dt = MockDataType {
            name: "int".to_string(),
            length: 4,
            is_pointer: false,
        };
        assert_eq!(construct_unique_name(Some(&dt), -1), "int *");
    }

    #[test]
    fn get_address_value_decodes_little_endian_default_pointer() {
        let space = ram_space();
        let buf = MockMemBuffer {
            bytes: vec![0x00, 0x10, 0x00, 0x00],
            big_endian: false,
            address: space.address(0),
        };
        let settings = MockSettings;
        let addr = get_address_value_default(&buf, 4, &settings).expect("address decoded");
        assert_eq!(addr.offset(), 0x1000);
    }

    #[test]
    fn get_address_value_decodes_big_endian_default_pointer() {
        let space = ram_space();
        let buf = MockMemBuffer {
            bytes: vec![0x00, 0x00, 0x10, 0x00],
            big_endian: true,
            address: space.address(0),
        };
        let settings = MockSettings;
        let addr = get_address_value_default(&buf, 4, &settings).expect("address decoded");
        assert_eq!(addr.offset(), 0x1000);
    }

    #[test]
    fn get_address_value_reports_insufficient_data() {
        let space = ram_space();
        let buf = MockMemBuffer {
            bytes: vec![0x00, 0x01],
            big_endian: false,
            address: space.address(0),
        };
        let settings = MockSettings;
        assert!(get_address_value_default(&buf, 4, &settings).is_none());
    }
}
