//! Port of `ghidra.program.model.data.PointerDataType`, plus the fixed-size
//! `Pointer8DataType`..`Pointer64DataType` subclasses (see [`sized_pointer_data_type!`]).
//!
//! Divergences from Java:
//!   - `getDefaultLabelPrefix(MemBuffer, Settings, int, DataTypeDisplayOptions)` delegates to
//!     the static `getLabelString`, which walks the program's reference manager, symbol table and
//!     listing. Those accessors are `&mut self` on [`Program`](crate::program::model::listing::Program)
//!     while this call chain only reaches a shared `Arc<dyn Program>`, so `getLabelString` is not
//!     ported and the prefix is always [`POINTER_LABEL_PREFIX`] (Java's result for every
//!     early-return branch: no program, reference or symbol, or a default-sourced symbol).
//!   - The `instanceof SegmentedAddressSpace` branch of `getAddressValue` (and the private
//!     `getSegmentedAddressValue`/`normalize` helpers) is not ported: [`AddressSpace`] carries no
//!     segmented-space identity to test against. `getStoredOffset` is reimplemented directly as
//!     [`read_stored_offset`] since `DataConverter.getInstance` is not ported.
//!   - Data type identity (Java `==`) in `dataTypeDeleted`/`dependsOn` is compared by data type
//!     path; `dataTypeReplaced` takes an owned replacement ([`PointerDataType::replace_data_type`]).
//!   - Parent tracking (`addParent`/`notifyNameChanged`) is not performed: `BuiltIn.addParent` is
//!     a no-op in Java too, and the referenced type does not track its pointers here.

use std::any::{Any, TypeId};

use crate::docking::settings::number_settings_definition::NumberSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::string_settings_definition::StringSettingsDefinition;
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::data::address_space_settings_definition::AddressSpaceSettingsDefinition;
use crate::program::model::data::category_path::{CategoryPath, ROOT};
use crate::program::model::data::component_offset_settings_definition::ComponentOffsetSettingsDefinition;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::database::data::data_type_utilities::DataTypeUtilities;
use crate::program::model::data::built_in::{impl_built_in, BuiltIn, BuiltInBase};
use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
use crate::program::model::data::data_type::{DataType, IntoDataTypeArc};
use crate::program::model::data::data_type_impl::DataTypeImpl;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::default_data_type::DefaultDataType;
use crate::program::model::data::offset_mask_settings_definition::{self, OffsetMaskSettingsDefinition};
use crate::program::model::data::offset_shift_settings_definition::OffsetShiftSettingsDefinition;
use crate::program::model::data::pointer::{Pointer, NAP};
use crate::program::model::data::pointer_typedef_builder::PointerTypedefBuilder;
use crate::program::model::lang::decompiler_language::DecompilerLanguage;
use crate::program::seam_stubs::share_data_type;
use crate::program::model::data::typedef_settings_definition::TypeDefSettingsDefinition;
use crate::program::model::data::pointer_type_settings_definition::PointerTypeSettingsDefinition;
use crate::program::model::mem::MemBuffer;
use std::sync::Arc;

/// The `PointerType` constants, by their stored settings value, for matching in
/// [`get_address_value`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PointerTypeKind {
    Default,
    ImageBaseRelative,
    Relative,
    FileOffset,
}

impl PointerTypeKind {
    /// `PointerType.valueOf(int)`; the settings definition already maps unknown values to
    /// `DEFAULT`.
    fn of(value: i32) -> Self {
        match value {
            1 => PointerTypeKind::ImageBaseRelative,
            2 => PointerTypeKind::Relative,
            3 => PointerTypeKind::FileOffset,
            _ => PointerTypeKind::Default,
        }
    }
}

/// Zero-sized marker for calling the defaulted [`DataTypeUtilities`] methods.
struct Utils;
impl DataTypeUtilities for Utils {}

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

/// Basic implementation for a pointer data type.
///
/// Port of `ghidra.program.model.data.PointerDataType` (a concrete `BuiltIn` implementing
/// [`Pointer`]). The referenced data type is held as the canonical `Arc<dyn DataType>` handle;
/// `None` is a default ("undefined") pointer. A length `<= 0` is stored as `-1` and means the
/// pointer size comes from the data organization.
///
/// Java's static `dataType` is [`PointerDataType::data_type`].
#[derive(Clone)]
pub struct PointerDataType {
    base: BuiltInBase,
    referenced_data_type: Option<Arc<dyn DataType>>,
    length: i32,
    deleted: bool,
}

impl std::fmt::Debug for PointerDataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.get_name())
    }
}

impl std::fmt::Display for PointerDataType {
    /// Java `toString()`: the name, which always includes an explicit pointer length.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.get_name())
    }
}

thread_local! {
    /// Java's per-instance `isEquivalentActive` `ThreadLocal`: the pointers (by address) whose
    /// `isEquivalent` is currently evaluating their referenced types on this thread, used to
    /// break cycles through self-referencing composites.
    static EQUIVALENCE_ACTIVE: std::cell::RefCell<std::collections::HashSet<usize>> =
        std::cell::RefCell::new(std::collections::HashSet::new());
}

impl PointerDataType {
    /// Port of `PointerDataType(DataType, int, DataTypeManager)`: a pointer to
    /// `referenced_data_type` (`None` for a default pointer) of `length` bytes (`<= 0` for a
    /// dynamically-sized pointer whose size comes from `dtm`'s data organization).
    ///
    /// # Errors
    /// Returns `Err` (Java: `IllegalArgumentException`) if the referenced type is a bitfield.
    pub fn new_with(
        referenced_data_type: Option<impl IntoDataTypeArc>,
        length: i32,
        dtm: Option<&dyn DataTypeManager>,
    ) -> Result<Self, String> {
        let referenced_data_type = referenced_data_type.map(IntoDataTypeArc::into_data_type_arc);
        if let Some(dt) = &referenced_data_type {
            if dt.is_bit_field_type() {
                return Err(format!(
                    "IllegalArgumentException: Pointer reference data-type may not be a bitfield: {}",
                    dt.get_name()
                ));
            }
        }
        let category_path = referenced_data_type.as_ref().map(|dt| dt.get_category_path());
        let name = construct_unique_name(referenced_data_type.as_deref(), length);
        Ok(PointerDataType {
            base: BuiltInBase::new(category_path, &name, dtm),
            referenced_data_type,
            length: if length <= 0 { -1 } else { length },
            deleted: false,
        })
    }

    /// Port of `PointerDataType()`/`PointerDataType(DataTypeManager)`: a dynamically-sized
    /// default pointer.
    pub fn new(dtm: Option<&dyn DataTypeManager>) -> Self {
        Self::new_with(None::<Arc<dyn DataType>>, -1, dtm).expect("a default pointer is always valid")
    }

    /// Port of `PointerDataType(DataType)`/`PointerDataType(DataType, int)`.
    ///
    /// # Errors
    /// See [`new_with`](Self::new_with).
    pub fn to(referenced_data_type: impl IntoDataTypeArc, length: i32) -> Result<Self, String> {
        Self::new_with(Some(referenced_data_type), length, None)
    }

    /// The shared default pointer (Java's static `PointerDataType.dataType`).
    pub fn instance() -> &'static Arc<PointerDataType> {
        static INSTANCE: std::sync::OnceLock<Arc<PointerDataType>> = std::sync::OnceLock::new();
        INSTANCE.get_or_init(|| Arc::new(PointerDataType::new(None)))
    }

    /// The shared default pointer as a data type handle (Java's static `dataType`).
    pub fn data_type() -> Arc<dyn DataType> {
        PointerDataType::instance().clone()
    }

    /// Port of the static `PointerDataType.getPointer(DataType, DataTypeManager)`.
    ///
    /// # Errors
    /// See [`new_with`](Self::new_with).
    pub fn get_pointer(dt: Option<impl IntoDataTypeArc>, dtm: Option<&dyn DataTypeManager>) -> Result<Self, String> {
        Self::new_with(dt, -1, dtm)
    }

    /// Port of the static `PointerDataType.getPointer(DataType, int)`: an out-of-range
    /// `pointer_size` (outside 1..=8) yields a dynamically-sized pointer.
    ///
    /// # Errors
    /// See [`new_with`](Self::new_with).
    pub fn get_pointer_sized(dt: Option<impl IntoDataTypeArc>, pointer_size: i32) -> Result<Self, String> {
        let length = if (1..=8).contains(&pointer_size) { pointer_size } else { -1 };
        Self::new_with(dt, length, None)
    }

    /// The raw stored length: `-1` for a dynamically-sized pointer.
    pub fn stored_length(&self) -> i32 {
        self.length
    }

    /// The shared handle on the referenced data type, if any.
    pub fn referenced_data_type(&self) -> Option<&Arc<dyn DataType>> {
        self.referenced_data_type.as_ref()
    }

    /// Port of `PointerDataType.dataTypeReplaced(DataType, DataType)` with an owned replacement:
    /// if this pointer references `old_dt` it now references `new_dt` and moves to `new_dt`'s
    /// category.
    ///
    /// # Errors
    /// Returns `Err` if `old_dt`/`new_dt` fail `DataTypeUtilities.checkValidReplacement`.
    pub fn replace_data_type(&mut self, old_dt: &dyn DataType, new_dt: Arc<dyn DataType>) -> Result<(), String> {
        Utils.check_valid_replacement(old_dt, new_dt.as_ref())?;
        let Some(referenced) = &self.referenced_data_type else {
            return Ok(());
        };
        if referenced.get_data_type_path() != old_dt.get_data_type_path() {
            return Ok(());
        }
        let new_dt = if std::ptr::addr_eq(Arc::as_ptr(&new_dt), self as *const Self) {
            DefaultDataType::data_type()
        } else {
            new_dt
        };
        let name = construct_unique_name(Some(new_dt.as_ref()), self.length);
        self.base = self.base.renamed(Some(new_dt.get_category_path()), &name);
        self.referenced_data_type = Some(new_dt);
        Ok(())
    }

    fn c_type_declaration(&self, data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
        let org = data_organization.map(|o| Arc::new(o.clone())).unwrap_or_else(|| self.get_data_organization());
        Some(self.built_in_get_c_type_declaration_for_self(false, &org, false))
    }

    fn built_in_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        Vec::new()
    }

    /// `BuiltIn.getDecompilerDisplayName`: the name fixed at construction.
    fn decompiler_display_name(&self, _language: DecompilerLanguage) -> String {
        self.base.name().to_string()
    }

    fn is_equivalent_to_pointer(&self, dt: &dyn DataType) -> bool {
        if std::ptr::addr_eq(dt as *const dyn DataType, self as *const Self) {
            return true;
        }
        let Some(p) = dt.as_pointer() else {
            return false;
        };
        let other_data_type = p.get_data_type();
        if self.has_language_dependant_length() != p.has_language_dependant_length() {
            return false;
        }
        if !self.has_language_dependant_length() && self.get_length() != p.get_length() {
            return false;
        }
        let Some(referenced) = &self.referenced_data_type else {
            return other_data_type.is_none();
        };
        let Some(other_data_type) = other_data_type else {
            return false;
        };
        // if they contain datatypes that have same ids, then we are essentially equivalent.
        if Utils.is_same_data_type(referenced.as_ref(), other_data_type.as_ref()) {
            return true;
        }
        if !Utils.equals_ignore_conflict(&referenced.get_path_name(), &other_data_type.get_path_name()) {
            return false;
        }
        let key = self as *const Self as usize;
        let already_active = EQUIVALENCE_ACTIVE.with(|active| !active.borrow_mut().insert(key));
        if already_active {
            return true;
        }
        let result = referenced.is_equivalent(other_data_type.as_ref());
        EQUIVALENCE_ACTIVE.with(|active| active.borrow_mut().remove(&key));
        result
    }
}

impl_built_in!(PointerDataType);

impl DataType for PointerDataType {
    /// Port of `PointerDataType.getName()`: recomputed from the referenced type (which may have
    /// been renamed), else the name fixed at construction.
    fn get_name(&self) -> String {
        match &self.referenced_data_type {
            Some(dt) => construct_unique_name(Some(dt.as_ref()), self.length),
            None => self.base.name().to_string(),
        }
    }

    /// Port of `PointerDataType.getDisplayName()`: only a default pointer shows its length.
    fn get_display_name(&self) -> String {
        match &self.referenced_data_type {
            None => {
                let mut s = POINTER_NAME.to_string();
                if self.length > 0 {
                    s.push_str(&(8 * self.length).to_string());
                }
                s
            }
            Some(dt) => format!("{} *", dt.get_display_name()),
        }
    }

    fn get_category_path(&self) -> CategoryPath {
        match &self.referenced_data_type {
            None => ROOT.clone(),
            Some(dt) => dt.get_category_path(),
        }
    }

    fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
        self.base.data_organization()
    }

    fn get_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        BuiltIn::built_in_get_settings_definitions(self)
    }

    fn get_default_settings(&self) -> Box<dyn Settings> {
        DataTypeImpl::data_type_impl_get_default_settings(self)
    }

    /// Port of `PointerDataType.clone(DataTypeManager)`: the referenced type is not cloned (to
    /// avoid circular references), only rebound to `dtm`'s data organization.
    fn clone_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        Box::new(
            PointerDataType::new_with(self.referenced_data_type.clone(), self.length, Some(dtm))
                .expect("an existing pointer's referenced type is valid"),
        )
    }

    /// `BuiltIn.copy(DataTypeManager)` is final and returns `clone(dtm)`.
    fn copy_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        self.clone_data_type(dtm)
    }

    fn has_language_dependant_length(&self) -> bool {
        self.length <= 0
    }

    fn get_length(&self) -> i32 {
        if self.length <= 0 {
            self.get_data_organization().get_pointer_size()
        } else {
            self.length
        }
    }

    fn get_aligned_length(&self) -> i32 {
        self.get_length()
    }

    fn get_alignment(&self) -> i32 {
        DataTypeImpl::data_type_impl_get_alignment(self)
    }

    fn get_default_label_prefix(&self) -> Option<String> {
        Some(POINTER_LABEL_PREFIX.to_string())
    }

    fn get_default_abbreviated_label_prefix(&self) -> Option<String> {
        self.get_default_label_prefix()
    }

    fn get_description(&self) -> String {
        let mut sbuf = String::new();
        if self.length > 0 {
            sbuf.push_str(&(8 * self.length).to_string());
            sbuf.push_str("-bit ");
        }
        sbuf.push_str(POINTER_NAME);
        if let Some(dt) = &self.referenced_data_type {
            sbuf.push_str(" to ");
            if dt.as_pointer().is_some() {
                sbuf.push_str(&dt.get_description());
            } else {
                sbuf.push_str(&dt.get_display_name());
            }
        }
        sbuf
    }

    fn get_mnemonic(&self, settings: &dyn Settings) -> String {
        match &self.referenced_data_type {
            None => "addr".to_string(),
            Some(dt) if dt.is_default_data_type() => "addr".to_string(),
            Some(dt) => format!("{} *", dt.get_mnemonic(settings)),
        }
    }

    fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, _length: i32) -> Option<Box<dyn Any>> {
        get_address_value_default(buf, self.get_length(), settings).map(|addr| Box::new(addr) as Box<dyn Any>)
    }

    fn get_value_class(&self, _settings: &dyn Settings) -> Option<TypeId> {
        Some(TypeId::of::<Address>())
    }

    fn get_type_def_settings_definitions(&self) -> Vec<Box<dyn TypeDefSettingsDefinition>> {
        // NOTE: order dictates auto-name attribute ordering (order should not be changed).
        vec![
            Box::new(PointerTypeSettingsDefinition::DEF),
            Box::new(AddressSpaceSettingsDefinition::DEF),
            Box::new(OffsetMaskSettingsDefinition::DEF),
            Box::new(OffsetShiftSettingsDefinition::DEF),
            Box::new(ComponentOffsetSettingsDefinition::DEF),
        ]
    }

    fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, _length: i32) -> String {
        match get_address_value_default(buf, self.get_length(), settings) {
            Some(addr) => addr.to_string(),
            None => NAP.to_string(),
        }
    }

    fn is_equivalent(&self, dt: &dyn DataType) -> bool {
        self.is_equivalent_to_pointer(dt)
    }

    /// Port of `PointerDataType.dataTypeDeleted(DataType)` (identity compared by data type path).
    fn data_type_deleted(&mut self, dt: &dyn DataType) {
        if let Some(referenced) = &self.referenced_data_type {
            if referenced.get_data_type_path() == dt.get_data_type_path() {
                self.deleted = true;
            }
        }
    }

    fn is_deleted(&self) -> bool {
        self.deleted
    }

    // `data_type_replaced(&dyn, &dyn)` keeps the trait default: storing the replacement needs an
    // owned handle; [`PointerDataType::replace_data_type`] is the owned entry point.

    fn depends_on(&self, dt: &dyn DataType) -> bool {
        match &self.referenced_data_type {
            None => false,
            Some(referenced) => referenced.get_data_type_path() == dt.get_data_type_path() || referenced.depends_on(dt),
        }
    }

    fn get_source_archive(&self) -> Option<Box<dyn crate::program::model::data::source_archive::SourceArchive>> {
        DataTypeImpl::data_type_impl_get_source_archive(self)
    }

    fn runtime_class(&self) -> Option<TypeId> {
        Some(TypeId::of::<Self>())
    }

    fn is_pointer(&self) -> bool {
        true
    }

    fn as_pointer(&self) -> Option<&dyn Pointer> {
        Some(self)
    }

    fn as_built_in(&self) -> Option<&dyn BuiltIn> {
        Some(self)
    }

    fn as_built_in_data_type(&self) -> Option<&dyn crate::program::model::data::built_in_data_type::BuiltInDataType> {
        Some(self)
    }
}

impl Pointer for PointerDataType {
    fn get_data_type(&self) -> Option<Box<dyn DataType>> {
        self.referenced_data_type.as_ref().map(share_data_type)
    }

    /// Port of `PointerDataType.newPointer(DataType)`: a pointer of this pointer's length to
    /// `data_type` (not cloned: no data type manager is recorded, see [`BuiltInBase`]).
    fn new_pointer(&self, data_type: Box<dyn DataType>) -> Box<dyn Pointer> {
        Box::new(
            PointerDataType::new_with(Some(data_type), self.length, None)
                .unwrap_or_else(|e| panic!("{e}")),
        )
    }

    fn typedef_builder(&self) -> PointerTypedefBuilder {
        PointerTypedefBuilder::for_pointer(self)
    }
}

/// Declares a fixed-size pointer class (Java `PointerNDataType extends PointerDataType`, whose
/// only content is constructors fixing the length): a newtype over [`PointerDataType`] with its
/// own class identity ([`DataType::runtime_class`]) and `dataType` singleton, forwarding every
/// other [`DataType`]/[`Pointer`] method. As in Java, `clone`/`copy` return a plain
/// `PointerDataType` (`PointerDataType.clone` is final).
macro_rules! sized_pointer_data_type {
    ($ty:ident, $len:expr, $java:literal) => {
        #[doc = concat!("Port of `ghidra.program.model.data.", $java, "`: a pointer of fixed length ", stringify!($len), ".")]
        #[derive(Clone, Debug)]
        pub struct $ty(pub $crate::program::model::data::pointer_data_type::PointerDataType);

        impl $ty {
            #[doc = concat!("Port of `", $java, "(DataType)`; `None` is the no-argument constructor.")]
            ///
            /// # Errors
            /// Returns `Err` if the referenced type is a bitfield.
            pub fn new(
                referenced_data_type: Option<impl $crate::program::model::data::data_type::IntoDataTypeArc>,
            ) -> Result<Self, String> {
                Ok($ty($crate::program::model::data::pointer_data_type::PointerDataType::new_with(
                    referenced_data_type,
                    $len,
                    None,
                )?))
            }

            /// The shared default instance (Java's static `dataType`).
            pub fn instance() -> &'static std::sync::Arc<$ty> {
                static INSTANCE: std::sync::OnceLock<std::sync::Arc<$ty>> = std::sync::OnceLock::new();
                INSTANCE.get_or_init(|| {
                    std::sync::Arc::new(
                        $ty::new(None::<std::sync::Arc<dyn $crate::program::model::data::data_type::DataType>>)
                            .expect("a default pointer is always valid"),
                    )
                })
            }

            /// The shared default instance as a data type handle (Java's static `dataType`).
            pub fn data_type() -> std::sync::Arc<dyn $crate::program::model::data::data_type::DataType> {
                $ty::instance().clone()
            }
        }

        impl std::ops::Deref for $ty {
            type Target = $crate::program::model::data::pointer_data_type::PointerDataType;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl $crate::program::model::data::data_type::DataType for $ty {
            fn has_language_dependant_length(&self) -> bool {
                self.0.has_language_dependant_length()
            }
            fn get_settings_definitions(&self) -> Vec<Box<dyn $crate::docking::settings::settings_definition::SettingsDefinition>> {
                self.0.get_settings_definitions()
            }
            fn get_type_def_settings_definitions(&self) -> Vec<Box<dyn $crate::program::model::data::typedef_settings_definition::TypeDefSettingsDefinition>> {
                self.0.get_type_def_settings_definitions()
            }
            fn get_default_settings(&self) -> Box<dyn $crate::docking::settings::settings::Settings> {
                self.0.get_default_settings()
            }
            fn clone_data_type(&self, dtm: &dyn $crate::program::model::data::data_type_manager::DataTypeManager) -> Box<dyn $crate::program::model::data::data_type::DataType> {
                self.0.clone_data_type(dtm)
            }
            fn copy_data_type(&self, dtm: &dyn $crate::program::model::data::data_type_manager::DataTypeManager) -> Box<dyn $crate::program::model::data::data_type::DataType> {
                self.0.copy_data_type(dtm)
            }
            fn get_category_path(&self) -> $crate::program::model::data::category_path::CategoryPath {
                self.0.get_category_path()
            }
            fn get_data_type_path(&self) -> $crate::program::seam_stubs::DataTypePath {
                self.0.get_data_type_path()
            }
            fn get_data_type_manager(&self) -> Option<Box<dyn $crate::program::model::data::data_type_manager::DataTypeManager>> {
                self.0.get_data_type_manager()
            }
            fn get_display_name(&self) -> String {
                self.0.get_display_name()
            }
            fn get_name(&self) -> String {
                self.0.get_name()
            }
            fn get_path_name(&self) -> String {
                self.0.get_path_name()
            }
            fn get_mnemonic(&self, settings: &dyn $crate::docking::settings::settings::Settings) -> String {
                self.0.get_mnemonic(settings)
            }
            fn get_length(&self) -> i32 {
                self.0.get_length()
            }
            fn get_aligned_length(&self) -> i32 {
                self.0.get_aligned_length()
            }
            fn is_zero_length(&self) -> bool {
                self.0.is_zero_length()
            }
            fn is_not_yet_defined(&self) -> bool {
                self.0.is_not_yet_defined()
            }
            fn get_description(&self) -> String {
                self.0.get_description()
            }
            fn get_value(&self, buf: &dyn $crate::program::model::mem::MemBuffer, settings: &dyn $crate::docking::settings::settings::Settings, length: i32) -> Option<Box<dyn std::any::Any>> {
                self.0.get_value(buf, settings, length)
            }
            fn is_encodable(&self) -> bool {
                self.0.is_encodable()
            }
            fn encode_value( &self, value: &dyn std::any::Any, buf: &dyn $crate::program::model::mem::MemBuffer, settings: &dyn $crate::docking::settings::settings::Settings, length: i32, ) -> Result<Vec<u8>, $crate::program::model::data::data_type_with_charset::DataTypeEncodeError> {
                self.0.encode_value(value, buf, settings, length)
            }
            fn get_value_class(&self, settings: &dyn $crate::docking::settings::settings::Settings) -> Option<std::any::TypeId> {
                self.0.get_value_class(settings)
            }
            fn get_default_label_prefix(&self) -> Option<String> {
                self.0.get_default_label_prefix()
            }
            fn get_default_abbreviated_label_prefix(&self) -> Option<String> {
                self.0.get_default_abbreviated_label_prefix()
            }
            fn get_default_label_prefix_for_data( &self, buf: &dyn $crate::program::model::mem::MemBuffer, settings: &dyn $crate::docking::settings::settings::Settings, len: i32, options: &dyn $crate::program::model::data::data_type_display_options::DataTypeDisplayOptions, ) -> Option<String> {
                self.0.get_default_label_prefix_for_data(buf, settings, len, options)
            }
            fn get_default_offcut_label_prefix( &self, buf: &dyn $crate::program::model::mem::MemBuffer, settings: &dyn $crate::docking::settings::settings::Settings, len: i32, options: &dyn $crate::program::model::data::data_type_display_options::DataTypeDisplayOptions, offcut_offset: i32, ) -> Option<String> {
                self.0.get_default_offcut_label_prefix(buf, settings, len, options, offcut_offset)
            }
            fn get_representation(&self, buf: &dyn $crate::program::model::mem::MemBuffer, settings: &dyn $crate::docking::settings::settings::Settings, length: i32) -> String {
                self.0.get_representation(buf, settings, length)
            }
            fn encode_representation( &self, repr: &str, buf: &dyn $crate::program::model::mem::MemBuffer, settings: &dyn $crate::docking::settings::settings::Settings, length: i32, ) -> Result<Vec<u8>, $crate::program::model::data::data_type_with_charset::DataTypeEncodeError> {
                self.0.encode_representation(repr, buf, settings, length)
            }
            fn is_deleted(&self) -> bool {
                self.0.is_deleted()
            }
            fn is_equivalent(&self, dt: &dyn $crate::program::model::data::data_type::DataType) -> bool {
                self.0.is_equivalent(dt)
            }
            fn get_parents(&self) -> Vec<Box<dyn $crate::program::model::data::data_type::DataType>> {
                self.0.get_parents()
            }
            fn get_alignment(&self) -> i32 {
                self.0.get_alignment()
            }
            fn depends_on(&self, dt: &dyn $crate::program::model::data::data_type::DataType) -> bool {
                self.0.depends_on(dt)
            }
            fn get_source_archive(&self) -> Option<Box<dyn $crate::program::model::data::source_archive::SourceArchive>> {
                self.0.get_source_archive()
            }
            fn get_last_change_time(&self) -> i64 {
                self.0.get_last_change_time()
            }
            fn get_last_change_time_in_source_archive(&self) -> i64 {
                self.0.get_last_change_time_in_source_archive()
            }
            fn get_universal_id(&self) -> $crate::util::UniversalID {
                self.0.get_universal_id()
            }
            fn get_data_organization(&self) -> std::sync::Arc<$crate::program::model::data::data_organization_impl::DataOrganizationImpl> {
                self.0.get_data_organization()
            }
            fn is_structure(&self) -> bool {
                self.0.is_structure()
            }
            fn is_union(&self) -> bool {
                self.0.is_union()
            }
            fn is_typedef(&self) -> bool {
                self.0.is_typedef()
            }
            fn typedef_base_data_type(&self) -> Option<Box<dyn $crate::program::model::data::data_type::DataType>> {
                self.0.typedef_base_data_type()
            }
            fn is_array(&self) -> bool {
                self.0.is_array()
            }
            fn is_pointer(&self) -> bool {
                self.0.is_pointer()
            }
            fn is_floating_point(&self) -> bool {
                self.0.is_floating_point()
            }
            fn is_integer_type(&self) -> bool {
                self.0.is_integer_type()
            }
            fn is_signed_integer_type(&self) -> bool {
                self.0.is_signed_integer_type()
            }
            fn is_default_data_type(&self) -> bool {
                self.0.is_default_data_type()
            }
            fn is_undefined_type(&self) -> bool {
                self.0.is_undefined_type()
            }
            fn is_void_type(&self) -> bool {
                self.0.is_void_type()
            }
            fn is_bit_field_type(&self) -> bool {
                self.0.is_bit_field_type()
            }
            fn is_dynamic_type(&self) -> bool {
                self.0.is_dynamic_type()
            }
            fn is_factory_type(&self) -> bool {
                self.0.is_factory_type()
            }
            fn is_function_definition_type(&self) -> bool {
                self.0.is_function_definition_type()
            }
            fn is_boolean_type(&self) -> bool {
                self.0.is_boolean_type()
            }
            fn is_wide_char_type(&self) -> bool {
                self.0.is_wide_char_type()
            }
            fn is_array_stringable_type(&self) -> bool {
                self.0.is_array_stringable_type()
            }
            fn is_string_type(&self) -> bool {
                self.0.is_string_type()
            }
            fn as_enum(&self) -> Option<&dyn $crate::program::model::data::enum_::Enum> {
                self.0.as_enum()
            }
            fn as_structure(&self) -> Option<&dyn crate::program::model::data::structure::Structure> {
                self.0.as_structure()
            }
            fn as_array(&self) -> Option<&dyn crate::program::model::data::array::Array> {
                self.0.as_array()
            }
            fn as_partial_union( &self, ) -> Option<&dyn crate::program::model::pcode::partial_union::PartialUnion> {
                self.0.as_partial_union()
            }
            fn as_dynamic(&self) -> Option<&dyn crate::program::model::data::dynamic::Dynamic> {
                self.0.as_dynamic()
            }
            fn as_factory(&self) -> Option<&dyn crate::program::model::data::factory_data_type::FactoryDataType> {
                self.0.as_factory()
            }
            fn as_typedef(&self) -> Option<&dyn crate::program::model::data::typedef::TypeDef> {
                self.0.as_typedef()
            }
            fn as_composite(&self) -> Option<&dyn crate::program::model::data::composite::Composite> {
                self.0.as_composite()
            }
            fn as_abstract_integer( &self, ) -> Option<&dyn crate::program::model::data::abstract_integer_data_type::AbstractIntegerDataType> {
                self.0.as_abstract_integer()
            }
            fn as_union(&self) -> Option<&dyn crate::program::model::data::union::Union> {
                self.0.as_union()
            }
            fn as_function_definition( &self, ) -> Option<&dyn crate::program::model::data::function_definition::FunctionDefinition> {
                self.0.as_function_definition()
            }
            fn as_built_in_data_type( &self, ) -> Option<&dyn crate::program::model::data::built_in_data_type::BuiltInDataType> {
                self.0.as_built_in_data_type()
            }
            fn as_built_in(&self) -> Option<&dyn crate::program::model::data::built_in::BuiltIn> {
                self.0.as_built_in()
            }
            fn as_bit_field(&self) -> Option<&dyn crate::program::seam_stubs::BitFieldDataType> {
                self.0.as_bit_field()
            }
            fn as_bit_field_data_type( &self, ) -> Option<&crate::program::model::data::bit_field_data_type::BitFieldDataType> {
                self.0.as_bit_field_data_type()
            }
            fn data_type_size_changed(&mut self, dt: &dyn $crate::program::model::data::data_type::DataType) {
                self.0.data_type_size_changed(dt)
            }
            fn data_type_alignment_changed(&mut self, dt: &dyn $crate::program::model::data::data_type::DataType) {
                self.0.data_type_alignment_changed(dt)
            }
            fn data_type_deleted(&mut self, dt: &dyn $crate::program::model::data::data_type::DataType) {
                self.0.data_type_deleted(dt)
            }
            fn data_type_name_changed(&mut self, dt: &dyn $crate::program::model::data::data_type::DataType, old_name: &str) {
                self.0.data_type_name_changed(dt, old_name)
            }

            fn runtime_class(&self) -> Option<std::any::TypeId> {
                Some(std::any::TypeId::of::<$ty>())
            }

            fn as_pointer(&self) -> Option<&dyn $crate::program::model::data::pointer::Pointer> {
                Some(self)
            }
        }

        impl $crate::program::model::data::pointer::Pointer for $ty {
            fn get_data_type(&self) -> Option<Box<dyn $crate::program::model::data::data_type::DataType>> {
                $crate::program::model::data::pointer::Pointer::get_data_type(&self.0)
            }

            fn new_pointer(
                &self,
                data_type: Box<dyn $crate::program::model::data::data_type::DataType>,
            ) -> Box<dyn $crate::program::model::data::pointer::Pointer> {
                $crate::program::model::data::pointer::Pointer::new_pointer(&self.0, data_type)
            }

            fn typedef_builder(&self) -> $crate::program::model::data::pointer_typedef_builder::PointerTypedefBuilder {
                $crate::program::model::data::pointer_typedef_builder::PointerTypedefBuilder::for_pointer(self)
            }
        }
    };
}
pub(crate) use sized_pointer_data_type;

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

    let pointer_type = PointerTypeKind::of(PointerTypeSettingsDefinition::DEF.get_type(Some(settings)).value());
    let signed_offset = pointer_type == PointerTypeKind::Relative;

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

    if pointer_type != PointerTypeKind::Default && space_name.is_some() {
        error_handler("Address Space and Pointer Type settings conflict".to_string());
        return None;
    }

    match pointer_type {
        PointerTypeKind::ImageBaseRelative => {
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
        PointerTypeKind::Relative => {
            if addr_offset == 0 {
                return None;
            }
            let base = buf.get_address();
            let unit_size = base.space().unit_size() as i64;
            return Some(base.add_wrap(addr_offset * unit_size));
        }
        PointerTypeKind::FileOffset => {
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
        PointerTypeKind::Default => {}
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
    use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::byte_data_type::ByteDataType;
    use crate::program::model::data::dword_data_type::DWordDataType;
    use crate::program::model::data::structure_data_type::StructureDataType;

    struct MockSettings;
    impl Settings for MockSettings {}

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
    fn default_pointer_matches_java_constants() {
        let p = PointerDataType::instance();
        assert_eq!(p.get_name(), "pointer");
        assert_eq!(p.get_display_name(), "pointer");
        assert_eq!(p.get_description(), "pointer");
        assert_eq!(p.get_mnemonic(&MockSettings), "addr");
        assert!(p.has_language_dependant_length());
        // default data organization: 4-byte pointers
        assert_eq!(p.get_length(), 4);
        assert_eq!(p.get_category_path(), ROOT.clone());
        assert_eq!(p.get_default_label_prefix(), Some("PTR".to_string()));
        assert!(p.get_data_type().is_none());
        assert_eq!(p.get_type_def_settings_definitions().len(), 5);
    }

    #[test]
    fn sized_pointer_names_include_bit_length() {
        let p = PointerDataType::new_with(None::<Arc<dyn DataType>>, 8, None).unwrap();
        assert_eq!(p.get_name(), "pointer64");
        assert_eq!(p.get_display_name(), "pointer64");
        assert_eq!(p.get_description(), "64-bit pointer");
        assert_eq!(p.get_length(), 8);
        assert!(!p.has_language_dependant_length());

        let q = PointerDataType::to(ByteDataType::data_type(), 8).unwrap();
        assert_eq!(q.get_name(), "byte *64");
        assert_eq!(q.get_display_name(), "byte *");
        assert_eq!(q.get_description(), "64-bit pointer to byte");
        assert_eq!(q.get_mnemonic(&MockSettings), "db *");
        assert_eq!(q.to_string(), "byte *64");
    }

    #[test]
    fn pointer_to_pointer_description_recurses() {
        let inner = PointerDataType::to(DWordDataType::data_type(), -1).unwrap();
        assert_eq!(inner.get_name(), "dword *");
        let outer = PointerDataType::to(Box::new(inner), -1).unwrap();
        assert_eq!(outer.get_name(), "dword * *");
        assert_eq!(outer.get_description(), "pointer to pointer to dword");
    }

    #[test]
    fn non_positive_length_is_dynamic() {
        let p = PointerDataType::to(ByteDataType::data_type(), 0).unwrap();
        assert_eq!(p.stored_length(), -1);
        assert!(p.has_language_dependant_length());
        assert_eq!(PointerDataType::get_pointer_sized(Some(ByteDataType::data_type()), 9).unwrap().stored_length(), -1);
        assert_eq!(PointerDataType::get_pointer_sized(Some(ByteDataType::data_type()), 2).unwrap().stored_length(), 2);
    }

    #[test]
    fn category_path_follows_referenced_type() {
        let s = StructureDataType::new_in_category(CategoryPath::parse("/a/b").unwrap(), "S", 4);
        let p = PointerDataType::to(Box::new(s), -1).unwrap();
        assert_eq!(p.get_category_path().get_path(), "/a/b");
        assert_eq!(p.get_path_name(), "/a/b/S *");
    }

    #[test]
    fn bitfield_reference_is_rejected() {
        use crate::program::model::data::bit_field_data_type::BitFieldDataType;
        let bf = BitFieldDataType::new_at_offset_zero(Box::new(ByteDataType::new(None)), 3).unwrap();
        let err = PointerDataType::to(Box::new(bf), -1).unwrap_err();
        assert!(err.contains("may not be a bitfield"), "{err}");
    }

    #[test]
    fn is_equivalent_compares_length_kind_and_referenced_type() {
        let a = PointerDataType::to(ByteDataType::data_type(), 4).unwrap();
        let b = PointerDataType::to(Box::new(ByteDataType::new(None)), 4).unwrap();
        assert!(a.is_equivalent(&b));
        let dynamic = PointerDataType::to(ByteDataType::data_type(), -1).unwrap();
        assert!(!a.is_equivalent(&dynamic));
        let other_len = PointerDataType::to(ByteDataType::data_type(), 8).unwrap();
        assert!(!a.is_equivalent(&other_len));
        let to_dword = PointerDataType::to(DWordDataType::data_type(), 4).unwrap();
        assert!(!a.is_equivalent(&to_dword));
        let bare = PointerDataType::new_with(None::<Arc<dyn DataType>>, 4, None).unwrap();
        assert!(!a.is_equivalent(&bare));
        assert!(bare.is_equivalent(&PointerDataType::new_with(None::<Arc<dyn DataType>>, 4, None).unwrap()));
        assert!(!a.is_equivalent(ByteDataType::instance().as_ref()));
    }

    #[test]
    fn deleted_and_replaced_referenced_type() {
        let mut p = PointerDataType::to(ByteDataType::data_type(), 4).unwrap();
        assert!(p.depends_on(ByteDataType::instance().as_ref()));
        p.replace_data_type(ByteDataType::instance().as_ref(), DWordDataType::data_type()).unwrap();
        assert_eq!(p.get_name(), "dword *32");
        assert!(!p.is_deleted());
        p.data_type_deleted(DWordDataType::instance().as_ref());
        assert!(p.is_deleted());
    }

    #[test]
    fn new_pointer_keeps_length_and_clone_rebinds() {
        let p = PointerDataType::to(ByteDataType::data_type(), 2).unwrap();
        let q = p.new_pointer(Box::new(DWordDataType::new(None)));
        assert_eq!(q.get_name(), "dword *16");
        assert_eq!(q.get_length(), 2);
    }

    #[test]
    fn construct_unique_name_matches_java() {
        assert_eq!(construct_unique_name(None, -1), "pointer");
        assert_eq!(construct_unique_name(None, 8), "pointer64");
        assert_eq!(construct_unique_name(Some(ByteDataType::instance().as_ref()), -1), "byte *");
        assert_eq!(construct_unique_name(Some(ByteDataType::instance().as_ref()), 4), "byte *32");
    }

    #[test]
    fn representation_decodes_address_or_nap() {
        let space = ram_space();
        let p = PointerDataType::new_with(None::<Arc<dyn DataType>>, 4, None).unwrap();
        let buf = MockMemBuffer { bytes: vec![0x00, 0x10, 0x00, 0x00], big_endian: false, address: space.address(0) };
        assert_eq!(p.get_representation(&buf, &MockSettings, 4), space.address(0x1000).to_string());
        let short = MockMemBuffer { bytes: vec![0x00], big_endian: false, address: space.address(0) };
        assert_eq!(p.get_representation(&short, &MockSettings, 4), "NaP");
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
