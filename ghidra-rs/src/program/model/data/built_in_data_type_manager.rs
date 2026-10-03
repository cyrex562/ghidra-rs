//! Port of `ghidra.program.model.data.BuiltInDataTypeManager`.
//!
//! Java's manager is a `StandAloneDataTypeManager` (a `DataTypeManagerDB` over a private,
//! in-memory database) that is populated once and then made immutable. Its contents come from
//! `ClassSearcher.getInstances(BuiltInDataType.class, new BuiltInDataTypeClassExclusionFilter())`
//! -- every built-in class found on the class path -- and it is refreshed when the class
//! searcher reports new classes.
//!
//! This port keeps the observable behaviour and drops the machinery that exists only to serve it:
//!
//! * **Discovery.** There is no class path to search. [`registered_built_in_data_types`] is an
//!   explicit, static registry of the real built-in singletons (each type's `data_type()`, Java's
//!   static `dataType` field). A newly ported built-in is added there. The exclusion filter's two
//!   classes (`BadDataType`, `MissingBuiltInDataType`) are simply not listed, and there is no
//!   class-searcher change listener / `refresh()`.
//! * **Storage.** The manager never changes after population (Java: `setImmutable()` plus the
//!   `UnsupportedOperationException` overrides), so the populated types are held directly, in
//!   registry order, rather than in a `DataTypeManagerDB`. The base `DataTypeManagerDB` is not a
//!   concrete type in this crate (only its trait surface is ported), and nothing here needs its
//!   transactions, IDs or change events.
//! * **Singleton.** `getDataTypeManager()` becomes [`BuiltInDataTypeManager::get_data_type_manager`]
//!   over a `OnceLock`; Java's shutdown hook that closes the static instance has no Rust
//!   counterpart (statics are never dropped) and `close()` is a no-op in Java too.
//!
//! Every mutator Java overrides to throw `UnsupportedOperationException` panics here with the
//! Java message; mutators Java inherits from `DataTypeManagerDB` would fail on the immutable
//! database (no transaction can be started), which this port reports the same way.
//!
//! Built-in classes whose Rust port is not yet a real data type (e.g. `AIFFDataType`,
//! `AlignmentDataType`, the complex-float family, `FileTimeDataType`, the image/audio resource
//! types) are absent from the registry until they are ported.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use crate::program::model::data::archive_type::ArchiveType;
use crate::program::model::data::built_in::shared_default_organization;
use crate::program::model::data::category_path::{CategoryPath, DELIMITER_CHAR};
use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_conflict_handler::{
    DataTypeConflictHandler, BUILT_IN_MANAGER_HANDLER,
};
use crate::program::model::data::data_type_manager::{
    built_in_archive_universal_id, DataTypeManager, ReplaceDataTypeError, BUILT_IN_DATA_TYPES_NAME,
};
use crate::program::model::data::source_archive::SourceArchive;
use crate::program::seam_stubs::{share_data_type, DataTypePath};
use crate::util::exception::InvalidNameException;
use crate::util::{Msg, UniversalID};

use crate::program::model::data::{
    boolean_data_type::BooleanDataType, byte_data_type::ByteDataType, char_data_type::CharDataType,
    double_data_type::DoubleDataType, dword_data_type::DWordDataType,
    float10_data_type::Float10DataType, float16_data_type::Float16DataType,
    float2_data_type::Float2DataType, float4_data_type::Float4DataType,
    float8_data_type::Float8DataType, float_data_type::FloatDataType,
    ibo32_data_type::IBO32DataType, ibo64_data_type::IBO64DataType,
    int16_t_data_type::Int16TDataType, int32_t_data_type::Int32TDataType,
    int64_t_data_type::Int64TDataType, int8_t_data_type::Int8TDataType,
    integer16_data_type::Integer16DataType, integer3_data_type::Integer3DataType,
    integer5_data_type::Integer5DataType, integer6_data_type::Integer6DataType,
    integer7_data_type::Integer7DataType, integer_data_type::IntegerDataType,
    long_data_type::LongDataType, long_double_data_type::LongDoubleDataType,
    long_long_data_type::LongLongDataType, pascal_string255_data_type::PascalString255DataType,
    pascal_string_data_type::PascalStringDataType, pascal_unicode_data_type::PascalUnicodeDataType,
    pointer16_data_type::Pointer16DataType, pointer24_data_type::Pointer24DataType,
    pointer32_data_type::Pointer32DataType, pointer40_data_type::Pointer40DataType,
    pointer48_data_type::Pointer48DataType, pointer56_data_type::Pointer56DataType,
    pointer64_data_type::Pointer64DataType, pointer8_data_type::Pointer8DataType,
    pointer_data_type::PointerDataType, pointer_sized_integer_data_type::PointerSizedIntegerDataType,
    qword_data_type::QWordDataType, repeated_string_data_type::RepeatedStringDataType,
    short_data_type::ShortDataType, signed_byte_data_type::SignedByteDataType,
    signed_char_data_type::SignedCharDataType, signed_dword_data_type::SignedDWordDataType,
    signed_leb128_data_type::SignedLeb128DataType, signed_qword_data_type::SignedQWordDataType,
    signed_word_data_type::SignedWordDataType, string_data_type::StringDataType,
    string_utf8_data_type::StringUTF8DataType, terminated_string_data_type::TerminatedStringDataType,
    terminated_unicode32_data_type::TerminatedUnicode32DataType,
    terminated_unicode_data_type::TerminatedUnicodeDataType, uint16_t_data_type::UInt16TDataType,
    uint32_t_data_type::UInt32TDataType, uint64_t_data_type::UInt64TDataType,
    uint8_t_data_type::UInt8TDataType, undefined1_data_type::Undefined1DataType,
    undefined2_data_type::Undefined2DataType, undefined3_data_type::Undefined3DataType,
    undefined4_data_type::Undefined4DataType, undefined5_data_type::Undefined5DataType,
    undefined6_data_type::Undefined6DataType, undefined7_data_type::Undefined7DataType,
    undefined8_data_type::Undefined8DataType, unicode32_data_type::Unicode32DataType,
    unicode_data_type::UnicodeDataType, unsigned_char_data_type::UnsignedCharDataType,
    unsigned_integer16_data_type::UnsignedInteger16DataType,
    unsigned_integer3_data_type::UnsignedInteger3DataType,
    unsigned_integer5_data_type::UnsignedInteger5DataType,
    unsigned_integer6_data_type::UnsignedInteger6DataType,
    unsigned_integer7_data_type::UnsignedInteger7DataType,
    unsigned_integer_data_type::UnsignedIntegerDataType,
    unsigned_leb128_data_type::UnsignedLeb128DataType,
    unsigned_long_data_type::UnsignedLongDataType,
    unsigned_long_long_data_type::UnsignedLongLongDataType,
    unsigned_pointer_sized_integer_data_type::UnsignedPointerSizedIntegerDataType,
    unsigned_short_data_type::UnsignedShortDataType, void_data_type::VoidDataType,
    wide_char16_data_type::WideChar16DataType, wide_char32_data_type::WideChar32DataType,
    wide_char_data_type::WideCharDataType, word_data_type::WordDataType,
};

/// The built-in data types the manager is populated with: the shared (manager-less) instance of
/// every ported built-in class, standing in for Java's `ClassSearcher` discovery of
/// `BuiltInDataType` implementations.
pub fn registered_built_in_data_types() -> Vec<Arc<dyn DataType>> {
    vec![
        // undefined
        Undefined1DataType::data_type(),
        Undefined2DataType::data_type(),
        Undefined3DataType::data_type(),
        Undefined4DataType::data_type(),
        Undefined5DataType::data_type(),
        Undefined6DataType::data_type(),
        Undefined7DataType::data_type(),
        Undefined8DataType::data_type(),
        // fixed-size unsigned / signed words
        ByteDataType::data_type(),
        SignedByteDataType::data_type(),
        WordDataType::data_type(),
        SignedWordDataType::data_type(),
        DWordDataType::data_type(),
        SignedDWordDataType::data_type(),
        QWordDataType::data_type(),
        SignedQWordDataType::data_type(),
        // C integer types
        ShortDataType::data_type(),
        UnsignedShortDataType::data_type(),
        IntegerDataType::data_type(),
        UnsignedIntegerDataType::data_type(),
        LongDataType::data_type(),
        UnsignedLongDataType::data_type(),
        LongLongDataType::data_type(),
        UnsignedLongLongDataType::data_type(),
        Integer3DataType::data_type(),
        UnsignedInteger3DataType::data_type(),
        Integer5DataType::data_type(),
        UnsignedInteger5DataType::data_type(),
        Integer6DataType::data_type(),
        UnsignedInteger6DataType::data_type(),
        Integer7DataType::data_type(),
        UnsignedInteger7DataType::data_type(),
        Integer16DataType::data_type(),
        UnsignedInteger16DataType::data_type(),
        Int8TDataType::data_type(),
        UInt8TDataType::data_type(),
        Int16TDataType::data_type(),
        UInt16TDataType::data_type(),
        Int32TDataType::data_type(),
        UInt32TDataType::data_type(),
        Int64TDataType::data_type(),
        UInt64TDataType::data_type(),
        PointerSizedIntegerDataType::data_type(),
        UnsignedPointerSizedIntegerDataType::data_type(),
        BooleanDataType::data_type(),
        // characters
        CharDataType::data_type(),
        SignedCharDataType::data_type(),
        UnsignedCharDataType::data_type(),
        WideCharDataType::data_type(),
        WideChar16DataType::data_type(),
        WideChar32DataType::data_type(),
        // floats
        FloatDataType::data_type(),
        DoubleDataType::data_type(),
        LongDoubleDataType::data_type(),
        Float2DataType::data_type(),
        Float4DataType::data_type(),
        Float8DataType::data_type(),
        Float10DataType::data_type(),
        Float16DataType::data_type(),
        // strings
        StringDataType::data_type(),
        StringUTF8DataType::data_type(),
        TerminatedStringDataType::data_type(),
        UnicodeDataType::data_type(),
        TerminatedUnicodeDataType::data_type(),
        Unicode32DataType::data_type(),
        TerminatedUnicode32DataType::data_type(),
        PascalStringDataType::data_type(),
        PascalString255DataType::data_type(),
        PascalUnicodeDataType::data_type(),
        RepeatedStringDataType::data_type(),
        // LEB128
        SignedLeb128DataType::data_type(),
        UnsignedLeb128DataType::data_type(),
        // pointers
        PointerDataType::data_type(),
        Pointer8DataType::data_type(),
        Pointer16DataType::data_type(),
        Pointer24DataType::data_type(),
        Pointer32DataType::data_type(),
        Pointer40DataType::data_type(),
        Pointer48DataType::data_type(),
        Pointer56DataType::data_type(),
        Pointer64DataType::data_type(),
        Arc::new(IBO32DataType::new()),
        Arc::new(IBO64DataType::new()),
        // void
        VoidDataType::data_type(),
    ]
}

/// Data type manager for built in types that do not live anywhere except in memory.
///
/// Port of `ghidra.program.model.data.BuiltInDataTypeManager`; see the module docs for what the
/// port keeps and drops.
pub struct BuiltInDataTypeManager {
    /// Populated data types, in population order (all in the root category).
    data_types: Vec<Arc<dyn DataType>>,
    /// Name -> index into `data_types`.
    by_name: HashMap<String, usize>,
}

impl BuiltInDataTypeManager {
    /// Returns the shared instance of the built-in data type manager
    /// (`BuiltInDataTypeManager.getDataTypeManager()`).
    pub fn get_data_type_manager() -> &'static BuiltInDataTypeManager {
        static MANAGER: OnceLock<BuiltInDataTypeManager> = OnceLock::new();
        MANAGER.get_or_init(|| BuiltInDataTypeManager::populate(registered_built_in_data_types()))
    }

    /// Builds a manager over `candidates` (Java's private constructor + `populateBuiltInTypes()`).
    ///
    /// A candidate whose name is already taken is not added: a non-equivalent one is reported
    /// as a name collision (Java's "Invalid BuiltIn Data Type" error); an equivalent one is the
    /// same built-in found twice.
    fn populate(candidates: Vec<Arc<dyn DataType>>) -> Self {
        let mut manager = BuiltInDataTypeManager { data_types: Vec::new(), by_name: HashMap::new() };
        for data_type in candidates {
            let name = data_type.get_name();
            match manager.by_name.get(&name) {
                None => {
                    manager.by_name.insert(name, manager.data_types.len());
                    manager.data_types.push(data_type);
                }
                Some(&existing) => {
                    let existing = &manager.data_types[existing];
                    if !existing.is_equivalent(data_type.as_ref()) {
                        Msg::show_error(
                            "BuiltInDataTypeManager",
                            "Invalid BuiltIn Data Type",
                            &format!(
                                "BuiltIn datatype name collision between {} and {}, both named '{}'",
                                data_type.get_display_name(),
                                existing.get_display_name(),
                                name
                            ),
                        );
                    }
                }
            }
        }
        manager
    }

    /// The built-in named `name` (all built-ins live in the root category), as the shared handle.
    pub fn get_built_in(&self, name: &str) -> Option<Arc<dyn DataType>> {
        self.by_name.get(name).map(|&i| self.data_types[i].clone())
    }

    /// Every built-in, in population order, as shared handles.
    pub fn built_ins(&self) -> &[Arc<dyn DataType>] {
        &self.data_types
    }

    /// `resolveSourceArchiveID(DataType)`: built-ins belong to the built-in archive; nothing
    /// else can be resolved by this manager.
    ///
    /// # Panics
    /// For a data type that is not a built-in (Java's `IllegalArgumentException`).
    pub fn resolve_source_archive_id(&self, data_type: &dyn DataType) -> UniversalID {
        if data_type.as_built_in_data_type().is_some() {
            return built_in_archive_universal_id();
        }
        panic!(
            "Only Built-in data types can be resolved by the BuiltInDataTypeManager manager."
        );
    }

    /// The member equal to `data_type` by identity, if `data_type` is one of this manager's own.
    fn member(&self, data_type: &dyn DataType) -> Option<&Arc<dyn DataType>> {
        let key = data_type.identity_key();
        self.data_types.iter().find(|dt| dt.identity_key() == key)
    }
}

impl DataTypeManager for BuiltInDataTypeManager {
    fn get_name(&self) -> String {
        BUILT_IN_DATA_TYPES_NAME.to_string()
    }

    /// Java: `UnsupportedOperationException`.
    fn set_name(&mut self, _name: &str) -> Result<(), InvalidNameException> {
        panic!("UnsupportedOperationException: BuiltInDataTypeManager.setName");
    }

    fn get_type(&self) -> ArchiveType {
        ArchiveType::BuiltIn
    }

    fn is_updatable(&self) -> bool {
        false
    }

    fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
        shared_default_organization()
    }

    fn contains_category(&self, path: &CategoryPath) -> bool {
        path.is_root()
    }

    fn get_category_count(&self) -> i32 {
        1
    }

    fn get_data_type_in_category(&self, path: &CategoryPath, name: &str) -> Option<Box<dyn DataType>> {
        if !path.is_root() {
            return None;
        }
        self.get_built_in(name).map(|dt| share_data_type(&dt))
    }

    fn get_data_type(&self, data_type_path: &str) -> Option<Box<dyn DataType>> {
        let (category, name) = data_type_path.rsplit_once(DELIMITER_CHAR)?;
        if !category.is_empty() {
            return None;
        }
        self.get_built_in(name).map(|dt| share_data_type(&dt))
    }

    fn get_data_type_at_path(&self, data_type_path: &DataTypePath) -> Option<Box<dyn DataType>> {
        self.get_data_type_in_category(&data_type_path.get_category_path(), &data_type_path.get_data_type_name())
    }

    fn find_data_types(&self, name: &str, list: &mut Vec<Box<dyn DataType>>) {
        if let Some(dt) = self.get_built_in(name) {
            list.push(share_data_type(&dt));
        }
    }

    fn get_all_data_types(&self) -> Vec<Box<dyn DataType>> {
        self.data_types.iter().map(share_data_type).collect()
    }

    fn get_data_type_count(&self, include_pointers_and_arrays: bool) -> i32 {
        self.data_types
            .iter()
            .filter(|dt| include_pointers_and_arrays || !(dt.is_pointer() || dt.is_array()))
            .count() as i32
    }

    fn contains(&self, data_type: &dyn DataType) -> bool {
        self.member(data_type).is_some()
    }

    /// `resolve(DataType, DataTypeConflictHandler)`: always resolves with
    /// `BUILT_IN_MANAGER_HANDLER`, whatever `handler` is passed.
    ///
    /// A member, or a data type equivalent to the built-in of the same name, resolves to that
    /// built-in.
    ///
    /// # Panics
    /// A non-equivalent data type with a built-in's name ("Built-in data-types may not be
    /// substantially changed while Ghidra is running"); a data type with a new name, which would
    /// have to be added to the immutable manager.
    fn resolve(&mut self, data_type: Box<dyn DataType>, _handler: &dyn DataTypeConflictHandler) -> Box<dyn DataType> {
        if let Some(member) = self.member(data_type.as_ref()) {
            return share_data_type(member);
        }
        if data_type.is_default_data_type() {
            return data_type;
        }
        if let Some(existing) = self.get_built_in(&data_type.get_name()) {
            if existing.is_equivalent(data_type.as_ref()) {
                return share_data_type(&existing);
            }
            BUILT_IN_MANAGER_HANDLER.resolve_conflict(data_type.as_ref(), existing.as_ref());
        }
        self.resolve_source_archive_id(data_type.as_ref());
        panic!("Built-in datatype manager may not be modified");
    }

    /// Java: `UnsupportedOperationException`.
    fn add_data_type(&mut self, _data_type: Box<dyn DataType>, _handler: &dyn DataTypeConflictHandler) -> Box<dyn DataType> {
        panic!("UnsupportedOperationException: BuiltInDataTypeManager.addDataType");
    }

    /// Java: `UnsupportedOperationException`.
    fn associate_data_type_with_archive(&mut self, _datatype: &dyn DataType, _archive: &dyn SourceArchive) {
        panic!("UnsupportedOperationException: BuiltInDataTypeManager.associateDataTypeWithArchive");
    }

    /// Java: `UnsupportedOperationException`.
    fn remove(&mut self, _data_type: &dyn DataType) -> bool {
        panic!("UnsupportedOperationException: BuiltInDataTypeManager.remove");
    }

    /// Java: `UnsupportedOperationException`.
    fn replace_data_type(
        &mut self,
        _existing_dt: &dyn DataType,
        _replacement_dt: Box<dyn DataType>,
        _update_category_path: bool,
    ) -> Result<Box<dyn DataType>, ReplaceDataTypeError> {
        panic!("UnsupportedOperationException: BuiltInDataTypeManager.replaceDataType");
    }

    /// Java: `UnsupportedOperationException("Built-in datatype manager may not be modified")`.
    fn start_transaction(&mut self, _description: &str) -> i32 {
        panic!("Built-in datatype manager may not be modified");
    }

    /// Java: `UnsupportedOperationException`.
    fn end_transaction(&mut self, _transaction_id: i32, _commit: bool) -> bool {
        panic!("UnsupportedOperationException: BuiltInDataTypeManager.endTransaction");
    }

    /// Cannot close a built-in data type manager.
    fn close(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::category_path::ROOT;
    use crate::program::model::data::data_type_conflict_handler::DEFAULT_HANDLER;
    use crate::program::model::data::structure_data_type::StructureDataType;
    use std::collections::HashSet;

    fn mgr() -> &'static BuiltInDataTypeManager {
        BuiltInDataTypeManager::get_data_type_manager()
    }

    #[test]
    fn singleton_identity_name_and_type() {
        assert!(std::ptr::eq(mgr(), BuiltInDataTypeManager::get_data_type_manager()));
        assert_eq!(mgr().get_name(), "BuiltInTypes");
        assert_eq!(mgr().get_type(), ArchiveType::BuiltIn);
        assert!(!mgr().is_updatable());
        assert!(mgr().contains_category(&ROOT));
    }

    #[test]
    fn registry_names_are_unique_so_every_built_in_is_populated() {
        // Java: "Should be no duplicate named built-in types"
        let registry = registered_built_in_data_types();
        let names: HashSet<String> = registry.iter().map(|dt| dt.get_name()).collect();
        assert_eq!(names.len(), registry.len());
        assert_eq!(mgr().built_ins().len(), registry.len());
    }

    #[test]
    fn finds_built_ins_by_root_category_name_and_path() {
        // names are the Java built-ins' getName() values
        for (name, len) in [("byte", 1), ("word", 2), ("dword", 4), ("qword", 8), ("int", 4),
            ("uint", 4), ("char", 1), ("float", 4), ("double", 8), ("undefined4", 4),
            ("bool", 1), ("wchar16", 2), ("int8_t", 1), ("uint64_t", 8)]
        {
            let dt = mgr().get_data_type_in_category(&ROOT, name).unwrap_or_else(|| panic!("{name}"));
            assert_eq!(dt.get_name(), name);
            assert_eq!(dt.get_length(), len, "{name}");
            assert_eq!(mgr().get_data_type(&format!("/{name}")).unwrap().get_name(), name);
        }
        for name in ["string", "TerminatedCString", "unicode", "pointer", "void", "sleb128", "uleb128"] {
            assert!(mgr().get_data_type(&format!("/{name}")).is_some(), "{name}");
        }
        assert!(mgr().get_data_type("/nosuch").is_none());
        assert!(mgr().get_data_type("/sub/byte").is_none());
        let sub = CategoryPath::parse("/sub").unwrap();
        assert!(mgr().get_data_type_in_category(&sub, "byte").is_none());

        let mut list = Vec::new();
        mgr().find_data_types("dword", &mut list);
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn members_are_the_shared_singletons() {
        let byte = ByteDataType::data_type();
        assert!(mgr().contains(byte.as_ref()));
        let handle = mgr().get_data_type_in_category(&ROOT, "byte").unwrap();
        assert!(mgr().contains(handle.as_ref()));
        assert_eq!(handle.identity_key(), byte.identity_key());
        // a fresh instance of the same class is equivalent but not a member
        let fresh = ByteDataType::new(None);
        assert!(!mgr().contains(&fresh));
    }

    #[test]
    fn resolve_returns_the_built_in_for_members_and_equivalents() {
        let mut m = BuiltInDataTypeManager::populate(registered_built_in_data_types());
        let resolved = m.resolve(Box::new(ByteDataType::new(None)), &DEFAULT_HANDLER);
        assert_eq!(resolved.identity_key(), ByteDataType::data_type().identity_key());
        let resolved = m.resolve(share_data_type(&DWordDataType::data_type()), &DEFAULT_HANDLER);
        assert_eq!(resolved.identity_key(), DWordDataType::data_type().identity_key());
    }

    #[test]
    #[should_panic(expected = "Built-in data-types may not be substantially changed")]
    fn resolving_a_conflicting_type_with_a_built_in_name_fails() {
        let mut m = BuiltInDataTypeManager::populate(registered_built_in_data_types());
        m.resolve(Box::new(StructureDataType::new("byte", 4)), &DEFAULT_HANDLER);
    }

    #[test]
    #[should_panic(expected = "Only Built-in data types can be resolved")]
    fn resolving_a_non_built_in_fails() {
        let mut m = BuiltInDataTypeManager::populate(registered_built_in_data_types());
        m.resolve(Box::new(StructureDataType::new("my_struct", 4)), &DEFAULT_HANDLER);
    }

    #[test]
    #[should_panic(expected = "Built-in datatype manager may not be modified")]
    fn transactions_are_refused() {
        let mut m = BuiltInDataTypeManager::populate(Vec::new());
        m.start_transaction("x");
    }

    #[test]
    fn name_collision_keeps_the_first_built_in() {
        let m = BuiltInDataTypeManager::populate(vec![
            ByteDataType::data_type(),
            ByteDataType::data_type(),
            Arc::new(StructureDataType::new("byte", 1)),
        ]);
        assert_eq!(m.built_ins().len(), 1);
        assert_eq!(m.get_built_in("byte").unwrap().identity_key(), ByteDataType::data_type().identity_key());
    }

    #[test]
    fn data_type_count_excludes_pointers_on_request() {
        let all = mgr().get_data_type_count(true);
        let no_ptrs = mgr().get_data_type_count(false);
        assert_eq!(all as usize, mgr().built_ins().len());
        assert!(no_ptrs < all, "pointer built-ins are excluded");
        assert_eq!(mgr().get_all_data_types().len(), all as usize);
    }

    #[test]
    fn resolve_source_archive_id_is_the_built_in_archive() {
        assert_eq!(
            mgr().resolve_source_archive_id(ByteDataType::data_type().as_ref()),
            built_in_archive_universal_id()
        );
    }
}
