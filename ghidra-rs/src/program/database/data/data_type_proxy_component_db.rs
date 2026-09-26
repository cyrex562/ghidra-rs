//! Port of `ghidra.program.database.data.DataTypeProxyComponentDB`, a small variant of
//! [`DataTypeComponentDb`](super::data_type_component_db::DataTypeComponentDB) that facilitates a
//! datatype/component substitution when a `DataTypeManagerDB` is constructed for read-only use
//! and datatype migration is required (e.g. `StructureDB`'s migration of flex-arrays to a
//! zero-element array).
//!
//! Java's `DataTypeProxyComponentDB extends DataTypeComponentDB`, overriding only `getFieldName`
//! and `getComment` to return fixed values supplied at construction (rather than reading them
//! from a backing record -- this proxy component has none; it is built through the
//! record-less/"explicit datatype+length" base constructor). Per this session's established
//! convention for "extends X" (see `data_component.rs`'s `DataDb`-composition pattern and
//! `typedef_db.rs`), this is ported as composition -- a `base: DataTypeComponentDB` field --
//! rather than inheritance.
//!
//! # Why `is_equivalent`/`get_default_field_name`/`is_default_field_name` need their own bodies
//!
//! [`DataTypeComponentDB`](super::data_type_component_db::DataTypeComponentDB)'s own
//! `is_equivalent_with_handler` and [`DataTypeComponent`]'s default
//! `get_default_field_name`/`is_default_field_name` all internally call `self.get_field_name()`/
//! `self.get_comment()` -- but through Rust's composition (not inheritance), a call made
//! `self.base.is_equivalent_with_handler(...)` would resolve `self.get_field_name()` against
//! `base`'s own (record-less, so always `None`) implementation, not this proxy's overridden
//! `field_name`/`comment`. Java's virtual dispatch means the *same* call in the original resolves
//! to the subclass override instead. To stay faithful to that, [`DataTypeComponent::is_equivalent`]
//! is given its own body here (reproducing `DataTypeComponentDB.isEquivalent(DataTypeComponent,
//! DataTypeConflictHandler)`'s logic verbatim, substituting this proxy's own field name/comment),
//! rather than delegating to `self.base`'s inherent method.
//! [`DataTypeComponent::get_default_field_name`]/[`DataTypeComponent::is_default_field_name`] use
//! the trait's own default bodies (via `DataTypeComponent::get_ordinal`/`get_offset`/`get_parent`
//! delegating to `base`, and `is_zero_bit_field_component` delegating to `base`), which is
//! correct: those defaults never read `get_field_name`/`get_comment`, so no override is needed
//! for them specifically.
//!
//! # `set_comment`/`set_field_name` are effectively no-ops, matching Java
//!
//! Java's `DataTypeProxyComponentDB` does not override `setComment`/`setFieldName`; it inherits
//! `DataTypeComponentDB`'s versions, which check `record != null` before persisting -- and this
//! proxy's `record` is always `None` (constructed via the record-less base constructor) -- then
//! `return this`, handing back the *same* Java object, `fieldName`/`comment` fields untouched.
//! The Rust base's `set_comment`/`set_field_name` instead return `Box::new(self.clone())` of
//! *just* `DataTypeComponentDB` -- which would silently drop this proxy's `field_name`/`comment`
//! overrides if delegated to naively. This port instead overrides both to return
//! `Box::new(self.clone())` of the *whole proxy* (ignoring the supplied value, exactly as the
//! record-less base would), preserving the override fields and matching Java's "return this,
//! unchanged" behavior exactly.

use std::sync::{Arc, Mutex};

use crate::program::database::data::data_type_component_db::DataTypeComponentDB;
use crate::program::database::data::data_type_manager_db::DataTypeManagerDb;
use crate::program::database::data::data_type_utilities::DataTypeUtilities as ModelDataTypeUtilities;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::data_type_conflict_handler::DataTypeConflictHandler;
use crate::docking::settings::settings::Settings;

/// A dummy zero-sized receiver used purely to invoke the model-layer [`ModelDataTypeUtilities`]'s
/// default methods, per the convention already established throughout `program/database/data`
/// (see e.g. `data_type_component_db.rs`, `category_db.rs`).
#[derive(Debug, Default, Clone, Copy)]
struct Utils;
impl ModelDataTypeUtilities for Utils {}

/// A datatype/component substitution used when a `DataTypeManagerDB` is constructed for
/// read-only use and datatype migration is required.
///
/// Port of `ghidra.program.database.data.DataTypeProxyComponentDB`. See the module documentation
/// for what was ported, and for why `is_equivalent`/`set_comment`/`set_field_name` need their own
/// bodies rather than a naive delegation to `base`.
///
/// Cheaply [`Clone`]: `base` is itself cheaply `Clone` (see its own module docs), and
/// `field_name`/`comment` are plain owned `String`s.
#[derive(Clone)]
pub struct DataTypeProxyComponentDb {
    base: DataTypeComponentDB,
    field_name: Option<String>,
    comment: Option<String>,
}

impl DataTypeProxyComponentDb {
    /// Construct a proxy component with specific component characteristics and without a record.
    ///
    /// Port of `DataTypeProxyComponentDB(DataTypeManagerDB, CompositeDB, int, int, DataType, int,
    /// String, String)`. As with [`DataTypeComponentDB`](super::data_type_component_db::DataTypeComponentDB)'s
    /// own record-less constructors, there is no live back-reference to the owning composite --
    /// see that module's docs for why this is sound.
    pub fn new(
        data_mgr: Arc<Mutex<dyn DataTypeManagerDb + Send>>,
        ordinal: i32,
        offset: i32,
        data_type: Box<dyn DataType>,
        length: i32,
        field_name: Option<String>,
        comment: Option<String>,
    ) -> Self {
        DataTypeProxyComponentDb {
            base: DataTypeComponentDB::new_immutable(data_mgr, ordinal, offset, data_type, length),
            field_name,
            comment,
        }
    }
}

impl DataTypeComponent for DataTypeProxyComponentDb {
    fn get_data_type(&self) -> Box<dyn DataType> {
        DataTypeComponent::get_data_type(&self.base)
    }

    fn get_parent(&self) -> Box<dyn DataType> {
        DataTypeComponent::get_parent(&self.base)
    }

    fn is_bit_field_component(&self) -> bool {
        DataTypeComponent::is_bit_field_component(&self.base)
    }

    fn is_zero_bit_field_component(&self) -> bool {
        DataTypeComponent::is_zero_bit_field_component(&self.base)
    }

    fn get_ordinal(&self) -> i32 {
        DataTypeComponent::get_ordinal(&self.base)
    }

    fn get_offset(&self) -> i32 {
        DataTypeComponent::get_offset(&self.base)
    }

    fn get_end_offset(&self) -> i32 {
        DataTypeComponent::get_end_offset(&self.base)
    }

    fn get_length(&self) -> i32 {
        DataTypeComponent::get_length(&self.base)
    }

    fn get_data_type_name(&self) -> String {
        DataTypeComponent::get_data_type_name(&self.base)
    }

    fn bit_field_bit_offset(&self) -> i32 {
        DataTypeComponent::bit_field_bit_offset(&self.base)
    }

    /// Port of the overridden `DataTypeProxyComponentDB.getComment()`.
    fn get_comment(&self) -> Option<String> {
        self.comment.clone()
    }

    fn get_default_settings(&self) -> Box<dyn Settings> {
        DataTypeComponent::get_default_settings(&self.base)
    }

    /// Port of the inherited (not overridden) `DataTypeComponentDB.setComment(String)`. See the
    /// module docs for why this proxy needs its own body rather than delegating to `base`.
    fn set_comment(&self, _comment: Option<String>) -> Box<dyn DataTypeComponent> {
        Box::new(self.clone())
    }

    /// Port of the overridden `DataTypeProxyComponentDB.getFieldName()`.
    fn get_field_name(&self) -> Option<String> {
        self.field_name.clone()
    }

    /// Port of the inherited (not overridden) `DataTypeComponentDB.setFieldName(String)`. See the
    /// module docs for why this proxy needs its own body rather than delegating to `base`.
    fn set_field_name(&self, _field_name: Option<String>) -> Box<dyn DataTypeComponent> {
        Box::new(self.clone())
    }

    /// Port of `DataTypeComponentDB.isEquivalent(DataTypeComponent, DataTypeConflictHandler)`,
    /// reproduced here (rather than delegated to `base`) so that `getFieldName()`/`getComment()`
    /// resolve to this proxy's overrides. See the module docs.
    fn is_equivalent(&self, dtc: &dyn DataTypeComponent) -> bool {
        let my_dt = DataTypeComponent::get_data_type(self);
        let other_dt = dtc.get_data_type();

        let my_parent = DataTypeComponent::get_parent(self);
        let is_packed = my_parent.as_composite().map(Composite::is_packing_enabled).unwrap_or(false);

        if (!is_packed && DataTypeComponent::get_offset(self) != dtc.get_offset())
            || DataTypeComponent::get_field_name(self) != dtc.get_field_name()
            || DataTypeComponent::get_comment(self) != dtc.get_comment()
        {
            return false;
        }

        // Component lengths need only be checked for dynamic types.
        if DataTypeComponent::get_length(self) != dtc.get_length() && my_dt.as_dynamic().is_some() {
            return false;
        }

        if Utils.is_same_data_type(my_dt.as_ref(), other_dt.as_ref()) {
            return true;
        }

        // Approximates the static `DataTypeDB.isEquivalent(DataType, DataType, handler)` dispatch
        // (which special-cases a `DataTypeDB` target's own handler-aware `isEquivalent`): a plain
        // `&dyn DataType` can't be downcast to check for that here, so this falls back to an
        // ordinary equivalence check. Mirrors `data_type_component_db.rs`'s identical precedent.
        let _handler: Option<&dyn DataTypeConflictHandler> = None;
        my_dt.is_equivalent(other_dt.as_ref())
    }

    fn is_undefined(&self) -> bool {
        DataTypeComponent::is_undefined(&self.base)
    }
}

impl std::fmt::Display for DataTypeProxyComponentDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", crate::program::model::data::internal_data_type_component::to_string(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use std::io;

    #[derive(Clone)]
    struct MockLeaf {
        name: String,
        length: i32,
    }
    impl DataType for MockLeaf {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.name == dt.get_name() && self.length == dt.get_length()
        }
    }

    struct TestManager;
    impl DataTypeManager for TestManager {}
    impl DataTypeManagerDb for TestManager {
        fn db_error(&mut self, _error: io::Error) {}
        fn add_data_type_to_replace(&mut self, _data_type_id: i64, _replacement: Box<dyn DataType>) {}
        fn add_data_type_to_delete(&mut self, _data_type_id: i64) {}
    }

    fn make_manager() -> Arc<Mutex<dyn DataTypeManagerDb + Send>> {
        Arc::new(Mutex::new(TestManager))
    }

    fn make_proxy(
        ordinal: i32,
        offset: i32,
        length: i32,
        dt_name: &str,
        dt_length: i32,
        field_name: Option<&str>,
        comment: Option<&str>,
    ) -> DataTypeProxyComponentDb {
        let dt: Box<dyn DataType> = Box::new(MockLeaf { name: dt_name.to_string(), length: dt_length });
        DataTypeProxyComponentDb::new(
            make_manager(),
            ordinal,
            offset,
            dt,
            length,
            field_name.map(str::to_string),
            comment.map(str::to_string),
        )
    }

    #[test]
    fn getters_reflect_constructor_arguments() {
        let c = make_proxy(2, 8, 4, "dword", 4, Some("myField"), Some("a comment"));

        assert_eq!(DataTypeComponent::get_ordinal(&c), 2);
        assert_eq!(DataTypeComponent::get_offset(&c), 8);
        assert_eq!(DataTypeComponent::get_length(&c), 4);
        assert_eq!(DataTypeComponent::get_end_offset(&c), 11);
        assert_eq!(DataTypeComponent::get_field_name(&c), Some("myField".to_string()));
        assert_eq!(DataTypeComponent::get_comment(&c), Some("a comment".to_string()));
        assert_eq!(DataTypeComponent::get_data_type(&c).get_name(), "dword");
        assert!(!DataTypeComponent::is_undefined(&c));
    }

    #[test]
    fn field_name_and_comment_may_be_none() {
        let c = make_proxy(0, 0, 1, "byte", 1, None, None);
        assert_eq!(DataTypeComponent::get_field_name(&c), None);
        assert_eq!(DataTypeComponent::get_comment(&c), None);
    }

    #[test]
    fn set_comment_and_set_field_name_are_no_ops_preserving_overrides() {
        // Mirrors Java: DataTypeProxyComponentDB doesn't override setComment/setFieldName, and
        // the inherited DataTypeComponentDB versions are no-ops for a record-less component,
        // returning `this` (here: an unchanged clone) rather than a mutated copy.
        let c = make_proxy(0, 0, 1, "byte", 1, Some("original"), Some("orig comment"));

        let after_comment = DataTypeComponent::set_comment(&c, Some("new comment".to_string()));
        assert_eq!(after_comment.get_comment(), Some("orig comment".to_string()));
        assert_eq!(after_comment.get_field_name(), Some("original".to_string()));

        let after_field = DataTypeComponent::set_field_name(&c, Some("new_field".to_string()));
        assert_eq!(after_field.get_field_name(), Some("original".to_string()));
        assert_eq!(after_field.get_comment(), Some("orig comment".to_string()));

        // The original is untouched either way.
        assert_eq!(DataTypeComponent::get_field_name(&c), Some("original".to_string()));
        assert_eq!(DataTypeComponent::get_comment(&c), Some("orig comment".to_string()));
    }

    #[test]
    fn is_equivalent_uses_proxys_own_field_name_and_comment() {
        let a = make_proxy(0, 0, 1, "byte", 1, Some("f"), Some("c"));
        let b = make_proxy(0, 0, 1, "byte", 1, Some("f"), Some("c"));
        assert!(DataTypeComponent::is_equivalent(&a, &b));

        let different_name = make_proxy(0, 0, 1, "byte", 1, Some("g"), Some("c"));
        assert!(!DataTypeComponent::is_equivalent(&a, &different_name));

        let different_comment = make_proxy(0, 0, 1, "byte", 1, Some("f"), Some("other"));
        assert!(!DataTypeComponent::is_equivalent(&a, &different_comment));
    }

    #[test]
    fn is_equivalent_compares_offset_and_data_type() {
        let a = make_proxy(0, 4, 1, "byte", 1, None, None);
        let same_offset = make_proxy(1, 4, 1, "byte", 1, None, None);
        assert!(DataTypeComponent::is_equivalent(&a, &same_offset));

        let different_offset = make_proxy(0, 8, 1, "byte", 1, None, None);
        assert!(!DataTypeComponent::is_equivalent(&a, &different_offset));

        let different_type = make_proxy(0, 4, 1, "word", 2, None, None);
        assert!(!DataTypeComponent::is_equivalent(&a, &different_type));
    }

    #[test]
    fn clone_preserves_field_name_and_comment() {
        let c = make_proxy(3, 12, 4, "dword", 4, Some("f"), Some("c"));
        let cloned = c.clone();
        assert_eq!(DataTypeComponent::get_field_name(&cloned), Some("f".to_string()));
        assert_eq!(DataTypeComponent::get_comment(&cloned), Some("c".to_string()));
    }

    #[test]
    fn display_matches_internal_to_string() {
        let c = make_proxy(0, 0, 1, "byte", 1, Some("f"), None);
        let text = format!("{c}");
        assert!(text.contains("byte"));
    }
}
