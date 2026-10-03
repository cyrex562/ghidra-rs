//! Port of `ghidra.program.database.data.EnumValues`.
//!
//! The Java type is a package-private, lazily-built cache class: `EnumDB` builds one from its
//! `EnumValueDBAdapter` on first need (`getEnumValues()`), holds onto it in a `lazyEnumValues`
//! field, and delegates almost every `Enum` accessor (`getValue`, `getName`, `getNames`,
//! `getComment`, `getValues`, `contains(String)`, `contains(long)`, `isSigned`,
//! `getSignedState`, `getMinimumPossibleLength`) straight through to it. A structural change
//! (`remove`) nulls the field out so the next accessor call reloads a fresh snapshot from the
//! adapter; `add` is the one exception -- it updates the live cache in place
//! (`enumValues.addValue(...)`) right after persisting the new value record, rather than
//! invalidating.
//!
//! # Why this is a genuine gap, not a redundant re-port
//!
//! [`EnumDb`](super::enum_db::EnumDb) -- the existing port of `EnumDB` -- is a cycle-cut *trait*
//! whose own module docs say plainly that it does not re-model `EnumDB`'s accessors that "just
//! forward straight through to `EnumValues`/the inherited `DataTypeDB` plumbing", because "they
//! need real per-instance record/adapter/cache storage this trait does not yet prescribe". That
//! storage is exactly what this module provides: a real, DB-backed name/value/comment cache with
//! the same lazy-load-then-incrementally-update behavior as the Java class, built on top of the
//! already-ported [`EnumValueDBAdapter`](super::enum_value_db_adapter::EnumValueDBAdapter) trait
//! (the same adapter `EnumValues(EnumDB, EnumValueDBAdapter)`'s constructor reads through). No
//! prior Rust port of this crate implements the name<->value<->comment lookup tables or the
//! signed-state inference (`computeSignedness`) `EnumValues.java` provides -- `EnumDb`'s trait
//! defaults only cover the handful of `EnumDB` methods that operate purely on the [`Enum`]/
//! [`DataType`] surface ([`EnumDb::check_value`], [`EnumDb::get_bit_groups`],
//! [`EnumDb::get_compound_value`], [`EnumDb::enum_db_representation`],
//! [`EnumDb::is_each_value_equivalent`], [`EnumDb::enum_db_is_equivalent`]), all of which assume
//! a `get_value_for_name`/`get_name_for_value`/etc. implementation already exists -- this module
//! is what a concrete implementation of those methods would actually be backed by.
//!
//! # Decoupled from `EnumDb`/`Enum` on purpose
//!
//! Java's constructor takes the owning `EnumDB` itself (only to read `enumm.getKey()` in the
//! loop and `enumm.getLength()` for `computeSignedness`) plus the `EnumValueDBAdapter`. Requiring
//! a whole `&dyn EnumDb`/`&dyn Enum` here would create a dependency this cache does not actually
//! need and cannot satisfy without a concrete implementor to hand it (no concrete `EnumDb`
//! exists yet in this crate -- that needs `DataTypeManagerDb`-backed enum plumbing, which is a
//! separate, much larger port). [`EnumValues::new`] instead takes just the two plain values Java
//! actually reads off `enumm`: `enum_key: i64` and `enum_length: i32`.
//!
//! # Method names mirror the [`Enum`] trait vocabulary
//!
//! So that a future concrete `EnumDb` implementor can compose an `EnumValues` cache field and
//! delegate its [`Enum`] methods to it directly (the same "cache field + thin delegating impl"
//! shape [`TypedefDb`](super::typedef_db::TypedefDb) uses for
//! [`DataTypeDb`](super::data_type_db::DataTypeDb)), the accessors here are named to match
//! [`Enum`]'s trait methods rather than `EnumValues.java`'s own names: `get_value_for_name`
//! (Java `getValue`), `get_name_for_value` (Java `getName`), `get_names_for_value` (Java
//! `getNames(long)`), `get_names` (Java `getNames()`), `get_count` (Java `size`), `add`/
//! `add_with_comment` (Java `addValue`). No such concrete implementor exists in this crate yet
//! (see above), so nothing calls this module's methods outside its own tests today; it is kept
//! public for whichever future `EnumDb`-implementing port needs it, the same way
//! [`TypedefDb::update_path`](super::typedef_db::TypedefDb::update_path)'s module docs note it is
//! kept public ahead of its own future caller.
//!
//! # `NoSuchElementException` -> `Option`
//!
//! Java's `getValue(String)` throws `NoSuchElementException` when the name is undefined; per this
//! crate's established convention (already used by [`Enum::get_value_for_name`] itself),
//! [`EnumValues::get_value_for_name`] returns `None` instead.

use std::collections::{BTreeMap, HashMap};
use std::io;

use crate::program::database::data::enum_db::{max_possible_value, min_possible_value};
use crate::program::database::data::enum_signed_state::EnumSignedState;
use crate::program::database::data::enum_value_db_adapter::{
    EnumValueDBAdapter, ENUMVAL_COMMENT_COL, ENUMVAL_ID_COL, ENUMVAL_NAME_COL, ENUMVAL_VALUE_COL,
};
use crate::program::model::data::enum_::Enum;

/// Immutable-from-the-outside cache of the name/value/comment/signed-state data for an enum data
/// type, loaded from an [`EnumValueDBAdapter`]-backed table.
///
/// Port of the package-private `ghidra.program.database.data.EnumValues`. See the module
/// documentation for the investigation that motivated this port and the naming/decoupling
/// choices made.
#[derive(Debug, Clone)]
pub struct EnumValues {
    name_map: HashMap<String, i64>,
    value_map: BTreeMap<i64, Vec<String>>,
    comment_map: HashMap<String, String>,
    signed_state: EnumSignedState,
    enum_length: i32,
}

impl EnumValues {
    /// Loads every value record belonging to `enum_key` from `adapter` and computes the initial
    /// signed state. `enum_length` stands in for `enumm.getLength()` -- see the module docs for
    /// why the owning enum itself is not threaded through as a trait object.
    ///
    /// Port of `EnumValues(EnumDB, EnumValueDBAdapter)`.
    pub fn new(
        enum_key: i64,
        enum_length: i32,
        adapter: &dyn EnumValueDBAdapter,
    ) -> io::Result<Self> {
        let mut values = EnumValues {
            name_map: HashMap::new(),
            value_map: BTreeMap::new(),
            comment_map: HashMap::new(),
            signed_state: EnumSignedState::None,
            enum_length,
        };
        for id in adapter.get_value_ids_in_enum(enum_key)? {
            if let Some(rec) = adapter.get_record(id.get_long_value())? {
                let value_name = rec.get_string(ENUMVAL_NAME_COL).unwrap_or_default().to_string();
                let value = rec.get_long(ENUMVAL_VALUE_COL).unwrap_or(0);
                let comment = rec.get_string(ENUMVAL_COMMENT_COL).unwrap_or_default().to_string();
                values.do_add_value(value_name, value, &comment);
            }
        }
        values.signed_state = values.compute_signedness();
        Ok(values)
    }

    /// Returns the value for a given name, or `None` if there is no value defined for it. Java
    /// throws `NoSuchElementException` here -- see the module docs.
    ///
    /// Port of `EnumValues.getValue(String)`.
    pub fn get_value_for_name(&self, value_name: &str) -> Option<i64> {
        self.name_map.get(value_name).copied()
    }

    /// Returns the name for a given value. If there is more than one name for a value, the first
    /// in alphabetical order is returned (the per-value name list is kept sorted on every
    /// insert). Returns `None` if there is no name for that value.
    ///
    /// Port of `EnumValues.getName(long)`.
    pub fn get_name_for_value(&self, value: i64) -> Option<String> {
        self.value_map.get(&value).and_then(|names| names.first().cloned())
    }

    /// Returns all the names for a given value, or `None` if there are none.
    ///
    /// Port of `EnumValues.getNames(long)`.
    pub fn get_names_for_value(&self, value: i64) -> Option<Vec<String>> {
        match self.value_map.get(&value) {
            Some(names) if !names.is_empty() => Some(names.clone()),
            _ => None,
        }
    }

    /// Returns the comment for a given value name, or the empty string if there is none set.
    ///
    /// Port of `EnumValues.getComment(String)`.
    pub fn get_comment(&self, value_name: &str) -> String {
        self.comment_map.get(value_name).cloned().unwrap_or_default()
    }

    /// Returns all values defined in this enum, in ascending order.
    ///
    /// Port of `EnumValues.getValues()`.
    pub fn get_values(&self) -> Vec<i64> {
        self.value_map.keys().copied().collect()
    }

    /// Returns all names defined in this enum, grouped by ascending value and alphabetically
    /// within each value.
    ///
    /// Port of `EnumValues.getNames()`.
    pub fn get_names(&self) -> Vec<String> {
        self.value_map.values().flatten().cloned().collect()
    }

    /// Returns the number of defined names in this enum.
    ///
    /// Port of `EnumValues.size()`.
    pub fn get_count(&self) -> i32 {
        self.name_map.len() as i32
    }

    /// Returns true if the given name has been defined in this enum.
    ///
    /// Port of `EnumValues.containsName(String)`.
    pub fn contains_name(&self, value_name: &str) -> bool {
        self.name_map.contains_key(value_name)
    }

    /// Returns true if the given value has been defined in this enum.
    ///
    /// Port of `EnumValues.containsValue(long)`.
    pub fn contains_value(&self, value: i64) -> bool {
        self.value_map.contains_key(&value)
    }

    /// Returns the current [`EnumSignedState`] for this enum.
    ///
    /// Port of `EnumValues.getSignedState()`.
    pub fn get_signed_state(&self) -> EnumSignedState {
        self.signed_state
    }

    /// Returns the minimum size (in bytes) this enum can be and still represent all currently
    /// defined values. Only ever returns a power of two (1, 2, 4, or 8).
    ///
    /// Port of `EnumValues.getMinimumPossbileLength()`.
    pub fn get_minimum_possible_length(&self) -> i32 {
        if self.value_map.is_empty() {
            return 1;
        }
        // `BTreeMap` keys iterate in ascending order, so the first/last keys are the min/max --
        // matching Java's `TreeMap.firstKey()`/`lastKey()`.
        let min_value = *self.value_map.keys().next().expect("checked non-empty above");
        let max_value = *self.value_map.keys().next_back().expect("checked non-empty above");
        let has_negative_values = min_value < 0;

        // Check the min and max values in this enum to see if they fit in a 1 byte enum, then a
        // 2 byte enum, then a 4 byte enum. If the min and max values fit, all other values will
        // fit as well.
        let mut size = 1;
        while size < 8 {
            let min_possible = min_possible_value(size, has_negative_values);
            let max_possible = max_possible_value(size, has_negative_values);
            if min_value >= min_possible && max_value <= max_possible {
                return size;
            }
            size *= 2;
        }
        8
    }

    /// Port of the private `EnumValues.computeSignedness()`.
    fn compute_signedness(&self) -> EnumSignedState {
        if self.value_map.is_empty() {
            return EnumSignedState::None;
        }
        let min_value = *self.value_map.keys().next().expect("checked non-empty above");
        let max_value = *self.value_map.keys().next_back().expect("checked non-empty above");

        if max_value > max_possible_value(self.enum_length, true) {
            if min_value < 0 {
                return EnumSignedState::Invalid;
            }
            return EnumSignedState::Unsigned;
        }
        if min_value < 0 {
            return EnumSignedState::Signed;
        }
        EnumSignedState::None // no negatives and no large unsigned values
    }

    /// Adds a new entry to the cache and recomputes the signed state, without a comment. Mirrors
    /// [`Enum::add`]'s naming.
    ///
    /// Port of `EnumValues.addValue(String, long, String)` (called from `EnumDB.add` right after
    /// the new value record is persisted, to keep the live cache in sync in place rather than
    /// invalidating it).
    pub fn add(&mut self, value_name: &str, value: i64) {
        self.add_with_comment(value_name, value, "");
    }

    /// Adds a new entry to the cache with a comment and recomputes the signed state. Mirrors
    /// [`Enum::add_with_comment`]'s naming.
    ///
    /// Port of `EnumValues.addValue(String, long, String)`.
    pub fn add_with_comment(&mut self, value_name: &str, value: i64, comment: &str) {
        self.do_add_value(value_name.to_string(), value, comment);
        self.signed_state = self.compute_signedness();
    }

    /// Port of the private `EnumValues.doAddValue(String, long, String)`.
    fn do_add_value(&mut self, value_name: String, value: i64, comment: &str) {
        self.name_map.insert(value_name.clone(), value);
        let list = self.value_map.entry(value).or_default();
        list.push(value_name.clone());
        list.sort();
        // `StringUtils.isBlank` treats null, empty, and whitespace-only as blank.
        if !comment.trim().is_empty() {
            self.comment_map.insert(value_name, comment.to_string());
        }
    }
}

impl Enum for EnumValues {
    fn get_value_for_name(&self, name: &str) -> Option<i64> {
        EnumValues::get_value_for_name(self, name)
    }

    fn get_name_for_value(&self, value: i64) -> Option<String> {
        EnumValues::get_name_for_value(self, value)
    }

    fn get_names_for_value(&self, value: i64) -> Option<Vec<String>> {
        EnumValues::get_names_for_value(self, value)
    }

    fn get_comment(&self, name: &str) -> String {
        EnumValues::get_comment(self, name)
    }

    fn get_values(&self) -> Vec<i64> {
        EnumValues::get_values(self)
    }

    fn get_names(&self) -> Vec<String> {
        EnumValues::get_names(self)
    }

    fn get_count(&self) -> i32 {
        EnumValues::get_count(self)
    }

    fn add(&mut self, name: &str, value: i64) {
        EnumValues::add(self, name, value)
    }

    fn add_with_comment(&mut self, name: &str, value: i64, comment: &str) {
        EnumValues::add_with_comment(self, name, value, comment)
    }

    fn remove(&mut self, name: &str) {
        // `EnumValues.java` has no `remove`: `EnumDB.remove` instead nulls out the whole
        // `lazyEnumValues` cache and lets the next accessor reload a fresh snapshot from the
        // adapter (see the module docs). This trait impl exists purely so `EnumValues` can stand
        // in for a minimal, purely in-memory [`Enum`] in tests (see below); a real DB-backed
        // consumer would instead drop its `EnumValues` and rebuild via `EnumValues::new`.
        if let Some(value) = self.name_map.remove(name) {
            self.comment_map.remove(name);
            if let std::collections::btree_map::Entry::Occupied(mut entry) =
                self.value_map.entry(value)
            {
                entry.get_mut().retain(|n| n != name);
                if entry.get().is_empty() {
                    entry.remove();
                }
            }
            self.signed_state = self.compute_signedness();
        }
    }

    fn set_description(&mut self, _description: &str) {
        // `EnumValues` holds no description field (that lives on `EnumDB`'s own record).
    }

    fn get_enum_representation(
        &self,
        big_int: i128,
        _settings: &dyn crate::docking::settings::settings::Settings,
        _bit_length: i32,
    ) -> String {
        // `EnumValues` alone cannot build the compound (`|`-separated) fallback representation
        // that `EnumDb::enum_db_representation` provides -- that needs bit-group partitioning
        // over `get_length()`, which is a `DataType` concern this cache does not carry. Only the
        // exact-name-match case is handled here.
        self.get_name_for_value(big_int as i64).unwrap_or_default()
    }

    fn contains_name(&self, name: &str) -> bool {
        EnumValues::contains_name(self, name)
    }

    fn contains_value(&self, value: i64) -> bool {
        EnumValues::contains_value(self, value)
    }

    fn is_signed(&self) -> bool {
        self.signed_state == EnumSignedState::Signed
    }

    fn get_signed_state(&self) -> EnumSignedState {
        EnumValues::get_signed_state(self)
    }

    fn get_max_possible_value(&self) -> i64 {
        max_possible_value(self.enum_length, self.signed_state != EnumSignedState::Unsigned)
    }

    fn get_min_possible_value(&self) -> i64 {
        min_possible_value(self.enum_length, self.signed_state == EnumSignedState::Signed)
    }

    fn get_minimum_possible_length(&self) -> i32 {
        EnumValues::get_minimum_possible_length(self)
    }

    fn clone_enum(
        &self,
        _dtm: &dyn crate::program::model::data::data_type_manager::DataTypeManager,
    ) -> Box<dyn Enum> {
        Box::new(self.clone())
    }
}

impl crate::program::model::data::data_type::DataType for EnumValues {
    fn get_length(&self) -> i32 {
        self.enum_length
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator};
    use std::cell::RefCell;
    use std::sync::Arc;

    /// Minimal in-memory [`EnumValueDBAdapter`], used only to feed [`EnumValues::new`] real
    /// records the way a live `EnumValueDBAdapterV1` would.
    struct MockAdapter {
        schema: Arc<crate::framework::db::Schema>,
        records: RefCell<Vec<DBRecord>>,
        next_key: RefCell<i64>,
    }

    impl MockAdapter {
        fn new() -> Self {
            MockAdapter {
                schema: crate::program::database::data::enum_value_db_adapter::schema(),
                records: RefCell::new(Vec::new()),
                next_key: RefCell::new(0),
            }
        }

        fn seed(&self, enum_id: i64, name: &str, value: i64, comment: Option<&str>) {
            let mut key = self.next_key.borrow_mut();
            let mut rec = DBRecord::new(self.schema.clone(), Field::Long(Some(*key)));
            *key += 1;
            rec.set_field(ENUMVAL_NAME_COL, Field::String(Some(name.to_string())));
            rec.set_field(ENUMVAL_VALUE_COL, Field::Long(Some(value)));
            rec.set_field(super::ENUMVAL_ID_COL, Field::Long(Some(enum_id)));
            rec.set_field(ENUMVAL_COMMENT_COL, Field::String(comment.map(str::to_string)));
            self.records.borrow_mut().push(rec);
        }
    }

    struct MockRecordIterator {
        records: std::vec::IntoIter<DBRecord>,
    }

    impl RecordIterator for MockRecordIterator {
        fn next(&mut self) -> io::Result<Option<DBRecord>> {
            Ok(self.records.next())
        }
        fn has_next(&self) -> bool {
            self.records.len() > 0
        }
    }

    impl crate::program::util::DBRecordAdapter for MockAdapter {
        fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            Ok(Box::new(MockRecordIterator { records: self.records.borrow().clone().into_iter() }))
        }
        fn get_record_count(&self) -> usize {
            self.records.borrow().len()
        }
    }

    impl crate::framework::db::RecordTranslator for MockAdapter {
        fn translate_record(&self, old_record: DBRecord) -> io::Result<DBRecord> {
            Ok(old_record)
        }
    }

    impl EnumValueDBAdapter for MockAdapter {
        fn create_record(
            &mut self,
            enum_id: i64,
            name: &str,
            value: i64,
            comment: Option<&str>,
        ) -> io::Result<()> {
            self.seed(enum_id, name, value, comment);
            Ok(())
        }
        fn get_record(&self, value_id: i64) -> io::Result<Option<DBRecord>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .find(|r| r.get_key() == &Field::Long(Some(value_id)))
                .cloned())
        }
        fn delete_table(&mut self, _handle: &mut DBHandle) -> io::Result<()> {
            self.records.borrow_mut().clear();
            Ok(())
        }
        fn remove_record(&mut self, value_id: i64) -> io::Result<()> {
            self.records.borrow_mut().retain(|r| r.get_key() != &Field::Long(Some(value_id)));
            Ok(())
        }
        fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
            let mut records = self.records.borrow_mut();
            if let Some(existing) = records.iter_mut().find(|r| r.get_key() == record.get_key()) {
                *existing = record.clone();
            }
            Ok(())
        }
        fn get_value_ids_in_enum(&self, enum_id: i64) -> io::Result<Vec<Field>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .filter(|r| {
                    matches!(r.get_field(super::ENUMVAL_ID_COL), Field::Long(Some(v)) if *v == enum_id)
                })
                .map(|r| r.get_key().clone())
                .collect())
        }
    }

    #[test]
    fn loads_records_for_only_the_requested_enum() {
        let adapter = MockAdapter::new();
        adapter.seed(5, "RED", 1, Some("the color red"));
        adapter.seed(5, "GREEN", 2, None);
        adapter.seed(7, "ON", 1, None); // different enum -- must not be picked up

        let values = EnumValues::new(5, 1, &adapter).unwrap();
        assert_eq!(values.get_count(), 2);
        assert_eq!(values.get_value_for_name("RED"), Some(1));
        assert_eq!(values.get_value_for_name("GREEN"), Some(2));
        assert_eq!(values.get_value_for_name("ON"), None);
    }

    #[test]
    fn get_name_for_value_prefers_alphabetically_first() {
        let adapter = MockAdapter::new();
        adapter.seed(1, "ZEBRA", 9, None);
        adapter.seed(1, "APPLE", 9, None);

        let values = EnumValues::new(1, 1, &adapter).unwrap();
        assert_eq!(values.get_name_for_value(9), Some("APPLE".to_string()));
        let mut names = values.get_names_for_value(9).unwrap();
        names.sort();
        assert_eq!(names, vec!["APPLE".to_string(), "ZEBRA".to_string()]);
    }

    #[test]
    fn get_names_for_value_is_none_when_absent() {
        let adapter = MockAdapter::new();
        let values = EnumValues::new(1, 1, &adapter).unwrap();
        assert_eq!(values.get_names_for_value(42), None);
    }

    #[test]
    fn comment_lookup_both_directions() {
        let adapter = MockAdapter::new();
        adapter.seed(1, "RED", 1, Some("the color red"));
        adapter.seed(1, "GREEN", 2, None);

        let values = EnumValues::new(1, 1, &adapter).unwrap();
        assert_eq!(values.get_comment("RED"), "the color red");
        assert_eq!(values.get_comment("GREEN"), ""); // no comment set
        assert_eq!(values.get_comment("MISSING"), ""); // name not defined at all
    }

    #[test]
    fn blank_comment_is_treated_as_no_comment() {
        let adapter = MockAdapter::new();
        adapter.seed(1, "RED", 1, Some("   "));

        let values = EnumValues::new(1, 1, &adapter).unwrap();
        assert_eq!(values.get_comment("RED"), "");
    }

    #[test]
    fn get_values_and_get_names_are_ordered() {
        let adapter = MockAdapter::new();
        adapter.seed(1, "C", 3, None);
        adapter.seed(1, "A", 1, None);
        adapter.seed(1, "B", 2, None);
        adapter.seed(1, "A2", 1, None);

        let values = EnumValues::new(1, 1, &adapter).unwrap();
        assert_eq!(values.get_values(), vec![1, 2, 3]);
        // grouped by ascending value, alphabetical within a value: A, A2 (value 1), B (value 2),
        // C (value 3).
        assert_eq!(
            values.get_names(),
            vec!["A".to_string(), "A2".to_string(), "B".to_string(), "C".to_string()]
        );
    }

    #[test]
    fn contains_name_and_value() {
        let adapter = MockAdapter::new();
        adapter.seed(1, "RED", 1, None);

        let values = EnumValues::new(1, 1, &adapter).unwrap();
        assert!(values.contains_name("RED"));
        assert!(!values.contains_name("BLUE"));
        assert!(values.contains_value(1));
        assert!(!values.contains_value(2));
    }

    #[test]
    fn signed_state_none_for_small_positive_only_enum() {
        let adapter = MockAdapter::new();
        adapter.seed(1, "A", 1, None);
        adapter.seed(1, "B", 2, None);

        let values = EnumValues::new(1, 1, &adapter).unwrap();
        assert_eq!(values.get_signed_state(), EnumSignedState::None);
    }

    #[test]
    fn signed_state_signed_when_negative_value_present() {
        let adapter = MockAdapter::new();
        adapter.seed(1, "NEG", -1, None);

        let values = EnumValues::new(1, 1, &adapter).unwrap();
        assert_eq!(values.get_signed_state(), EnumSignedState::Signed);
    }

    #[test]
    fn signed_state_unsigned_when_high_unsigned_value_present() {
        let adapter = MockAdapter::new();
        // For a 1-byte enum, 200 exceeds the signed max (127) but fits the unsigned max (255).
        adapter.seed(1, "HIGH", 200, None);

        let values = EnumValues::new(1, 1, &adapter).unwrap();
        assert_eq!(values.get_signed_state(), EnumSignedState::Unsigned);
    }

    #[test]
    fn signed_state_invalid_when_both_negative_and_high_unsigned_present() {
        let adapter = MockAdapter::new();
        adapter.seed(1, "NEG", -1, None);
        adapter.seed(1, "HIGH", 200, None);

        let values = EnumValues::new(1, 1, &adapter).unwrap();
        assert_eq!(values.get_signed_state(), EnumSignedState::Invalid);
    }

    #[test]
    fn signed_state_empty_enum_is_none() {
        let adapter = MockAdapter::new();
        let values = EnumValues::new(1, 1, &adapter).unwrap();
        assert_eq!(values.get_signed_state(), EnumSignedState::None);
    }

    #[test]
    fn get_minimum_possible_length_grows_with_magnitude() {
        let adapter = MockAdapter::new();
        adapter.seed(1, "SMALL", 100, None);
        let values = EnumValues::new(1, 1, &adapter).unwrap();
        assert_eq!(values.get_minimum_possible_length(), 1);

        let adapter2 = MockAdapter::new();
        adapter2.seed(1, "BIG", 100_000, None);
        let values2 = EnumValues::new(1, 4, &adapter2).unwrap();
        assert_eq!(values2.get_minimum_possible_length(), 4);
    }

    #[test]
    fn get_minimum_possible_length_of_empty_enum_is_one() {
        let adapter = MockAdapter::new();
        let values = EnumValues::new(1, 1, &adapter).unwrap();
        assert_eq!(values.get_minimum_possible_length(), 1);
    }

    #[test]
    fn add_updates_cache_and_recomputes_signed_state_in_place() {
        let adapter = MockAdapter::new();
        adapter.seed(1, "A", 1, None);
        let mut values = EnumValues::new(1, 1, &adapter).unwrap();
        assert_eq!(values.get_signed_state(), EnumSignedState::None);

        values.add_with_comment("NEG", -1, "went negative");
        assert_eq!(values.get_count(), 2);
        assert_eq!(values.get_value_for_name("NEG"), Some(-1));
        assert_eq!(values.get_comment("NEG"), "went negative");
        assert_eq!(values.get_signed_state(), EnumSignedState::Signed);
    }

    #[test]
    fn add_without_comment_leaves_comment_empty() {
        let adapter = MockAdapter::new();
        let mut values = EnumValues::new(1, 1, &adapter).unwrap();
        values.add("PLAIN", 5);
        assert_eq!(values.get_comment("PLAIN"), "");
    }

    #[test]
    fn duplicate_name_added_twice_overwrites_value_mapping() {
        // `EnumValues.doAddValue` (like the Java `Map.put`) silently overwrites; `EnumDB.add`
        // itself is what rejects a duplicate name (via `containsName`) before ever calling
        // `addValue` -- see the module docs. This test documents that the cache layer itself is
        // last-write-wins, exactly mirroring `nameMap.put(valueName, value)`.
        let adapter = MockAdapter::new();
        let mut values = EnumValues::new(1, 1, &adapter).unwrap();
        values.add("DUP", 1);
        values.add("DUP", 2);
        assert_eq!(values.get_value_for_name("DUP"), Some(2));
        // The stale entry under the old value's bucket is still present -- `doAddValue` never
        // removes it, matching Java exactly (a real caller is expected to reject duplicates
        // before calling `addValue`, as `EnumDB.add` does).
        assert_eq!(values.get_names_for_value(1), Some(vec!["DUP".to_string()]));
        assert_eq!(values.get_names_for_value(2), Some(vec!["DUP".to_string()]));
    }

    #[test]
    fn usable_as_enum_trait_object() {
        let adapter = MockAdapter::new();
        adapter.seed(1, "RED", 1, Some("red"));
        let values = EnumValues::new(1, 1, &adapter).unwrap();
        let e: &dyn Enum = &values;
        assert_eq!(e.get_count(), 1);
        assert_eq!(e.get_value_for_name("RED"), Some(1));
        assert_eq!(e.get_comment("RED"), "red");
    }

    #[test]
    fn enum_trait_remove_updates_cache() {
        let adapter = MockAdapter::new();
        adapter.seed(1, "RED", 1, None);
        adapter.seed(1, "GREEN", 2, None);
        let mut values = EnumValues::new(1, 1, &adapter).unwrap();

        Enum::remove(&mut values, "RED");
        assert!(!values.contains_name("RED"));
        assert!(values.contains_name("GREEN"));
        assert_eq!(values.get_count(), 1);
    }
}
