//! Port of `ghidra.program.model.data.CycleGroup`, a plain (non-`DataType`) helper class that
//! defines a set of `DataType`s that a single action can cycle through.
//!
//! # Design notes
//!
//! Java's `dataList` is a shared, mutable `ArrayList<DataType>`: every accessor (`getDataTypes`,
//! `getNextDataType`, `removeDataType`, ...) either aliases or removes one of those exact object
//! references. Rust's ownership rules don't allow producing an *owned* `Box<dyn DataType>` from a
//! `&dyn DataType` (needed by [`CycleGroup::get_next_data_type`], which must sometimes hand
//! ownership of a stored entry to [`Pointer::new_pointer`] when cycling the pointee of a pointer),
//! since the already-ported (and, per this crate's convention, not modifiable here) [`DataType`]
//! trait has no generic clone capability. [`CycleDataType`] adds exactly that one capability,
//! scoped to this module's own needs rather than widening `DataType` itself; every other method
//! here (`remove_data_type`, `contains`, `add_data_type`'s dedup check, ...) still operates on
//! real stored instances exactly as Java does.
//!
//! # Known gap: the three built-in singleton cycle groups
//!
//! Java exposes three public static singletons -- `BYTE_CYCLE_GROUP` (byte/word/dword/qword),
//! `FLOAT_CYCLE_GROUP` (float/double/long double), and `STRING_CYCLE_GROUP`
//! (char/string/unicode) -- plus `ALL_CYCLE_GROUPS`, populated by three private nested
//! `CycleGroup` subclasses (`ByteCycleGroup`/`FloatCycleGroup`/`StringCycleGroup`) that each
//! construct real `ByteDataType`/`WordDataType`/.../`UnicodeDataType` instances in their
//! constructors. **This port does not populate those three singletons**: every one of those leaf
//! data types was ported in this crate as a trait (`ByteDataType`, `WordDataType`, `DWordDataType`,
//! `QWordDataType`, `FloatDataType`, `DoubleDataType`, `LongDoubleDataType`, `CharDataType`,
//! `StringDataType`, `UnicodeDataType`) with only private `Mock*` implementors in each trait's own
//! test module -- there is no concrete, constructible, production implementor of any of them
//! anywhere in this crate yet. Fabricating one here (or reaching into another module's private
//! test mock) would be exactly the kind of guessed, unverified stand-in this project's porting
//! rules rule out. The generic engine below (arbitrary `CycleGroup`s built from caller-supplied
//! [`CycleDataType`] instances, including the pointer-stacking `get_next_data_type` behavior) is
//! fully ported and tested; only the three convenience singletons are the documented gap, and
//! they should be straightforward to add once concrete implementors of those ten leaf traits
//! exist.
//!
//! `KeyStroke` (`javax.swing.KeyStroke`) is likewise only an empty marker trait in this crate
//! ([`crate::framework::seam_stubs::KeyStroke`]) with no constructible implementor, so
//! [`CycleGroup::default_key_stroke`] can never be populated by this crate today either; the
//! specific key codes the blocked built-in groups would have used are documented on this module's
//! (currently absent) singleton constructors for when both gaps are eventually closed:
//! `BYTE_CYCLE_GROUP` used `VK_B`, `FLOAT_CYCLE_GROUP` used `VK_F`, and `STRING_CYCLE_GROUP` used
//! `VK_QUOTE`, all with no modifiers.

use crate::framework::seam_stubs::KeyStroke;
use crate::program::model::data::data_type::DataType;

/// A [`DataType`] usable as a [`CycleGroup`] entry.
///
/// See the module docs for why this (rather than plain `Box<dyn DataType>`, as Java's
/// `DataType[]`/`DataType` parameters use) is needed: [`CycleGroup::get_next_data_type`] must be
/// able to hand ownership of a stored entry to [`Pointer::new_pointer`](super::pointer::Pointer::new_pointer).
pub trait CycleDataType: DataType {
    /// Produces a fresh, independently-owned [`DataType`] box representing the same type as
    /// `self`.
    fn box_clone(&self) -> Box<dyn DataType>;
}

/// Class to define a set of `DataType`s that a single action can cycle through.
///
/// Port of `ghidra.program.model.data.CycleGroup`.
pub struct CycleGroup {
    name: String,
    data_list: Vec<Box<dyn CycleDataType>>,
    default_key_stroke: Option<Box<dyn KeyStroke>>,
}

impl CycleGroup {
    /// Constructs a new cycle group with the given data types.
    ///
    /// # Arguments
    /// * `name` - cycle group name, which will be the suggested action name for those plugins
    ///   which implement a cycle group action.
    /// * `data_types` - data types in the group
    /// * `key_stroke` - default key stroke for the action to cycle through the data types
    pub fn new(
        name: impl Into<String>,
        data_types: Vec<Box<dyn CycleDataType>>,
        key_stroke: Option<Box<dyn KeyStroke>>,
    ) -> Self {
        CycleGroup {
            name: name.into(),
            data_list: data_types,
            default_key_stroke: key_stroke,
        }
    }

    /// Constructs a cycle group with one data type.
    ///
    /// # Arguments
    /// * `name` - cycle group name, which will be the suggested action name for those plugins
    ///   which implement a cycle group action.
    /// * `data_type` - single data type for the group
    /// * `key_stroke` - default key stroke for the action to cycle through the data types
    pub fn with_single(
        name: impl Into<String>,
        data_type: Box<dyn CycleDataType>,
        key_stroke: Option<Box<dyn KeyStroke>>,
    ) -> Self {
        Self::new(name, vec![data_type], key_stroke)
    }

    /// Constructs an empty group with no data types or keystroke.
    pub fn named(name: impl Into<String>) -> Self {
        Self::new(name, Vec::new(), None)
    }

    /// Get the data types in this group.
    pub fn get_data_types(&self) -> Vec<&dyn DataType> {
        self.data_list.iter().map(|dt| dt.as_ref() as &dyn DataType).collect()
    }

    /// Returns the cycle group name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the number of types in the group.
    pub fn size(&self) -> usize {
        self.data_list.len()
    }

    /// Returns the default key stroke for cycling through this group, if any.
    pub fn default_key_stroke(&self) -> Option<&dyn KeyStroke> {
        self.default_key_stroke.as_deref()
    }

    /// Sets the default key stroke for cycling through this group.
    ///
    /// Mirrors direct assignment of the Java `protected` `defaultKeyStroke` field (used by the
    /// built-in singleton subclasses' constructors).
    pub fn set_default_key_stroke(&mut self, key_stroke: Option<Box<dyn KeyStroke>>) {
        self.default_key_stroke = key_stroke;
    }

    /// Add a data type to this group.
    pub fn add_data_type(&mut self, dt: Box<dyn CycleDataType>) {
        if !self.exists(dt.as_ref()) {
            self.data_list.push(dt);
        }
    }

    /// Add the data type as the first in the list.
    pub fn add_first(&mut self, dt: Box<dyn CycleDataType>) {
        if !self.exists(dt.as_ref()) {
            self.data_list.insert(0, dt);
        }
    }

    /// Remove the data type from this group.
    ///
    /// Mirrors Java's `dataList.remove(dt)` (`List.remove(Object)`), which removes the first
    /// element equal to `dt` under `Object.equals` -- reference identity, since `DataType` does
    /// not override `equals`/`hashCode`. This is therefore a no-op unless `dt` is the exact same
    /// stored instance (not merely [`DataType::is_equivalent`]), matching Java precisely.
    pub fn remove_data_type(&mut self, dt: &dyn DataType) {
        let target_ptr = dt as *const dyn DataType as *const ();
        if let Some(pos) = self.data_list.iter().position(|d| {
            let candidate_ptr = d.as_ref() as &dyn DataType as *const dyn DataType as *const ();
            std::ptr::eq(candidate_ptr, target_ptr)
        }) {
            self.data_list.remove(pos);
        }
    }

    /// Remove the first data type in the list.
    ///
    /// # Errors
    /// Returns `Err` if the group is empty (mirrors `IndexOutOfBoundsException`).
    pub fn remove_first(&mut self) -> Result<(), String> {
        if self.data_list.is_empty() {
            return Err("IndexOutOfBoundsException: Index 0 out of bounds for length 0".to_string());
        }
        self.data_list.remove(0);
        Ok(())
    }

    /// Remove the last data type in the list.
    ///
    /// # Errors
    /// Returns `Err` if the group is empty (mirrors `IndexOutOfBoundsException`).
    pub fn remove_last(&mut self) -> Result<(), String> {
        if self.data_list.is_empty() {
            return Err(
                "IndexOutOfBoundsException: Index -1 out of bounds for length 0".to_string(),
            );
        }
        self.data_list.pop();
        Ok(())
    }

    /// Returns `true` if the given data type is in this cycle group.
    pub fn contains(&self, dt: &dyn DataType) -> bool {
        self.exists(dt)
    }

    /// Returns `true` if the given data type is the same type as any data type in the list.
    fn exists(&self, dt: &dyn DataType) -> bool {
        self.data_list
            .iter()
            .any(|d| dt.is_equivalent(d.as_ref() as &dyn DataType))
    }

    /// Get the next data type which should be used.
    ///
    /// # Arguments
    /// * `current_data_type` - current data type to which this cycle group is to be applied
    /// * `stack_pointers` - if true and `current_data_type` is a pointer, the pointer's base
    ///   type will be cycled
    ///
    /// # Returns
    /// The next data type, or `None` if this cycle group is empty.
    pub fn get_next_data_type(
        &self,
        current_data_type: Option<&dyn DataType>,
        stack_pointers: bool,
    ) -> Option<Box<dyn DataType>> {
        if self.data_list.is_empty() {
            return None;
        }

        if stack_pointers {
            if let Some(ptr) = current_data_type.and_then(DataType::as_pointer) {
                let inner = ptr.get_data_type();
                // `self.data_list` is non-empty (checked above), so the recursive call always
                // yields `Some`, exactly as in Java (where `dataList.get(0)` is always safe once
                // `dataList.size() != 0`).
                let next_inner = self
                    .get_next_data_type(inner.as_deref(), true)
                    .expect("non-empty cycle group always yields a next data type");
                return Some(ptr.new_pointer(next_inner) as Box<dyn DataType>);
            }
        }

        let mut index: i32 = -1;
        if let Some(dt) = current_data_type {
            if !dt.is_default_data_type() {
                for (i, cycle_dt) in self.data_list.iter().enumerate() {
                    if dt.is_equivalent(cycle_dt.as_ref() as &dyn DataType) {
                        index = i as i32;
                        break;
                    }
                }
            }
        }

        index += 1;
        let next = if index as usize >= self.data_list.len() {
            &self.data_list[0]
        } else {
            &self.data_list[index as usize]
        };

        Some(next.box_clone())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::pointer::Pointer;
    use crate::program::model::data::pointer_typedef_builder::PointerTypedefBuilder;

    /// A minimal [`CycleDataType`] test double. Two `MockLeaf`s are
    /// [`is_equivalent`](DataType::is_equivalent) exactly when their `kind` strings match,
    /// mirroring how real leaf `DataType`s (e.g. `ByteDataType`) compare structurally rather than
    /// by reference identity.
    #[derive(Clone)]
    struct MockLeaf {
        kind: String,
    }

    impl DataType for MockLeaf {
        fn get_name(&self) -> String {
            self.kind.clone()
        }

        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.kind == dt.get_name()
        }
    }

    impl CycleDataType for MockLeaf {
        fn box_clone(&self) -> Box<dyn DataType> {
            Box::new(self.clone())
        }
    }

    fn leaf(kind: &str) -> Box<dyn CycleDataType> {
        Box::new(MockLeaf { kind: kind.to_string() })
    }

    fn leaf_dt(kind: &str) -> Box<dyn DataType> {
        Box::new(MockLeaf { kind: kind.to_string() })
    }

    fn abc_group() -> CycleGroup {
        CycleGroup::new("Cycle: a,b,c", vec![leaf("a"), leaf("b"), leaf("c")], None)
    }

    #[test]
    fn new_group_has_expected_name_and_size() {
        let group = abc_group();
        assert_eq!(group.name(), "Cycle: a,b,c");
        assert_eq!(group.size(), 3);
    }

    #[test]
    fn named_constructs_empty_group() {
        let group = CycleGroup::named("Empty");
        assert_eq!(group.name(), "Empty");
        assert_eq!(group.size(), 0);
        assert!(group.default_key_stroke().is_none());
    }

    #[test]
    fn with_single_constructs_one_entry_group() {
        let group = CycleGroup::with_single("Solo", leaf("a"), None);
        assert_eq!(group.size(), 1);
    }

    #[test]
    fn get_data_types_returns_all_entries_in_order() {
        let group = abc_group();
        let types = group.get_data_types();
        assert_eq!(types.len(), 3);
        assert_eq!(types[0].get_name(), "a");
        assert_eq!(types[1].get_name(), "b");
        assert_eq!(types[2].get_name(), "c");
    }

    #[test]
    fn contains_uses_structural_equivalence() {
        let group = abc_group();
        assert!(group.contains(leaf_dt("a").as_ref()));
        assert!(!group.contains(leaf_dt("z").as_ref()));
    }

    #[test]
    fn add_data_type_skips_duplicates() {
        let mut group = CycleGroup::named("g");
        group.add_data_type(leaf("a"));
        group.add_data_type(leaf("a"));
        assert_eq!(group.size(), 1);
    }

    #[test]
    fn add_data_type_appends_new_entries() {
        let mut group = CycleGroup::named("g");
        group.add_data_type(leaf("a"));
        group.add_data_type(leaf("b"));
        assert_eq!(group.size(), 2);
    }

    #[test]
    fn add_first_inserts_at_front_and_skips_duplicates() {
        let mut group = abc_group();
        group.add_first(leaf("z"));
        assert_eq!(group.size(), 4);
        assert_eq!(group.get_data_types()[0].get_name(), "z");

        group.add_first(leaf("a"));
        assert_eq!(group.size(), 4); // "a" already present
    }

    #[test]
    fn remove_data_type_only_removes_the_exact_stored_instance() {
        let mut group = CycleGroup::named("g");
        group.add_data_type(leaf("a"));
        // A different (though structurally-equivalent) instance is not the same object.
        let other_a = leaf_dt("a");
        group.remove_data_type(other_a.as_ref());
        assert_eq!(group.size(), 1, "remove_data_type is reference-identity, not is_equivalent");
    }

    #[test]
    fn remove_data_type_removes_the_actual_instance() {
        let mut group = CycleGroup::named("g");
        let entry = leaf("a");
        // Capture the entry's address *before* moving it into `group`: moving a `Box` relocates
        // only the pointer, not its heap allocation, so this stays valid afterwards. This avoids
        // borrowing `group` at all (unlike going back through `get_data_types()`), sidestepping
        // any borrow-checker interaction with the mutable call below.
        let entry_ptr: *const dyn DataType = entry.as_ref() as &dyn DataType as *const dyn DataType;
        group.add_data_type(entry);

        // SAFETY: `group` now owns the entry the pointer refers to, and nothing has freed or
        // moved that heap allocation since it was captured above.
        group.remove_data_type(unsafe { &*entry_ptr });
        assert_eq!(group.size(), 0);
    }

    #[test]
    fn remove_first_and_remove_last() {
        let mut group = abc_group();
        group.remove_first().unwrap();
        assert_eq!(group.size(), 2);
        assert_eq!(group.get_data_types()[0].get_name(), "b");
        group.remove_last().unwrap();
        assert_eq!(group.size(), 1);
    }

    #[test]
    fn remove_first_on_empty_group_errors() {
        let mut group = CycleGroup::named("g");
        assert!(group.remove_first().is_err());
    }

    #[test]
    fn remove_last_on_empty_group_errors() {
        let mut group = CycleGroup::named("g");
        assert!(group.remove_last().is_err());
    }

    #[test]
    fn get_next_data_type_on_empty_group_is_none() {
        let group = CycleGroup::named("g");
        assert!(group.get_next_data_type(None, false).is_none());
    }

    #[test]
    fn get_next_data_type_with_no_current_returns_first() {
        let group = abc_group();
        let next = group.get_next_data_type(None, false).unwrap();
        assert_eq!(next.get_name(), "a");
    }

    #[test]
    fn get_next_data_type_cycles_forward() {
        let group = abc_group();
        let a = leaf_dt("a");
        let next = group.get_next_data_type(Some(a.as_ref()), false).unwrap();
        assert_eq!(next.get_name(), "b");
    }

    #[test]
    fn get_next_data_type_wraps_around_at_end() {
        let group = abc_group();
        let c = leaf_dt("c");
        let next = group.get_next_data_type(Some(c.as_ref()), false).unwrap();
        assert_eq!(next.get_name(), "a");
    }

    #[test]
    fn get_next_data_type_with_unmatched_current_returns_first() {
        let group = abc_group();
        let unmatched = leaf_dt("not_in_group");
        let next = group.get_next_data_type(Some(unmatched.as_ref()), false).unwrap();
        assert_eq!(next.get_name(), "a");
    }

    #[test]
    fn get_next_data_type_treats_default_data_type_like_no_current() {
        struct MockDefault;
        impl DataType for MockDefault {
            fn is_default_data_type(&self) -> bool {
                true
            }
        }

        let group = abc_group();
        let next = group.get_next_data_type(Some(&MockDefault), false).unwrap();
        assert_eq!(next.get_name(), "a");
    }

    // --- pointer-stacking behavior ---

    /// A minimal [`Pointer`] test double whose pointee (if any) is always a [`MockLeaf`],
    /// identified by name rather than by storing a `Box<dyn DataType>` directly -- this sidesteps
    /// needing any downcasting machinery in this test module, since `get_name()` alone is enough
    /// to reconstruct an equivalent `MockLeaf`.
    struct MockPointer {
        pointee_kind: Option<String>,
    }

    impl DataType for MockPointer {
        fn as_pointer(&self) -> Option<&dyn Pointer> {
            Some(self)
        }

        fn get_name(&self) -> String {
            format!("*{}", self.pointee_kind.clone().unwrap_or_default())
        }

        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.get_name() == dt.get_name()
        }
    }

    impl Pointer for MockPointer {
        fn get_data_type(&self) -> Option<Box<dyn DataType>> {
            self.pointee_kind.clone().map(|kind| Box::new(MockLeaf { kind }) as Box<dyn DataType>)
        }

        fn new_pointer(&self, data_type: Box<dyn DataType>) -> Box<dyn Pointer> {
            Box::new(MockPointer { pointee_kind: Some(data_type.get_name()) })
        }

        fn typedef_builder(&self) -> Box<dyn PointerTypedefBuilder> {
            unimplemented!("not exercised by these tests")
        }
    }

    #[test]
    fn get_next_data_type_stacks_through_pointer() {
        let group = abc_group();
        let ptr = MockPointer { pointee_kind: Some("a".to_string()) };

        let next = group
            .get_next_data_type(Some(&ptr as &dyn DataType), true)
            .expect("non-empty group always yields a next data type");

        let next_ptr = next.as_pointer().expect("result should still be a pointer");
        let next_pointee = next_ptr.get_data_type().expect("pointee should be present");
        assert_eq!(next_pointee.get_name(), "b");
    }

    #[test]
    fn get_next_data_type_stacks_through_pointer_to_null_pointee() {
        let group = abc_group();
        let ptr = MockPointer { pointee_kind: None };

        let next = group
            .get_next_data_type(Some(&ptr as &dyn DataType), true)
            .expect("non-empty group always yields a next data type");

        let next_ptr = next.as_pointer().expect("result should still be a pointer");
        let next_pointee = next_ptr.get_data_type().expect("pointee should be present");
        assert_eq!(next_pointee.get_name(), "a");
    }

    #[test]
    fn get_next_data_type_ignores_stack_pointers_when_current_is_not_a_pointer() {
        let group = abc_group();
        let a = leaf_dt("a");
        let next = group.get_next_data_type(Some(a.as_ref()), true).unwrap();
        assert_eq!(next.get_name(), "b");
    }
}
