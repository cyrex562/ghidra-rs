//! Port of `ghidra.util.graph.attributes.DoubleAttribute`.

use std::cmp::Ordering;

use crate::util::datastruct::long_double_hashtable::LongDoubleHashtable;
use crate::util::exception::NoValueException;
use crate::util::graph::attributes::attribute::Attribute;
use crate::util::graph::attributes::attribute_manager::DOUBLE_TYPE;
use crate::util::graph::key_indexable_set::KeyIndexableSet;
use crate::util::graph::keyed_object::KeyedObject;

/// Storage mechanism for double-valued information about the elements of a `KeyIndexableSet`,
/// e.g. the vertices of a `DirectedGraph`.
///
/// Port of `ghidra.util.graph.attributes.DoubleAttribute<T extends KeyedObject>` (deprecated since
/// Ghidra 10.2). Values are stored in a [`LongDoubleHashtable`] keyed by [`KeyedObject::key`],
/// mirroring the Java field (`private LongDoubleHashtable values`; the commented-out `double[]
/// values` shown in the Java source was never actually used).
///
/// Per this crate's composition-over-inheritance convention, and following the precedent already
/// set by the ported [`Attribute`] trait itself (see that trait's own doc comment on why it holds
/// no shared `base` struct: an implementer's constructor captures a reference to its owning set,
/// which a shared base cannot express without picking a concrete lifetime/ownership strategy for
/// that borrow), this struct stores the `name`/`owning_set`/`modification_number`/
/// `backing_set_modification_number` fields Java's abstract `Attribute` superclass would have held
/// directly, and implements [`Attribute<T>`] using them.
#[deprecated(note = "Deprecated since Ghidra 10.2")]
pub struct DoubleAttribute<'a, T: KeyedObject> {
    name: String,
    owning_set: &'a dyn KeyIndexableSet<T>,
    modification_number: i64,
    backing_set_modification_number: i64,
    values: LongDoubleHashtable,
}

#[allow(deprecated)]
impl<'a, T: KeyedObject> DoubleAttribute<'a, T> {
    /// Construct a new `DoubleAttribute`.
    ///
    /// Port of `DoubleAttribute(String name, KeyIndexableSet<T> set)`.
    ///
    /// * `name` - the name used to identify this attribute.
    /// * `set` - the `KeyIndexableSet` whose elements can be assigned a value within this
    ///   attribute.
    pub fn new(name: impl Into<String>, set: &'a dyn KeyIndexableSet<T>) -> Self {
        Self {
            name: name.into(),
            owning_set: set,
            modification_number: 0,
            backing_set_modification_number: set.modification_number(),
            values: LongDoubleHashtable::new(),
        }
    }

    /// Set the value of this attribute for the specified `KeyedObject`.
    ///
    /// Port of `setValue(T o, double value)`.
    ///
    /// * `o` - the `KeyedObject` that is assigned the value. Should be a member of the owning
    ///   set.
    /// * `value` - the value to associate with the specified `KeyedObject`.
    ///
    /// Returns `true` if the value could be set. Returns `false` if `o` is not a member of the
    /// owning set.
    pub fn set_value(&mut self, o: &T, value: f64) -> bool {
        if self.owning_set.contains(o) {
            self.values.put(o.key(), value);
            self.update();
            true
        } else {
            false
        }
    }

    /// Return the value associated with the specified `KeyedObject`.
    ///
    /// Port of `getValue(KeyedObject o)`.
    ///
    /// # Errors
    /// Returns [`NoValueException`] if the value has not been set (this also covers `o` not
    /// belonging to the owning set, matching Java's own behavior -- see the struct's own docs).
    pub fn get_value(&self, o: &dyn KeyedObject) -> Result<f64, NoValueException> {
        self.values.get(o.key())
    }

    /// Returns the elements of the owning set sorted by their values of this attribute.
    ///
    /// Port of `toSortedArray()`.
    pub fn to_sorted_array(&self) -> Vec<&T> {
        let mut keyed_objects = self.owning_set.to_array();
        keyed_objects.sort_by(|a, b| self.compare(*a, *b));
        keyed_objects
    }

    /// Sorts the given array of `KeyedObject`s by their values of this attribute.
    ///
    /// Port of `toSortedArray(KeyedObject[] keyedObjects)`. Unlike [`to_sorted_array`
    /// ](Self::to_sorted_array), this accepts any `KeyedObject`s -- not just members of the
    /// owning set -- matching Java's loosely-typed `KeyedObject[]` parameter (this attribute's
    /// [`compare`](Self::compare) tolerates values that were never set, per its own docs).
    ///
    /// Java sorts a *clone* of the given array and returns it, leaving the input untouched; this
    /// is mirrored here by returning a freshly-sorted `Vec` rather than sorting in place.
    pub fn sort_array<'k>(&self, keyed_objects: &[&'k dyn KeyedObject]) -> Vec<&'k dyn KeyedObject> {
        let mut clone: Vec<&'k dyn KeyedObject> = keyed_objects.to_vec();
        clone.sort_by(|a, b| self.compare(*a, *b));
        clone
    }

    /// Port of the nested `DoubleAttribute.DoubleComparator.compare(Object, Object)`.
    ///
    /// Keyed objects are first compared by the value of the attribute. Ties (including the case
    /// where neither value compares less-than or greater-than the other, e.g. because one or
    /// both are `NaN` -- see the preserved-quirk note below) are broken by comparing the keys of
    /// the `KeyedObject`s. A `KeyedObject` with no value set is treated as sorting *after* one
    /// that does have a value; if neither has a value, they are compared by key.
    ///
    /// # Preserved quirk: `NaN` values fall through to key comparison
    /// Java's `(value1 - value2) < 0`/`(value1 - value2) > 0` checks are both `false` whenever
    /// either value is `NaN` (per IEEE 754, every comparison involving `NaN` is `false`), so two
    /// `KeyedObject`s where at least one has a `NaN` value fall through to the key-comparison
    /// branch exactly as if their values were equal -- reproduced here as-is via the same
    /// floating-point comparisons rather than `f64::total_cmp` or similar NaN-aware ordering.
    fn compare(&self, ko1: &dyn KeyedObject, ko2: &dyn KeyedObject) -> Ordering {
        match self.get_value(ko1) {
            Ok(value1) => match self.get_value(ko2) {
                Ok(value2) => {
                    if (value1 - value2) < 0.0 {
                        Ordering::Less
                    } else if (value1 - value2) > 0.0 {
                        Ordering::Greater
                    } else {
                        Self::compare_keys(ko1, ko2)
                    }
                }
                // ko1 is ok, ko2 fails.
                Err(_) => Ordering::Less,
            },
            Err(_) => match self.get_value(ko2) {
                // ko2 is ok so it precedes ko1.
                Ok(_) => Ordering::Greater,
                Err(_) => Self::compare_keys(ko1, ko2),
            },
        }
    }

    fn compare_keys(ko1: &dyn KeyedObject, ko2: &dyn KeyedObject) -> Ordering {
        if (ko1.key() - ko2.key()) < 0 {
            Ordering::Less
        } else if (ko1.key() - ko2.key()) > 0 {
            Ordering::Greater
        } else {
            Ordering::Equal
        }
    }
}

#[allow(deprecated)]
impl<'a, T: KeyedObject> Attribute<T> for DoubleAttribute<'a, T> {
    fn name(&self) -> &str {
        &self.name
    }

    fn owning_set(&self) -> &dyn KeyIndexableSet<T> {
        self.owning_set
    }

    fn get_modification_number(&self) -> i64 {
        self.modification_number
    }

    fn update(&mut self) {
        self.modification_number += 1;
    }

    fn backing_set_modification_number(&self) -> i64 {
        self.backing_set_modification_number
    }

    /// Port of `attributeType()`: returns `AttributeManager.DOUBLE_TYPE`.
    fn attribute_type(&self) -> String {
        DOUBLE_TYPE.to_string()
    }

    /// Port of `getValueAsString(KeyedObject o)`: `Double.toString(getValue(o))`, or `"0.0"` if
    /// the value has not been set.
    ///
    /// Uses Rust's native `f64` `Display` for the successful case, which -- like
    /// [`VtScore::to_storage_string`](crate::feature::vt::api::main::vt_score::VtScore::to_storage_string)
    /// and [`LSHVector`](crate::generic::lsh::vector::lsh_cosine_vector)'s own documented
    /// `Double.toString`-approximation -- corresponds to, but is not always byte-identical to,
    /// Java's `Double.toString` for every possible value (e.g. Java always renders a whole number
    /// with a trailing `.0`; Rust's `Display` does not). The `"0.0"` fallback for the
    /// no-value-set case is a Java string literal, not a `Double.toString` call, so it is
    /// reproduced verbatim regardless.
    fn get_value_as_string(&self, o: &dyn KeyedObject) -> String {
        match self.get_value(o) {
            Ok(v) => v.to_string(),
            Err(_) => "0.0".to_string(),
        }
    }

    /// Port of `clear()`: `values.removeAll();`.
    ///
    /// # Preserved quirk: does not bump the modification number
    /// Unlike [`set_value`](Self::set_value), Java's `clear()` does *not* call `update()` --
    /// clearing every value leaves [`Attribute::get_modification_number`] unchanged, reproduced
    /// as-is here rather than "fixed" to call [`update`](Attribute::update).
    fn clear(&mut self) {
        self.values.remove_all();
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::util::seam_stubs::GraphIteratorLike;

    struct MockKeyedObject {
        key: i64,
    }

    impl KeyedObject for MockKeyedObject {
        fn key(&self) -> i64 {
            self.key
        }
    }

    struct MockIterator<'a> {
        remaining: std::slice::Iter<'a, MockKeyedObject>,
    }

    impl<'a> GraphIteratorLike<MockKeyedObject> for MockIterator<'a> {
        fn has_next(&self) -> bool {
            self.remaining.clone().next().is_some()
        }
        fn next(&mut self) -> Option<MockKeyedObject> {
            self.remaining.next().map(|o| MockKeyedObject { key: o.key })
        }
        fn remove(&mut self) -> bool {
            false
        }
    }

    struct MockSet {
        objects: Vec<MockKeyedObject>,
        modification_number: i64,
    }

    impl KeyIndexableSet<MockKeyedObject> for MockSet {
        fn modification_number(&self) -> i64 {
            self.modification_number
        }
        fn size(&self) -> usize {
            self.objects.len()
        }
        fn capacity(&self) -> usize {
            self.objects.capacity()
        }
        fn add(&mut self, obj: MockKeyedObject) -> bool {
            if self.contains(&obj) {
                return false;
            }
            self.objects.push(obj);
            self.modification_number += 1;
            true
        }
        fn remove(&mut self, obj: &MockKeyedObject) -> bool {
            let before = self.objects.len();
            self.objects.retain(|o| o.key != obj.key);
            let removed = self.objects.len() != before;
            if removed {
                self.modification_number += 1;
            }
            removed
        }
        fn contains(&self, obj: &MockKeyedObject) -> bool {
            self.objects.iter().any(|o| o.key == obj.key)
        }
        fn iterator(&self) -> Box<dyn GraphIteratorLike<MockKeyedObject> + '_> {
            Box::new(MockIterator { remaining: self.objects.iter() })
        }
        fn to_array(&self) -> Vec<&MockKeyedObject> {
            self.objects.iter().collect()
        }
        fn get_keyed_object(&self, key: i64) -> Option<&MockKeyedObject> {
            self.objects.iter().find(|o| o.key == key)
        }
    }

    fn set_with(keys: &[i64]) -> MockSet {
        let mut set = MockSet { objects: Vec::new(), modification_number: 0 };
        for &k in keys {
            set.add(MockKeyedObject { key: k });
        }
        set
    }

    #[test]
    fn name_and_type_report_constructed_values() {
        let set = set_with(&[]);
        let attr = DoubleAttribute::new("weight", &set);
        assert_eq!(attr.name(), "weight");
        assert_eq!(attr.attribute_type(), "DOUBLE_TYPE");
    }

    #[test]
    fn set_value_then_get_value_round_trips_for_member_of_owning_set() {
        let set = set_with(&[1, 2]);
        let mut attr = DoubleAttribute::new("weight", &set);
        let obj = MockKeyedObject { key: 1 };
        assert!(attr.set_value(&obj, 3.5));
        assert_eq!(attr.get_value(&obj), Ok(3.5));
    }

    #[test]
    fn set_value_returns_false_and_does_not_store_for_non_member() {
        let set = set_with(&[1]);
        let mut attr = DoubleAttribute::new("weight", &set);
        let stray = MockKeyedObject { key: 99 };
        assert!(!attr.set_value(&stray, 1.0));
        assert!(attr.get_value(&stray).is_err());
    }

    #[test]
    fn set_value_bumps_modification_number() {
        let set = set_with(&[1]);
        let mut attr = DoubleAttribute::new("weight", &set);
        assert_eq!(attr.get_modification_number(), 0);
        attr.set_value(&MockKeyedObject { key: 1 }, 2.0);
        assert_eq!(attr.get_modification_number(), 1);
    }

    #[test]
    fn get_value_for_unset_object_is_no_value_exception() {
        let set = set_with(&[1]);
        let attr: DoubleAttribute<MockKeyedObject> = DoubleAttribute::new("weight", &set);
        assert!(attr.get_value(&MockKeyedObject { key: 1 }).is_err());
    }

    #[test]
    fn get_value_as_string_for_unset_object_is_the_literal_zero_point_zero() {
        let set = set_with(&[1]);
        let attr: DoubleAttribute<MockKeyedObject> = DoubleAttribute::new("weight", &set);
        assert_eq!(attr.get_value_as_string(&MockKeyedObject { key: 1 }), "0.0");
    }

    #[test]
    fn get_value_as_string_for_set_object_matches_rusts_float_display() {
        let set = set_with(&[1]);
        let mut attr = DoubleAttribute::new("weight", &set);
        let obj = MockKeyedObject { key: 1 };
        attr.set_value(&obj, 3.5);
        assert_eq!(attr.get_value_as_string(&obj), "3.5");
    }

    #[test]
    fn clear_removes_values_but_does_not_bump_modification_number() {
        // Preserved quirk: unlike set_value, clear() does not call update().
        let set = set_with(&[1]);
        let mut attr = DoubleAttribute::new("weight", &set);
        let obj = MockKeyedObject { key: 1 };
        attr.set_value(&obj, 5.0);
        assert_eq!(attr.get_modification_number(), 1);

        attr.clear();
        assert!(attr.get_value(&obj).is_err());
        // Modification number is unchanged by clear(), unlike set_value.
        assert_eq!(attr.get_modification_number(), 1);
    }

    #[test]
    fn to_sorted_array_orders_ascending_by_value() {
        let set = set_with(&[1, 2, 3]);
        let mut attr = DoubleAttribute::new("weight", &set);
        attr.set_value(&MockKeyedObject { key: 1 }, 30.0);
        attr.set_value(&MockKeyedObject { key: 2 }, 10.0);
        attr.set_value(&MockKeyedObject { key: 3 }, 20.0);

        let sorted = attr.to_sorted_array();
        let keys: Vec<i64> = sorted.iter().map(|o| o.key()).collect();
        assert_eq!(keys, vec![2, 3, 1]);
    }

    #[test]
    fn to_sorted_array_treats_unset_values_as_sorting_last() {
        // Preserved quirk: DoubleComparator.compare's nested try/catch, when ko1's lookup
        // throws NoValueException but ko2's succeeds, returns +1 (ko1 sorts *after* ko2) --
        // and symmetrically -1 (ko1 first) when ko1 has a value but ko2's lookup fails. So an
        // object with a real value always sorts before one with none, regardless of the value.
        let set = set_with(&[1, 2]);
        let mut attr = DoubleAttribute::new("weight", &set);
        attr.set_value(&MockKeyedObject { key: 2 }, -1000.0);
        // key 1 is never given a value.

        let sorted = attr.to_sorted_array();
        let keys: Vec<i64> = sorted.iter().map(|o| o.key()).collect();
        assert_eq!(keys, vec![2, 1]);
    }

    #[test]
    fn to_sorted_array_breaks_ties_by_key() {
        let set = set_with(&[5, 1, 3]);
        let mut attr = DoubleAttribute::new("weight", &set);
        for key in [5, 1, 3] {
            attr.set_value(&MockKeyedObject { key }, 7.0);
        }

        let sorted = attr.to_sorted_array();
        let keys: Vec<i64> = sorted.iter().map(|o| o.key()).collect();
        assert_eq!(keys, vec![1, 3, 5]);
    }

    #[test]
    fn sort_array_returns_a_new_sorted_vec_leaving_input_unchanged() {
        let set = set_with(&[1, 2]);
        let mut attr = DoubleAttribute::new("weight", &set);
        attr.set_value(&MockKeyedObject { key: 1 }, 9.0);
        attr.set_value(&MockKeyedObject { key: 2 }, 1.0);

        let a = MockKeyedObject { key: 1 };
        let b = MockKeyedObject { key: 2 };
        let input: Vec<&dyn KeyedObject> = vec![&a, &b];
        let sorted = attr.sort_array(&input);

        assert_eq!(sorted[0].key(), 2);
        assert_eq!(sorted[1].key(), 1);
        // Input order is untouched.
        assert_eq!(input[0].key(), 1);
        assert_eq!(input[1].key(), 2);
    }

    #[test]
    fn sort_array_tolerates_keyed_objects_outside_the_owning_set() {
        // Java's toSortedArray(KeyedObject[]) accepts any KeyedObject array, not just members of
        // the owning set; a non-member has no stored value (NoValueException, same as an unset
        // member), so it sorts *after* one with a real value -- see
        // to_sorted_array_treats_unset_values_as_sorting_last for why.
        let set = set_with(&[1]);
        let mut attr = DoubleAttribute::new("weight", &set);
        attr.set_value(&MockKeyedObject { key: 1 }, 4.0);

        let member = MockKeyedObject { key: 1 };
        let stranger = MockKeyedObject { key: 42 };
        let input: Vec<&dyn KeyedObject> = vec![&member, &stranger];
        let sorted = attr.sort_array(&input);
        assert_eq!(sorted[0].key(), 1);
        assert_eq!(sorted[1].key(), 42);
    }

    #[test]
    fn owning_set_is_unmodified_tracks_backing_set() {
        let mut set = set_with(&[]);
        set.add(MockKeyedObject { key: 1 });
        let attr: DoubleAttribute<MockKeyedObject> = DoubleAttribute::new("weight", &set);
        assert!(attr.owning_set_is_unmodified());
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let set = set_with(&[1]);
        let mut attr: Box<dyn Attribute<MockKeyedObject>> = Box::new(DoubleAttribute::new("weight", &set));
        assert_eq!(attr.name(), "weight");
        assert_eq!(attr.attribute_type(), "DOUBLE_TYPE");
        attr.clear();
    }
}
