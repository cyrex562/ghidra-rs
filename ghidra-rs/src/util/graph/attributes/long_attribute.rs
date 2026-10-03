//! Port of `ghidra.util.graph.attributes.LongAttribute`.

use std::cmp::Ordering;

use crate::util::datastruct::long_long_hashtable::LongLongHashtable;
use crate::util::exception::NoValueException;
use crate::util::graph::attributes::attribute::Attribute;
use crate::util::graph::attributes::attribute_manager::LONG_TYPE;
use crate::util::graph::key_indexable_set::KeyIndexableSet;
use crate::util::graph::keyed_object::KeyedObject;

/// Storage mechanism for long-valued (`i64`) information about the elements of a
/// `KeyIndexableSet`, e.g. the vertices of a `DirectedGraph`.
///
/// Port of `ghidra.util.graph.attributes.LongAttribute<T extends KeyedObject>` (deprecated since
/// Ghidra 10.2). Values are stored in a [`LongLongHashtable`] keyed by [`KeyedObject::key`],
/// mirroring the Java field (`private LongLongHashtable values`; the commented-out `int[] values`
/// shown in the Java source was never actually used).
///
/// As with [`IntegerAttribute`](crate::util::graph::attributes::IntegerAttribute)'s own docs,
/// Java's `LongAttribute` constructor passes the owning set's current size as an initial capacity
/// hint (`new ghidra.util.datastruct.LongLongHashtable(set.size())`) -- mirrored here via
/// [`LongLongHashtable::with_capacity`] rather than [`LongLongHashtable::new`] (which is what
/// [`DoubleAttribute`](crate::util::graph::attributes::DoubleAttribute)'s sibling constructor uses
/// instead).
///
/// Per this crate's composition-over-inheritance convention, and following the precedent already
/// set by the ported [`Attribute`] trait itself (see that trait's own doc comment on why it holds
/// no shared `base` struct), this struct stores the `name`/`owning_set`/`modification_number`/
/// `backing_set_modification_number` fields Java's abstract `Attribute` superclass would have held
/// directly, and implements [`Attribute<T>`] using them.
#[deprecated(note = "Deprecated since Ghidra 10.2")]
pub struct LongAttribute<'a, T: KeyedObject> {
    name: String,
    owning_set: &'a dyn KeyIndexableSet<T>,
    modification_number: i64,
    backing_set_modification_number: i64,
    values: LongLongHashtable,
}

#[allow(deprecated)]
impl<'a, T: KeyedObject> LongAttribute<'a, T> {
    /// Construct a new `LongAttribute`.
    ///
    /// Port of `LongAttribute(String name, KeyIndexableSet<T> set)`.
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
            values: LongLongHashtable::with_capacity(set.size() as i32),
        }
    }

    /// Set the value of this attribute for the specified `KeyedObject`.
    ///
    /// Port of `setValue(KeyedObject o, long value)`. Note the Java parameter is typed
    /// `KeyedObject`, not `T` (unlike every sibling `*Attribute::set_value` in this package),
    /// mirrored here via `&dyn KeyedObject` rather than `&T`. As with
    /// [`IntegerAttribute::set_value`](crate::util::graph::attributes::IntegerAttribute::set_value),
    /// Java's `LongAttribute.setValue` does not check `owningSet().contains(o)` before storing --
    /// it always calls `update()` and stores the value, and returns nothing (`void`).
    ///
    /// * `o` - the `KeyedObject` that is assigned the value. Should be a member of the owning
    ///   set.
    /// * `value` - the value to associate with the specified `KeyedObject`.
    pub fn set_value(&mut self, o: &dyn KeyedObject, value: i64) {
        self.update();
        self.values.put(o.key(), value);
    }

    /// Return the value associated with the specified `KeyedObject`.
    ///
    /// Port of `getValue(KeyedObject o)`.
    ///
    /// # Errors
    /// Returns [`NoValueException`] if the value has not been set (this also covers `o` not
    /// belonging to the owning set, matching Java's own behavior -- see the struct's own docs).
    pub fn get_value(&self, o: &dyn KeyedObject) -> Result<i64, NoValueException> {
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
    /// Port of `toSortedArray(KeyedObject[] keyedObjects)`. See
    /// [`DoubleAttribute::sort_array`](crate::util::graph::attributes::DoubleAttribute::sort_array)'s
    /// docs for why this returns a freshly-sorted `Vec` rather than sorting in place, and why it
    /// tolerates `KeyedObject`s outside the owning set.
    pub fn sort_array<'k>(&self, keyed_objects: &[&'k dyn KeyedObject]) -> Vec<&'k dyn KeyedObject> {
        let mut clone: Vec<&'k dyn KeyedObject> = keyed_objects.to_vec();
        clone.sort_by(|a, b| self.compare(*a, *b));
        clone
    }

    /// Port of the nested `LongAttribute.LongComparator.compare(Object, Object)`.
    ///
    /// Keyed objects are first compared by the value of the attribute. Ties are broken by
    /// comparing the keys of the `KeyedObject`s. A `KeyedObject` with no value set is treated as
    /// sorting *after* one that does have a value; if neither has a value, they are compared by
    /// key. Same nested-try/catch shape as
    /// [`DoubleAttribute`](crate::util::graph::attributes::DoubleAttribute)'s own
    /// `DoubleComparator` (see that struct's `compare` docs for the full trace) and
    /// [`IntegerAttribute`](crate::util::graph::attributes::IntegerAttribute)'s `IntegerComparator`
    /// -- except Java's `LongComparator` compares values via explicit `<`/`>` rather than
    /// subtraction (avoiding the subtraction-overflow risk `i64` subtraction could otherwise
    /// introduce), mirrored here the same way.
    fn compare(&self, ko1: &dyn KeyedObject, ko2: &dyn KeyedObject) -> Ordering {
        match self.get_value(ko1) {
            Ok(value1) => match self.get_value(ko2) {
                Ok(value2) => {
                    if value1 < value2 {
                        Ordering::Less
                    } else if value1 > value2 {
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
impl<'a, T: KeyedObject> Attribute<T> for LongAttribute<'a, T> {
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

    /// Port of `attributeType()`: returns `AttributeManager.LONG_TYPE`.
    fn attribute_type(&self) -> String {
        LONG_TYPE.to_string()
    }

    /// Port of `getValueAsString(KeyedObject o)`: `Long.toString(getValue(o))`, or `"0"` if the
    /// value has not been set.
    fn get_value_as_string(&self, o: &dyn KeyedObject) -> String {
        match self.get_value(o) {
            Ok(v) => v.to_string(),
            Err(_) => "0".to_string(),
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
        let attr = LongAttribute::new("size", &set);
        assert_eq!(attr.name(), "size");
        assert_eq!(attr.attribute_type(), "LONG_TYPE");
    }

    #[test]
    fn set_value_then_get_value_round_trips() {
        let set = set_with(&[1, 2]);
        let mut attr = LongAttribute::new("size", &set);
        let obj = MockKeyedObject { key: 1 };
        attr.set_value(&obj, 1_000_000_000_000);
        assert_eq!(attr.get_value(&obj), Ok(1_000_000_000_000));
    }

    #[test]
    fn set_value_does_not_check_owning_set_membership() {
        // Preserved quirk: like IntegerAttribute::set_value, this stores (and bumps the
        // modification number) unconditionally, even for a stray KeyedObject.
        let set = set_with(&[1]);
        let mut attr = LongAttribute::new("size", &set);
        let stray = MockKeyedObject { key: 99 };
        attr.set_value(&stray, 7);
        assert_eq!(attr.get_value(&stray), Ok(7));
        assert_eq!(attr.get_modification_number(), 1);
    }

    #[test]
    fn get_value_for_unset_object_is_no_value_exception() {
        let set = set_with(&[1]);
        let attr: LongAttribute<MockKeyedObject> = LongAttribute::new("size", &set);
        assert!(attr.get_value(&MockKeyedObject { key: 1 }).is_err());
    }

    #[test]
    fn get_value_as_string_for_unset_object_is_the_literal_zero() {
        let set = set_with(&[1]);
        let attr: LongAttribute<MockKeyedObject> = LongAttribute::new("size", &set);
        assert_eq!(attr.get_value_as_string(&MockKeyedObject { key: 1 }), "0");
    }

    #[test]
    fn get_value_as_string_for_set_object_matches_display() {
        let set = set_with(&[1]);
        let mut attr = LongAttribute::new("size", &set);
        let obj = MockKeyedObject { key: 1 };
        attr.set_value(&obj, -12);
        assert_eq!(attr.get_value_as_string(&obj), "-12");
    }

    #[test]
    fn clear_removes_values_but_does_not_bump_modification_number() {
        let set = set_with(&[1]);
        let mut attr = LongAttribute::new("size", &set);
        let obj = MockKeyedObject { key: 1 };
        attr.set_value(&obj, 5);
        assert_eq!(attr.get_modification_number(), 1);

        attr.clear();
        assert!(attr.get_value(&obj).is_err());
        assert_eq!(attr.get_modification_number(), 1);
    }

    #[test]
    fn to_sorted_array_orders_ascending_by_value() {
        let set = set_with(&[1, 2, 3]);
        let mut attr = LongAttribute::new("size", &set);
        attr.set_value(&MockKeyedObject { key: 1 }, 30);
        attr.set_value(&MockKeyedObject { key: 2 }, 10);
        attr.set_value(&MockKeyedObject { key: 3 }, 20);

        let sorted = attr.to_sorted_array();
        let keys: Vec<i64> = sorted.iter().map(|o| o.key()).collect();
        assert_eq!(keys, vec![2, 3, 1]);
    }

    #[test]
    fn to_sorted_array_treats_unset_values_as_sorting_last() {
        let set = set_with(&[1, 2]);
        let mut attr = LongAttribute::new("size", &set);
        attr.set_value(&MockKeyedObject { key: 2 }, -1000);
        // key 1 is never given a value.

        let sorted = attr.to_sorted_array();
        let keys: Vec<i64> = sorted.iter().map(|o| o.key()).collect();
        assert_eq!(keys, vec![2, 1]);
    }

    #[test]
    fn to_sorted_array_breaks_ties_by_key() {
        let set = set_with(&[5, 1, 3]);
        let mut attr = LongAttribute::new("size", &set);
        for key in [5, 1, 3] {
            attr.set_value(&MockKeyedObject { key }, 7);
        }

        let sorted = attr.to_sorted_array();
        let keys: Vec<i64> = sorted.iter().map(|o| o.key()).collect();
        assert_eq!(keys, vec![1, 3, 5]);
    }

    #[test]
    fn sort_array_returns_a_new_sorted_vec_leaving_input_unchanged() {
        let set = set_with(&[1, 2]);
        let mut attr = LongAttribute::new("size", &set);
        attr.set_value(&MockKeyedObject { key: 1 }, 9);
        attr.set_value(&MockKeyedObject { key: 2 }, 1);

        let a = MockKeyedObject { key: 1 };
        let b = MockKeyedObject { key: 2 };
        let input: Vec<&dyn KeyedObject> = vec![&a, &b];
        let sorted = attr.sort_array(&input);

        assert_eq!(sorted[0].key(), 2);
        assert_eq!(sorted[1].key(), 1);
        assert_eq!(input[0].key(), 1);
        assert_eq!(input[1].key(), 2);
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let set = set_with(&[1]);
        let mut attr: Box<dyn Attribute<MockKeyedObject>> = Box::new(LongAttribute::new("size", &set));
        assert_eq!(attr.name(), "size");
        assert_eq!(attr.attribute_type(), "LONG_TYPE");
        attr.clear();
    }
}
