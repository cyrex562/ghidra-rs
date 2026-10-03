//! Port of `ghidra.util.graph.attributes.ObjectAttribute`.

use std::collections::HashMap;

use crate::util::graph::attributes::attribute::Attribute;
use crate::util::graph::attributes::attribute_manager::OBJECT_TYPE;
use crate::util::graph::key_indexable_set::KeyIndexableSet;
use crate::util::graph::keyed_object::KeyedObject;

/// Storage mechanism for `Object`-valued information about the elements of a `KeyIndexableSet`,
/// e.g. the vertices of a `DirectedGraph`.
///
/// Port of `ghidra.util.graph.attributes.ObjectAttribute<T extends KeyedObject>` (deprecated since
/// Ghidra 10.2). Values are stored in a `HashMap<i64, V>` keyed by [`KeyedObject::key`], mirroring
/// the Java field (`private Map<Long, Object> values`; the commented-out `Object[] values` shown
/// in the Java source was never actually used).
///
/// Java's `Object` value type is modeled here as a type parameter `V` rather than, say, `Box<dyn
/// Any>`, since every concrete caller in practice stores a single consistent value type and this
/// keeps `get_value` usably typed; a `V: ToString` bound (standing in for every Java `Object`
/// implicitly supporting `.toString()`) is required only where
/// [`Attribute::get_value_as_string`] actually needs it.
///
/// Unlike [`DoubleAttribute`](crate::util::graph::attributes::DoubleAttribute) and its numeric
/// siblings, `ObjectAttribute` has no `toSortedArray`/comparator in the Java source -- there is no
/// natural ordering over arbitrary `Object` values -- so none is ported here either.
///
/// Per this crate's composition-over-inheritance convention, and following the precedent already
/// set by the ported [`Attribute`] trait itself (see that trait's own doc comment on why it holds
/// no shared `base` struct), this struct stores the `name`/`owning_set`/`modification_number`/
/// `backing_set_modification_number` fields Java's abstract `Attribute` superclass would have held
/// directly, and implements [`Attribute<T>`] using them.
#[deprecated(note = "Deprecated since Ghidra 10.2")]
pub struct ObjectAttribute<'a, T: KeyedObject, V> {
    name: String,
    owning_set: &'a dyn KeyIndexableSet<T>,
    modification_number: i64,
    backing_set_modification_number: i64,
    values: HashMap<i64, V>,
}

#[allow(deprecated)]
impl<'a, T: KeyedObject, V> ObjectAttribute<'a, T, V> {
    /// Construct a new `ObjectAttribute`.
    ///
    /// Port of `ObjectAttribute(String name, KeyIndexableSet<T> set)`.
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
            values: HashMap::new(),
        }
    }

    /// Set the value of this attribute for the specified `KeyedObject`.
    ///
    /// Port of `setValue(T o, Object value)`. Java's `Object value` parameter is nullable, and the
    /// method's first line rejects a `null` value outright (`if (value == null) return false;`);
    /// mirrored here by taking `value: Option<V>`, where `None` stands in for Java `null`.
    ///
    /// * `o` - the `KeyedObject` that is assigned the value. Should be a member of the owning
    ///   set.
    /// * `value` - the value to associate with the specified `KeyedObject`, or `None` for Java's
    ///   `null` (always rejected).
    ///
    /// Returns `true` if the value could be set. Returns `false` if `value` is `None`, or if `o`
    /// is not a member of the owning set.
    pub fn set_value(&mut self, o: &T, value: Option<V>) -> bool {
        let Some(value) = value
        else {
            return false;
        };
        if self.owning_set.contains(o) {
            self.values.insert(o.key(), value);
            self.update();
            true
        }
        else {
            false
        }
    }

    /// Return the value associated with the specified `KeyedObject`.
    ///
    /// Port of `getValue(KeyedObject o)`. Takes `&dyn KeyedObject` rather than `&T`, matching the
    /// Java signature's deliberately loose typing (it accepts any `KeyedObject`, not only ones
    /// from the owning set of type `T`). Java never throws here (no `NoValueException`,
    /// unlike [`IntegerAttribute`](crate::util::graph::attributes::IntegerAttribute)/
    /// [`LongAttribute`](crate::util::graph::attributes::LongAttribute)) -- it simply returns
    /// `null` for an absent value, mirrored here as `None`.
    pub fn get_value(&self, o: &dyn KeyedObject) -> Option<&V> {
        self.values.get(&o.key())
    }

    fn update(&mut self) {
        self.modification_number += 1;
    }
}

#[allow(deprecated)]
impl<'a, T: KeyedObject, V: ToString> Attribute<T> for ObjectAttribute<'a, T, V> {
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

    /// Port of `attributeType()`: returns `AttributeManager.OBJECT_TYPE`.
    fn attribute_type(&self) -> String {
        OBJECT_TYPE.to_string()
    }

    /// Port of `getValueAsString(KeyedObject o)`.
    ///
    /// Java's version guards with `values.containsKey(o.key())` before calling `getValue(o)`, and
    /// only returns `v.toString()` if that second lookup also came back non-`null`; otherwise it
    /// returns the empty string. Since [`set_value`](Self::set_value) never actually stores a
    /// `null`/`None` value (it is rejected up front, per that method's own docs), a present key
    /// always has a present value in practice, so this port collapses the double-guard into a
    /// single `HashMap::get` -- the same reachable behavior as the more literal Java transcription.
    fn get_value_as_string(&self, o: &dyn KeyedObject) -> String {
        match self.values.get(&o.key()) {
            Some(v) => v.to_string(),
            None => String::new(),
        }
    }

    /// Port of `clear()`: `values.clear();`.
    ///
    /// # Preserved quirk: does not bump the modification number
    /// Unlike [`set_value`](Self::set_value), Java's `clear()` does *not* call `update()` --
    /// clearing every value leaves [`Attribute::get_modification_number`] unchanged, reproduced
    /// as-is here rather than "fixed" to call [`update`](Attribute::update).
    fn clear(&mut self) {
        self.values.clear();
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
        let attr: ObjectAttribute<MockKeyedObject, String> = ObjectAttribute::new("tag", &set);
        assert_eq!(attr.name(), "tag");
        assert_eq!(attr.attribute_type(), "OBJECT_TYPE");
    }

    #[test]
    fn set_value_then_get_value_round_trips_for_member_of_owning_set() {
        let set = set_with(&[1, 2]);
        let mut attr = ObjectAttribute::new("tag", &set);
        let obj = MockKeyedObject { key: 1 };
        assert!(attr.set_value(&obj, Some("hello".to_string())));
        assert_eq!(attr.get_value(&obj), Some(&"hello".to_string()));
    }

    #[test]
    fn set_value_returns_false_and_does_not_store_for_non_member() {
        let set = set_with(&[1]);
        let mut attr = ObjectAttribute::new("tag", &set);
        let stray = MockKeyedObject { key: 99 };
        assert!(!attr.set_value(&stray, Some("x".to_string())));
        assert!(attr.get_value(&stray).is_none());
    }

    #[test]
    fn set_value_none_is_rejected_like_javas_null() {
        let set = set_with(&[1]);
        let mut attr: ObjectAttribute<MockKeyedObject, String> = ObjectAttribute::new("tag", &set);
        let obj = MockKeyedObject { key: 1 };
        assert!(!attr.set_value(&obj, None));
        assert!(attr.get_value(&obj).is_none());
        assert_eq!(attr.get_modification_number(), 0);
    }

    #[test]
    fn set_value_bumps_modification_number() {
        let set = set_with(&[1]);
        let mut attr = ObjectAttribute::new("tag", &set);
        assert_eq!(attr.get_modification_number(), 0);
        attr.set_value(&MockKeyedObject { key: 1 }, Some("v".to_string()));
        assert_eq!(attr.get_modification_number(), 1);
    }

    #[test]
    fn get_value_for_unset_object_is_none_not_an_error() {
        let set = set_with(&[1]);
        let attr: ObjectAttribute<MockKeyedObject, String> = ObjectAttribute::new("tag", &set);
        assert!(attr.get_value(&MockKeyedObject { key: 1 }).is_none());
    }

    #[test]
    fn get_value_as_string_for_unset_object_is_the_empty_string() {
        let set = set_with(&[1]);
        let attr: ObjectAttribute<MockKeyedObject, String> = ObjectAttribute::new("tag", &set);
        assert_eq!(attr.get_value_as_string(&MockKeyedObject { key: 1 }), "");
    }

    #[test]
    fn get_value_as_string_for_set_object_uses_to_string() {
        let set = set_with(&[1]);
        let mut attr = ObjectAttribute::new("tag", &set);
        let obj = MockKeyedObject { key: 1 };
        attr.set_value(&obj, Some(42i32));
        assert_eq!(attr.get_value_as_string(&obj), "42");
    }

    #[test]
    fn clear_removes_values_but_does_not_bump_modification_number() {
        let set = set_with(&[1]);
        let mut attr = ObjectAttribute::new("tag", &set);
        let obj = MockKeyedObject { key: 1 };
        attr.set_value(&obj, Some("v".to_string()));
        assert_eq!(attr.get_modification_number(), 1);

        attr.clear();
        assert!(attr.get_value(&obj).is_none());
        assert_eq!(attr.get_modification_number(), 1);
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let set = set_with(&[1]);
        let mut attr: Box<dyn Attribute<MockKeyedObject>> =
            Box::new(ObjectAttribute::<MockKeyedObject, String>::new("tag", &set));
        assert_eq!(attr.name(), "tag");
        assert_eq!(attr.attribute_type(), "OBJECT_TYPE");
        attr.clear();
    }
}
