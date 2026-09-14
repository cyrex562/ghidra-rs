//! Port of `ghidra.util.graph.attributes.StringAttribute`.

use std::cmp::Ordering;
use std::collections::HashMap;

use crate::util::graph::attributes::attribute::Attribute;
use crate::util::graph::attributes::attribute_manager::STRING_TYPE;
use crate::util::graph::key_indexable_set::KeyIndexableSet;
use crate::util::graph::keyed_object::KeyedObject;

/// Storage mechanism for `String`-valued information about the elements of a `KeyIndexableSet`,
/// e.g. the vertices of a `DirectedGraph`.
///
/// Port of `ghidra.util.graph.attributes.StringAttribute<T extends KeyedObject>` (deprecated since
/// Ghidra 10.2). Values are stored in a `HashMap<i64, String>` keyed by [`KeyedObject::key`],
/// mirroring the Java field (`private Map<Long, String> values`; the commented-out `String[]
/// values` shown in the Java source was never actually used).
///
/// Per this crate's composition-over-inheritance convention, and following the precedent already
/// set by the ported [`Attribute`] trait itself (see that trait's own doc comment on why it holds
/// no shared `base` struct), this struct stores the `name`/`owning_set`/`modification_number`/
/// `backing_set_modification_number` fields Java's abstract `Attribute` superclass would have held
/// directly, and implements [`Attribute<T>`] using them.
#[deprecated(note = "Deprecated since Ghidra 10.2")]
pub struct StringAttribute<'a, T: KeyedObject> {
    name: String,
    owning_set: &'a dyn KeyIndexableSet<T>,
    modification_number: i64,
    backing_set_modification_number: i64,
    values: HashMap<i64, String>,
}

#[allow(deprecated)]
impl<'a, T: KeyedObject> StringAttribute<'a, T> {
    /// Construct a new `StringAttribute`.
    ///
    /// Port of `StringAttribute(String name, KeyIndexableSet<T> set)`.
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
    /// Port of `setValue(T o, String value)`. Java's `String value` parameter is nullable, and the
    /// method's first line rejects a `null` value outright (`if (value == null) return false;`);
    /// mirrored here by taking `value: Option<String>`, where `None` stands in for Java `null`.
    ///
    /// * `o` - the `KeyedObject` that is assigned the value. Should be a member of the owning
    ///   set.
    /// * `value` - the value to associate with the specified `KeyedObject`, or `None` for Java's
    ///   `null` (always rejected).
    ///
    /// Returns `true` if the value could be set. Returns `false` if `value` is `None`, or if `o`
    /// is not a member of the owning set.
    pub fn set_value(&mut self, o: &T, value: Option<String>) -> bool {
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
    /// Java signature's deliberately loose typing. Java never throws here (no `NoValueException`)
    /// -- it simply returns `null` for an absent value, mirrored here as `None`.
    ///
    /// This is the value [`Attribute::get_value_as_string`]'s implementation for this type
    /// literally delegates to (`return getValue(o);` in Java) -- see that trait method's own docs
    /// on this type for the nullable-return quirk that delegation carries with it.
    pub fn get_value(&self, o: &dyn KeyedObject) -> Option<&String> {
        self.values.get(&o.key())
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

    /// Port of the nested `StringAttribute.StringComparator.compare(Object, Object)`.
    ///
    /// Keyed objects are first compared by the value of the attribute (`String::compareTo`,
    /// mirrored here as `str::cmp`). Ties are broken by comparing the keys of the `KeyedObject`s.
    /// A `KeyedObject` with no value set is treated as sorting *after* one that does have a
    /// value; if neither has a value, they are compared by key -- the same "no value sorts last"
    /// convention as [`DoubleAttribute`](crate::util::graph::attributes::DoubleAttribute)'s
    /// `DoubleComparator` and its other numeric siblings, though Java's `StringComparator` reaches
    /// it via plain `null` checks rather than a `NoValueException` try/catch (since
    /// [`get_value`](Self::get_value) never throws).
    fn compare(&self, ko1: &dyn KeyedObject, ko2: &dyn KeyedObject) -> Ordering {
        let value1 = self.get_value(ko1);
        let value2 = self.get_value(ko2);

        match (value1, value2) {
            (Some(v1), Some(v2)) => {
                let cmp = v1.cmp(v2);
                if cmp != Ordering::Equal {
                    cmp
                }
                else {
                    Self::compare_keys(ko1, ko2)
                }
            }
            // ko1 is ok, ko2 fails.
            (Some(_), None) => Ordering::Less,
            // ko2 is ok so it precedes ko1.
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Self::compare_keys(ko1, ko2),
        }
    }

    fn compare_keys(ko1: &dyn KeyedObject, ko2: &dyn KeyedObject) -> Ordering {
        if (ko1.key() - ko2.key()) < 0 {
            Ordering::Less
        }
        else if (ko1.key() - ko2.key()) > 0 {
            Ordering::Greater
        }
        else {
            Ordering::Equal
        }
    }
}

#[allow(deprecated)]
impl<'a, T: KeyedObject> Attribute<T> for StringAttribute<'a, T> {
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

    /// Port of `attributeType()`: returns `AttributeManager.STRING_TYPE`.
    fn attribute_type(&self) -> String {
        STRING_TYPE.to_string()
    }

    /// Port of `getValueAsString(KeyedObject o)`: `return getValue(o);`.
    ///
    /// # Java quirk preserved (adapted)
    ///
    /// Unlike every other sibling in this package (which all fall back to a non-null default --
    /// `"0"`, `"0.0"`, or `""` -- when no value is set), `StringAttribute.getValueAsString` is a
    /// bare, unconditional delegation to `getValue(o)`, which itself returns Java `null` for an
    /// unset value. So in real Java, `getValueAsString` on a `StringAttribute` with no value set
    /// for the given `KeyedObject` returns `null`, not a placeholder string.
    ///
    /// This crate's shared [`Attribute::get_value_as_string`] trait method signature (established
    /// by every already-ported sibling in this package) returns a non-nullable `String`, so this
    /// impl cannot return Rust's equivalent of `null` through it. [`get_value`](Self::get_value)
    /// (this method's real Java delegate) is the faithful, genuinely-nullable equivalent -- use it
    /// directly to observe the true Java behavior. This trait impl instead falls back to the empty
    /// string for the unset case, an adaptation forced by the non-nullable trait signature rather
    /// than a silent "fix" of the underlying quirk.
    fn get_value_as_string(&self, o: &dyn KeyedObject) -> String {
        self.get_value(o).cloned().unwrap_or_default()
    }

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
        let attr = StringAttribute::new("label", &set);
        assert_eq!(attr.name(), "label");
        assert_eq!(attr.attribute_type(), "STRING_TYPE");
    }

    #[test]
    fn set_value_then_get_value_round_trips_for_member_of_owning_set() {
        let set = set_with(&[1, 2]);
        let mut attr = StringAttribute::new("label", &set);
        let obj = MockKeyedObject { key: 1 };
        assert!(attr.set_value(&obj, Some("hello".to_string())));
        assert_eq!(attr.get_value(&obj), Some(&"hello".to_string()));
    }

    #[test]
    fn set_value_returns_false_and_does_not_store_for_non_member() {
        let set = set_with(&[1]);
        let mut attr = StringAttribute::new("label", &set);
        let stray = MockKeyedObject { key: 99 };
        assert!(!attr.set_value(&stray, Some("x".to_string())));
        assert!(attr.get_value(&stray).is_none());
    }

    #[test]
    fn set_value_none_is_rejected_like_javas_null() {
        let set = set_with(&[1]);
        let mut attr = StringAttribute::new("label", &set);
        let obj = MockKeyedObject { key: 1 };
        assert!(!attr.set_value(&obj, None));
        assert!(attr.get_value(&obj).is_none());
        assert_eq!(attr.get_modification_number(), 0);
    }

    #[test]
    fn get_value_for_unset_object_is_none_not_an_error() {
        let set = set_with(&[1]);
        let attr: StringAttribute<MockKeyedObject> = StringAttribute::new("label", &set);
        assert!(attr.get_value(&MockKeyedObject { key: 1 }).is_none());
    }

    /// Direct proof of the real, genuinely-nullable Java behavior: `getValue` (the exact delegate
    /// `getValueAsString` calls) returns nothing for an unset value.
    #[test]
    fn get_value_is_the_true_nullable_delegate_get_value_as_string_forwards_to() {
        let set = set_with(&[1]);
        let attr: StringAttribute<MockKeyedObject> = StringAttribute::new("label", &set);
        assert_eq!(attr.get_value(&MockKeyedObject { key: 1 }), None);
    }

    #[test]
    fn get_value_as_string_for_unset_object_falls_back_to_empty_string() {
        // See Attribute::get_value_as_string's docs on this type: real Java returns null here;
        // this trait impl adapts to an empty string since the shared trait signature can't
        // express null.
        let set = set_with(&[1]);
        let attr: StringAttribute<MockKeyedObject> = StringAttribute::new("label", &set);
        assert_eq!(attr.get_value_as_string(&MockKeyedObject { key: 1 }), "");
    }

    #[test]
    fn get_value_as_string_for_set_object_is_the_value_itself() {
        let set = set_with(&[1]);
        let mut attr = StringAttribute::new("label", &set);
        let obj = MockKeyedObject { key: 1 };
        attr.set_value(&obj, Some("hi there".to_string()));
        assert_eq!(attr.get_value_as_string(&obj), "hi there");
    }

    #[test]
    fn clear_removes_values_but_does_not_bump_modification_number() {
        let set = set_with(&[1]);
        let mut attr = StringAttribute::new("label", &set);
        let obj = MockKeyedObject { key: 1 };
        attr.set_value(&obj, Some("v".to_string()));
        assert_eq!(attr.get_modification_number(), 1);

        attr.clear();
        assert!(attr.get_value(&obj).is_none());
        assert_eq!(attr.get_modification_number(), 1);
    }

    #[test]
    fn to_sorted_array_orders_ascending_lexicographically() {
        let set = set_with(&[1, 2, 3]);
        let mut attr = StringAttribute::new("label", &set);
        attr.set_value(&MockKeyedObject { key: 1 }, Some("charlie".to_string()));
        attr.set_value(&MockKeyedObject { key: 2 }, Some("alpha".to_string()));
        attr.set_value(&MockKeyedObject { key: 3 }, Some("bravo".to_string()));

        let sorted = attr.to_sorted_array();
        let keys: Vec<i64> = sorted.iter().map(|o| o.key()).collect();
        assert_eq!(keys, vec![2, 3, 1]);
    }

    #[test]
    fn to_sorted_array_treats_unset_values_as_sorting_last() {
        let set = set_with(&[1, 2]);
        let mut attr = StringAttribute::new("label", &set);
        attr.set_value(&MockKeyedObject { key: 2 }, Some("zzz".to_string()));
        // key 1 is never given a value.

        let sorted = attr.to_sorted_array();
        let keys: Vec<i64> = sorted.iter().map(|o| o.key()).collect();
        assert_eq!(keys, vec![2, 1]);
    }

    #[test]
    fn to_sorted_array_breaks_ties_by_key() {
        let set = set_with(&[5, 1, 3]);
        let mut attr = StringAttribute::new("label", &set);
        for key in [5, 1, 3] {
            attr.set_value(&MockKeyedObject { key }, Some("same".to_string()));
        }

        let sorted = attr.to_sorted_array();
        let keys: Vec<i64> = sorted.iter().map(|o| o.key()).collect();
        assert_eq!(keys, vec![1, 3, 5]);
    }

    #[test]
    fn sort_array_returns_a_new_sorted_vec_leaving_input_unchanged() {
        let set = set_with(&[1, 2]);
        let mut attr = StringAttribute::new("label", &set);
        attr.set_value(&MockKeyedObject { key: 1 }, Some("zzz".to_string()));
        attr.set_value(&MockKeyedObject { key: 2 }, Some("aaa".to_string()));

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
        let mut attr: Box<dyn Attribute<MockKeyedObject>> = Box::new(StringAttribute::new("label", &set));
        assert_eq!(attr.name(), "label");
        assert_eq!(attr.attribute_type(), "STRING_TYPE");
        attr.clear();
    }
}
