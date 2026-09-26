//! Port of `ghidra.util.graph.attributes.Attribute`.

use crate::util::graph::key_indexable_set::KeyIndexableSet;
use crate::util::graph::keyed_object::KeyedObject;

/// Base trait for attributes -- int, double, or String values -- which can be assigned to the
/// members of a [`KeyIndexableSet`], e.g. the vertices or edges of a `DirectedGraph`.
///
/// Port of `ghidra.util.graph.attributes.Attribute` (deprecated since Ghidra 10.2), cut to a trait
/// following the same "abstract class -> trait" convention already used throughout this package
/// (see e.g. [`crate::util::graph::Vertex`], [`crate::util::graph::Edge`],
/// [`crate::util::graph::AbstractDependencyGraph`]) rather than the "concrete struct holding a
/// `base` field" composition pattern: like those siblings, `Attribute`'s constructor captures a
/// reference to its owning set (here `KeyIndexableSet<T>`, itself a trait/dependency-cycle
/// cut-point), which a shared field-holding base struct cannot express without also picking a
/// concrete lifetime/ownership strategy for that borrow. Implementers instead supply the
/// `name`/`owning_set`/`modification_number`/`backing_set_modification_number` accessors directly
/// (however their concrete backend prefers to store that state), matching how `Vertex`/`Edge`
/// leave their `key` assignment to implementers.
///
/// The attributes do not track changes in the owning set, but
/// [`owning_set_is_unmodified`](Attribute::owning_set_is_unmodified) can check if the owning set
/// has been modified since creation time. It is possible to create an attribute on the vertex set
/// and then remove the vertex from the graph; the concrete int/long/double/String/object attribute
/// subclasses (not yet ported) are expected to raise `NoValueException` when asked for the value
/// of a `KeyedObject` no longer present in the owning set, matching Java's documented behavior.
#[deprecated(note = "Deprecated since Ghidra 10.2")]
pub trait Attribute<T: KeyedObject> {
    /// Returns the name of this Attribute.
    ///
    /// Java: `name()`.
    fn name(&self) -> &str;

    /// Returns the `KeyIndexableSet`, typically a `VertexSet` or `EdgeSet`, that this attribute is
    /// defined for. An attribute value can only be set for a `KeyedObject` if it is a member of
    /// the owning set.
    ///
    /// Java: `owningSet()`.
    fn owning_set(&self) -> &dyn KeyIndexableSet<T>;

    /// Returns the current value of the modification number, which counts the number of changes
    /// this Attribute has undergone.
    ///
    /// Java: `getModificationNumber()`.
    fn get_modification_number(&self) -> i64;

    /// Increases the modification number.
    ///
    /// Java: package-private `update()`. Left `pub` since Rust has no package-private visibility
    /// tier narrower than the crate (matching the convention already used elsewhere in this
    /// port, e.g. [`crate::app::plugin::processors::generic::ConstructorInfo::get_flow_type`]).
    fn update(&mut self);

    /// The owning set's modification number as recorded when this attribute was constructed.
    /// Used by the default [`owning_set_is_unmodified`](Attribute::owning_set_is_unmodified).
    ///
    /// Stands in for the Java constructor's `this.backingSetModificationNumber =
    /// set.getModificationNumber();` field capture, exposed as an accessor since a trait has no
    /// fields of its own.
    fn backing_set_modification_number(&self) -> i64;

    /// Returns true iff the set attributes are defined for has not changed since the set was
    /// created.
    ///
    /// Java: package-private `owningSetIsUnmodified()`. Left `pub` for the same reason as
    /// [`update`](Attribute::update).
    fn owning_set_is_unmodified(&self) -> bool {
        self.backing_set_modification_number() == self.owning_set().modification_number()
    }

    /// Returns the type of Attribute, i.e. what kind of values does this attribute hold. "Long",
    /// "Object", "Double" are examples.
    ///
    /// Java: `abstract attributeType()`.
    fn attribute_type(&self) -> String;

    /// Returns the attribute of the specified `KeyedObject` as a String.
    ///
    /// Java: `abstract getValueAsString(KeyedObject o)`. Takes `&dyn KeyedObject` rather than
    /// `&T`, matching the Java signature's deliberately loose typing (it accepts any
    /// `KeyedObject`, not only ones from the owning set of type `T`).
    fn get_value_as_string(&self, o: &dyn KeyedObject) -> String;

    /// Undefine all values set for this attribute.
    ///
    /// Java: `abstract clear()`.
    fn clear(&mut self);
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::util::seam_stubs::GraphIteratorLike;
    use std::collections::HashMap;

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

    /// A minimal "string attribute" implementation, exercising the trait's default
    /// [`Attribute::owning_set_is_unmodified`] plus its own `attribute_type`/`get_value_as_string`/
    /// `clear` abstract methods.
    struct StringAttribute<'a> {
        name: String,
        owning_set: &'a MockSet,
        modification_number: i64,
        backing_set_modification_number: i64,
        values: HashMap<i64, String>,
    }

    impl<'a> StringAttribute<'a> {
        fn new(name: &str, set: &'a MockSet) -> Self {
            StringAttribute {
                name: name.to_string(),
                owning_set: set,
                modification_number: 0,
                backing_set_modification_number: set.modification_number(),
                values: HashMap::new(),
            }
        }

        fn set_value(&mut self, obj: &MockKeyedObject, value: &str) {
            self.values.insert(obj.key(), value.to_string());
            self.update();
        }
    }

    impl<'a> Attribute<MockKeyedObject> for StringAttribute<'a> {
        fn name(&self) -> &str {
            &self.name
        }
        fn owning_set(&self) -> &dyn KeyIndexableSet<MockKeyedObject> {
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
        fn attribute_type(&self) -> String {
            "String".to_string()
        }
        fn get_value_as_string(&self, o: &dyn KeyedObject) -> String {
            self.values.get(&o.key()).cloned().unwrap_or_default()
        }
        fn clear(&mut self) {
            self.values.clear();
            self.update();
        }
    }

    #[test]
    fn name_and_type_report_constructed_values() {
        let set = MockSet { objects: Vec::new(), modification_number: 0 };
        let attr = StringAttribute::new("label", &set);
        assert_eq!(attr.name(), "label");
        assert_eq!(attr.attribute_type(), "String");
    }

    #[test]
    fn modification_number_increases_on_update() {
        let set = MockSet { objects: Vec::new(), modification_number: 0 };
        let mut attr = StringAttribute::new("label", &set);
        assert_eq!(attr.get_modification_number(), 0);
        let obj = MockKeyedObject { key: 1 };
        attr.set_value(&obj, "hello");
        assert_eq!(attr.get_modification_number(), 1);
        assert_eq!(attr.get_value_as_string(&obj), "hello");
    }

    #[test]
    fn owning_set_is_unmodified_tracks_the_backing_sets_modification_number() {
        let mut set = MockSet { objects: Vec::new(), modification_number: 0 };
        set.add(MockKeyedObject { key: 1 });
        // Construct the attribute *after* the set already has one change, capturing that as the
        // baseline modification number -- mirrors the Java constructor's
        // `set.getModificationNumber()` capture.
        let attr = StringAttribute::new("label", &set);
        assert!(attr.owning_set_is_unmodified());
    }

    #[test]
    fn owning_set_is_unmodified_becomes_false_after_a_later_change() {
        let mut set = MockSet { objects: Vec::new(), modification_number: 0 };
        let attr_baseline = set.modification_number();
        set.add(MockKeyedObject { key: 1 });
        // Simulate constructing before the mutation by comparing directly against the captured
        // baseline via a fresh attribute over the now-mutated set: the owning set's *current*
        // modification number has moved past the (earlier) baseline.
        let attr = StringAttribute {
            name: "label".to_string(),
            owning_set: &set,
            modification_number: 0,
            backing_set_modification_number: attr_baseline,
            values: HashMap::new(),
        };
        assert!(!attr.owning_set_is_unmodified());
    }

    #[test]
    fn clear_empties_values_and_bumps_modification_number() {
        let set = MockSet { objects: Vec::new(), modification_number: 0 };
        let mut attr = StringAttribute::new("label", &set);
        let obj = MockKeyedObject { key: 1 };
        attr.set_value(&obj, "hello");
        attr.clear();
        assert_eq!(attr.get_value_as_string(&obj), "");
        assert_eq!(attr.get_modification_number(), 2);
    }

    #[test]
    fn get_value_as_string_accepts_any_keyed_object_not_just_owning_sets_type() {
        let set = MockSet { objects: Vec::new(), modification_number: 0 };
        let attr = StringAttribute::new("label", &set);
        // A KeyedObject that was never added to the owning set at all -- matching Java's loosely
        // typed `getValueAsString(KeyedObject o)`, which accepts any KeyedObject.
        let stray = MockKeyedObject { key: 999 };
        assert_eq!(attr.get_value_as_string(&stray), "");
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let set = MockSet { objects: Vec::new(), modification_number: 0 };
        let attr: Box<dyn Attribute<MockKeyedObject>> = Box::new(StringAttribute::new("label", &set));
        assert_eq!(attr.name(), "label");
        assert!(attr.owning_set_is_unmodified());
    }
}
