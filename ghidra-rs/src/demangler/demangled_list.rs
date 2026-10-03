//! Port of `ghidra.app.util.demangler.DemangledList`.
//!
//! A convenience [`Demangled`] object that holds a list of other [`Demangled`] objects.

use std::ops::{Deref, DerefMut};

use crate::demangler::demangled::Demangled;
use crate::demangler::mangled_context::MangledContext;

/// A convenience [`Demangled`] object that holds a list of other [`Demangled`] objects.
///
/// Port of `ghidra.app.util.demangler.DemangledList`. Java `extends ArrayList<Demangled>
/// implements Demangled`; this port follows the crate's composition-over-inheritance convention
/// (see e.g. [`crate::app::plugin::match::function_match_set::FunctionMatchSet`], another
/// `extends ArrayList<...>` port) by composing a `Vec` and exposing its slice API via
/// [`Deref`]/[`DerefMut`] instead of faking struct inheritance from `ArrayList`.
///
/// Elements are `Option<Box<dyn Demangled>>` rather than `Box<dyn Demangled>`: Java's
/// `List<Demangled>` can hold `null` elements (that is exactly what
/// [`DemangledList::contains_null`] checks for), and a non-nullable `Box` could never model that.
///
/// Every [`Demangled`] method on `DemangledList` itself (as opposed to on its elements) is a
/// faithful port of the Java overrides, which all return `null`/no-op: this "list" object carries
/// no name, namespace, or mangled/demangled strings of its own. `String`-returning methods here
/// flatten that `null` to the empty string, mirroring this crate's established convention (see
/// `DemangledObjectBase`'s module docs) for turning a nullable Java string into an infallible Rust
/// one at the [`Demangled`] trait boundary.
#[derive(Default)]
pub struct DemangledList {
    items: Vec<Option<Box<dyn Demangled>>>,
}

impl DemangledList {
    /// Creates a [`DemangledList`] and adds the given list of [`Demangled`] objects to it.
    ///
    /// Mirrors `DemangledList(List<Demangled> demangledList)`, which copies (rather than shares)
    /// the given list via `ArrayList`'s copy constructor.
    pub fn new(demangled_list: Vec<Option<Box<dyn Demangled>>>) -> Self {
        Self { items: demangled_list }
    }

    /// Returns `true` if this contains any `null` elements; otherwise, `false`.
    ///
    /// Mirrors `containsNull()`.
    pub fn contains_null(&self) -> bool {
        self.items.iter().any(|e| e.is_none())
    }
}

impl Deref for DemangledList {
    type Target = Vec<Option<Box<dyn Demangled>>>;

    fn deref(&self) -> &Self::Target {
        &self.items
    }
}

impl DerefMut for DemangledList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.items
    }
}

impl Demangled for DemangledList {
    // `set_mangled_context`/`get_mangled_context` are not overridden here: Java's
    // `DemangledList` does not override those `Demangled` interface default methods either, so
    // this simply omits them and inherits the trait's own no-op/`None` defaults.

    fn get_mangled_string(&self) -> String {
        // Mirrors `getMangledString()` returning `null`.
        String::new()
    }

    fn get_original_demangled(&self) -> String {
        // Mirrors `getOriginalDemangled()` returning `null`.
        String::new()
    }

    fn get_name(&self) -> String {
        // Mirrors `getName()` returning `null`.
        String::new()
    }

    fn set_name(&mut self, name: &str) {
        // Mirrors `setName(String)`, whose body is `// Nothing to do`.
        let _ = name;
    }

    fn get_demangled_name(&self) -> String {
        // Mirrors `getDemangledName()` returning `null`.
        String::new()
    }

    fn get_namespace(&self) -> Option<&dyn Demangled> {
        // Mirrors `getNamespace()` returning `null`.
        None
    }

    fn get_namespace_mut(&mut self) -> Option<&mut (dyn Demangled + 'static)> {
        // No Java counterpart (see `Demangled::get_namespace_mut`'s docs); there is no namespace
        // to mutate here either.
        None
    }

    fn set_namespace(&mut self, namespace: Option<Box<dyn Demangled>>) {
        // Mirrors `setNamespace(Demangled)`, whose body is `// Nothing to do`.
        let _ = namespace;
    }

    fn get_namespace_string(&self) -> String {
        // Mirrors `getNamespaceString()` returning `null`.
        String::new()
    }

    fn get_namespace_name(&self) -> String {
        // Mirrors `getNamespaceName()` returning `null`.
        String::new()
    }

    fn get_signature(&self) -> String {
        // Mirrors `getSignature()` returning `null`.
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demangler::demangled_type::DemangledType;

    /// A minimal `Demangled` implementor for exercising list elements, mirroring
    /// `DemangledType`'s shape without pulling in its full behaviour.
    fn named(name: &str) -> Box<dyn Demangled> {
        Box::new(DemangledType::new("m", "o", name))
    }

    #[test]
    fn new_copies_the_given_list() {
        let list = DemangledList::new(vec![Some(named("Foo")), Some(named("Bar"))]);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].as_ref().unwrap().get_name(), "Foo");
        assert_eq!(list[1].as_ref().unwrap().get_name(), "Bar");
    }

    #[test]
    fn contains_null_is_false_for_an_all_present_list() {
        let list = DemangledList::new(vec![Some(named("Foo")), Some(named("Bar"))]);
        assert!(!list.contains_null());
    }

    #[test]
    fn contains_null_is_true_when_any_element_is_null() {
        // Java: `List<Demangled>` may legally hold `null` elements; `containsNull()` exists
        // specifically to detect that.
        let list = DemangledList::new(vec![Some(named("Foo")), None, Some(named("Bar"))]);
        assert!(list.contains_null());
    }

    #[test]
    fn empty_list_does_not_contain_null() {
        let list = DemangledList::new(Vec::new());
        assert!(!list.contains_null());
        assert!(list.is_empty());
    }

    #[test]
    fn deref_exposes_vec_style_mutation() {
        // `DemangledList` behaves like a `Vec` via `Deref`/`DerefMut`, mirroring `extends
        // ArrayList<Demangled>`: ordinary list operations (push/pop/indexing) work directly.
        let mut list = DemangledList::default();
        list.push(Some(named("Foo")));
        list.push(None);
        assert_eq!(list.len(), 2);
        assert!(list.contains_null());

        let popped = list.pop().unwrap();
        assert!(popped.is_none());
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn demangled_methods_all_report_the_javas_null_or_no_op_behaviour() {
        // Every `Demangled` override on `DemangledList` itself returns `null`/no-ops in Java,
        // since the list carries no name/namespace/mangled state of its own.
        let mut list = DemangledList::new(vec![Some(named("Foo"))]);

        assert_eq!(list.get_mangled_string(), "");
        assert_eq!(list.get_original_demangled(), "");
        assert_eq!(list.get_name(), "");
        assert_eq!(list.get_demangled_name(), "");
        assert!(list.get_namespace().is_none());
        assert!(list.get_namespace_mut().is_none());
        assert_eq!(list.get_namespace_string(), "");
        assert_eq!(list.get_namespace_name(), "");
        assert_eq!(list.get_signature(), "");

        // set_name/set_namespace are no-ops: calling them must not panic, and must not change
        // this object's own (still-empty) name/namespace, nor touch the list's elements.
        list.set_name("ignored");
        list.set_namespace(Some(named("AlsoIgnored")));
        assert_eq!(list.get_name(), "");
        assert!(list.get_namespace().is_none());
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].as_ref().unwrap().get_name(), "Foo");
    }

    #[test]
    fn default_mangled_context_is_none_and_set_is_a_no_op() {
        // `setMangledContext`/`getMangledContext` are `Demangled` interface default methods that
        // `DemangledList` does not override in Java, so the trait's own defaults apply here too.
        let mut list = DemangledList::default();
        assert!(list.get_mangled_context().is_none());
        list.set_mangled_context(MangledContext::new(
            None,
            Default::default(),
            "_Zfoo".to_string(),
            None,
        ));
        assert!(list.get_mangled_context().is_none());
    }
}
