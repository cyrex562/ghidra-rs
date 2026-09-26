//! A unifying top-level interface for all `DemangledObject`s and `DemangledType`s.
//!
//! Port of `ghidra.app.util.demangler.Demangled`.

use crate::demangler::mangled_context::MangledContext;

/// A unifying top-level interface for all `DemangledObject`s and `DemangledType`s.
///
/// Port of `ghidra.app.util.demangler.Demangled`.
///
/// Genuinely polymorphic (many concrete implementations in the original), so this stays a
/// trait-object seam. `set_mangled_context`/`get_mangled_context` are Java `default` methods
/// (currently no-op / `null`), modeled here as default methods for the same reason. `set_name`/
/// `set_namespace` take `&mut self`, not `&self`, since every implementor mutates owned state to
/// satisfy them.
///
/// `Any` is grown in as a supertrait (automatically satisfied by every existing implementor,
/// since `impl<T: 'static> Any for T` is a blanket impl in `std`) for
/// [`SwiftDemangler::demangle`](crate::demangler::swift::swift_demangler::SwiftDemangler)'s port
/// of the `instanceof DemangledFunction`/`DemangledLabel`/`DemangledUnknown` dispatch in
/// `SwiftDemangler.demangle(MangledContext)`, which downcasts `dyn Demangled`/`Box<dyn Demangled>`
/// to concrete types via trait-object upcasting (`dyn Demangled` -> `dyn Any`) plus
/// `Any::downcast_ref`/`Any::downcast`.
pub trait Demangled: Send + Sync + std::any::Any {
    /// Sets the mangled context.
    ///
    /// Mirrors `Demangled.setMangledContext(MangledContext)`. Defaults to a no-op, mirroring the
    /// Java interface's current empty default implementation.
    fn set_mangled_context(&mut self, mangled_context: MangledContext) {
        let _ = mangled_context;
    }

    /// Returns the mangled context, if any.
    ///
    /// Mirrors `Demangled.getMangledContext()`. Defaults to `None`, mirroring the Java
    /// interface's current `null`-returning default implementation.
    fn get_mangled_context(&self) -> Option<MangledContext> {
        None
    }

    /// Returns the original mangled string.
    ///
    /// Mirrors `Demangled.getMangledString()`.
    fn get_mangled_string(&self) -> String;

    /// Returns the original demangled string returned by the demangling service.
    ///
    /// Mirrors `Demangled.getOriginalDemangled()`.
    fn get_original_demangled(&self) -> String;

    /// Returns the demangled name of this object. Unsupported symbol characters, like
    /// whitespace, are converted to an underscore.
    ///
    /// Mirrors `Demangled.getName()`.
    fn get_name(&self) -> String;

    /// Sets the name for this object.
    ///
    /// Mirrors `Demangled.setName(String)`.
    fn set_name(&mut self, name: &str);

    /// Returns the unmodified demangled name of this object. This name may contain whitespace
    /// and other characters not supported for symbol or data type creation.
    ///
    /// Mirrors `Demangled.getDemangledName()`.
    fn get_demangled_name(&self) -> String;

    /// Returns the namespace containing this demangled object.
    ///
    /// Mirrors `Demangled.getNamespace()`.
    fn get_namespace(&self) -> Option<&dyn Demangled>;

    /// Returns the namespace containing this demangled object, for mutation.
    ///
    /// Has no Java counterpart: the original walks a namespace chain with `getNamespace()` and
    /// then mutates the innermost link with `setNamespace(...)` (see
    /// `ghidra.app.util.demangler.swift.nodes.SwiftNode.join`), which Rust cannot do through the
    /// shared reference `get_namespace` hands back.
    fn get_namespace_mut(&mut self) -> Option<&mut (dyn Demangled + 'static)>;

    /// Sets the namespace of this demangled object.
    ///
    /// Mirrors `Demangled.setNamespace(Demangled)`.
    fn set_namespace(&mut self, namespace: Option<Box<dyn Demangled>>);

    /// Returns a representation of this object as a fully-qualified namespace. The value
    /// returned here may have had some special characters replaced, such as ' ' replaced with
    /// '_' and '::' replaced with '--'.
    ///
    /// Mirrors `Demangled.getNamespaceString()`.
    fn get_namespace_string(&self) -> String;

    /// Returns this object's namespace name without the fully-qualified parent path. The value
    /// returned here may have had some special characters replaced, such as ' ' replaced with
    /// '_' and '::' replaced with '--'.
    ///
    /// Mirrors `Demangled.getNamespaceName()`.
    fn get_namespace_name(&self) -> String;

    /// Generates a complete representation of this object to include all known attributes of
    /// this object.
    ///
    /// Mirrors `Demangled.getSignature()`.
    fn get_signature(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Simple {
        name: String,
        demangled_name: String,
        namespace: Option<Box<dyn Demangled>>,
    }

    impl Demangled for Simple {
        fn get_mangled_string(&self) -> String {
            "_Zfoo".to_string()
        }

        fn get_original_demangled(&self) -> String {
            self.demangled_name.clone()
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn set_name(&mut self, name: &str) {
            self.demangled_name = name.to_string();
            self.name = name.replace(' ', "_");
        }

        fn get_demangled_name(&self) -> String {
            self.demangled_name.clone()
        }

        fn get_namespace(&self) -> Option<&dyn Demangled> {
            self.namespace.as_deref()
        }

        fn get_namespace_mut(&mut self) -> Option<&mut (dyn Demangled + 'static)> {
            self.namespace.as_deref_mut()
        }

        fn set_namespace(&mut self, namespace: Option<Box<dyn Demangled>>) {
            self.namespace = namespace;
        }

        fn get_namespace_string(&self) -> String {
            match &self.namespace {
                Some(ns) => format!("{}::{}", ns.get_namespace_string(), self.demangled_name),
                None => self.demangled_name.clone(),
            }
        }

        fn get_namespace_name(&self) -> String {
            self.name.clone()
        }

        fn get_signature(&self) -> String {
            self.get_namespace_name()
        }
    }

    fn simple(name: &str) -> Simple {
        Simple { name: name.replace(' ', "_"), demangled_name: name.to_string(), namespace: None }
    }

    #[test]
    fn default_mangled_context_is_none_and_set_is_a_no_op() {
        let mut s = simple("foo bar");
        assert!(s.get_mangled_context().is_none());
        // Mirrors the Java interface's current no-op default implementation: calling this must
        // not panic and must not change the (still-None) mangled context.
        s.set_mangled_context(MangledContext::new(None, Default::default(), "_Zfoo".to_string(), None));
        assert!(s.get_mangled_context().is_none());
    }

    #[test]
    fn namespace_string_prepends_parent_with_delimiter() {
        let mut child = simple("Bar");
        let parent: Box<dyn Demangled> = Box::new(simple("Foo"));
        child.set_namespace(Some(parent));

        assert_eq!(child.get_namespace_string(), "Foo::Bar");
        assert_eq!(child.get_namespace_name(), "Bar");
        assert_eq!(child.get_signature(), "Bar");
    }

    #[test]
    fn name_converts_whitespace_to_underscore() {
        let s = simple("foo bar");
        assert_eq!(s.get_name(), "foo_bar");
        assert_eq!(s.get_demangled_name(), "foo bar");
    }
}
