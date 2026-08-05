//! The built-in schemas common to every context, ported as a trait because it was selected as a
//! cycle cut-point: in the original Java, `PrimitiveTraceObjectSchema` is an enum whose constants
//! (e.g. `ANY`, `OBJECT`, `VOID`) are handed to [`DefaultSchemaContext::new`] to seed a fresh
//! context, while `PrimitiveTraceObjectSchema.getContext()` returns a `DefaultSchemaContext`
//! singleton (`MinimalSchemaContext.INSTANCE`) -- a direct value-level cycle between the two
//! types.
//!
//! Java source: `ghidra.trace.model.target.schema.PrimitiveTraceObjectSchema`.
//!
//! [`DefaultSchemaContext`](crate::trace::model::target::schema::default_schema_context::DefaultSchemaContext)
//! is itself a trait (for the same reason), so `getContext()` here is a required trait method
//! rather than a hardwired reference to a concrete singleton -- that is precisely how the cycle
//! is cut. Likewise, `Class<?>` (used by `getType()`/`getTypes()`/`schemaForPrimitive(Class)`) has
//! no Rust reflection analog, so it is represented as a stable type-name string.
//!
//! `TraceObjectInterface` and `AttributeSchema` are not yet ported (see
//! [`seam_stubs::TraceObjectInterface`](crate::trace::seam_stubs::TraceObjectInterface) and
//! [`seam_stubs::AttributeSchema`](crate::trace::seam_stubs::AttributeSchema)), and the static
//! `PrimitiveTraceObjectSchema.values()` registry has no Rust equivalent without a concrete enum,
//! so [`schema_for_primitive`] and [`name_for_primitive`] take the candidate set as a parameter
//! rather than reaching for a static list.
use std::collections::HashMap;

use crate::debug::api::tracermi::SchemaName;
use crate::trace::model::target::path::key_path::{KeyPath, PathFilter};
use crate::trace::model::target::schema::schema_context::SchemaContext;
use crate::trace::seam_stubs::{AttributeSchema, TraceObjectInterface, TraceObjectSchema};

/// A built-in schema describing a primitive or built-in type (as opposed to a user-defined
/// object schema).
///
/// Mirrors `ghidra.trace.model.target.schema.PrimitiveTraceObjectSchema`.
pub trait PrimitiveTraceObjectSchema: TraceObjectSchema {
    /// The context this primitive is a member of.
    ///
    /// Mirrors `getContext()`, which in Java always returns the same
    /// `MinimalSchemaContext.INSTANCE`. That singleton would require a concrete
    /// `DefaultSchemaContext` implementation to construct, so it is left to the implementer here.
    fn get_context(&self) -> Box<dyn SchemaContext>;

    /// The Java classes (boxed and/or primitive) this schema accepts, in preference order.
    ///
    /// Mirrors `getTypes()`. `Class<?>` has no Rust reflection analog, so each class is
    /// represented by a stable name (e.g. `"java.lang.Boolean"`, `"boolean"`).
    fn get_types(&self) -> Vec<&'static str>;

    /// The Java class that best represents this type, i.e. the first of [`Self::get_types`].
    ///
    /// Mirrors `getType()`.
    fn get_type(&self) -> &'static str {
        self.get_types()
            .into_iter()
            .next()
            .expect("a primitive schema always names at least one type")
    }

    /// Whether a value satisfying `that` also satisfies this schema.
    ///
    /// Mirrors `isAssignableFrom(TraceObjectSchema)`. `ANY` and `OBJECT` override this to always
    /// return `true`; every other primitive keeps the default of `false`, since primitives (other
    /// than those two) are not assignable from an arbitrary schema.
    fn is_assignable_from(&self, _that: &dyn TraceObjectSchema) -> bool {
        false
    }

    /// The minimum interfaces supported by a conforming object.
    ///
    /// Mirrors `getInterfaces()`, which every primitive returns as an empty set.
    fn get_interfaces(&self) -> Vec<Box<dyn TraceObjectInterface>> {
        Vec::new()
    }

    /// Whether this is the canonical container for its elements.
    ///
    /// Mirrors `isCanonicalContainer()`, which every primitive returns as `false`.
    fn is_canonical_container(&self) -> bool {
        false
    }

    /// The map of element indices to named schemas.
    ///
    /// Mirrors `getElementSchemas()`, which every primitive returns as empty (primitives cannot
    /// have successors).
    fn get_element_schemas(&self) -> HashMap<String, SchemaName> {
        HashMap::new()
    }

    /// The default schema for elements.
    ///
    /// Mirrors `getDefaultElementSchema()`. `ANY` and `OBJECT` override this to `OBJECT`'s name;
    /// every other primitive keeps the default of `VOID`'s name, since primitives cannot have
    /// successors.
    fn get_default_element_schema(&self) -> SchemaName {
        SchemaName::new("VOID")
    }

    /// The map of attribute names to named schemas.
    ///
    /// Mirrors `getAttributeSchemas()`, which every primitive returns as empty.
    fn get_attribute_schemas(&self) -> HashMap<String, Box<dyn AttributeSchema>> {
        HashMap::new()
    }

    /// The map of attribute name aliases.
    ///
    /// Mirrors `getAttributeAliases()`, which every primitive returns as empty.
    fn get_attribute_aliases(&self) -> HashMap<String, String> {
        HashMap::new()
    }

    /// The default schema for attributes.
    ///
    /// Mirrors `getDefaultAttributeSchema()`. `ANY` and `OBJECT` override this to
    /// `AttributeSchema.DEFAULT_ANY`; every other primitive keeps the default of
    /// `AttributeSchema.DEFAULT_VOID`, forbidding additional attributes.
    fn get_default_attribute_schema(&self) -> Box<dyn AttributeSchema> {
        Box::new(DefaultVoidAttributeSchema)
    }

    /// Searches for a path filter matching successors satisfying `type`.
    ///
    /// Mirrors `searchFor(Class, boolean)`, which every primitive returns as `PathFilter.NONE`
    /// (primitives have no successors to search). Represented as `None` since no concrete
    /// "matches nothing" [`PathFilter`] is exported yet.
    fn search_for(&self, _type: &str, _require_canonical: bool) -> Option<Box<dyn PathFilter>> {
        None
    }

    /// Searches for the canonical container of `type` among this schema's successors.
    ///
    /// Mirrors `searchForCanonicalContainer(Class)`, which every primitive returns as `null`.
    fn search_for_canonical_container(&self, _type: &str) -> Option<KeyPath> {
        None
    }

    /// Searches for a suitable successor satisfying `type`, relative to `path`.
    ///
    /// Mirrors `searchForSuitable(Class, KeyPath)`, which every primitive returns as `null`.
    fn search_for_suitable(&self, _type: &str, _path: &KeyPath) -> Option<KeyPath> {
        None
    }
}

/// Marker [`AttributeSchema`] backing [`PrimitiveTraceObjectSchema::get_default_attribute_schema`]'s
/// default. Mirrors `AttributeSchema.DEFAULT_VOID`.
struct DefaultVoidAttributeSchema;
impl AttributeSchema for DefaultVoidAttributeSchema {}

/// Marker [`AttributeSchema`] for use by `ANY`/`OBJECT`-like overrides of
/// [`PrimitiveTraceObjectSchema::get_default_attribute_schema`]. Mirrors
/// `AttributeSchema.DEFAULT_ANY`.
pub struct DefaultAnyAttributeSchema;
impl AttributeSchema for DefaultAnyAttributeSchema {}

/// Finds the primitive among `candidates` whose [`PrimitiveTraceObjectSchema::get_types`]
/// contains `type_name`.
///
/// Mirrors the static `schemaForPrimitive(Class<?>)`, which searches `values()`; here the
/// candidate set is passed in explicitly since there is no static registry.
pub fn schema_for_primitive<'a>(
    candidates: &'a [Box<dyn PrimitiveTraceObjectSchema>],
    type_name: &str,
) -> Option<&'a dyn PrimitiveTraceObjectSchema> {
    candidates
        .iter()
        .find(|schema| schema.get_types().contains(&type_name))
        .map(|schema| schema.as_ref())
}

/// Finds the name of the primitive among `candidates` whose [`PrimitiveTraceObjectSchema::get_types`]
/// contains `type_name`.
///
/// Mirrors the static `nameForPrimitive(Class<?>)`.
pub fn name_for_primitive(
    candidates: &[Box<dyn PrimitiveTraceObjectSchema>],
    type_name: &str,
) -> Option<SchemaName> {
    schema_for_primitive(candidates, type_name).map(|schema| schema.get_name())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockContext;

    impl SchemaContext for MockContext {
        fn get_schema(&self, _name: &SchemaName) -> Box<dyn TraceObjectSchema> {
            Box::new(MockAny)
        }

        fn get_schema_or_null(&self, _name: &SchemaName) -> Option<Box<dyn TraceObjectSchema>> {
            None
        }

        fn get_all_schemas(&self) -> Vec<Box<dyn TraceObjectSchema>> {
            Vec::new()
        }
    }

    struct MockAny;

    impl TraceObjectSchema for MockAny {
        fn get_name(&self) -> SchemaName {
            SchemaName::new("ANY")
        }

        fn to_string(&self) -> String {
            "ANY".to_string()
        }
    }

    impl PrimitiveTraceObjectSchema for MockAny {
        fn get_context(&self) -> Box<dyn SchemaContext> {
            Box::new(MockContext)
        }

        fn get_types(&self) -> Vec<&'static str> {
            vec!["java.lang.Object"]
        }

        fn is_assignable_from(&self, _that: &dyn TraceObjectSchema) -> bool {
            true
        }

        fn get_default_element_schema(&self) -> SchemaName {
            SchemaName::new("OBJECT")
        }

        fn get_default_attribute_schema(&self) -> Box<dyn AttributeSchema> {
            Box::new(DefaultAnyAttributeSchema)
        }
    }

    struct MockVoid;

    impl TraceObjectSchema for MockVoid {
        fn get_name(&self) -> SchemaName {
            SchemaName::new("VOID")
        }

        fn to_string(&self) -> String {
            "VOID".to_string()
        }
    }

    impl PrimitiveTraceObjectSchema for MockVoid {
        fn get_context(&self) -> Box<dyn SchemaContext> {
            Box::new(MockContext)
        }

        fn get_types(&self) -> Vec<&'static str> {
            vec!["java.lang.Void", "void"]
        }
    }

    fn as_dyn(p: &MockAny) -> &dyn PrimitiveTraceObjectSchema {
        p
    }

    #[test]
    fn is_object_safe() {
        let any = MockAny;
        let _dyn_ref = as_dyn(&any);
    }

    #[test]
    fn any_overrides_defaults() {
        let any = MockAny;
        assert!(any.is_assignable_from(&MockVoid));
        assert_eq!(any.get_default_element_schema(), SchemaName::new("OBJECT"));
        assert_eq!(any.get_type(), "java.lang.Object");
    }

    #[test]
    fn void_keeps_common_defaults() {
        let void = MockVoid;
        assert!(!void.is_assignable_from(&MockAny));
        assert_eq!(void.get_default_element_schema(), SchemaName::new("VOID"));
        assert!(!void.is_canonical_container());
        assert!(void.get_element_schemas().is_empty());
        assert!(void.search_for("Process", false).is_none());
        assert!(void.search_for_canonical_container("Process").is_none());
        assert!(void.search_for_suitable("Process", &KeyPath::root()).is_none());
    }

    #[test]
    fn schema_for_primitive_finds_by_type_name() {
        let candidates: Vec<Box<dyn PrimitiveTraceObjectSchema>> =
            vec![Box::new(MockAny), Box::new(MockVoid)];
        let found = schema_for_primitive(&candidates, "void").expect("void is registered");
        assert_eq!(found.get_name(), SchemaName::new("VOID"));
        assert!(schema_for_primitive(&candidates, "java.lang.String").is_none());
    }

    #[test]
    fn name_for_primitive_finds_by_type_name() {
        let candidates: Vec<Box<dyn PrimitiveTraceObjectSchema>> =
            vec![Box::new(MockAny), Box::new(MockVoid)];
        assert_eq!(
            name_for_primitive(&candidates, "java.lang.Object"),
            Some(SchemaName::new("ANY"))
        );
        assert_eq!(name_for_primitive(&candidates, "nope"), None);
    }
}
