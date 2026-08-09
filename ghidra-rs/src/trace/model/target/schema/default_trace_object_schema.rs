//! The general-purpose [`TraceObjectSchema`] implementation, ported as a trait because it was
//! selected as a cycle cut-point: in the original Java, every `DefaultTraceObjectSchema` is
//! built by a `SchemaBuilder` obtained from (and tied back to) a `SchemaContext`, while
//! `DefaultTraceObjectSchema.getContext()` returns that very context -- a value-level cycle
//! between schema and context, the same shape that made
//! [`PrimitiveTraceObjectSchema`](crate::trace::model::target::schema::primitive_trace_object_schema::PrimitiveTraceObjectSchema)
//! and
//! [`DefaultSchemaContext`](crate::trace::model::target::schema::default_schema_context::DefaultSchemaContext)
//! traits rather than concrete types.
//!
//! Java source: `ghidra.trace.model.target.schema.DefaultTraceObjectSchema`.
//!
//! As with `PrimitiveTraceObjectSchema`, `Class<?>` (used by `getType()`) has no Rust reflection
//! analog, so it is represented as a stable type-name string. `TraceObjectInterface` and
//! `AttributeSchema` are not yet ported beyond the marker stubs in
//! [`seam_stubs`](crate::trace::seam_stubs) -- `DefaultTraceObjectSchema` (like
//! `PrimitiveTraceObjectSchema`) only ever hands these back opaquely, never inspecting them, so
//! the markers suffice here too.
//!
//! The Java class also declares a nested `DefaultAttributeSchema` (a concrete
//! [`AttributeSchema`](crate::trace::seam_stubs::AttributeSchema) implementation) and a
//! package-private `AliasResolver` helper. Neither is part of the public schema API this
//! cut-point exists to break, so they are left unported; `AttributeSchema` stays an opaque marker
//! until a caller needs to inspect one, at which point that nested class is the natural port
//! target. Likewise, `equals`/`hashCode` are omitted: Java's `equals` performs structural
//! comparison of the interfaces set, element/attribute schema maps, and default attribute schema,
//! none of which is possible through the current opaque `TraceObjectInterface`/`AttributeSchema`
//! markers.
use std::collections::HashMap;

use crate::debug::api::tracermi::SchemaName;
use crate::trace::model::target::schema::schema_context::SchemaContext;
use crate::trace::model::target::iface::TraceObjectInterface;
use crate::trace::seam_stubs::{AttributeSchema, TraceObjectSchema};

/// The "type descriptor" of a trace object.
///
/// Mirrors `ghidra.trace.model.target.schema.DefaultTraceObjectSchema`.
pub trait DefaultTraceObjectSchema: TraceObjectSchema {
    /// The context this schema is a member of. All schema names referenced by this schema are
    /// resolved in this same context.
    ///
    /// Mirrors `getContext()`.
    fn get_context(&self) -> Box<dyn SchemaContext>;

    /// The Java class that best represents this type: either a primitive, or `TraceObject`.
    ///
    /// Mirrors `getType()`. `Class<?>` has no Rust reflection analog, so it is represented by a
    /// stable name (e.g. `"ghidra.trace.model.target.TraceObject"`).
    fn get_type(&self) -> &'static str;

    /// The minimum interfaces supported by a conforming object.
    ///
    /// Mirrors `getInterfaces()`.
    fn get_interfaces(&self) -> Vec<Box<dyn TraceObjectInterface>>;

    /// Whether this object is the canonical container for its elements.
    ///
    /// Mirrors `isCanonicalContainer()`.
    fn is_canonical_container(&self) -> bool;

    /// The map of element indices to named schemas.
    ///
    /// Mirrors `getElementSchemas()`.
    fn get_element_schemas(&self) -> HashMap<String, SchemaName>;

    /// The default schema for elements not covered by [`Self::get_element_schemas`].
    ///
    /// Mirrors `getDefaultElementSchema()`.
    fn get_default_element_schema(&self) -> SchemaName;

    /// The map of attribute names to named schemas, with aliases already resolved to their
    /// target's schema.
    ///
    /// Mirrors `getAttributeSchemas()`.
    fn get_attribute_schemas(&self) -> HashMap<String, Box<dyn AttributeSchema>>;

    /// The map of attribute name aliases to the (possibly transitively resolved) name they refer
    /// to.
    ///
    /// Mirrors `getAttributeAliases()`.
    fn get_attribute_aliases(&self) -> HashMap<String, String>;

    /// The default schema for attributes not covered by [`Self::get_attribute_schemas`].
    ///
    /// Mirrors `getDefaultAttributeSchema()`.
    fn get_default_attribute_schema(&self) -> Box<dyn AttributeSchema>;

    /// Compares two schemas by name, matching `Comparable<DefaultTraceObjectSchema>`.
    ///
    /// Mirrors `compareTo(DefaultTraceObjectSchema)`, which delegates to `SchemaName`'s natural
    /// (string) ordering.
    fn compare_to(&self, other: &dyn DefaultTraceObjectSchema) -> i32 {
        match self.get_name().cmp(&other.get_name()) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSchema {
        name: SchemaName,
        is_canonical: bool,
        elements: HashMap<String, SchemaName>,
    }

    impl TraceObjectSchema for MockSchema {
        fn get_name(&self) -> SchemaName {
            self.name.clone()
        }

        fn to_string(&self) -> String {
            format!("schema {}", self.name)
        }
    }

    struct MockContext;

    impl SchemaContext for MockContext {
        fn get_schema(&self, name: &SchemaName) -> Box<dyn TraceObjectSchema> {
            Box::new(MockSchema {
                name: name.clone(),
                is_canonical: false,
                elements: HashMap::new(),
            })
        }

        fn get_schema_or_null(&self, _name: &SchemaName) -> Option<Box<dyn TraceObjectSchema>> {
            None
        }

        fn get_all_schemas(&self) -> Vec<Box<dyn TraceObjectSchema>> {
            Vec::new()
        }
    }

    impl DefaultTraceObjectSchema for MockSchema {
        fn get_context(&self) -> Box<dyn SchemaContext> {
            Box::new(MockContext)
        }

        fn get_type(&self) -> &'static str {
            "ghidra.trace.model.target.TraceObject"
        }

        fn get_interfaces(&self) -> Vec<Box<dyn TraceObjectInterface>> {
            Vec::new()
        }

        fn is_canonical_container(&self) -> bool {
            self.is_canonical
        }

        fn get_element_schemas(&self) -> HashMap<String, SchemaName> {
            self.elements.clone()
        }

        fn get_default_element_schema(&self) -> SchemaName {
            SchemaName::new("VOID")
        }

        fn get_attribute_schemas(&self) -> HashMap<String, Box<dyn AttributeSchema>> {
            HashMap::new()
        }

        fn get_attribute_aliases(&self) -> HashMap<String, String> {
            HashMap::new()
        }

        fn get_default_attribute_schema(&self) -> Box<dyn AttributeSchema> {
            struct DefaultVoid;
            impl AttributeSchema for DefaultVoid {}
            Box::new(DefaultVoid)
        }
    }

    fn as_dyn(s: &MockSchema) -> &dyn DefaultTraceObjectSchema {
        s
    }

    #[test]
    fn is_object_safe() {
        let schema = MockSchema {
            name: SchemaName::new("Process"),
            is_canonical: true,
            elements: HashMap::new(),
        };
        let _dyn_ref = as_dyn(&schema);
    }

    #[test]
    fn compare_to_orders_by_name() {
        let a = MockSchema {
            name: SchemaName::new("AAA"),
            is_canonical: false,
            elements: HashMap::new(),
        };
        let b = MockSchema {
            name: SchemaName::new("BBB"),
            is_canonical: false,
            elements: HashMap::new(),
        };
        assert_eq!(a.compare_to(&b), -1);
        assert_eq!(b.compare_to(&a), 1);
        assert_eq!(a.compare_to(&a), 0);
    }

    #[test]
    fn exposes_element_schemas_and_canonical_flag() {
        let mut elements = HashMap::new();
        elements.insert("0".to_string(), SchemaName::new("Thread"));
        let schema = MockSchema {
            name: SchemaName::new("ThreadContainer"),
            is_canonical: true,
            elements,
        };
        assert!(schema.is_canonical_container());
        assert_eq!(
            schema.get_element_schemas().get("0"),
            Some(&SchemaName::new("Thread"))
        );
        assert_eq!(schema.get_default_element_schema(), SchemaName::new("VOID"));
    }
}
