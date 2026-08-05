//! The default [`SchemaContext`] implementation, ported as a trait because it was selected as a
//! cycle cut-point: in the original Java, `DefaultSchemaContext` constructs `SchemaBuilder`
//! instances that hold a back-reference to the context, and its no-arg constructor seeds itself
//! from `PrimitiveTraceObjectSchema.values()`, whose own methods (e.g.
//! `schemaForPrimitive`/`searchFor`) take or return a `SchemaContext`.
//!
//! Java source: `ghidra.trace.model.target.schema.DefaultSchemaContext`.
//!
//! `PrimitiveTraceObjectSchema` and `SchemaBuilder` are not yet ported (see
//! [`seam_stubs::PrimitiveTraceObjectSchema`](crate::trace::seam_stubs::PrimitiveTraceObjectSchema)
//! and [`seam_stubs::SchemaBuilder`](crate::trace::seam_stubs::SchemaBuilder)), so the
//! constructors take the seed primitives as a parameter rather than reaching for a static
//! `PrimitiveTraceObjectSchema.values()`, and the two `builder(...)` overloads are split into
//! [`builder_for_schema`](DefaultSchemaContext::builder_for_schema) and
//! [`builder_for_name`](DefaultSchemaContext::builder_for_name) since Rust traits cannot
//! overload on parameter type.
use crate::debug::api::tracermi::SchemaName;
use crate::trace::model::target::schema::schema_context::SchemaContext;
use crate::trace::seam_stubs::{PrimitiveTraceObjectSchema, SchemaBuilder, TraceObjectSchema};

/// The default implementation of a schema context.
///
/// Mirrors `ghidra.trace.model.target.schema.DefaultSchemaContext`.
pub trait DefaultSchemaContext: SchemaContext {
    /// Constructs a new context, seeded with the given primitive schemas.
    ///
    /// Mirrors the no-arg constructor, which seeds from `PrimitiveTraceObjectSchema.values()`;
    /// callers supply that set here since `PrimitiveTraceObjectSchema` is not yet ported.
    fn new(primitives: Vec<Box<dyn PrimitiveTraceObjectSchema>>) -> Self
    where
        Self: Sized;

    /// Constructs a new context seeded with `primitives`, then copies every schema from `ctx`
    /// that isn't already one of `primitives` into it.
    ///
    /// Mirrors the `DefaultSchemaContext(SchemaContext)` constructor, which seeds itself via
    /// `this()` and then re-adds every schema from `ctx` that is not a
    /// `PrimitiveTraceObjectSchema` (already covered by the seed).
    fn from_context(ctx: &dyn SchemaContext, primitives: Vec<Box<dyn PrimitiveTraceObjectSchema>>) -> Self
    where
        Self: Sized,
    {
        let primitive_names: std::collections::HashSet<SchemaName> =
            primitives.iter().map(|p| p.get_name()).collect();
        let mut result = Self::new(primitives);
        for schema in ctx.get_all_schemas() {
            if !primitive_names.contains(&schema.get_name()) {
                result.builder_for_schema(schema).build_and_add();
            }
        }
        result
    }

    /// Starts building a schema derived from `schema`, tied back to this context.
    ///
    /// Mirrors `builder(TraceObjectSchema)`.
    fn builder_for_schema(&self, schema: Box<dyn TraceObjectSchema>) -> Box<dyn SchemaBuilder>;

    /// Starts building a schema with the given `name`, tied back to this context.
    ///
    /// Mirrors `builder(SchemaName)`.
    fn builder_for_name(&self, name: &SchemaName) -> Box<dyn SchemaBuilder>;

    /// Starts building a modified copy of the schema currently registered under `name`.
    ///
    /// Mirrors `modify(SchemaName)`.
    fn modify(&self, name: &SchemaName) -> Box<dyn SchemaBuilder> {
        self.builder_for_schema(self.get_schema(name))
    }

    /// Registers `schema` under its name, failing if that name is already taken.
    ///
    /// Mirrors the synchronized `putSchema(TraceObjectSchema)`, which throws
    /// `IllegalArgumentException` on a name collision.
    fn put_schema(&mut self, schema: Box<dyn TraceObjectSchema>) -> Result<(), String> {
        let name = schema.get_name();
        if self.get_schema_or_null(&name).is_some() {
            return Err(format!("Name already in context: {name}"));
        }
        self.replace_schema(schema);
        Ok(())
    }

    /// Registers `schema` under its name, overwriting any existing schema of that name.
    ///
    /// Mirrors the synchronized `replaceSchema(TraceObjectSchema)`.
    fn replace_schema(&mut self, schema: Box<dyn TraceObjectSchema>);

    /// Mirrors the `toString()` override: every registered schema's own `toString()`, one per
    /// line, in insertion order.
    fn to_string(&self) -> String {
        let mut result = String::new();
        for schema in self.get_all_schemas() {
            result.push_str(&schema.to_string());
            result.push('\n');
        }
        result
    }

    /// Mirrors the `equals(Object)` override, collapsed to the common case (both sides are some
    /// `SchemaContext`): equal iff they hold the same schemas, by name, in the same order.
    fn equals(&self, other: &dyn SchemaContext) -> bool {
        let mine = self.get_all_schemas();
        let theirs = other.get_all_schemas();
        mine.len() == theirs.len()
            && mine
                .iter()
                .zip(theirs.iter())
                .all(|(a, b)| a.get_name() == b.get_name())
    }

    /// Mirrors the `hashCode()` override (`schemas.hashCode()`), approximated here as a
    /// Java-`String.hashCode()`-style combination of the registered schema names.
    fn hash_code(&self) -> i32 {
        let mut result: i32 = 0;
        for schema in self.get_all_schemas() {
            result = result.wrapping_add(java_string_hash(schema.get_name().as_str()));
        }
        result
    }
}

/// Mirrors `java.lang.String.hashCode()`.
fn java_string_hash(s: &str) -> i32 {
    let mut h: i32 = 0;
    for c in s.encode_utf16() {
        h = h.wrapping_mul(31).wrapping_add(c as i32);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct MockSchema {
        name: SchemaName,
        label: &'static str,
    }

    impl TraceObjectSchema for MockSchema {
        fn get_name(&self) -> SchemaName {
            self.name.clone()
        }

        fn to_string(&self) -> String {
            format!("Schema[{}]={}", self.name, self.label)
        }
    }

    struct MockPrimitive {
        name: SchemaName,
    }

    impl TraceObjectSchema for MockPrimitive {
        fn get_name(&self) -> SchemaName {
            self.name.clone()
        }

        fn to_string(&self) -> String {
            format!("Primitive[{}]", self.name)
        }
    }

    impl PrimitiveTraceObjectSchema for MockPrimitive {}

    /// Insertion-ordered `(name, schema)` list, shared (via `Arc<Mutex<_>>`) between a
    /// `MockContext` and every `MockBuilder` created from it, so a builder's `build_and_add()`
    /// is visible through the context's own `get_all_schemas()` -- matching how the real
    /// `SchemaBuilder` writes back into the `DefaultSchemaContext` it was built from.
    type SharedSchemas = std::sync::Arc<std::sync::Mutex<Vec<(SchemaName, Box<dyn TraceObjectSchema>)>>>;

    struct MockBuilder {
        name: SchemaName,
        ctx: SharedSchemas,
    }

    impl SchemaBuilder for MockBuilder {
        fn build_and_add(&self) -> Box<dyn TraceObjectSchema> {
            let built: Box<dyn TraceObjectSchema> = Box::new(MockSchema {
                name: self.name.clone(),
                label: "built",
            });
            let mut schemas = self.ctx.lock().unwrap();
            schemas.retain(|(n, _)| n != &self.name);
            schemas.push((
                self.name.clone(),
                Box::new(MockSchema { name: self.name.clone(), label: "built" }),
            ));
            built
        }
    }

    struct MockContext {
        schemas: SharedSchemas,
    }

    impl SchemaContext for MockContext {
        fn get_schema(&self, name: &SchemaName) -> Box<dyn TraceObjectSchema> {
            self.get_schema_or_null(name).unwrap_or_else(|| {
                Box::new(MockSchema {
                    name: SchemaName::new("ANY"),
                    label: "any",
                })
            })
        }

        fn get_schema_or_null(&self, name: &SchemaName) -> Option<Box<dyn TraceObjectSchema>> {
            self.schemas
                .lock()
                .unwrap()
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, s)| Box::new(MockSchema { name: s.get_name(), label: "stored" }) as Box<dyn TraceObjectSchema>)
        }

        fn get_all_schemas(&self) -> Vec<Box<dyn TraceObjectSchema>> {
            self.schemas
                .lock()
                .unwrap()
                .iter()
                .map(|(n, _)| Box::new(MockSchema { name: n.clone(), label: "stored" }) as Box<dyn TraceObjectSchema>)
                .collect()
        }
    }

    impl DefaultSchemaContext for MockContext {
        fn new(primitives: Vec<Box<dyn PrimitiveTraceObjectSchema>>) -> Self {
            let schemas: Vec<(SchemaName, Box<dyn TraceObjectSchema>)> = primitives
                .into_iter()
                .map(|p| {
                    let name = p.get_name();
                    (name.clone(), Box::new(MockSchema { name, label: "primitive" }) as Box<dyn TraceObjectSchema>)
                })
                .collect();
            MockContext {
                schemas: std::sync::Arc::new(std::sync::Mutex::new(schemas)),
            }
        }

        fn builder_for_schema(&self, schema: Box<dyn TraceObjectSchema>) -> Box<dyn SchemaBuilder> {
            Box::new(MockBuilder {
                name: schema.get_name(),
                ctx: self.schemas.clone(),
            })
        }

        fn builder_for_name(&self, name: &SchemaName) -> Box<dyn SchemaBuilder> {
            Box::new(MockBuilder {
                name: name.clone(),
                ctx: self.schemas.clone(),
            })
        }

        fn replace_schema(&mut self, schema: Box<dyn TraceObjectSchema>) {
            let name = schema.get_name();
            let mut schemas = self.schemas.lock().unwrap();
            schemas.retain(|(n, _)| n != &name);
            schemas.push((name, schema));
        }
    }

    fn as_dyn(c: &MockContext) -> &dyn DefaultSchemaContext {
        c
    }

    #[test]
    fn is_object_safe() {
        let ctx = MockContext::new(vec![]);
        let _dyn_ref = as_dyn(&ctx);
    }

    #[test]
    fn new_seeds_from_primitives() {
        let ctx = MockContext::new(vec![Box::new(MockPrimitive {
            name: SchemaName::new("ANY"),
        })]);
        assert!(ctx.get_schema_or_null(&SchemaName::new("ANY")).is_some());
        assert_eq!(ctx.get_all_schemas().len(), 1);
    }

    #[test]
    fn put_schema_rejects_duplicate_name() {
        let mut ctx = MockContext::new(vec![]);
        let name = SchemaName::new("Process");
        ctx.put_schema(Box::new(MockSchema { name: name.clone(), label: "a" }))
            .expect("first insert succeeds");
        let err = ctx
            .put_schema(Box::new(MockSchema { name: name.clone(), label: "b" }))
            .unwrap_err();
        assert!(err.contains("Process"));
    }

    #[test]
    fn replace_schema_overwrites_existing() {
        let mut ctx = MockContext::new(vec![]);
        let name = SchemaName::new("Process");
        ctx.replace_schema(Box::new(MockSchema { name: name.clone(), label: "a" }));
        ctx.replace_schema(Box::new(MockSchema { name: name.clone(), label: "b" }));
        assert_eq!(ctx.get_all_schemas().len(), 1);
    }

    #[test]
    fn from_context_copies_non_primitive_schemas() {
        let mut base = MockContext::new(vec![Box::new(MockPrimitive {
            name: SchemaName::new("ANY"),
        })]);
        base.put_schema(Box::new(MockSchema {
            name: SchemaName::new("Process"),
            label: "custom",
        }))
        .expect("insert succeeds");

        let copy = MockContext::from_context(
            &base,
            vec![Box::new(MockPrimitive {
                name: SchemaName::new("ANY"),
            })],
        );

        assert!(copy.get_schema_or_null(&SchemaName::new("ANY")).is_some());
        assert!(copy.get_schema_or_null(&SchemaName::new("Process")).is_some());
        assert_eq!(copy.get_all_schemas().len(), 2);
    }

    #[test]
    fn modify_builds_from_existing_schema() {
        let mut ctx = MockContext::new(vec![]);
        let name = SchemaName::new("Process");
        ctx.put_schema(Box::new(MockSchema { name: name.clone(), label: "a" }))
            .expect("insert succeeds");
        let built = ctx.modify(&name).build_and_add();
        assert_eq!(built.get_name(), name);
    }

    #[test]
    fn to_string_lists_every_schema() {
        let mut ctx = MockContext::new(vec![]);
        ctx.put_schema(Box::new(MockSchema {
            name: SchemaName::new("Process"),
            label: "a",
        }))
        .expect("insert succeeds");
        let s = ctx.to_string();
        assert!(s.contains("Process"));
    }

    #[test]
    fn equals_compares_schema_names_in_order() {
        let mut a = MockContext::new(vec![]);
        a.put_schema(Box::new(MockSchema {
            name: SchemaName::new("Process"),
            label: "a",
        }))
        .expect("insert succeeds");
        let mut b = MockContext::new(vec![]);
        b.put_schema(Box::new(MockSchema {
            name: SchemaName::new("Process"),
            label: "different label, same name",
        }))
        .expect("insert succeeds");
        assert!(a.equals(&b));

        let c = MockContext::new(vec![]);
        assert!(!a.equals(&c));
    }

    #[test]
    fn hash_code_is_stable_for_same_names() {
        let mut a = MockContext::new(vec![]);
        a.put_schema(Box::new(MockSchema {
            name: SchemaName::new("Process"),
            label: "a",
        }))
        .expect("insert succeeds");
        let mut b = MockContext::new(vec![]);
        b.put_schema(Box::new(MockSchema {
            name: SchemaName::new("Process"),
            label: "b",
        }))
        .expect("insert succeeds");
        assert_eq!(a.hash_code(), b.hash_code());
    }
}
