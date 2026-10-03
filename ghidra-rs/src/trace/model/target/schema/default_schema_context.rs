//! Port of `ghidra.trace.model.target.schema.DefaultSchemaContext`, the default implementation of
//! a schema context.
//!
//! # Ownership
//!
//! Java schemas hold a reference to their context, and the context holds the schemas. Here the
//! context is a cheap, cloneable handle onto a shared store (Java reference semantics; the store
//! is locked because every Java accessor is `synchronized`). The store keeps each object schema's
//! *data* only; [`DefaultSchemaContext::get_schema`] pairs that data with a clone of the handle to
//! produce a [`DefaultTraceObjectSchema`]. Data never points back at the store, so there is no
//! reference cycle.
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};

use crate::debug::api::tracermi::SchemaName;
use crate::trace::model::target::schema::default_trace_object_schema::{
    DefaultSchemaData, DefaultTraceObjectSchema,
};
use crate::trace::model::target::schema::primitive_trace_object_schema::PrimitiveTraceObjectSchema;
use crate::trace::model::target::schema::schema_builder::SchemaBuilder;
use crate::trace::model::target::schema::schema_context::SchemaContext;
use crate::trace::model::target::schema::trace_object_schema::{
    SchemaArgumentError, TraceObjectSchema,
};
use crate::util::msg::Msg;

/// A schema as stored in a context.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Stored {
    Primitive(PrimitiveTraceObjectSchema),
    Object(Arc<DefaultSchemaData>),
}

/// Insertion-ordered schema map (Java's `LinkedHashMap<SchemaName, TraceObjectSchema>`).
#[derive(Debug, Default)]
struct Store {
    order: Vec<SchemaName>,
    map: HashMap<SchemaName, Stored>,
}

impl Store {
    fn entries(&self) -> impl Iterator<Item = (&SchemaName, &Stored)> {
        self.order.iter().map(|n| (n, &self.map[n]))
    }

    fn put(&mut self, name: SchemaName, schema: Stored) {
        if self.map.insert(name.clone(), schema).is_none() {
            self.order.push(name);
        }
    }
}

/// The default implementation of a schema context.
///
/// Mirrors `ghidra.trace.model.target.schema.DefaultSchemaContext`. Cloning yields another handle
/// onto the same context.
#[derive(Clone)]
pub struct DefaultSchemaContext {
    store: Arc<RwLock<Store>>,
}

impl DefaultSchemaContext {
    /// A context holding only the primitive schemas. Mirrors `DefaultSchemaContext()`.
    pub fn new() -> Self {
        let mut store = Store::default();
        for p in PrimitiveTraceObjectSchema::VALUES {
            store.put(p.get_name(), Stored::Primitive(p));
        }
        DefaultSchemaContext { store: Arc::new(RwLock::new(store)) }
    }

    /// A context holding the primitives plus a copy of every non-primitive schema of `ctx`.
    /// Mirrors `DefaultSchemaContext(SchemaContext)`.
    pub fn from_context(ctx: &dyn SchemaContext) -> Result<Self, SchemaArgumentError> {
        let result = Self::new();
        for schema in ctx.get_all_schemas() {
            if !schema.is_primitive() {
                result.builder_from(schema.as_ref()).build_and_add()?;
            }
        }
        Ok(result)
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Store> {
        self.store.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Store> {
        self.store.write().unwrap_or_else(|e| e.into_inner())
    }

    /// A builder initialized from `schema`, which adds to this context. Mirrors
    /// `builder(TraceObjectSchema)`.
    pub fn builder_from(&self, schema: &dyn TraceObjectSchema) -> SchemaBuilder {
        SchemaBuilder::from_schema(self.clone(), schema)
    }

    /// A fresh builder for a schema named `name`. Mirrors `builder(SchemaName)`.
    pub fn builder(&self, name: SchemaName) -> SchemaBuilder {
        SchemaBuilder::new(self.clone(), name)
    }

    /// A builder initialized from the existing schema `name`, for use with
    /// [`SchemaBuilder::build_and_replace`]. Mirrors `modify(SchemaName)`.
    pub fn modify(&self, name: &SchemaName) -> SchemaBuilder {
        let schema = self.get_schema(name);
        SchemaBuilder::from_schema(self.clone(), schema.as_ref())
    }

    /// Add a schema. Mirrors `putSchema(TraceObjectSchema)`: fails if the name is taken.
    pub fn put_schema(&self, schema: &DefaultTraceObjectSchema) -> Result<(), SchemaArgumentError> {
        let mut store = self.write();
        let name = schema.get_name();
        if store.map.contains_key(&name) {
            return Err(SchemaArgumentError(format!("Name already in context: {name}")));
        }
        store.put(name, Stored::Object(schema.data().clone()));
        Ok(())
    }

    /// Add or replace a schema. Mirrors `replaceSchema(TraceObjectSchema)`; a replaced schema
    /// keeps its position.
    pub fn replace_schema(&self, schema: &DefaultTraceObjectSchema) {
        self.write().put(schema.get_name(), Stored::Object(schema.data().clone()));
    }

    /// The names of all schemas, in insertion order.
    pub fn get_all_schema_names(&self) -> Vec<SchemaName> {
        self.read().order.clone()
    }

    fn materialize(&self, stored: &Stored) -> Box<dyn TraceObjectSchema> {
        match stored {
            Stored::Primitive(p) => Box::new(*p),
            Stored::Object(data) => {
                Box::new(DefaultTraceObjectSchema::from_parts(data.clone(), self.clone()))
            }
        }
    }

    /// Whether `self` and `other` are handles onto the same context.
    pub fn same_context(&self, other: &DefaultSchemaContext) -> bool {
        Arc::ptr_eq(&self.store, &other.store)
    }
}

impl Default for DefaultSchemaContext {
    fn default() -> Self {
        Self::new()
    }
}

impl SchemaContext for DefaultSchemaContext {
    fn get_schema(&self, name: &SchemaName) -> Box<dyn TraceObjectSchema> {
        match self.get_schema_or_null(name) {
            Some(schema) => schema,
            None => {
                Msg::error("DefaultSchemaContext", &format!("No such schema name: {name}"));
                Box::new(PrimitiveTraceObjectSchema::Any)
            }
        }
    }

    fn get_schema_or_null(&self, name: &SchemaName) -> Option<Box<dyn TraceObjectSchema>> {
        let stored = self.read().map.get(name).cloned()?;
        Some(self.materialize(&stored))
    }

    fn get_all_schemas(&self) -> Vec<Box<dyn TraceObjectSchema>> {
        let stored: Vec<Stored> = self.read().entries().map(|(_, s)| s.clone()).collect();
        stored.iter().map(|s| self.materialize(s)).collect()
    }
}

impl PartialEq for DefaultSchemaContext {
    /// Mirrors `equals`: the schema maps are equal.
    fn eq(&self, other: &Self) -> bool {
        if self.same_context(other) {
            return true;
        }
        let a = self.read();
        let b = other.read();
        a.order.len() == b.order.len() && a.entries().all(|(n, s)| b.map.get(n) == Some(s))
    }
}

impl fmt::Display for DefaultSchemaContext {
    /// Mirrors `toString()`: each schema followed by a newline.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for schema in self.get_all_schemas() {
            writeln!(f, "{}", schema.to_string())?;
        }
        Ok(())
    }
}

impl fmt::Debug for DefaultSchemaContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.get_all_schema_names()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_context_holds_primitives_in_declaration_order() {
        let ctx = DefaultSchemaContext::new();
        let names = ctx.get_all_schema_names();
        assert_eq!(names.len(), 22);
        assert_eq!(names[0], SchemaName::new("ANY"));
        assert_eq!(names[21], SchemaName::new("STRING_ARR"));
        assert!(ctx.get_schema(&SchemaName::new("INT")).is_primitive());
    }

    #[test]
    fn unknown_name_resolves_to_any() {
        let ctx = DefaultSchemaContext::new();
        assert!(ctx.get_schema_or_null(&SchemaName::new("Nope")).is_none());
        assert_eq!(ctx.get_schema(&SchemaName::new("Nope")).get_name(), SchemaName::new("ANY"));
    }

    #[test]
    fn put_schema_rejects_duplicates_and_replace_keeps_position() {
        let ctx = DefaultSchemaContext::new();
        ctx.builder(SchemaName::new("Session")).build_and_add().unwrap();
        ctx.builder(SchemaName::new("Process")).build_and_add().unwrap();
        let err = ctx.builder(SchemaName::new("Session")).build_and_add().unwrap_err();
        assert_eq!(err.0, "Name already in context: Session");

        let mut b = ctx.modify(&SchemaName::new("Session"));
        b.set_canonical_container(true);
        b.build_and_replace().unwrap();
        let names = ctx.get_all_schema_names();
        assert_eq!(names[22], SchemaName::new("Session"));
        assert_eq!(names[23], SchemaName::new("Process"));
        assert!(ctx.get_schema(&SchemaName::new("Session")).is_canonical_container());
    }

    #[test]
    fn schemas_resolve_children_through_their_context() {
        let ctx = DefaultSchemaContext::new();
        let mut b = ctx.builder(SchemaName::new("Session"));
        b.add_element_schema("", SchemaName::new("Process"), "test").unwrap();
        b.build_and_add().unwrap();
        ctx.builder(SchemaName::new("Process")).build_and_add().unwrap();
        let session = ctx.get_schema(&SchemaName::new("Session"));
        assert_eq!(session.get_child_schema("[1]").get_name(), SchemaName::new("Process"));
        assert!(session.get_context().same_context(&ctx));
    }

    #[test]
    fn copy_constructor_and_equality() {
        let ctx = DefaultSchemaContext::new();
        ctx.builder(SchemaName::new("Session")).build_and_add().unwrap();
        let copy = DefaultSchemaContext::from_context(&ctx).unwrap();
        assert!(!copy.same_context(&ctx));
        assert_eq!(copy, ctx);
        copy.builder(SchemaName::new("Extra")).build_and_add().unwrap();
        assert_ne!(copy, ctx);
    }

    #[test]
    fn display_lists_every_schema() {
        let ctx = DefaultSchemaContext::new();
        let text = ctx.to_string();
        assert!(text.starts_with("ANY\nOBJECT\nTYPE\n"));
        assert_eq!(text.lines().count(), 22);
    }
}
