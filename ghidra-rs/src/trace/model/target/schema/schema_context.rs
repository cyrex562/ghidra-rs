//! Port of `ghidra.trace.model.target.schema.SchemaContext`.
use crate::debug::api::tracermi::SchemaName;
use crate::trace::model::target::schema::trace_object_schema::TraceObjectSchema;

/// A collection of related schemas all for the same trace or target.
///
/// Mirrors `ghidra.trace.model.target.schema.SchemaContext`. The concrete contexts are
/// [`DefaultSchemaContext`](crate::trace::model::target::schema::default_schema_context::DefaultSchemaContext)
/// and [`XmlSchemaContext`](crate::trace::model::target::schema::xml_schema_context::XmlSchemaContext).
pub trait SchemaContext: Send + Sync {
    /// Resolves a schema in this context by name.
    ///
    /// Note that resolving a name generated outside of this context may have undefined results.
    /// Returns the "ANY" primitive schema if no schema by the given name exists.
    fn get_schema(&self, name: &SchemaName) -> Box<dyn TraceObjectSchema>;

    /// Resolves a schema in this context by name, or `None` if no schema by the given name
    /// exists.
    fn get_schema_or_null(&self, name: &SchemaName) -> Option<Box<dyn TraceObjectSchema>>;

    /// Collects all schemas in this context.
    ///
    /// Mirrors the Java `SequencedSet<TraceObjectSchema>` return, preserving insertion order.
    fn get_all_schemas(&self) -> Vec<Box<dyn TraceObjectSchema>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::model::target::schema::default_schema_context::DefaultSchemaContext;

    fn as_dyn(c: &DefaultSchemaContext) -> &dyn SchemaContext {
        c
    }

    #[test]
    fn resolves_through_the_trait_object() {
        let ctx = DefaultSchemaContext::new();
        ctx.builder(SchemaName::new("Process")).build_and_add().unwrap();
        let ctx = as_dyn(&ctx);
        assert_eq!(
            ctx.get_schema_or_null(&SchemaName::new("Process")).unwrap().get_name(),
            SchemaName::new("Process")
        );
        assert!(ctx.get_schema_or_null(&SchemaName::new("Missing")).is_none());
        assert_eq!(ctx.get_schema(&SchemaName::new("Missing")).get_name(), SchemaName::new("ANY"));
        let all = ctx.get_all_schemas();
        assert_eq!(all.len(), 23);
        assert_eq!(all.last().unwrap().get_name(), SchemaName::new("Process"));
    }
}
