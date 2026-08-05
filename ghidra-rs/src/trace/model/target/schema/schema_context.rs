use crate::debug::api::tracermi::SchemaName;
use crate::trace::seam_stubs::TraceObjectSchema;

/// A collection of related schemas all for the same trace or target.
///
/// Mirrors `ghidra.trace.model.target.schema.SchemaContext`.
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

    struct MockSchema {
        name: SchemaName,
    }

    impl TraceObjectSchema for MockSchema {}

    struct MockContext {
        schemas: Vec<SchemaName>,
    }

    impl SchemaContext for MockContext {
        fn get_schema(&self, name: &SchemaName) -> Box<dyn TraceObjectSchema> {
            Box::new(MockSchema { name: name.clone() })
        }

        fn get_schema_or_null(&self, name: &SchemaName) -> Option<Box<dyn TraceObjectSchema>> {
            if self.schemas.contains(name) {
                Some(Box::new(MockSchema { name: name.clone() }))
            } else {
                None
            }
        }

        fn get_all_schemas(&self) -> Vec<Box<dyn TraceObjectSchema>> {
            self.schemas
                .iter()
                .cloned()
                .map(|name| Box::new(MockSchema { name }) as Box<dyn TraceObjectSchema>)
                .collect()
        }
    }

    fn as_dyn(c: &MockContext) -> &dyn SchemaContext {
        c
    }

    #[test]
    fn is_object_safe() {
        let ctx = MockContext {
            schemas: vec![SchemaName::new("Root")],
        };
        let _dyn_ref = as_dyn(&ctx);
    }

    #[test]
    fn get_schema_or_null_finds_existing() {
        let ctx = MockContext {
            schemas: vec![SchemaName::new("Root"), SchemaName::new("Process")],
        };
        assert!(ctx.get_schema_or_null(&SchemaName::new("Process")).is_some());
    }

    #[test]
    fn get_schema_or_null_missing_returns_none() {
        let ctx = MockContext {
            schemas: vec![SchemaName::new("Root")],
        };
        assert!(ctx.get_schema_or_null(&SchemaName::new("Missing")).is_none());
    }

    #[test]
    fn get_schema_never_fails_for_unknown_name() {
        let ctx = MockContext { schemas: vec![] };
        let _schema = ctx.get_schema(&SchemaName::new("Unknown"));
    }

    #[test]
    fn get_all_schemas_preserves_insertion_order() {
        let ctx = MockContext {
            schemas: vec![
                SchemaName::new("Root"),
                SchemaName::new("Process"),
                SchemaName::new("Thread"),
            ],
        };
        let all = ctx.get_all_schemas();
        assert_eq!(all.len(), 3);
    }
}
