//! Mirrors `ghidra.util.database.annot.DBAnnotatedColumn`: the annotation marking a Java field
//! (of type `DBObjectColumn`) to receive a column handle.
//!
//! Java annotations are compile-time metadata read via reflection at runtime; there is no direct
//! Rust equivalent, so this is ported as a trait describing the same per-field metadata (the
//! column name), implemented by whatever stands in for an annotated column handle's spec once the
//! reflective object-store machinery (`DBAnnotatedObjectFactory`, `DBCachedObjectStoreFactory`) is
//! ported. There should be a [`DBAnnotatedField`](super::DBAnnotatedField) with the same column
//! name.

/// Per-column-handle metadata, mirroring the members of the `@DBAnnotatedColumn` annotation.
pub trait DBAnnotatedColumn: Send + Sync {
    /// The name of the column, mirroring `DBAnnotatedColumn.value()`.
    fn value(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PlainColumn(&'static str);
    impl DBAnnotatedColumn for PlainColumn {
        fn value(&self) -> &str {
            self.0
        }
    }

    #[test]
    fn object_safe_and_reports_column_name() {
        let column: Box<dyn DBAnnotatedColumn> = Box::new(PlainColumn("NAME"));
        assert_eq!(column.value(), "NAME");
    }

    #[test]
    fn distinct_instances_report_distinct_names() {
        let name: Box<dyn DBAnnotatedColumn> = Box::new(PlainColumn("NAME"));
        let address: Box<dyn DBAnnotatedColumn> = Box::new(PlainColumn("ADDRESS"));
        assert_ne!(name.value(), address.value());
    }
}
