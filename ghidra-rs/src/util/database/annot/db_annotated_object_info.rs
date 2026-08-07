//! Mirrors `ghidra.util.database.annot.DBAnnotatedObjectInfo`: the required annotation on every
//! [`DBAnnotatedObject`](crate::util::seam_stubs::DBAnnotatedObject) implementation, carrying its
//! schema version.
//!
//! Java annotations are compile-time metadata read via reflection at runtime; there is no direct
//! Rust equivalent, so this is ported as a trait describing the same per-class metadata
//! (`version`), implemented by whatever stands in for an annotated object type's spec once the
//! reflective object-store machinery (`DBAnnotatedObjectFactory`, `DBCachedObjectStoreFactory`) is
//! ported. Unlike `@DBAnnotatedField`/`@DBAnnotatedColumn`, `version` has no annotation-level
//! default -- Java requires every use to supply it -- so this trait has no default body either.

/// Per-class schema metadata, mirroring the single member of the `@DBAnnotatedObjectInfo`
/// annotation.
pub trait DBAnnotatedObjectInfo: Send + Sync {
    /// The schema version, mirroring `DBAnnotatedObjectInfo.version()`.
    ///
    /// This should be incremented in many situations, including but not limited to:
    /// a field is added or removed; a field's type changes; a field's column name changes; a
    /// field's codec changes; a field's sparse-storage flag changes; a field's index flag
    /// changes; the order of field declarations changes; the codec used by a field changes how
    /// it encodes values; or the fields of a superclass change in any of the above ways.
    fn version(&self) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedVersion(i32);
    impl DBAnnotatedObjectInfo for FixedVersion {
        fn version(&self) -> i32 {
            self.0
        }
    }

    #[test]
    fn object_safe_and_reports_version() {
        let info: Box<dyn DBAnnotatedObjectInfo> = Box::new(FixedVersion(3));
        assert_eq!(info.version(), 3);
    }

    #[test]
    fn distinct_instances_report_distinct_versions() {
        let v1: Box<dyn DBAnnotatedObjectInfo> = Box::new(FixedVersion(1));
        let v2: Box<dyn DBAnnotatedObjectInfo> = Box::new(FixedVersion(2));
        assert_ne!(v1.version(), v2.version());
    }
}
