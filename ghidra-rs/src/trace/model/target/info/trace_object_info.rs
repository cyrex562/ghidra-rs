/// Information about a trace target interface.
///
/// This is the Rust equivalent of the `@TraceObjectInfo` Java annotation
/// (`ghidra.trace.model.target.info.TraceObjectInfo`). In Java, this annotation
/// is applied to types at compile time and retained at runtime for reflective
/// lookup. In Rust, the same metadata is carried by a plain struct; types that
/// represent trace target interfaces expose an instance (e.g., via a `const` or
/// a trait method) instead of relying on reflection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceObjectInfo {
    /// The name for this interface in the schema.
    pub schema_name: String,
    /// A short, human-readable name for this interface type.
    pub short_name: String,
    /// The attributes expected or required by this interface.
    pub attributes: Vec<String>,
    /// Keys intrinsic to this interface whose values are fixed during the
    /// object's lifespan.
    pub fixed_keys: Vec<String>,
}

impl TraceObjectInfo {
    /// Creates a new `TraceObjectInfo`.
    pub fn new(
        schema_name: impl Into<String>,
        short_name: impl Into<String>,
        attributes: impl IntoIterator<Item = impl Into<String>>,
        fixed_keys: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            schema_name: schema_name.into(),
            short_name: short_name.into(),
            attributes: attributes.into_iter().map(Into::into).collect(),
            fixed_keys: fixed_keys.into_iter().map(Into::into).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> TraceObjectInfo {
        TraceObjectInfo::new(
            "Process",
            "proc",
            ["_display", "Exit Code"],
            ["_self"],
        )
    }

    #[test]
    fn schema_name_is_stored() {
        assert_eq!(sample().schema_name, "Process");
    }

    #[test]
    fn short_name_is_stored() {
        assert_eq!(sample().short_name, "proc");
    }

    #[test]
    fn attributes_are_stored() {
        assert_eq!(sample().attributes, vec!["_display", "Exit Code"]);
    }

    #[test]
    fn fixed_keys_are_stored() {
        assert_eq!(sample().fixed_keys, vec!["_self"]);
    }

    #[test]
    fn empty_slices_are_accepted() {
        let info = TraceObjectInfo::new("Minimal", "min", [] as [&str; 0], [] as [&str; 0]);
        assert!(info.attributes.is_empty());
        assert!(info.fixed_keys.is_empty());
    }

    #[test]
    fn equality_holds_for_identical_values() {
        let a = sample();
        let b = sample();
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_on_different_schema_name() {
        let a = sample();
        let b = TraceObjectInfo::new("Thread", "proc", ["_display", "Exit Code"], ["_self"]);
        assert_ne!(a, b);
    }

    #[test]
    fn clone_produces_equal_value() {
        let a = sample();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn debug_contains_schema_name() {
        let info = sample();
        assert!(format!("{:?}", info).contains("Process"));
    }
}
