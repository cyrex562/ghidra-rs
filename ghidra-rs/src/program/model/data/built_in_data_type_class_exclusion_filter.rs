//! Port of `ghidra.program.model.data.BuiltInDataTypeClassExclusionFilter`.
//!
//! The Java class is a trivial concrete subclass of `ClassExclusionFilter`
//! ([`ClassExclusionFilter`](crate::util::classfinder::ClassExclusionFilter), already ported in
//! this crate) whose only content is its no-arg constructor, which forwards two hardcoded
//! `Class<?>` literals (`BadDataType.class`, `MissingBuiltInDataType.class`) to the superclass
//! constructor. This crate's [`ClassExclusionFilter`] already models Java's `Class<?>`
//! exclusions as fully-qualified name strings (see that port's own module docs), so this port is
//! a thin wrapper struct whose constructor supplies those same two Java class names as strings,
//! composing [`ClassExclusionFilter`] rather than subclassing it (Rust has no struct
//! inheritance).
//!
//! [`BadDataType`](super::bad_data_type::BadDataType) is a real, `DONE` port in this crate;
//! [`MissingBuiltInDataType`](super::missing_built_in_data_type::MissingBuiltInDataType) is
//! ported earlier in this same batch. Neither Rust trait is actually referenced here, though --
//! only their original Java fully-qualified class names are, which [`ClassExclusionFilter`]
//! needs and which do not depend on either trait's Rust port status.

use crate::util::classfinder::{ClassExclusionFilter, ClassFileInfo, ClassFilter};

/// Fully-qualified Java class name of `ghidra.program.model.data.BadDataType`, standing in for
/// `BadDataType.class`.
const BAD_DATA_TYPE_CLASS: &str = "ghidra.program.model.data.BadDataType";

/// Fully-qualified Java class name of `ghidra.program.model.data.MissingBuiltInDataType`,
/// standing in for `MissingBuiltInDataType.class`.
const MISSING_BUILT_IN_DATA_TYPE_CLASS: &str = "ghidra.program.model.data.MissingBuiltInDataType";

/// An exclusion filter to use when searching for classes that implement `BuiltInDataType`.
///
/// Port of `ghidra.program.model.data.BuiltInDataTypeClassExclusionFilter`.
#[derive(Debug, Clone)]
pub struct BuiltInDataTypeClassExclusionFilter(ClassExclusionFilter);

impl BuiltInDataTypeClassExclusionFilter {
    /// Port of `BuiltInDataTypeClassExclusionFilter()`, the no-arg constructor forwarding
    /// `BadDataType.class, MissingBuiltInDataType.class` to `ClassExclusionFilter`'s constructor.
    pub fn new() -> Self {
        Self(ClassExclusionFilter::new([BAD_DATA_TYPE_CLASS, MISSING_BUILT_IN_DATA_TYPE_CLASS]))
    }
}

impl Default for BuiltInDataTypeClassExclusionFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl ClassFilter for BuiltInDataTypeClassExclusionFilter {
    fn accepts(&self, class_info: &ClassFileInfo) -> bool {
        self.0.accepts(class_info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_info(name: &str) -> ClassFileInfo {
        ClassFileInfo::new(
            "/path/to/class".to_string(),
            name.to_string(),
            "suffix".to_string(),
            "module".to_string(),
        )
    }

    #[test]
    fn excludes_bad_data_type() {
        let filter = BuiltInDataTypeClassExclusionFilter::new();
        assert!(!filter.accepts(&make_info("ghidra.program.model.data.BadDataType")));
    }

    #[test]
    fn excludes_missing_built_in_data_type() {
        let filter = BuiltInDataTypeClassExclusionFilter::new();
        assert!(!filter.accepts(&make_info("ghidra.program.model.data.MissingBuiltInDataType")));
    }

    #[test]
    fn accepts_everything_else() {
        let filter = BuiltInDataTypeClassExclusionFilter::new();
        assert!(filter.accepts(&make_info("ghidra.program.model.data.ByteDataType")));
        assert!(filter.accepts(&make_info("ghidra.program.model.data.Undefined1DataType")));
    }

    #[test]
    fn default_matches_new() {
        let filter = BuiltInDataTypeClassExclusionFilter::default();
        assert!(!filter.accepts(&make_info("ghidra.program.model.data.BadDataType")));
    }
}
