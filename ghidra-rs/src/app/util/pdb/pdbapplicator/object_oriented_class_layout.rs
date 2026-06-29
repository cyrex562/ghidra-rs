use std::fmt;

/// PDB Analyzer user algorithmic choice for performing object-oriented class layout.
///
/// `MembersOnly` is the legacy output that only shows members of the current class.
/// `ClassHierarchy` provides a nested layout suited for understanding class composition
/// from base classes and members via the Structure Editor perspective.
/// `ClassHierarchySpeculative` extends `ClassHierarchy` with speculative virtual class
/// placement when an in-memory Virtual Base Table is not found (risky).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectOrientedClassLayout {
    /// Processes members of the current class only; legacy solution.
    MembersOnly,
    /// Includes base class hierarchies and other C++-isms into a class layout.
    ClassHierarchy,
    /// Same as `ClassHierarchy`, but also performs speculative virtual class placement
    /// if an in-memory Virtual Base Table is not found.
    ClassHierarchySpeculative,
}

impl ObjectOrientedClassLayout {
    /// Returns the human-readable label for this layout choice.
    pub fn label(self) -> &'static str {
        match self {
            ObjectOrientedClassLayout::MembersOnly => "No C++ Hierarchy (Legacy)",
            ObjectOrientedClassLayout::ClassHierarchy => "Class Hierarchy (Experimental)",
            ObjectOrientedClassLayout::ClassHierarchySpeculative => {
                "Class Hierarchy (Missing VBT Speculatation - Risky)"
            }
        }
    }
}

impl fmt::Display for ObjectOrientedClassLayout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_labels() {
        assert_eq!(
            ObjectOrientedClassLayout::MembersOnly.label(),
            "No C++ Hierarchy (Legacy)"
        );
        assert_eq!(
            ObjectOrientedClassLayout::ClassHierarchy.label(),
            "Class Hierarchy (Experimental)"
        );
        assert_eq!(
            ObjectOrientedClassLayout::ClassHierarchySpeculative.label(),
            "Class Hierarchy (Missing VBT Speculatation - Risky)"
        );
    }

    #[test]
    fn test_display_matches_label() {
        for variant in [
            ObjectOrientedClassLayout::MembersOnly,
            ObjectOrientedClassLayout::ClassHierarchy,
            ObjectOrientedClassLayout::ClassHierarchySpeculative,
        ] {
            assert_eq!(format!("{}", variant), variant.label());
        }
    }

    #[test]
    fn test_clone_copy_eq() {
        let a = ObjectOrientedClassLayout::ClassHierarchy;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(a, ObjectOrientedClassLayout::MembersOnly);
    }

    #[test]
    fn test_debug() {
        assert_eq!(
            format!("{:?}", ObjectOrientedClassLayout::MembersOnly),
            "MembersOnly"
        );
        assert_eq!(
            format!("{:?}", ObjectOrientedClassLayout::ClassHierarchySpeculative),
            "ClassHierarchySpeculative"
        );
    }
}
