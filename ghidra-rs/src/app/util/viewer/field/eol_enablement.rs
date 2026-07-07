//! Controls when end-of-line comments are shown in the listing.

/// Determines when end-of-line (EOL) comments are displayed.
///
/// Corresponds to Java `ghidra.app.util.viewer.field.EolEnablement`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EolEnablement {
    /// Always show EOL comments.
    Always,
    /// Use the default display behaviour.
    Default,
    /// Never show EOL comments.
    Never,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        assert_ne!(EolEnablement::Always, EolEnablement::Default);
        assert_ne!(EolEnablement::Always, EolEnablement::Never);
        assert_ne!(EolEnablement::Default, EolEnablement::Never);
    }

    #[test]
    fn clone_and_copy() {
        let a = EolEnablement::Always;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", EolEnablement::Always), "Always");
        assert_eq!(format!("{:?}", EolEnablement::Default), "Default");
        assert_eq!(format!("{:?}", EolEnablement::Never), "Never");
    }
}
