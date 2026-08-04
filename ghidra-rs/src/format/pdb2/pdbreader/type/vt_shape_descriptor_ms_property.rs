//! VTShape Descriptor Property used on `VtShapeMsType` PDB data type.
//!
//! Corresponds to the Java enum
//! `ghidra.app.util.bin.format.pdb2.pdbreader.type.VtShapeDescriptorMsProperty`.
//!
//! Ported as a trait (rather than a plain Rust enum) because this type was selected as a
//! dependency-cycle cut-point: callers such as `VtShapeMsType` (not yet ported) can depend on
//! `dyn VtShapeDescriptorMsProperty` instead of a single concrete enum, so their crates don't
//! need to see the full fixed variant list.

/// A VTShape descriptor property used on the `VtShapeMsType` PDB data type.
///
/// See `VtShapeMsType` in the Java source.
pub trait VtShapeDescriptorMsProperty: std::fmt::Debug {
    /// Returns the display label (e.g. `"near"`), matching Java's `toString()`.
    fn label(&self) -> &str;

    /// Returns the raw wire value of this descriptor property.
    fn value(&self) -> i32;
}

/// The standard, fixed set of VTShape descriptor properties recognized by the PDB reader.
///
/// Corresponds to the enum constants of the Java `VtShapeDescriptorMsProperty` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandardVtShapeDescriptorMsProperty {
    Near,
    Far,
    Thin,
    Outer,
    Meta,
    Near32,
    Far32,
    Unused,
}

impl StandardVtShapeDescriptorMsProperty {
    fn data(self) -> (&'static str, i32) {
        match self {
            Self::Near => ("near", 0),
            Self::Far => ("far", 1),
            Self::Thin => ("thin", 2),
            Self::Outer => ("outer", 3),
            Self::Meta => ("meta", 4),
            Self::Near32 => ("near32", 5),
            Self::Far32 => ("far32", 6),
            Self::Unused => ("unused", 7),
        }
    }

    /// Looks up a descriptor property by its raw wire value, matching Java's `fromValue(int)`.
    /// Unrecognized values map to [`StandardVtShapeDescriptorMsProperty::Unused`].
    pub fn from_value(val: i32) -> Self {
        match val {
            0 => Self::Near,
            1 => Self::Far,
            2 => Self::Thin,
            3 => Self::Outer,
            4 => Self::Meta,
            5 => Self::Near32,
            6 => Self::Far32,
            7 => Self::Unused,
            _ => Self::Unused,
        }
    }
}

impl VtShapeDescriptorMsProperty for StandardVtShapeDescriptorMsProperty {
    fn label(&self) -> &str {
        self.data().0
    }

    fn value(&self) -> i32 {
        self.data().1
    }
}

impl std::fmt::Display for StandardVtShapeDescriptorMsProperty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_value_matches_java_constants() {
        assert_eq!(
            StandardVtShapeDescriptorMsProperty::from_value(0),
            StandardVtShapeDescriptorMsProperty::Near
        );
        assert_eq!(
            StandardVtShapeDescriptorMsProperty::from_value(6),
            StandardVtShapeDescriptorMsProperty::Far32
        );
        assert_eq!(
            StandardVtShapeDescriptorMsProperty::from_value(7),
            StandardVtShapeDescriptorMsProperty::Unused
        );
        assert_eq!(
            StandardVtShapeDescriptorMsProperty::from_value(-1),
            StandardVtShapeDescriptorMsProperty::Unused
        );
        assert_eq!(
            StandardVtShapeDescriptorMsProperty::from_value(9999),
            StandardVtShapeDescriptorMsProperty::Unused
        );
    }

    #[test]
    fn accessors_match_java_fields() {
        let thin = StandardVtShapeDescriptorMsProperty::Thin;
        assert_eq!(thin.label(), "thin");
        assert_eq!(thin.value(), 2);
        assert_eq!(thin.to_string(), "thin");
    }

    /// Mock impl proving the trait is object-safe and usable by a caller that only knows about
    /// `dyn VtShapeDescriptorMsProperty`, matching how a cycle-breaking cut-point trait is
    /// consumed.
    #[derive(Debug)]
    struct MockVtShapeDescriptorMsProperty;

    impl VtShapeDescriptorMsProperty for MockVtShapeDescriptorMsProperty {
        fn label(&self) -> &str {
            "mock"
        }

        fn value(&self) -> i32 {
            0x7f
        }
    }

    #[test]
    fn is_object_safe() {
        let properties: Vec<Box<dyn VtShapeDescriptorMsProperty>> = vec![
            Box::new(StandardVtShapeDescriptorMsProperty::Near),
            Box::new(MockVtShapeDescriptorMsProperty),
        ];
        assert_eq!(properties[0].label(), "near");
        assert_eq!(properties[0].value(), 0);
        assert_eq!(properties[1].label(), "mock");
        assert_eq!(properties[1].value(), 0x7f);
    }
}
