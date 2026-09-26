/// Controls whether a symbol should be demangled as a function or a non-function symbol.
///
/// When a mangled name has multiple possible interpretations, this enum selects which
/// interpretation the Microsoft demangler uses.
///
/// Port of `ghidra.app.util.demangler.microsoft.MsCInterpretation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MsCInterpretation {
    /// Forces processing as a function symbol if there are multiple symbol interpretations.
    Function,
    /// Forces processing as a non-function (e.g., variable) if there are multiple symbol
    /// interpretations.
    NonFunction,
    /// Forces processing as a function only if there is already a function at the address.
    FunctionIfExists,
}

impl MsCInterpretation {
    /// The Java constant name of this variant, as `Enum.name()` returns it. This is the form in
    /// which the value is persisted (see
    /// [`MsdApplyOption`](crate::demangler::microsoft::options::MsdApplyOption)).
    pub fn name(&self) -> &'static str {
        match self {
            MsCInterpretation::Function => "FUNCTION",
            MsCInterpretation::NonFunction => "NON_FUNCTION",
            MsCInterpretation::FunctionIfExists => "FUNCTION_IF_EXISTS",
        }
    }

    /// The variant whose Java constant name is `name`, mirroring `MsCInterpretation.valueOf`;
    /// `None` where Java would throw `IllegalArgumentException`.
    pub fn value_of(name: &str) -> Option<Self> {
        match name {
            "FUNCTION" => Some(MsCInterpretation::Function),
            "NON_FUNCTION" => Some(MsCInterpretation::NonFunction),
            "FUNCTION_IF_EXISTS" => Some(MsCInterpretation::FunctionIfExists),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        assert_ne!(MsCInterpretation::Function, MsCInterpretation::NonFunction);
        assert_ne!(MsCInterpretation::Function, MsCInterpretation::FunctionIfExists);
        assert_ne!(MsCInterpretation::NonFunction, MsCInterpretation::FunctionIfExists);
    }

    #[test]
    fn equality_holds_for_same_variant() {
        assert_eq!(MsCInterpretation::Function, MsCInterpretation::Function);
        assert_eq!(MsCInterpretation::NonFunction, MsCInterpretation::NonFunction);
        assert_eq!(MsCInterpretation::FunctionIfExists, MsCInterpretation::FunctionIfExists);
    }

    #[test]
    fn copy_produces_independent_value() {
        let a = MsCInterpretation::FunctionIfExists;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn debug_is_available() {
        let _ = format!("{:?}", MsCInterpretation::Function);
        let _ = format!("{:?}", MsCInterpretation::NonFunction);
        let _ = format!("{:?}", MsCInterpretation::FunctionIfExists);
    }

    #[test]
    fn clone_produces_equal_value() {
        let original = MsCInterpretation::NonFunction;
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn name_and_value_of_round_trip_java_constant_names() {
        for (v, n) in [
            (MsCInterpretation::Function, "FUNCTION"),
            (MsCInterpretation::NonFunction, "NON_FUNCTION"),
            (MsCInterpretation::FunctionIfExists, "FUNCTION_IF_EXISTS"),
        ] {
            assert_eq!(v.name(), n);
            assert_eq!(MsCInterpretation::value_of(n), Some(v));
        }
        assert_eq!(MsCInterpretation::value_of("Function"), None);
    }
}
