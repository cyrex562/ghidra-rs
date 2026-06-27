use once_cell::sync::Lazy;
use regex::Regex;

/// Classification of a Go symbol name.
///
/// Mirrors Ghidra's `GoSymbolNameType` Java enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GoSymbolNameType {
    Unknown,
    Func,
    MethodWrapper,
    /// Anonymous function (lambda).
    AnonFunc,
    DeferWrapper,
    GoWrapper,
    DataType,
}

static SUFFIX_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^.*?([a-z]+)[0-9]+(?:\.[0-9]+)?$").unwrap());

impl GoSymbolNameType {
    /// Returns `true` when this variant represents a closure
    /// (`AnonFunc`, `DeferWrapper`, or `GoWrapper`).
    pub fn is_closure(self) -> bool {
        matches!(self, Self::AnonFunc | Self::DeferWrapper | Self::GoWrapper)
    }

    /// Classifies a symbol name that may carry a dash suffix (e.g. `pkg.Type.Method-fm`).
    ///
    /// Returns [`GoSymbolNameType::MethodWrapper`] when `name` ends with `"-fm"`,
    /// otherwise [`GoSymbolNameType::Func`].
    pub fn from_name_with_dash_suffix(name: &str) -> Self {
        if name.ends_with("-fm") {
            Self::MethodWrapper
        } else {
            Self::Func
        }
    }

    /// Classifies a symbol from its suffix component.
    ///
    /// `None` is treated the same as a missing suffix and returns [`GoSymbolNameType::Func`].
    /// An unrecognised suffix returns [`GoSymbolNameType::Unknown`].
    pub fn from_name_suffix(suffix: Option<&str>) -> Self {
        let suffix = match suffix {
            None => return Self::Func,
            Some(s) => s,
        };
        match SUFFIX_RE.captures(suffix) {
            Some(caps) => match &caps[1] {
                "func" => Self::AnonFunc,
                "deferwrap" => Self::DeferWrapper,
                "gowrap" => Self::GoWrapper,
                _ => Self::Unknown,
            },
            None => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::GoSymbolNameType;

    // --- is_closure ---

    #[test]
    fn anon_func_is_closure() {
        assert!(GoSymbolNameType::AnonFunc.is_closure());
    }

    #[test]
    fn defer_wrapper_is_closure() {
        assert!(GoSymbolNameType::DeferWrapper.is_closure());
    }

    #[test]
    fn go_wrapper_is_closure() {
        assert!(GoSymbolNameType::GoWrapper.is_closure());
    }

    #[test]
    fn non_closure_variants() {
        for v in [
            GoSymbolNameType::Unknown,
            GoSymbolNameType::Func,
            GoSymbolNameType::MethodWrapper,
            GoSymbolNameType::DataType,
        ] {
            assert!(!v.is_closure(), "{v:?} should not be a closure");
        }
    }

    // --- from_name_with_dash_suffix ---

    #[test]
    fn dash_fm_suffix_yields_method_wrapper() {
        assert_eq!(
            GoSymbolNameType::from_name_with_dash_suffix("pkg.Type.Method-fm"),
            GoSymbolNameType::MethodWrapper,
        );
    }

    #[test]
    fn no_dash_fm_yields_func() {
        assert_eq!(
            GoSymbolNameType::from_name_with_dash_suffix("pkg.Func"),
            GoSymbolNameType::Func,
        );
    }

    #[test]
    fn exact_dash_fm_yields_method_wrapper() {
        assert_eq!(
            GoSymbolNameType::from_name_with_dash_suffix("-fm"),
            GoSymbolNameType::MethodWrapper,
        );
    }

    // --- from_name_suffix ---

    #[test]
    fn none_suffix_yields_func() {
        assert_eq!(GoSymbolNameType::from_name_suffix(None), GoSymbolNameType::Func);
    }

    #[test]
    fn func_suffix_yields_anon_func() {
        assert_eq!(
            GoSymbolNameType::from_name_suffix(Some("func1")),
            GoSymbolNameType::AnonFunc,
        );
    }

    #[test]
    fn func_suffix_with_dot_yields_anon_func() {
        assert_eq!(
            GoSymbolNameType::from_name_suffix(Some("func1.1")),
            GoSymbolNameType::AnonFunc,
        );
    }

    #[test]
    fn deferwrap_suffix_yields_defer_wrapper() {
        assert_eq!(
            GoSymbolNameType::from_name_suffix(Some("deferwrap1")),
            GoSymbolNameType::DeferWrapper,
        );
    }

    #[test]
    fn gowrap_suffix_yields_go_wrapper() {
        assert_eq!(
            GoSymbolNameType::from_name_suffix(Some("gowrap1")),
            GoSymbolNameType::GoWrapper,
        );
    }

    #[test]
    fn unrecognised_suffix_yields_unknown() {
        assert_eq!(
            GoSymbolNameType::from_name_suffix(Some("other1")),
            GoSymbolNameType::Unknown,
        );
    }

    #[test]
    fn no_trailing_digits_yields_unknown() {
        assert_eq!(
            GoSymbolNameType::from_name_suffix(Some("func")),
            GoSymbolNameType::Unknown,
        );
    }

    #[test]
    fn qualified_func_suffix_yields_anon_func() {
        // e.g. "pkg.Something.func1" — the suffix includes a dotted path prefix
        assert_eq!(
            GoSymbolNameType::from_name_suffix(Some("pkg.Something.func1")),
            GoSymbolNameType::AnonFunc,
        );
    }
}
