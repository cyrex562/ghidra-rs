use std::fmt;

/// Tracks conditional preprocessing state during Sleigh grammar parsing.
///
/// Mirrors `ghidra.sleigh.grammar.ConditionalHelper`, which holds the four boolean
/// flags used by the preprocessor to manage `@if`/`@else`/`@endif` directives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionalHelper {
    inif: bool,
    sawelse: bool,
    handled: bool,
    copy: bool,
}

impl ConditionalHelper {
    pub fn new(inif: bool, sawelse: bool, handled: bool, copy: bool) -> Self {
        Self { inif, sawelse, handled, copy }
    }

    pub fn inif(&self) -> bool {
        self.inif
    }

    pub fn set_inif(&mut self, inif: bool) {
        self.inif = inif;
    }

    pub fn sawelse(&self) -> bool {
        self.sawelse
    }

    pub fn set_sawelse(&mut self, sawelse: bool) {
        self.sawelse = sawelse;
    }

    pub fn handled(&self) -> bool {
        self.handled
    }

    pub fn set_handled(&mut self, handled: bool) {
        self.handled = handled;
    }

    pub fn copy(&self) -> bool {
        self.copy
    }

    pub fn set_copy(&mut self, copy: bool) {
        self.copy = copy;
    }
}

impl fmt::Display for ConditionalHelper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{{}:{}:{}:{}}}",
            if self.inif { "inif" } else { "!inif" },
            if self.sawelse { "sawelse" } else { "!sawelse" },
            if self.handled { "handled" } else { "!handled" },
            if self.copy { "copy" } else { "!copy" },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_sets_all_fields() {
        let h = ConditionalHelper::new(true, false, true, false);
        assert!(h.inif());
        assert!(!h.sawelse());
        assert!(h.handled());
        assert!(!h.copy());
    }

    #[test]
    fn setters_mutate_fields() {
        let mut h = ConditionalHelper::new(false, false, false, false);
        h.set_inif(true);
        h.set_sawelse(true);
        h.set_handled(true);
        h.set_copy(true);
        assert!(h.inif());
        assert!(h.sawelse());
        assert!(h.handled());
        assert!(h.copy());
    }

    #[test]
    fn display_all_true() {
        let h = ConditionalHelper::new(true, true, true, true);
        assert_eq!(h.to_string(), "{inif:sawelse:handled:copy}");
    }

    #[test]
    fn display_all_false() {
        let h = ConditionalHelper::new(false, false, false, false);
        assert_eq!(h.to_string(), "{!inif:!sawelse:!handled:!copy}");
    }

    #[test]
    fn display_mixed() {
        let h = ConditionalHelper::new(true, false, true, false);
        assert_eq!(h.to_string(), "{inif:!sawelse:handled:!copy}");
    }

    #[test]
    fn equality() {
        let a = ConditionalHelper::new(true, false, true, false);
        let b = ConditionalHelper::new(true, false, true, false);
        let c = ConditionalHelper::new(false, false, false, false);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn clone_is_independent() {
        let a = ConditionalHelper::new(true, true, false, false);
        let mut b = a.clone();
        b.set_inif(false);
        assert!(a.inif());
        assert!(!b.inif());
    }
}
