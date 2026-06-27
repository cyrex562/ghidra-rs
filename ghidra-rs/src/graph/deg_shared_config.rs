/// Shared configuration state for data graph providers.
///
/// If any provider changes any of these values, that change takes effect for all. The last
/// writer wins.
#[derive(Debug, Clone, PartialEq)]
pub struct DegSharedConfig {
    navigate_in: bool,
    navigate_out: bool,
    show_popups: bool,
    use_compact_format: bool,
}

impl DegSharedConfig {
    pub fn new() -> Self {
        Self {
            navigate_in: false,
            navigate_out: true,
            show_popups: true,
            use_compact_format: true,
        }
    }

    pub fn is_navigate_in(&self) -> bool {
        self.navigate_in
    }

    pub fn set_navigate_in(&mut self, navigate_in: bool) {
        self.navigate_in = navigate_in;
    }

    pub fn is_navigate_out(&self) -> bool {
        self.navigate_out
    }

    pub fn set_navigate_out(&mut self, navigate_out: bool) {
        self.navigate_out = navigate_out;
    }

    pub fn is_show_popups(&self) -> bool {
        self.show_popups
    }

    pub fn set_show_popups(&mut self, show_popups: bool) {
        self.show_popups = show_popups;
    }

    pub fn use_compact_format(&self) -> bool {
        self.use_compact_format
    }

    pub fn set_compact_format(&mut self, use_compact_format: bool) {
        self.use_compact_format = use_compact_format;
    }
}

impl Default for DegSharedConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults() {
        let cfg = DegSharedConfig::default();
        assert!(!cfg.is_navigate_in());
        assert!(cfg.is_navigate_out());
        assert!(cfg.is_show_popups());
        assert!(cfg.use_compact_format());
    }

    #[test]
    fn test_set_navigate_in() {
        let mut cfg = DegSharedConfig::default();
        cfg.set_navigate_in(true);
        assert!(cfg.is_navigate_in());
        cfg.set_navigate_in(false);
        assert!(!cfg.is_navigate_in());
    }

    #[test]
    fn test_set_navigate_out() {
        let mut cfg = DegSharedConfig::default();
        cfg.set_navigate_out(false);
        assert!(!cfg.is_navigate_out());
        cfg.set_navigate_out(true);
        assert!(cfg.is_navigate_out());
    }

    #[test]
    fn test_set_show_popups() {
        let mut cfg = DegSharedConfig::default();
        cfg.set_show_popups(false);
        assert!(!cfg.is_show_popups());
        cfg.set_show_popups(true);
        assert!(cfg.is_show_popups());
    }

    #[test]
    fn test_set_compact_format() {
        let mut cfg = DegSharedConfig::default();
        cfg.set_compact_format(false);
        assert!(!cfg.use_compact_format());
        cfg.set_compact_format(true);
        assert!(cfg.use_compact_format());
    }

    #[test]
    fn test_last_writer_wins_independence() {
        let mut cfg = DegSharedConfig::default();
        cfg.set_navigate_in(true);
        cfg.set_navigate_out(false);
        assert!(cfg.is_navigate_in());
        assert!(!cfg.is_navigate_out());
    }
}
