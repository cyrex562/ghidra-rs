/// A write flag for target-associated emulator states.
///
/// Java equivalent: `ghidra.app.plugin.core.debug.service.emulation.Mode`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// The state can write the target directly.
    Rw,
    /// The state will never write the target.
    Ro,
}

impl Mode {
    /// Check if the mode permits writing the target.
    pub fn is_write_target(self) -> bool {
        matches!(self, Mode::Rw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rw_is_write_target() {
        assert!(Mode::Rw.is_write_target());
    }

    #[test]
    fn ro_is_not_write_target() {
        assert!(!Mode::Ro.is_write_target());
    }

    #[test]
    fn clone_and_eq() {
        assert_eq!(Mode::Rw, Mode::Rw.clone());
        assert_eq!(Mode::Ro, Mode::Ro.clone());
        assert_ne!(Mode::Rw, Mode::Ro);
    }

    #[test]
    fn copy_semantics() {
        let m = Mode::Rw;
        let n = m;
        assert_eq!(m, n);
    }
}
