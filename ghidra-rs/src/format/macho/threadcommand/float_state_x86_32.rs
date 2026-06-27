/// x86-32 floating-point thread state.
///
/// Mirrors Ghidra's `FloatStateX86_32`, which is defined as an empty marker class
/// in the Mach-O thread-command package.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FloatStateX86_32;

impl FloatStateX86_32 {
    /// Creates a new `FloatStateX86_32`.
    pub fn new() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_equals_new() {
        assert_eq!(FloatStateX86_32::default(), FloatStateX86_32::new());
    }

    #[test]
    fn debug_impl_exists() {
        let s = format!("{:?}", FloatStateX86_32::new());
        assert!(s.contains("FloatStateX86_32"));
    }

    #[test]
    fn clone_equals_original() {
        let a = FloatStateX86_32::new();
        let b = a;
        assert_eq!(a, b);
    }
}
