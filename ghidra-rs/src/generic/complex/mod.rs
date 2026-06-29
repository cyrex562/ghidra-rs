use std::fmt;

/// A complex number `a + bi`.
///
/// Mirrors `generic.complex.Complex` from Ghidra. This type supports only storage and
/// display; it provides no arithmetic operations and does not implement [`PartialOrd`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Complex {
    pub real: f64,
    pub imaginary: f64,
}

impl Complex {
    /// Creates a new complex number with the given `real` and `imaginary` components.
    pub fn new(real: f64, imaginary: f64) -> Self {
        Self { real, imaginary }
    }

    /// Returns the real component.
    pub fn get_real(&self) -> f64 {
        self.real
    }

    /// Returns the imaginary component.
    pub fn get_imaginary(&self) -> f64 {
        self.imaginary
    }
}

impl fmt::Display for Complex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} + {}i", self.real, self.imaginary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_complex() {
        let c = Complex::new(1.0, 2.0);
        assert_eq!(c.real, 1.0);
        assert_eq!(c.imaginary, 2.0);
        assert_eq!(format!("{}", c), "1 + 2i");
    }

    #[test]
    fn test_getters() {
        let c = Complex::new(3.5, -1.5);
        assert_eq!(c.get_real(), 3.5);
        assert_eq!(c.get_imaginary(), -1.5);
    }

    #[test]
    fn test_zero() {
        let c = Complex::new(0.0, 0.0);
        assert_eq!(c.get_real(), 0.0);
        assert_eq!(c.get_imaginary(), 0.0);
        assert_eq!(format!("{}", c), "0 + 0i");
    }

    #[test]
    fn test_equality() {
        let a = Complex::new(1.0, 2.0);
        let b = Complex::new(1.0, 2.0);
        let c = Complex::new(1.0, 3.0);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_copy() {
        let a = Complex::new(5.0, 6.0);
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn test_display_fractional() {
        let c = Complex::new(1.5, 2.5);
        assert_eq!(format!("{}", c), "1.5 + 2.5i");
    }
}
