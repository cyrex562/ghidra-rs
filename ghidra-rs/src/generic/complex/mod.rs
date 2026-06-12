use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Complex {
    pub real: f64,
    pub imaginary: f64,
}

impl Complex {
    pub fn new(real: f64, imaginary: f64) -> Self {
        Self { real, imaginary }
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
}
