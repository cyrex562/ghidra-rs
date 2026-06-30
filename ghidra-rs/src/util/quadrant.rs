/// Quadrant of an overlay image: upper-left, upper-right, lower-left, or lower-right.
///
/// Port of `resources.QUADRANT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quadrant {
    /// Upper-left (x=0, y=0).
    Ul,
    /// Upper-right (x=1, y=0).
    Ur,
    /// Lower-left (x=0, y=1).
    Ll,
    /// Lower-right (x=1, y=1).
    Lr,
}

impl Quadrant {
    /// Horizontal offset of this quadrant (0 = left, 1 = right).
    pub fn x(self) -> i32 {
        match self {
            Self::Ul | Self::Ll => 0,
            Self::Ur | Self::Lr => 1,
        }
    }

    /// Vertical offset of this quadrant (0 = top, 1 = bottom).
    pub fn y(self) -> i32 {
        match self {
            Self::Ul | Self::Ur => 0,
            Self::Ll | Self::Lr => 1,
        }
    }

    /// Parses a quadrant name case-insensitively, returning `default` when `s` is
    /// `None` or does not match a known variant name.
    ///
    /// Mirrors `QUADRANT.valueOf(String, QUADRANT)` from the Java source.
    pub fn from_str_or(s: Option<&str>, default: Self) -> Self {
        match s {
            None => default,
            Some(s) => match s.to_uppercase().as_str() {
                "UL" => Self::Ul,
                "UR" => Self::Ur,
                "LL" => Self::Ll,
                "LR" => Self::Lr,
                _ => default,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coordinates() {
        assert_eq!(Quadrant::Ul.x(), 0);
        assert_eq!(Quadrant::Ul.y(), 0);
        assert_eq!(Quadrant::Ur.x(), 1);
        assert_eq!(Quadrant::Ur.y(), 0);
        assert_eq!(Quadrant::Ll.x(), 0);
        assert_eq!(Quadrant::Ll.y(), 1);
        assert_eq!(Quadrant::Lr.x(), 1);
        assert_eq!(Quadrant::Lr.y(), 1);
    }

    #[test]
    fn from_str_or_valid() {
        let d = Quadrant::Ul;
        assert_eq!(Quadrant::from_str_or(Some("UL"), d), Quadrant::Ul);
        assert_eq!(Quadrant::from_str_or(Some("UR"), d), Quadrant::Ur);
        assert_eq!(Quadrant::from_str_or(Some("LL"), d), Quadrant::Ll);
        assert_eq!(Quadrant::from_str_or(Some("LR"), d), Quadrant::Lr);
    }

    #[test]
    fn from_str_or_case_insensitive() {
        let d = Quadrant::Lr;
        assert_eq!(Quadrant::from_str_or(Some("ul"), d), Quadrant::Ul);
        assert_eq!(Quadrant::from_str_or(Some("Ur"), d), Quadrant::Ur);
        assert_eq!(Quadrant::from_str_or(Some("lL"), d), Quadrant::Ll);
    }

    #[test]
    fn from_str_or_invalid_returns_default() {
        let d = Quadrant::Ur;
        assert_eq!(Quadrant::from_str_or(Some("invalid"), d), Quadrant::Ur);
        assert_eq!(Quadrant::from_str_or(Some(""), d), Quadrant::Ur);
    }

    #[test]
    fn from_str_or_none_returns_default() {
        assert_eq!(Quadrant::from_str_or(None, Quadrant::Ll), Quadrant::Ll);
    }

    #[test]
    fn derives() {
        let a = Quadrant::Lr;
        let b = a;
        assert_eq!(a, b);
        let _ = format!("{:?}", a);
    }
}
