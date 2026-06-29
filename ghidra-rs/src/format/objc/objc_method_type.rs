/// Whether a method belongs to the class itself or to instances of the class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjcMethodType {
    /// Class method, indicated by `+`.
    Class,
    /// Instance method, indicated by `-`.
    Instance,
}

impl ObjcMethodType {
    /// Returns the single-character indicator used in Objective-C source notation.
    pub fn indicator(self) -> char {
        match self {
            Self::Class => '+',
            Self::Instance => '-',
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_indicator_is_plus() {
        assert_eq!(ObjcMethodType::Class.indicator(), '+');
    }

    #[test]
    fn instance_indicator_is_minus() {
        assert_eq!(ObjcMethodType::Instance.indicator(), '-');
    }

    #[test]
    fn variants_are_distinct() {
        assert_ne!(ObjcMethodType::Class, ObjcMethodType::Instance);
    }

    #[test]
    fn indicators_are_distinct() {
        assert_ne!(
            ObjcMethodType::Class.indicator(),
            ObjcMethodType::Instance.indicator(),
        );
    }
}
