use crate::program::model::data::isf::IsfObject;
use crate::program::model::symbol::Equate;

/// Represents an extended equate for SARIF export.
///
/// Mirrors `ExtEquate` from Ghidra's `sarif.export.equates` package.
pub struct ExtEquate {
    pub name: String,
    pub value: i64,
}

impl ExtEquate {
    /// Creates a new `ExtEquate` from an `Equate`.
    pub fn new(equate: &dyn Equate) -> Self {
        Self {
            name: equate.name().to_string(),
            value: equate.value(),
        }
    }
}

impl IsfObject for ExtEquate {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::symbol::SimpleEquate;

    #[test]
    fn creates_ext_equate_from_simple_equate() {
        let equate = SimpleEquate::new("FLAG", 0x80).unwrap();
        let ext_equate = ExtEquate::new(&equate);

        assert_eq!(ext_equate.name, "FLAG");
        assert_eq!(ext_equate.value, 0x80);
    }

    #[test]
    fn preserves_equate_name_and_value() {
        let equate = SimpleEquate::new("MY_CONST", 42).unwrap();
        let ext_equate = ExtEquate::new(&equate);

        assert_eq!(ext_equate.name, "MY_CONST");
        assert_eq!(ext_equate.value, 42);
    }

    #[test]
    fn handles_negative_values() {
        let equate = SimpleEquate::new("NEG_VALUE", -100).unwrap();
        let ext_equate = ExtEquate::new(&equate);

        assert_eq!(ext_equate.name, "NEG_VALUE");
        assert_eq!(ext_equate.value, -100);
    }

    #[test]
    fn handles_zero_value() {
        let equate = SimpleEquate::new("ZERO", 0).unwrap();
        let ext_equate = ExtEquate::new(&equate);

        assert_eq!(ext_equate.name, "ZERO");
        assert_eq!(ext_equate.value, 0);
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let equate = SimpleEquate::new("TEST", 123).unwrap();
        let ext_equate = ExtEquate::new(&equate);
        accepts_isf_object(&ext_equate);
    }

    #[test]
    fn handles_large_values() {
        let equate = SimpleEquate::new("LARGE", i64::MAX).unwrap();
        let ext_equate = ExtEquate::new(&equate);

        assert_eq!(ext_equate.name, "LARGE");
        assert_eq!(ext_equate.value, i64::MAX);
    }

    #[test]
    fn handles_large_negative_values() {
        let equate = SimpleEquate::new("VERY_NEG", i64::MIN).unwrap();
        let ext_equate = ExtEquate::new(&equate);

        assert_eq!(ext_equate.name, "VERY_NEG");
        assert_eq!(ext_equate.value, i64::MIN);
    }
}
