use crate::program::model::data::isf::IsfObject;
use crate::program::model::symbol::EquateReference;

/// Represents equate reference metadata extracted from an [`EquateReference`] for SARIF export.
///
/// Mirrors `ExtEquateReference` from Ghidra's `sarif.export.ref` package.
/// Captures the equate name, value, and operand index.
pub struct ExtEquateReference {
    pub name: String,
    pub op_index: i32,
    pub value: i64,
}

impl ExtEquateReference {
    /// Creates a new `ExtEquateReference` from an [`EquateReference`].
    ///
    /// Extracts the operand index from the reference and stores the provided
    /// name and value.
    pub fn new(reference: &dyn EquateReference, name: String, value: i64) -> Self {
        Self {
            name,
            op_index: reference.op_index() as i32,
            value,
        }
    }
}

impl IsfObject for ExtEquateReference {}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockEquateReference {
        op_index: i16,
    }

    impl EquateReference for MockEquateReference {
        fn address(&self) -> &crate::program::model::address::Address {
            unreachable!()
        }

        fn op_index(&self) -> i16 {
            self.op_index
        }

        fn dynamic_hash_value(&self) -> i64 {
            0
        }
    }

    #[test]
    fn stores_name_and_value() {
        let mock_ref = MockEquateReference { op_index: 2 };
        let ext_eq = ExtEquateReference::new(&mock_ref, "MY_EQUATE".to_string(), 0x1234);

        assert_eq!(ext_eq.name, "MY_EQUATE");
        assert_eq!(ext_eq.value, 0x1234);
        assert_eq!(ext_eq.op_index, 2);
    }

    #[test]
    fn extracts_op_index_from_reference() {
        let mock_ref = MockEquateReference { op_index: 5 };
        let ext_eq = ExtEquateReference::new(&mock_ref, "TEST".to_string(), 100);

        assert_eq!(ext_eq.op_index, 5);
    }

    #[test]
    fn handles_negative_op_index() {
        let mock_ref = MockEquateReference { op_index: -1 };
        let ext_eq = ExtEquateReference::new(&mock_ref, "NEG".to_string(), -50);

        assert_eq!(ext_eq.op_index, -1);
        assert_eq!(ext_eq.value, -50);
    }

    #[test]
    fn handles_empty_name() {
        let mock_ref = MockEquateReference { op_index: 0 };
        let ext_eq = ExtEquateReference::new(&mock_ref, String::new(), 0);

        assert!(ext_eq.name.is_empty());
        assert_eq!(ext_eq.op_index, 0);
    }

    #[test]
    fn handles_large_values() {
        let mock_ref = MockEquateReference { op_index: 100 };
        let ext_eq = ExtEquateReference::new(&mock_ref, "LARGE".to_string(), i64::MAX);

        assert_eq!(ext_eq.value, i64::MAX);
        assert_eq!(ext_eq.op_index, 100);
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}

        let mock_ref = MockEquateReference { op_index: 1 };
        let ext_eq = ExtEquateReference::new(&mock_ref, "ISF_TEST".to_string(), 42);
        accepts_isf_object(&ext_eq);
    }
}
