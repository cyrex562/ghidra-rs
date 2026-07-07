use crate::format::seam_stubs::AbstractMsType;

/// Trait for PDB Type Information (TPI) streams.
///
/// Corresponds to the Java interface
/// `ghidra.app.util.bin.format.pdb2.pdbreader.TPI`.
pub trait Tpi {
    /// Returns the minimum type index (inclusive) present in this stream.
    fn type_index_min(&self) -> i32;

    /// Returns the maximum type index (exclusive) present in this stream.
    fn type_index_max_exclusive(&self) -> i32;

    /// Random access of the [`AbstractMsType`] record indicated by `record_number`.
    fn get_random_access_record(&self, record_number: i32) -> Box<dyn AbstractMsType>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockMsType;
    impl AbstractMsType for MockMsType {}

    struct MockTpi;
    impl Tpi for MockTpi {
        fn type_index_min(&self) -> i32 {
            0x1000
        }

        fn type_index_max_exclusive(&self) -> i32 {
            0x2000
        }

        fn get_random_access_record(&self, _record_number: i32) -> Box<dyn AbstractMsType> {
            Box::new(MockMsType)
        }
    }

    #[test]
    fn mock_tpi_reports_type_index_bounds() {
        let tpi = MockTpi;
        assert_eq!(tpi.type_index_min(), 0x1000);
        assert_eq!(tpi.type_index_max_exclusive(), 0x2000);
    }

    #[test]
    fn mock_tpi_returns_random_access_record() {
        let tpi: Box<dyn Tpi> = Box::new(MockTpi);
        let _record = tpi.get_random_access_record(0x1005);
    }
}
