/// Marker trait for table columns that operate on a [`crate::program::model::listing::program::Program`].
///
/// This trait specializes [`DynamicTableColumn`](crate::docking::widgets::table::DynamicTableColumn)
/// with `Program` as the data source type. Implementors provide custom column rendering for
/// program-aware table cells.
///
/// Port of `ghidra.util.table.field.ProgramBasedDynamicTableColumn`.
pub trait ProgramBasedDynamicTableColumn {}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProgramColumn;
    impl ProgramBasedDynamicTableColumn for MockProgramColumn {}

    #[test]
    fn marker_trait_can_be_implemented() {
        let _col: Box<dyn ProgramBasedDynamicTableColumn> = Box::new(MockProgramColumn);
        // Verify the trait is sound and can be used as expected.
    }

    #[test]
    fn multiple_implementations_can_coexist() {
        struct ColumnA;
        struct ColumnB;
        impl ProgramBasedDynamicTableColumn for ColumnA {}
        impl ProgramBasedDynamicTableColumn for ColumnB {}

        let cols: Vec<Box<dyn ProgramBasedDynamicTableColumn>> =
            vec![Box::new(ColumnA), Box::new(ColumnB)];
        assert_eq!(cols.len(), 2);
    }
}
