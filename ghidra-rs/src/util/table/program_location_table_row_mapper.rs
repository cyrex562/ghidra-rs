//! Port of `ghidra.util.table.ProgramLocationTableRowMapper`.

use std::sync::Arc;

use crate::util::seam_stubs::{DynamicTableColumn, MappedProgramLocationTableColumn, TableRowMapper};

/// An interface that allows implementors to map an object of one type to another. This is
/// useful for table models whose row type is easily converted to a more generic type -- for
/// example, the Bookmarks table model's data is based on `Bookmark` objects, which are easily
/// converted to `ProgramLocation`s and `Address`es. Creating a mapper for such types lets the
/// table model show dynamic columns that work on `ProgramLocation`s and `Address`es.
///
/// This is an extension of [`TableRowMapper`] that has knowledge of
/// [`ProgramLocationTableColumn`](crate::util::table::field::program_location_table_column::ProgramLocationTableColumn)s,
/// meaning it knows how to generate `ProgramLocation`s. This is the preferred mapper to use with
/// tables that work on program data, as it means the column works with navigation.
///
/// Port of `ghidra.util.table.ProgramLocationTableRowMapper`.
///
/// NOTE: as in the Java original, real implementors' type names must end in `TableRowMapper` for
/// Ghidra's `ClassSearcher` extension-point discovery to find them.
pub trait ProgramLocationTableRowMapper<ROW_TYPE, EXPECTED_ROW_TYPE>:
    TableRowMapper<ROW_TYPE, EXPECTED_ROW_TYPE> + Send + Sync
{
    /// Creates a table column that maps the given `ROW_TYPE` to the type of the column passed
    /// in, the `EXPECTED_ROW_TYPE`.
    ///
    /// When `destination_column` is also a
    /// [`ProgramLocationTableColumn`](crate::util::table::field::program_location_table_column::ProgramLocationTableColumn),
    /// the returned column knows how to compute `ProgramLocation`s too (mirroring the Java
    /// override, which wraps it in a `MappedProgramLocationTableColumn`); otherwise this would
    /// fall back to the plain [`TableRowMapper`] mapping (not yet implementable, since
    /// `MappedTableColumn` is not ported).
    fn create_mapped_table_column<COLUMN_TYPE>(
        self: Arc<Self>,
        destination_column: Box<dyn DynamicTableColumn<EXPECTED_ROW_TYPE, COLUMN_TYPE>>,
    ) -> Box<dyn DynamicTableColumn<ROW_TYPE, COLUMN_TYPE>>
    where
        Self: Sized + 'static,
        ROW_TYPE: 'static,
        EXPECTED_ROW_TYPE: 'static,
        COLUMN_TYPE: 'static,
    {
        Box::new(MappedProgramLocationTableColumn {
            mapper: self,
            table_column: destination_column,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::framework::plugintool::service_provider::ServiceProvider;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::program::Program;
    use crate::program::util::program_location::ProgramLocation;

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock_program".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    struct MockSettings;
    impl Settings for MockSettings {
        fn is_immutable_settings(&self) -> bool {
            false
        }
    }

    struct MockServiceProvider;
    impl ServiceProvider for MockServiceProvider {
        fn get_service(&self, _service_class: &str) -> Option<Box<dyn std::any::Any + Send + Sync>> {
            None
        }
        fn add_service_listener(&mut self, _listener: Box<dyn crate::framework::plugintool::ServiceListener>) {
        }
        fn remove_service_listener(&mut self, _listener: Box<dyn crate::framework::plugintool::ServiceListener>) {
        }
    }

    struct MockProgramLocation {
        address: Address,
    }

    impl ProgramLocation for MockProgramLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_byte_address(&self) -> Address {
            self.address.clone()
        }
    }

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, offset)
    }

    /// Maps a bookmark id (`i32`) to a synthetic address label, mirroring how a real
    /// `BookmarkRowObjectToProgramLocationTableRowMapper` would map a `Bookmark` to an `Address`.
    struct BookmarkIdToAddressLabelMapper;

    impl TableRowMapper<i32, String> for BookmarkIdToAddressLabelMapper {
        fn map(&self, row_object: &i32, _data: &dyn Program, _service_provider: &dyn ServiceProvider) -> String {
            format!("addr:{:#x}", *row_object as u64 * 0x1000)
        }
    }

    impl ProgramLocationTableRowMapper<i32, String> for BookmarkIdToAddressLabelMapper {}

    /// A destination column keyed on the mapped `String` address label -- the "existing column,
    /// based upon EXPECTED_ROW_TYPE" from the Java doc comment.
    struct AddressLabelColumn;

    impl crate::util::table::field::program_based_dynamic_table_column::ProgramBasedDynamicTableColumn
        for AddressLabelColumn
    {
    }

    impl crate::util::table::field::program_location_table_column::ProgramLocationTableColumn<String, String>
        for AddressLabelColumn
    {
        fn get_program_location(
            &self,
            row_object: &String,
            _settings: &dyn Settings,
            _program: &dyn Program,
            _service_provider: &dyn ServiceProvider,
        ) -> Box<dyn ProgramLocation> {
            let offset = i64::from_str_radix(row_object.trim_start_matches("addr:0x"), 16).unwrap();
            Box::new(MockProgramLocation {
                address: ram_address(offset),
            })
        }
    }

    impl DynamicTableColumn<String, String> for AddressLabelColumn {
        fn as_program_location_table_column(
            &self,
        ) -> Option<
            &dyn crate::util::table::field::program_location_table_column::ProgramLocationTableColumn<
                String,
                String,
            >,
        > {
            Some(self)
        }
    }

    #[test]
    fn create_mapped_table_column_delegates_through_mapper_then_destination_column() {
        let mapper = Arc::new(BookmarkIdToAddressLabelMapper);
        let destination: Box<dyn DynamicTableColumn<String, String>> =
            Box::new(AddressLabelColumn);

        let mapped_column = mapper.create_mapped_table_column(destination);

        let program = MockProgram;
        let settings = MockSettings;
        let provider = MockServiceProvider;

        // Bookmark id 5 maps to "addr:0x5000" (via BookmarkIdToAddressLabelMapper::map), which
        // AddressLabelColumn::get_program_location then parses back into a ram address -- the
        // same two-step delegation `MappedProgramLocationTableColumn.getProgramLocation` performs
        // in Java (`mapper.map(...)` then `tableColumn.getProgramLocation(...)`).
        let location = mapped_column
            .as_program_location_table_column()
            .expect("destination column was a ProgramLocationTableColumn")
            .get_program_location(&5, &settings, &program, &provider);

        assert_eq!(location.get_address().offset(), 0x5000);
        assert_eq!(location.get_address().space().name(), "ram");
    }
}
