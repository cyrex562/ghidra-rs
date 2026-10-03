//! Port of `ghidra.app.plugin.core.commentwindow.CommentRowObjectToAddressTableRowMapper`.

use crate::framework::plugintool::service_provider::ServiceProvider;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::util::seam_stubs::TableRowMapper;
use crate::util::table::ProgramLocationTableRowMapper;

use super::CommentRowObject;

/// Maps a [`CommentRowObject`] to its [`Address`], letting columns designed for address tables
/// be reused by the Comment Window.
///
/// Port of `ghidra.app.plugin.core.commentwindow.CommentRowObjectToAddressTableRowMapper`, which
/// `extends ProgramLocationTableRowMapper<CommentRowObject, Address>`. As with the other
/// row-mapper ports (e.g.
/// [`SymbolToAddressTableRowMapper`](crate::util::table::mapper::SymbolToAddressTableRowMapper)),
/// the Java `extends` becomes implementing [`TableRowMapper`] plus a blanket, field-less impl of
/// [`ProgramLocationTableRowMapper`] to pick up its default methods.
///
/// NOTE: as in the Java original, real implementors' type names must end in `TableRowMapper` for
/// Ghidra's `ClassSearcher` extension-point discovery to find them.
pub struct CommentRowObjectToAddressTableRowMapper;

impl TableRowMapper<CommentRowObject, Address> for CommentRowObjectToAddressTableRowMapper {
    fn map(
        &self,
        row_object: &CommentRowObject,
        _data: &dyn Program,
        _service_provider: &dyn ServiceProvider,
    ) -> Address {
        row_object.address().clone()
    }
}

impl ProgramLocationTableRowMapper<CommentRowObject, Address>
    for CommentRowObjectToAddressTableRowMapper
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::plugintool::ServiceListener;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::CommentType;

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

    struct MockServiceProvider;
    impl ServiceProvider for MockServiceProvider {
        fn get_service(&self, _service_class: &str) -> Option<Box<dyn std::any::Any + Send + Sync>> {
            None
        }
        fn add_service_listener(&mut self, _listener: Box<dyn ServiceListener>) {}
        fn remove_service_listener(&mut self, _listener: Box<dyn ServiceListener>) {}
    }

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, offset)
    }

    #[test]
    fn map_returns_comment_row_object_address() {
        let mapper = CommentRowObjectToAddressTableRowMapper;
        let row = CommentRowObject::new(ram_address(0x400), CommentType::Eol);
        let program = MockProgram;
        let provider = MockServiceProvider;

        let mapped = mapper.map(&row, &program, &provider);

        assert_eq!(mapped, ram_address(0x400));
    }

    #[test]
    fn different_comment_types_at_same_address_map_to_same_address() {
        let mapper = CommentRowObjectToAddressTableRowMapper;
        let program = MockProgram;
        let provider = MockServiceProvider;

        let eol = CommentRowObject::new(ram_address(0x800), CommentType::Eol);
        let pre = CommentRowObject::new(ram_address(0x800), CommentType::Pre);

        assert_eq!(mapper.map(&eol, &program, &provider), ram_address(0x800));
        assert_eq!(mapper.map(&pre, &program, &provider), ram_address(0x800));
    }
}
