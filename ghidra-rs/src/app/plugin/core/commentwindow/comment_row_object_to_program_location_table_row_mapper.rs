//! Port of `ghidra.app.plugin.core.commentwindow.CommentRowObjectToProgramLocationTableRowMapper`.

use std::sync::Arc;

use crate::framework::plugintool::service_provider::ServiceProvider;
use crate::program::model::listing::program::Program;
use crate::program::util::program_location::ProgramLocation;
use crate::util::seam_stubs::TableRowMapper;
use crate::util::table::ProgramLocationTableRowMapper;

use super::CommentRowObject;

/// A minimal, owned snapshot of the two [`Program`] accessors every implementor is guaranteed to
/// have (`get_name`/`get_language_id`), used to back [`MappedProgramLocation::get_program`].
///
/// Same approach as
/// [`ScalarRowObjectToProgramLocationTableRowMapper`](crate::app::plugin::core::scalartable::scalar_row_object_to_program_location_table_row_mapper::ScalarRowObjectToProgramLocationTableRowMapper)'s
/// own `ProgramSnapshot`: [`TableRowMapper::map`]'s `data` parameter is `&dyn Program` --
/// borrowed, not `'static` -- while [`ProgramLocation::get_program`] must return an owned
/// `Arc<dyn Program>`, and there is no way to recover an existing `Arc<dyn Program>` from a bare
/// `&dyn Program` without `unsafe`.
struct ProgramSnapshot {
    name: String,
    language_id: String,
}

impl crate::framework::model::DomainObject for ProgramSnapshot {}

impl Program for ProgramSnapshot {
    fn get_name(&self) -> String {
        self.name.clone()
    }
    fn get_language_id(&self) -> String {
        self.language_id.clone()
    }
}

/// The `new ProgramLocation(program, address)` this mapper's `map` builds.
struct MappedProgramLocation {
    program: Arc<dyn Program>,
    address: crate::program::model::address::Address,
}

impl ProgramLocation for MappedProgramLocation {
    fn get_program(&self) -> Arc<dyn Program> {
        Arc::clone(&self.program)
    }
    fn get_address(&self) -> crate::program::model::address::Address {
        self.address.clone()
    }
    fn get_byte_address(&self) -> crate::program::model::address::Address {
        self.address.clone()
    }
}

/// This allows columns designed for Program Location tables to be used by the Comment Window.
///
/// Port of `ghidra.app.plugin.core.commentwindow.CommentRowObjectToProgramLocationTableRowMapper`,
/// which `extends ProgramLocationTableRowMapper<CommentRowObject, ProgramLocation>`. As with this
/// crate's other row-mapper ports (e.g.
/// [`ScalarRowObjectToProgramLocationTableRowMapper`](crate::app::plugin::core::scalartable::scalar_row_object_to_program_location_table_row_mapper::ScalarRowObjectToProgramLocationTableRowMapper)),
/// the Java `extends` becomes implementing [`TableRowMapper`] plus a blanket, field-less impl of
/// [`ProgramLocationTableRowMapper`] to pick up its default methods.
///
/// NOTE: as in the Java original, real implementors' type names must end in `TableRowMapper` for
/// Ghidra's `ClassSearcher` extension-point discovery to find them.
pub struct CommentRowObjectToProgramLocationTableRowMapper;

impl TableRowMapper<CommentRowObject, Box<dyn ProgramLocation>>
    for CommentRowObjectToProgramLocationTableRowMapper
{
    fn map(
        &self,
        row_object: &CommentRowObject,
        data: &dyn Program,
        _service_provider: &dyn ServiceProvider,
    ) -> Box<dyn ProgramLocation> {
        let program: Arc<dyn Program> = Arc::new(ProgramSnapshot {
            name: Program::get_name(data),
            language_id: data.get_language_id(),
        });
        Box::new(MappedProgramLocation { program, address: row_object.address().clone() })
    }
}

impl ProgramLocationTableRowMapper<CommentRowObject, Box<dyn ProgramLocation>>
    for CommentRowObjectToProgramLocationTableRowMapper
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::plugintool::ServiceListener;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
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
    fn map_returns_a_program_location_over_the_row_objects_address() {
        let mapper = CommentRowObjectToProgramLocationTableRowMapper;
        let row = CommentRowObject::new(ram_address(0x400), CommentType::Eol);
        let program = MockProgram;
        let provider = MockServiceProvider;

        let location = mapper.map(&row, &program, &provider);

        assert_eq!(location.get_address(), ram_address(0x400));
        assert_eq!(location.get_byte_address(), ram_address(0x400));
    }

    #[test]
    fn mapped_locations_program_carries_the_source_programs_identity() {
        let mapper = CommentRowObjectToProgramLocationTableRowMapper;
        let row = CommentRowObject::new(ram_address(0x10), CommentType::Pre);
        let program = MockProgram;
        let provider = MockServiceProvider;

        let location = mapper.map(&row, &program, &provider);

        let mapped_program = location.get_program();
        assert_eq!(Program::get_name(mapped_program.as_ref()), "mock_program");
        assert_eq!(mapped_program.get_language_id(), "mock:LE:32:default");
    }

    #[test]
    fn different_comment_types_at_same_address_map_to_the_same_location() {
        let mapper = CommentRowObjectToProgramLocationTableRowMapper;
        let program = MockProgram;
        let provider = MockServiceProvider;

        let eol = CommentRowObject::new(ram_address(0x800), CommentType::Eol);
        let pre = CommentRowObject::new(ram_address(0x800), CommentType::Pre);

        assert_eq!(mapper.map(&eol, &program, &provider).get_address(), ram_address(0x800));
        assert_eq!(mapper.map(&pre, &program, &provider).get_address(), ram_address(0x800));
    }
}
