//! Port of `ghidra.app.tablechooser.AddressableRowObjectToProgramLocationTableRowMapper`.

use std::sync::Arc;

use crate::app::tablechooser::AddressableRowObject;
use crate::framework::plugintool::service_provider::ServiceProvider;
use crate::program::model::address::Address;
use crate::program::model::listing::program::Program;
use crate::program::util::program_location::ProgramLocation;
use crate::util::seam_stubs::TableRowMapper;
use crate::util::table::ProgramLocationTableRowMapper;

/// A minimal, owned snapshot of the two [`Program`] accessors every implementor is guaranteed to
/// have (`get_name`/`get_language_id`), used to back [`MappedProgramLocation::get_program`].
///
/// [`TableRowMapper::map`]'s `data` parameter is `&dyn Program` -- borrowed, not `'static` --
/// while [`ProgramLocation::get_program`] must return an owned `Arc<dyn Program>`. There is no
/// way to recover an existing `Arc<dyn Program>` from a bare `&dyn Program` (that would need
/// `unsafe`, e.g. `Arc::from_raw` on a pointer nothing guarantees came from an `Arc` in the first
/// place), so this snapshot captures what *can* be captured -- the identity strings -- rather
/// than the original `Program` object itself. This means the returned location's
/// `get_program()` is not reference-equal to the `Program` `map` was called with; every other
/// accessor (`get_address_factory`, `get_memory`, ...) falls back to this crate's `Program`
/// trait defaults (`None`) on the snapshot. Real callers that need those should get the program
/// from elsewhere (e.g. the tool's current program), the same way Java callers already must once
/// they only hold a `ProgramLocation` rather than the original `Program` reference.
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

/// The `new ProgramLocation(program, address)` this mapper's `map` builds. Mirrors the same
/// approach as
/// [`generate_program_location`](crate::feature::base::memsearch::bytesource::addressable_byte_source::generate_program_location)'s
/// `SimpleProgramLocation` and
/// [`AbstractUnwoundFrame`](crate::app::plugin::core::debug::stack::abstract_unwound_frame)'s
/// `FrameProgramLocation`: the base two-argument Java constructor code-unit-aligns `addr` via
/// `getCodeUnitAddress(program, addr)` before storing it (with the original, unaligned address
/// kept as `byteAddr`); that alignment needs `Listing.getCodeUnitContaining`, which requires
/// mutable/database access this trait's `map` (given only `&dyn Program`) does not have, so (as
/// with those other two ports) `address` and `byte_address` are simply the same, unaligned value
/// here.
struct MappedProgramLocation {
    program: Arc<dyn Program>,
    address: Address,
}

impl ProgramLocation for MappedProgramLocation {
    fn get_program(&self) -> Arc<dyn Program> {
        Arc::clone(&self.program)
    }
    fn get_address(&self) -> Address {
        self.address.clone()
    }
    fn get_byte_address(&self) -> Address {
        self.address.clone()
    }
}

/// Maps an [`AddressableRowObject`] row object to a [`ProgramLocation`] over its [`Address`],
/// letting columns designed for program-location tables be reused by any table whose rows are
/// addressable.
///
/// Port of `ghidra.app.tablechooser.AddressableRowObjectToProgramLocationTableRowMapper`, which
/// `extends ProgramLocationTableRowMapper<AddressableRowObject, ProgramLocation>`. As with this
/// crate's other row-mapper ports (e.g.
/// [`SymbolToAddressTableRowMapper`](crate::util::table::mapper::SymbolToAddressTableRowMapper)),
/// the Java `extends` becomes implementing [`TableRowMapper`] plus a blanket, field-less impl of
/// [`ProgramLocationTableRowMapper`] to pick up its default methods.
///
/// NOTE: as in the Java original, real implementors' type names must end in `TableRowMapper` for
/// Ghidra's `ClassSearcher` extension-point discovery to find them.
pub struct AddressableRowObjectToProgramLocationTableRowMapper;

impl TableRowMapper<Arc<dyn AddressableRowObject>, Box<dyn ProgramLocation>>
    for AddressableRowObjectToProgramLocationTableRowMapper
{
    fn map(
        &self,
        row_object: &Arc<dyn AddressableRowObject>,
        data: &dyn Program,
        _service_provider: &dyn ServiceProvider,
    ) -> Box<dyn ProgramLocation> {
        let program: Arc<dyn Program> = Arc::new(ProgramSnapshot {
            name: Program::get_name(data),
            language_id: data.get_language_id(),
        });
        Box::new(MappedProgramLocation { program, address: row_object.get_address().clone() })
    }
}

impl ProgramLocationTableRowMapper<Arc<dyn AddressableRowObject>, Box<dyn ProgramLocation>>
    for AddressableRowObjectToProgramLocationTableRowMapper
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::plugintool::ServiceListener;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

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

    struct MockRowObject {
        address: Address,
    }
    impl AddressableRowObject for MockRowObject {
        fn get_address(&self) -> &Address {
            &self.address
        }
    }

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, offset)
    }

    #[test]
    fn map_returns_a_program_location_over_the_row_objects_address() {
        let mapper = AddressableRowObjectToProgramLocationTableRowMapper;
        let row_object: Arc<dyn AddressableRowObject> = Arc::new(MockRowObject { address: ram_address(0x5000) });
        let program = MockProgram;
        let provider = MockServiceProvider;

        let location = mapper.map(&row_object, &program, &provider);

        assert_eq!(location.get_address(), ram_address(0x5000));
        assert_eq!(location.get_byte_address(), ram_address(0x5000));
    }

    #[test]
    fn mapped_locations_program_carries_the_source_programs_identity() {
        let mapper = AddressableRowObjectToProgramLocationTableRowMapper;
        let row_object: Arc<dyn AddressableRowObject> = Arc::new(MockRowObject { address: ram_address(0x10) });
        let program = MockProgram;
        let provider = MockServiceProvider;

        let location = mapper.map(&row_object, &program, &provider);

        let mapped_program = location.get_program();
        assert_eq!(Program::get_name(mapped_program.as_ref()), "mock_program");
        assert_eq!(mapped_program.get_language_id(), "mock:LE:32:default");
    }

    #[test]
    fn different_row_objects_map_to_their_own_locations() {
        let mapper = AddressableRowObjectToProgramLocationTableRowMapper;
        let program = MockProgram;
        let provider = MockServiceProvider;

        let a: Arc<dyn AddressableRowObject> = Arc::new(MockRowObject { address: ram_address(0x100) });
        let b: Arc<dyn AddressableRowObject> = Arc::new(MockRowObject { address: ram_address(0x200) });

        assert_eq!(mapper.map(&a, &program, &provider).get_address(), ram_address(0x100));
        assert_eq!(mapper.map(&b, &program, &provider).get_address(), ram_address(0x200));
    }
}
