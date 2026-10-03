//! Port of `ghidra.util.table.mapper.ReferenceToReferenceAddressPairTableRowMapper`.

use std::sync::Arc;

use crate::app::plugin::core::analysis::reference_address_pair::ReferenceAddressPair;
use crate::framework::plugintool::service_provider::ServiceProvider;
use crate::program::model::listing::program::Program;
use crate::program::model::symbol::Reference;
use crate::util::seam_stubs::TableRowMapper;
use crate::util::table::ProgramLocationTableRowMapper;

/// Maps a [`Reference`] to a [`ReferenceAddressPair`] of its from/to addresses, letting columns
/// designed for that pair type be reused by reference tables.
///
/// Port of `ghidra.util.table.mapper.ReferenceToReferenceAddressPairTableRowMapper`, which
/// `extends ProgramLocationTableRowMapper<Reference, ReferenceAddressPair>`. As with this crate's
/// other row-mapper ports (e.g.
/// [`SymbolToAddressTableRowMapper`](crate::util::table::mapper::SymbolToAddressTableRowMapper)),
/// the Java `extends` becomes implementing [`TableRowMapper`] plus a blanket, field-less impl of
/// [`ProgramLocationTableRowMapper`] to pick up its default methods.
///
/// NOTE: as in the Java original, real implementors' type names must end in `TableRowMapper` for
/// Ghidra's `ClassSearcher` extension-point discovery to find them.
pub struct ReferenceToReferenceAddressPairTableRowMapper;

impl TableRowMapper<Arc<dyn Reference>, ReferenceAddressPair>
    for ReferenceToReferenceAddressPairTableRowMapper
{
    fn map(
        &self,
        row_object: &Arc<dyn Reference>,
        _data: &dyn Program,
        _service_provider: &dyn ServiceProvider,
    ) -> ReferenceAddressPair {
        ReferenceAddressPair::new(Some(row_object.from_address()), Some(row_object.to_address()))
    }
}

impl ProgramLocationTableRowMapper<Arc<dyn Reference>, ReferenceAddressPair>
    for ReferenceToReferenceAddressPairTableRowMapper
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::plugintool::ServiceListener;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::RefType;

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

    struct MockReference {
        from: Address,
        to: Address,
    }
    impl Reference for MockReference {
        fn from_address(&self) -> Address {
            self.from.clone()
        }
        fn to_address(&self) -> Address {
            self.to.clone()
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn symbol_id(&self) -> i64 {
            -1
        }
        fn reference_type(&self) -> RefType {
            RefType::Data
        }
        fn operand_index(&self) -> i32 {
            0
        }
        fn is_mnemonic_reference(&self) -> bool {
            false
        }
        fn is_operand_reference(&self) -> bool {
            true
        }
        fn is_stack_reference(&self) -> bool {
            false
        }
        fn is_external_reference(&self) -> bool {
            false
        }
        fn is_entry_point_reference(&self) -> bool {
            false
        }
        fn is_memory_reference(&self) -> bool {
            true
        }
        fn is_register_reference(&self) -> bool {
            false
        }
        fn is_offset_reference(&self) -> bool {
            false
        }
        fn is_shifted_reference(&self) -> bool {
            false
        }
        fn source(&self) -> crate::program::model::symbol::SourceType {
            crate::program::model::symbol::SourceType::UserDefined
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, offset)
    }

    fn reference(from: i64, to: i64) -> Arc<dyn Reference> {
        Arc::new(MockReference { from: ram_address(from), to: ram_address(to) })
    }

    #[test]
    fn map_returns_a_pair_of_the_references_addresses() {
        let mapper = ReferenceToReferenceAddressPairTableRowMapper;
        let reference = reference(0x1000, 0x2000);
        let program = MockProgram;
        let provider = MockServiceProvider;

        let pair = mapper.map(&reference, &program, &provider);

        assert_eq!(*pair.source(), ram_address(0x1000));
        assert_eq!(*pair.destination(), ram_address(0x2000));
    }

    #[test]
    fn different_references_map_to_their_own_pairs() {
        let mapper = ReferenceToReferenceAddressPairTableRowMapper;
        let program = MockProgram;
        let provider = MockServiceProvider;

        let a = mapper.map(&reference(0x10, 0x20), &program, &provider);
        let b = mapper.map(&reference(0x30, 0x40), &program, &provider);

        assert_ne!(a, b);
        assert_eq!(*a.source(), ram_address(0x10));
        assert_eq!(*b.destination(), ram_address(0x40));
    }
}
