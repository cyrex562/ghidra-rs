use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::listing::Program;
use crate::program::model::symbol::SymbolTable;

use super::SubroutineMatch;

/// A collection of subroutine matches found between two programs, together with the programs
/// involved.
///
/// Behaves like `Vec<SubroutineMatch>` via `Deref`/`DerefMut`, mirroring the Java class's
/// `extends ArrayList<SubroutineMatch>`.
///
/// Port of `ghidra.app.plugin.match.FunctionMatchSet`.
pub struct FunctionMatchSet {
    /// The program from which the matching was initiated.
    pub a_program: Arc<dyn Program>,
    /// The program being matched.
    pub b_program: Arc<dyn Program>,
    matches: Vec<SubroutineMatch>,
}

impl FunctionMatchSet {
    /// Creates a new, empty match set between `a_program` and `b_program`.
    pub fn new(a_program: Arc<dyn Program>, b_program: Arc<dyn Program>) -> Self {
        FunctionMatchSet {
            a_program,
            b_program,
            matches: Vec::new(),
        }
    }

    /// Returns the matches as an array, in their current (insertion) order.
    pub fn get_matches(&self) -> Vec<SubroutineMatch> {
        self.matches.clone()
    }

    /// Returns the length, in addresses, of the function containing `addr` in `program`.
    ///
    /// Returns `None` if `program` has no listing, or no function contains `addr`.
    pub fn get_length(&self, addr: &Address, program: &mut dyn Program) -> Option<usize> {
        Self::length_at(addr, program)
    }

    /// Same as [`Self::get_length`], assuming `addr` is in `a_program`.
    ///
    /// Returns `None` if `a_program` is currently shared (its listing cannot be borrowed
    /// mutably while other `Arc` clones exist), has no listing, or has no function containing
    /// `addr`.
    pub fn get_length_in_a(&mut self, addr: &Address) -> Option<usize> {
        Self::length_at(addr, Arc::get_mut(&mut self.a_program)?)
    }

    fn length_at(addr: &Address, program: &mut dyn Program) -> Option<usize> {
        let listing = program.get_listing()?;
        let func = listing.get_function_containing(addr)?;
        Some(Self::function_body_length(func.get_body().as_ref()))
    }

    fn function_body_length(body: &dyn AddressSetView) -> usize {
        body.num_addresses() as usize
    }

    /// Returns the symbol table for `a_program`, if it is currently uniquely owned.
    ///
    /// Ported from the package-private `FunctionMatchSet.getATable`.
    pub(crate) fn get_a_table(&mut self) -> Option<&mut dyn SymbolTable> {
        Arc::get_mut(&mut self.a_program)?.get_symbol_table()
    }

    /// Returns the symbol table for `b_program`, if it is currently uniquely owned.
    ///
    /// Ported from the package-private `FunctionMatchSet.getBTable`.
    pub(crate) fn get_b_table(&mut self) -> Option<&mut dyn SymbolTable> {
        Arc::get_mut(&mut self.b_program)?.get_symbol_table()
    }
}

impl Deref for FunctionMatchSet {
    type Target = Vec<SubroutineMatch>;

    fn deref(&self) -> &Vec<SubroutineMatch> {
        &self.matches
    }
}

impl DerefMut for FunctionMatchSet {
    fn deref_mut(&mut self) -> &mut Vec<SubroutineMatch> {
        &mut self.matches
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSet, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{SourceType, Symbol};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    struct NoListingProgram;
    impl DomainObject for NoListingProgram {}
    impl Program for NoListingProgram {
        fn get_name(&self) -> String {
            "no-listing".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    fn no_listing_program() -> Arc<dyn Program> {
        Arc::new(NoListingProgram)
    }

    struct MockSymbolTable;
    impl SymbolTable for MockSymbolTable {
        fn create_label(
            &mut self,
            _addr: &Address,
            _name: &str,
            _source: SourceType,
        ) -> io::Result<Arc<dyn Symbol>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_symbol(&self, _id: i64) -> io::Result<Option<Arc<dyn Symbol>>> {
            Ok(None)
        }
        fn get_symbols(&self, _addr: &Address) -> io::Result<Vec<Arc<dyn Symbol>>> {
            Ok(Vec::new())
        }
    }

    struct ProgramWithSymbolTable {
        table: MockSymbolTable,
    }
    impl DomainObject for ProgramWithSymbolTable {}
    impl Program for ProgramWithSymbolTable {
        fn get_name(&self) -> String {
            "with-table".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        fn get_symbol_table(&mut self) -> Option<&mut dyn SymbolTable> {
            Some(&mut self.table)
        }
    }

    fn program_with_symbol_table() -> Arc<dyn Program> {
        Arc::new(ProgramWithSymbolTable { table: MockSymbolTable })
    }

    #[test]
    fn new_creates_empty_set_with_programs() {
        let a = no_listing_program();
        let b = no_listing_program();
        let set = FunctionMatchSet::new(Arc::clone(&a), Arc::clone(&b));
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        assert!(Arc::ptr_eq(&set.a_program, &a));
        assert!(Arc::ptr_eq(&set.b_program, &b));
    }

    #[test]
    fn deref_supports_vec_like_push_and_len() {
        let mut set = FunctionMatchSet::new(no_listing_program(), no_listing_program());
        set.push(SubroutineMatch::new("reason a"));
        set.push(SubroutineMatch::new("reason b"));
        assert_eq!(set.len(), 2);
        assert_eq!(set.first().unwrap().get_reason(), "reason a");
    }

    #[test]
    fn get_matches_returns_current_contents() {
        let mut set = FunctionMatchSet::new(no_listing_program(), no_listing_program());
        set.push(SubroutineMatch::new("only"));
        let matches = set.get_matches();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].get_reason(), "only");
    }

    #[test]
    fn function_body_length_counts_addresses_inclusive() {
        let body = AddressSet::from_start_end(addr(0x1000), addr(0x100f));
        assert_eq!(FunctionMatchSet::function_body_length(&body), 16);
    }

    #[test]
    fn get_length_returns_none_without_listing() {
        let set = FunctionMatchSet::new(no_listing_program(), no_listing_program());
        let mut program = NoListingProgram;
        assert_eq!(set.get_length(&addr(0x1000), &mut program), None);
    }

    #[test]
    fn get_length_in_a_returns_none_without_listing() {
        let mut set = FunctionMatchSet::new(no_listing_program(), no_listing_program());
        assert_eq!(set.get_length_in_a(&addr(0x1000)), None);
    }

    #[test]
    fn get_length_in_a_returns_none_when_a_program_is_shared() {
        let a = no_listing_program();
        let _clone = Arc::clone(&a);
        let mut set = FunctionMatchSet::new(a, no_listing_program());
        assert_eq!(set.get_length_in_a(&addr(0x1000)), None);
    }

    #[test]
    fn get_a_table_returns_symbol_table_when_uniquely_owned() {
        let mut set = FunctionMatchSet::new(program_with_symbol_table(), no_listing_program());
        assert!(set.get_a_table().is_some());
    }

    #[test]
    fn get_a_table_returns_none_when_shared() {
        let a = program_with_symbol_table();
        let _clone = Arc::clone(&a);
        let mut set = FunctionMatchSet::new(a, no_listing_program());
        assert!(set.get_a_table().is_none());
    }

    #[test]
    fn get_b_table_returns_symbol_table_when_uniquely_owned() {
        let mut set = FunctionMatchSet::new(no_listing_program(), program_with_symbol_table());
        assert!(set.get_b_table().is_some());
    }
}
