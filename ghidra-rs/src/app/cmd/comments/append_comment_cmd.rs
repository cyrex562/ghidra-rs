//! Port of `ghidra.app.cmd.comments.AppendCommentCmd`.

use std::sync::Arc;

use crate::framework::cmd::Command;
use crate::program::model::address::Address;
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::comment_type::CommentType;
use crate::program::model::listing::Program;

/// Command to append a specific type of comment on a code unit.
///
/// Port of `ghidra.app.cmd.comments.AppendCommentCmd`. The deprecated
/// `AppendCommentCmd(Address, int, String, String)` constructor (taking a raw comment-type
/// ordinal) is not ported; callers should use [`CommentType`] directly.
pub struct AppendCommentCmd {
    address: Address,
    comment_type: CommentType,
    comment: String,
    separator: String,
    message: Option<String>,
}

impl AppendCommentCmd {
    /// Port of `AppendCommentCmd(Address, CommentType, String, String)`.
    pub fn new(address: Address, comment_type: CommentType, comment: impl Into<String>, separator: impl Into<String>) -> Self {
        AppendCommentCmd {
            address,
            comment_type,
            comment: comment.into(),
            separator: separator.into(),
            message: None,
        }
    }

    /// Port of the private `AppendCommentCmd.getCodeUnit(Program)`.
    fn get_code_unit(&self, program: &mut dyn Program) -> Option<Arc<dyn CodeUnit>> {
        let listing = program.get_listing()?;
        let cu = listing.get_code_unit_containing(&self.address)?;
        let cu_addr = cu.get_min_address();
        if let Some(data) = cu.as_data() {
            if self.address != cu_addr {
                let offset = self.address.subtract(&cu_addr) as i32;
                let primitive = data.get_primitive_at(offset)?;
                return Some(Arc::from(primitive as Box<dyn CodeUnit>));
            }
        }
        Some(cu)
    }
}

impl Command<dyn Program + 'static> for AppendCommentCmd {
    /// Port of `AppendCommentCmd.applyTo(Program)`.
    fn apply_to(&mut self, program: &mut (dyn Program + 'static)) -> bool {
        let Some(cu) = self.get_code_unit(program) else {
            self.message = Some(format!(
                "No Instruction or Data found for address {}  Is this address valid?",
                self.address
            ));
            return false;
        };

        let previous_comment = cu.get_comment(self.comment_type);
        let new_comment = match previous_comment {
            Some(prev) => format!("{prev}{}{}", self.separator, self.comment),
            None => self.comment.clone(),
        };

        // `cu` is shared (`Arc<dyn CodeUnit>`) but this command needs to mutate it in place, the
        // same way `SetFunctionRepeatableCommentCmd`/`ClearFallThroughCmd` do for their targets:
        // there is exactly one owner in practice (the listing's backing store), so a raw-pointer
        // cast to `&mut` is used to reach `set_comment`, which Java's identical-looking in-place
        // mutation gets for free.
        let cu_ptr = cu.as_ref() as *const dyn CodeUnit as *mut dyn CodeUnit;
        unsafe {
            (*cu_ptr).set_comment(self.comment_type, Some(new_comment));
        }
        true
    }

    fn status_msg(&self) -> Option<String> {
        self.message.clone()
    }

    fn name(&self) -> String {
        "Append Comment".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::stub_listing::StubListing;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{Reference, ReferenceIterator, Symbol};
    use crate::program::model::util::PropertySet;
    use std::sync::Mutex;

    fn mk_addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct EmptyReferenceIterator;
    impl Iterator for EmptyReferenceIterator {
        type Item = Arc<dyn Reference>;
        fn next(&mut self) -> Option<Self::Item> {
            None
        }
    }
    impl ReferenceIterator for EmptyReferenceIterator {}

    /// Minimal `CodeUnit` fixture. Only `get_min_address`/`get_comment`/`set_comment` are
    /// exercised by [`AppendCommentCmd`]; everything else is `unimplemented!()`, matching the
    /// convention `create_data_cmd.rs`'s own `MockData` fixture uses for the same trait.
    ///
    /// `comment` is a shared `Arc<Mutex<_>>` rather than a plain field for two reasons: (1)
    /// `set_comment` -- which the command reaches through a shared `Arc<dyn CodeUnit>` via the
    /// same raw-pointer idiom `ClearFallThroughCmd`/`SetFunctionRepeatableCommentCmd` use -- needs
    /// to record the write; (2) `Program: Send + Sync` requires every field reachable from a
    /// `Program` impl to be `Send + Sync`, and `dyn CodeUnit` (unlike its listing/program
    /// supertraits) carries no such bound, so a `dyn CodeUnit` trait object itself can never be
    /// stored in a field -- only ever returned fresh from a method, as
    /// [`FixtureListing::get_code_unit_containing`] does below (mirroring
    /// `code_unit_location.rs`'s own `MockListing` fixture).
    struct FixtureCodeUnit {
        min_addr: Address,
        comment: Arc<Mutex<Option<String>>>,
    }

    impl crate::program::model::mem::MemBuffer for FixtureCodeUnit {
        fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            self.min_addr.clone()
        }
    }
    impl PropertySet for FixtureCodeUnit {}

    impl CodeUnit for FixtureCodeUnit {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            unimplemented!("not exercised by these tests")
        }
        fn get_label(&self) -> Option<String> {
            None
        }
        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            Vec::new()
        }
        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn get_min_address(&self) -> Address {
            self.min_addr.clone()
        }
        fn get_max_address(&self) -> Address {
            self.min_addr.clone()
        }
        fn get_mnemonic_string(&self) -> String {
            String::new()
        }
        fn get_comment(&self, comment_type: CommentType) -> Option<String> {
            if comment_type == CommentType::Eol {
                self.comment.lock().unwrap().clone()
            } else {
                None
            }
        }
        fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(&mut self, comment_type: CommentType, comment: Option<String>) {
            if comment_type == CommentType::Eol {
                *self.comment.lock().unwrap() = comment;
            }
        }
        fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) {}
        fn get_length(&self) -> i32 {
            1
        }
        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes_in_code_unit(
            &self,
            _buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn contains(&self, _test_addr: &Address) -> bool {
            false
        }
        fn compare_to(&self, _addr: &Address) -> i32 {
            0
        }
        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: crate::program::model::symbol::RefType,
            _source_type: crate::program::model::symbol::SourceType,
        ) {
        }
        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}
        fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }
        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }
        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn Reference>> {
            None
        }
        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: crate::program::model::symbol::RefType,
            _source_type: crate::program::model::symbol::SourceType,
        ) {
        }
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}
        fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }
        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            Box::new(EmptyReferenceIterator)
        }
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by these tests")
        }
        fn get_external_reference(
            &self,
            _op_index: i32,
        ) -> Option<Arc<dyn crate::program::model::symbol::ExternalReference>> {
            None
        }
        fn remove_external_reference(&mut self, _op_index: i32) {}
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn Reference>) {}
        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: crate::program::model::symbol::SourceType,
            _ref_type: crate::program::model::symbol::RefType,
        ) {
        }
        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &crate::program::model::lang::register::Register,
            _source_type: crate::program::model::symbol::SourceType,
            _ref_type: crate::program::model::symbol::RefType,
        ) {
        }
        fn get_num_operands(&self) -> i32 {
            1
        }
        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }
        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
            None
        }
    }

    struct FixtureListing {
        min_addr: Address,
        comment: Arc<Mutex<Option<String>>>,
    }
    impl StubListing for FixtureListing {
        fn get_code_unit_containing(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            Some(Arc::new(FixtureCodeUnit {
                min_addr: self.min_addr.clone(),
                comment: self.comment.clone(),
            }))
        }
    }

    struct FixtureProgram {
        listing: FixtureListing,
    }

    impl DomainObject for FixtureProgram {
        fn is_changed(&self) -> bool {
            false
        }
    }

    impl Program for FixtureProgram {
        fn get_name(&self) -> String {
            "fixture".to_string()
        }
        fn get_language_id(&self) -> String {
            "fixture:LE:32:default".to_string()
        }
        fn get_listing(&mut self) -> Option<&mut dyn crate::program::model::listing::Listing> {
            Some(&mut self.listing)
        }
    }

    fn mk_program(initial_comment: Option<&str>) -> FixtureProgram {
        let comment = Arc::new(Mutex::new(initial_comment.map(str::to_string)));
        FixtureProgram { listing: FixtureListing { min_addr: mk_addr(0x1000), comment } }
    }

    #[test]
    fn applies_comment_when_none_existing() {
        let mut program = mk_program(None);
        let comment = program.listing.comment.clone();
        let mut cmd = AppendCommentCmd::new(mk_addr(0x1000), CommentType::Eol, "hello", "; ");
        assert!(cmd.apply_to(&mut program));
        assert_eq!(*comment.lock().unwrap(), Some("hello".to_string()));
        assert_eq!(cmd.status_msg(), None);
    }

    #[test]
    fn appends_with_separator_when_comment_exists() {
        let mut program = mk_program(Some("existing"));
        let comment = program.listing.comment.clone();
        let mut cmd = AppendCommentCmd::new(mk_addr(0x1000), CommentType::Eol, "new", "; ");
        assert!(cmd.apply_to(&mut program));
        assert_eq!(*comment.lock().unwrap(), Some("existing; new".to_string()));
    }

    #[test]
    fn fails_and_sets_status_message_when_no_code_unit() {
        struct NoCodeUnitListing;
        impl StubListing for NoCodeUnitListing {
            fn get_code_unit_containing(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
                None
            }
        }
        struct NoCodeUnitProgram {
            listing: NoCodeUnitListing,
        }
        impl DomainObject for NoCodeUnitProgram {
            fn is_changed(&self) -> bool {
                false
            }
        }
        impl Program for NoCodeUnitProgram {
            fn get_name(&self) -> String {
                "fixture".to_string()
            }
            fn get_language_id(&self) -> String {
                "fixture:LE:32:default".to_string()
            }
            fn get_listing(&mut self) -> Option<&mut dyn crate::program::model::listing::Listing> {
                Some(&mut self.listing)
            }
        }

        let mut program = NoCodeUnitProgram { listing: NoCodeUnitListing };
        let addr = mk_addr(0x2000);
        let mut cmd = AppendCommentCmd::new(addr, CommentType::Eol, "hello", "; ");
        assert!(!cmd.apply_to(&mut program));
        assert!(cmd.status_msg().unwrap().contains("No Instruction or Data found"));
    }

    #[test]
    fn name_matches_java() {
        let cmd = AppendCommentCmd::new(mk_addr(0), CommentType::Eol, "x", "; ");
        assert_eq!(cmd.name(), "Append Comment");
    }
}
