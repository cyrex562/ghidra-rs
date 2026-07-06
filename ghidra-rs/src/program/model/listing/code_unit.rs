use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::lang::register::Register;
use crate::program::model::listing::program::Program;
use crate::program::model::mem::MemoryAccessException;
use crate::program::model::scalar::Scalar;
use crate::program::model::symbol::{RefType, Reference, ReferenceIterator, SourceType, Symbol};
use crate::program::seam_stubs::{CommentType, ExternalReference, MemBuffer, PropertySet};

/// Indicator for a mnemonic (versus an operand).
pub const MNEMONIC: i32 = -1;

/// comment type for end of line
#[deprecated(since = "11.4", note = "use CommentType::Eol instead")]
pub const EOL_COMMENT: i32 = 0;
/// comment type that goes before a code unit
#[deprecated(since = "11.4", note = "use CommentType::Pre instead")]
pub const PRE_COMMENT: i32 = 1;
/// comment type that follows after a code unit
#[deprecated(since = "11.4", note = "use CommentType::Post instead")]
pub const POST_COMMENT: i32 = 2;
/// Property name for plate comment type
#[deprecated(since = "11.4", note = "use CommentType::Plate instead")]
pub const PLATE_COMMENT: i32 = 3;
/// Property name for repeatable comment type
#[deprecated(since = "11.4", note = "use CommentType::Repeatable instead")]
pub const REPEATABLE_COMMENT: i32 = 4;

/// Any comment property.
pub const COMMENT_PROPERTY: &str = "COMMENT__GHIDRA_";
/// Property name for vertical space formatting
pub const SPACE_PROPERTY: &str = "Space";
/// Property name for code units that are instructions
pub const INSTRUCTION_PROPERTY: &str = "INSTRUCTION__GHIDRA_";
/// Property name for code units that are defined data
pub const DEFINED_DATA_PROPERTY: &str = "DEFINED_DATA__GHIDRA_";

/// Interface common to both instructions and data.
///
/// Port of `ghidra.program.model.listing.CodeUnit`.
pub trait CodeUnit: MemBuffer + PropertySet {
    /// Get the string representation of the starting address for this code unit.
    ///
    /// # Arguments
    /// * `show_block_name` - true if the string should include the memory block name
    /// * `pad` - if true, the address will be padded with leading zeros. Even if pad is false,
    ///   the string will be padded to make the address string contain at least 4 digits.
    fn get_address_string(&self, show_block_name: bool, pad: bool) -> String;

    /// The label for this code unit, or `None` if no label is defined.
    fn get_label(&self) -> Option<String>;

    /// The Symbols for this code unit.
    fn get_symbols(&self) -> Vec<Arc<dyn Symbol>>;

    /// The Primary Symbol for this code unit, or `None` if there isn't one.
    fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>>;

    /// The starting address for this code unit.
    fn get_min_address(&self) -> Address;

    /// The ending address for this code unit.
    fn get_max_address(&self) -> Address;

    /// The mnemonic for this code unit, e.g., MOV, JMP.
    fn get_mnemonic_string(&self) -> String;

    /// Get the comment for the given type.
    ///
    /// # Errors
    /// Panics if `comment_type` is not a valid [`CommentType`] ordinal.
    #[deprecated(since = "11.4", note = "use get_comment(CommentType) instead")]
    fn get_comment_by_ordinal(&self, comment_type: i32) -> Option<String> {
        self.get_comment(
            CommentType::from_ordinal(comment_type).expect("valid comment type ordinal"),
        )
    }

    /// Get the comment for the given type, or `None` if no comment of that type exists for this
    /// code unit.
    fn get_comment(&self, comment_type: CommentType) -> Option<String>;

    /// Get the comment for the given type and parse it into an array of strings such that each
    /// line is its own string.
    ///
    /// # Errors
    /// Panics if `comment_type` is not a valid [`CommentType`] ordinal.
    #[deprecated(since = "11.4", note = "use get_comment_as_array(CommentType) instead")]
    fn get_comment_as_array_by_ordinal(&self, comment_type: i32) -> Vec<String> {
        self.get_comment_as_array(
            CommentType::from_ordinal(comment_type).expect("valid comment type ordinal"),
        )
    }

    /// Get the comment for the given type and parse it into an array of strings such that each
    /// line is its own string. If there is no comment of the requested type, an empty array is
    /// returned.
    fn get_comment_as_array(&self, comment_type: CommentType) -> Vec<String>;

    /// Set the comment for the given comment type. Passing `None` clears the comment.
    ///
    /// # Errors
    /// Panics if `comment_type` is not a valid [`CommentType`] ordinal.
    #[deprecated(since = "11.4", note = "use set_comment(CommentType, Option<String>) instead")]
    fn set_comment_by_ordinal(&mut self, comment_type: i32, comment: Option<String>) {
        self.set_comment(
            CommentType::from_ordinal(comment_type).expect("valid comment type ordinal"),
            comment,
        )
    }

    /// Set the comment for the given comment type. Passing `None` clears the comment.
    fn set_comment(&mut self, comment_type: CommentType, comment: Option<String>);

    /// Set the comment (with each line in its own string) for the given comment type.
    ///
    /// # Errors
    /// Panics if `comment_type` is not a valid [`CommentType`] ordinal.
    #[deprecated(
        since = "11.4",
        note = "use set_comment_as_array(CommentType, &[String]) instead"
    )]
    fn set_comment_as_array_by_ordinal(&mut self, comment_type: i32, comment: &[String]) {
        self.set_comment_as_array(
            CommentType::from_ordinal(comment_type).expect("valid comment type ordinal"),
            comment,
        )
    }

    /// Set the comment (with each line in its own string) for the given comment type.
    fn set_comment_as_array(&mut self, comment_type: CommentType, comment: &[String]);

    /// Get length of this code unit.
    ///
    /// NOTE: If an instruction length-override is set this method will return the reduced
    /// length.
    fn get_length(&self) -> i32;

    /// Get the bytes that make up this code unit.
    ///
    /// NOTE: If an instruction length-override is set this method will not return all bytes
    /// associated with the instruction prototype.
    fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException>;

    /// Copies `max(buffer.len(), code unit length)` bytes into `buffer` starting at the given
    /// offset in `buffer`.
    fn get_bytes_in_code_unit(
        &self,
        buffer: &mut [u8],
        buffer_offset: i32,
    ) -> Result<(), MemoryAccessException>;

    /// Returns true if `test_addr` is contained in the range of this code unit.
    fn contains(&self, test_addr: &Address) -> bool;

    /// Compares the given address to the address range of this node.
    ///
    /// Returns a negative integer if `addr` is greater than the maximum range address, zero if
    /// `addr` is in the range, and a positive integer if `addr` is less than the minimum range
    /// address.
    fn compare_to(&self, addr: &Address) -> i32;

    /// Add a reference to the mnemonic for this code unit.
    fn add_mnemonic_reference(
        &mut self,
        ref_addr: Address,
        ref_type: RefType,
        source_type: SourceType,
    );

    /// Remove a reference to the mnemonic for this code unit.
    fn remove_mnemonic_reference(&mut self, ref_addr: &Address);

    /// Get references for the mnemonic for this code unit. An empty vector is returned if there
    /// are no references for the mnemonic.
    fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>>;

    /// The references for the operand index.
    ///
    /// # Arguments
    /// * `index` - operand index (0 is the first operand)
    fn get_operand_references(&self, index: i32) -> Vec<Arc<dyn Reference>>;

    /// The primary reference for the operand index.
    ///
    /// # Arguments
    /// * `index` - operand index (0 is the first operand)
    fn get_primary_reference(&self, index: i32) -> Option<Arc<dyn Reference>>;

    /// Add a memory reference to the operand at the given index.
    fn add_operand_reference(
        &mut self,
        index: i32,
        ref_addr: Address,
        ref_type: RefType,
        source_type: SourceType,
    );

    /// Remove a reference to the operand.
    fn remove_operand_reference(&mut self, index: i32, ref_addr: &Address);

    /// Get ALL memory references FROM this code unit, or an empty vector if there are none.
    fn get_references_from(&self) -> Vec<Arc<dyn Reference>>;

    /// An iterator over all references TO this code unit.
    fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator>;

    /// The program that generated this CodeUnit.
    fn get_program(&self) -> Arc<dyn Program>;

    /// Gets the external reference (if any) at the opIndex.
    fn get_external_reference(&self, op_index: i32) -> Option<Arc<dyn ExternalReference>>;

    /// Remove external reference (if any) at the given opIndex.
    fn remove_external_reference(&mut self, op_index: i32);

    /// Sets a memory reference to be the primary reference at its address/opIndex location. The
    /// primary reference is the one used when displaying the operand representation.
    fn set_primary_memory_reference(&mut self, reference: Arc<dyn Reference>);

    /// Sets a stack reference at the `offset` on the specified operand index, which effectively
    /// substitutes the previous operation interpretation.
    ///
    /// NOTE: If another reference was previously set on the operand, then it will be replaced
    /// with this stack reference.
    fn set_stack_reference(
        &mut self,
        op_index: i32,
        offset: i32,
        source_type: SourceType,
        ref_type: RefType,
    );

    /// Sets a register reference at the `offset` on the specified operand index, which
    /// effectively substitutes the previous operation interpretation.
    ///
    /// NOTE: If another reference was previously set on the operand, then it will be replaced
    /// with this register reference.
    fn set_register_reference(
        &mut self,
        op_index: i32,
        reg: &Register,
        source_type: SourceType,
        ref_type: RefType,
    );

    /// The number of operands for this code unit.
    fn get_num_operands(&self) -> i32;

    /// Get the Address for the given operand index if one exists. Data objects have one operand
    /// (the value).
    ///
    /// An address is returned if the operand represents a fully qualified address (given the
    /// context), or if the operand is a Scalar treated as an address. `None` is returned if no
    /// address or scalar exists on that operand.
    fn get_address(&self, op_index: i32) -> Option<Address>;

    /// Returns the scalar at the given operand index, or `None` if no scalar exists at that
    /// index. Data objects have one operand (the value).
    fn get_scalar(&self, op_index: i32) -> Option<Scalar>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::SymbolType;

    struct MockSymbol;
    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            mock_address(0x100)
        }
        fn get_name(&self) -> &str {
            "LAB_00000100"
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }
        fn get_source(&self) -> SourceType {
            SourceType::Analysis
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            1
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
    }

    struct MockReference;
    impl Reference for MockReference {
        fn from_address(&self) -> Address {
            mock_address(0x100)
        }
        fn to_address(&self) -> Address {
            mock_address(0x200)
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn symbol_id(&self) -> i64 {
            -1
        }
        fn reference_type(&self) -> RefType {
            RefType::Flow
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
        fn source(&self) -> SourceType {
            SourceType::Analysis
        }
    }

    struct MockExternalReference;
    impl Reference for MockExternalReference {
        fn from_address(&self) -> Address {
            mock_address(0x100)
        }
        fn to_address(&self) -> Address {
            mock_address(0x300)
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
            true
        }
        fn is_entry_point_reference(&self) -> bool {
            false
        }
        fn is_memory_reference(&self) -> bool {
            false
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
        fn source(&self) -> SourceType {
            SourceType::Analysis
        }
    }
    impl ExternalReference for MockExternalReference {}

    struct MockProgram;
    impl Program for MockProgram {
        fn get_name(&self) -> &str {
            "mock.bin"
        }
        fn get_language_id(&self) -> &str {
            "test:LE:32:default"
        }
    }

    struct MockReferenceIterator {
        references: Vec<Arc<dyn Reference>>,
        index: usize,
    }
    impl ReferenceIterator for MockReferenceIterator {
        fn has_next(&self) -> bool {
            self.index < self.references.len()
        }
        fn next_reference(&mut self) -> Option<Arc<dyn Reference>> {
            let next = self.references.get(self.index).cloned();
            if next.is_some() {
                self.index += 1;
            }
            next
        }
    }

    struct MockCodeUnit {
        min_address: Address,
        length: i32,
        comment: Option<String>,
    }

    impl MemBuffer for MockCodeUnit {}
    impl PropertySet for MockCodeUnit {}

    impl CodeUnit for MockCodeUnit {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            format!("{:08x}", self.min_address.offset())
        }

        fn get_label(&self) -> Option<String> {
            Some("LAB_00000100".to_string())
        }

        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            vec![Arc::new(MockSymbol)]
        }

        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
            Some(Arc::new(MockSymbol))
        }

        fn get_min_address(&self) -> Address {
            self.min_address.clone()
        }

        fn get_max_address(&self) -> Address {
            self.min_address.clone()
        }

        fn get_mnemonic_string(&self) -> String {
            "MOV".to_string()
        }

        fn get_comment(&self, comment_type: CommentType) -> Option<String> {
            match comment_type {
                CommentType::Eol => self.comment.clone(),
                _ => None,
            }
        }

        fn get_comment_as_array(&self, comment_type: CommentType) -> Vec<String> {
            self.get_comment(comment_type)
                .map(|c| c.lines().map(str::to_string).collect())
                .unwrap_or_default()
        }

        fn set_comment(&mut self, comment_type: CommentType, comment: Option<String>) {
            if comment_type == CommentType::Eol {
                self.comment = comment;
            }
        }

        fn set_comment_as_array(&mut self, comment_type: CommentType, comment: &[String]) {
            self.set_comment(comment_type, Some(comment.join("\n")));
        }

        fn get_length(&self) -> i32 {
            self.length
        }

        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![0x90; self.length as usize])
        }

        fn get_bytes_in_code_unit(
            &self,
            buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            buffer.fill(0x90);
            Ok(())
        }

        fn contains(&self, test_addr: &Address) -> bool {
            test_addr.offset() >= self.min_address.offset()
                && test_addr.offset() < self.min_address.offset() + self.length as i64
        }

        fn compare_to(&self, addr: &Address) -> i32 {
            self.min_address.offset().cmp(&addr.offset()) as i32
        }

        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: RefType,
            _source_type: SourceType,
        ) {
        }

        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}

        fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }

        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn Reference>> {
            vec![Arc::new(MockReference)]
        }

        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn Reference>> {
            Some(Arc::new(MockReference))
        }

        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: RefType,
            _source_type: SourceType,
        ) {
        }

        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}

        fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
            vec![Arc::new(MockReference)]
        }

        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            Box::new(MockReferenceIterator {
                references: Vec::new(),
                index: 0,
            })
        }

        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }

        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            Some(Arc::new(MockExternalReference))
        }

        fn remove_external_reference(&mut self, _op_index: i32) {}

        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn Reference>) {}

        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: SourceType,
            _ref_type: RefType,
        ) {
        }

        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &Register,
            _source_type: SourceType,
            _ref_type: RefType,
        ) {
        }

        fn get_num_operands(&self) -> i32 {
            1
        }

        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }

        fn get_scalar(&self, op_index: i32) -> Option<Scalar> {
            if op_index == 0 {
                Some(Scalar::new(32, 42))
            } else {
                None
            }
        }
    }

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn usable_as_trait_object() {
        let mut unit: Box<dyn CodeUnit> = Box::new(MockCodeUnit {
            min_address: mock_address(0x100),
            length: 4,
            comment: None,
        });

        assert_eq!(unit.get_length(), 4);
        assert_eq!(unit.get_mnemonic_string(), "MOV");
        assert!(unit.contains(&mock_address(0x102)));
        assert!(!unit.contains(&mock_address(0x200)));

        unit.set_comment(CommentType::Eol, Some("hello".to_string()));
        assert_eq!(unit.get_comment(CommentType::Eol), Some("hello".to_string()));

        #[allow(deprecated)]
        {
            assert_eq!(
                unit.get_comment_by_ordinal(0),
                Some("hello".to_string())
            );
        }

        assert_eq!(unit.get_scalar(0), Some(Scalar::new(32, 42)));
        assert_eq!(unit.get_scalar(1), None);
        assert_eq!(unit.get_bytes().unwrap(), vec![0x90; 4]);
    }
}
