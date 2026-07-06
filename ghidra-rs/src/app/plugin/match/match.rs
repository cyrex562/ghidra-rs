use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::listing::CodeUnit;

/// A single item making up a [`Match`]: a raw byte (rendered as its hex string) for
/// byte-based matches, or a [`CodeUnit`] for code-unit-based matches.
#[derive(Clone)]
pub enum MatchItem {
    Byte(String),
    CodeUnit(Arc<dyn CodeUnit>),
}

impl fmt::Display for MatchItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MatchItem::Byte(hex) => write!(f, "{hex}"),
            MatchItem::CodeUnit(cu) => write!(f, "{}", cu.get_address_string(true, true)),
        }
    }
}

impl fmt::Debug for MatchItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MatchItem::Byte(hex) => f.debug_tuple("Byte").field(hex).finish(),
            MatchItem::CodeUnit(cu) => f
                .debug_tuple("CodeUnit")
                .field(&cu.get_address_string(true, true))
                .finish(),
        }
    }
}

impl PartialEq for MatchItem {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (MatchItem::Byte(a), MatchItem::Byte(b)) => a == b,
            (MatchItem::CodeUnit(a), MatchItem::CodeUnit(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}

fn byte_hex(b: u8) -> String {
    format!("{b:x}")
}

/// Maintains information about a single match between two programs. The match can consist
/// of either bytes or code units.
///
/// Port of `ghidra.app.plugin.match.Match`.
#[derive(Clone)]
pub struct Match {
    this_beginning: Address,
    other_beginning: Address,
    this_match: Vec<MatchItem>,
    other_match: Vec<MatchItem>,
    total_length: i32,
}

impl Match {
    /// Creates a match from a run of raw bytes.
    ///
    /// # Arguments
    /// * `this_beginning` - the start Address of the match in the program from which the
    ///   matches are being found.
    /// * `other_beginning` - the start Address of the match in the program to which the
    ///   matches are being found.
    /// * `bytes` - the bytes which make up this match.
    /// * `length` - the number of leading bytes of `bytes` which make up this match.
    ///
    /// Note: unlike the Java constructor (which aliases a single `ArrayList` for both
    /// this-program and other-program items), the items here are cloned into two owned
    /// vectors, since Rust has no equivalent to sharing one mutable list by reference.
    pub fn new_from_bytes(
        this_beginning: Address,
        other_beginning: Address,
        bytes: &[u8],
        length: usize,
    ) -> Self {
        let this_match: Vec<MatchItem> = bytes[..length]
            .iter()
            .map(|&b| MatchItem::Byte(byte_hex(b)))
            .collect();
        let other_match = this_match.clone();
        Match {
            this_beginning,
            other_beginning,
            this_match,
            other_match,
            total_length: length as i32,
        }
    }

    /// Creates a match from parallel runs of code units in each program.
    ///
    /// # Arguments
    /// * `this_beginning` - the start Address of the match in the program from which the
    ///   matches are being found.
    /// * `other_beginning` - the start Address of the match in the program to which the
    ///   matches are being found.
    /// * `code_units` - the CodeUnits which make up the match in this Program.
    /// * `other_units` - the CodeUnits which make up this match in the other program. Note,
    ///   the code units need not match up byte for byte.
    /// * `length` - the number of leading elements of `code_units`/`other_units` which make
    ///   up this match.
    pub fn new_from_code_units(
        this_beginning: Address,
        other_beginning: Address,
        code_units: &[Arc<dyn CodeUnit>],
        other_units: &[Arc<dyn CodeUnit>],
        length: usize,
    ) -> Self {
        let mut this_match = Vec::with_capacity(length);
        let mut other_match = Vec::with_capacity(length);
        let mut total_length = 0i32;
        for i in 0..length {
            total_length += code_units[i].get_length();
            this_match.push(MatchItem::CodeUnit(code_units[i].clone()));
            other_match.push(MatchItem::CodeUnit(other_units[i].clone()));
        }
        Match {
            this_beginning,
            other_beginning,
            this_match,
            other_match,
            total_length,
        }
    }

    /// Continues the match by adding the additional byte `b`.
    pub fn continue_match_byte(&mut self, b: u8) {
        self.this_match.push(MatchItem::Byte(byte_hex(b)));
        self.total_length += 1;
    }

    /// Continues the match by adding the CodeUnit which extends the match in `this` program,
    /// and the CodeUnit which extends the match in `the other` program.
    pub fn continue_match_code_units(&mut self, cu: Arc<dyn CodeUnit>, other_unit: Arc<dyn CodeUnit>) {
        self.total_length += cu.get_length();
        self.this_match.push(MatchItem::CodeUnit(cu));
        self.other_match.push(MatchItem::CodeUnit(other_unit));
    }

    /// The number of items that make up this match.
    pub fn length(&self) -> usize {
        self.this_match.len()
    }

    /// The total number of bytes that make up this match.
    pub fn total_length(&self) -> i32 {
        self.total_length
    }

    /// The Address that starts the match in the other program.
    pub fn get_other_beginning(&self) -> &Address {
        &self.other_beginning
    }

    /// The Address that starts the match in this program.
    pub fn get_this_beginning(&self) -> &Address {
        &self.this_beginning
    }

    /// The items that make up the match in this program.
    pub fn get_bytes(&self) -> &[MatchItem] {
        &self.this_match
    }

    /// The items that make up the match in the other program.
    pub fn get_other_bytes(&self) -> &[MatchItem] {
        &self.other_match
    }

    /// Formats a one-line summary of this match.
    pub fn print_match(&self) -> String {
        let len = self.length();
        let this_str = self.this_beginning.format(true, 8);
        let this_hex = format!("{:x}", self.this_beginning.unsigned_offset());
        let other_str = self.other_beginning.format(true, 8);
        let other_hex = format!("{:x}", self.other_beginning.unsigned_offset());
        format!("1.00 {len} {len}{this_str} {this_hex}{other_str} {other_hex}\n")
    }

    /// The Address at which a continuing byte or code unit would be expected to be found in
    /// the other program.
    ///
    /// `base_length` is the minimum number of items which make up a match. There are
    /// different values for instruction and byte matches.
    pub fn expected_address_for_next_match(&self, base_length: i32) -> Address {
        let index = self.length() as i32 - base_length + 1;
        let item = &self.this_match[index as usize];
        if let MatchItem::CodeUnit(cu) = item {
            return cu.get_min_address();
        }
        self.this_beginning
            .add((self.total_length() - base_length + 1) as i64)
            .expect("address overflow computing expected next match address")
    }
}

impl fmt::Display for Match {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.other_beginning.format(true, 8))?;
        for item in &self.this_match {
            write!(f, "{item} ")?;
        }
        Ok(())
    }
}

impl PartialEq for Match {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Match {}

impl PartialOrd for Match {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Match {
    fn cmp(&self, other: &Self) -> Ordering {
        self.this_beginning
            .cmp(&other.this_beginning)
            .then_with(|| self.other_beginning.cmp(&other.other_beginning))
            .then_with(|| self.length().cmp(&other.length()))
    }
}

impl Hash for Match {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.this_beginning.offset().hash(state);
        self.other_beginning.offset().hash(state);
        self.total_length.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::register::Register;
    use crate::program::model::listing::program::Program;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{RefType, Reference, ReferenceIterator, SourceType, Symbol};
    use crate::program::seam_stubs::{CommentType, ExternalReference, MemBuffer, PropertySet};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    struct FakeProgram;
    impl Program for FakeProgram {
        fn get_name(&self) -> &str {
            "fake.bin"
        }
        fn get_language_id(&self) -> &str {
            "test:LE:32:default"
        }
    }

    struct FakeReferenceIterator;
    impl ReferenceIterator for FakeReferenceIterator {
        fn has_next(&self) -> bool {
            false
        }
        fn next_reference(&mut self) -> Option<Arc<dyn Reference>> {
            None
        }
    }

    struct FakeCodeUnit {
        min_address: Address,
        length: i32,
    }

    impl MemBuffer for FakeCodeUnit {}
    impl PropertySet for FakeCodeUnit {}

    impl CodeUnit for FakeCodeUnit {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            format!("{:08x}", self.min_address.offset())
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
            self.min_address.clone()
        }

        fn get_max_address(&self) -> Address {
            self.min_address.clone()
        }

        fn get_mnemonic_string(&self) -> String {
            "MOV".to_string()
        }

        fn get_comment(&self, _comment_type: CommentType) -> Option<String> {
            None
        }

        fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> {
            Vec::new()
        }

        fn set_comment(&mut self, _comment_type: CommentType, _comment: Option<String>) {}

        fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) {}

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
            Vec::new()
        }

        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn Reference>> {
            None
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
            Vec::new()
        }

        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            Box::new(FakeReferenceIterator)
        }

        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(FakeProgram)
        }

        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            None
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

        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
            None
        }
    }

    fn code_unit(offset: i64, length: i32) -> Arc<dyn CodeUnit> {
        Arc::new(FakeCodeUnit {
            min_address: addr(offset),
            length,
        })
    }

    #[test]
    fn byte_match_converts_bytes_to_unsigned_hex() {
        let m = Match::new_from_bytes(addr(0x1000), addr(0x2000), &[0x05, 0xff, 0x80, 0x7f], 4);
        assert_eq!(m.length(), 4);
        assert_eq!(m.total_length(), 4);
        assert_eq!(
            m.get_bytes(),
            &[
                MatchItem::Byte("5".to_string()),
                MatchItem::Byte("ff".to_string()),
                MatchItem::Byte("80".to_string()),
                MatchItem::Byte("7f".to_string()),
            ]
        );
        assert_eq!(m.get_bytes(), m.get_other_bytes());
    }

    #[test]
    fn byte_match_respects_length_shorter_than_slice() {
        let m = Match::new_from_bytes(addr(0x1000), addr(0x2000), &[0x01, 0x02, 0x03], 2);
        assert_eq!(m.length(), 2);
        assert_eq!(m.total_length(), 2);
    }

    #[test]
    fn continue_match_byte_appends_and_grows_total_length() {
        let mut m = Match::new_from_bytes(addr(0x1000), addr(0x2000), &[0x01], 1);
        m.continue_match_byte(0xff);
        assert_eq!(m.length(), 2);
        assert_eq!(m.total_length(), 2);
        assert_eq!(m.get_bytes()[1], MatchItem::Byte("ff".to_string()));
    }

    #[test]
    fn code_unit_match_sums_lengths() {
        let this_units = vec![code_unit(0x1000, 2), code_unit(0x1002, 2), code_unit(0x1004, 2)];
        let other_units = vec![code_unit(0x3000, 2), code_unit(0x3002, 2), code_unit(0x3004, 2)];
        let m = Match::new_from_code_units(addr(0x1000), addr(0x3000), &this_units, &other_units, 3);
        assert_eq!(m.length(), 3);
        assert_eq!(m.total_length(), 6);
    }

    #[test]
    fn continue_match_code_units_appends_to_both_sides() {
        let this_units = vec![code_unit(0x1000, 4)];
        let other_units = vec![code_unit(0x3000, 4)];
        let mut m = Match::new_from_code_units(addr(0x1000), addr(0x3000), &this_units, &other_units, 1);
        m.continue_match_code_units(code_unit(0x1004, 2), code_unit(0x3004, 2));
        assert_eq!(m.length(), 2);
        assert_eq!(m.total_length(), 6);
    }

    #[test]
    fn expected_address_for_next_match_from_bytes() {
        let m = Match::new_from_bytes(addr(0x1000), addr(0x2000), &[0x01, 0x02, 0x03, 0x04], 4);
        // index = length() - base_length + 1 = 4 - 2 + 1 = 3 (a byte, not a CodeUnit)
        // -> thisBeginning + (totalLength() - baseLength + 1) = 0x1000 + 3
        assert_eq!(m.expected_address_for_next_match(2), addr(0x1003));
    }

    #[test]
    fn expected_address_for_next_match_from_code_units() {
        let this_units = vec![code_unit(0x1000, 2), code_unit(0x1002, 2), code_unit(0x1004, 2)];
        let other_units = vec![code_unit(0x3000, 2), code_unit(0x3002, 2), code_unit(0x3004, 2)];
        let m = Match::new_from_code_units(addr(0x1000), addr(0x3000), &this_units, &other_units, 3);
        // index = length() - base_length + 1 = 3 - 2 + 1 = 2 -> the third CodeUnit
        assert_eq!(m.expected_address_for_next_match(2), addr(0x1004));
    }

    #[test]
    fn print_match_matches_java_format() {
        let m = Match::new_from_bytes(addr(0x1000), addr(0x2000), &[0x01, 0x02, 0x03, 0x04], 4);
        assert_eq!(
            m.print_match(),
            "1.00 4 4ram:00001000 1000ram:00002000 2000\n"
        );
    }

    #[test]
    fn display_matches_java_format() {
        let m = Match::new_from_bytes(addr(0x1000), addr(0x2000), &[0x05, 0xff], 2);
        assert_eq!(m.to_string(), "ram:00002000\n5 ff ");
    }

    #[test]
    fn ordering_compares_this_then_other_then_length() {
        let base = Match::new_from_bytes(addr(0x100), addr(0x200), &[0x01, 0x02], 2);
        let later_this = Match::new_from_bytes(addr(0x150), addr(0x200), &[0x01, 0x02], 2);
        let later_other = Match::new_from_bytes(addr(0x100), addr(0x250), &[0x01, 0x02], 2);
        let longer = Match::new_from_bytes(addr(0x100), addr(0x200), &[0x01, 0x02, 0x03], 3);

        assert!(base < later_this);
        assert!(base < later_other);
        assert!(base < longer);
        assert_eq!(
            base.cmp(&Match::new_from_bytes(addr(0x100), addr(0x200), &[0x09, 0x09], 2)),
            Ordering::Equal
        );
    }

    #[test]
    fn get_this_and_other_beginning() {
        let m = Match::new_from_bytes(addr(0x1000), addr(0x2000), &[0x01], 1);
        assert_eq!(m.get_this_beginning(), &addr(0x1000));
        assert_eq!(m.get_other_beginning(), &addr(0x2000));
    }
}
