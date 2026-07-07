use std::fmt;

use crate::util::bytesearch::byte_pattern::BytePattern;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_exception::XmlException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// A pattern of bits/mask to match to a stream of bytes. The bits/mask can be of any length.
///
/// Port of `ghidra.util.bytesearch.DittedBitSequence`. The sequence can be initialized by:
///  - a string
///  - an array of bytes (no mask)
///  - an array of bytes and a mask
///
/// The dits represent bits (binary) or nibbles (hex) that are don't care, for example:
/// ```text
///    0x..d.4de2 ....0000 .1...... 00101101 11101001
/// ```
/// where `0x` starts a hex number and `.` is a don't care nibble (hex) or bit (binary).
#[derive(Debug, Clone, Default)]
pub struct DittedBitSequence {
    index: i32,
    bits: Vec<u8>,
    dits: Vec<u8>,
}

/// Error returned when a ditted-bit-sequence string is malformed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DittedBitSequenceParseError(String);

impl DittedBitSequenceParseError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for DittedBitSequenceParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for DittedBitSequenceParseError {}

impl DittedBitSequence {
    /// Creates an empty, uninitialized sequence.
    pub fn new() -> Self {
        Self::default()
    }

    /// Constructs a sequence from a ditted-bit-sequence string where white space is ignored
    /// (e.g. `"10..11.0"`).
    ///
    /// # Panics
    ///
    /// Panics if `ditted_bit_data` is not a valid ditted-bit sequence.
    pub fn from_ditted_string(ditted_bit_data: &str) -> Self {
        let mut seq = Self::new();
        seq.init_from_ditted_string_data(ditted_bit_data)
            .expect("invalid ditted bit sequence");
        seq
    }

    /// Constructs a sequence from a ditted-bit string where white space is ignored. If there
    /// are no dits, `hex` is true, and `ditted_bit_data` does not begin with `0x`, `0x` is
    /// prepended to the string before constructing the sequence.
    ///
    /// # Panics
    ///
    /// Panics if `ditted_bit_data` is not a valid ditted-bit sequence.
    pub fn from_ditted_string_hex(ditted_bit_data: &str, hex: bool) -> Self {
        let mut data = ditted_bit_data.to_string();
        if hex && !data.contains('.') && !data.starts_with("0x") {
            data = format!("0x{data}");
        }
        Self::from_ditted_string(&data)
    }

    /// Constructs a sequence of bytes to search for. No bits are masked off.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let dits = vec![0xffu8; bytes.len()];
        Self { index: 0, bits: bytes, dits }
    }

    /// Constructs a bit pattern to search for consisting of 0 bits, 1 bits, and don't care
    /// bits.
    ///
    /// `bytes` indicates the 0 and 1 bits that are cared about; `mask` masks off the bits
    /// that should be cared about, where a 0 indicates a "don't care".
    pub fn from_bytes_and_mask(bytes: Vec<u8>, mask: Vec<u8>) -> Self {
        Self { index: 0, bits: bytes, dits: mask }
    }

    /// Builds the smallest ditted sequence commensurate with two other ditted sequences.
    pub fn combine(s1: &DittedBitSequence, s2: &DittedBitSequence) -> Self {
        let len = s1.bits.len();
        let mut bits = vec![0u8; len];
        let mut dits = vec![0u8; len];
        for i in 0..len {
            dits[i] = s1.dits[i] & s2.dits[i] & (0xffu8 ^ s1.bits[i] ^ s2.bits[i]);
            bits[i] = s1.bits[i] & s2.bits[i];
        }
        Self { index: 0, bits, dits }
    }

    /// Returns the value bytes.
    pub fn get_value_bytes(&self) -> Vec<u8> {
        self.bits.clone()
    }

    /// Returns the mask bytes which correspond to the value bytes.
    pub fn get_mask_bytes(&self) -> Vec<u8> {
        self.dits.clone()
    }

    /// Concatenates `to_concat` to the end of this sequence and returns a new sequence.
    pub fn concatenate(&self, to_concat: &DittedBitSequence) -> Self {
        let mut bits = Vec::with_capacity(self.bits.len() + to_concat.bits.len());
        let mut dits = Vec::with_capacity(self.dits.len() + to_concat.dits.len());
        bits.extend_from_slice(&self.bits);
        bits.extend_from_slice(&to_concat.bits);
        dits.extend_from_slice(&self.dits);
        dits.extend_from_slice(&to_concat.dits);
        Self { index: 0, bits, dits }
    }

    /// Sets an index in a larger sequence, or an identifying id on this pattern.
    pub fn set_index(&mut self, index: i32) {
        self.index = index;
    }

    /// Returns the index or identifying id attached to this pattern.
    pub fn get_index(&self) -> i32 {
        self.index
    }

    /// Returns the number of bits that must be 0/1 (not don't care).
    pub fn get_num_fixed_bits(&self) -> usize {
        self.dits.iter().map(|d| d.count_ones() as usize).sum()
    }

    /// Returns the number of bits that are ditted (don't care).
    pub fn get_num_uncertain_bits(&self) -> usize {
        8 * self.dits.len() - self.get_num_fixed_bits()
    }

    /// Writes this sequence's bit representation into `buf`, preceded by a space per byte.
    pub fn write_bits(&self, buf: &mut String) {
        for chunk in 0..self.bits.len() {
            buf.push(' ');
            let dchomp = self.dits[chunk];
            let bchomp = self.bits[chunk];
            let mut pos: u8 = 128;
            while pos > 0 {
                if (dchomp & pos) == 0 {
                    buf.push('.');
                }
                else {
                    buf.push(if (bchomp & pos) != 0 { '1' } else { '0' });
                }
                pos >>= 1;
            }
        }
    }

    /// Returns a ditted hex string representing this sequence.
    pub fn get_hex_string(&self) -> String {
        let uncompressed = self.to_string();
        let parts: Vec<&str> = uncompressed.trim().split(' ').collect();
        let max = parts.len();
        let mut sb = String::new();
        for (i, part) in parts.iter().enumerate() {
            if part.contains('.') {
                sb.push_str(part);
                if i != max - 1 {
                    sb.push(' ');
                }
                continue;
            }
            let val = u8::from_str_radix(part.trim(), 2).expect("invalid binary chunk");
            sb.push_str(&format!("0x{val:02x}"));
            if i != max - 1 {
                sb.push(' ');
            }
        }
        sb
    }

    /// Restores ditted string data from an XML stream with hex/binary ditted sequences in the
    /// form:
    /// ```text
    ///    <data> 0x..d.4de2 ....0000 .1...... 00101101 11101001 </data>
    /// ```
    /// where `0x` starts a hex number and `.` is a don't care nibble (hex) or bit (binary).
    ///
    /// Returns the number of bytes read from the XML `<data>` tag.
    pub(crate) fn restore_xml_data<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
    ) -> Result<i32, XmlException> {
        parser.start(&["data"])?;
        let text = parser.end()?.get_text().to_string();
        self.init_from_ditted_string_data(&text).map_err(|_| {
            XmlException::with_message(format!(
                "Bad <data> tag in at line {} : {}",
                parser.get_line_number(),
                text
            ))
        })
    }

    /// Initializes this sequence with a ditted sequence from a string in the form
    /// (e.g. `011...1.`, `0x.F`, `01110011 0xAB`).
    ///
    /// Returns the number of bytes marked in the ditted sequence.
    fn init_from_ditted_string_data(
        &mut self,
        text: &str,
    ) -> Result<i32, DittedBitSequenceParseError> {
        let chars: Vec<char> = text.chars().collect();
        let char_at = |idx: usize| -> Result<char, DittedBitSequenceParseError> {
            chars
                .get(idx)
                .copied()
                .ok_or_else(|| DittedBitSequenceParseError::new("Bad ditted bit sequence"))
        };

        let mut mark_offset: i32 = -1;
        // -1: looking for start, -2: skip to EOL, 0: hex mode, 1: binary mode
        let mut mode: i32 = -1;
        let mut bit_array: Vec<u8> = Vec::new();
        let mut dit_array: Vec<u8> = Vec::new();
        let mut i: usize = 0;
        while i < chars.len() {
            let c1 = chars[i];
            if mode == -2 && c1 != '\n' {
                i += 1;
                continue;
            }
            if c1.is_whitespace() {
                mode = -1;
                i += 1;
                continue;
            }
            if c1 == '#' {
                // start comment - skip remainder of line
                mode = -2;
                i += 1;
                continue;
            }
            if mode == -1 {
                if c1 == '0' {
                    if char_at(i + 1)? == 'x' {
                        mode = 0; // Normal hexadecimal mode
                        i += 2;
                        continue;
                    }
                }
                else if c1 == '*' {
                    mark_offset = dit_array.len() as i32; // Set mark at current number of bytes specified
                    i += 1;
                    continue;
                }
                else if c1 == '0' || c1 == '1' || c1 == '.' {
                    mode = 1;
                }
                else {
                    return Err(DittedBitSequenceParseError::new("Bad ditted bit sequence"));
                }
            }
            if mode == 0 {
                let c2 = char_at(i + 1)?;
                i += 2;
                let mut val: u8 = 0;
                let mut mask: u8 = 0xff;
                if c1 == '.' {
                    mask ^= 0xf0;
                }
                else {
                    val = (c1.to_digit(16).ok_or_else(|| {
                        DittedBitSequenceParseError::new("Bad ditted bit sequence")
                    })? as u8)
                        << 4;
                }
                if c2 == '.' {
                    mask ^= 0xf;
                }
                else {
                    val |= c2.to_digit(16).ok_or_else(|| {
                        DittedBitSequenceParseError::new("Bad ditted bit sequence")
                    })? as u8;
                }

                bit_array.push(val);
                dit_array.push(mask);
            }
            else {
                let mut val: u8 = 0;
                let mut mask: u8 = 0;
                for j in 0..8 {
                    let cj = char_at(i + j)?;
                    if cj == '0' {
                        val <<= 1;
                        mask <<= 1;
                        mask |= 1;
                    }
                    else if cj == '.' {
                        val <<= 1;
                        mask <<= 1;
                    }
                    else {
                        val <<= 1;
                        val |= 1;
                        mask <<= 1;
                        mask |= 1;
                    }
                }
                i += 8;
                bit_array.push(val);
                dit_array.push(mask);
            }
        }
        self.bits = bit_array;
        self.dits = dit_array;
        Ok(mark_offset)
    }

    /// Returns the number of bits that are fixed, not ditted (don't care), among the first
    /// `marked` bytes of the pattern.
    pub fn get_num_initial_fixed_bits(&self, marked: i32) -> usize {
        if marked <= 0 || marked as usize > self.dits.len() {
            return 0; // perhaps return -1 instead?
        }
        self.dits[..marked as usize]
            .iter()
            .map(|d| d.count_ones() as usize)
            .sum()
    }
}

impl PartialEq for DittedBitSequence {
    fn eq(&self, other: &Self) -> bool {
        self.bits == other.bits && self.dits == other.dits
    }
}

impl Eq for DittedBitSequence {}

impl std::hash::Hash for DittedBitSequence {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.bits.hash(state);
        self.dits.hash(state);
    }
}

impl fmt::Display for DittedBitSequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = String::new();
        self.write_bits(&mut buf);
        write!(f, "{buf}")
    }
}

impl BytePattern for DittedBitSequence {
    fn size(&self) -> usize {
        self.bits.len()
    }

    /// Checks for a match of `byte_value` at `pattern_offset` in the pattern. An outside
    /// matcher keeps track of the match position within this ditted bit sequence, then calls
    /// this method to match.
    fn is_match(&self, pattern_offset: usize, byte_value: u8) -> bool {
        match self.dits.get(pattern_offset) {
            Some(&dit) => (byte_value & dit) == self.bits[pattern_offset],
            None => false,
        }
    }

    fn pre_sequence_length(&self) -> usize {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_from_bytes_and_mask_produces_expected_hex_string() {
        let bits = 0xe0u8; // 11100000
        let dits = 0xe7u8; // 11100111
        let seq = DittedBitSequence::from_bytes_and_mask(vec![bits], vec![dits]);
        assert_eq!(seq.get_hex_string(), "111..000");
    }

    #[test]
    fn constructor_from_ditted_string_hex_variants() {
        let seq = DittedBitSequence::from_ditted_string_hex("0x048f", true);
        assert_eq!(seq.get_hex_string(), "0x04 0x8f");

        let seq = DittedBitSequence::from_ditted_string_hex("00000000", false);
        assert_eq!(seq.get_hex_string(), "0x00");

        let seq = DittedBitSequence::from_ditted_string_hex("11111111", false);
        assert_eq!(seq.get_hex_string(), "0xff");

        let seq = DittedBitSequence::from_ditted_string_hex("1111000000001111", false);
        assert_eq!(seq.get_hex_string(), "0xf0 0x0f");

        let seq = DittedBitSequence::from_ditted_string_hex("0.0.1.1.11111111", false);
        assert_eq!(seq.get_hex_string(), "0.0.1.1. 0xff");
    }

    #[test]
    fn get_num_uncertain_bits_counts_dont_care_bits() {
        let seq = DittedBitSequence::from_ditted_string_hex("0xffff", true);
        assert_eq!(seq.get_num_uncertain_bits(), 0);

        let seq = DittedBitSequence::from_ditted_string_hex("0x0000", true);
        assert_eq!(seq.get_num_uncertain_bits(), 0);

        let bits = 0xa0u8; // 10100000
        let dits = 0x55u8; // 01010101
        let seq = DittedBitSequence::from_bytes_and_mask(vec![bits], vec![dits]);
        assert_eq!(seq.get_num_uncertain_bits(), 4);
    }

    #[test]
    fn combine_produces_least_upper_bound() {
        let zeros = DittedBitSequence::from_bytes_and_mask(vec![0], vec![0xff]);
        let ones = DittedBitSequence::from_bytes_and_mask(vec![0xff], vec![0xff]);

        let even_dits = 0x55u8; // 01010101
        let odd_dits = 0xaau8; // 10101010

        let evens = DittedBitSequence::from_bytes_and_mask(vec![0], vec![even_dits]);
        let odds = DittedBitSequence::from_bytes_and_mask(vec![0xff], vec![odd_dits]);

        let merge = DittedBitSequence::combine(&odds, &evens);
        assert_eq!(merge.get_num_fixed_bits(), 0);
        assert_eq!(merge.get_num_uncertain_bits(), 8);
        assert_eq!(merge.get_hex_string(), "........");

        let merge = DittedBitSequence::combine(&ones, &zeros);
        assert_eq!(merge.get_num_fixed_bits(), 0);
        assert_eq!(merge.get_num_uncertain_bits(), 8);
        assert_eq!(merge.get_hex_string(), "........");

        let merge = DittedBitSequence::combine(&evens, &zeros);
        assert_eq!(merge.get_num_fixed_bits(), 4);
        assert_eq!(merge.get_num_uncertain_bits(), 4);
        assert_eq!(merge.get_hex_string(), ".0.0.0.0");

        let merge = DittedBitSequence::combine(&odds, &ones);
        assert_eq!(merge.get_num_fixed_bits(), 4);
        assert_eq!(merge.get_num_uncertain_bits(), 4);
        assert_eq!(merge.get_hex_string(), "1.1.1.1.");
    }

    #[test]
    fn get_num_initial_fixed_bits_matches_java_parity_cases() {
        let uninitialized = DittedBitSequence::new();
        assert_eq!(uninitialized.get_num_initial_fixed_bits(0), 0);
        assert_eq!(uninitialized.get_num_initial_fixed_bits(1), 0);

        let length_zero = DittedBitSequence::from_bytes(vec![]);
        assert_eq!(length_zero.get_num_initial_fixed_bits(0), 0);
        assert_eq!(length_zero.get_num_initial_fixed_bits(1), 0);

        let no_dits = DittedBitSequence::from_ditted_string("0x00ff");
        assert_eq!(no_dits.get_num_initial_fixed_bits(0), 0);
        assert_eq!(no_dits.get_num_initial_fixed_bits(1), 8);
        assert_eq!(no_dits.get_num_initial_fixed_bits(2), 16);
        assert_eq!(no_dits.get_num_initial_fixed_bits(3), 0);

        let some_dits = DittedBitSequence::from_ditted_string("0.0.0.0.1.1.1.1.");
        assert_eq!(some_dits.get_num_initial_fixed_bits(0), 0);
        assert_eq!(some_dits.get_num_initial_fixed_bits(1), 4);
        assert_eq!(some_dits.get_num_initial_fixed_bits(2), 8);
        assert_eq!(some_dits.get_num_initial_fixed_bits(3), 0);

        let all_dits = DittedBitSequence::from_ditted_string("................");
        assert_eq!(all_dits.get_num_initial_fixed_bits(0), 0);
        assert_eq!(all_dits.get_num_initial_fixed_bits(1), 0);
        assert_eq!(all_dits.get_num_initial_fixed_bits(2), 0);
        assert_eq!(all_dits.get_num_initial_fixed_bits(3), 0);
    }

    #[test]
    fn is_match_checks_dits_and_bits() {
        // "1..0 00.." — 1st and 4th bits fixed to 1/0, rest don't care.
        let seq = DittedBitSequence::from_ditted_string("1..000..");
        assert!(BytePattern::is_match(&seq, 0, 0b1000_0000));
        assert!(BytePattern::is_match(&seq, 0, 0b1110_0011));
        assert!(!BytePattern::is_match(&seq, 0, 0b0000_0000));
    }

    #[test]
    fn is_match_out_of_bounds_offset_returns_false() {
        let seq = DittedBitSequence::from_bytes(vec![0xAB]);
        assert!(!BytePattern::is_match(&seq, 1, 0xAB));
    }

    #[test]
    fn size_and_pre_sequence_length() {
        let seq = DittedBitSequence::from_bytes(vec![1, 2, 3]);
        assert_eq!(BytePattern::size(&seq), 3);
        assert_eq!(BytePattern::pre_sequence_length(&seq), 0);
    }

    #[test]
    fn index_getter_and_setter() {
        let mut seq = DittedBitSequence::new();
        assert_eq!(seq.get_index(), 0);
        seq.set_index(42);
        assert_eq!(seq.get_index(), 42);
    }

    #[test]
    fn concatenate_joins_bits_and_dits() {
        let a = DittedBitSequence::from_bytes_and_mask(vec![0b1010_0000], vec![0xf0]);
        let b = DittedBitSequence::from_bytes_and_mask(vec![0b0000_1111], vec![0x0f]);
        let joined = a.concatenate(&b);
        assert_eq!(joined.get_value_bytes(), vec![0b1010_0000, 0b0000_1111]);
        assert_eq!(joined.get_mask_bytes(), vec![0xf0, 0x0f]);
    }

    #[test]
    fn equal_sequences_are_equal_and_hash_equal() {
        let a = DittedBitSequence::from_ditted_string("1.0.1.0.");
        let b = DittedBitSequence::from_ditted_string("1.0.1.0.");
        assert_eq!(a, b);

        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut ha = DefaultHasher::new();
        a.hash(&mut ha);
        let mut hb = DefaultHasher::new();
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn different_sequences_are_not_equal() {
        let a = DittedBitSequence::from_ditted_string("11111111");
        let b = DittedBitSequence::from_ditted_string("00000000");
        assert_ne!(a, b);
    }

    #[test]
    #[should_panic(expected = "invalid ditted bit sequence")]
    fn from_ditted_string_panics_on_malformed_input() {
        DittedBitSequence::from_ditted_string("zzzz");
    }

    #[test]
    fn comment_is_skipped() {
        let seq = DittedBitSequence::from_ditted_string("# a comment\n0x00");
        assert_eq!(seq.get_hex_string(), "0x00");
    }

    #[test]
    fn mark_offset_reports_byte_position() {
        let mut seq = DittedBitSequence::new();
        let mark_offset = seq.init_from_ditted_string_data("0x00 *0x11").unwrap();
        assert_eq!(mark_offset, 1);
        assert_eq!(seq.get_hex_string(), "0x00 0x11");
    }

    #[test]
    fn no_mark_returns_negative_one() {
        let mut seq = DittedBitSequence::new();
        let mark_offset = seq.init_from_ditted_string_data("0x00").unwrap();
        assert_eq!(mark_offset, -1);
    }

    #[test]
    fn display_matches_write_bits() {
        let seq = DittedBitSequence::from_bytes_and_mask(vec![0xe0], vec![0xe7]);
        let mut buf = String::new();
        seq.write_bits(&mut buf);
        assert_eq!(seq.to_string(), buf);
    }
}
