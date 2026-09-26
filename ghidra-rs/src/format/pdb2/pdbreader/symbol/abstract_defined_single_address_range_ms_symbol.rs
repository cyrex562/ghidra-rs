//! Various flavors of "Defined Single Address Range" PDB symbol.
//!
//! Corresponds to the Java abstract class
//! `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractDefinedSingleAddressRangeMsSymbol`.
//!
//! Note: we do not necessarily understand each of these symbol type classes. Refer to the
//! base class for more information.
//!
//! Ported as a trait (rather than a struct extending a concrete `AbstractMsSymbol` parsing
//! pipeline) because this type was selected as a dependency-cycle cut-point: leaf symbol types
//! that carry a defined single address range (not yet ported) can depend on
//! `dyn AbstractDefinedSingleAddressRangeMsSymbol` instead of a concrete class, so their crates
//! don't need to see `AbstractMsSymbol`/`AbstractPdb`/`PdbByteReader`'s full parsing machinery.
//!
//! `AddressRange` and `AddressGap` (Java classes in the same `symbol` package) are not yet
//! ported, so they are represented here via minimal placeholder structs in
//! [`seam_stubs`](crate::format::seam_stubs); see `STUBS.tsv` for provenance.

use crate::format::pdb2::pdbreader::abstract_parsable_item::AbstractParsableItem;
use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;
use crate::format::seam_stubs::{AddressGap, AddressRange};

/// The various flavors of Defined Single Address Range symbol.
pub trait AbstractDefinedSingleAddressRangeMsSymbol {
    /// Returns the address range.
    fn address_range(&self) -> &AddressRange;

    /// Returns the list of address gaps.
    fn address_gap_list(&self) -> &[AddressGap];

    /// Outputs the Range and Gaps data into `builder`, matching Java's
    /// `emitRangeAndGaps(StringBuilder)`.
    fn emit_range_and_gaps(&self, builder: &mut String) {
        builder.push_str(&self.address_range().to_display_string());
        builder.push_str(&format!(", {} Gaps", self.address_gap_list().len()));
        if self.address_gap_list().is_empty() {
            return;
        }
        builder.push_str(" (startOffset, length):");
        for gap in self.address_gap_list() {
            builder.push_str(&gap.to_display_string());
        }
    }
}

/// Parses an [`AddressRange`] followed by zero or more [`AddressGap`]s from `reader`, matching
/// Java's `parseRangeAndGaps(PdbByteReader)`.
pub fn parse_range_and_gaps(
    reader: &mut PdbByteReader,
) -> Result<(AddressRange, Vec<AddressGap>), PdbException> {
    let start_offset = reader.parse_unsigned_int_val()?;
    let section_start = reader.parse_unsigned_short_val()?;
    let length_range = reader.parse_unsigned_short_val()?;
    let address_range = AddressRange { start_offset, section_start, length_range };

    let mut address_gap_list = Vec::new();
    while reader.has_more() {
        let gap_start_offset = reader.parse_unsigned_short_val()?;
        let gap_length_range = reader.parse_unsigned_short_val()?;
        address_gap_list.push(AddressGap { gap_start_offset, length_range: gap_length_range });
    }

    Ok((address_range, address_gap_list))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock impl proving the trait is object-safe and usable by a caller that only knows about
    /// `dyn AbstractDefinedSingleAddressRangeMsSymbol`, matching how a cycle-breaking cut-point
    /// trait is consumed. Populated via [`parse_range_and_gaps`], exercising the real parsing
    /// logic rather than hand-setting fields.
    struct MockRangeSymbol {
        address_range: AddressRange,
        address_gap_list: Vec<AddressGap>,
    }

    impl AbstractDefinedSingleAddressRangeMsSymbol for MockRangeSymbol {
        fn address_range(&self) -> &AddressRange {
            &self.address_range
        }

        fn address_gap_list(&self) -> &[AddressGap] {
            &self.address_gap_list
        }
    }

    #[test]
    fn parse_range_and_gaps_reads_range_then_gaps_until_exhausted() {
        let mut reader = PdbByteReader::new(vec![
            0x00, 0x10, 0x00, 0x00, // startOffset = 0x1000
            0x01, 0x00, // sectionStart = 1
            0x20, 0x00, // lengthRange = 0x20
            0x10, 0x00, 0x08, 0x00, // gap 1: (0x10, 0x08)
            0x30, 0x00, 0x04, 0x00, // gap 2: (0x30, 0x04)
        ]);
        let (address_range, address_gap_list) = parse_range_and_gaps(&mut reader).unwrap();

        assert_eq!(address_range.start_offset, 0x1000);
        assert_eq!(address_range.section_start, 1);
        assert_eq!(address_range.length_range, 0x20);
        assert_eq!(address_gap_list.len(), 2);
        assert_eq!(address_gap_list[0].gap_start_offset, 0x10);
        assert_eq!(address_gap_list[0].length_range, 0x08);
        assert_eq!(address_gap_list[1].gap_start_offset, 0x30);
        assert_eq!(address_gap_list[1].length_range, 0x04);
    }

    #[test]
    fn parse_range_and_gaps_with_no_trailing_bytes_has_empty_gap_list() {
        let mut reader = PdbByteReader::new(vec![
            0x00, 0x00, 0x00, 0x00, // startOffset = 0
            0x00, 0x00, // sectionStart = 0
            0x00, 0x00, // lengthRange = 0
        ]);
        let (_, address_gap_list) = parse_range_and_gaps(&mut reader).unwrap();
        assert!(address_gap_list.is_empty());
    }

    #[test]
    fn parse_range_and_gaps_errors_on_short_buffer() {
        let mut reader = PdbByteReader::new(vec![0x00, 0x00]);
        assert!(parse_range_and_gaps(&mut reader).is_err());
    }

    #[test]
    fn emit_range_and_gaps_matches_java_format_with_gaps() {
        let (address_range, address_gap_list) = parse_range_and_gaps(&mut PdbByteReader::new(vec![
            0x00, 0x10, 0x00, 0x00, 0x01, 0x00, 0x20, 0x00, 0x10, 0x00, 0x08, 0x00,
        ]))
        .unwrap();
        let sym = MockRangeSymbol { address_range, address_gap_list };

        let mut builder = String::new();
        sym.emit_range_and_gaps(&mut builder);

        assert_eq!(
            builder,
            "   Range: [0001:00001000] - [0001:00001020], 1 Gaps (startOffset, length): (0010, 8)"
        );
    }

    #[test]
    fn emit_range_and_gaps_omits_gap_detail_when_empty() {
        let sym = MockRangeSymbol {
            address_range: AddressRange { start_offset: 0, section_start: 0, length_range: 0 },
            address_gap_list: vec![],
        };
        let mut builder = String::new();
        sym.emit_range_and_gaps(&mut builder);
        assert_eq!(builder, "   Range: [0000:00000000] - [0000:00000000], 0 Gaps");
    }

    #[test]
    fn is_object_safe() {
        let sym: Box<dyn AbstractDefinedSingleAddressRangeMsSymbol> = Box::new(MockRangeSymbol {
            address_range: AddressRange { start_offset: 5, section_start: 1, length_range: 2 },
            address_gap_list: vec![],
        });
        assert_eq!(sym.address_range().start_offset, 5);
    }
}
