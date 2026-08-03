use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;
use crate::format::pdb2::pdbreader::r#type::ms_type::MsType;
use crate::format::seam_stubs::{AbstractMsType, AbstractPdb, Bind, RecordNumber};

/// Trait for the various flavors of Dimensioned Array type with constant upper and lower
/// bounds on the dimensions.
///
/// Corresponds to the Java abstract class
/// `ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractDimensionedArrayConstBoundsLowerUpperMsType`.
///
/// Note: we do not necessarily understand each of these data type classes. Refer to the
/// base class for more information.
pub trait AbstractDimensionedArrayConstBoundsLowerUpperMsType: MsType {
    /// Appears to be number of dimensions--independence of which cannot be guaranteed to
    /// determine a true "rank."
    fn rank(&self) -> i32;

    /// Returns the record number of the element type of the array.
    fn type_record_number(&self) -> RecordNumber;

    /// Returns the constant lower bound of each dimension, one entry per
    /// [`rank`](Self::rank).
    fn lower_bound(&self) -> &[i64];

    /// Returns the constant upper bound of each dimension, one entry per
    /// [`rank`](Self::rank).
    fn upper_bound(&self) -> &[i64];

    /// Returns the element type pointed to by
    /// [`type_record_number`](Self::type_record_number).
    fn element_type(&self, pdb: &dyn AbstractPdb) -> Box<dyn AbstractMsType> {
        pdb.get_type_record(self.type_record_number())
    }

    /// Emits string output of this class into `builder`.
    ///
    /// `bind` is accepted for signature fidelity with the Java override but, matching the Java
    /// implementation (there is no documented API for output), is not consulted.
    fn emit(&self, builder: &mut String, _bind: Bind, pdb: &dyn AbstractPdb) {
        builder.push_str(&self.element_type(pdb).to_display_string());
        for i in 0..self.rank() as usize {
            builder.push('[');
            builder.push_str(&self.lower_bound()[i].to_string());
            builder.push(':');
            builder.push_str(&self.upper_bound()[i].to_string());
            builder.push(']');
        }
    }
}

/// Parses the constant lower/upper dimension bounds that trail the beginning fields, mirroring
/// the shared logic in the Java constructor
/// (`AbstractDimensionedArrayConstBoundsLowerUpperMsType(AbstractPdb, PdbByteReader)`) that runs
/// after the implementation-specific `parseBeginningFields` step.
///
/// The remaining data is expected to be a multiple of `2 * rank` (one lower and one upper bound
/// per dimension) times the size of the integral element (1, 2, 4, or 8 bytes); that
/// per-element size is inferred from the remaining length and used to pick the appropriate
/// parse width.
///
/// # Errors
/// Returns [`PdbException`] if `rank` is not positive, if the remaining data length is not a
/// multiple of `2 * rank`, or if the inferred per-element size is not one of 1, 2, 4, or 8
/// bytes.
pub fn parse_bounds(
    rank: i32,
    reader: &mut PdbByteReader,
) -> Result<(Vec<i64>, Vec<i64>), PdbException> {
    if rank <= 0 {
        return Err(PdbException::new("We are not expecting this--needs investigation"));
    }
    let rank = rank as usize;
    let remaining_data = reader.parse_bytes_remaining();
    let length = remaining_data.len();
    if length % (2 * rank) != 0 {
        return Err(PdbException::new("We are not expecting this--needs investigation"));
    }
    let mut bounds_reader = PdbByteReader::new(remaining_data);
    let mut lower_bound = vec![0i64; rank];
    let mut upper_bound = vec![0i64; rank];
    let size = length / (2 * rank);
    match size {
        1 => {
            for i in 0..rank {
                lower_bound[i] = bounds_reader.parse_unsigned_byte_val()? as i64;
                upper_bound[i] = bounds_reader.parse_unsigned_byte_val()? as i64;
            }
        }
        2 => {
            for i in 0..rank {
                lower_bound[i] = bounds_reader.parse_short()? as i64;
                upper_bound[i] = bounds_reader.parse_short()? as i64;
            }
        }
        4 => {
            for i in 0..rank {
                lower_bound[i] = bounds_reader.parse_int()? as i64;
                upper_bound[i] = bounds_reader.parse_int()? as i64;
            }
        }
        8 => {
            for i in 0..rank {
                lower_bound[i] = bounds_reader.parse_long()?;
                upper_bound[i] = bounds_reader.parse_long()?;
            }
        }
        _ => {
            return Err(PdbException::new("We are not expecting this--needs investigation"));
        }
    }
    Ok((lower_bound, upper_bound))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::pdb2::pdbreader::abstract_parsable_item::AbstractParsableItem;
    use crate::format::pdb2::pdbreader::id_ms_parsable::IdMsParsable;
    use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbCharset;
    use crate::format::seam_stubs::PdbReaderOptions;

    struct MockElementType;
    impl AbstractParsableItem for MockElementType {
        fn emit(&self, builder: &mut String) {
            builder.push_str("ElementType");
        }
    }
    impl AbstractMsType for MockElementType {}

    struct MockPdb {
        options: PdbReaderOptions,
    }
    impl AbstractPdb for MockPdb {
        fn pdb_reader_options(&self) -> &PdbReaderOptions {
            &self.options
        }

        fn get_type_record(&self, _record_number: RecordNumber) -> Box<dyn AbstractMsType> {
            Box::new(MockElementType)
        }
    }

    fn mock_pdb() -> MockPdb {
        MockPdb {
            options: PdbReaderOptions {
                one_byte_charset: PdbCharset::OneByte,
                two_byte_charset: PdbCharset::Utf16Le,
            },
        }
    }

    struct MockDimensionedArray {
        rank: i32,
        type_record_number: RecordNumber,
        lower_bound: Vec<i64>,
        upper_bound: Vec<i64>,
    }
    impl IdMsParsable for MockDimensionedArray {
        fn pdb_id(&self) -> i32 {
            0x1508
        }
    }
    impl MsType for MockDimensionedArray {}
    impl AbstractDimensionedArrayConstBoundsLowerUpperMsType for MockDimensionedArray {
        fn rank(&self) -> i32 {
            self.rank
        }

        fn type_record_number(&self) -> RecordNumber {
            self.type_record_number
        }

        fn lower_bound(&self) -> &[i64] {
            &self.lower_bound
        }

        fn upper_bound(&self) -> &[i64] {
            &self.upper_bound
        }
    }

    #[test]
    fn parse_bounds_reads_one_byte_elements() {
        // rank = 2, remaining length = 4 => size = 4 / (2*2) = 1 byte per element.
        let bytes: Vec<u8> = vec![0x01, 0x05, 0x02, 0x0a];
        let mut reader = PdbByteReader::new(bytes);
        let (lower, upper) = parse_bounds(2, &mut reader).unwrap();
        assert_eq!(lower, vec![1, 2]);
        assert_eq!(upper, vec![5, 10]);
    }

    #[test]
    fn parse_bounds_reads_four_byte_elements() {
        // rank = 1, remaining length = 8 => size = 8 / (2*1) = 4 bytes per element.
        let bytes: Vec<u8> = vec![
            0x64, 0x00, 0x00, 0x00, // lower[0] = 100
            0xc8, 0x00, 0x00, 0x00, // upper[0] = 200
        ];
        let mut reader = PdbByteReader::new(bytes);
        let (lower, upper) = parse_bounds(1, &mut reader).unwrap();
        assert_eq!(lower, vec![100]);
        assert_eq!(upper, vec![200]);
    }

    #[test]
    fn parse_bounds_rejects_non_multiple_length() {
        let bytes: Vec<u8> = vec![0x01, 0x02, 0x03];
        let mut reader = PdbByteReader::new(bytes);
        assert!(parse_bounds(2, &mut reader).is_err());
    }

    #[test]
    fn parse_bounds_rejects_non_positive_rank() {
        let bytes: Vec<u8> = vec![0x01, 0x02];
        let mut reader = PdbByteReader::new(bytes);
        assert!(parse_bounds(0, &mut reader).is_err());
    }

    #[test]
    fn emit_matches_java_format() {
        let t = MockDimensionedArray {
            rank: 2,
            type_record_number: RecordNumber { number: 7 },
            lower_bound: vec![0, 1],
            upper_bound: vec![9, 4],
        };
        let pdb = mock_pdb();
        let mut builder = String::new();
        t.emit(&mut builder, Bind::None, &pdb);
        assert_eq!(builder, "ElementType[0:9][1:4]");
    }

    #[test]
    fn is_object_safe() {
        let t: Box<dyn AbstractDimensionedArrayConstBoundsLowerUpperMsType> =
            Box::new(MockDimensionedArray {
                rank: 0,
                type_record_number: RecordNumber::no_type(),
                lower_bound: vec![],
                upper_bound: vec![],
            });
        assert_eq!(t.pdb_id(), 0x1508);
        assert_eq!(t.rank(), 0);
    }
}
