use std::hash::{Hash, Hasher};
use std::io::{self, Write};

use crate::feature::bitpatterns::info::context_register_filter::ContextRegisterFilter;
use crate::feature::bitpatterns::info::pattern_type::PatternType;
use crate::util::bytesearch::ditted_bit_sequence::DittedBitSequence;

/// A pattern (selected by the user) displayed in the pattern clipboard.
///
/// Mirrors `ghidra.bitpatterns.gui.PatternInfoRowObject`.
#[derive(Debug, Clone)]
pub struct PatternInfoRowObject {
    pattern_type: PatternType,
    bit_sequence: DittedBitSequence,
    c_reg_filter: Option<ContextRegisterFilter>,
    note: Option<String>,
    alignment: Option<i32>,
}

impl PatternInfoRowObject {
    /// Represents one pattern.
    ///
    /// * `pattern_type` - type of the pattern
    /// * `bit_sequence` - bit sequence of the pattern
    /// * `c_reg_filter` - context register filter constraining pattern
    pub fn new(
        pattern_type: PatternType,
        bit_sequence: DittedBitSequence,
        c_reg_filter: Option<ContextRegisterFilter>,
    ) -> Self {
        Self {
            pattern_type,
            bit_sequence,
            c_reg_filter,
            note: None,
            alignment: None,
        }
    }

    /// Gets the type of this pattern.
    pub fn get_pattern_type(&self) -> PatternType {
        self.pattern_type
    }

    /// Gets the [`DittedBitSequence`] representing this pattern.
    pub fn get_ditted_bit_sequence(&self) -> &DittedBitSequence {
        &self.bit_sequence
    }

    /// Gets the [`ContextRegisterFilter`] associated with this pattern.
    pub fn get_context_register_filter(&self) -> Option<&ContextRegisterFilter> {
        self.c_reg_filter.as_ref()
    }

    /// Gets the alignment associated with this pattern.
    pub fn get_alignment(&self) -> Option<i32> {
        self.alignment
    }

    /// Sets the alignment associated with this pattern.
    pub fn set_alignment(&mut self, alignment: Option<i32>) {
        self.alignment = alignment;
    }

    /// Gets the note associated with this pattern.
    pub fn get_note(&self) -> Option<&str> {
        self.note.as_deref()
    }

    /// Sets the note associated with this pattern.
    pub fn set_note(&mut self, note: &str) {
        self.note = Some(note.trim().to_string());
    }

    /// Export the patterns to an XML file.
    ///
    /// * `rows` - patterns
    /// * `writer` - destination
    /// * `postbits` - number of postbits to require
    /// * `totalbits` - number of totalbits to require
    pub fn export_xml_file<W: Write>(
        rows: &[PatternInfoRowObject],
        writer: &mut W,
        postbits: i32,
        totalbits: i32,
    ) -> io::Result<()> {
        writer.write_all(b"<patternlist>\n")?;
        writer.write_all(b"  <patternpairs totalbits=\"")?;
        write!(writer, "{totalbits}")?;
        writer.write_all(b"\" postbits=\"")?;
        write!(writer, "{postbits}")?;
        writer.write_all(b"\">\n")?;
        writer.write_all(b"    <prepatterns>\n")?;
        for row in rows {
            if row.get_pattern_type() == PatternType::Pre {
                writer.write_all(b"        <data>")?;
                writer.write_all(row.get_ditted_bit_sequence().get_hex_string().as_bytes())?;
                writer.write_all(b"</data>\n")?;
            }
        }
        writer.write_all(b"    </prepatterns>\n")?;
        writer.write_all(b"    <postpatterns>\n")?;
        for row in rows {
            if row.get_pattern_type() == PatternType::First {
                writer.write_all(b"       <data>")?;
                writer.write_all(row.get_ditted_bit_sequence().get_hex_string().as_bytes())?;
                writer.write_all(b"</data>\n")?;
            }
        }
        // find the alignment and context register constraints
        let mut alignment = None;
        let mut c_reg_filter = None;
        for row in rows {
            if row.get_pattern_type() == PatternType::First {
                alignment = row.get_alignment();
                c_reg_filter = row.get_context_register_filter();
                break;
            }
        }
        if let Some(alignment) = alignment {
            writer.write_all(b"       <align mark=\"0\" bits=\"")?;
            write!(writer, "{}", (alignment as u32).trailing_zeros())?;
            writer.write_all(b"\"/>\n")?;
        }
        if let Some(c_reg_filter) = c_reg_filter {
            let mut names: Vec<&String> = c_reg_filter.get_value_map().keys().collect();
            names.sort();
            for name in names {
                let value = c_reg_filter.get_value_map()[name];
                writer.write_all(b"       <setcontext name=\"")?;
                writer.write_all(name.as_bytes())?;
                writer.write_all(b"\" value=\"")?;
                write!(writer, "{value}")?;
                writer.write_all(b"\"/>\n")?;
            }
        }
        writer.write_all(b"       <funcstart/>\n")?;
        writer.write_all(b"    </postpatterns>\n")?;
        writer.write_all(b"  </patternpairs>\n")?;
        writer.write_all(b"</patternlist>\n")?;
        Ok(())
    }
}

// don't hash in the note
impl Hash for PatternInfoRowObject {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pattern_type.hash(state);
        self.bit_sequence.hash(state);
        self.c_reg_filter.as_ref().map(|f| f.get_compact_string()).hash(state);
        self.alignment.hash(state);
    }
}

// don't consider the note
impl PartialEq for PatternInfoRowObject {
    fn eq(&self, other: &Self) -> bool {
        self.pattern_type == other.pattern_type
            && self.bit_sequence == other.bit_sequence
            && self.c_reg_filter == other.c_reg_filter
            && self.alignment == other.alignment
    }
}

impl Eq for PatternInfoRowObject {}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_row(pattern_type: PatternType, hex: &str) -> PatternInfoRowObject {
        PatternInfoRowObject::new(pattern_type, DittedBitSequence::from_ditted_string_hex(hex, true), None)
    }

    #[test]
    fn new_row_has_no_note_or_alignment() {
        let row = make_row(PatternType::First, "0x00");
        assert_eq!(row.get_note(), None);
        assert_eq!(row.get_alignment(), None);
        assert_eq!(row.get_pattern_type(), PatternType::First);
    }

    #[test]
    fn set_note_trims_whitespace() {
        let mut row = make_row(PatternType::First, "0x00");
        row.set_note("  hello world  ");
        assert_eq!(row.get_note(), Some("hello world"));
    }

    #[test]
    fn set_and_get_alignment() {
        let mut row = make_row(PatternType::First, "0x00");
        row.set_alignment(Some(4));
        assert_eq!(row.get_alignment(), Some(4));
    }

    #[test]
    fn context_register_filter_round_trip() {
        let mut filter = ContextRegisterFilter::new();
        filter.add_reg_and_value_to_filter("TMode", 1).unwrap();
        let row = PatternInfoRowObject::new(
            PatternType::First,
            DittedBitSequence::from_ditted_string_hex("0x00", true),
            Some(filter.clone()),
        );
        assert_eq!(row.get_context_register_filter(), Some(&filter));
    }

    #[test]
    fn equality_ignores_note() {
        let mut a = make_row(PatternType::First, "0x00");
        let mut b = make_row(PatternType::First, "0x00");
        a.set_note("note a");
        b.set_note("note b");
        assert_eq!(a, b);
    }

    #[test]
    fn equality_considers_type_bitsequence_filter_and_alignment() {
        let a = make_row(PatternType::First, "0x00");
        let b = make_row(PatternType::Pre, "0x00");
        assert_ne!(a, b);

        let mut c = make_row(PatternType::First, "0x00");
        let mut d = make_row(PatternType::First, "0x00");
        c.set_alignment(Some(2));
        d.set_alignment(Some(4));
        assert_ne!(c, d);
    }

    #[test]
    fn hash_ignores_note() {
        use std::collections::hash_map::DefaultHasher;

        let mut a = make_row(PatternType::First, "0x00");
        let mut b = make_row(PatternType::First, "0x00");
        a.set_note("note a");
        b.set_note("note b");

        let mut ha = DefaultHasher::new();
        a.hash(&mut ha);
        let mut hb = DefaultHasher::new();
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn export_xml_file_writes_expected_structure() {
        let mut filter = ContextRegisterFilter::new();
        filter.add_reg_and_value_to_filter("TMode", 1).unwrap();

        let pre_row = make_row(PatternType::Pre, "0x11");
        let mut first_row = PatternInfoRowObject::new(
            PatternType::First,
            DittedBitSequence::from_ditted_string_hex("0x22", true),
            Some(filter),
        );
        first_row.set_alignment(Some(4));

        let rows = vec![pre_row, first_row];
        let mut buf: Vec<u8> = Vec::new();
        PatternInfoRowObject::export_xml_file(&rows, &mut buf, 8, 16).unwrap();
        let xml = String::from_utf8(buf).unwrap();

        assert!(xml.contains("<patternpairs totalbits=\"16\" postbits=\"8\">"));
        assert!(xml.contains("<data>0x11</data>"));
        assert!(xml.contains("<data>0x22</data>"));
        assert!(xml.contains("<align mark=\"0\" bits=\"2\"/>"));
        assert!(xml.contains("<setcontext name=\"TMode\" value=\"1\"/>"));
        assert!(xml.contains("<funcstart/>"));
    }

    #[test]
    fn export_xml_file_with_no_alignment_or_filter_omits_those_tags() {
        let row = make_row(PatternType::First, "0x00");
        let rows = vec![row];
        let mut buf: Vec<u8> = Vec::new();
        PatternInfoRowObject::export_xml_file(&rows, &mut buf, 0, 0).unwrap();
        let xml = String::from_utf8(buf).unwrap();

        assert!(!xml.contains("<align"));
        assert!(!xml.contains("<setcontext"));
    }
}
