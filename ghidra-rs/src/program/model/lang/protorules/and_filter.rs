use crate::program::model::lang::protorules::qualifier_filter::QualifierFilter;
use crate::program::model::pcode::Encoder;
use crate::program::seam_stubs::PrototypePieces;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Logically AND multiple [`QualifierFilter`]s together into a single filter.
///
/// An instance contains some number of other arbitrary filters. In order for this filter to
/// pass, all these contained filters must pass.
///
/// Port of `ghidra.program.model.lang.protorules.AndFilter`.
pub struct AndFilter {
    /// Filters being logically ANDed together (`AndFilter.subQualifiers`).
    pub sub_qualifiers: Vec<Box<dyn QualifierFilter>>,
}

impl AndFilter {
    /// Port of the `(ArrayList<QualifierFilter> qualifierList)` constructor. Takes ownership of
    /// every filter in `qualifier_list`, mirroring the Java doc's "assumes ownership" note.
    pub fn new(qualifier_list: Vec<Box<dyn QualifierFilter>>) -> Self {
        AndFilter { sub_qualifiers: qualifier_list }
    }
}

impl Clone for AndFilter {
    fn clone(&self) -> Self {
        AndFilter {
            sub_qualifiers: self.sub_qualifiers.iter().map(|q| q.clone_box()).collect(),
        }
    }
}

impl QualifierFilter for AndFilter {
    fn clone_box(&self) -> Box<dyn QualifierFilter> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn is_equivalent(&self, op: &dyn QualifierFilter) -> bool {
        let Some(other) = op.as_any().downcast_ref::<AndFilter>() else {
            return false;
        };
        if self.sub_qualifiers.len() != other.sub_qualifiers.len() {
            return false;
        }
        // Preserve strict order
        self.sub_qualifiers
            .iter()
            .zip(other.sub_qualifiers.iter())
            .all(|(a, b)| a.is_equivalent(b.as_ref()))
    }

    fn filter(&self, proto: &PrototypePieces, pos: i32) -> bool {
        self.sub_qualifiers.iter().all(|q| q.filter(proto, pos))
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        for q in &self.sub_qualifiers {
            q.encode(encoder)?;
        }
        Ok(())
    }

    fn restore_xml<P: XmlPullParser>(&mut self, _parser: &mut P) -> Result<(), XmlParseException>
    where
        Self: Sized,
    {
        // Port of Java's `restoreXml`, whose body is the comment "This method is not called":
        // an `AndFilter` is built directly by its collector (whatever restores the enclosing
        // `<rule>`/qualifier list gathers named sub-qualifier elements itself and calls
        // `AndFilter::new`), never by dispatching a `<and>`-tagged element to this method.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::protorules::position_match_filter::PositionMatchFilter;

    #[derive(Clone)]
    struct AlwaysTrue;
    impl QualifierFilter for AlwaysTrue {
        fn clone_box(&self) -> Box<dyn QualifierFilter> {
            Box::new(self.clone())
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
        fn is_equivalent(&self, op: &dyn QualifierFilter) -> bool {
            op.as_any().downcast_ref::<AlwaysTrue>().is_some()
        }
        fn filter(&self, _proto: &PrototypePieces, _pos: i32) -> bool {
            true
        }
        fn encode(&self, _encoder: &mut dyn Encoder) -> std::io::Result<()> {
            Ok(())
        }
        fn restore_xml<P: XmlPullParser>(&mut self, _parser: &mut P) -> Result<(), XmlParseException>
        where
            Self: Sized,
        {
            Ok(())
        }
    }

    #[test]
    fn empty_and_filter_passes_vacuously() {
        let f = AndFilter::new(Vec::new());
        let proto = PrototypePieces::default();
        assert!(f.filter(&proto, 0));
    }

    #[test]
    fn filter_requires_all_sub_qualifiers_to_pass() {
        let f = AndFilter::new(vec![
            Box::new(PositionMatchFilter::new(2)),
            Box::new(AlwaysTrue),
        ]);
        let proto = PrototypePieces::default();
        assert!(f.filter(&proto, 2));
        assert!(!f.filter(&proto, 3)); // PositionMatchFilter(2) fails
    }

    #[test]
    fn is_equivalent_requires_same_length_and_order() {
        let a = AndFilter::new(vec![
            Box::new(PositionMatchFilter::new(1)),
            Box::new(PositionMatchFilter::new(2)),
        ]);
        let b = AndFilter::new(vec![
            Box::new(PositionMatchFilter::new(1)),
            Box::new(PositionMatchFilter::new(2)),
        ]);
        let reordered = AndFilter::new(vec![
            Box::new(PositionMatchFilter::new(2)),
            Box::new(PositionMatchFilter::new(1)),
        ]);
        let shorter = AndFilter::new(vec![Box::new(PositionMatchFilter::new(1))]);

        assert!(QualifierFilter::is_equivalent(&a, &b));
        assert!(!QualifierFilter::is_equivalent(&a, &reordered));
        assert!(!QualifierFilter::is_equivalent(&a, &shorter));
    }

    #[test]
    fn clone_box_produces_independent_equivalent_copy() {
        let f = AndFilter::new(vec![Box::new(PositionMatchFilter::new(7))]);
        let cloned = f.clone_box();
        assert!(QualifierFilter::is_equivalent(&f, cloned.as_ref()));
    }

    struct RecordingEncoder(i32);
    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, _elem_id: crate::program::model::pcode::ElementId) -> std::io::Result<()> {
            Ok(())
        }
        fn close_element(&mut self, _elem_id: crate::program::model::pcode::ElementId) -> std::io::Result<()> {
            Ok(())
        }
        fn write_bool(&mut self, _attrib_id: crate::program::model::pcode::AttributeId, _val: bool) -> std::io::Result<()> {
            Ok(())
        }
        fn write_signed_integer(&mut self, _attrib_id: crate::program::model::pcode::AttributeId, _val: i64) -> std::io::Result<()> {
            self.0 += 1;
            Ok(())
        }
        fn write_unsigned_integer(&mut self, _attrib_id: crate::program::model::pcode::AttributeId, _val: u64) -> std::io::Result<()> {
            Ok(())
        }
        fn write_string(&mut self, _attrib_id: crate::program::model::pcode::AttributeId, _val: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn write_string_indexed(&mut self, _attrib_id: crate::program::model::pcode::AttributeId, _index: i32, _val: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn write_space(&mut self, _attrib_id: crate::program::model::pcode::AttributeId, _spc: &crate::program::model::address::AddressSpace) -> std::io::Result<()> {
            Ok(())
        }
        fn write_space_indexed(&mut self, _attrib_id: crate::program::model::pcode::AttributeId, _index: i32, _name: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn write_opcode(&mut self, _attrib_id: crate::program::model::pcode::AttributeId, _opcode: crate::decompiler::opcodes::op_code::OpCode) -> std::io::Result<()> {
            Ok(())
        }
        fn write_opcode_ordinal(&mut self, _attrib_id: crate::program::model::pcode::AttributeId, _opcode: i32) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn encode_delegates_to_every_sub_qualifier_without_wrapping() {
        let f = AndFilter::new(vec![
            Box::new(PositionMatchFilter::new(1)),
            Box::new(PositionMatchFilter::new(2)),
        ]);
        let mut enc = RecordingEncoder(0);
        f.encode(&mut enc).unwrap();
        // Each PositionMatchFilter::encode writes exactly one signed integer (ATTRIB_INDEX).
        assert_eq!(enc.0, 2);
    }
}
