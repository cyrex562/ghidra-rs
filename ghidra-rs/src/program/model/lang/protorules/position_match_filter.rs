use crate::program::model::lang::protorules::qualifier_filter::QualifierFilter;
use crate::program::model::pcode::ids::{ATTRIB_INDEX, ELEM_POSITION};
use crate::program::model::pcode::Encoder;
use crate::program::seam_stubs::PrototypePieces;
use crate::util::xml::spec_xml_utils::decode_int;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Filter that selects for a particular parameter position.
///
/// This matches if the position of the current parameter being assigned, within the data-type
/// list, matches the position attribute of this filter.
///
/// Port of `ghidra.program.model.lang.protorules.PositionMatchFilter`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PositionMatchFilter {
    /// Parameter position being filtered for (`PositionMatchFilter.position`).
    pub position: i32,
}

impl PositionMatchFilter {
    /// Port of the `(int pos)` constructor.
    pub fn new(pos: i32) -> Self {
        PositionMatchFilter { position: pos }
    }
}

impl QualifierFilter for PositionMatchFilter {
    fn clone_box(&self) -> Box<dyn QualifierFilter> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn is_equivalent(&self, op: &dyn QualifierFilter) -> bool {
        let Some(other) = op.as_any().downcast_ref::<PositionMatchFilter>() else {
            return false;
        };
        self.position == other.position
    }

    fn filter(&self, _proto: &PrototypePieces, pos: i32) -> bool {
        pos == self.position
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        encoder.open_element(ELEM_POSITION)?;
        encoder.write_signed_integer(ATTRIB_INDEX, self.position as i64)?;
        encoder.close_element(ELEM_POSITION)?;
        Ok(())
    }

    fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), XmlParseException>
    where
        Self: Sized,
    {
        let elem = parser
            .start(&[ELEM_POSITION.name])
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        self.position = decode_int(elem.get_attribute(ATTRIB_INDEX.name).as_deref());
        parser
            .end()
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::protorules::xml_test_support::{MockElement, QueueParser};

    #[test]
    fn filter_matches_only_exact_position() {
        let f = PositionMatchFilter::new(2);
        let proto = PrototypePieces::default();
        assert!(!f.filter(&proto, 0));
        assert!(!f.filter(&proto, 1));
        assert!(f.filter(&proto, 2));
        assert!(!f.filter(&proto, 3));
    }

    #[test]
    fn filter_matches_output_position_negative_one() {
        let f = PositionMatchFilter::new(-1);
        let proto = PrototypePieces::default();
        assert!(f.filter(&proto, -1));
        assert!(!f.filter(&proto, 0));
    }

    #[test]
    fn is_equivalent_compares_position() {
        let a = PositionMatchFilter::new(3);
        let b = PositionMatchFilter::new(3);
        let c = PositionMatchFilter::new(4);
        assert!(QualifierFilter::is_equivalent(&a, &b));
        assert!(!QualifierFilter::is_equivalent(&a, &c));
    }

    #[test]
    fn clone_box_round_trips() {
        let f = PositionMatchFilter::new(5);
        let cloned = f.clone_box();
        assert!(QualifierFilter::is_equivalent(&f, cloned.as_ref()));
    }

    #[test]
    fn restore_xml_reads_index() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("position", 0, &[("index", "3")]),
            MockElement::end("position", 0),
        ]);
        let mut f = PositionMatchFilter::new(0);
        QualifierFilter::restore_xml(&mut f, &mut parser).unwrap();
        assert_eq!(f.position, 3);
    }
}
