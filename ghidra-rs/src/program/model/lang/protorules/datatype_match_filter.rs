use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::protorules::datatype_filter::DatatypeFilter;
use crate::program::model::lang::protorules::qualifier_filter::QualifierFilter;
use crate::program::model::pcode::ids::{ATTRIB_INDEX, ELEM_DATATYPE_AT};
use crate::program::model::pcode::Encoder;
use crate::program::seam_stubs::PrototypePieces;
use crate::util::xml::spec_xml_utils::decode_int;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Check if the function signature has a specific data-type in a specific position.
///
/// This filter does not match against the data-type in the current position being assigned, but
/// against a parameter at a fixed position.
///
/// Port of `ghidra.program.model.lang.protorules.DatatypeMatchFilter`.
pub struct DatatypeMatchFilter {
    /// The position of the data-type to check (`DatatypeMatchFilter.position`).
    pub position: i32,
    /// The data-type filter that must match at `position` (`DatatypeMatchFilter.typeFilter`).
    ///
    /// `None` mirrors the Java field starting out `null` (the no-arg constructor never sets it);
    /// unlike Java, dereferencing it before it's configured doesn't segfault, but
    /// [`filter`](QualifierFilter::filter)/[`is_equivalent`](QualifierFilter::is_equivalent)
    /// still `panic` in that state (matching Java's `NullPointerException`) since those methods
    /// have no way to report an error.
    pub type_filter: Option<Box<dyn DatatypeFilter>>,
}

impl DatatypeMatchFilter {
    /// Port of the no-arg constructor.
    pub fn new() -> Self {
        DatatypeMatchFilter { position: -1, type_filter: None }
    }
}

impl Default for DatatypeMatchFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl QualifierFilter for DatatypeMatchFilter {
    fn clone_box(&self) -> Box<dyn QualifierFilter> {
        Box::new(DatatypeMatchFilter {
            position: self.position,
            type_filter: self.type_filter.as_ref().map(|f| f.clone_box()),
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn is_equivalent(&self, op: &dyn QualifierFilter) -> bool {
        let Some(other) = op.as_any().downcast_ref::<DatatypeMatchFilter>() else {
            return false;
        };
        if self.position != other.position {
            return false;
        }
        let type_filter = self
            .type_filter
            .as_ref()
            .expect("DatatypeMatchFilter.type_filter not set (mirrors Java NullPointerException)");
        let other_filter = other
            .type_filter
            .as_ref()
            .expect("DatatypeMatchFilter.type_filter not set (mirrors Java NullPointerException)");
        type_filter.is_equivalent(other_filter.as_ref())
    }

    fn filter(&self, proto: &PrototypePieces, _pos: i32) -> bool {
        // The position of the current parameter being assigned, `_pos`, is NOT used.
        let dt: &dyn DataType = if self.position < 0 {
            // Unlike Java (where `proto.outtype` is conventionally always a real DataType, even
            // for `void`, and `null` here would NullPointerException downstream), this port's
            // seam-stub `PrototypePieces::outtype` genuinely models "no return type" as `None`.
            // Treating that as "does not match" is a safe, honest adaptation rather than a panic.
            match &proto.outtype {
                Some(dt) => dt.as_ref(),
                None => return false,
            }
        } else {
            let position = self.position as usize;
            if position >= proto.intypes.len() {
                return false;
            }
            proto.intypes[position].as_ref()
        };
        let type_filter = self
            .type_filter
            .as_ref()
            .expect("DatatypeMatchFilter.type_filter not set (mirrors Java NullPointerException)");
        type_filter.filter(dt)
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        encoder.open_element(ELEM_DATATYPE_AT)?;
        encoder.write_signed_integer(ATTRIB_INDEX, self.position as i64)?;
        let type_filter = self.type_filter.as_ref().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "DatatypeMatchFilter.type_filter not set")
        })?;
        type_filter.encode(encoder)?;
        encoder.close_element(ELEM_DATATYPE_AT)?;
        Ok(())
    }

    fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), XmlParseException>
    where
        Self: Sized,
    {
        let elem = parser
            .start(&[ELEM_DATATYPE_AT.name])
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        self.position = decode_int(elem.get_attribute(ATTRIB_INDEX.name).as_deref());
        // TODO(port): Java reads the nested sub-filter via
        // `typeFilter = DatatypeFilter.restoreFilterXml(parser)`, the static factory that
        // inspects the next element's tag name and dispatches to `SizeRestrictedFilter`,
        // `MetaTypeFilter`, or `HomogeneousAggregate`. That dispatcher is not ported (see
        // `DatatypeFilter`'s own module doc: it's intentionally left for "alongside those
        // concrete filters once they exist" -- deliberately out of scope here to avoid touching
        // the shared `datatype_filter.rs` trait file). Until it exists, `type_filter` is left
        // as whatever it already was (`None` for a freshly-constructed filter), and the nested
        // element is discarded so the parser stream stays well-formed for whatever called this.
        parser.discard_sub_tree();
        parser
            .end()
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::protorules::size_restricted_filter::SizeRestrictedFilter;
    use crate::program::model::lang::protorules::xml_test_support::{MockElement, QueueParser};
    use std::sync::Arc;

    struct MockDataType {
        length: i32,
    }
    impl DataType for MockDataType {
        fn get_length(&self) -> i32 {
            self.length
        }
    }

    fn proto_with(outtype: Option<Arc<dyn DataType>>, intypes: Vec<Arc<dyn DataType>>) -> PrototypePieces {
        PrototypePieces { outtype, intypes, ..Default::default() }
    }

    #[test]
    fn filter_checks_input_position_not_current_position() {
        let mut f = DatatypeMatchFilter::new();
        f.position = 1;
        f.type_filter = Some(Box::new(SizeRestrictedFilter::with_min_max(4, 4)));
        let proto = proto_with(
            None,
            vec![
                Arc::new(MockDataType { length: 8 }),
                Arc::new(MockDataType { length: 4 }),
            ],
        );
        // `pos` argument (the current assignment position) is deliberately different from
        // `f.position` and must be ignored.
        assert!(f.filter(&proto, 99));
    }

    #[test]
    fn filter_checks_output_type_when_position_negative() {
        let mut f = DatatypeMatchFilter::new();
        f.position = -1;
        f.type_filter = Some(Box::new(SizeRestrictedFilter::with_min_max(4, 4)));
        let proto = proto_with(Some(Arc::new(MockDataType { length: 4 })), Vec::new());
        assert!(f.filter(&proto, 5));
    }

    #[test]
    fn filter_rejects_out_of_range_position() {
        let mut f = DatatypeMatchFilter::new();
        f.position = 5;
        f.type_filter = Some(Box::new(SizeRestrictedFilter::new()));
        let proto = proto_with(None, vec![Arc::new(MockDataType { length: 4 })]);
        assert!(!f.filter(&proto, 0));
    }

    #[test]
    fn filter_rejects_missing_output_type() {
        let mut f = DatatypeMatchFilter::new();
        f.position = -1;
        f.type_filter = Some(Box::new(SizeRestrictedFilter::new()));
        let proto = proto_with(None, Vec::new());
        assert!(!f.filter(&proto, 0));
    }

    #[test]
    fn is_equivalent_compares_position_and_type_filter() {
        let mut a = DatatypeMatchFilter::new();
        a.position = 1;
        a.type_filter = Some(Box::new(SizeRestrictedFilter::with_min_max(4, 8)));
        let mut b = DatatypeMatchFilter::new();
        b.position = 1;
        b.type_filter = Some(Box::new(SizeRestrictedFilter::with_min_max(4, 8)));
        let mut c = DatatypeMatchFilter::new();
        c.position = 2;
        c.type_filter = Some(Box::new(SizeRestrictedFilter::with_min_max(4, 8)));

        assert!(QualifierFilter::is_equivalent(&a, &b));
        assert!(!QualifierFilter::is_equivalent(&a, &c));
    }

    #[test]
    fn clone_box_produces_independent_equivalent_copy() {
        let mut f = DatatypeMatchFilter::new();
        f.position = 3;
        f.type_filter = Some(Box::new(SizeRestrictedFilter::with_min_max(1, 2)));
        let cloned = f.clone_box();
        assert!(QualifierFilter::is_equivalent(&f, cloned.as_ref()));
    }

    #[test]
    fn restore_xml_reads_index_and_discards_unported_nested_filter() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("datatype_at", 0, &[("index", "2")]),
            MockElement::start("datatype", 1, &[("name", "any")]),
            MockElement::end("datatype", 1),
            MockElement::end("datatype_at", 0),
        ]);
        let mut f = DatatypeMatchFilter::new();
        QualifierFilter::restore_xml(&mut f, &mut parser).unwrap();
        assert_eq!(f.position, 2);
        assert!(f.type_filter.is_none());
        assert!(!parser.has_next());
    }
}
