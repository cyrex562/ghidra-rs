use crate::program::model::lang::protorules::datatype_match_filter::DatatypeMatchFilter;
use crate::program::model::lang::protorules::position_match_filter::PositionMatchFilter;
use crate::program::model::lang::protorules::varargs_filter::VarargsFilter;
use crate::program::model::pcode::ids::{ELEM_DATATYPE_AT, ELEM_POSITION, ELEM_VARARGS};
use crate::program::model::pcode::Encoder;
use crate::program::seam_stubs::PrototypePieces;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// A filter on some aspect of a specific function prototype.
///
/// An instance is configured via [`restore_xml`](QualifierFilter::restore_xml), then a test of
/// whether a function prototype meets its criteria can be performed by calling
/// [`filter`](QualifierFilter::filter).
///
/// Port of `ghidra.program.model.lang.protorules.QualifierFilter`.
pub trait QualifierFilter: Send + Sync {
    /// Make a copy of this qualifier, boxed as a trait object.
    ///
    /// Port of the Java `clone()` method; renamed because `clone` returning `Self` is not
    /// object-safe.
    fn clone_box(&self) -> Box<dyn QualifierFilter>;

    /// Returns this filter as [`std::any::Any`], so that [`is_equivalent`](Self::is_equivalent)
    /// implementations can downcast `op` to a concrete type.
    ///
    /// Every Java implementer of `isEquivalent` starts with a `getClass() != op.getClass()`
    /// check and then casts `op` to its own concrete type; `downcast_ref` on the value returned
    /// here is the Rust equivalent of that pattern.
    fn as_any(&self) -> &dyn std::any::Any;

    /// Test if the given filter is configured and performs identically to this one.
    fn is_equivalent(&self, op: &dyn QualifierFilter) -> bool;

    /// Test whether the given function prototype meets this filter's criteria.
    ///
    /// `pos` is the position of a specific output (`pos == -1`) or input (`pos >= 0`) in
    /// context.
    fn filter(&self, proto: &PrototypePieces, pos: i32) -> bool;

    /// Save this filter and its configuration to a stream.
    ///
    /// # Errors
    /// Returns an error for problems writing to the stream.
    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()>;

    /// Configure details of the criteria being filtered from the given stream.
    ///
    /// Generic over the parser implementation (rather than a trait object) because
    /// [`XmlPullParser`] is not object-safe; this keeps [`QualifierFilter`] itself
    /// dyn-compatible for every other method.
    ///
    /// # Errors
    /// Returns an error if there are problems with the stream.
    fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), XmlParseException>
    where
        Self: Sized;
}

/// Instantiate a qualifier from the stream. If the next element is not a qualifier, returns
/// `Ok(None)`.
///
/// Port of the static `QualifierFilter.restoreFilterXml`. A free function, not a trait method,
/// for the same reason as [`datatype_filter::restore_filter_xml`](super::datatype_filter::restore_filter_xml):
/// each branch calls `restore_xml` on the concrete, `Sized` filter type before erasing it to
/// `Box<dyn QualifierFilter>`.
///
/// # Errors
/// Returns an error for problems decoding the stream.
pub fn restore_filter_xml<P: XmlPullParser>(
    parser: &mut P,
) -> Result<Option<Box<dyn QualifierFilter>>, XmlParseException> {
    let elem = parser.peek();
    let nm = elem.get_name().to_string();
    if nm == ELEM_VARARGS.name {
        let mut filter = VarargsFilter::new();
        filter.restore_xml(parser)?;
        return Ok(Some(Box::new(filter)));
    }
    if nm == ELEM_POSITION.name {
        let mut filter = PositionMatchFilter::new(-1);
        filter.restore_xml(parser)?;
        return Ok(Some(Box::new(filter)));
    }
    if nm == ELEM_DATATYPE_AT.name {
        let mut filter = DatatypeMatchFilter::new();
        filter.restore_xml(parser)?;
        return Ok(Some(Box::new(filter)));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct PositionMockFilter {
        min_pos: i32,
        max_pos: i32,
    }

    impl QualifierFilter for PositionMockFilter {
        fn clone_box(&self) -> Box<dyn QualifierFilter> {
            Box::new(self.clone())
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        fn is_equivalent(&self, op: &dyn QualifierFilter) -> bool {
            let Some(other) = op.as_any().downcast_ref::<PositionMockFilter>() else {
                return false;
            };
            self.min_pos == other.min_pos && self.max_pos == other.max_pos
        }

        fn filter(&self, _proto: &PrototypePieces, pos: i32) -> bool {
            pos >= self.min_pos && pos <= self.max_pos
        }

        fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
            encoder.write_signed_integer(
                crate::program::model::pcode::ATTRIB_SIZE,
                self.min_pos as i64,
            )
        }

        fn restore_xml<P: XmlPullParser>(
            &mut self,
            _parser: &mut P,
        ) -> Result<(), XmlParseException>
        where
            Self: Sized,
        {
            Ok(())
        }
    }

    struct NoopEncoder;
    impl Encoder for NoopEncoder {
        fn open_element(
            &mut self,
            _elem_id: crate::program::model::pcode::ElementId,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn close_element(
            &mut self,
            _elem_id: crate::program::model::pcode::ElementId,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn write_bool(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _val: bool,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn write_signed_integer(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _val: i64,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn write_unsigned_integer(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _val: u64,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn write_string(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _val: &str,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn write_string_indexed(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _index: i32,
            _val: &str,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn write_space(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _spc: &crate::program::model::address::AddressSpace,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn write_space_indexed(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _index: i32,
            _name: &str,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn write_opcode(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _opcode: crate::decompiler::opcodes::op_code::OpCode,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn write_opcode_ordinal(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _opcode: i32,
        ) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn usable_as_trait_object_and_filters_by_position() {
        let filter: Box<dyn QualifierFilter> = Box::new(PositionMockFilter { min_pos: 0, max_pos: 2 });
        let proto = PrototypePieces::default();

        assert!(filter.filter(&proto, 0));
        assert!(filter.filter(&proto, 2));
        assert!(!filter.filter(&proto, 3));
        assert!(!filter.filter(&proto, -1));
    }

    #[test]
    fn clone_box_produces_equivalent_independent_copy() {
        let filter = PositionMockFilter { min_pos: 1, max_pos: 4 };
        let cloned = filter.clone_box();

        assert!(filter.is_equivalent(cloned.as_ref()));

        let different = PositionMockFilter { min_pos: 1, max_pos: 5 };
        assert!(!filter.is_equivalent(&different));
    }

    #[test]
    fn encode_reaches_the_stream() {
        let filter = PositionMockFilter { min_pos: 0, max_pos: 3 };
        let mut encoder = NoopEncoder;
        assert!(filter.encode(&mut encoder).is_ok());
    }

    #[test]
    fn restore_filter_xml_dispatches_varargs_position_and_datatype_at() {
        use crate::program::model::lang::protorules::varargs_filter::VarargsFilter;
        use crate::program::model::lang::protorules::position_match_filter::PositionMatchFilter;
        use crate::program::model::lang::protorules::datatype_match_filter::DatatypeMatchFilter;
        use crate::program::model::lang::protorules::xml_test_support::{MockElement, QueueParser};

        let mut varargs_parser = QueueParser::new(vec![
            MockElement::start("varargs", 0, &[]),
            MockElement::end("varargs", 0),
        ]);
        let varargs = restore_filter_xml(&mut varargs_parser).unwrap().unwrap();
        assert!(varargs.as_any().downcast_ref::<VarargsFilter>().is_some());

        let mut position_parser = QueueParser::new(vec![
            MockElement::start("position", 0, &[("index", "2")]),
            MockElement::end("position", 0),
        ]);
        let position = restore_filter_xml(&mut position_parser).unwrap().unwrap();
        assert!(position.as_any().downcast_ref::<PositionMatchFilter>().is_some());

        // DatatypeMatchFilter::restore_xml requires a nested <datatype> sub-element (its own
        // filter dispatch isn't ported -- see that file's own TODO(port) note -- so it's just
        // discarded), matching that file's own restore_xml test fixture.
        let mut datatype_at_parser = QueueParser::new(vec![
            MockElement::start("datatype_at", 0, &[]),
            MockElement::start("datatype", 1, &[("name", "any")]),
            MockElement::end("datatype", 1),
            MockElement::end("datatype_at", 0),
        ]);
        let datatype_at = restore_filter_xml(&mut datatype_at_parser).unwrap().unwrap();
        assert!(datatype_at.as_any().downcast_ref::<DatatypeMatchFilter>().is_some());
    }

    #[test]
    fn restore_filter_xml_returns_none_for_an_unrecognized_element_without_consuming_it() {
        use crate::program::model::lang::protorules::xml_test_support::{MockElement, QueueParser};

        let mut parser = QueueParser::new(vec![
            MockElement::start("goto_stack", 0, &[]),
            MockElement::end("goto_stack", 0),
        ]);
        assert!(restore_filter_xml(&mut parser).unwrap().is_none());
        // Still there for the caller to handle, since restore_filter_xml only peeked.
        assert!(parser.peek().is_start_with("goto_stack"));
    }
}
