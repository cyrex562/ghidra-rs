use crate::program::model::data::data_type::DataType;
use crate::program::model::pcode::Encoder;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// A filter selecting a specific class of data-type.
///
/// A test of whether a data-type belongs to its class can be performed by calling the
/// [`filter`](DatatypeFilter::filter) method.
///
/// Port of `ghidra.program.model.lang.protorules.DatatypeFilter`.
///
/// The Java interface also declares a static `restoreFilterXml` factory that inspects the
/// root element of an XML stream and dispatches to one of `SizeRestrictedFilter`,
/// `HomogeneousAggregate`, or `MetaTypeFilter` (falling back to `PcodeDataTypeManager` to
/// resolve a decompiler metatype name). None of those sibling filters, nor
/// `PcodeDataTypeManager`, are ported yet, so that dispatch factory is not ported here; it
/// belongs alongside those concrete filters once they exist.
pub trait DatatypeFilter {
    /// Make a copy of this filter, boxed as a trait object.
    ///
    /// Port of the Java `clone()` method; renamed because `clone` returning `Self` is not
    /// object-safe.
    fn clone_box(&self) -> Box<dyn DatatypeFilter>;

    /// Returns this filter as [`std::any::Any`], so that [`is_equivalent`](Self::is_equivalent)
    /// implementations can downcast `op` to a concrete type.
    ///
    /// Every Java implementer of `isEquivalent` starts with a `getClass() != op.getClass()`
    /// check and then casts `op` to its own concrete type; `downcast_ref` on the value returned
    /// here is the Rust equivalent of that pattern.
    fn as_any(&self) -> &dyn std::any::Any;

    /// Test if the given filter is configured and performs identically to this one.
    fn is_equivalent(&self, op: &dyn DatatypeFilter) -> bool;

    /// Test whether the given data-type belongs to this filter's data-type class.
    fn filter(&self, dt: &dyn DataType) -> bool;

    /// Encode this filter and its configuration to a stream.
    ///
    /// # Errors
    /// Returns an error for problems writing to the stream.
    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()>;

    /// Configure details of the data-type class being filtered from the given stream.
    ///
    /// Generic over the parser implementation (rather than a trait object) because
    /// [`XmlPullParser`] is not object-safe; this keeps [`DatatypeFilter`] itself
    /// dyn-compatible for every other method.
    ///
    /// # Errors
    /// Returns an error if there are problems with the stream.
    fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), XmlParseException>
    where
        Self: Sized;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct MockDataType {
        name: String,
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    #[derive(Clone)]
    struct SizeMockFilter {
        min_size: i32,
        max_size: i32,
    }

    impl DatatypeFilter for SizeMockFilter {
        fn clone_box(&self) -> Box<dyn DatatypeFilter> {
            Box::new(self.clone())
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        fn is_equivalent(&self, op: &dyn DatatypeFilter) -> bool {
            let Some(other) = op.as_any().downcast_ref::<SizeMockFilter>() else {
                return false;
            };
            self.min_size == other.min_size && self.max_size == other.max_size
        }

        fn filter(&self, dt: &dyn DataType) -> bool {
            let len = dt.get_name().len() as i32;
            len >= self.min_size && len <= self.max_size
        }

        fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
            encoder.write_signed_integer(
                crate::program::model::pcode::ATTRIB_SIZE,
                self.min_size as i64,
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
    fn usable_as_trait_object_and_filters_by_predicate() {
        let filter: Box<dyn DatatypeFilter> = Box::new(SizeMockFilter { min_size: 2, max_size: 4 });

        let short = MockDataType { name: "ab".to_string() };
        let long = MockDataType { name: "abcdefgh".to_string() };

        assert!(filter.filter(&short));
        assert!(!filter.filter(&long));
    }

    #[test]
    fn clone_box_produces_equivalent_independent_copy() {
        let filter = SizeMockFilter { min_size: 1, max_size: 8 };
        let cloned = filter.clone_box();

        assert!(filter.is_equivalent(cloned.as_ref()));

        let different = SizeMockFilter { min_size: 1, max_size: 9 };
        assert!(!filter.is_equivalent(&different));
    }

    #[test]
    fn encode_reaches_the_stream() {
        let filter = SizeMockFilter { min_size: 3, max_size: 5 };
        let mut encoder = NoopEncoder;
        assert!(filter.encode(&mut encoder).is_ok());
    }
}
