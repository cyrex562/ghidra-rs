use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::protorules::datatype_filter::DatatypeFilter;
use crate::program::model::lang::protorules::size_restricted_filter::SizeRestrictedFilter;
use crate::program::model::pcode::ids::{ATTRIB_NAME, ELEM_DATATYPE};
use crate::program::model::pcode::pcode_data_type_manager::{get_metatype, get_metatype_from_string, get_metatype_string};
use crate::program::model::pcode::Encoder;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Filter on a single meta data-type. Filters on `TYPE_STRUCT` or `TYPE_FLOAT` etc. Additional
/// filtering on size of the data-type can be configured.
///
/// Port of `ghidra.program.model.lang.protorules.MetaTypeFilter`.
///
/// Java expresses this as `extends SizeRestrictedFilter`; Rust has no inheritance, so the size
/// bound state is held in the `base` field and delegated to instead of a `super.*` call. See
/// [`SizeRestrictedFilter`]'s module doc for the general pattern.
#[derive(Clone, Debug, PartialEq)]
pub struct MetaTypeFilter {
    /// Embedded size-restriction state (`SizeRestrictedFilter`'s inherited fields).
    pub base: SizeRestrictedFilter,
    /// The meta-type this filter lets through (`MetaTypeFilter.metaType`).
    pub meta_type: i32,
}

impl MetaTypeFilter {
    /// Port of the `(int meta)` constructor, for use with `restore_xml`/`decode`. No size
    /// restriction is applied (`base.max_size` stays `0`).
    pub fn new(meta: i32) -> Self {
        MetaTypeFilter {
            base: SizeRestrictedFilter::new(),
            meta_type: meta,
        }
    }

    /// Port of the `(int meta, int min, int max)` constructor.
    pub fn with_min_max(meta: i32, min: i32, max: i32) -> Self {
        MetaTypeFilter {
            base: SizeRestrictedFilter::with_min_max(min, max),
            meta_type: meta,
        }
    }
}

impl DatatypeFilter for MetaTypeFilter {
    fn clone_box(&self) -> Box<dyn DatatypeFilter> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn is_equivalent(&self, op: &dyn DatatypeFilter) -> bool {
        // Port of `MetaTypeFilter.isEquivalent`, which calls `super.isEquivalent(op)` (a
        // `getClass()` check plus a size-bound comparison) and then repeats an identical
        // `getClass()` check itself before comparing `metaType`. Both `getClass()` checks
        // compare the *same* pair of classes (`this` is a `MetaTypeFilter` either way), so they
        // are redundant in Java; a single `downcast_ref` captures both.
        let Some(other) = op.as_any().downcast_ref::<MetaTypeFilter>() else {
            return false;
        };
        if !self.base.bounds_equivalent(&other.base) {
            return false;
        }
        self.meta_type == other.meta_type
    }

    fn filter(&self, dt: &dyn DataType) -> bool {
        if get_metatype(dt) != self.meta_type {
            return false;
        }
        self.base.filter_on_size(dt)
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        encoder.open_element(ELEM_DATATYPE)?;
        let meta = get_metatype_string(self.meta_type)?;
        encoder.write_string(ATTRIB_NAME, &meta)?;
        self.base.encode_attributes(encoder)?;
        encoder.close_element(ELEM_DATATYPE)?;
        Ok(())
    }

    fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), XmlParseException>
    where
        Self: Sized,
    {
        let elem = parser
            .start(&[ELEM_DATATYPE.name])
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        let name = elem.get_attribute(ATTRIB_NAME.name).unwrap_or_default();
        self.meta_type = get_metatype_from_string(&name)
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        self.base.restore_attributes_xml(&elem)?;
        parser
            .end()
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::pcode::pcode_data_type_manager::{TYPE_FLOAT, TYPE_STRUCT};
    use crate::program::model::lang::protorules::xml_test_support::{MockElement, QueueParser};

    struct MockDataType {
        length: i32,
        floating_point: bool,
    }
    impl DataType for MockDataType {
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_floating_point(&self) -> bool {
            self.floating_point
        }
    }

    #[test]
    fn filter_rejects_wrong_metatype() {
        let f = MetaTypeFilter::new(TYPE_FLOAT);
        let dt = MockDataType { length: 4, floating_point: false };
        assert!(!f.filter(&dt));
    }

    #[test]
    fn filter_accepts_matching_metatype_within_size_bounds() {
        let f = MetaTypeFilter::with_min_max(TYPE_FLOAT, 4, 8);
        assert!(f.filter(&MockDataType { length: 4, floating_point: true }));
        assert!(f.filter(&MockDataType { length: 8, floating_point: true }));
        assert!(!f.filter(&MockDataType { length: 16, floating_point: true }));
    }

    #[test]
    fn is_equivalent_requires_same_metatype_even_with_same_bounds() {
        let a = MetaTypeFilter::with_min_max(TYPE_FLOAT, 4, 8);
        let b = MetaTypeFilter::with_min_max(TYPE_STRUCT, 4, 8);
        assert!(!DatatypeFilter::is_equivalent(&a, &b));
    }

    #[test]
    fn is_equivalent_requires_same_bounds() {
        let a = MetaTypeFilter::with_min_max(TYPE_FLOAT, 4, 8);
        let b = MetaTypeFilter::with_min_max(TYPE_FLOAT, 4, 16);
        assert!(!DatatypeFilter::is_equivalent(&a, &b));
        let c = MetaTypeFilter::with_min_max(TYPE_FLOAT, 4, 8);
        assert!(DatatypeFilter::is_equivalent(&a, &c));
    }

    #[test]
    fn clone_box_round_trips() {
        let f = MetaTypeFilter::with_min_max(TYPE_FLOAT, 4, 8);
        let cloned = f.clone_box();
        assert!(DatatypeFilter::is_equivalent(&f, cloned.as_ref()));
    }

    #[test]
    fn restore_xml_reads_metatype_name_and_bounds() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("datatype", 0, &[("name", "float"), ("minsize", "4"), ("maxsize", "8")]),
            MockElement::end("datatype", 0),
        ]);
        let mut f = MetaTypeFilter::new(0);
        DatatypeFilter::restore_xml(&mut f, &mut parser).unwrap();
        assert_eq!(f.meta_type, TYPE_FLOAT);
        assert_eq!(f.base.min_size, 4);
        assert_eq!(f.base.max_size, 8);
    }
}
