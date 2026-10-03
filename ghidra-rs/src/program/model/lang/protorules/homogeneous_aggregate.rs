use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::protorules::datatype_filter::DatatypeFilter;
use crate::program::model::lang::protorules::primitive_extractor::PrimitiveExtractor;
use crate::program::model::lang::protorules::size_restricted_filter::SizeRestrictedFilter;
use crate::program::model::pcode::ids::{ATTRIB_MAX_PRIMITIVES, ATTRIB_NAME, ELEM_DATATYPE};
use crate::program::model::pcode::pcode_data_type_manager::{get_metatype, TYPE_ARRAY, TYPE_STRUCT};
use crate::program::model::pcode::Encoder;
use crate::util::xml::spec_xml_utils::decode_int;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Filter on a homogeneous aggregate data-type. All primitive data-types must be the same.
///
/// Port of `ghidra.program.model.lang.protorules.HomogeneousAggregate`.
///
/// Java expresses this as `extends SizeRestrictedFilter`; Rust has no inheritance, so the size
/// bound state is held in the `base` field and delegated to instead of a `super.*` call. See
/// [`SizeRestrictedFilter`]'s module doc for the general pattern.
///
/// # `is_equivalent` quirk (faithfully reproduced)
///
/// Java's `HomogeneousAggregate` does **not** override `isEquivalent` -- it inherits
/// `SizeRestrictedFilter.isEquivalent`, which only compares `minSize`/`maxSize`/`sizes`. So two
/// `HomogeneousAggregate` instances with identical size bounds but *different* `name`/`metaType`/
/// `maxPrimitives` are still reported equivalent. This is almost certainly an oversight relative
/// to the sibling `MetaTypeFilter`, which *does* extend the comparison with its own field --
/// but this port reproduces it exactly (see `is_equivalent_ignores_metatype_and_name_and_max_primitives`
/// below) rather than silently fixing it.
#[derive(Clone, Debug, PartialEq)]
pub struct HomogeneousAggregate {
    /// Embedded size-restriction state (`SizeRestrictedFilter`'s inherited fields).
    pub base: SizeRestrictedFilter,
    /// The name attribute associated with the tag (`HomogeneousAggregate.name`).
    pub name: String,
    /// The expected meta-type of the aggregate's homogeneous primitive members
    /// (`HomogeneousAggregate.metaType`).
    pub meta_type: i32,
    /// Maximum number of primitives in the aggregate (`HomogeneousAggregate.maxPrimitives`).
    pub max_primitives: i32,
}

impl HomogeneousAggregate {
    /// The name attribute used for a homogeneous floating-point aggregate
    /// (`HomogeneousAggregate.NAME_FLOAT`).
    pub const NAME_FLOAT: &'static str = "homogeneous-float-aggregate";
    /// Default maximum number of primitives allowed in the aggregate
    /// (`HomogeneousAggregate.DEFAULT_MAX_PRIMITIVES`).
    pub const DEFAULT_MAX_PRIMITIVES: i32 = 4;

    /// Port of the `(String nm, int meta)` constructor, for use with `restore_xml`/`decode`.
    pub fn new(nm: impl Into<String>, meta: i32) -> Self {
        HomogeneousAggregate {
            base: SizeRestrictedFilter::new(),
            name: nm.into(),
            meta_type: meta,
            max_primitives: Self::DEFAULT_MAX_PRIMITIVES,
        }
    }

    /// Port of the `(String nm, int meta, int maxPrim, int minSize, int maxSize)` constructor.
    pub fn with_bounds(nm: impl Into<String>, meta: i32, max_prim: i32, min_size: i32, max_size: i32) -> Self {
        HomogeneousAggregate {
            base: SizeRestrictedFilter::with_min_max(min_size, max_size),
            name: nm.into(),
            meta_type: meta,
            max_primitives: max_prim,
        }
    }
}

impl DatatypeFilter for HomogeneousAggregate {
    fn clone_box(&self) -> Box<dyn DatatypeFilter> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn is_equivalent(&self, op: &dyn DatatypeFilter) -> bool {
        // See the struct doc: faithfully mirrors the inherited (not overridden)
        // `SizeRestrictedFilter.isEquivalent` -- only `base` is compared.
        let Some(other) = op.as_any().downcast_ref::<HomogeneousAggregate>() else {
            return false;
        };
        self.base.bounds_equivalent(&other.base)
    }

    fn filter(&self, dt: &dyn DataType) -> bool {
        let meta = get_metatype(dt);
        if meta != TYPE_ARRAY && meta != TYPE_STRUCT {
            return false;
        }
        let primitives = PrimitiveExtractor::new(dt, true, 0, self.max_primitives);
        if !primitives.is_valid()
            || primitives.size() == 0
            || primitives.contains_unknown()
            || !primitives.is_aligned()
            || primitives.contains_holes()
        {
            return false;
        }
        let base_meta = get_metatype(primitives.get(0).dt.as_ref());
        if base_meta != self.meta_type {
            return false;
        }
        // Port of `primitives.get(i).dt != base` (Java reference-identity comparison). See this
        // module's doc, and `primitive_extractor`'s, for why a structural `is_equivalent` is the
        // closest available stand-in once ownership stops the port from aliasing the exact same
        // `DataType` instance the way interned Java objects do.
        for i in 1..primitives.size() {
            if !primitives.get(i).dt.is_equivalent(primitives.get(0).dt.as_ref()) {
                return false;
            }
        }
        true
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        encoder.open_element(ELEM_DATATYPE)?;
        encoder.write_string(ATTRIB_NAME, &self.name)?;
        self.encode_attributes(encoder)?;
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
        self.restore_attributes_xml(&elem)?;
        parser
            .end()
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        Ok(())
    }
}

impl HomogeneousAggregate {
    /// Port of the protected `encodeAttributes` override: calls the base implementation, then
    /// additionally writes `ATTRIB_MAX_PRIMITIVES`.
    fn encode_attributes(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        self.base.encode_attributes(encoder)?;
        encoder.write_unsigned_integer(ATTRIB_MAX_PRIMITIVES, self.max_primitives as u64)?;
        Ok(())
    }

    /// Port of the protected `restoreAttributesXml` override: calls the base implementation,
    /// then additionally reads `ATTRIB_MAX_PRIMITIVES` (only overriding `max_primitives` when
    /// the parsed value is positive, matching Java's `if (xmlMaxPrim > 0)` guard).
    fn restore_attributes_xml<E: crate::util::xml::xml_element::XmlElement>(
        &mut self,
        el: &E,
    ) -> Result<(), XmlParseException> {
        self.base.restore_attributes_xml(el)?;
        for (name, value) in el.get_attribute_iter() {
            if name == ATTRIB_MAX_PRIMITIVES.name {
                let xml_max_prim = decode_int(Some(&value));
                if xml_max_prim > 0 {
                    self.max_primitives = xml_max_prim;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::array::Array;
    use crate::program::model::data::composite::Composite;
    use crate::program::model::data::data_type_component::DataTypeComponent;
    use crate::program::model::data::structure::Structure;
    use crate::program::model::lang::protorules::xml_test_support::{MockElement, QueueParser};
    use crate::program::model::pcode::pcode_data_type_manager::TYPE_FLOAT;

    #[derive(Clone)]
    struct MockFloat {
        length: i32,
    }
    impl DataType for MockFloat {
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_alignment(&self) -> i32 {
            self.length
        }
        fn is_floating_point(&self) -> bool {
            true
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            dt.is_floating_point() && dt.get_length() == self.length
        }
    }

    #[derive(Clone)]
    struct MockComponent {
        offset: i32,
        dt: MockFloat,
    }
    impl DataTypeComponent for MockComponent {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(self.dt.clone())
        }
        fn get_offset(&self) -> i32 {
            self.offset
        }
    }

    struct MockStruct {
        components: Vec<MockComponent>,
    }
    impl DataType for MockStruct {
        fn is_structure(&self) -> bool {
            true
        }
        fn as_structure(&self) -> Option<&dyn Structure> {
            Some(self)
        }
    }
    impl Composite for MockStruct {
        fn get_defined_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
            self.components.iter().cloned().map(|c| Box::new(c) as Box<dyn DataTypeComponent>).collect()
        }
        fn is_packing_enabled(&self) -> bool {
            true // packed: skip alignment/hole bookkeeping, matching a compiler-packed vector-of-floats ABI struct
        }
    }
    impl Structure for MockStruct {}

    struct NotAnAggregate {
        length: i32,
    }
    impl DataType for NotAnAggregate {
        fn get_length(&self) -> i32 {
            self.length
        }
    }

    #[test]
    fn filter_rejects_non_array_non_struct() {
        let f = HomogeneousAggregate::new(HomogeneousAggregate::NAME_FLOAT, TYPE_FLOAT);
        assert!(!f.filter(&NotAnAggregate { length: 4 }));
    }

    #[test]
    fn filter_accepts_struct_of_uniform_floats() {
        let f = HomogeneousAggregate::new(HomogeneousAggregate::NAME_FLOAT, TYPE_FLOAT);
        let s = MockStruct {
            components: vec![
                MockComponent { offset: 0, dt: MockFloat { length: 4 } },
                MockComponent { offset: 4, dt: MockFloat { length: 4 } },
            ],
        };
        assert!(f.filter(&s));
    }

    #[test]
    fn filter_rejects_struct_with_mixed_primitive_sizes() {
        // Same TYPE_FLOAT metatype throughout, but not the *same* primitive type (4-byte float
        // vs. 8-byte double) -- Java's reference-identity check on `.dt` would also reject this,
        // since distinct built-in types are distinct interned objects.
        let f = HomogeneousAggregate::new(HomogeneousAggregate::NAME_FLOAT, TYPE_FLOAT);
        let s = MockStruct {
            components: vec![
                MockComponent { offset: 0, dt: MockFloat { length: 4 } },
                MockComponent { offset: 4, dt: MockFloat { length: 8 } },
            ],
        };
        assert!(!f.filter(&s));
    }

    #[test]
    fn filter_rejects_when_base_metatype_does_not_match() {
        let f = HomogeneousAggregate::new(HomogeneousAggregate::NAME_FLOAT, TYPE_STRUCT); // wrong expected metatype
        let s = MockStruct {
            components: vec![MockComponent { offset: 0, dt: MockFloat { length: 4 } }],
        };
        assert!(!f.filter(&s));
    }

    #[test]
    fn filter_rejects_when_exceeding_max_primitives() {
        let f = HomogeneousAggregate::with_bounds(HomogeneousAggregate::NAME_FLOAT, TYPE_FLOAT, 1, 0, 0);
        let s = MockStruct {
            components: vec![
                MockComponent { offset: 0, dt: MockFloat { length: 4 } },
                MockComponent { offset: 4, dt: MockFloat { length: 4 } },
            ],
        };
        assert!(!f.filter(&s));
    }

    struct EmptyStruct;
    impl DataType for EmptyStruct {
        fn is_structure(&self) -> bool {
            true
        }
        fn as_structure(&self) -> Option<&dyn Structure> {
            Some(self)
        }
    }
    impl Composite for EmptyStruct {
        fn is_packing_enabled(&self) -> bool {
            true
        }
    }
    impl Structure for EmptyStruct {}

    #[test]
    fn filter_rejects_empty_aggregate() {
        let f = HomogeneousAggregate::new(HomogeneousAggregate::NAME_FLOAT, TYPE_FLOAT);
        assert!(!f.filter(&EmptyStruct));
    }

    #[test]
    fn is_equivalent_ignores_metatype_and_name_and_max_primitives() {
        // Faithfully reproduces the Java quirk documented on the struct: HomogeneousAggregate
        // inherits SizeRestrictedFilter's isEquivalent verbatim, so only size bounds matter.
        let a = HomogeneousAggregate::with_bounds("homogeneous-float-aggregate", TYPE_FLOAT, 4, 0, 16);
        let b = HomogeneousAggregate::with_bounds("something-else", TYPE_STRUCT, 2, 0, 16);
        assert!(DatatypeFilter::is_equivalent(&a, &b));
    }

    #[test]
    fn is_equivalent_still_compares_size_bounds() {
        let a = HomogeneousAggregate::with_bounds(HomogeneousAggregate::NAME_FLOAT, TYPE_FLOAT, 4, 0, 16);
        let b = HomogeneousAggregate::with_bounds(HomogeneousAggregate::NAME_FLOAT, TYPE_FLOAT, 4, 0, 32);
        assert!(!DatatypeFilter::is_equivalent(&a, &b));
    }

    #[test]
    fn clone_box_round_trips() {
        let f = HomogeneousAggregate::with_bounds(HomogeneousAggregate::NAME_FLOAT, TYPE_FLOAT, 4, 0, 16);
        let cloned = f.clone_box();
        assert!(DatatypeFilter::is_equivalent(&f, cloned.as_ref()));
    }

    #[test]
    fn restore_xml_reads_max_primitives_when_positive() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("datatype", 0, &[("name", "homogeneous-float-aggregate"), ("maxprimitives", "2")]),
            MockElement::end("datatype", 0),
        ]);
        let mut f = HomogeneousAggregate::new(HomogeneousAggregate::NAME_FLOAT, TYPE_FLOAT);
        DatatypeFilter::restore_xml(&mut f, &mut parser).unwrap();
        assert_eq!(f.max_primitives, 2);
    }

    #[test]
    fn restore_xml_ignores_non_positive_max_primitives() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("datatype", 0, &[("maxprimitives", "0")]),
            MockElement::end("datatype", 0),
        ]);
        let mut f = HomogeneousAggregate::new(HomogeneousAggregate::NAME_FLOAT, TYPE_FLOAT);
        DatatypeFilter::restore_xml(&mut f, &mut parser).unwrap();
        assert_eq!(f.max_primitives, HomogeneousAggregate::DEFAULT_MAX_PRIMITIVES);
    }

    // Used only to confirm `Array` dispatch is also exercised by `filter`, not just `Structure`.
    struct MockArray {
        num_elements: i32,
    }
    impl DataType for MockArray {
        fn is_array(&self) -> bool {
            true
        }
        fn as_array(&self) -> Option<&dyn Array> {
            Some(self)
        }
    }
    impl Array for MockArray {
        fn get_num_elements(&self) -> i32 {
            self.num_elements
        }
        fn get_element_length(&self) -> i32 {
            4
        }
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockFloat { length: 4 })
        }
    }

    #[test]
    fn filter_accepts_array_of_uniform_floats() {
        let f = HomogeneousAggregate::new(HomogeneousAggregate::NAME_FLOAT, TYPE_FLOAT);
        let arr = MockArray { num_elements: 4 };
        assert!(f.filter(&arr));
    }
}
