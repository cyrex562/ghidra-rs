use std::collections::HashSet;

use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::protorules::datatype_filter::DatatypeFilter;
use crate::program::model::pcode::ids::{ATTRIB_MAXSIZE, ATTRIB_MINSIZE, ATTRIB_NAME, ATTRIB_SIZES, ELEM_DATATYPE};
use crate::program::model::pcode::Encoder;
use crate::util::xml::spec_xml_utils::decode_int;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// A base for data-type filters that test either a range or an enumerated list of sizes.
///
/// Any filter built on top of this can use `min_size`/`max_size`/`sizes` to place bounds on the
/// possible sizes of data-types. The bounds are enforced by calling
/// [`filter_on_size`](SizeRestrictedFilter::filter_on_size) within the composing filter's
/// `filter()` method.
///
/// Port of `ghidra.program.model.lang.protorules.SizeRestrictedFilter`.
///
/// Java expresses [`MetaTypeFilter`](super::meta_type_filter::MetaTypeFilter) and
/// [`HomogeneousAggregate`](super::homogeneous_aggregate::HomogeneousAggregate) as subclasses
/// (`extends SizeRestrictedFilter`) that reuse its protected `filterOnSize`/`encodeAttributes`/
/// `restoreAttributesXml` methods. Rust has no inheritance, so those two composing filters
/// embed a `base: SizeRestrictedFilter` field and delegate to the (renamed to avoid the `pub`
/// keyword clash) methods below instead of calling `super.*`.
#[derive(Clone, Debug, PartialEq)]
pub struct SizeRestrictedFilter {
    /// Minimum size of the data-type in bytes (`SizeRestrictedFilter.minSize`).
    pub min_size: i32,
    /// Maximum size of the data-type in bytes (`SizeRestrictedFilter.maxSize`).
    pub max_size: i32,
    /// Enumerated set of exact sizes allowed, or `None` if a min/max range is used instead
    /// (`SizeRestrictedFilter.sizes`).
    pub sizes: Option<HashSet<i32>>,
}

impl SizeRestrictedFilter {
    /// The `name` attribute value used by the base (unqualified) filter (`SizeRestrictedFilter.NAME`).
    pub const NAME: &'static str = "any";

    /// Port of the no-arg constructor: no size restriction at all (`maxSize` stays `0`, which
    /// [`filter_on_size`](Self::filter_on_size) treats as "no filtering").
    pub fn new() -> Self {
        SizeRestrictedFilter {
            min_size: 0,
            max_size: 0,
            sizes: None,
        }
    }

    /// Port of the `(int min, int max)` constructor.
    ///
    /// If `max` is `0` and `min` is non-negative, there is no explicit upper bound, so `max_size`
    /// is set to `i32::MAX` (`0x7fffffff` in the Java source) instead.
    pub fn with_min_max(min: i32, max: i32) -> Self {
        let mut max_size = max;
        if max_size == 0 && min >= 0 {
            max_size = 0x7fff_ffff;
        }
        SizeRestrictedFilter {
            min_size: min,
            max_size,
            sizes: None,
        }
    }

    /// Parse the given string as a comma- or space-separated list of decimal integers,
    /// populating [`sizes`](Self::sizes) (and recomputing [`min_size`](Self::min_size)/
    /// [`max_size`](Self::max_size) as the extremes of the parsed set).
    ///
    /// Port of `initFromSizeList`. Java splits on the regex `" +|,"` -- a run of one-or-more
    /// spaces, OR a single comma -- which means adjacent commas (`"1,,2"`) produce an empty
    /// token that fails `Integer.parseInt` (an unchecked `NumberFormatException` in Java,
    /// propagated here as an [`XmlParseException`] since this port's signature is checked).
    ///
    /// # Errors
    /// Returns an error if any token fails to parse as an integer, or parses to a
    /// non-positive value.
    pub fn init_from_size_list(&mut self, str: &str) -> Result<(), XmlParseException> {
        let num_strings = split_size_list(str);
        let mut sizes = HashSet::new();
        let mut min_size = i32::MAX;
        let mut max_size = 0;
        for val_string in &num_strings {
            let val: i32 = val_string.parse().map_err(|_| {
                XmlParseException::new(format!("Bad filter size: \"{val_string}\""))
            })?;
            if val <= 0 {
                return Err(XmlParseException::new("Bad filter size"));
            }
            sizes.insert(val);
            if val < min_size {
                min_size = val;
            }
            if val > max_size {
                max_size = val;
            }
        }
        if sizes.is_empty() {
            self.sizes = None;
            self.min_size = 0;
            self.max_size = 0;
        } else {
            self.sizes = Some(sizes);
            self.min_size = min_size;
            self.max_size = max_size;
        }
        Ok(())
    }

    /// Enforce any size bounds on a given data-type.
    ///
    /// If [`max_size`](Self::max_size) is not zero, the data-type is checked to see if its size
    /// in bytes falls between [`min_size`](Self::min_size) and [`max_size`](Self::max_size)
    /// inclusive. If enumerated sizes are present, also check that the particular size is in
    /// the enumerated set.
    ///
    /// Port of `filterOnSize`.
    pub fn filter_on_size(&self, dt: &dyn DataType) -> bool {
        if self.max_size == 0 {
            // maxSize of 0 means no size filtering is performed
            return true;
        }
        if let Some(sizes) = &self.sizes {
            return sizes.contains(&dt.get_length());
        }
        let len = dt.get_length();
        len >= self.min_size && len <= self.max_size
    }

    /// Test if the size-bound configuration of `self` and `other` is identical.
    ///
    /// Port of the size-bound-comparison body of `SizeRestrictedFilter.isEquivalent` (the
    /// `getClass()` check at the top of the Java method is the caller's responsibility -- see
    /// [`DatatypeFilter::is_equivalent`] implementations in this package for how each composing
    /// filter performs its own class check via `as_any().downcast_ref`).
    pub fn bounds_equivalent(&self, other: &SizeRestrictedFilter) -> bool {
        if self.max_size != other.max_size || self.min_size != other.min_size {
            return false;
        }
        match (&self.sizes, &other.sizes) {
            (Some(a), Some(b)) => a == b,
            (None, None) => true,
            _ => false,
        }
    }

    /// Port of the protected `encodeAttributes` method.
    ///
    /// # Errors
    /// Returns an error for problems writing to the stream.
    pub fn encode_attributes(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        if let Some(sizes) = &self.sizes {
            let mut buffer = String::new();
            let mut iter = sizes.iter();
            if let Some(first) = iter.next() {
                buffer.push_str(&first.to_string());
            }
            for val in iter {
                buffer.push(',');
                buffer.push_str(&val.to_string());
            }
            encoder.write_string(ATTRIB_SIZES, &buffer)?;
        } else {
            encoder.write_unsigned_integer(ATTRIB_MINSIZE, self.min_size as u64)?;
            encoder.write_unsigned_integer(ATTRIB_MAXSIZE, self.max_size as u64)?;
        }
        Ok(())
    }

    /// Port of the protected `restoreAttributesXml` method.
    ///
    /// # Errors
    /// Returns an error if `minsize`/`maxsize` are mixed with `sizes` on the same element, or if
    /// the `sizes` list is malformed.
    pub fn restore_attributes_xml<E: XmlElement>(&mut self, el: &E) -> Result<(), XmlParseException> {
        for (name, value) in el.get_attribute_iter() {
            if name == ATTRIB_MINSIZE.name {
                if self.sizes.is_some() {
                    return Err(XmlParseException::new(
                        "Mixing \"sizes\" with \"minsize\" and \"maxsize\"",
                    ));
                }
                self.min_size = decode_int(Some(&value));
            } else if name == ATTRIB_MAXSIZE.name {
                if self.sizes.is_some() {
                    return Err(XmlParseException::new(
                        "Mixing \"sizes\" with \"minsize\" and \"maxsize\"",
                    ));
                }
                self.max_size = decode_int(Some(&value));
            } else if name == ATTRIB_SIZES.name {
                if self.min_size != 0 || self.max_size != 0 {
                    return Err(XmlParseException::new(
                        "Mixing \"sizes\" with \"minsize\" and \"maxsize\"",
                    ));
                }
                self.init_from_size_list(&value)?;
            }
        }
        if self.max_size == 0 && self.min_size >= 0 {
            // If no ATTRIB_MAXSIZE is given, assume there is no upper bound on size
            self.max_size = 0x7fff_ffff;
        }
        Ok(())
    }
}

impl Default for SizeRestrictedFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Splits `str` the way Java's `str.split(" +|,")` does: a run of one-or-more spaces is a single
/// delimiter, while each individual comma is its own delimiter (so adjacent commas yield an
/// empty token between them, faithfully reproducing the Java quirk documented on
/// [`SizeRestrictedFilter::init_from_size_list`]).
fn split_size_list(str: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = str.chars().peekable();
    while let Some(c) = chars.next() {
        if c == ',' {
            tokens.push(std::mem::take(&mut current));
        } else if c == ' ' {
            while chars.peek() == Some(&' ') {
                chars.next();
            }
            tokens.push(std::mem::take(&mut current));
        } else {
            current.push(c);
        }
    }
    tokens.push(current);
    tokens
}

impl DatatypeFilter for SizeRestrictedFilter {
    fn clone_box(&self) -> Box<dyn DatatypeFilter> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn is_equivalent(&self, op: &dyn DatatypeFilter) -> bool {
        let Some(other) = op.as_any().downcast_ref::<SizeRestrictedFilter>() else {
            return false;
        };
        self.bounds_equivalent(other)
    }

    fn filter(&self, dt: &dyn DataType) -> bool {
        self.filter_on_size(dt)
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        encoder.open_element(ELEM_DATATYPE)?;
        encoder.write_string(ATTRIB_NAME, Self::NAME)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::pcode::{AttributeId, ElementId};
    use crate::util::xml::xml_element_impl::XmlElementImpl;

    struct MockDataType {
        length: i32,
    }
    impl DataType for MockDataType {
        fn get_length(&self) -> i32 {
            self.length
        }
    }

    #[test]
    fn new_has_no_size_restriction() {
        let f = SizeRestrictedFilter::new();
        assert_eq!(f.min_size, 0);
        assert_eq!(f.max_size, 0);
        assert!(f.filter_on_size(&MockDataType { length: 0 }));
        assert!(f.filter_on_size(&MockDataType { length: 1_000_000 }));
    }

    #[test]
    fn with_min_max_default_upper_bound_when_max_is_zero() {
        let f = SizeRestrictedFilter::with_min_max(4, 0);
        assert_eq!(f.max_size, 0x7fff_ffff);
        assert!(f.filter_on_size(&MockDataType { length: 4 }));
        assert!(!f.filter_on_size(&MockDataType { length: 3 }));
    }

    #[test]
    fn filter_on_size_bounds_are_inclusive() {
        let f = SizeRestrictedFilter::with_min_max(4, 8);
        assert!(!f.filter_on_size(&MockDataType { length: 3 }));
        assert!(f.filter_on_size(&MockDataType { length: 4 })); // lower bound inclusive
        assert!(f.filter_on_size(&MockDataType { length: 8 })); // upper bound inclusive
        assert!(!f.filter_on_size(&MockDataType { length: 9 }));
    }

    #[test]
    fn init_from_size_list_parses_comma_separated_sizes() {
        let mut f = SizeRestrictedFilter::new();
        f.init_from_size_list("1,2,4,8").unwrap();
        assert_eq!(f.min_size, 1);
        assert_eq!(f.max_size, 8);
        assert!(f.filter_on_size(&MockDataType { length: 4 }));
        assert!(!f.filter_on_size(&MockDataType { length: 3 })); // not an enumerated size
    }

    #[test]
    fn init_from_size_list_parses_space_separated_sizes() {
        let mut f = SizeRestrictedFilter::new();
        f.init_from_size_list("1 2   4 8").unwrap();
        assert_eq!(f.sizes.as_ref().unwrap().len(), 4);
    }

    #[test]
    fn init_from_size_list_rejects_non_positive_values() {
        let mut f = SizeRestrictedFilter::new();
        assert!(f.init_from_size_list("0").is_err());
        assert!(f.init_from_size_list("-1").is_err());
    }

    #[test]
    fn init_from_size_list_adjacent_commas_produce_empty_token_error() {
        // Faithfully reproduces the Java quirk where "1,,2" splits into ["1", "", "2"] (a lone
        // comma is its own delimiter, unlike a run of spaces which collapses to one delimiter),
        // and the empty token fails to parse as an integer.
        let mut f = SizeRestrictedFilter::new();
        assert!(f.init_from_size_list("1,,2").is_err());
    }

    #[test]
    fn init_from_size_list_run_of_spaces_collapses_to_one_delimiter() {
        // Unlike commas, a run of spaces is a single delimiter, so no empty tokens result.
        let mut f = SizeRestrictedFilter::new();
        assert!(f.init_from_size_list("1   2").is_ok());
    }

    #[test]
    fn is_equivalent_compares_bounds_not_type() {
        let a = SizeRestrictedFilter::with_min_max(4, 8);
        let b = SizeRestrictedFilter::with_min_max(4, 8);
        let c = SizeRestrictedFilter::with_min_max(4, 9);
        assert!(DatatypeFilter::is_equivalent(&a, &b));
        assert!(!DatatypeFilter::is_equivalent(&a, &c));
    }

    #[test]
    fn is_equivalent_compares_enumerated_sizes() {
        let mut a = SizeRestrictedFilter::new();
        a.init_from_size_list("1,2,4").unwrap();
        let mut b = SizeRestrictedFilter::new();
        b.init_from_size_list("4,2,1").unwrap();
        let mut c = SizeRestrictedFilter::new();
        c.init_from_size_list("1,2,8").unwrap();
        assert!(DatatypeFilter::is_equivalent(&a, &b));
        assert!(!DatatypeFilter::is_equivalent(&a, &c));
    }

    #[test]
    fn clone_box_produces_independent_equivalent_copy() {
        let f = SizeRestrictedFilter::with_min_max(4, 8);
        let cloned = f.clone_box();
        assert!(DatatypeFilter::is_equivalent(&f, cloned.as_ref()));
    }

    struct RecordingEncoder {
        strings: Vec<(AttributeId, String)>,
        unsigned: Vec<(AttributeId, u64)>,
        elements: Vec<ElementId>,
    }
    impl RecordingEncoder {
        fn new() -> Self {
            RecordingEncoder { strings: Vec::new(), unsigned: Vec::new(), elements: Vec::new() }
        }
    }
    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: ElementId) -> std::io::Result<()> {
            self.elements.push(elem_id);
            Ok(())
        }
        fn close_element(&mut self, _elem_id: ElementId) -> std::io::Result<()> {
            Ok(())
        }
        fn write_bool(&mut self, _attrib_id: AttributeId, _val: bool) -> std::io::Result<()> {
            Ok(())
        }
        fn write_signed_integer(&mut self, _attrib_id: AttributeId, _val: i64) -> std::io::Result<()> {
            Ok(())
        }
        fn write_unsigned_integer(&mut self, attrib_id: AttributeId, val: u64) -> std::io::Result<()> {
            self.unsigned.push((attrib_id, val));
            Ok(())
        }
        fn write_string(&mut self, attrib_id: AttributeId, val: &str) -> std::io::Result<()> {
            self.strings.push((attrib_id, val.to_string()));
            Ok(())
        }
        fn write_string_indexed(&mut self, _attrib_id: AttributeId, _index: i32, _val: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn write_space(&mut self, _attrib_id: AttributeId, _spc: &crate::program::model::address::AddressSpace) -> std::io::Result<()> {
            Ok(())
        }
        fn write_space_indexed(&mut self, _attrib_id: AttributeId, _index: i32, _name: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn write_opcode(&mut self, _attrib_id: AttributeId, _opcode: crate::decompiler::opcodes::op_code::OpCode) -> std::io::Result<()> {
            Ok(())
        }
        fn write_opcode_ordinal(&mut self, _attrib_id: AttributeId, _opcode: i32) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn encode_writes_min_max_when_no_enumerated_sizes() {
        let f = SizeRestrictedFilter::with_min_max(4, 8);
        let mut enc = RecordingEncoder::new();
        DatatypeFilter::encode(&f, &mut enc).unwrap();
        assert_eq!(enc.elements, vec![ELEM_DATATYPE]);
        assert_eq!(enc.strings, vec![(ATTRIB_NAME, "any".to_string())]);
        assert_eq!(enc.unsigned, vec![(ATTRIB_MINSIZE, 4), (ATTRIB_MAXSIZE, 8)]);
    }

    #[test]
    fn encode_writes_sizes_when_enumerated() {
        let mut f = SizeRestrictedFilter::new();
        f.init_from_size_list("2,4").unwrap();
        let mut enc = RecordingEncoder::new();
        DatatypeFilter::encode(&f, &mut enc).unwrap();
        assert_eq!(enc.strings.len(), 2); // ATTRIB_NAME + ATTRIB_SIZES
        assert_eq!(enc.strings[0], (ATTRIB_NAME, "any".to_string()));
        assert_eq!(enc.strings[1].0, ATTRIB_SIZES);
        assert!(enc.unsigned.is_empty());
    }

    #[test]
    fn restore_xml_round_trips_min_max() {
        use crate::program::model::lang::protorules::xml_test_support::{MockElement, QueueParser};
        let mut parser = QueueParser::new(vec![
            MockElement::start("datatype", 0, &[("minsize", "4"), ("maxsize", "8")]),
            MockElement::end("datatype", 0),
        ]);
        let mut f = SizeRestrictedFilter::new();
        DatatypeFilter::restore_xml(&mut f, &mut parser).unwrap();
        assert_eq!(f.min_size, 4);
        assert_eq!(f.max_size, 8);
    }

    #[test]
    fn restore_attributes_xml_rejects_mixed_sizes_and_minsize() {
        use crate::program::model::lang::protorules::xml_test_support::MockElement;
        let mut f = SizeRestrictedFilter::new();
        f.sizes = Some(HashSet::from([1, 2]));
        let elem = MockElement::start("datatype", 0, &[("minsize", "4")]);
        assert!(f.restore_attributes_xml(&elem).is_err());
    }
}
