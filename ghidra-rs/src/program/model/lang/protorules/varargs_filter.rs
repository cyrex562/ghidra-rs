use crate::program::model::lang::protorules::qualifier_filter::QualifierFilter;
use crate::program::model::pcode::ids::{ATTRIB_FIRST, ATTRIB_LAST, ELEM_VARARGS};
use crate::program::model::pcode::Encoder;
use crate::program::seam_stubs::PrototypePieces;
use crate::util::xml::spec_xml_utils::decode_int;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// A filter that selects a range of function parameters that are considered optional.
///
/// If the underlying function prototype takes variable arguments, the first n parameters (as
/// determined by `PrototypePieces.firstVarArgSlot`) are considered non-optional. If additional
/// data-types are provided beyond the initial n, these are considered optional. By default this
/// filter matches on all parameters in a prototype with variable arguments. Optionally, it can
/// filter on a range of parameters that are specified relative to the first variable argument:
///
/// - `<varargs first="0"/>` matches optional arguments but not non-optional ones.
/// - `<varargs first="0" last="0"/>` matches the first optional argument.
/// - `<varargs first="-1"/>` matches the last non-optional argument and all optional ones.
///
/// Port of `ghidra.program.model.lang.protorules.VarargsFilter`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VarargsFilter {
    /// Start of the range of params to match, relative to the first variable argument
    /// (`VarargsFilter.firstPos`).
    pub first_pos: i32,
    /// End of the range of params to match, relative to the first variable argument
    /// (`VarargsFilter.lastPos`).
    pub last_pos: i32,
}

impl VarargsFilter {
    /// Port of the no-arg constructor: matches every position relative to the first vararg.
    pub fn new() -> Self {
        VarargsFilter { first_pos: i32::MIN, last_pos: i32::MAX }
    }

    /// Port of the `(int first, int last)` constructor.
    pub fn with_range(first: i32, last: i32) -> Self {
        VarargsFilter { first_pos: first, last_pos: last }
    }
}

impl Default for VarargsFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl QualifierFilter for VarargsFilter {
    fn clone_box(&self) -> Box<dyn QualifierFilter> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn is_equivalent(&self, op: &dyn QualifierFilter) -> bool {
        let Some(other) = op.as_any().downcast_ref::<VarargsFilter>() else {
            return false;
        };
        self.first_pos == other.first_pos && self.last_pos == other.last_pos
    }

    fn filter(&self, proto: &PrototypePieces, pos: i32) -> bool {
        if proto.first_var_arg_slot < 0 {
            return false;
        }
        let pos = pos - proto.first_var_arg_slot;
        pos >= self.first_pos && pos <= self.last_pos
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        encoder.open_element(ELEM_VARARGS)?;
        if self.first_pos != i32::MIN {
            encoder.write_signed_integer(ATTRIB_FIRST, self.first_pos as i64)?;
        }
        if self.last_pos != i32::MAX {
            encoder.write_signed_integer(ATTRIB_LAST, self.last_pos as i64)?;
        }
        encoder.close_element(ELEM_VARARGS)?;
        Ok(())
    }

    fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), XmlParseException>
    where
        Self: Sized,
    {
        let elem = parser
            .start(&[ELEM_VARARGS.name])
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        if let Some(first_pos_string) = elem.get_attribute(ATTRIB_FIRST.name) {
            self.first_pos = decode_int(Some(&first_pos_string));
        }
        if let Some(last_pos_string) = elem.get_attribute(ATTRIB_LAST.name) {
            self.last_pos = decode_int(Some(&last_pos_string));
        }
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

    fn proto_with_first_vararg(slot: i32) -> PrototypePieces {
        PrototypePieces { first_var_arg_slot: slot, ..Default::default() }
    }

    #[test]
    fn default_prototype_has_no_varargs_so_filter_never_matches() {
        let f = VarargsFilter::new();
        let proto = PrototypePieces::default();
        assert_eq!(proto.first_var_arg_slot, -1);
        assert!(!f.filter(&proto, 0));
        assert!(!f.filter(&proto, 100));
    }

    #[test]
    fn default_filter_matches_everything_once_prototype_has_varargs() {
        let f = VarargsFilter::new();
        let proto = proto_with_first_vararg(2);
        assert!(f.filter(&proto, 0)); // non-optional
        assert!(f.filter(&proto, 2)); // first optional
        assert!(f.filter(&proto, 50));
    }

    #[test]
    fn first_zero_matches_only_optional_arguments() {
        // <varargs first="0"/>
        let f = VarargsFilter::with_range(0, i32::MAX);
        let proto = proto_with_first_vararg(2);
        assert!(!f.filter(&proto, 0)); // relative -2: non-optional, excluded
        assert!(!f.filter(&proto, 1)); // relative -1: non-optional, excluded
        assert!(f.filter(&proto, 2)); // relative 0: first optional, included
        assert!(f.filter(&proto, 3));
    }

    #[test]
    fn first_zero_last_zero_matches_only_the_first_optional_argument() {
        // <varargs first="0" last="0"/>
        let f = VarargsFilter::with_range(0, 0);
        let proto = proto_with_first_vararg(2);
        assert!(!f.filter(&proto, 1));
        assert!(f.filter(&proto, 2));
        assert!(!f.filter(&proto, 3));
    }

    #[test]
    fn first_negative_one_matches_last_non_optional_and_all_optional() {
        // <varargs first="-1"/>
        let f = VarargsFilter::with_range(-1, i32::MAX);
        let proto = proto_with_first_vararg(2);
        assert!(!f.filter(&proto, 0)); // relative -2, excluded
        assert!(f.filter(&proto, 1)); // relative -1, last non-optional, included
        assert!(f.filter(&proto, 2)); // first optional
        assert!(f.filter(&proto, 10));
    }

    #[test]
    fn is_equivalent_compares_range() {
        let a = VarargsFilter::with_range(0, 5);
        let b = VarargsFilter::with_range(0, 5);
        let c = VarargsFilter::with_range(0, 6);
        assert!(QualifierFilter::is_equivalent(&a, &b));
        assert!(!QualifierFilter::is_equivalent(&a, &c));
    }

    #[test]
    fn clone_box_round_trips() {
        let f = VarargsFilter::with_range(1, 2);
        let cloned = f.clone_box();
        assert!(QualifierFilter::is_equivalent(&f, cloned.as_ref()));
    }

    #[test]
    fn restore_xml_defaults_are_kept_when_attributes_absent() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("varargs", 0, &[]),
            MockElement::end("varargs", 0),
        ]);
        let mut f = VarargsFilter::new();
        QualifierFilter::restore_xml(&mut f, &mut parser).unwrap();
        assert_eq!(f.first_pos, i32::MIN);
        assert_eq!(f.last_pos, i32::MAX);
    }

    #[test]
    fn restore_xml_reads_first_and_last() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("varargs", 0, &[("first", "0"), ("last", "0")]),
            MockElement::end("varargs", 0),
        ]);
        let mut f = VarargsFilter::new();
        QualifierFilter::restore_xml(&mut f, &mut parser).unwrap();
        assert_eq!(f.first_pos, 0);
        assert_eq!(f.last_pos, 0);
    }
}
