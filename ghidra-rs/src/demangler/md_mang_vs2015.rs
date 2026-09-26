//! Specialization of the (unported) `MDMang` driver that tailors output to Visual Studio 2015
//! demangling results.
//!
//! Mirrors `mdemangler.MDMangVS2015`, cut to a trait to break a dependency cycle: it is a
//! cut-point between the still-unported `MDMang` driver/base class (`mdemangler`) and the types
//! its overrides touch (`MDString`, `MDQualification`, `MDTemplateArgumentsList`, `MDCVMod`,
//! `MDFragmentName`, `MDObjectCPP`, `MDObjectReserved`/`MDObjectBracket`). Two of the original's
//! overrides are already represented on the pre-existing `MDMang` rendering-helper seam,
//! [`crate::demangler::seam_stubs::MdMangLike`], rather than redeclared here:
//! [`MdMangLike::use_vs_all_qualification`] (for `insert(StringBuilder, MDQualification)`) and
//! [`MdMangLike::use_vs2015_cli_array_ref_suffix`] (for `insertCLIArrayRefSuffix`, extended by
//! this port since it is called by the already-ported
//! [`crate::demangler::datatype::modifier::md_modifier_type::MdModifierType`]). This trait models
//! the rest of the class: the `demangle()` entry point and its remaining specialization methods.
//!
//! The character cursor itself (`MDMang.iter`, an `MDCharacterIterator`) *is* already ported for
//! real as [`MdCharacterIterator`](crate::demangler::md_character_iterator::MdCharacterIterator),
//! so [`MdMangVs2015::parse_fragment_name`] (which overrides to call
//! `MDFragmentName.parseFragmentName_VS2All()`, itself pure cursor movement never touching any
//! `MDFragmentName` field) is given a full, real default implementation built directly on that
//! type, the same treatment
//! [`MdMangGenericize`](crate::demangler::md_mang_genericize::MdMangGenericize) gives the sibling
//! `parseFragmentName_Md()` grammar.

use crate::demangler::demangle_exception::DemangledException;
use crate::demangler::md_character_iterator::{MdCharacterIterator, DONE};
use crate::demangler::object::md_object_cpp::MdObjectCpp;
use crate::demangler::seam_stubs::{
    MdCvModLike, MdExceptionLike, MdFragmentNameLike, MdMangLike, MdParsableItemLike,
    MdStringLike, MdTemplateArgumentsListLike,
};

/// Specialization of the `MDMang` driver that tailors output to Visual Studio 2015 results.
///
/// Mirrors `mdemangler.MDMangVS2015`. See the module docs for why the unported parts of the
/// `MDMang` base class this type extends are represented as required trait methods, and why two
/// of its overrides live on [`MdMangLike`] instead of here.
pub trait MdMangVs2015: MdMangLike {
    /// Read access to the character cursor over the mangled string.
    ///
    /// Stands in for the inherited `MDMang.iter`, needed by
    /// [`MdMangVs2015::parse_fragment_name`].
    fn char_iter(&self) -> &MdCharacterIterator;

    /// Mutable access to the character cursor over the mangled string.
    ///
    /// Stands in for the inherited `MDMang.iter`, needed by
    /// [`MdMangVs2015::parse_fragment_name`].
    fn char_iter_mut(&mut self) -> &mut MdCharacterIterator;

    /// Constructs an exception carrying `message`.
    ///
    /// Stands in for `new MDException(message)`, needed by the two spots
    /// [`MdMangVs2015::demangle`]/[`MdMangVs2015::parse_fragment_name`] raise one directly (rather
    /// than propagating one from an unported callee), since `MDException` is not ported (see
    /// [`MdExceptionLike`]).
    fn make_exception(&self, message: &str) -> Box<dyn MdExceptionLike>;

    /// Demangles the string already stored (via the un-overridden parts of the inherited
    /// `MDMang.demangle()`: `initState()`, `MDMangObjectParser.determineItemAndParse(this)`, and
    /// the trailing "characters remain after demangling" check) and returns the parsed item.
    ///
    /// Required since driving the character cursor and parser dispatch depends on `MDMang`'s own
    /// state, which isn't ported -- the same reasoning behind
    /// [`MdMangGenericize::parse_item`](crate::demangler::md_mang_genericize::MdMangGenericize::parse_item).
    /// A faithful implementor's `getEmbeddedObject(MDObjectCPP)` polymorphic dispatch call
    /// (`MDMang.demangle()`'s one `MDMANG SPECIALIZATION USED` line) should already be applied
    /// here -- e.g. via [`MdMangVs2015::get_embedded_object`] -- since [`MdMangVs2015::demangle`]
    /// does not re-apply it.
    fn base_demangle(&mut self) -> Result<Box<dyn MdParsableItemLike>, Box<dyn MdExceptionLike>>;

    /// Demangles the string already stored, rejecting any "made up" reserved object type VS2015
    /// output doesn't understand (except `MDObjectBracket`, which it does).
    ///
    /// Mirrors the `@Override` of `demangle()`.
    fn demangle(&mut self) -> Result<Box<dyn MdParsableItemLike>, Box<dyn MdExceptionLike>> {
        let item = self.base_demangle()?;
        let rejected = match item.as_object_reserved() {
            Some(reserved) => !reserved.is_object_bracket(),
            None => false,
        };
        if rejected {
            return Err(self.make_exception("Invalid mangled symbol."));
        }
        Ok(item)
    }

    /// Inserts the string literal's name text into `builder`.
    ///
    /// Mirrors the `@Override` of `insert(StringBuilder, MDString)`.
    fn insert_md_string(&self, builder: &mut String, mdstring: &dyn MdStringLike) {
        self.insert_string(builder, &mdstring.get_name());
    }

    /// Returns whether a template argument list's first argument should be preceded by a comma.
    ///
    /// Mirrors the `@Override` of `emptyFirstArgComma(MDTemplateArgumentsList)`.
    fn empty_first_arg_comma(&self, _args: &dyn MdTemplateArgumentsListLike) -> bool {
        true
    }

    /// Returns whether a template argument list back-reference should be preceded by a comma.
    ///
    /// Mirrors the `@Override` of `templateBackrefComma(MDTemplateArgumentsList)`.
    fn template_backref_comma(&self, _args: &dyn MdTemplateArgumentsListLike) -> bool {
        false
    }

    /// Does nothing (VS2015 output omits the managed-properties suffix at this dispatch point).
    ///
    /// Mirrors the `@Override` of `insertManagedPropertiesSuffix(StringBuilder, MDCVMod)`, which
    /// replaces the base `MDMang` behavior (`cvMod.insertManagedPropertiesSuffix(builder)`) with a
    /// no-op.
    fn insert_managed_properties_suffix(&self, _builder: &mut String, _cv_mod: &dyn MdCvModLike) {}

    /// Parses a fragment name using the VS2015 grammar: consumes letters, digits, and `_$<>-`
    /// characters (unlike the base `MD` grammar, `.` is illegal rather than a terminator) from the
    /// cursor until a non-matching character or the end of input is reached.
    ///
    /// Mirrors the `@Override` of `parseFragmentName(MDFragmentName)`, which delegates to
    /// `MDFragmentName.parseFragmentName_VS2All()`. The `fragment` parameter is accepted (unused)
    /// for signature parity with the Java override -- like the original, this override never reads
    /// or writes any of the `MDFragmentName` instance's own fields.
    fn parse_fragment_name(
        &mut self,
        _fragment: &mut dyn MdFragmentNameLike,
    ) -> Result<String, Box<dyn MdExceptionLike>> {
        let mut frag = String::new();
        loop {
            let ch = self.char_iter().peek();
            if ch == DONE {
                break;
            }
            if ch == '.' {
                return Err(self.make_exception("Illegal '.' character in MDFragmentName"));
            }
            let is_fragment_char =
                ch.is_alphabetic() || ch.is_numeric() || matches!(ch, '_' | '$' | '<' | '>' | '-');
            if !is_fragment_char {
                break;
            }
            frag.push(ch);
            self.char_iter_mut().next();
        }
        Ok(frag)
    }

    /// Returns `true`: VS2015 output allows the default `MDTypeInfoParser` dispatch.
    ///
    /// Mirrors the `@Override` of `allowMDTypeInfoParserDefault()`.
    fn allow_md_type_info_parser_default(&self) -> bool {
        true
    }

    /// Returns `false`: VS2015 output does not treat a qualified `C` component as a special
    /// fragment.
    ///
    /// Mirrors the `@Override` of `processQualCAsSpecialFragment()`.
    fn process_qual_c_as_special_fragment(&self) -> bool {
        false
    }

    /// Returns the embedded object if `obj` has one, else `obj` itself.
    ///
    /// Mirrors the `@Override` of `getEmbeddedObject(MDObjectCPP)`, which (unlike the base
    /// `MDMang` behavior of always returning `obj` unchanged) delegates to
    /// `obj.getEmbeddedObject()`. Requires `Self: Sized` (like
    /// [`MdObjectCpp::embedded_object`](crate::demangler::object::md_object_cpp::MdObjectCpp::embedded_object),
    /// which this delegates to) so call only through a concrete type, not through
    /// `&dyn MdMangVs2015`.
    fn get_embedded_object<'a, T>(&self, obj: &'a T) -> &'a dyn MdObjectCpp
    where
        Self: Sized,
        T: MdObjectCpp,
    {
        obj.embedded_object()
    }

    /// Processes `obj` as a hashed object the VS2015 (MSFT-failure-mimicking) way: always fails.
    ///
    /// Mirrors the `@Override` of `processHashedObject(MDObjectCPP)`, which delegates to
    /// `obj.processHashedObjectMSVC()`.
    fn process_hashed_object(&self, obj: &dyn MdObjectCpp) -> Result<(), DemangledException> {
        obj.process_hashed_object_msvc()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demangler::naming::md_qualification::MdQualification;
    use crate::demangler::naming::md_qualifier::MdQualifier;
    use crate::demangler::seam_stubs::MdObjectReservedLike;

    #[derive(Debug)]
    struct MockException(String);

    impl std::fmt::Display for MockException {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl MdExceptionLike for MockException {}

    struct MockMdString(&'static str);

    impl MdStringLike for MockMdString {
        fn get_name(&self) -> String {
            self.0.to_string()
        }
    }

    struct MockParsableItem {
        reserved: Option<MockReserved>,
    }

    struct MockReserved {
        is_bracket: bool,
    }

    impl MdObjectReservedLike for MockReserved {
        fn is_object_bracket(&self) -> bool {
            self.is_bracket
        }
    }

    impl MdParsableItemLike for MockParsableItem {
        fn as_object_reserved(&self) -> Option<&dyn MdObjectReservedLike> {
            self.reserved.as_ref().map(|r| r as &dyn MdObjectReservedLike)
        }
    }

    #[derive(Default)]
    struct MockQualification {
        quals: Vec<Box<dyn MdQualifier>>,
    }

    impl MdQualification for MockQualification {
        fn qualifiers(&self) -> &[Box<dyn MdQualifier>] {
            &self.quals
        }
    }

    struct MockMang {
        iter: MdCharacterIterator,
        base_result: Option<Box<dyn MdParsableItemLike>>,
        base_result_taken: bool,
    }

    impl MockMang {
        fn new(mangled: &str) -> Self {
            Self {
                iter: MdCharacterIterator::new(mangled),
                base_result: None,
                base_result_taken: false,
            }
        }

        fn with_base_result(mangled: &str, item: MockParsableItem) -> Self {
            Self {
                iter: MdCharacterIterator::new(mangled),
                base_result: Some(Box::new(item)),
                base_result_taken: false,
            }
        }
    }

    impl MdMangLike for MockMang {
        fn insert_string(&self, builder: &mut String, s: &str) {
            builder.insert_str(0, s);
        }

        fn insert_spaced_string(&self, builder: &mut String, s: &str) {
            builder.insert_str(0, s);
        }
    }

    impl MdMangVs2015 for MockMang {
        fn char_iter(&self) -> &MdCharacterIterator {
            &self.iter
        }

        fn char_iter_mut(&mut self) -> &mut MdCharacterIterator {
            &mut self.iter
        }

        fn make_exception(&self, message: &str) -> Box<dyn MdExceptionLike> {
            Box::new(MockException(message.to_string()))
        }

        fn base_demangle(
            &mut self,
        ) -> Result<Box<dyn MdParsableItemLike>, Box<dyn MdExceptionLike>> {
            if self.base_result_taken {
                return Err(Box::new(MockException("already demangled".into())));
            }
            self.base_result_taken = true;
            self.base_result
                .take()
                .ok_or_else(|| Box::new(MockException("no result".into())) as Box<dyn MdExceptionLike>)
        }
    }

    /// Proves [`MdMangVs2015`] is object-safe: usable behind a `&mut dyn` trait object.
    #[test]
    fn trait_object_is_usable() {
        let mut mock = MockMang::with_base_result("Foo@@", MockParsableItem { reserved: None });
        let dmang: &mut dyn MdMangVs2015 = &mut mock;

        let result = dmang.demangle();

        assert!(result.is_ok());
    }

    #[test]
    fn demangle_accepts_plain_item() {
        let mut mock = MockMang::with_base_result("Foo@@", MockParsableItem { reserved: None });

        assert!(mock.demangle().is_ok());
    }

    #[test]
    fn demangle_accepts_object_bracket() {
        let mut mock = MockMang::with_base_result(
            "Foo@@",
            MockParsableItem { reserved: Some(MockReserved { is_bracket: true }) },
        );

        assert!(mock.demangle().is_ok());
    }

    #[test]
    fn demangle_rejects_other_reserved_objects() {
        let mut mock = MockMang::with_base_result(
            "Foo@@",
            MockParsableItem { reserved: Some(MockReserved { is_bracket: false }) },
        );

        match mock.demangle() {
            Err(err) => assert_eq!(err.to_string(), "Invalid mangled symbol."),
            Ok(_) => panic!("expected demangle() to reject a non-bracket reserved object"),
        }
    }

    #[test]
    fn demangle_propagates_base_demangle_error() {
        let mut mock = MockMang::new("");

        match mock.demangle() {
            Err(err) => assert_eq!(err.to_string(), "no result"),
            Ok(_) => panic!("expected demangle() to propagate base_demangle's error"),
        }
    }

    #[test]
    fn insert_md_string_inserts_name() {
        let mock = MockMang::new("");
        let mut builder = String::from("rest");

        mock.insert_md_string(&mut builder, &MockMdString("prefix "));

        assert_eq!(builder, "prefix rest");
    }

    #[test]
    fn empty_first_arg_comma_is_true() {
        let mock = MockMang::new("");
        let args = MockTemplateArgs;

        assert!(mock.empty_first_arg_comma(&args));
    }

    #[test]
    fn template_backref_comma_is_false() {
        let mock = MockMang::new("");
        let args = MockTemplateArgs;

        assert!(!mock.template_backref_comma(&args));
    }

    struct MockTemplateArgs;
    impl MdTemplateArgumentsListLike for MockTemplateArgs {}

    #[test]
    fn insert_managed_properties_suffix_is_a_no_op() {
        let mock = MockMang::new("");
        let mut builder = String::from("unchanged");
        let cv_mod = MockCvMod;

        mock.insert_managed_properties_suffix(&mut builder, &cv_mod);

        assert_eq!(builder, "unchanged");
    }

    struct MockCvMod;
    impl MdCvModLike for MockCvMod {
        fn is_pointer64(&self) -> bool {
            false
        }
        fn is_restricted(&self) -> bool {
            false
        }
        fn is_unaligned(&self) -> bool {
            false
        }
        fn based_name(&self) -> Option<&str> {
            None
        }
        fn member_scope(&self) -> Option<&str> {
            None
        }
        fn is_cli_array(&self) -> bool {
            false
        }
        fn is_pointer_type(&self) -> bool {
            false
        }
        fn is_function_pointer_type(&self) -> bool {
            false
        }
        fn is_reference_type(&self) -> bool {
            false
        }
        fn is_function_reference_type(&self) -> bool {
            false
        }
        fn is_array_type(&self) -> bool {
            false
        }
        fn is_pin_pointer(&self) -> bool {
            false
        }
        fn is_question_type(&self) -> bool {
            false
        }
        fn insert(&self, _dmang: &dyn MdMangLike, _builder: &mut String) {}
        fn insert_managed_properties_prefix(&self, _dmang: &dyn MdMangLike, _builder: &mut String) {}
        fn insert_managed_properties_suffix(&self, _dmang: &dyn MdMangLike, _builder: &mut String) {}
    }

    #[test]
    fn parse_fragment_name_stops_at_non_fragment_char() {
        let mut mock = MockMang::new("Foo_Bar<Baz>@@rest");
        let mut fragment = MockFragmentName;

        let frag = mock.parse_fragment_name(&mut fragment).unwrap();

        assert_eq!(frag, "Foo_Bar<Baz>");
        assert_eq!(mock.char_iter().peek(), '@');
    }

    #[test]
    fn parse_fragment_name_rejects_dot() {
        let mut mock = MockMang::new("Foo.Bar");
        let mut fragment = MockFragmentName;

        let err = mock.parse_fragment_name(&mut fragment).unwrap_err();

        assert_eq!(err.to_string(), "Illegal '.' character in MDFragmentName");
    }

    struct MockFragmentName;
    impl MdFragmentNameLike for MockFragmentName {
        fn get_name(&self) -> String {
            String::new()
        }
        fn set_name(&mut self, _name: String) {}
        fn insert(&self, _dmang: &dyn MdMangLike, _builder: &mut String) {}
    }

    #[test]
    fn allow_md_type_info_parser_default_is_true() {
        assert!(MockMang::new("").allow_md_type_info_parser_default());
    }

    #[test]
    fn process_qual_c_as_special_fragment_is_false() {
        assert!(!MockMang::new("").process_qual_c_as_special_fragment());
    }

    #[test]
    fn use_vs_all_qualification_flag_drives_qualification_insert() {
        // Exercises the pre-existing MdMangLike seam this port relies on instead of
        // redeclaring `insert(StringBuilder, MDQualification)` itself.
        struct VsMang;
        impl MdMangLike for VsMang {
            fn insert_string(&self, builder: &mut String, s: &str) {
                builder.insert_str(0, s);
            }
            fn insert_spaced_string(&self, builder: &mut String, s: &str) {
                builder.insert_str(0, s);
            }
            fn use_vs_all_qualification(&self) -> bool {
                true
            }
        }

        let dmang = VsMang;
        let qual = MockQualification::default();
        let mut builder = String::new();
        qual.insert(&dmang, &mut builder);

        assert!(builder.is_empty());
    }

    #[test]
    fn use_vs2015_cli_array_ref_suffix_flag_discards_prior_content() {
        // Exercises the pre-existing MdMangLike seam extended by this port instead of
        // redeclaring `insertCLIArrayRefSuffix` itself.
        struct VsMang;
        impl MdMangLike for VsMang {
            fn insert_string(&self, builder: &mut String, s: &str) {
                builder.push_str(s);
            }
            fn insert_spaced_string(&self, builder: &mut String, s: &str) {
                builder.push_str(s);
            }
            fn use_vs2015_cli_array_ref_suffix(&self) -> bool {
                true
            }
        }

        let dmang = VsMang;
        let mut builder = String::from("stale");
        dmang.insert_cli_array_ref_suffix(&mut builder, "cli::array<int>");

        assert_eq!(builder, "cli::array<int>");
    }
}
