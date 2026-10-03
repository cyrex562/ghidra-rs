//! Dispatches character codes in a mangled string to the appropriate data-type parse tier
//! (void/indirect/reference/basic/extended), then does the top-level multi-mode retry.
//!
//! Mirrors `mdemangler.datatype.MDDataTypeParser`, cut to a trait to break a dependency cycle: it
//! is a cut-point between the still-unported `MDMang` driver (context stack, processing mode,
//! character cursor beyond what [`MdCharacterIterator`] already covers) and the ~40 still-unported
//! concrete `MDDataType` subclasses (in `mdemangler.datatype.{complex,extended,modifier}` and
//! `mdemangler.object`) each parse tier switches on and constructs. Rather than stub a placeholder
//! trait per concrete subclass -- which would model no real behavior, since this parser never calls
//! anything on them beyond constructing and parsing -- the four switch-dispatch methods
//! ([`MdDataTypeParser::parse_data_type`], [`MdDataTypeParser::parse_primary_data_type`],
//! [`MdDataTypeParser::parse_special_extended_type`], [`MdDataTypeParser::parse_basic_data_type`])
//! are declared as required (implementor-supplied) trait methods, mirroring how
//! [`crate::demangler::md_mang_genericize::MdMangGenericize::parse_item`] collapses
//! `MDMangObjectParser.determineItemAndParse` (which needs the full unported `MDMang` grammar
//! surface) onto a required method instead of a seam. [`MdDataTypeParser::determine_and_parse_data_type`]
//! -- the only method whose logic doesn't depend on those unported concrete types -- is given a
//! real default implementation here, built on the required dispatch/context/mode primitives and
//! the already-ported [`MdCharacterIterator`].

use crate::demangler::md_character_iterator::MdCharacterIterator;
use crate::demangler::seam_stubs::{MdDataTypeLike, MdExceptionLike};

/// Mirrors the nested `MDMang.ProcessingMode` enum, whose two variants
/// [`MdDataTypeParser::determine_and_parse_data_type`] toggles between on retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdProcessingMode {
    /// Mirrors `ProcessingMode.DEFAULT_STANDARD`, used for the first parse attempt.
    DefaultStandard,
    /// Mirrors `ProcessingMode.LLVM`, used for the retry attempt after the first fails.
    Llvm,
}

/// Combined failure of both the standard and LLVM parse attempts.
///
/// Mirrors the `new MDException("Reason1: " + ... + "; Reason2: " + ...)` constructed in the
/// `catch` block of `determineAndParseDataType`. Defined locally (rather than requiring the
/// implementor to supply a constructor) since formatting two prior errors into one message needs
/// no knowledge of the concrete exception type.
#[derive(Debug)]
struct CombinedDataTypeError(String);

impl std::fmt::Display for CombinedDataTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl MdExceptionLike for CombinedDataTypeError {}

/// Parses data types out of a Microsoft-mangled string, at the several tiers of the (Microsoft)
/// data type hierarchy: some things (e.g. a reference to a pointer) are permitted in the grammar
/// while others (a pointer to a reference) are not, and the tiering enforces that by calling the
/// appropriate parser at the appropriate place.
///
/// Mirrors `mdemangler.datatype.MDDataTypeParser`. See the module docs for why the four
/// switch-dispatch methods are required rather than given real bodies here.
pub trait MdDataTypeParser {
    /// Read access to the character cursor over the mangled string.
    ///
    /// Stands in for `MDMang.iter`, reused directly since [`MdCharacterIterator`] is already
    /// fully ported.
    fn char_iter(&self) -> &MdCharacterIterator;

    /// Mutable access to the character cursor over the mangled string.
    ///
    /// Stands in for `MDMang.iter`.
    fn char_iter_mut(&mut self) -> &mut MdCharacterIterator;

    /// Pushes a fresh parse context onto the (unported) context stack.
    ///
    /// Mirrors `MDMang.pushContext()`. Required since `MDContext` is not ported.
    fn push_context(&mut self);

    /// Pops the current parse context off the (unported) context stack.
    ///
    /// Mirrors `MDMang.popContext()`. Required since `MDContext` is not ported.
    fn pop_context(&mut self);

    /// Sets the active processing mode.
    ///
    /// Mirrors `MDMang.setProcessingMode(ProcessingMode)`. Required since the processing-mode
    /// field lives on the still-unported `MDMang`.
    fn set_processing_mode(&mut self, mode: MdProcessingMode);

    /// Resets driver state ahead of a retry attempt (context stack and cursor index).
    ///
    /// Mirrors `MDMang.resetState()`. Required since the context stack it clears is not ported.
    fn reset_state(&mut self);

    /// Parses void, data-indirect, and function-indirect types, plus everything
    /// [`MdDataTypeParser::parse_primary_data_type`] parses.
    ///
    /// Mirrors `parseDataType(MDMang, boolean)`. Required: the concrete type it constructs for
    /// each switched-on code (`?` -> `MDQuestionModifierType`, `X` -> `MDVoidDataType`, default ->
    /// [`MdDataTypeParser::parse_primary_data_type`]) is not yet ported.
    fn parse_data_type(
        &mut self,
        is_highest: bool,
    ) -> Result<Box<dyn MdDataTypeLike>, Box<dyn MdExceptionLike>>;

    /// Parses references, plus everything [`MdDataTypeParser::parse_basic_data_type`] and
    /// [`MdDataTypeParser::parse_special_extended_type`] parse.
    ///
    /// Mirrors `parsePrimaryDataType(MDMang, boolean)`. Required: the concrete type it constructs
    /// for each switched-on code (`A`/`B` -> `MDReferenceType`, default ->
    /// [`MdDataTypeParser::parse_basic_data_type`]) is not yet ported.
    fn parse_primary_data_type(
        &mut self,
        is_highest: bool,
    ) -> Result<Box<dyn MdDataTypeLike>, Box<dyn MdExceptionLike>>;

    /// Parses the special extended data types Microsoft had not originally planned for: function
    /// indirect, pointer-reference, data-reference, data-reference-reference, `std::nullptr_t`,
    /// and a handful of others.
    ///
    /// Mirrors `parseSpecialExtendedType(MDMang, boolean)`. Required: every branch constructs one
    /// of `MDFunctionIndirectType`/`MDPointerRefDataType`/`MDDataReferenceType`/
    /// `MDDataRightReferenceType`/`MDStdNullPtrType`/`MDNamedUnspecifiedType`/
    /// `MDEmptyParameterType`/`MDEndParameterType`, none of which are yet ported.
    fn parse_special_extended_type(
        &mut self,
        is_highest: bool,
    ) -> Result<Box<dyn MdDataTypeLike>, Box<dyn MdExceptionLike>>;

    /// Parses basic and extended data types: the built-in arithmetic types, class/struct/union/
    /// enum/coclass/cointerface, pointers, and the `_`-prefixed extended-width/char variants.
    ///
    /// Mirrors `parseBasicDataType(MDMang, boolean)`. Required: every branch constructs one of the
    /// ~30 concrete basic/extended `MDDataType` subclasses, none of which are yet ported (with the
    /// sole exception of `MDComplexType`'s non-parsing surface, ported as
    /// [`crate::demangler::datatype::complex::md_complex_type::MdComplexType`], which doesn't
    /// change that constructing and parsing a fresh instance here is still unavailable).
    fn parse_basic_data_type(
        &mut self,
        is_highest: bool,
    ) -> Result<Box<dyn MdDataTypeLike>, Box<dyn MdExceptionLike>>;

    /// Top-level entry point used only by `MDMang` itself, for the highest-level type parsing
    /// where there isn't already a multi-mode retry in play. Checks for (and skips) a leading
    /// optional `.`, determines and parses the type via
    /// [`MdDataTypeParser::parse_data_type`], and -- mirroring `MDMangObjectParser`'s handling for
    /// generic mangled objects -- retries once under [`MdProcessingMode::Llvm`] if the first
    /// (`DefaultStandard`) attempt fails, combining both failures into one error if the retry also
    /// fails.
    ///
    /// Mirrors `determineAndParseDataType(MDMang, boolean)`. Given a real default body: unlike the
    /// four dispatch methods above, its own logic (mode toggling, context push/pop, the `.`-skip,
    /// and the retry/error-combining control flow) depends only on primitives already available on
    /// this trait, not on any unported concrete `MDDataType` subclass.
    fn determine_and_parse_data_type(
        &mut self,
        is_highest: bool,
    ) -> Result<Box<dyn MdDataTypeLike>, Box<dyn MdExceptionLike>> {
        self.set_processing_mode(MdProcessingMode::DefaultStandard);
        self.push_context();
        if self.char_iter().peek() == '.' {
            self.char_iter_mut().increment();
        }
        match self.parse_data_type(is_highest) {
            Ok(dt) => {
                self.pop_context();
                Ok(dt)
            }
            Err(e1) => {
                self.reset_state();
                self.set_processing_mode(MdProcessingMode::Llvm);
                self.push_context();
                self.char_iter_mut().increment();
                match self.parse_data_type(is_highest) {
                    Ok(dt) => {
                        self.pop_context();
                        Ok(dt)
                    }
                    Err(e2) => Err(Box::new(CombinedDataTypeError(format!(
                        "Reason1: {}; Reason2: {}",
                        e1, e2
                    )))),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MockDataType;

    impl MdDataTypeLike for MockDataType {
        fn is_specified_signed(&self) -> bool {
            false
        }

        fn is_unsigned(&self) -> bool {
            false
        }
    }

    #[derive(Debug)]
    struct MockParseError(String);

    impl std::fmt::Display for MockParseError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl MdExceptionLike for MockParseError {}

    struct MockParser {
        iter: MdCharacterIterator,
        push_count: usize,
        pop_count: usize,
        reset_count: usize,
        modes: Vec<MdProcessingMode>,
        attempts: usize,
        fail_first_n: usize,
    }

    impl MockParser {
        fn new(mangled: &str, fail_first_n: usize) -> Self {
            Self {
                iter: MdCharacterIterator::new(mangled),
                push_count: 0,
                pop_count: 0,
                reset_count: 0,
                modes: Vec::new(),
                attempts: 0,
                fail_first_n,
            }
        }
    }

    impl MdDataTypeParser for MockParser {
        fn char_iter(&self) -> &MdCharacterIterator {
            &self.iter
        }

        fn char_iter_mut(&mut self) -> &mut MdCharacterIterator {
            &mut self.iter
        }

        fn push_context(&mut self) {
            self.push_count += 1;
        }

        fn pop_context(&mut self) {
            self.pop_count += 1;
        }

        fn set_processing_mode(&mut self, mode: MdProcessingMode) {
            self.modes.push(mode);
        }

        fn reset_state(&mut self) {
            self.reset_count += 1;
        }

        fn parse_data_type(
            &mut self,
            _is_highest: bool,
        ) -> Result<Box<dyn MdDataTypeLike>, Box<dyn MdExceptionLike>> {
            self.attempts += 1;
            if self.attempts <= self.fail_first_n {
                Err(Box::new(MockParseError(format!("attempt {} failed", self.attempts))))
            } else {
                Ok(Box::new(MockDataType))
            }
        }

        fn parse_primary_data_type(
            &mut self,
            is_highest: bool,
        ) -> Result<Box<dyn MdDataTypeLike>, Box<dyn MdExceptionLike>> {
            self.parse_data_type(is_highest)
        }

        fn parse_special_extended_type(
            &mut self,
            is_highest: bool,
        ) -> Result<Box<dyn MdDataTypeLike>, Box<dyn MdExceptionLike>> {
            self.parse_data_type(is_highest)
        }

        fn parse_basic_data_type(
            &mut self,
            is_highest: bool,
        ) -> Result<Box<dyn MdDataTypeLike>, Box<dyn MdExceptionLike>> {
            self.parse_data_type(is_highest)
        }
    }

    #[test]
    fn first_attempt_success_skips_leading_dot_and_pops_once() {
        let mut parser = MockParser::new(".Pax", 0);

        let result = parser.determine_and_parse_data_type(true);

        assert!(result.is_ok());
        assert_eq!(parser.push_count, 1);
        assert_eq!(parser.pop_count, 1);
        assert_eq!(parser.reset_count, 0);
        assert_eq!(parser.modes, vec![MdProcessingMode::DefaultStandard]);
        // The leading '.' was consumed, leaving the cursor at 'P'.
        assert_eq!(parser.char_iter().peek(), 'P');
    }

    #[test]
    fn no_leading_dot_is_left_untouched() {
        let mut parser = MockParser::new("Pax", 0);

        let result = parser.determine_and_parse_data_type(true);

        assert!(result.is_ok());
        assert_eq!(parser.char_iter().get_index(), 0);
    }

    #[test]
    fn failed_first_attempt_retries_under_llvm_mode_and_succeeds() {
        let mut parser = MockParser::new(".Pax", 1);

        let result = parser.determine_and_parse_data_type(true);

        assert!(result.is_ok());
        assert_eq!(parser.attempts, 2);
        assert_eq!(parser.reset_count, 1);
        assert_eq!(parser.push_count, 2);
        assert_eq!(parser.pop_count, 1, "only the successful attempt pops its context");
        assert_eq!(
            parser.modes,
            vec![MdProcessingMode::DefaultStandard, MdProcessingMode::Llvm]
        );
    }

    #[test]
    fn both_attempts_failing_combines_both_reasons() {
        let mut parser = MockParser::new(".Pax", 2);

        let result = parser.determine_and_parse_data_type(true);

        let err = match result {
            Ok(_) => panic!("both attempts should fail"),
            Err(e) => e,
        };
        let message = err.to_string();
        assert!(message.contains("Reason1: attempt 1 failed"), "{message}");
        assert!(message.contains("Reason2: attempt 2 failed"), "{message}");
        assert_eq!(parser.pop_count, 0, "no attempt succeeded, so nothing pops its context");
    }

    #[test]
    fn trait_object_is_usable() {
        let mut parser = MockParser::new(".Pax", 0);
        let dtp: &mut dyn MdDataTypeParser = &mut parser;

        let result = dtp.determine_and_parse_data_type(false);

        assert!(result.is_ok());
    }
}
