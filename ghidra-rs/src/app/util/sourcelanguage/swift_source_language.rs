use crate::app::util::sourcelanguage::source_language::SourceLanguage;
use crate::app::util::sourcelanguage::source_language_id::{SourceLanguageId, SourceLanguageIdValue};

/// Returns the shared Swift source language ID, `"Swift"`.
///
/// Mirrors the constant `SwiftSourceLanguage.SWIFT_ID`.
///
/// A pre-existing seam stub, [`crate::demangler::seam_stubs::swift_source_language_id`], already
/// provides this exact same value (built the same way) for
/// [`SwiftDemangler`](crate::demangler::swift::swift_demangler::SwiftDemangler), which needed only
/// the ID constant and predates this real port. That call site is left as-is (not rewired to this
/// module) to avoid a collateral change outside a single class's porting scope -- the same
/// precedent already documented on
/// [`AssemblyParseTreeNode`](crate::app::plugin::assembler::sleigh::tree::AssemblyParseTreeNode)
/// for not retrofitting an already-complete, already-tested call site onto a newly-ported type.
pub fn swift_id() -> SourceLanguageIdValue {
    SourceLanguageIdValue::new("Swift").expect("\"Swift\" is a valid SourceLanguageID")
}

/// The base Swift [`SourceLanguage`].
///
/// Port of `ghidra.app.util.sourcelanguage.SwiftSourceLanguage`, an abstract class implementing
/// `SourceLanguage` that supplies a concrete `getID()` (always [`swift_id`]) while leaving
/// `existsIn` abstract for its own subclasses (`ElfSwiftSourceLanguage`,
/// `MachoSwiftSourceLanguage`, `PeSwiftSourceLanguage` in Java -- none ported yet).
///
/// Per this crate's composition-over-inheritance convention, a concrete Swift source language type
/// would embed this unit struct as a marker/placeholder for "is a Swift source language" and
/// implement the [`SwiftSourceLanguage`] trait below (whose default [`SwiftSourceLanguage::get_id`]
/// it forwards its own required [`SourceLanguage::get_id`] to) alongside [`SourceLanguage`] itself
/// (supplying `exists_in` for real). Rust's trait system does not forward same-named default
/// methods across independent traits automatically -- see
/// [`FunctionEntryPointBasedAbstractMarkupType`](crate::feature::vt::api::markuptype::FunctionEntryPointBasedAbstractMarkupType)
/// for the same shadowing pattern and its explanation. There being no state to carry (Java's
/// `SwiftSourceLanguage` itself declares no instance fields, only the static `SWIFT_ID`), this
/// struct is a marker with no fields, rather than a `Base` type wrapping one.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SwiftSourceLanguageBase;

/// Port of the abstract class `ghidra.app.util.sourcelanguage.SwiftSourceLanguage`. See
/// [`SwiftSourceLanguageBase`]'s own docs for the composition/shadowing split.
pub trait SwiftSourceLanguage: SourceLanguage {
    /// Mirrors `SwiftSourceLanguage.getID()`, which always returns the shared `SWIFT_ID` constant.
    fn get_id(&self) -> Box<dyn SourceLanguageId> {
        Box::new(swift_id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::sourcelanguage::source_language::ExistsInError;
    use crate::program::model::listing::Program;
    use crate::util::task::TaskMonitor;

    struct MockProgram;

    impl crate::framework::model::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn get_language_id(&self) -> String {
            "x86:LE:64:default".to_string()
        }
    }

    /// A minimal, concrete "Swift-flavored" source language standing in for one of Java's real
    /// subclasses (`ElfSwiftSourceLanguage`/`MachoSwiftSourceLanguage`/`PeSwiftSourceLanguage`,
    /// none ported yet), supplying only `exists_in` for real while inheriting `getID()`'s answer
    /// from [`SwiftSourceLanguage`]'s default.
    struct StubSwiftSourceLanguage {
        _base: SwiftSourceLanguageBase,
        present: bool,
    }

    impl SourceLanguage for StubSwiftSourceLanguage {
        fn get_id(&self) -> Box<dyn SourceLanguageId> {
            SwiftSourceLanguage::get_id(self)
        }

        fn exists_in(
            &self,
            _program: &dyn Program,
            _monitor: &dyn TaskMonitor,
        ) -> Result<bool, ExistsInError> {
            Ok(self.present)
        }
    }

    impl SwiftSourceLanguage for StubSwiftSourceLanguage {}

    #[test]
    fn swift_id_is_the_literal_string_swift() {
        assert_eq!(swift_id().get_id_as_string(), "Swift");
    }

    /// Java: every `SwiftSourceLanguage` subclass's `getID()` returns the same shared `SWIFT_ID`
    /// constant, regardless of which concrete subclass it is.
    #[test]
    fn get_id_is_always_the_shared_swift_id() {
        let language = StubSwiftSourceLanguage { _base: SwiftSourceLanguageBase, present: true };
        assert_eq!(SourceLanguage::get_id(&language).get_id_as_string(), "Swift");
        assert_eq!(SwiftSourceLanguage::get_id(&language).get_id_as_string(), "Swift");
    }

    #[test]
    fn exists_in_is_left_to_the_concrete_subclass() {
        let program = MockProgram;
        let monitor = crate::util::task::DummyMonitor;

        let present = StubSwiftSourceLanguage { _base: SwiftSourceLanguageBase, present: true };
        assert!(present.exists_in(&program, &monitor).unwrap());

        let absent = StubSwiftSourceLanguage { _base: SwiftSourceLanguageBase, present: false };
        assert!(!absent.exists_in(&program, &monitor).unwrap());
    }

    #[test]
    fn usable_as_source_language_trait_object() {
        let language: Box<dyn SourceLanguage> =
            Box::new(StubSwiftSourceLanguage { _base: SwiftSourceLanguageBase, present: true });
        assert_eq!(language.get_id().get_id_as_string(), "Swift");
    }
}
