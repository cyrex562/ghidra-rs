//! Mirrors `ghidra.app.util.sourcelanguage.ObjcSourceLanguage`.

use crate::app::util::sourcelanguage::source_language::SourceLanguage;
use crate::app::util::sourcelanguage::source_language_id::{SourceLanguageId, SourceLanguageIdValue};

/// Returns the shared Objective-C source language ID, `"Objective-C"`.
///
/// Mirrors the constant `ObjcSourceLanguage.OBJC_ID`.
pub fn objc_id() -> SourceLanguageIdValue {
    SourceLanguageIdValue::new("Objective-C").expect("\"Objective-C\" is a valid SourceLanguageID")
}

/// The base Objective-C [`SourceLanguage`].
///
/// Port of `ghidra.app.util.sourcelanguage.ObjcSourceLanguage`, an abstract class implementing
/// `SourceLanguage` that supplies a concrete `getID()` (always [`objc_id`]) while leaving
/// `existsIn` abstract for its own subclasses.
///
/// Follows the same composition/shadowing split already established by
/// [`SwiftSourceLanguage`](crate::app::util::sourcelanguage::swift_source_language::SwiftSourceLanguage)
/// for the identically-shaped Java class: a concrete Objective-C source language type would embed
/// [`ObjcSourceLanguageBase`] as a marker/placeholder for "is an Objective-C source language" and
/// implement the [`ObjcSourceLanguage`] trait below (whose default
/// [`ObjcSourceLanguage::get_id`] it forwards its own required [`SourceLanguage::get_id`] to)
/// alongside [`SourceLanguage`] itself (supplying `exists_in` for real). Rust's trait system does
/// not forward same-named default methods across independent traits automatically -- see
/// [`SwiftSourceLanguage`](crate::app::util::sourcelanguage::swift_source_language::SwiftSourceLanguage)'s
/// own docs (and, further back,
/// [`FunctionEntryPointBasedAbstractMarkupType`](crate::feature::vt::api::markuptype::FunctionEntryPointBasedAbstractMarkupType))
/// for the same shadowing pattern and its explanation. There being no state to carry (Java's
/// `ObjcSourceLanguage` itself declares no instance fields, only the static `OBJC_ID`), this
/// struct is a marker with no fields, rather than a `Base` type wrapping one.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ObjcSourceLanguageBase;

/// Port of the abstract class `ghidra.app.util.sourcelanguage.ObjcSourceLanguage`. See
/// [`ObjcSourceLanguageBase`]'s own docs for the composition/shadowing split.
pub trait ObjcSourceLanguage: SourceLanguage {
    /// Mirrors `ObjcSourceLanguage.getID()`, which always returns the shared `OBJC_ID` constant.
    fn get_id(&self) -> Box<dyn SourceLanguageId> {
        Box::new(objc_id())
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

    /// A minimal, concrete "Objective-C-flavored" source language standing in for one of Java's
    /// real subclasses (none ported yet), supplying only `exists_in` for real while inheriting
    /// `getID()`'s answer from [`ObjcSourceLanguage`]'s default.
    struct StubObjcSourceLanguage {
        _base: ObjcSourceLanguageBase,
        present: bool,
    }

    impl SourceLanguage for StubObjcSourceLanguage {
        fn get_id(&self) -> Box<dyn SourceLanguageId> {
            ObjcSourceLanguage::get_id(self)
        }

        fn exists_in(
            &self,
            _program: &dyn Program,
            _monitor: &dyn TaskMonitor,
        ) -> Result<bool, ExistsInError> {
            Ok(self.present)
        }
    }

    impl ObjcSourceLanguage for StubObjcSourceLanguage {}

    #[test]
    fn objc_id_is_the_literal_string_objective_c() {
        assert_eq!(objc_id().get_id_as_string(), "Objective-C");
    }

    /// Java: every `ObjcSourceLanguage` subclass's `getID()` returns the same shared `OBJC_ID`
    /// constant, regardless of which concrete subclass it is.
    #[test]
    fn get_id_is_always_the_shared_objc_id() {
        let language = StubObjcSourceLanguage { _base: ObjcSourceLanguageBase, present: true };
        assert_eq!(SourceLanguage::get_id(&language).get_id_as_string(), "Objective-C");
        assert_eq!(ObjcSourceLanguage::get_id(&language).get_id_as_string(), "Objective-C");
    }

    #[test]
    fn exists_in_is_left_to_the_concrete_subclass() {
        let program = MockProgram;
        let monitor = crate::util::task::DummyMonitor;

        let present = StubObjcSourceLanguage { _base: ObjcSourceLanguageBase, present: true };
        assert!(present.exists_in(&program, &monitor).unwrap());

        let absent = StubObjcSourceLanguage { _base: ObjcSourceLanguageBase, present: false };
        assert!(!absent.exists_in(&program, &monitor).unwrap());
    }

    #[test]
    fn usable_as_source_language_trait_object() {
        let language: Box<dyn SourceLanguage> =
            Box::new(StubObjcSourceLanguage { _base: ObjcSourceLanguageBase, present: true });
        assert_eq!(language.get_id().get_id_as_string(), "Objective-C");
    }
}
