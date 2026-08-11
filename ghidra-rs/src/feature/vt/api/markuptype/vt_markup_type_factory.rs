//! Registry of the well-known [`VtMarkupType`] singletons, keyed by the stable numeric id each
//! one is persisted under in the version tracking database.
//!
//! Port of `ghidra.feature.vt.api.markuptype.VTMarkupTypeFactory`. The Java class is a pure
//! statics holder (two static maps and four static methods, never instantiated), so this is a
//! plain module of free functions over a lazily-initialized static registry rather than a
//! zero-field struct with an `impl` block.

use std::sync::{Arc, OnceLock, RwLock};

use crate::feature::seam_stubs::{
    DataTypeMarkupType, EolCommentMarkupType, FunctionNameMarkupType, FunctionSignatureMarkupType,
    LabelMarkupType, PlateCommentMarkupType, PostCommentMarkupType, PreCommentMarkupType,
    RepeatableCommentMarkupType, VtMarkupType,
};
use crate::util::exception::AssertException;
use crate::util::system_utilities::SystemUtilities;

/// The id an unregistered markup type is assigned when [`get_id`] is called in testing mode,
/// mirroring the Java `getID` fallback of `register(9999, markupType)`.
const UNREGISTERED_TEST_ID: i32 = 9999;

type Registry = RwLock<Vec<(i32, Arc<dyn VtMarkupType>)>>;

static REGISTRY: OnceLock<Registry> = OnceLock::new();

fn registry() -> &'static Registry {
    REGISTRY.get_or_init(|| {
        // WARNING - never change the id for a markup type. It is the number stored in the
        // database. Commented-out ids in the Java source (not yet ported markup types) are
        // omitted here rather than carried forward as dead code.
        let entries: Vec<(i32, Arc<dyn VtMarkupType>)> = vec![
            (12, Arc::new(EolCommentMarkupType)),
            (13, Arc::new(FunctionNameMarkupType)),
            (22, Arc::new(LabelMarkupType)),
            (23, Arc::new(PlateCommentMarkupType)),
            (24, Arc::new(PostCommentMarkupType)),
            (25, Arc::new(PreCommentMarkupType)),
            (26, Arc::new(RepeatableCommentMarkupType)),
            (27, Arc::new(DataTypeMarkupType)),
            (29, Arc::new(FunctionSignatureMarkupType)),
        ];
        RwLock::new(entries)
    })
}

/// Port of `VTMarkupTypeFactory.getMarkupTypes()`.
pub fn get_markup_types() -> Vec<Arc<dyn VtMarkupType>> {
    registry()
        .read()
        .unwrap()
        .iter()
        .map(|(_, markup_type)| markup_type.clone())
        .collect()
}

/// Port of `VTMarkupTypeFactory.getMarkupType(int)`.
pub fn get_markup_type(id: i32) -> Option<Arc<dyn VtMarkupType>> {
    registry()
        .read()
        .unwrap()
        .iter()
        .find(|(entry_id, _)| *entry_id == id)
        .map(|(_, markup_type)| markup_type.clone())
}

/// Port of `VTMarkupTypeFactory.getID(VTMarkupType)`.
///
/// # Panics
///
/// Panics with an [`AssertException`] if `markup_type` was never registered and
/// [`SystemUtilities::is_in_testing_mode`] is false, mirroring the Java method throwing an
/// unchecked `AssertException` in that case.
pub fn get_id(markup_type: &Arc<dyn VtMarkupType>) -> i32 {
    if let Some(id) = registry()
        .read()
        .unwrap()
        .iter()
        .find(|(_, entry)| Arc::ptr_eq(entry, markup_type))
        .map(|(id, _)| *id)
    {
        return id;
    }

    if SystemUtilities::is_in_testing_mode() {
        registry()
            .write()
            .unwrap()
            .push((UNREGISTERED_TEST_ID, markup_type.clone()));
        return UNREGISTERED_TEST_ID;
    }

    panic!(
        "{}",
        AssertException::with_message("Attempted to use an unregistered VTMarkupType")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_the_nine_well_known_markup_types() {
        // `>=` rather than `==`: the registry is a shared static, and
        // `get_id_registers_unknown_type_under_9999_in_testing_mode` (below) may run concurrently
        // and add a 10th entry.
        let types = get_markup_types();
        assert!(
            types.len() >= 9,
            "expected at least the 9 well-known markup types, got {}",
            types.len()
        );
    }

    #[test]
    fn get_markup_type_looks_up_by_id() {
        let eol = get_markup_type(12).expect("id 12 should be registered");
        assert_eq!(eol.get_name(), "EOL Comment");

        let function_signature = get_markup_type(29).expect("id 29 should be registered");
        assert_eq!(function_signature.get_name(), "Function Signature");

        // 11 is a commented-out id in the Java source (never registered by this port); 9999 is
        // deliberately not asserted against here since another test in this module registers it
        // under the shared static registry, and tests may run concurrently.
        assert!(get_markup_type(11).is_none());
    }

    #[test]
    fn get_id_round_trips_through_get_markup_type() {
        let markup_type = get_markup_type(22).expect("id 22 should be registered");
        assert_eq!(get_id(&markup_type), 22);
    }

    #[test]
    fn get_id_registers_unknown_type_under_9999_in_testing_mode() {
        std::env::set_var(SystemUtilities::TESTING_PROPERTY, "true");
        assert!(SystemUtilities::is_in_testing_mode());

        let unregistered: Arc<dyn VtMarkupType> = Arc::new(LabelMarkupType);
        // Distinct `Arc` from the one seeded into the registry, so this is genuinely unregistered
        // by pointer identity even though `LabelMarkupType` is already registered under id 22.
        let id = get_id(&unregistered);
        assert_eq!(id, 9999);

        // A second lookup of the same instance now finds the entry `get_id` just inserted.
        assert_eq!(get_id(&unregistered), 9999);
    }
}
