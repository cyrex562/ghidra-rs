use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

static CLASS_PATH_MAP: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

fn get_class_path_map() -> &'static Mutex<HashMap<String, String>> {
    CLASS_PATH_MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Provides a way to map an old Ghidra class to a current Ghidra class. It can
/// be used whenever a class is moved or renamed and Ghidra needs to know.
///
/// **Important**: Any class that is indicated by the `current_class_path`
/// passed to [`ClassTranslator::put`] should implement `ExtensionPoint`.
///
/// Whenever a class whose name gets stored in the database is moved to
/// another package or renamed, the map of the old class path name to the
/// new one should get registered with `ClassTranslator`.
///
/// Example: The class `ghidra.app.plugin.core.MyPlugin.MyInfo` is in Ghidra
/// version 1. In Ghidra version 2, it is moved and renamed to
/// `ghidra.app.plugin.core.RenamedPlugin.SubPackage.SaveInfo`. Register the
/// following mapping when the version 2 `SaveInfo` type is initialized:
/// ```ignore
/// ClassTranslator::put("ghidra.app.plugin.core.MyPlugin.MyInfo", SaveInfo::class_name());
/// ```
///
/// Warning: If the class gets moved or renamed again in a subsequent version
/// of Ghidra, a new translation (`put` call) should get added and any old
/// translations should have their current path name changed to the new
/// class path.
///
/// Port of `ghidra.util.classfinder.ClassTranslator`.
pub struct ClassTranslator;

impl ClassTranslator {
    /// Returns `true` if this `ClassTranslator` has a mapping for the indicated
    /// old class path name.
    pub fn contains(old_class_path: &str) -> bool {
        get_class_path_map().lock().unwrap().contains_key(old_class_path)
    }

    /// Returns the current class path name that is mapped for the indicated
    /// old class path name, or `None` if the old class path name isn't mapped.
    pub fn get(old_class_path: &str) -> Option<String> {
        get_class_path_map().lock().unwrap().get(old_class_path).cloned()
    }

    /// Defines a mapping indicating the class path name of the current Ghidra
    /// class that is the same class as the indicated old class path name from
    /// a previous Ghidra version.
    ///
    /// **Important**: Any class that is indicated by `current_class_path`
    /// should implement `ExtensionPoint`.
    pub fn put(old_class_path: &str, current_class_path: &str) {
        get_class_path_map()
            .lock()
            .unwrap()
            .insert(old_class_path.to_string(), current_class_path.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    // Serializes tests since ClassTranslator's map is a shared, process-global static.
    static TEST_GUARD: StdMutex<()> = StdMutex::new(());

    #[test]
    fn contains_is_false_for_unmapped_class() {
        let _guard = TEST_GUARD.lock().unwrap();
        assert!(!ClassTranslator::contains("no.such.OldClass"));
    }

    #[test]
    fn put_then_contains_and_get() {
        let _guard = TEST_GUARD.lock().unwrap();
        ClassTranslator::put("old.pkg.OldClass", "new.pkg.NewClass");
        assert!(ClassTranslator::contains("old.pkg.OldClass"));
        assert_eq!(
            ClassTranslator::get("old.pkg.OldClass"),
            Some("new.pkg.NewClass".to_string())
        );
    }

    #[test]
    fn get_returns_none_for_unmapped_class() {
        let _guard = TEST_GUARD.lock().unwrap();
        assert_eq!(ClassTranslator::get("still.no.such.OldClass"), None);
    }

    #[test]
    fn put_overwrites_existing_mapping() {
        let _guard = TEST_GUARD.lock().unwrap();
        ClassTranslator::put("overwrite.OldClass", "first.NewClass");
        ClassTranslator::put("overwrite.OldClass", "second.NewClass");
        assert_eq!(
            ClassTranslator::get("overwrite.OldClass"),
            Some("second.NewClass".to_string())
        );
    }
}
