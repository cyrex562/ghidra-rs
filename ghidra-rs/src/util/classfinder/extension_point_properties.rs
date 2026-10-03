use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Properties for an extension point, including priority and exclusion status.
///
/// Port of `ghidra.util.classfinder.ExtensionPointProperties`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionPointProperties {
    pub priority: i32,
    pub exclude: bool,
}

impl ExtensionPointProperties {
    /// Default priority for an extension point. Higher values represent higher priorities.
    pub const DEFAULT_PRIORITY: i32 = 1;

    /// Default behavior for an extension point being discoverable.
    pub const DEFAULT_EXCLUDE: bool = false;

    /// Creates a new ExtensionPointProperties with the given priority and exclusion status.
    pub fn new(priority: i32, exclude: bool) -> Self {
        Self { priority, exclude }
    }

    /// Creates default properties.
    pub fn default() -> Self {
        Self {
            priority: Self::DEFAULT_PRIORITY,
            exclude: Self::DEFAULT_EXCLUDE,
        }
    }
}

static PROPERTIES_MAP: OnceLock<Mutex<HashMap<String, ExtensionPointProperties>>> =
    OnceLock::new();

fn get_properties_map() -> &'static Mutex<HashMap<String, ExtensionPointProperties>> {
    PROPERTIES_MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Utility methods for working with extension point properties.
pub struct Util;

impl Util {
    /// Gets whether or not the extension point will be excluded from being discovered.
    ///
    /// # Arguments
    ///
    /// * `class_path` - The fully qualified class name (e.g., `com.example.MyExtension`)
    ///
    /// # Returns
    ///
    /// `true` if the class is marked as excluded from being discovered
    pub fn is_excluded(class_path: &str) -> bool {
        get_properties_map()
            .lock()
            .unwrap()
            .get(class_path)
            .map(|p| p.exclude)
            .unwrap_or(ExtensionPointProperties::DEFAULT_EXCLUDE)
    }

    /// Gets the extension point priority.
    ///
    /// # Arguments
    ///
    /// * `class_path` - The fully qualified class name (e.g., `com.example.MyExtension`)
    ///
    /// # Returns
    ///
    /// The extension point priority, or `DEFAULT_PRIORITY` if not registered
    pub fn get_priority(class_path: &str) -> i32 {
        get_properties_map()
            .lock()
            .unwrap()
            .get(class_path)
            .map(|p| p.priority)
            .unwrap_or(ExtensionPointProperties::DEFAULT_PRIORITY)
    }

    /// Registers properties for an extension point class.
    ///
    /// # Arguments
    ///
    /// * `class_path` - The fully qualified class name
    /// * `properties` - The properties to register
    pub fn set_properties(class_path: &str, properties: ExtensionPointProperties) {
        get_properties_map()
            .lock()
            .unwrap()
            .insert(class_path.to_string(), properties);
    }

    /// Gets the properties for an extension point class, or defaults if not registered.
    ///
    /// # Arguments
    ///
    /// * `class_path` - The fully qualified class name
    ///
    /// # Returns
    ///
    /// The registered properties, or default properties if not registered
    pub fn get_properties(class_path: &str) -> ExtensionPointProperties {
        get_properties_map()
            .lock()
            .unwrap()
            .get(class_path)
            .cloned()
            .unwrap_or_else(ExtensionPointProperties::default)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    static TEST_GUARD: StdMutex<()> = StdMutex::new(());

    #[test]
    fn default_constants() {
        assert_eq!(ExtensionPointProperties::DEFAULT_PRIORITY, 1);
        assert_eq!(ExtensionPointProperties::DEFAULT_EXCLUDE, false);
    }

    #[test]
    fn default_properties() {
        let props = ExtensionPointProperties::default();
        assert_eq!(props.priority, 1);
        assert_eq!(props.exclude, false);
    }

    #[test]
    fn new_properties() {
        let props = ExtensionPointProperties::new(5, true);
        assert_eq!(props.priority, 5);
        assert_eq!(props.exclude, true);
    }

    #[test]
    fn is_excluded_defaults_to_false() {
        let _guard = TEST_GUARD.lock().unwrap();
        assert!(!Util::is_excluded("com.example.UnregisteredClass"));
    }

    #[test]
    fn get_priority_defaults_to_one() {
        let _guard = TEST_GUARD.lock().unwrap();
        assert_eq!(Util::get_priority("com.example.UnregisteredClass"), 1);
    }

    #[test]
    fn set_and_get_properties() {
        let _guard = TEST_GUARD.lock().unwrap();
        let props = ExtensionPointProperties::new(10, true);
        Util::set_properties("com.example.MyExtension", props.clone());

        assert_eq!(Util::get_properties("com.example.MyExtension"), props);
    }

    #[test]
    fn is_excluded_returns_registered_value() {
        let _guard = TEST_GUARD.lock().unwrap();
        Util::set_properties(
            "com.example.ExcludedClass",
            ExtensionPointProperties::new(1, true),
        );
        assert!(Util::is_excluded("com.example.ExcludedClass"));
    }

    #[test]
    fn is_excluded_returns_false_for_unexcluded() {
        let _guard = TEST_GUARD.lock().unwrap();
        Util::set_properties(
            "com.example.IncludedClass",
            ExtensionPointProperties::new(1, false),
        );
        assert!(!Util::is_excluded("com.example.IncludedClass"));
    }

    #[test]
    fn get_priority_returns_registered_value() {
        let _guard = TEST_GUARD.lock().unwrap();
        Util::set_properties(
            "com.example.HighPriorityClass",
            ExtensionPointProperties::new(99, false),
        );
        assert_eq!(Util::get_priority("com.example.HighPriorityClass"), 99);
    }

    #[test]
    fn properties_equality() {
        let a = ExtensionPointProperties::new(5, true);
        let b = ExtensionPointProperties::new(5, true);
        let c = ExtensionPointProperties::new(5, false);

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn properties_clone() {
        let original = ExtensionPointProperties::new(42, true);
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn get_properties_returns_defaults_for_unregistered() {
        let _guard = TEST_GUARD.lock().unwrap();
        let props = Util::get_properties("com.example.AnotherUnregisteredClass");
        assert_eq!(props.priority, 1);
        assert_eq!(props.exclude, false);
    }

    #[test]
    fn set_properties_overwrites_existing() {
        let _guard = TEST_GUARD.lock().unwrap();
        Util::set_properties(
            "com.example.OverwriteClass",
            ExtensionPointProperties::new(5, false),
        );
        Util::set_properties(
            "com.example.OverwriteClass",
            ExtensionPointProperties::new(10, true),
        );

        assert_eq!(Util::get_priority("com.example.OverwriteClass"), 10);
        assert!(Util::is_excluded("com.example.OverwriteClass"));
    }
}
