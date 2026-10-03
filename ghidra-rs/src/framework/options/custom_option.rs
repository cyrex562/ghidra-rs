//! Port of `ghidra.framework.options.CustomOption`.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use crate::framework::options::g_properties::GProperties;

/// Key which corresponds to the custom option implementation class.
///
/// The use of this key/value within the stored state information is reserved for use by the
/// option storage implementation and should be ignored by [`CustomOption::read_state`]
/// implementations.
///
/// Stands in for `CustomOption.CUSTOM_OPTION_CLASS_NAME_KEY`.
pub const CUSTOM_OPTION_CLASS_NAME_KEY: &str = "CUSTOM_OPTION_CLASS";

/// A user-defined option value type that knows how to persist and restore its own state.
///
/// Port of `ghidra.framework.options.CustomOption`.
///
/// Java persists a custom option together with its class name (`getClass().getName()`) and later
/// re-creates it reflectively through its public no-arg constructor; here the class name comes
/// from [`java_class_name`](CustomOption::java_class_name) and the constructor from
/// [`register_custom_option_class`].
pub trait CustomOption: std::fmt::Display {
    /// Read state from the given properties.
    fn read_state(&mut self, properties: &GProperties);

    /// Write state into the given properties.
    fn write_state(&self, properties: &mut GProperties);

    /// The fully-qualified Java class name this option persists as (`getClass().getName()`).
    fn java_class_name(&self) -> &'static str;
}

/// A custom option's public no-arg constructor, as Java's `getConstructor().newInstance()` finds
/// it reflectively.
pub type CustomOptionConstructor = fn() -> Box<dyn CustomOption + Send + Sync>;

fn registry() -> &'static RwLock<HashMap<String, CustomOptionConstructor>> {
    static REGISTRY: OnceLock<RwLock<HashMap<String, CustomOptionConstructor>>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let mut map: HashMap<String, CustomOptionConstructor> = HashMap::new();
        // The ported CustomOption implementations.
        map.insert(
            "ghidra.app.util.demangler.microsoft.options.MsdApplyOption".to_string(),
            || Box::new(crate::demangler::microsoft::options::MsdApplyOption::default()),
        );
        RwLock::new(map)
    })
}

/// Registers the constructor used to re-create a persisted custom option of Java class
/// `class_name` (replacing any earlier one), standing in for `ClassSearcher.forNameSafe`.
pub fn register_custom_option_class(class_name: &str, constructor: CustomOptionConstructor) {
    registry().write().unwrap().insert(class_name.to_string(), constructor);
}

/// A new, default-constructed custom option of Java class `class_name`, if that class is
/// registered (Java's `ClassNotFoundException` otherwise).
pub fn new_custom_option(class_name: &str) -> Option<Box<dyn CustomOption + Send + Sync>> {
    registry().read().unwrap().get(class_name).map(|ctor| ctor())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    struct IntOption(i32);

    impl fmt::Display for IntOption {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl CustomOption for IntOption {
        fn read_state(&mut self, properties: &GProperties) {
            self.0 = properties.get_int("value", -1);
        }

        fn write_state(&self, properties: &mut GProperties) {
            properties.put_int("value", self.0);
        }

        fn java_class_name(&self) -> &'static str {
            "test.IntOption"
        }
    }

    #[test]
    fn object_safe_and_round_trips_via_dyn() {
        let option: Box<dyn CustomOption> = Box::new(IntOption(42));
        let mut props = GProperties::new("p");
        option.write_state(&mut props);
        let mut restored: Box<dyn CustomOption> = Box::new(IntOption(0));
        restored.read_state(&props);
        assert_eq!(restored.to_string(), "42");
    }
}
