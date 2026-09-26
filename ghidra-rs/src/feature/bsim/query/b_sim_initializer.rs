use crate::framework::ModuleInitializer;
use crate::util::ExtensionPoint;

/// Module initializer for the BSim feature, responsible for registering the PostgreSQL URL scheme.
///
/// Port of `ghidra.features.bsim.query.BSimInitializer`.
pub struct BSimInitializer;

impl ExtensionPoint for BSimInitializer {}

impl ModuleInitializer for BSimInitializer {
    fn run(&self) {
        super::postgresql::register_handler();
    }

    fn get_name(&self) -> String {
        "BSim Module".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initializer_name() {
        let initializer = BSimInitializer;
        assert_eq!(initializer.get_name(), "BSim Module");
    }

    #[test]
    fn test_run_does_not_panic() {
        let initializer = BSimInitializer;
        initializer.run();
    }

    #[test]
    fn test_initializer_is_extension_point() {
        let _: &dyn ExtensionPoint = &BSimInitializer;
    }

    #[test]
    fn test_initializer_is_module_initializer() {
        let _: &dyn ModuleInitializer = &BSimInitializer;
    }
}
