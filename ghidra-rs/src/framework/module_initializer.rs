use crate::util::classfinder::ExtensionPoint;

/// An extension point that users can implement to perform work before the application is loaded.
///
/// To create a module initializer:
/// 1. Implement ModuleInitializer
/// 2. Have the name of your implementation end with the keyword 'Initializer'
///
/// Port of `ghidra.framework.ModuleInitializer`.
pub trait ModuleInitializer: ExtensionPoint + Send + Sync {
    /// Runs the initialization logic.
    fn run(&self);

    /// Returns the initializer name.
    fn get_name(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestInitializer;

    impl ExtensionPoint for TestInitializer {}

    impl ModuleInitializer for TestInitializer {
        fn run(&self) {}

        fn get_name(&self) -> String {
            "TestInitializer".to_string()
        }
    }

    #[test]
    fn module_initializer_trait_is_implementable() {
        let initializer: Box<dyn ModuleInitializer> = Box::new(TestInitializer);
        assert_eq!(initializer.get_name(), "TestInitializer");
    }

    #[test]
    fn module_initializer_run_can_be_called() {
        let initializer = TestInitializer;
        initializer.run();
    }

    #[test]
    fn module_initializer_is_send_sync() {
        fn assert_send_sync<T: Send + Sync + ModuleInitializer>() {}
        assert_send_sync::<TestInitializer>();
    }
}
