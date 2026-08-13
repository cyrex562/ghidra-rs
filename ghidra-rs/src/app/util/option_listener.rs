/// Notification that an Option changed.
pub trait OptionListener: Send + Sync {
    /// Notification that the given option changed.
    fn option_changed(&self, option: &dyn std::any::Any);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestOptionListener {
        called: std::sync::atomic::AtomicBool,
    }

    impl TestOptionListener {
        fn new() -> Self {
            Self {
                called: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    impl OptionListener for TestOptionListener {
        fn option_changed(&self, _option: &dyn std::any::Any) {
            self.called.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn test_option_listener_called() {
        let listener = TestOptionListener::new();
        let option_name = "test_option";

        listener.option_changed(&option_name);
        assert!(listener.called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn test_listener_can_be_boxed() {
        let listener: Box<dyn OptionListener> = Box::new(TestOptionListener::new());
        listener.option_changed(&"test");
    }
}
