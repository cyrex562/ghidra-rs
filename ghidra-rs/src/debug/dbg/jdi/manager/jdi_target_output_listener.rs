/// Listener for target console output events emitted by JDI.
///
/// Note: the semantics of this listener are not well established; JDI's target
/// output record is rarely used in practice.
pub trait JdiTargetOutputListener: Send + Sync {
    /// Called when the target produces output text.
    ///
    /// `out` is the text that was produced.
    fn output(&self, out: &str);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Collector {
        text: Mutex<String>,
    }

    impl Collector {
        fn new() -> Self {
            Self {
                text: Mutex::new(String::new()),
            }
        }
    }

    impl JdiTargetOutputListener for Collector {
        fn output(&self, out: &str) {
            *self.text.lock().unwrap() = out.to_owned();
        }
    }

    #[test]
    fn listener_receives_output() {
        let c = Collector::new();
        c.output("hello target");
        assert_eq!(*c.text.lock().unwrap(), "hello target");
    }

    #[test]
    fn listener_receives_empty_string() {
        let c = Collector::new();
        c.output("");
        assert_eq!(*c.text.lock().unwrap(), "");
    }

    #[test]
    fn listener_as_trait_object() {
        let c = Collector::new();
        let listener: &dyn JdiTargetOutputListener = &c;
        listener.output("via trait object");
        assert_eq!(*c.text.lock().unwrap(), "via trait object");
    }
}
