/// Indicates whether console output is on the standard output or error stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Stdout,
    Stderr,
}

/// Listener for console output events emitted by JDI.
pub trait JdiConsoleOutputListener: Send + Sync {
    /// Called when JDI produces console output.
    ///
    /// `channel` identifies whether the text arrived on stdout or stderr;
    /// `out` is the text that was produced.
    fn output(&self, channel: Channel, out: &str);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Collector {
        channel: Mutex<Option<Channel>>,
        text: Mutex<String>,
    }

    impl Collector {
        fn new() -> Self {
            Self {
                channel: Mutex::new(None),
                text: Mutex::new(String::new()),
            }
        }
    }

    impl JdiConsoleOutputListener for Collector {
        fn output(&self, channel: Channel, out: &str) {
            *self.channel.lock().unwrap() = Some(channel);
            *self.text.lock().unwrap() = out.to_owned();
        }
    }

    #[test]
    fn channel_variants_distinct() {
        assert_ne!(Channel::Stdout, Channel::Stderr);
    }

    #[test]
    fn channel_is_copy() {
        let a = Channel::Stdout;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn channel_debug() {
        assert_eq!(format!("{:?}", Channel::Stdout), "Stdout");
        assert_eq!(format!("{:?}", Channel::Stderr), "Stderr");
    }

    #[test]
    fn listener_receives_stdout() {
        let c = Collector::new();
        c.output(Channel::Stdout, "hello");
        assert_eq!(*c.channel.lock().unwrap(), Some(Channel::Stdout));
        assert_eq!(*c.text.lock().unwrap(), "hello");
    }

    #[test]
    fn listener_receives_stderr() {
        let c = Collector::new();
        c.output(Channel::Stderr, "error text");
        assert_eq!(*c.channel.lock().unwrap(), Some(Channel::Stderr));
        assert_eq!(*c.text.lock().unwrap(), "error text");
    }

    #[test]
    fn listener_as_trait_object() {
        let c = Collector::new();
        let listener: &dyn JdiConsoleOutputListener = &c;
        listener.output(Channel::Stdout, "via trait object");
        assert_eq!(*c.text.lock().unwrap(), "via trait object");
    }
}
