use crate::pty::PtyEndpoint;

/// The parent (UNIX "master") end of a pseudo-terminal.
pub trait PtyParent: PtyEndpoint {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor, ErrorKind, Read, Write};

    struct MockPtyParent;

    impl PtyEndpoint for MockPtyParent {
        fn get_output_stream(&self) -> io::Result<Box<dyn Write>> {
            Ok(Box::new(io::sink()))
        }

        fn get_input_stream(&self) -> io::Result<Box<dyn Read>> {
            Ok(Box::new(Cursor::new(vec![])))
        }
    }

    impl PtyParent for MockPtyParent {}

    #[test]
    fn pty_parent_implements_endpoint() {
        let parent = MockPtyParent;
        let output = parent.get_output_stream();
        assert!(output.is_ok());
        let input = parent.get_input_stream();
        assert!(input.is_ok());
    }

    #[test]
    fn pty_parent_is_marker_trait() {
        fn accepts_parent<T: PtyParent>() {}
        let parent = MockPtyParent;
        drop(parent);
    }
}
