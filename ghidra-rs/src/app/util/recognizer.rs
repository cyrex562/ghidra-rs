/// Recognizes a byte format from a leading sample of bytes (e.g. a file header), returning a
/// description of the recognized format.
///
/// NOTE: In the Java original, all recognizer implementation class names must end in
/// "Recognizer", or the `ClassSearcher` will not find them via classpath scanning. That
/// constraint doesn't apply here since Rust recognizers are registered explicitly rather than
/// discovered by name.
///
/// Port of `ghidra.app.util.recognizer.Recognizer`. The Java interface also extends
/// `ExtensionPoint`, a marker interface with no methods that exists solely to aid Ghidra's
/// classpath scanner; it has no Rust equivalent and is omitted.
pub trait Recognizer {
    /// How many bytes (maximum) does this recognizer need to recognize its format?
    ///
    /// Returns the maximum number of bytes needed to send to this recognizer in the
    /// `recognize(...)` method.
    fn number_of_bytes_required(&self) -> usize;

    /// Ask the recognizer to recognize some bytes. Returns a description if recognized;
    /// otherwise, `None`. DO NOT MUNGE THE BYTES. Right now for efficiency's sake the array of
    /// bytes is just passed to each recognizer in turn. Abuse this and we will need to create
    /// copies, and everyone loses.
    fn recognize(&self, bytes: &[u8]) -> Option<String>;

    /// Return the recognizer priority; for instance, a GZIP/TAR recognizer should have higher
    /// priority than just the GZIP recognizer (because the GZIP/TAR will unzip part of the
    /// payload and then test against the TAR recognizer...so every GZIP/TAR match will also
    /// match GZIP). Note that higher is more specific, which is opposite the convention used
    /// with the Loader hierarchy.
    fn get_priority(&self) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal mock recognizer proving the trait is object-safe and usable via `Box<dyn
    /// Recognizer>`.
    struct GzipRecognizer;

    impl Recognizer for GzipRecognizer {
        fn number_of_bytes_required(&self) -> usize {
            2
        }

        fn recognize(&self, bytes: &[u8]) -> Option<String> {
            if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
                Some("GZIP".to_string())
            } else {
                None
            }
        }

        fn get_priority(&self) -> i32 {
            0
        }
    }

    #[test]
    fn recognizes_gzip_header_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(GzipRecognizer);

        assert_eq!(recognizer.number_of_bytes_required(), 2);
        assert_eq!(recognizer.recognize(&[0x1f, 0x8b, 0x00]), Some("GZIP".to_string()));
        assert_eq!(recognizer.recognize(&[0x00, 0x00]), None);
        assert_eq!(recognizer.get_priority(), 0);
    }
}
