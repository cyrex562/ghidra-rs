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

/// Recognizes ACE compressed files by their magic header bytes: `**ACE**`.
///
/// Port of `ghidra.app.util.recognizer.AceRecognizer`.
pub struct AceRecognizer;

impl Recognizer for AceRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        7
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x2a
                && bytes[1] == 0x2a
                && bytes[2] == 0x41
                && bytes[3] == 0x43
                && bytes[4] == 0x45
                && bytes[5] == 0x2a
                && bytes[6] == 0x2a
            {
                return Some("File appears to be an ACE compressed file".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes ARJ compressed files by their magic header bytes: `0x60 0xea`.
///
/// Port of `ghidra.app.util.recognizer.ArjRecognizer`.
pub struct ArjRecognizer;

impl Recognizer for ArjRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        2
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x60 && bytes[1] == 0xea {
                return Some("File appears to be an ARJ compressed file".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes BZIP2 compressed files by their magic header bytes: `0x42 0x5a 0x68`.
///
/// Port of `ghidra.app.util.recognizer.Bzip2Recognizer`.
pub struct Bzip2Recognizer;

impl Recognizer for Bzip2Recognizer {
    fn number_of_bytes_required(&self) -> usize {
        3
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x42 && bytes[1] == 0x5a && bytes[2] == 0x68 {
                return Some("File appears to be a BZIP2 compressed file".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes Microsoft Compiled HTML (CHM) files by their magic header bytes: `ITSF`.
///
/// Port of `ghidra.app.util.recognizer.CHMRecognizer`.
pub struct ChmRecognizer;

impl Recognizer for ChmRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        4
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x49 && bytes[1] == 0x54 && bytes[2] == 0x53 && bytes[3] == 0x46 {
                return Some("File appears to be a Microsoft Compiled HTML (CHM) file".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
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

    #[test]
    fn ace_recognizer_identifies_valid_header() {
        let recognizer = AceRecognizer;
        let ace_header = [0x2a, 0x2a, 0x41, 0x43, 0x45, 0x2a, 0x2a];

        assert_eq!(recognizer.number_of_bytes_required(), 7);
        assert_eq!(
            recognizer.recognize(&ace_header),
            Some("File appears to be an ACE compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn ace_recognizer_rejects_insufficient_bytes() {
        let recognizer = AceRecognizer;
        let short_buffer = [0x2a, 0x2a, 0x41, 0x43, 0x45];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn ace_recognizer_rejects_mismatched_magic() {
        let recognizer = AceRecognizer;
        let wrong_magic = [0x2a, 0x2a, 0x42, 0x43, 0x45, 0x2a, 0x2a];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn ace_recognizer_works_with_extra_data() {
        let recognizer = AceRecognizer;
        let ace_header_with_data =
            [0x2a, 0x2a, 0x41, 0x43, 0x45, 0x2a, 0x2a, 0xff, 0xfe, 0xfd];

        assert_eq!(
            recognizer.recognize(&ace_header_with_data),
            Some("File appears to be an ACE compressed file".to_string())
        );
    }

    #[test]
    fn ace_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(AceRecognizer);
        let ace_header = [0x2a, 0x2a, 0x41, 0x43, 0x45, 0x2a, 0x2a];

        assert_eq!(recognizer.number_of_bytes_required(), 7);
        assert_eq!(
            recognizer.recognize(&ace_header),
            Some("File appears to be an ACE compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn arj_recognizer_identifies_valid_header() {
        let recognizer = ArjRecognizer;
        let arj_header = [0x60, 0xea];

        assert_eq!(recognizer.number_of_bytes_required(), 2);
        assert_eq!(
            recognizer.recognize(&arj_header),
            Some("File appears to be an ARJ compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn arj_recognizer_rejects_insufficient_bytes() {
        let recognizer = ArjRecognizer;
        let short_buffer = [0x60];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn arj_recognizer_rejects_mismatched_magic() {
        let recognizer = ArjRecognizer;
        let wrong_magic = [0x60, 0xeb];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn arj_recognizer_works_with_extra_data() {
        let recognizer = ArjRecognizer;
        let arj_header_with_data = [0x60, 0xea, 0xff, 0xfe, 0xfd];

        assert_eq!(
            recognizer.recognize(&arj_header_with_data),
            Some("File appears to be an ARJ compressed file".to_string())
        );
    }

    #[test]
    fn arj_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(ArjRecognizer);
        let arj_header = [0x60, 0xea];

        assert_eq!(recognizer.number_of_bytes_required(), 2);
        assert_eq!(
            recognizer.recognize(&arj_header),
            Some("File appears to be an ARJ compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn bzip2_recognizer_identifies_valid_header() {
        let recognizer = Bzip2Recognizer;
        let bzip2_header = [0x42, 0x5a, 0x68];

        assert_eq!(recognizer.number_of_bytes_required(), 3);
        assert_eq!(
            recognizer.recognize(&bzip2_header),
            Some("File appears to be a BZIP2 compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn bzip2_recognizer_rejects_insufficient_bytes() {
        let recognizer = Bzip2Recognizer;
        let short_buffer = [0x42, 0x5a];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn bzip2_recognizer_rejects_mismatched_magic() {
        let recognizer = Bzip2Recognizer;
        let wrong_magic = [0x42, 0x5a, 0x69];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn bzip2_recognizer_works_with_extra_data() {
        let recognizer = Bzip2Recognizer;
        let bzip2_header_with_data = [0x42, 0x5a, 0x68, 0xff, 0xfe, 0xfd];

        assert_eq!(
            recognizer.recognize(&bzip2_header_with_data),
            Some("File appears to be a BZIP2 compressed file".to_string())
        );
    }

    #[test]
    fn bzip2_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(Bzip2Recognizer);
        let bzip2_header = [0x42, 0x5a, 0x68];

        assert_eq!(recognizer.number_of_bytes_required(), 3);
        assert_eq!(
            recognizer.recognize(&bzip2_header),
            Some("File appears to be a BZIP2 compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn chm_recognizer_identifies_valid_header() {
        let recognizer = ChmRecognizer;
        let chm_header = [0x49, 0x54, 0x53, 0x46];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&chm_header),
            Some("File appears to be a Microsoft Compiled HTML (CHM) file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn chm_recognizer_rejects_insufficient_bytes() {
        let recognizer = ChmRecognizer;
        let short_buffer = [0x49, 0x54, 0x53];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn chm_recognizer_rejects_mismatched_magic() {
        let recognizer = ChmRecognizer;
        let wrong_magic = [0x49, 0x54, 0x53, 0x46];

        // Change the last byte to invalidate the magic
        let mut modified = wrong_magic;
        modified[3] = 0x47;

        assert_eq!(recognizer.recognize(&modified), None);
    }

    #[test]
    fn chm_recognizer_works_with_extra_data() {
        let recognizer = ChmRecognizer;
        let chm_header_with_data = [0x49, 0x54, 0x53, 0x46, 0xff, 0xfe, 0xfd];

        assert_eq!(
            recognizer.recognize(&chm_header_with_data),
            Some("File appears to be a Microsoft Compiled HTML (CHM) file".to_string())
        );
    }

    #[test]
    fn chm_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(ChmRecognizer);
        let chm_header = [0x49, 0x54, 0x53, 0x46];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&chm_header),
            Some("File appears to be a Microsoft Compiled HTML (CHM) file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }
}
