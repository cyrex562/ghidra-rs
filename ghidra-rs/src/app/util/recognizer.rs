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

/// Recognizes CABARC compressed files by their magic header bytes: `MSCF`.
///
/// Port of `ghidra.app.util.recognizer.CabarcRecognizer`.
pub struct CabarcRecognizer;

impl Recognizer for CabarcRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        4
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x4d && bytes[1] == 0x53 && bytes[2] == 0x43 && bytes[3] == 0x46 {
                return Some("File appears to be a CABARC compressed file".to_string());
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

/// Recognizes Compressia compressed files by their magic header bytes: `CMP0CMP1`.
///
/// Port of `ghidra.app.util.recognizer.CompressiaRecognizer`.
pub struct CompressiaRecognizer;

impl Recognizer for CompressiaRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        8
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x43
                && bytes[1] == 0x4d
                && bytes[2] == 0x50
                && bytes[3] == 0x30
                && bytes[4] == 0x43
                && bytes[5] == 0x4d
                && bytes[6] == 0x50
                && bytes[7] == 0x31
            {
                return Some("File appears to be a Compressia compressed file".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes cpio archive files by their magic header bytes.
///
/// Recognizes both standard cpio (newc format: `070707`, `070701`, `070702`) and
/// byte-swapped cpio format (`0143561`).
///
/// Port of `ghidra.app.util.recognizer.CpioRecognizer`.
pub struct CpioRecognizer;

impl Recognizer for CpioRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        7
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x30
                && bytes[1] == 0x37
                && bytes[2] == 0x30
                && bytes[3] == 0x37
                && bytes[4] == 0x30
                && (bytes[5] == 0x37 || bytes[5] == 0x31 || bytes[5] == 0x32)
            {
                return Some("File appears to be a cpio archive file".to_string());
            }
            if bytes[0] == 0x30
                && bytes[1] == 0x31
                && bytes[2] == 0x34
                && bytes[3] == 0x33
                && bytes[4] == 0x35
                && bytes[5] == 0x36
                && bytes[6] == 0x31
            {
                return Some("File appears to be a byte-swapped cpio archive file".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes CramFS filesystem image files by their magic header bytes: `0x45 0x3d 0xcd 0x28`.
///
/// Port of `ghidra.app.util.recognizer.CramFSRecognizer`.
pub struct CramFSRecognizer;

impl Recognizer for CramFSRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        4
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x45 && bytes[1] == 0x3d && bytes[2] == 0xcd && bytes[3] == 0x28 {
                return Some("File appears to be a CramFS image file".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes Debian package files by their magic header bytes: `!` followed by newline and `debian`.
///
/// The magic bytes are: `0x21 0x0a 0x64 0x65 0x62 0x69 0x61 0x6e` (which is "!\n" + "debian").
///
/// Port of `ghidra.app.util.recognizer.DebRecognizer`.
pub struct DebRecognizer;

impl Recognizer for DebRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        8
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x21
                && bytes[1] == 0x0a
                && bytes[2] == 0x64
                && bytes[3] == 0x65
                && bytes[4] == 0x62
                && bytes[5] == 0x69
                && bytes[6] == 0x61
                && bytes[7] == 0x6e
            {
                return Some("File appears to be a Debian package file".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes Apple Disk Image (DMG) files by their magic header bytes: `GMI2`.
///
/// The magic bytes are: `0x47 0x4d 0x49 0x32` (which is "GMI2").
///
/// Port of `ghidra.app.util.recognizer.DmgRecognizer`.
pub struct DmgRecognizer;

impl Recognizer for DmgRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        4
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x47 && bytes[1] == 0x4d && bytes[2] == 0x49 && bytes[3] == 0x32 {
                return Some("File appears to be an Apple Disk Image file".to_string());
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
    fn cabarc_recognizer_identifies_valid_header() {
        let recognizer = CabarcRecognizer;
        let cabarc_header = [0x4d, 0x53, 0x43, 0x46];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&cabarc_header),
            Some("File appears to be a CABARC compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn cabarc_recognizer_rejects_insufficient_bytes() {
        let recognizer = CabarcRecognizer;
        let short_buffer = [0x4d, 0x53, 0x43];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn cabarc_recognizer_rejects_mismatched_magic() {
        let recognizer = CabarcRecognizer;
        let wrong_magic = [0x4d, 0x53, 0x43, 0x47];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn cabarc_recognizer_works_with_extra_data() {
        let recognizer = CabarcRecognizer;
        let cabarc_header_with_data = [0x4d, 0x53, 0x43, 0x46, 0xff, 0xfe, 0xfd];

        assert_eq!(
            recognizer.recognize(&cabarc_header_with_data),
            Some("File appears to be a CABARC compressed file".to_string())
        );
    }

    #[test]
    fn cabarc_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(CabarcRecognizer);
        let cabarc_header = [0x4d, 0x53, 0x43, 0x46];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&cabarc_header),
            Some("File appears to be a CABARC compressed file".to_string())
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

    #[test]
    fn compressia_recognizer_identifies_valid_header() {
        let recognizer = CompressiaRecognizer;
        let compressia_header = [0x43, 0x4d, 0x50, 0x30, 0x43, 0x4d, 0x50, 0x31];

        assert_eq!(recognizer.number_of_bytes_required(), 8);
        assert_eq!(
            recognizer.recognize(&compressia_header),
            Some("File appears to be a Compressia compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn compressia_recognizer_rejects_insufficient_bytes() {
        let recognizer = CompressiaRecognizer;
        let short_buffer = [0x43, 0x4d, 0x50, 0x30, 0x43, 0x4d, 0x50];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn compressia_recognizer_rejects_mismatched_magic() {
        let recognizer = CompressiaRecognizer;
        let wrong_magic = [0x43, 0x4d, 0x50, 0x30, 0x43, 0x4d, 0x50, 0x32];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn compressia_recognizer_works_with_extra_data() {
        let recognizer = CompressiaRecognizer;
        let compressia_header_with_data =
            [0x43, 0x4d, 0x50, 0x30, 0x43, 0x4d, 0x50, 0x31, 0xff, 0xfe, 0xfd];

        assert_eq!(
            recognizer.recognize(&compressia_header_with_data),
            Some("File appears to be a Compressia compressed file".to_string())
        );
    }

    #[test]
    fn compressia_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(CompressiaRecognizer);
        let compressia_header = [0x43, 0x4d, 0x50, 0x30, 0x43, 0x4d, 0x50, 0x31];

        assert_eq!(recognizer.number_of_bytes_required(), 8);
        assert_eq!(
            recognizer.recognize(&compressia_header),
            Some("File appears to be a Compressia compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn cpio_recognizer_identifies_standard_format_070707() {
        let recognizer = CpioRecognizer;
        let cpio_header = [0x30, 0x37, 0x30, 0x37, 0x30, 0x37, 0x00];

        assert_eq!(recognizer.number_of_bytes_required(), 7);
        assert_eq!(
            recognizer.recognize(&cpio_header),
            Some("File appears to be a cpio archive file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn cpio_recognizer_identifies_standard_format_070701() {
        let recognizer = CpioRecognizer;
        let cpio_header = [0x30, 0x37, 0x30, 0x37, 0x30, 0x31, 0x00];

        assert_eq!(
            recognizer.recognize(&cpio_header),
            Some("File appears to be a cpio archive file".to_string())
        );
    }

    #[test]
    fn cpio_recognizer_identifies_standard_format_070702() {
        let recognizer = CpioRecognizer;
        let cpio_header = [0x30, 0x37, 0x30, 0x37, 0x30, 0x32, 0x00];

        assert_eq!(
            recognizer.recognize(&cpio_header),
            Some("File appears to be a cpio archive file".to_string())
        );
    }

    #[test]
    fn cpio_recognizer_identifies_byte_swapped_format() {
        let recognizer = CpioRecognizer;
        let byte_swapped_header = [0x30, 0x31, 0x34, 0x33, 0x35, 0x36, 0x31];

        assert_eq!(
            recognizer.recognize(&byte_swapped_header),
            Some("File appears to be a byte-swapped cpio archive file".to_string())
        );
    }

    #[test]
    fn cpio_recognizer_rejects_insufficient_bytes() {
        let recognizer = CpioRecognizer;
        let short_buffer = [0x30, 0x37, 0x30, 0x37, 0x30];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn cpio_recognizer_rejects_invalid_prefix() {
        let recognizer = CpioRecognizer;
        let wrong_magic = [0x31, 0x37, 0x30, 0x37, 0x30, 0x37, 0x00];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn cpio_recognizer_rejects_invalid_sixth_byte() {
        let recognizer = CpioRecognizer;
        let invalid_sixth = [0x30, 0x37, 0x30, 0x37, 0x30, 0x38, 0x00];

        assert_eq!(recognizer.recognize(&invalid_sixth), None);
    }

    #[test]
    fn cpio_recognizer_works_with_extra_data_standard_format() {
        let recognizer = CpioRecognizer;
        let cpio_with_data = [
            0x30, 0x37, 0x30, 0x37, 0x30, 0x37, 0x00, 0xff, 0xfe, 0xfd, 0xfc,
        ];

        assert_eq!(
            recognizer.recognize(&cpio_with_data),
            Some("File appears to be a cpio archive file".to_string())
        );
    }

    #[test]
    fn cpio_recognizer_works_with_extra_data_byte_swapped() {
        let recognizer = CpioRecognizer;
        let byte_swapped_with_data = [0x30, 0x31, 0x34, 0x33, 0x35, 0x36, 0x31, 0xff, 0xfe];

        assert_eq!(
            recognizer.recognize(&byte_swapped_with_data),
            Some("File appears to be a byte-swapped cpio archive file".to_string())
        );
    }

    #[test]
    fn cpio_recognizer_via_trait_object_standard_format() {
        let recognizer: Box<dyn Recognizer> = Box::new(CpioRecognizer);
        let cpio_header = [0x30, 0x37, 0x30, 0x37, 0x30, 0x37, 0x00];

        assert_eq!(recognizer.number_of_bytes_required(), 7);
        assert_eq!(
            recognizer.recognize(&cpio_header),
            Some("File appears to be a cpio archive file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn cpio_recognizer_via_trait_object_byte_swapped() {
        let recognizer: Box<dyn Recognizer> = Box::new(CpioRecognizer);
        let byte_swapped = [0x30, 0x31, 0x34, 0x33, 0x35, 0x36, 0x31];

        assert_eq!(recognizer.number_of_bytes_required(), 7);
        assert_eq!(
            recognizer.recognize(&byte_swapped),
            Some("File appears to be a byte-swapped cpio archive file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn cramfs_recognizer_identifies_valid_header() {
        let recognizer = CramFSRecognizer;
        let cramfs_header = [0x45, 0x3d, 0xcd, 0x28];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&cramfs_header),
            Some("File appears to be a CramFS image file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn cramfs_recognizer_rejects_insufficient_bytes() {
        let recognizer = CramFSRecognizer;
        let short_buffer = [0x45, 0x3d, 0xcd];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn cramfs_recognizer_rejects_mismatched_magic() {
        let recognizer = CramFSRecognizer;
        let wrong_magic = [0x45, 0x3d, 0xcd, 0x29];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn cramfs_recognizer_rejects_first_byte_mismatch() {
        let recognizer = CramFSRecognizer;
        let wrong_first = [0x46, 0x3d, 0xcd, 0x28];

        assert_eq!(recognizer.recognize(&wrong_first), None);
    }

    #[test]
    fn cramfs_recognizer_rejects_second_byte_mismatch() {
        let recognizer = CramFSRecognizer;
        let wrong_second = [0x45, 0x3e, 0xcd, 0x28];

        assert_eq!(recognizer.recognize(&wrong_second), None);
    }

    #[test]
    fn cramfs_recognizer_rejects_third_byte_mismatch() {
        let recognizer = CramFSRecognizer;
        let wrong_third = [0x45, 0x3d, 0xce, 0x28];

        assert_eq!(recognizer.recognize(&wrong_third), None);
    }

    #[test]
    fn cramfs_recognizer_works_with_extra_data() {
        let recognizer = CramFSRecognizer;
        let cramfs_with_data = [0x45, 0x3d, 0xcd, 0x28, 0xff, 0xfe, 0xfd, 0xfc];

        assert_eq!(
            recognizer.recognize(&cramfs_with_data),
            Some("File appears to be a CramFS image file".to_string())
        );
    }

    #[test]
    fn cramfs_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(CramFSRecognizer);
        let cramfs_header = [0x45, 0x3d, 0xcd, 0x28];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&cramfs_header),
            Some("File appears to be a CramFS image file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn deb_recognizer_identifies_valid_header() {
        let recognizer = DebRecognizer;
        let deb_header = [0x21, 0x0a, 0x64, 0x65, 0x62, 0x69, 0x61, 0x6e];

        assert_eq!(recognizer.number_of_bytes_required(), 8);
        assert_eq!(
            recognizer.recognize(&deb_header),
            Some("File appears to be a Debian package file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn deb_recognizer_rejects_insufficient_bytes() {
        let recognizer = DebRecognizer;
        let short_buffer = [0x21, 0x0a, 0x64, 0x65, 0x62, 0x69, 0x61];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn deb_recognizer_rejects_mismatched_magic() {
        let recognizer = DebRecognizer;
        let wrong_magic = [0x21, 0x0a, 0x64, 0x65, 0x62, 0x69, 0x61, 0x6f];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn deb_recognizer_rejects_first_byte_mismatch() {
        let recognizer = DebRecognizer;
        let wrong_first = [0x22, 0x0a, 0x64, 0x65, 0x62, 0x69, 0x61, 0x6e];

        assert_eq!(recognizer.recognize(&wrong_first), None);
    }

    #[test]
    fn deb_recognizer_rejects_second_byte_mismatch() {
        let recognizer = DebRecognizer;
        let wrong_second = [0x21, 0x0b, 0x64, 0x65, 0x62, 0x69, 0x61, 0x6e];

        assert_eq!(recognizer.recognize(&wrong_second), None);
    }

    #[test]
    fn deb_recognizer_works_with_extra_data() {
        let recognizer = DebRecognizer;
        let deb_with_data = [0x21, 0x0a, 0x64, 0x65, 0x62, 0x69, 0x61, 0x6e, 0xff, 0xfe, 0xfd];

        assert_eq!(
            recognizer.recognize(&deb_with_data),
            Some("File appears to be a Debian package file".to_string())
        );
    }

    #[test]
    fn deb_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(DebRecognizer);
        let deb_header = [0x21, 0x0a, 0x64, 0x65, 0x62, 0x69, 0x61, 0x6e];

        assert_eq!(recognizer.number_of_bytes_required(), 8);
        assert_eq!(
            recognizer.recognize(&deb_header),
            Some("File appears to be a Debian package file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn dmg_recognizer_identifies_valid_header() {
        let recognizer = DmgRecognizer;
        let dmg_header = [0x47, 0x4d, 0x49, 0x32];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&dmg_header),
            Some("File appears to be an Apple Disk Image file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn dmg_recognizer_rejects_insufficient_bytes() {
        let recognizer = DmgRecognizer;
        let short_buffer = [0x47, 0x4d, 0x49];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn dmg_recognizer_rejects_mismatched_magic() {
        let recognizer = DmgRecognizer;
        let wrong_magic = [0x47, 0x4d, 0x49, 0x33];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn dmg_recognizer_rejects_first_byte_mismatch() {
        let recognizer = DmgRecognizer;
        let wrong_first = [0x48, 0x4d, 0x49, 0x32];

        assert_eq!(recognizer.recognize(&wrong_first), None);
    }

    #[test]
    fn dmg_recognizer_rejects_second_byte_mismatch() {
        let recognizer = DmgRecognizer;
        let wrong_second = [0x47, 0x4e, 0x49, 0x32];

        assert_eq!(recognizer.recognize(&wrong_second), None);
    }

    #[test]
    fn dmg_recognizer_rejects_third_byte_mismatch() {
        let recognizer = DmgRecognizer;
        let wrong_third = [0x47, 0x4d, 0x4a, 0x32];

        assert_eq!(recognizer.recognize(&wrong_third), None);
    }

    #[test]
    fn dmg_recognizer_works_with_extra_data() {
        let recognizer = DmgRecognizer;
        let dmg_with_data = [0x47, 0x4d, 0x49, 0x32, 0xff, 0xfe, 0xfd, 0xfc];

        assert_eq!(
            recognizer.recognize(&dmg_with_data),
            Some("File appears to be an Apple Disk Image file".to_string())
        );
    }

    #[test]
    fn dmg_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(DmgRecognizer);
        let dmg_header = [0x47, 0x4d, 0x49, 0x32];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&dmg_header),
            Some("File appears to be an Apple Disk Image file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }
}
