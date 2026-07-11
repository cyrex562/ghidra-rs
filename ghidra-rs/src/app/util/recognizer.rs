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

/// Recognizes empty PKZIP compressed files by their magic header bytes: `PK\x05\x06`.
///
/// The magic bytes are: `0x50 0x4b 0x05 0x06` (which is "PK" followed by ETX and ACK control chars).
///
/// Port of `ghidra.app.util.recognizer.EmptyPkzipRecognizer`.
pub struct EmptyPkzipRecognizer;

impl Recognizer for EmptyPkzipRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        4
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x50 && bytes[1] == 0x4b && bytes[2] == 0x05 && bytes[3] == 0x06 {
                return Some("File appears to be an empty PKZIP compressed file".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes Freeze compressed files by their magic header bytes: `0x1f 0x9e`.
///
/// Port of `ghidra.app.util.recognizer.FreezeRecognizer`.
pub struct FreezeRecognizer;

impl Recognizer for FreezeRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        2
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x1f && bytes[1] == 0x9e {
                return Some("File appears to be a Freeze compressed file".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes GZIP compressed files by their magic header bytes: `0x1f 0x8b`.
///
/// Port of `ghidra.app.util.recognizer.GzipRecognizer`.
pub struct GzipRecognizer;

impl Recognizer for GzipRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        2
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x1f && bytes[1] == 0x8b {
                return Some("File appears to be a GZIP compressed file".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes ISO 9660 CD images by their volume descriptor signature "CD01" at specific offsets.
///
/// ISO 9660 is the standard file system used on CD-ROMs. This recognizer checks for the
/// volume descriptor signature at three possible offsets: 32769, 34817, and 36865 bytes.
///
/// Port of `ghidra.app.util.recognizer.ISO9660Recognizer`.
pub struct Iso9660Recognizer;

impl Recognizer for Iso9660Recognizer {
    fn number_of_bytes_required(&self) -> usize {
        36870
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= 32774 {
            if bytes[32769] == 0x43
                && bytes[32770] == 0x44
                && bytes[32771] == 0x30
                && bytes[32772] == 0x30
                && bytes[32773] == 0x31
            {
                return Some("File appears to be an ISO9660 (CD) image".to_string());
            }
        }
        if bytes.len() >= 34822 {
            if bytes[34817] == 0x43
                && bytes[34818] == 0x44
                && bytes[34819] == 0x30
                && bytes[34820] == 0x30
                && bytes[34821] == 0x31
            {
                return Some("File appears to be an ISO9660 (CD) image".to_string());
            }
        }
        if bytes.len() >= 36870 {
            if bytes[36865] == 0x43
                && bytes[36866] == 0x44
                && bytes[36867] == 0x30
                && bytes[36868] == 0x30
                && bytes[36869] == 0x31
            {
                return Some("File appears to be an ISO9660 (CD) image".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes IMP compressed files by their magic header bytes: `0x49 0x4d 0x50 0x0a`.
///
/// The magic bytes are: `0x49 0x4d 0x50 0x0a` (which is "IMP" followed by a newline).
///
/// Port of `ghidra.app.util.recognizer.ImpRecognizer`.
pub struct ImpRecognizer;

impl Recognizer for ImpRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        4
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x49 && bytes[1] == 0x4d && bytes[2] == 0x50 && bytes[3] == 0x0a {
                return Some("File appears to be an IMP compressed file".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes JAR compressed files by their magic header bytes: `0x50 0x4b 0x03 0x04`.
///
/// Port of `ghidra.app.util.recognizer.JarRecognizer`.
pub struct JarRecognizer;

impl Recognizer for JarRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        4
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x50
                && bytes[1] == 0x4b
                && bytes[2] == 0x03
                && bytes[3] == 0x04
            {
                return Some("File appears to be a JAR compressed file".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes LHA/LHARC compressed files by their magic header bytes: `0x2d 0x6c 0x68` ("-lh").
///
/// LHA files have the signature starting at offset 2 with the bytes "-lh" (0x2d 0x6c 0x68).
///
/// Port of `ghidra.app.util.recognizer.LhaRecognizer`.
pub struct LhaRecognizer;

impl Recognizer for LhaRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        5
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[2] == 0x2d && bytes[3] == 0x6c && bytes[4] == 0x68 {
                return Some("File appears to be a LHA/LHARC compressed file".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes Windows Imaging Format (WIM) files by their magic header bytes: `MSWIM\0\0`.
///
/// The magic bytes are: `0x4d 0x53 0x57 0x49 0x4d 0x00 0x00` (which is "MSWIM" followed by two null bytes).
///
/// Port of `ghidra.app.util.recognizer.MSWIMRecognizer`.
pub struct MswimRecognizer;

impl Recognizer for MswimRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        7
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x4d
                && bytes[1] == 0x53
                && bytes[2] == 0x57
                && bytes[3] == 0x49
                && bytes[4] == 0x4d
                && bytes[5] == 0x00
                && bytes[6] == 0x00
            {
                return Some("File appears to be a Windows Imaging Format (WIM) file".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes Macromedia Flash compressed files by their magic header bytes: `CWS`.
///
/// The magic bytes are: `0x43 0x57 0x53` (which is "CWS").
///
/// Port of `ghidra.app.util.recognizer.MacromediaFlashRecognizer`.
pub struct MacromediaFlashRecognizer;

impl Recognizer for MacromediaFlashRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        3
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x43 && bytes[1] == 0x57 && bytes[2] == 0x53 {
                return Some("File appears to be a Macromedia Flash compressed file".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes PAK or ARC compressed files by their magic header bytes.
///
/// Checks for byte 0x1a (0x1a) followed by a byte with upper nibble 0x0 (i.e., second byte & 0xf0 == 0x00).
///
/// Port of `ghidra.app.util.recognizer.PakArcRecognizer`.
pub struct PakArcRecognizer;

impl Recognizer for PakArcRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        2
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x1a && (bytes[1] & 0xf0) == 0x00 {
                return Some("File appears to be a PAK or ARC compressed file".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes PPMD compressed files by their magic header bytes: `0x8f 0xaf 0xac 0x8c`.
///
/// Port of `ghidra.app.util.recognizer.PpmdRecognizer`.
pub struct PpmdRecognizer;

impl Recognizer for PpmdRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        4
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x8f && bytes[1] == 0xaf && bytes[2] == 0xac && bytes[3] == 0x8c {
                return Some("File appears to be a PPMD compressed file".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes PKZIP, WINZIP, or JAR compressed files by their magic header bytes:
/// `0x50 0x4b 0x03 0x04`.
///
/// Port of `ghidra.app.util.recognizer.PkzipRecognizer`.
pub struct PkzipRecognizer;

impl Recognizer for PkzipRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        4
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x50
                && bytes[1] == 0x4b
                && bytes[2] == 0x03
                && bytes[3] == 0x04
            {
                return Some("File appears to be a PKZIP, WINZIP, or JAR compressed file".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes RPM package files by their magic header bytes: `0xed 0xab 0xee 0xdb`.
///
/// Port of `ghidra.app.util.recognizer.RPMRecognizer`.
pub struct RpmRecognizer;

impl Recognizer for RpmRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        4
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0xed && bytes[1] == 0xab && bytes[2] == 0xee && bytes[3] == 0xdb {
                return Some("File appears to be an RPM package".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes RAR compressed files by their magic header bytes: `Rar!` (0x52 0x61 0x72 0x21).
///
/// Port of `ghidra.app.util.recognizer.RarRecognizer`.
pub struct RarRecognizer;

impl Recognizer for RarRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        4
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x52 && bytes[1] == 0x61 && bytes[2] == 0x72 && bytes[3] == 0x21 {
                return Some("File appears to be a RAR compressed file".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes SBC compressed files by their magic header bytes: `0x53 0x42 0x43 0x1c`.
///
/// Port of `ghidra.app.util.recognizer.SbcRecognizer`.
pub struct SbcRecognizer;

impl Recognizer for SbcRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        4
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x53 && bytes[1] == 0x42 && bytes[2] == 0x43 && bytes[3] == 0x1c {
                return Some("File appears to be a SBC compressed file".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes SBX compressed files by their magic header bytes: `0x53 0x42 0x31 0x00`.
///
/// Port of `ghidra.app.util.recognizer.SbxRecognizer`.
pub struct SbxRecognizer;

impl Recognizer for SbxRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        4
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x53 && bytes[1] == 0x42 && bytes[2] == 0x31 && bytes[3] == 0x00 {
                return Some("File appears to be an SBX compressed file".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes 7-ZIP compressed files by their magic header bytes: `0x37 0x7a 0xbc 0xaf 0x27 0x1c`.
///
/// Port of `ghidra.app.util.recognizer.SevenZipRecognizer`.
pub struct SevenZipRecognizer;

impl Recognizer for SevenZipRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        6
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x37
                && bytes[1] == 0x7a
                && bytes[2] == 0xbc
                && bytes[3] == 0xaf
                && bytes[4] == 0x27
                && bytes[5] == 0x1c
            {
                return Some("File appears to be a 7-ZIP compressed file".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes spanned PKZIP compressed files by their magic header bytes: `0x50 0x4b 0x07 0x08`.
///
/// Port of `ghidra.app.util.recognizer.SpannedPkzipRecognizer`.
pub struct SpannedPkzipRecognizer;

impl Recognizer for SpannedPkzipRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        4
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x50 && bytes[1] == 0x4b && bytes[2] == 0x07 && bytes[3] == 0x08 {
                return Some("File appears to be a spanned PKZIP compressed file".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes SQZ compressed files by their magic header bytes: `HLSQZ1`.
///
/// Port of `ghidra.app.util.recognizer.SqzRecognizer`.
pub struct SqzRecognizer;

impl Recognizer for SqzRecognizer {
    fn number_of_bytes_required(&self) -> usize {
        6
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x48
                && bytes[1] == 0x4c
                && bytes[2] == 0x53
                && bytes[3] == 0x51
                && bytes[4] == 0x5a
                && bytes[5] == 0x31
            {
                return Some("File appears to be a SQZ compressed file".to_string());
            }
        }
        None
    }

    fn get_priority(&self) -> i32 {
        100
    }
}

/// Recognizes Stuffit1 compressed files by their magic header bytes: `SIT!`.
///
/// Recognizes Stuffit versions up to v4.0. The magic bytes are: `0x53 0x49 0x54 0x21`
/// (which is "SIT!").
///
/// Port of `ghidra.app.util.recognizer.StuffIt1Recognizer`.
pub struct StuffIt1Recognizer;

impl Recognizer for StuffIt1Recognizer {
    fn number_of_bytes_required(&self) -> usize {
        4
    }

    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.number_of_bytes_required() {
            if bytes[0] == 0x53
                && bytes[1] == 0x49
                && bytes[2] == 0x54
                && bytes[3] == 0x21
            {
                return Some(
                    "File appears to be a Stuffit1 (Stuffit versions up to v4.0) compressed file"
                        .to_string(),
                );
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
    struct MockGzipRecognizer;

    impl Recognizer for MockGzipRecognizer {
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
        let recognizer: Box<dyn Recognizer> = Box::new(MockGzipRecognizer);

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

    #[test]
    fn empty_pkzip_recognizer_identifies_valid_header() {
        let recognizer = EmptyPkzipRecognizer;
        let empty_pkzip_header = [0x50, 0x4b, 0x05, 0x06];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&empty_pkzip_header),
            Some("File appears to be an empty PKZIP compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn empty_pkzip_recognizer_rejects_insufficient_bytes() {
        let recognizer = EmptyPkzipRecognizer;
        let short_buffer = [0x50, 0x4b, 0x05];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn empty_pkzip_recognizer_rejects_mismatched_magic() {
        let recognizer = EmptyPkzipRecognizer;
        let wrong_magic = [0x50, 0x4b, 0x05, 0x07];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn empty_pkzip_recognizer_rejects_first_byte_mismatch() {
        let recognizer = EmptyPkzipRecognizer;
        let wrong_first = [0x51, 0x4b, 0x05, 0x06];

        assert_eq!(recognizer.recognize(&wrong_first), None);
    }

    #[test]
    fn empty_pkzip_recognizer_rejects_second_byte_mismatch() {
        let recognizer = EmptyPkzipRecognizer;
        let wrong_second = [0x50, 0x4c, 0x05, 0x06];

        assert_eq!(recognizer.recognize(&wrong_second), None);
    }

    #[test]
    fn empty_pkzip_recognizer_rejects_third_byte_mismatch() {
        let recognizer = EmptyPkzipRecognizer;
        let wrong_third = [0x50, 0x4b, 0x04, 0x06];

        assert_eq!(recognizer.recognize(&wrong_third), None);
    }

    #[test]
    fn empty_pkzip_recognizer_works_with_extra_data() {
        let recognizer = EmptyPkzipRecognizer;
        let empty_pkzip_with_data = [0x50, 0x4b, 0x05, 0x06, 0xff, 0xfe, 0xfd, 0xfc];

        assert_eq!(
            recognizer.recognize(&empty_pkzip_with_data),
            Some("File appears to be an empty PKZIP compressed file".to_string())
        );
    }

    #[test]
    fn empty_pkzip_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(EmptyPkzipRecognizer);
        let empty_pkzip_header = [0x50, 0x4b, 0x05, 0x06];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&empty_pkzip_header),
            Some("File appears to be an empty PKZIP compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn freeze_recognizer_identifies_valid_header() {
        let recognizer = FreezeRecognizer;
        let freeze_header = [0x1f, 0x9e];

        assert_eq!(recognizer.number_of_bytes_required(), 2);
        assert_eq!(
            recognizer.recognize(&freeze_header),
            Some("File appears to be a Freeze compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn freeze_recognizer_rejects_insufficient_bytes() {
        let recognizer = FreezeRecognizer;
        let short_buffer = [0x1f];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn freeze_recognizer_rejects_mismatched_magic() {
        let recognizer = FreezeRecognizer;
        let wrong_magic = [0x1f, 0x9f];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn freeze_recognizer_rejects_first_byte_mismatch() {
        let recognizer = FreezeRecognizer;
        let wrong_first = [0x1e, 0x9e];

        assert_eq!(recognizer.recognize(&wrong_first), None);
    }

    #[test]
    fn freeze_recognizer_rejects_second_byte_mismatch() {
        let recognizer = FreezeRecognizer;
        let wrong_second = [0x1f, 0x9d];

        assert_eq!(recognizer.recognize(&wrong_second), None);
    }

    #[test]
    fn freeze_recognizer_works_with_extra_data() {
        let recognizer = FreezeRecognizer;
        let freeze_with_data = [0x1f, 0x9e, 0xff, 0xfe, 0xfd];

        assert_eq!(
            recognizer.recognize(&freeze_with_data),
            Some("File appears to be a Freeze compressed file".to_string())
        );
    }

    #[test]
    fn freeze_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(FreezeRecognizer);
        let freeze_header = [0x1f, 0x9e];

        assert_eq!(recognizer.number_of_bytes_required(), 2);
        assert_eq!(
            recognizer.recognize(&freeze_header),
            Some("File appears to be a Freeze compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn gzip_recognizer_identifies_valid_header() {
        let recognizer = GzipRecognizer;
        let gzip_header = [0x1f, 0x8b];

        assert_eq!(recognizer.number_of_bytes_required(), 2);
        assert_eq!(
            recognizer.recognize(&gzip_header),
            Some("File appears to be a GZIP compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn gzip_recognizer_rejects_insufficient_bytes() {
        let recognizer = GzipRecognizer;
        let short_buffer = [0x1f];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn gzip_recognizer_rejects_mismatched_magic() {
        let recognizer = GzipRecognizer;
        let wrong_magic = [0x1f, 0x9e];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn gzip_recognizer_works_with_extra_data() {
        let recognizer = GzipRecognizer;
        let gzip_header_with_data = [0x1f, 0x8b, 0xff, 0xfe, 0xfd];

        assert_eq!(
            recognizer.recognize(&gzip_header_with_data),
            Some("File appears to be a GZIP compressed file".to_string())
        );
    }

    #[test]
    fn gzip_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(GzipRecognizer);
        let gzip_header = [0x1f, 0x8b];

        assert_eq!(recognizer.number_of_bytes_required(), 2);
        assert_eq!(
            recognizer.recognize(&gzip_header),
            Some("File appears to be a GZIP compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn iso9660_recognizer_identifies_valid_header_at_first_offset() {
        let recognizer = Iso9660Recognizer;
        let mut buffer = vec![0u8; 32774];
        buffer[32769] = 0x43;
        buffer[32770] = 0x44;
        buffer[32771] = 0x30;
        buffer[32772] = 0x30;
        buffer[32773] = 0x31;

        assert_eq!(recognizer.number_of_bytes_required(), 36870);
        assert_eq!(
            recognizer.recognize(&buffer),
            Some("File appears to be an ISO9660 (CD) image".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn iso9660_recognizer_identifies_valid_header_at_second_offset() {
        let recognizer = Iso9660Recognizer;
        let mut buffer = vec![0u8; 34822];
        buffer[34817] = 0x43;
        buffer[34818] = 0x44;
        buffer[34819] = 0x30;
        buffer[34820] = 0x30;
        buffer[34821] = 0x31;

        assert_eq!(
            recognizer.recognize(&buffer),
            Some("File appears to be an ISO9660 (CD) image".to_string())
        );
    }

    #[test]
    fn iso9660_recognizer_identifies_valid_header_at_third_offset() {
        let recognizer = Iso9660Recognizer;
        let mut buffer = vec![0u8; 36870];
        buffer[36865] = 0x43;
        buffer[36866] = 0x44;
        buffer[36867] = 0x30;
        buffer[36868] = 0x30;
        buffer[36869] = 0x31;

        assert_eq!(
            recognizer.recognize(&buffer),
            Some("File appears to be an ISO9660 (CD) image".to_string())
        );
    }

    #[test]
    fn iso9660_recognizer_rejects_insufficient_bytes_for_first_offset() {
        let recognizer = Iso9660Recognizer;
        let short_buffer = vec![0u8; 32773];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn iso9660_recognizer_rejects_mismatched_magic_at_first_offset() {
        let recognizer = Iso9660Recognizer;
        let mut buffer = vec![0u8; 32774];
        buffer[32769] = 0x42;
        buffer[32770] = 0x44;
        buffer[32771] = 0x30;
        buffer[32772] = 0x30;
        buffer[32773] = 0x31;

        assert_eq!(recognizer.recognize(&buffer), None);
    }

    #[test]
    fn iso9660_recognizer_works_with_extra_data() {
        let recognizer = Iso9660Recognizer;
        let mut buffer = vec![0xffu8; 36870];
        buffer[36865] = 0x43;
        buffer[36866] = 0x44;
        buffer[36867] = 0x30;
        buffer[36868] = 0x30;
        buffer[36869] = 0x31;

        assert_eq!(
            recognizer.recognize(&buffer),
            Some("File appears to be an ISO9660 (CD) image".to_string())
        );
    }

    #[test]
    fn iso9660_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(Iso9660Recognizer);
        let mut buffer = vec![0u8; 36870];
        buffer[36865] = 0x43;
        buffer[36866] = 0x44;
        buffer[36867] = 0x30;
        buffer[36868] = 0x30;
        buffer[36869] = 0x31;

        assert_eq!(recognizer.number_of_bytes_required(), 36870);
        assert_eq!(
            recognizer.recognize(&buffer),
            Some("File appears to be an ISO9660 (CD) image".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn imp_recognizer_identifies_valid_header() {
        let recognizer = ImpRecognizer;
        let imp_header = [0x49, 0x4d, 0x50, 0x0a];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&imp_header),
            Some("File appears to be an IMP compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn imp_recognizer_rejects_insufficient_bytes() {
        let recognizer = ImpRecognizer;
        let short_buffer = [0x49, 0x4d, 0x50];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn imp_recognizer_rejects_mismatched_magic() {
        let recognizer = ImpRecognizer;
        let wrong_magic = [0x49, 0x4d, 0x50, 0x0b];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn imp_recognizer_rejects_first_byte_mismatch() {
        let recognizer = ImpRecognizer;
        let wrong_first = [0x4a, 0x4d, 0x50, 0x0a];

        assert_eq!(recognizer.recognize(&wrong_first), None);
    }

    #[test]
    fn imp_recognizer_rejects_second_byte_mismatch() {
        let recognizer = ImpRecognizer;
        let wrong_second = [0x49, 0x4c, 0x50, 0x0a];

        assert_eq!(recognizer.recognize(&wrong_second), None);
    }

    #[test]
    fn imp_recognizer_rejects_third_byte_mismatch() {
        let recognizer = ImpRecognizer;
        let wrong_third = [0x49, 0x4d, 0x51, 0x0a];

        assert_eq!(recognizer.recognize(&wrong_third), None);
    }

    #[test]
    fn imp_recognizer_works_with_extra_data() {
        let recognizer = ImpRecognizer;
        let imp_header_with_data = [0x49, 0x4d, 0x50, 0x0a, 0xff, 0xfe, 0xfd];

        assert_eq!(
            recognizer.recognize(&imp_header_with_data),
            Some("File appears to be an IMP compressed file".to_string())
        );
    }

    #[test]
    fn imp_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(ImpRecognizer);
        let imp_header = [0x49, 0x4d, 0x50, 0x0a];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&imp_header),
            Some("File appears to be an IMP compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn jar_recognizer_identifies_valid_header() {
        let recognizer = JarRecognizer;
        let jar_header = [0x50, 0x4b, 0x03, 0x04];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&jar_header),
            Some("File appears to be a JAR compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn jar_recognizer_rejects_insufficient_bytes() {
        let recognizer = JarRecognizer;
        let short_buffer = [0x50, 0x4b, 0x03];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn jar_recognizer_rejects_mismatched_magic() {
        let recognizer = JarRecognizer;
        let wrong_magic = [0x50, 0x4b, 0x03, 0x05];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn jar_recognizer_rejects_first_byte_mismatch() {
        let recognizer = JarRecognizer;
        let wrong_first = [0x51, 0x4b, 0x03, 0x04];

        assert_eq!(recognizer.recognize(&wrong_first), None);
    }

    #[test]
    fn jar_recognizer_rejects_second_byte_mismatch() {
        let recognizer = JarRecognizer;
        let wrong_second = [0x50, 0x4c, 0x03, 0x04];

        assert_eq!(recognizer.recognize(&wrong_second), None);
    }

    #[test]
    fn jar_recognizer_rejects_third_byte_mismatch() {
        let recognizer = JarRecognizer;
        let wrong_third = [0x50, 0x4b, 0x02, 0x04];

        assert_eq!(recognizer.recognize(&wrong_third), None);
    }

    #[test]
    fn jar_recognizer_rejects_fourth_byte_mismatch() {
        let recognizer = JarRecognizer;
        let wrong_fourth = [0x50, 0x4b, 0x03, 0x05];

        assert_eq!(recognizer.recognize(&wrong_fourth), None);
    }

    #[test]
    fn jar_recognizer_works_with_extra_data() {
        let recognizer = JarRecognizer;
        let jar_header_with_data = [0x50, 0x4b, 0x03, 0x04, 0xff, 0xfe, 0xfd];

        assert_eq!(
            recognizer.recognize(&jar_header_with_data),
            Some("File appears to be a JAR compressed file".to_string())
        );
    }

    #[test]
    fn jar_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(JarRecognizer);
        let jar_header = [0x50, 0x4b, 0x03, 0x04];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&jar_header),
            Some("File appears to be a JAR compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn lha_recognizer_identifies_valid_header() {
        let recognizer = LhaRecognizer;
        let lha_header = [0x00, 0x00, 0x2d, 0x6c, 0x68];

        assert_eq!(recognizer.number_of_bytes_required(), 5);
        assert_eq!(
            recognizer.recognize(&lha_header),
            Some("File appears to be a LHA/LHARC compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn lha_recognizer_rejects_insufficient_bytes() {
        let recognizer = LhaRecognizer;
        let short_buffer = [0x00, 0x00, 0x2d, 0x6c];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn lha_recognizer_rejects_mismatched_magic() {
        let recognizer = LhaRecognizer;
        let wrong_magic = [0x00, 0x00, 0x2d, 0x6c, 0x69];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn lha_recognizer_rejects_third_byte_mismatch() {
        let recognizer = LhaRecognizer;
        let wrong_third = [0x00, 0x00, 0x2c, 0x6c, 0x68];

        assert_eq!(recognizer.recognize(&wrong_third), None);
    }

    #[test]
    fn lha_recognizer_rejects_fourth_byte_mismatch() {
        let recognizer = LhaRecognizer;
        let wrong_fourth = [0x00, 0x00, 0x2d, 0x6d, 0x68];

        assert_eq!(recognizer.recognize(&wrong_fourth), None);
    }

    #[test]
    fn lha_recognizer_rejects_fifth_byte_mismatch() {
        let recognizer = LhaRecognizer;
        let wrong_fifth = [0x00, 0x00, 0x2d, 0x6c, 0x69];

        assert_eq!(recognizer.recognize(&wrong_fifth), None);
    }

    #[test]
    fn lha_recognizer_works_with_extra_data() {
        let recognizer = LhaRecognizer;
        let lha_with_data = [0x00, 0x00, 0x2d, 0x6c, 0x68, 0xff, 0xfe, 0xfd, 0xfc];

        assert_eq!(
            recognizer.recognize(&lha_with_data),
            Some("File appears to be a LHA/LHARC compressed file".to_string())
        );
    }

    #[test]
    fn lha_recognizer_recognizes_common_lh0_variant() {
        let recognizer = LhaRecognizer;
        let lh0_header = [0xff, 0xff, 0x2d, 0x6c, 0x68];

        assert_eq!(
            recognizer.recognize(&lh0_header),
            Some("File appears to be a LHA/LHARC compressed file".to_string())
        );
    }

    #[test]
    fn lha_recognizer_recognizes_common_lh5_variant() {
        let recognizer = LhaRecognizer;
        let lh5_header = [0xaa, 0xbb, 0x2d, 0x6c, 0x68];

        assert_eq!(
            recognizer.recognize(&lh5_header),
            Some("File appears to be a LHA/LHARC compressed file".to_string())
        );
    }

    #[test]
    fn lha_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(LhaRecognizer);
        let lha_header = [0x00, 0x00, 0x2d, 0x6c, 0x68];

        assert_eq!(recognizer.number_of_bytes_required(), 5);
        assert_eq!(
            recognizer.recognize(&lha_header),
            Some("File appears to be a LHA/LHARC compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn mswim_recognizer_identifies_valid_header() {
        let recognizer = MswimRecognizer;
        let mswim_header = [0x4d, 0x53, 0x57, 0x49, 0x4d, 0x00, 0x00];

        assert_eq!(recognizer.number_of_bytes_required(), 7);
        assert_eq!(
            recognizer.recognize(&mswim_header),
            Some("File appears to be a Windows Imaging Format (WIM) file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn mswim_recognizer_rejects_insufficient_bytes() {
        let recognizer = MswimRecognizer;
        let short_buffer = [0x4d, 0x53, 0x57, 0x49, 0x4d, 0x00];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn mswim_recognizer_rejects_mismatched_magic() {
        let recognizer = MswimRecognizer;
        let wrong_magic = [0x4d, 0x53, 0x57, 0x49, 0x4d, 0x01, 0x00];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn mswim_recognizer_rejects_first_byte_mismatch() {
        let recognizer = MswimRecognizer;
        let wrong_first = [0x4e, 0x53, 0x57, 0x49, 0x4d, 0x00, 0x00];

        assert_eq!(recognizer.recognize(&wrong_first), None);
    }

    #[test]
    fn mswim_recognizer_rejects_second_byte_mismatch() {
        let recognizer = MswimRecognizer;
        let wrong_second = [0x4d, 0x52, 0x57, 0x49, 0x4d, 0x00, 0x00];

        assert_eq!(recognizer.recognize(&wrong_second), None);
    }

    #[test]
    fn mswim_recognizer_rejects_third_byte_mismatch() {
        let recognizer = MswimRecognizer;
        let wrong_third = [0x4d, 0x53, 0x58, 0x49, 0x4d, 0x00, 0x00];

        assert_eq!(recognizer.recognize(&wrong_third), None);
    }

    #[test]
    fn mswim_recognizer_rejects_fourth_byte_mismatch() {
        let recognizer = MswimRecognizer;
        let wrong_fourth = [0x4d, 0x53, 0x57, 0x4a, 0x4d, 0x00, 0x00];

        assert_eq!(recognizer.recognize(&wrong_fourth), None);
    }

    #[test]
    fn mswim_recognizer_rejects_fifth_byte_mismatch() {
        let recognizer = MswimRecognizer;
        let wrong_fifth = [0x4d, 0x53, 0x57, 0x49, 0x4e, 0x00, 0x00];

        assert_eq!(recognizer.recognize(&wrong_fifth), None);
    }

    #[test]
    fn mswim_recognizer_rejects_sixth_byte_mismatch() {
        let recognizer = MswimRecognizer;
        let wrong_sixth = [0x4d, 0x53, 0x57, 0x49, 0x4d, 0x01, 0x00];

        assert_eq!(recognizer.recognize(&wrong_sixth), None);
    }

    #[test]
    fn mswim_recognizer_rejects_seventh_byte_mismatch() {
        let recognizer = MswimRecognizer;
        let wrong_seventh = [0x4d, 0x53, 0x57, 0x49, 0x4d, 0x00, 0x01];

        assert_eq!(recognizer.recognize(&wrong_seventh), None);
    }

    #[test]
    fn mswim_recognizer_works_with_extra_data() {
        let recognizer = MswimRecognizer;
        let mswim_with_data = [0x4d, 0x53, 0x57, 0x49, 0x4d, 0x00, 0x00, 0xff, 0xfe, 0xfd];

        assert_eq!(
            recognizer.recognize(&mswim_with_data),
            Some("File appears to be a Windows Imaging Format (WIM) file".to_string())
        );
    }

    #[test]
    fn mswim_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(MswimRecognizer);
        let mswim_header = [0x4d, 0x53, 0x57, 0x49, 0x4d, 0x00, 0x00];

        assert_eq!(recognizer.number_of_bytes_required(), 7);
        assert_eq!(
            recognizer.recognize(&mswim_header),
            Some("File appears to be a Windows Imaging Format (WIM) file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn macromedia_flash_recognizer_identifies_valid_header() {
        let recognizer = MacromediaFlashRecognizer;
        let flash_header = [0x43, 0x57, 0x53];

        assert_eq!(recognizer.number_of_bytes_required(), 3);
        assert_eq!(
            recognizer.recognize(&flash_header),
            Some("File appears to be a Macromedia Flash compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn macromedia_flash_recognizer_rejects_insufficient_bytes() {
        let recognizer = MacromediaFlashRecognizer;
        let short_buffer = [0x43, 0x57];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn macromedia_flash_recognizer_rejects_mismatched_magic() {
        let recognizer = MacromediaFlashRecognizer;
        let wrong_magic = [0x43, 0x57, 0x54];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn macromedia_flash_recognizer_rejects_first_byte_mismatch() {
        let recognizer = MacromediaFlashRecognizer;
        let wrong_first = [0x42, 0x57, 0x53];

        assert_eq!(recognizer.recognize(&wrong_first), None);
    }

    #[test]
    fn macromedia_flash_recognizer_rejects_second_byte_mismatch() {
        let recognizer = MacromediaFlashRecognizer;
        let wrong_second = [0x43, 0x58, 0x53];

        assert_eq!(recognizer.recognize(&wrong_second), None);
    }

    #[test]
    fn macromedia_flash_recognizer_rejects_third_byte_mismatch() {
        let recognizer = MacromediaFlashRecognizer;
        let wrong_third = [0x43, 0x57, 0x52];

        assert_eq!(recognizer.recognize(&wrong_third), None);
    }

    #[test]
    fn macromedia_flash_recognizer_works_with_extra_data() {
        let recognizer = MacromediaFlashRecognizer;
        let flash_with_data = [0x43, 0x57, 0x53, 0xff, 0xfe, 0xfd];

        assert_eq!(
            recognizer.recognize(&flash_with_data),
            Some("File appears to be a Macromedia Flash compressed file".to_string())
        );
    }

    #[test]
    fn macromedia_flash_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(MacromediaFlashRecognizer);
        let flash_header = [0x43, 0x57, 0x53];

        assert_eq!(recognizer.number_of_bytes_required(), 3);
        assert_eq!(
            recognizer.recognize(&flash_header),
            Some("File appears to be a Macromedia Flash compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn pak_arc_recognizer_identifies_valid_header() {
        let recognizer = PakArcRecognizer;
        let pak_arc_header = [0x1a, 0x00];

        assert_eq!(recognizer.number_of_bytes_required(), 2);
        assert_eq!(
            recognizer.recognize(&pak_arc_header),
            Some("File appears to be a PAK or ARC compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn pak_arc_recognizer_identifies_valid_header_with_second_byte_variations() {
        let recognizer = PakArcRecognizer;

        for second_byte in 0x00..=0x0f {
            let header = [0x1a, second_byte];
            assert_eq!(
                recognizer.recognize(&header),
                Some("File appears to be a PAK or ARC compressed file".to_string()),
                "failed for second_byte=0x{:02x}",
                second_byte
            );
        }
    }

    #[test]
    fn pak_arc_recognizer_rejects_insufficient_bytes() {
        let recognizer = PakArcRecognizer;
        let short_buffer = [0x1a];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn pak_arc_recognizer_rejects_mismatched_first_byte() {
        let recognizer = PakArcRecognizer;
        let wrong_first = [0x1b, 0x00];

        assert_eq!(recognizer.recognize(&wrong_first), None);
    }

    #[test]
    fn pak_arc_recognizer_rejects_second_byte_with_high_nibble_nonzero() {
        let recognizer = PakArcRecognizer;

        for second_byte in 0x10..=0xff {
            let header = [0x1a, second_byte];
            assert_eq!(
                recognizer.recognize(&header),
                None,
                "should reject second_byte=0x{:02x}",
                second_byte
            );
        }
    }

    #[test]
    fn pak_arc_recognizer_works_with_extra_data() {
        let recognizer = PakArcRecognizer;
        let pak_arc_with_data = [0x1a, 0x05, 0xff, 0xfe, 0xfd, 0xfc];

        assert_eq!(
            recognizer.recognize(&pak_arc_with_data),
            Some("File appears to be a PAK or ARC compressed file".to_string())
        );
    }

    #[test]
    fn pak_arc_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(PakArcRecognizer);
        let pak_arc_header = [0x1a, 0x07];

        assert_eq!(recognizer.number_of_bytes_required(), 2);
        assert_eq!(
            recognizer.recognize(&pak_arc_header),
            Some("File appears to be a PAK or ARC compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn ppmd_recognizer_identifies_valid_header() {
        let recognizer = PpmdRecognizer;
        let ppmd_header = [0x8f, 0xaf, 0xac, 0x8c];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&ppmd_header),
            Some("File appears to be a PPMD compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn ppmd_recognizer_rejects_insufficient_bytes() {
        let recognizer = PpmdRecognizer;
        let short_buffer = [0x8f, 0xaf, 0xac];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn ppmd_recognizer_rejects_mismatched_magic() {
        let recognizer = PpmdRecognizer;
        let wrong_magic = [0x8f, 0xaf, 0xac, 0x8d];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn ppmd_recognizer_rejects_first_byte_mismatch() {
        let recognizer = PpmdRecognizer;
        let wrong_first = [0x8e, 0xaf, 0xac, 0x8c];

        assert_eq!(recognizer.recognize(&wrong_first), None);
    }

    #[test]
    fn ppmd_recognizer_rejects_second_byte_mismatch() {
        let recognizer = PpmdRecognizer;
        let wrong_second = [0x8f, 0xae, 0xac, 0x8c];

        assert_eq!(recognizer.recognize(&wrong_second), None);
    }

    #[test]
    fn ppmd_recognizer_rejects_third_byte_mismatch() {
        let recognizer = PpmdRecognizer;
        let wrong_third = [0x8f, 0xaf, 0xad, 0x8c];

        assert_eq!(recognizer.recognize(&wrong_third), None);
    }

    #[test]
    fn ppmd_recognizer_rejects_fourth_byte_mismatch() {
        let recognizer = PpmdRecognizer;
        let wrong_fourth = [0x8f, 0xaf, 0xac, 0x8d];

        assert_eq!(recognizer.recognize(&wrong_fourth), None);
    }

    #[test]
    fn ppmd_recognizer_works_with_extra_data() {
        let recognizer = PpmdRecognizer;
        let ppmd_with_data = [0x8f, 0xaf, 0xac, 0x8c, 0xff, 0xfe, 0xfd, 0xfc];

        assert_eq!(
            recognizer.recognize(&ppmd_with_data),
            Some("File appears to be a PPMD compressed file".to_string())
        );
    }

    #[test]
    fn ppmd_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(PpmdRecognizer);
        let ppmd_header = [0x8f, 0xaf, 0xac, 0x8c];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&ppmd_header),
            Some("File appears to be a PPMD compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn pkzip_recognizer_identifies_valid_header() {
        let recognizer = PkzipRecognizer;
        let pkzip_header = [0x50, 0x4b, 0x03, 0x04];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&pkzip_header),
            Some("File appears to be a PKZIP, WINZIP, or JAR compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn pkzip_recognizer_rejects_insufficient_bytes() {
        let recognizer = PkzipRecognizer;
        let short_buffer = [0x50, 0x4b, 0x03];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn pkzip_recognizer_rejects_mismatched_magic() {
        let recognizer = PkzipRecognizer;
        let wrong_magic = [0x50, 0x4b, 0x03, 0x05];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn pkzip_recognizer_rejects_first_byte_mismatch() {
        let recognizer = PkzipRecognizer;
        let wrong_first = [0x51, 0x4b, 0x03, 0x04];

        assert_eq!(recognizer.recognize(&wrong_first), None);
    }

    #[test]
    fn pkzip_recognizer_rejects_second_byte_mismatch() {
        let recognizer = PkzipRecognizer;
        let wrong_second = [0x50, 0x4c, 0x03, 0x04];

        assert_eq!(recognizer.recognize(&wrong_second), None);
    }

    #[test]
    fn pkzip_recognizer_rejects_third_byte_mismatch() {
        let recognizer = PkzipRecognizer;
        let wrong_third = [0x50, 0x4b, 0x02, 0x04];

        assert_eq!(recognizer.recognize(&wrong_third), None);
    }

    #[test]
    fn pkzip_recognizer_works_with_extra_data() {
        let recognizer = PkzipRecognizer;
        let pkzip_with_data = [0x50, 0x4b, 0x03, 0x04, 0xff, 0xfe, 0xfd, 0xfc];

        assert_eq!(
            recognizer.recognize(&pkzip_with_data),
            Some("File appears to be a PKZIP, WINZIP, or JAR compressed file".to_string())
        );
    }

    #[test]
    fn pkzip_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(PkzipRecognizer);
        let pkzip_header = [0x50, 0x4b, 0x03, 0x04];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&pkzip_header),
            Some("File appears to be a PKZIP, WINZIP, or JAR compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn rpm_recognizer_identifies_valid_header() {
        let recognizer = RpmRecognizer;
        let rpm_header = [0xed, 0xab, 0xee, 0xdb];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&rpm_header),
            Some("File appears to be an RPM package".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn rpm_recognizer_rejects_insufficient_bytes() {
        let recognizer = RpmRecognizer;
        let short_buffer = [0xed, 0xab, 0xee];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn rpm_recognizer_rejects_mismatched_magic() {
        let recognizer = RpmRecognizer;
        let wrong_magic = [0xed, 0xab, 0xee, 0xdc];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn rpm_recognizer_rejects_first_byte_mismatch() {
        let recognizer = RpmRecognizer;
        let wrong_first = [0xec, 0xab, 0xee, 0xdb];

        assert_eq!(recognizer.recognize(&wrong_first), None);
    }

    #[test]
    fn rpm_recognizer_rejects_second_byte_mismatch() {
        let recognizer = RpmRecognizer;
        let wrong_second = [0xed, 0xac, 0xee, 0xdb];

        assert_eq!(recognizer.recognize(&wrong_second), None);
    }

    #[test]
    fn rpm_recognizer_rejects_third_byte_mismatch() {
        let recognizer = RpmRecognizer;
        let wrong_third = [0xed, 0xab, 0xef, 0xdb];

        assert_eq!(recognizer.recognize(&wrong_third), None);
    }

    #[test]
    fn rpm_recognizer_rejects_fourth_byte_mismatch() {
        let recognizer = RpmRecognizer;
        let wrong_fourth = [0xed, 0xab, 0xee, 0xda];

        assert_eq!(recognizer.recognize(&wrong_fourth), None);
    }

    #[test]
    fn rpm_recognizer_works_with_extra_data() {
        let recognizer = RpmRecognizer;
        let rpm_with_data = [0xed, 0xab, 0xee, 0xdb, 0xff, 0xfe, 0xfd, 0xfc];

        assert_eq!(
            recognizer.recognize(&rpm_with_data),
            Some("File appears to be an RPM package".to_string())
        );
    }

    #[test]
    fn rpm_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(RpmRecognizer);
        let rpm_header = [0xed, 0xab, 0xee, 0xdb];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&rpm_header),
            Some("File appears to be an RPM package".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn rar_recognizer_identifies_valid_header() {
        let recognizer = RarRecognizer;
        let rar_header = [0x52, 0x61, 0x72, 0x21];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&rar_header),
            Some("File appears to be a RAR compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn rar_recognizer_rejects_insufficient_bytes() {
        let recognizer = RarRecognizer;
        let short_buffer = [0x52, 0x61, 0x72];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn rar_recognizer_rejects_mismatched_magic() {
        let recognizer = RarRecognizer;
        let wrong_magic = [0x52, 0x61, 0x72, 0x22];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn rar_recognizer_rejects_first_byte_mismatch() {
        let recognizer = RarRecognizer;
        let wrong_first = [0x53, 0x61, 0x72, 0x21];

        assert_eq!(recognizer.recognize(&wrong_first), None);
    }

    #[test]
    fn rar_recognizer_rejects_second_byte_mismatch() {
        let recognizer = RarRecognizer;
        let wrong_second = [0x52, 0x62, 0x72, 0x21];

        assert_eq!(recognizer.recognize(&wrong_second), None);
    }

    #[test]
    fn rar_recognizer_rejects_third_byte_mismatch() {
        let recognizer = RarRecognizer;
        let wrong_third = [0x52, 0x61, 0x73, 0x21];

        assert_eq!(recognizer.recognize(&wrong_third), None);
    }

    #[test]
    fn rar_recognizer_rejects_fourth_byte_mismatch() {
        let recognizer = RarRecognizer;
        let wrong_fourth = [0x52, 0x61, 0x72, 0x20];

        assert_eq!(recognizer.recognize(&wrong_fourth), None);
    }

    #[test]
    fn rar_recognizer_works_with_extra_data() {
        let recognizer = RarRecognizer;
        let rar_with_data = [0x52, 0x61, 0x72, 0x21, 0xff, 0xfe, 0xfd, 0xfc];

        assert_eq!(
            recognizer.recognize(&rar_with_data),
            Some("File appears to be a RAR compressed file".to_string())
        );
    }

    #[test]
    fn rar_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(RarRecognizer);
        let rar_header = [0x52, 0x61, 0x72, 0x21];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&rar_header),
            Some("File appears to be a RAR compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn sbc_recognizer_identifies_valid_header() {
        let recognizer = SbcRecognizer;
        let sbc_header = [0x53, 0x42, 0x43, 0x1c];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&sbc_header),
            Some("File appears to be a SBC compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn sbc_recognizer_rejects_insufficient_bytes() {
        let recognizer = SbcRecognizer;
        let short_buffer = [0x53, 0x42, 0x43];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn sbc_recognizer_rejects_mismatched_magic() {
        let recognizer = SbcRecognizer;
        let wrong_magic = [0x53, 0x42, 0x43, 0x1d];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn sbc_recognizer_rejects_first_byte_mismatch() {
        let recognizer = SbcRecognizer;
        let wrong_first = [0x54, 0x42, 0x43, 0x1c];

        assert_eq!(recognizer.recognize(&wrong_first), None);
    }

    #[test]
    fn sbc_recognizer_rejects_second_byte_mismatch() {
        let recognizer = SbcRecognizer;
        let wrong_second = [0x53, 0x41, 0x43, 0x1c];

        assert_eq!(recognizer.recognize(&wrong_second), None);
    }

    #[test]
    fn sbc_recognizer_rejects_third_byte_mismatch() {
        let recognizer = SbcRecognizer;
        let wrong_third = [0x53, 0x42, 0x44, 0x1c];

        assert_eq!(recognizer.recognize(&wrong_third), None);
    }

    #[test]
    fn sbc_recognizer_rejects_fourth_byte_mismatch() {
        let recognizer = SbcRecognizer;
        let wrong_fourth = [0x53, 0x42, 0x43, 0x1d];

        assert_eq!(recognizer.recognize(&wrong_fourth), None);
    }

    #[test]
    fn sbc_recognizer_works_with_extra_data() {
        let recognizer = SbcRecognizer;
        let sbc_with_data = [0x53, 0x42, 0x43, 0x1c, 0xff, 0xfe, 0xfd, 0xfc];

        assert_eq!(
            recognizer.recognize(&sbc_with_data),
            Some("File appears to be a SBC compressed file".to_string())
        );
    }

    #[test]
    fn sbc_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(SbcRecognizer);
        let sbc_header = [0x53, 0x42, 0x43, 0x1c];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&sbc_header),
            Some("File appears to be a SBC compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn sbx_recognizer_identifies_valid_header() {
        let recognizer = SbxRecognizer;
        let sbx_header = [0x53, 0x42, 0x31, 0x00];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&sbx_header),
            Some("File appears to be an SBX compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn sbx_recognizer_rejects_insufficient_bytes() {
        let recognizer = SbxRecognizer;
        let short_buffer = [0x53, 0x42, 0x31];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn sbx_recognizer_rejects_mismatched_magic() {
        let recognizer = SbxRecognizer;
        let wrong_magic = [0x53, 0x42, 0x31, 0x01];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn sbx_recognizer_rejects_first_byte_mismatch() {
        let recognizer = SbxRecognizer;
        let wrong_first = [0x54, 0x42, 0x31, 0x00];

        assert_eq!(recognizer.recognize(&wrong_first), None);
    }

    #[test]
    fn sbx_recognizer_rejects_second_byte_mismatch() {
        let recognizer = SbxRecognizer;
        let wrong_second = [0x53, 0x41, 0x31, 0x00];

        assert_eq!(recognizer.recognize(&wrong_second), None);
    }

    #[test]
    fn sbx_recognizer_rejects_third_byte_mismatch() {
        let recognizer = SbxRecognizer;
        let wrong_third = [0x53, 0x42, 0x32, 0x00];

        assert_eq!(recognizer.recognize(&wrong_third), None);
    }

    #[test]
    fn sbx_recognizer_rejects_fourth_byte_mismatch() {
        let recognizer = SbxRecognizer;
        let wrong_fourth = [0x53, 0x42, 0x31, 0x01];

        assert_eq!(recognizer.recognize(&wrong_fourth), None);
    }

    #[test]
    fn sbx_recognizer_works_with_extra_data() {
        let recognizer = SbxRecognizer;
        let sbx_with_data = [0x53, 0x42, 0x31, 0x00, 0xff, 0xfe, 0xfd, 0xfc];

        assert_eq!(
            recognizer.recognize(&sbx_with_data),
            Some("File appears to be an SBX compressed file".to_string())
        );
    }

    #[test]
    fn sbx_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(SbxRecognizer);
        let sbx_header = [0x53, 0x42, 0x31, 0x00];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&sbx_header),
            Some("File appears to be an SBX compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn seven_zip_recognizer_identifies_valid_header() {
        let recognizer = SevenZipRecognizer;
        let seven_zip_header = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];

        assert_eq!(recognizer.number_of_bytes_required(), 6);
        assert_eq!(
            recognizer.recognize(&seven_zip_header),
            Some("File appears to be a 7-ZIP compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn seven_zip_recognizer_rejects_insufficient_bytes() {
        let recognizer = SevenZipRecognizer;
        let short_buffer = [0x37, 0x7a, 0xbc, 0xaf, 0x27];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn seven_zip_recognizer_rejects_mismatched_magic() {
        let recognizer = SevenZipRecognizer;
        let wrong_magic = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1d];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn seven_zip_recognizer_rejects_first_byte_mismatch() {
        let recognizer = SevenZipRecognizer;
        let wrong_first = [0x36, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];

        assert_eq!(recognizer.recognize(&wrong_first), None);
    }

    #[test]
    fn seven_zip_recognizer_rejects_second_byte_mismatch() {
        let recognizer = SevenZipRecognizer;
        let wrong_second = [0x37, 0x7b, 0xbc, 0xaf, 0x27, 0x1c];

        assert_eq!(recognizer.recognize(&wrong_second), None);
    }

    #[test]
    fn seven_zip_recognizer_rejects_third_byte_mismatch() {
        let recognizer = SevenZipRecognizer;
        let wrong_third = [0x37, 0x7a, 0xbd, 0xaf, 0x27, 0x1c];

        assert_eq!(recognizer.recognize(&wrong_third), None);
    }

    #[test]
    fn seven_zip_recognizer_rejects_fourth_byte_mismatch() {
        let recognizer = SevenZipRecognizer;
        let wrong_fourth = [0x37, 0x7a, 0xbc, 0xae, 0x27, 0x1c];

        assert_eq!(recognizer.recognize(&wrong_fourth), None);
    }

    #[test]
    fn seven_zip_recognizer_rejects_fifth_byte_mismatch() {
        let recognizer = SevenZipRecognizer;
        let wrong_fifth = [0x37, 0x7a, 0xbc, 0xaf, 0x26, 0x1c];

        assert_eq!(recognizer.recognize(&wrong_fifth), None);
    }

    #[test]
    fn seven_zip_recognizer_rejects_sixth_byte_mismatch() {
        let recognizer = SevenZipRecognizer;
        let wrong_sixth = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1d];

        assert_eq!(recognizer.recognize(&wrong_sixth), None);
    }

    #[test]
    fn seven_zip_recognizer_works_with_extra_data() {
        let recognizer = SevenZipRecognizer;
        let seven_zip_with_data =
            [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0xff, 0xfe, 0xfd, 0xfc];

        assert_eq!(
            recognizer.recognize(&seven_zip_with_data),
            Some("File appears to be a 7-ZIP compressed file".to_string())
        );
    }

    #[test]
    fn seven_zip_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(SevenZipRecognizer);
        let seven_zip_header = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];

        assert_eq!(recognizer.number_of_bytes_required(), 6);
        assert_eq!(
            recognizer.recognize(&seven_zip_header),
            Some("File appears to be a 7-ZIP compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn spanned_pkzip_recognizer_identifies_valid_header() {
        let recognizer = SpannedPkzipRecognizer;
        let spanned_pkzip_header = [0x50, 0x4b, 0x07, 0x08];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&spanned_pkzip_header),
            Some("File appears to be a spanned PKZIP compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn spanned_pkzip_recognizer_rejects_insufficient_bytes() {
        let recognizer = SpannedPkzipRecognizer;
        let short_buffer = [0x50, 0x4b, 0x07];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn spanned_pkzip_recognizer_rejects_mismatched_magic() {
        let recognizer = SpannedPkzipRecognizer;
        let wrong_magic = [0x50, 0x4b, 0x07, 0x09];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn spanned_pkzip_recognizer_rejects_first_byte_mismatch() {
        let recognizer = SpannedPkzipRecognizer;
        let wrong_first = [0x51, 0x4b, 0x07, 0x08];

        assert_eq!(recognizer.recognize(&wrong_first), None);
    }

    #[test]
    fn spanned_pkzip_recognizer_rejects_second_byte_mismatch() {
        let recognizer = SpannedPkzipRecognizer;
        let wrong_second = [0x50, 0x4c, 0x07, 0x08];

        assert_eq!(recognizer.recognize(&wrong_second), None);
    }

    #[test]
    fn spanned_pkzip_recognizer_rejects_third_byte_mismatch() {
        let recognizer = SpannedPkzipRecognizer;
        let wrong_third = [0x50, 0x4b, 0x08, 0x08];

        assert_eq!(recognizer.recognize(&wrong_third), None);
    }

    #[test]
    fn spanned_pkzip_recognizer_rejects_fourth_byte_mismatch() {
        let recognizer = SpannedPkzipRecognizer;
        let wrong_fourth = [0x50, 0x4b, 0x07, 0x07];

        assert_eq!(recognizer.recognize(&wrong_fourth), None);
    }

    #[test]
    fn spanned_pkzip_recognizer_works_with_extra_data() {
        let recognizer = SpannedPkzipRecognizer;
        let spanned_pkzip_with_data = [0x50, 0x4b, 0x07, 0x08, 0xff, 0xfe, 0xfd, 0xfc];

        assert_eq!(
            recognizer.recognize(&spanned_pkzip_with_data),
            Some("File appears to be a spanned PKZIP compressed file".to_string())
        );
    }

    #[test]
    fn spanned_pkzip_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(SpannedPkzipRecognizer);
        let spanned_pkzip_header = [0x50, 0x4b, 0x07, 0x08];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&spanned_pkzip_header),
            Some("File appears to be a spanned PKZIP compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn sqz_recognizer_identifies_valid_header() {
        let recognizer = SqzRecognizer;
        let sqz_header = [0x48, 0x4c, 0x53, 0x51, 0x5a, 0x31];

        assert_eq!(recognizer.number_of_bytes_required(), 6);
        assert_eq!(
            recognizer.recognize(&sqz_header),
            Some("File appears to be a SQZ compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn sqz_recognizer_rejects_insufficient_bytes() {
        let recognizer = SqzRecognizer;
        let short_buffer = [0x48, 0x4c, 0x53, 0x51, 0x5a];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn sqz_recognizer_rejects_mismatched_magic() {
        let recognizer = SqzRecognizer;
        let wrong_magic = [0x48, 0x4c, 0x53, 0x51, 0x5a, 0x32];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn sqz_recognizer_rejects_first_byte_mismatch() {
        let recognizer = SqzRecognizer;
        let wrong_first = [0x49, 0x4c, 0x53, 0x51, 0x5a, 0x31];

        assert_eq!(recognizer.recognize(&wrong_first), None);
    }

    #[test]
    fn sqz_recognizer_rejects_second_byte_mismatch() {
        let recognizer = SqzRecognizer;
        let wrong_second = [0x48, 0x4d, 0x53, 0x51, 0x5a, 0x31];

        assert_eq!(recognizer.recognize(&wrong_second), None);
    }

    #[test]
    fn sqz_recognizer_rejects_third_byte_mismatch() {
        let recognizer = SqzRecognizer;
        let wrong_third = [0x48, 0x4c, 0x54, 0x51, 0x5a, 0x31];

        assert_eq!(recognizer.recognize(&wrong_third), None);
    }

    #[test]
    fn sqz_recognizer_rejects_fourth_byte_mismatch() {
        let recognizer = SqzRecognizer;
        let wrong_fourth = [0x48, 0x4c, 0x53, 0x52, 0x5a, 0x31];

        assert_eq!(recognizer.recognize(&wrong_fourth), None);
    }

    #[test]
    fn sqz_recognizer_rejects_fifth_byte_mismatch() {
        let recognizer = SqzRecognizer;
        let wrong_fifth = [0x48, 0x4c, 0x53, 0x51, 0x5b, 0x31];

        assert_eq!(recognizer.recognize(&wrong_fifth), None);
    }

    #[test]
    fn sqz_recognizer_rejects_sixth_byte_mismatch() {
        let recognizer = SqzRecognizer;
        let wrong_sixth = [0x48, 0x4c, 0x53, 0x51, 0x5a, 0x30];

        assert_eq!(recognizer.recognize(&wrong_sixth), None);
    }

    #[test]
    fn sqz_recognizer_works_with_extra_data() {
        let recognizer = SqzRecognizer;
        let sqz_with_data = [0x48, 0x4c, 0x53, 0x51, 0x5a, 0x31, 0xff, 0xfe, 0xfd, 0xfc];

        assert_eq!(
            recognizer.recognize(&sqz_with_data),
            Some("File appears to be a SQZ compressed file".to_string())
        );
    }

    #[test]
    fn sqz_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(SqzRecognizer);
        let sqz_header = [0x48, 0x4c, 0x53, 0x51, 0x5a, 0x31];

        assert_eq!(recognizer.number_of_bytes_required(), 6);
        assert_eq!(
            recognizer.recognize(&sqz_header),
            Some("File appears to be a SQZ compressed file".to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn stuffit1_recognizer_identifies_valid_header() {
        let recognizer = StuffIt1Recognizer;
        let stuffit1_header = [0x53, 0x49, 0x54, 0x21];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&stuffit1_header),
            Some("File appears to be a Stuffit1 (Stuffit versions up to v4.0) compressed file"
                .to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }

    #[test]
    fn stuffit1_recognizer_rejects_insufficient_bytes() {
        let recognizer = StuffIt1Recognizer;
        let short_buffer = [0x53, 0x49, 0x54];

        assert_eq!(recognizer.recognize(&short_buffer), None);
    }

    #[test]
    fn stuffit1_recognizer_rejects_mismatched_magic() {
        let recognizer = StuffIt1Recognizer;
        let wrong_magic = [0x53, 0x49, 0x54, 0x22];

        assert_eq!(recognizer.recognize(&wrong_magic), None);
    }

    #[test]
    fn stuffit1_recognizer_rejects_first_byte_mismatch() {
        let recognizer = StuffIt1Recognizer;
        let wrong_first = [0x52, 0x49, 0x54, 0x21];

        assert_eq!(recognizer.recognize(&wrong_first), None);
    }

    #[test]
    fn stuffit1_recognizer_rejects_second_byte_mismatch() {
        let recognizer = StuffIt1Recognizer;
        let wrong_second = [0x53, 0x48, 0x54, 0x21];

        assert_eq!(recognizer.recognize(&wrong_second), None);
    }

    #[test]
    fn stuffit1_recognizer_rejects_third_byte_mismatch() {
        let recognizer = StuffIt1Recognizer;
        let wrong_third = [0x53, 0x49, 0x55, 0x21];

        assert_eq!(recognizer.recognize(&wrong_third), None);
    }

    #[test]
    fn stuffit1_recognizer_rejects_fourth_byte_mismatch() {
        let recognizer = StuffIt1Recognizer;
        let wrong_fourth = [0x53, 0x49, 0x54, 0x20];

        assert_eq!(recognizer.recognize(&wrong_fourth), None);
    }

    #[test]
    fn stuffit1_recognizer_works_with_extra_data() {
        let recognizer = StuffIt1Recognizer;
        let stuffit1_with_data = [0x53, 0x49, 0x54, 0x21, 0xff, 0xfe, 0xfd, 0xfc];

        assert_eq!(
            recognizer.recognize(&stuffit1_with_data),
            Some("File appears to be a Stuffit1 (Stuffit versions up to v4.0) compressed file"
                .to_string())
        );
    }

    #[test]
    fn stuffit1_recognizer_via_trait_object() {
        let recognizer: Box<dyn Recognizer> = Box::new(StuffIt1Recognizer);
        let stuffit1_header = [0x53, 0x49, 0x54, 0x21];

        assert_eq!(recognizer.number_of_bytes_required(), 4);
        assert_eq!(
            recognizer.recognize(&stuffit1_header),
            Some("File appears to be a Stuffit1 (Stuffit versions up to v4.0) compressed file"
                .to_string())
        );
        assert_eq!(recognizer.get_priority(), 100);
    }
}
