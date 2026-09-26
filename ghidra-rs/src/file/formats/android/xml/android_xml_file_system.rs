//! Rust port of `ghidra.file.formats.android.xml.AndroidXmlFileSystem`.
//!
//! A [`GFileSystem`](crate::filesystem::gfilesystem::g_file_system::GFileSystem) that exposes a
//! single file: the text rendering of a binary Android XML document.
//!
//! In Java this class extends `GFileSystemBase` (unported: it wires the generic
//! `GFileSystem` machinery -- ref counting, FSRL roots, filesystem-service registration -- none
//! of which this class's own logic touches) and references `GFileSystemBaseFactory` only via
//! the class-level `@FileSystemInfo` annotation, which Rust has no analog for. Since nothing in
//! the crate yet drives a concrete `FSRL`/`FSRLRoot` pair, this port only carries the state and
//! behavior this class itself declares (the constructor, `getPayloadFile`, `isValid`, `open`,
//! `getByteProvider`, `getListing`, and the `isAndroidXmlFile` probe) rather than also
//! reimplementing `GFileSystemBase`'s inherited plumbing.
//!
//! `AndroidXmlConvertor` (the binary-XML-to-text converter) is fully ported at
//! [`crate::file::formats::android::xml::android_xml_convertor`], but the third-party
//! `AXmlResourceParser` it walks is not part of Ghidra's own source tree (see that module's doc
//! comment), so this filesystem still cannot actually convert a real payload -- it wires
//! `AndroidXmlConvertor::convert` up against [`UnimplementedAXmlResourceParser`], a local stand-in
//! that always fails, preserving this crate's prior behavior here. The lone file this filesystem
//! exposes is represented with the already-ported
//! [`GFileImpl`](crate::filesystem::gfilesystem::g_file_impl::GFileImpl), parameterized over a
//! small local filesystem handle ([`XmlFsMarker`]) carrying this filesystem's real
//! [`FsrlRoot`].

use std::io;

use crate::file::formats::android::xml::android_xml_convertor::{
    AndroidXmlConvertor, ANDROID_BINARY_XML_MAGIC,
};
use crate::file::seam_stubs::{AXmlParseError, AXmlResourceParser, AndroidXmlEvent, ByteArrayProvider};
use crate::filesystem::ghidra::g_binary_reader::GByteStore;
use crate::filesystem::gfilesystem::g_file::GFile;
use crate::filesystem::gfilesystem::fsrl::Fsrl;
use crate::filesystem::gfilesystem::fsrl_root::FsrlRoot;
use crate::filesystem::gfilesystem::g_file_impl::{FsGetListing, GFileImpl, HasFsrlRoot};
use crate::util::task::TaskMonitor;

/// Placeholder [`AXmlResourceParser`] used until a real binary-XML parser is ported (see that
/// trait's own doc comment: neither `AXmlResourceParser` nor `TypedValue` are part of Ghidra's
/// own source tree, so there is no Java source to port them from). Every method fails/panics,
/// matching this crate's prior behavior here (`AndroidXmlConvertor::convert` itself was
/// `unimplemented!()` before it was ported against this seam) -- this filesystem cannot yet
/// actually render a binary XML payload, only detect one is malformed/absent via I/O errors.
struct UnimplementedAXmlResourceParser;

impl AXmlResourceParser for UnimplementedAXmlResourceParser {
    fn open(&mut self, _input: &[u8]) -> Result<(), AXmlParseError> {
        Err(AXmlParseError("no AXmlResourceParser implementation is available yet".to_string()))
    }
    fn next(&mut self) -> Result<AndroidXmlEvent, AXmlParseError> {
        Err(AXmlParseError("no AXmlResourceParser implementation is available yet".to_string()))
    }
    fn get_prefix(&self) -> Option<String> {
        None
    }
    fn get_name(&self) -> String {
        String::new()
    }
    fn get_depth(&self) -> i32 {
        0
    }
    fn get_namespace_count(&self, _depth: i32) -> i32 {
        0
    }
    fn get_namespace_prefix(&self, _index: i32) -> String {
        String::new()
    }
    fn get_namespace_uri(&self, _index: i32) -> String {
        String::new()
    }
    fn get_attribute_count(&self) -> i32 {
        0
    }
    fn get_attribute_prefix(&self, _index: i32) -> Option<String> {
        None
    }
    fn get_attribute_name(&self, _index: i32) -> String {
        String::new()
    }
    fn get_attribute_value(&self, _index: i32) -> String {
        String::new()
    }
    fn get_attribute_value_type(&self, _index: i32) -> i32 {
        0
    }
    fn get_attribute_value_data(&self, _index: i32) -> i32 {
        0
    }
    fn get_text(&self) -> String {
        String::new()
    }
    fn close(&mut self) {}
}

/// Minimal stand-in FS marker used to parameterize [`GFileImpl`] for this filesystem's single
/// file, until a concrete `GFileSystem` implementer type is threaded through generically.
#[derive(Clone, Debug)]
pub struct XmlFsMarker {
    root: FsrlRoot,
}

impl HasFsrlRoot for XmlFsMarker {
    fn root_fsrl(&self) -> &Fsrl {
        self.root.as_fsrl()
    }
}

impl FsGetListing<XmlFsMarker> for XmlFsMarker {
    fn fs_get_listing(
        &self,
        _file: &dyn GFile<XmlFsMarker>,
    ) -> io::Result<Vec<Box<dyn GFile<XmlFsMarker>>>> {
        Ok(vec![])
    }
}

/// A [`GFileSystem`](crate::filesystem::gfilesystem::g_file_system::GFileSystem) that provides a
/// single file, which is the text version of a binary Android XML file.
///
/// NOTE: most of the conversion logic was hijacked from `AXMLPrinter.java` (see
/// `AndroidXmlConvertor`).
pub struct AndroidXmlFileSystem {
    file_system_name: String,
    /// This filesystem's FSRL root (Java `GFileSystemBase.fsFSRL`).
    fs_fsrl: FsrlRoot,
    provider: Box<dyn GByteStore>,
    /// Text rendering of the binary XML payload, produced by [`open`](Self::open). `None`
    /// until `open` has been called, matching Java's `payloadFile == null` prior to `open()`.
    payload_bytes: Option<Vec<u8>>,
}

impl AndroidXmlFileSystem {
    /// Probes whether `provider`'s contents are a binary Android XML file.
    ///
    /// Mirrors `AndroidXmlFileSystem.isAndroidXmlFile`: an initial magic-number mismatch (or an
    /// I/O error reading it) is a hard `false`/error, while a failure converting the body (an
    /// `IOException` or `CancelledException` in Java) is folded into `false`.
    pub fn is_android_xml_file(
        provider: &mut dyn GByteStore,
        monitor: &dyn TaskMonitor,
    ) -> io::Result<bool> {
        let magic = ANDROID_BINARY_XML_MAGIC;
        let actual_bytes = provider.read_bytes(0, magic.len())?;
        if actual_bytes != magic {
            return Ok(false);
        }

        let len = provider.length()?;
        let bytes = provider.read_bytes(0, len as usize)?;
        let mut out = String::new();
        let mut parser = UnimplementedAXmlResourceParser;
        Ok(AndroidXmlConvertor::convert(&bytes, &mut out, &mut parser, monitor).is_ok())
    }

    /// Mirrors the `AndroidXmlFileSystem(String, GByteStore)` constructor followed by the
    /// `GFileSystemBase.setFSRL(FSRLRoot)` call its factory always makes before use -- folded
    /// into construction here so the FSRL root is never absent.
    pub fn new(
        file_system_name: impl Into<String>,
        fs_fsrl: FsrlRoot,
        provider: Box<dyn GByteStore>,
    ) -> Self {
        AndroidXmlFileSystem {
            file_system_name: file_system_name.into(),
            fs_fsrl,
            provider,
            payload_bytes: None,
        }
    }

    /// This filesystem's FSRL root.
    ///
    /// Mirrors `GFileSystemBase.getFSRL`.
    pub fn get_fsrl(&self) -> &FsrlRoot {
        &self.fs_fsrl
    }

    /// This filesystem's volume name.
    pub fn name(&self) -> &str {
        &self.file_system_name
    }

    /// The single file this filesystem exposes, or `None` before [`open`](Self::open) has run.
    ///
    /// Returns a freshly-constructed [`GFileImpl`] each call rather than aliasing a stored
    /// field -- equivalent here since `GFileImpl` equality is structural and this filesystem
    /// only ever has the one file.
    pub fn get_payload_file(&self) -> Option<GFileImpl<XmlFsMarker>> {
        self.payload_file()
    }

    fn payload_file(&self) -> Option<GFileImpl<XmlFsMarker>> {
        let len = self.payload_bytes.as_ref()?.len() as i64;
        let marker = XmlFsMarker { root: self.fs_fsrl.clone() };
        Some(GFileImpl::from_filename(marker, None, "XML", false, len, None))
    }

    /// Mirrors `AndroidXmlFileSystem.isValid`.
    pub fn is_valid(&mut self, monitor: &dyn TaskMonitor) -> io::Result<bool> {
        Self::is_android_xml_file(self.provider.as_mut(), monitor)
    }

    /// Mirrors `AndroidXmlFileSystem.open`: converts the binary XML payload to text, falling
    /// back to a fixed error payload if conversion fails (matching Java's `catch (IOException)`
    /// -- see
    /// [`AndroidXmlConvertor::convert`](crate::file::formats::android::xml::android_xml_convertor::AndroidXmlConvertor::convert)
    /// doc for why `CancelledException` is folded into the same fallback here).
    pub fn open(&mut self, monitor: &dyn TaskMonitor) -> io::Result<()> {
        let len = self.provider.length()?;
        let bytes = self.provider.read_bytes(0, len as usize)?;

        let mut out = String::new();
        let mut parser = UnimplementedAXmlResourceParser;
        self.payload_bytes = Some(match AndroidXmlConvertor::convert(&bytes, &mut out, &mut parser, monitor) {
            Ok(()) => out.into_bytes(),
            Err(_) => b"failed to convert".to_vec(),
        });
        Ok(())
    }

    /// Mirrors `AndroidXmlFileSystem.getByteProvider`.
    pub fn get_byte_provider(
        &self,
        _file: &GFileImpl<XmlFsMarker>,
        _monitor: &dyn TaskMonitor,
    ) -> io::Result<Box<dyn GByteStore>> {
        let bytes = self
            .payload_bytes
            .clone()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "filesystem not opened"))?;
        Ok(Box::new(ByteArrayProvider::new(bytes)))
    }

    /// Mirrors `AndroidXmlFileSystem.getListing`.
    pub fn get_listing(
        &self,
        _directory: Option<&GFileImpl<XmlFsMarker>>,
    ) -> io::Result<Vec<GFileImpl<XmlFsMarker>>> {
        Ok(self.payload_file().into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;

    fn fs_root() -> FsrlRoot {
        Fsrl::from_string("file:///tmp/AndroidManifest.xml").unwrap().make_nested("androidxml")
    }

    struct VecByteProvider(Vec<u8>);

    impl GByteStore for VecByteProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }

        fn is_valid_index(&mut self, index: u64) -> bool {
            (index as usize) < self.0.len()
        }

        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "out of bounds"))
        }

        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            if end > self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "out of bounds"));
            }
            Ok(self.0[start..end].to_vec())
        }

        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Other, "read-only"))
        }

        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Other, "read-only"))
        }
    }

    #[test]
    fn is_android_xml_file_false_on_magic_mismatch() {
        let mut provider = VecByteProvider(vec![0xAA, 0xBB, 0xCC, 0xDD, 0x00]);
        let monitor = DummyMonitor;
        assert!(!AndroidXmlFileSystem::is_android_xml_file(&mut provider, &monitor).unwrap());
    }

    #[test]
    fn is_android_xml_file_errors_when_shorter_than_magic() {
        let mut provider = VecByteProvider(vec![0x03, 0x00]);
        let monitor = DummyMonitor;
        assert!(AndroidXmlFileSystem::is_android_xml_file(&mut provider, &monitor).is_err());
    }

    #[test]
    fn new_stores_name_and_no_payload_yet() {
        let provider = Box::new(VecByteProvider(vec![0x03, 0x00, 0x08, 0x00]));
        let fs = AndroidXmlFileSystem::new("androidxml", fs_root(), provider);
        assert_eq!(fs.name(), "androidxml");
        assert!(fs.get_payload_file().is_none());
    }

    #[test]
    fn get_byte_provider_errors_before_open() {
        let provider = Box::new(VecByteProvider(vec![0x03, 0x00, 0x08, 0x00]));
        let fs = AndroidXmlFileSystem::new("androidxml", fs_root(), provider);
        let payload = GFileImpl::from_filename(
            XmlFsMarker { root: fs_root() },
            None,
            "XML",
            false,
            0,
            None,
        );
        assert!(fs.get_byte_provider(&payload, &DummyMonitor).is_err());
    }

    #[test]
    fn get_listing_empty_before_open() {
        let provider = Box::new(VecByteProvider(vec![0x03, 0x00, 0x08, 0x00]));
        let fs = AndroidXmlFileSystem::new("androidxml", fs_root(), provider);
        assert!(fs.get_listing(None).unwrap().is_empty());
    }

    #[test]
    fn payload_file_fsrl_is_under_fs_root() {
        let provider = Box::new(VecByteProvider(vec![0x03, 0x00, 0x08, 0x00]));
        let mut fs = AndroidXmlFileSystem::new("androidxml", fs_root(), provider);
        fs.open(&DummyMonitor).unwrap();
        let payload = fs.get_payload_file().expect("payload after open");
        // Java: GFileImpl.fromFilename(this, root, "XML", ...) -> root.getFSRL().appendPath("XML")
        assert_eq!(
            payload.get_fsrl().to_string(),
            "file:///tmp/AndroidManifest.xml|androidxml:///XML"
        );
        assert_eq!(payload.get_path(), "/XML");
        assert_eq!(fs.get_fsrl(), &fs_root());
    }
}
