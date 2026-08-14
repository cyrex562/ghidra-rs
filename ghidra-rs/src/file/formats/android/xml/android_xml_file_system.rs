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
//! `AndroidXmlConvertor` (the binary-XML-to-text converter) is not yet ported; see
//! [`crate::file::seam_stubs::AndroidXmlConvertor`] for its minimal stand-in. The lone file this
//! filesystem exposes is represented with the already-ported
//! [`GFileImpl`](crate::filesystem::gfilesystem::g_file_impl::GFileImpl), parameterized over a
//! small local FS/FSRL pair ([`XmlFsMarker`]/[`XmlFsrl`]) since no concrete `FSRL` type exists
//! in the crate yet either.

use std::io;

use crate::file::seam_stubs::{AndroidXmlConvertor, ByteArrayProvider};
use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::filesystem::gfilesystem::g_file::GFile;
use crate::filesystem::gfilesystem::g_file_impl::{FsGetListing, FsrlLike, GFileImpl, HasFsrlRoot};
use crate::util::task::TaskMonitor;

/// Minimal stand-in FSRL used to parameterize [`GFileImpl`] for this filesystem's single file,
/// until a concrete `FSRL` type is ported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmlFsrl(String);

impl FsrlLike for XmlFsrl {
    fn fsrl_name(&self) -> String {
        self.0.rsplit('/').next().unwrap_or(self.0.as_str()).to_string()
    }

    fn fsrl_path(&self) -> String {
        self.0.clone()
    }

    fn append_path(&self, segment: &str) -> Self {
        if self.0.ends_with('/') {
            XmlFsrl(format!("{}{}", self.0, segment))
        } else {
            XmlFsrl(format!("{}/{}", self.0, segment))
        }
    }
}

/// Minimal stand-in FS marker used to parameterize [`GFileImpl`] for this filesystem's single
/// file, until a concrete `GFileSystem` implementer type is threaded through generically.
#[derive(Clone, Debug)]
pub struct XmlFsMarker {
    root: XmlFsrl,
}

impl HasFsrlRoot<XmlFsrl> for XmlFsMarker {
    fn root_fsrl(&self) -> &XmlFsrl {
        &self.root
    }
}

impl FsGetListing<XmlFsMarker, XmlFsrl> for XmlFsMarker {
    fn fs_get_listing(
        &self,
        _file: &dyn GFile<XmlFsMarker, XmlFsrl>,
    ) -> io::Result<Vec<Box<dyn GFile<XmlFsMarker, XmlFsrl>>>> {
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
    provider: Box<dyn ByteProvider>,
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
        provider: &mut dyn ByteProvider,
        monitor: &dyn TaskMonitor,
    ) -> io::Result<bool> {
        let magic = AndroidXmlConvertor::ANDROID_BINARY_XML_MAGIC;
        let actual_bytes = provider.read_bytes(0, magic.len())?;
        if actual_bytes != magic {
            return Ok(false);
        }

        let len = provider.length()?;
        let bytes = provider.read_bytes(0, len as usize)?;
        let mut out = String::new();
        Ok(AndroidXmlConvertor::convert(&bytes, &mut out, monitor).is_ok())
    }

    /// Mirrors the `AndroidXmlFileSystem(String, ByteProvider)` constructor.
    pub fn new(file_system_name: impl Into<String>, provider: Box<dyn ByteProvider>) -> Self {
        AndroidXmlFileSystem {
            file_system_name: file_system_name.into(),
            provider,
            payload_bytes: None,
        }
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
    pub fn get_payload_file(&self) -> Option<GFileImpl<XmlFsMarker, XmlFsrl>> {
        self.payload_file()
    }

    fn payload_file(&self) -> Option<GFileImpl<XmlFsMarker, XmlFsrl>> {
        let len = self.payload_bytes.as_ref()?.len() as i64;
        let marker = XmlFsMarker { root: XmlFsrl("/".to_string()) };
        Some(GFileImpl::from_filename(marker, None, "XML", false, len, None))
    }

    /// Mirrors `AndroidXmlFileSystem.isValid`.
    pub fn is_valid(&mut self, monitor: &dyn TaskMonitor) -> io::Result<bool> {
        Self::is_android_xml_file(self.provider.as_mut(), monitor)
    }

    /// Mirrors `AndroidXmlFileSystem.open`: converts the binary XML payload to text, falling
    /// back to a fixed error payload if conversion fails (matching Java's `catch (IOException)`
    /// -- see [`AndroidXmlConvertor::convert`](crate::file::seam_stubs::AndroidXmlConvertor::convert)
    /// doc for why `CancelledException` is folded into the same fallback here).
    pub fn open(&mut self, monitor: &dyn TaskMonitor) -> io::Result<()> {
        let len = self.provider.length()?;
        let bytes = self.provider.read_bytes(0, len as usize)?;

        let mut out = String::new();
        self.payload_bytes = Some(match AndroidXmlConvertor::convert(&bytes, &mut out, monitor) {
            Ok(()) => out.into_bytes(),
            Err(_) => b"failed to convert".to_vec(),
        });
        Ok(())
    }

    /// Mirrors `AndroidXmlFileSystem.getByteProvider`.
    pub fn get_byte_provider(
        &self,
        _file: &GFileImpl<XmlFsMarker, XmlFsrl>,
        _monitor: &dyn TaskMonitor,
    ) -> io::Result<Box<dyn ByteProvider>> {
        let bytes = self
            .payload_bytes
            .clone()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "filesystem not opened"))?;
        Ok(Box::new(ByteArrayProvider::new(bytes)))
    }

    /// Mirrors `AndroidXmlFileSystem.getListing`.
    pub fn get_listing(
        &self,
        _directory: Option<&GFileImpl<XmlFsMarker, XmlFsrl>>,
    ) -> io::Result<Vec<GFileImpl<XmlFsMarker, XmlFsrl>>> {
        Ok(self.payload_file().into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;

    struct VecByteProvider(Vec<u8>);

    impl ByteProvider for VecByteProvider {
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
        let fs = AndroidXmlFileSystem::new("androidxml", provider);
        assert_eq!(fs.name(), "androidxml");
        assert!(fs.get_payload_file().is_none());
    }

    #[test]
    fn get_byte_provider_errors_before_open() {
        let provider = Box::new(VecByteProvider(vec![0x03, 0x00, 0x08, 0x00]));
        let fs = AndroidXmlFileSystem::new("androidxml", provider);
        let payload = GFileImpl::from_filename(
            XmlFsMarker { root: XmlFsrl("/".to_string()) },
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
        let fs = AndroidXmlFileSystem::new("androidxml", provider);
        assert!(fs.get_listing(None).unwrap().is_empty());
    }
}
