//! Minimal forward-reference placeholders for [`super::oat_header`]'s dependencies that are not
//! ported yet.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::file::formats::android::oat::bundle::OatBundle;
use crate::file::formats::android::oat::oat_constants::OatConstants;

/// Placeholder for the unported Java type `OatDexFile`
/// (`ghidra.file.formats.android.oat.oatdexfile.OatDexFile`), referenced by
/// [`super::oat_header::OatHeader::parse`].
///
/// Concrete stub: Java is an abstract class with many version-specific subclasses, not an
/// interface. `OatHeader.parse` only stores the instances this factory returns in a list -- it
/// never calls a method on them -- so no fields or methods are included here.
pub struct OatDexFile;

/// Placeholder for the unported Java type `OatDexFileFactory`
/// (`ghidra.file.formats.android.oat.oatdexfile.OatDexFileFactory`), referenced by
/// [`super::oat_header::OatHeader::parse`].
pub struct OatDexFileFactory;

impl OatDexFileFactory {
    /// Mirrors `OatDexFileFactory.getOatDexFile(BinaryReader, String, OatBundle)`.
    ///
    /// The real factory dispatches to one of many version-specific `OatDexFile_*` subclass
    /// constructors (none ported yet) and throws `IOException` for an unrecognized version. This
    /// stub reproduces just the version check so callers see the same success/failure split.
    pub fn get_oat_dex_file(
        _reader: &mut dyn BinaryReader,
        oat_version: &str,
        _bundle: &dyn OatBundle,
    ) -> io::Result<OatDexFile> {
        if OatConstants::is_supported_version(oat_version) {
            Ok(OatDexFile)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported OAT version: {oat_version}"),
            ))
        }
    }
}
