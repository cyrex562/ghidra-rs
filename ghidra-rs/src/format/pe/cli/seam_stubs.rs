//! Minimal placeholder types for `ghidra.app.util.bin.format.pe.cli` classes referenced by a
//! ported type in this module before the real Rust port of that class exists yet. See
//! `STUBS.tsv` for provenance.

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::pe::pe_markupable::PeMarkupable;

/// Placeholder for `ghidra.app.util.bin.format.pe.cli.streams.CliAbstractStream`, referenced by
/// [`CliStreamHeader`](crate::format::pe::cli::cli_stream_header::CliStreamHeader) before the
/// real class (and the rest of the `cli.streams` subpackage) is ported. The real Java class
/// `implements PeMarkupable`; modeled here as exactly that supertrait plus nothing else, since
/// `CliStreamHeader::markup` only ever calls through to `stream.markup(...)`.
pub trait CliAbstractStream: PeMarkupable {}

/// Placeholder for `ghidra.app.util.bin.format.pe.cli.blobs.CliBlob`, referenced by
/// [`CliSigAssembly`](crate::format::pe::cli::blobs::cli_sig_assembly::CliSigAssembly) before the
/// real class (and the rest of the `cli.blobs` subpackage) is ported. Only the two accessors
/// `CliSigAssembly`'s constructor needs: a fresh reader positioned at the blob's contents, and
/// the blob's (already-computed, `getContentsName() + "_" + streamIndex`) display name.
pub trait CliBlob: Send + Sync {
    /// `CliBlob.getContentsReader()`.
    fn get_contents_reader(&self) -> Box<dyn BinaryReader>;
    /// `CliBlob.getName()`.
    fn get_name(&self) -> String;
}
