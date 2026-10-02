//! Port of `ghidra.pcode.utils.SlaFormat`: the on-disk `.sla` file format (a 4-byte `sla<version>`
//! header followed by a zlib-deflated packed-encoding stream) and its attribute/element ids.
//!
//! Java's class is a holder of statics, so this is a plain module. The 55 `ATTRIB_*` and 88
//! `ELEM_*` ids Java declares here already live (with the same names and numbers) in
//! [`crate::program::model::pcode`] (`ids.rs`), where the ported `.sla` decoders
//! ([`SleighLanguage::decode`](crate::program::model::lang::sleigh::SleighLanguage::decode) and
//! friends) use them; they are re-exported below rather than duplicated.
//!
//! `ResourceFile` arguments are plain filesystem paths.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;

use crate::program::model::address::factory::AddressFactory;
use crate::program::model::pcode::{PackedDecode, PackedEncode};

pub use crate::program::model::pcode::{
    ATTRIB_ALIGN, ATTRIB_BASE, ATTRIB_BIGENDIAN, ATTRIB_CODE, ATTRIB_CONTAIN, ATTRIB_CONTEXT,
    ATTRIB_CT, ATTRIB_DEFAULTSPACE, ATTRIB_DELAY, ATTRIB_ENDBIT, ATTRIB_ENDBYTE, ATTRIB_FIRST,
    ATTRIB_FLOW, ATTRIB_HIGH, ATTRIB_I, ATTRIB_ID, ATTRIB_INDEX, ATTRIB_LABELS, ATTRIB_LENGTH,
    ATTRIB_LINE, ATTRIB_LOW, ATTRIB_MASK, ATTRIB_MAXDELAY, ATTRIB_MINLEN, ATTRIB_NAME,
    ATTRIB_NONZERO, ATTRIB_NUMBER, ATTRIB_NUMCT, ATTRIB_NUMSECTIONS, ATTRIB_OFF, ATTRIB_PARENT,
    ATTRIB_PHYSICAL, ATTRIB_PIECE, ATTRIB_PLUS, ATTRIB_S, ATTRIB_SCOPE, ATTRIB_SCOPESIZE,
    ATTRIB_SECTION, ATTRIB_SHIFT, ATTRIB_SIGNBIT, ATTRIB_SIZE, ATTRIB_SOURCE, ATTRIB_SPACE,
    ATTRIB_STARTBIT, ATTRIB_STARTBYTE, ATTRIB_SUBSYM, ATTRIB_SYMBOLSIZE, ATTRIB_TABLE,
    ATTRIB_UNIQBASE, ATTRIB_UNIQMASK, ATTRIB_VAL, ATTRIB_VARNODE, ATTRIB_VERSION,
    ATTRIB_WORDSIZE,
};
pub use crate::program::model::pcode::{
    ELEM_AND_EXP, ELEM_COMBINE_PAT, ELEM_COMMIT, ELEM_CONSTRUCTOR, ELEM_CONSTRUCT_TPL,
    ELEM_CONST_CURSPACE, ELEM_CONST_CURSPACE_SIZE, ELEM_CONST_FLOWDEST, ELEM_CONST_FLOWDEST_SIZE,
    ELEM_CONST_FLOWREF, ELEM_CONST_FLOWREF_SIZE, ELEM_CONST_HANDLE, ELEM_CONST_NEXT,
    ELEM_CONST_NEXT2, ELEM_CONST_REAL, ELEM_CONST_RELATIVE, ELEM_CONST_SPACEID, ELEM_CONST_START,
    ELEM_CONTEXTFIELD, ELEM_CONTEXT_OP, ELEM_CONTEXT_PAT, ELEM_CONTEXT_SYM,
    ELEM_CONTEXT_SYM_HEAD, ELEM_DECISION, ELEM_DIV_EXP, ELEM_END_EXP, ELEM_END_SYM,
    ELEM_END_SYM_HEAD, ELEM_EPSILON_SYM, ELEM_EPSILON_SYM_HEAD, ELEM_HANDLE_TPL,
    ELEM_INSTRUCT_PAT, ELEM_INTB, ELEM_LSHIFT_EXP, ELEM_MASK_WORD, ELEM_MINUS_EXP, ELEM_MULT_EXP,
    ELEM_NAMETAB, ELEM_NAME_SYM, ELEM_NAME_SYM_HEAD, ELEM_NEXT2_EXP, ELEM_NEXT2_SYM,
    ELEM_NEXT2_SYM_HEAD, ELEM_NOT_EXP, ELEM_NULL, ELEM_OPER, ELEM_OPERAND_EXP, ELEM_OPERAND_SYM,
    ELEM_OPERAND_SYM_HEAD, ELEM_OPPRINT, ELEM_OP_TPL, ELEM_OR_EXP, ELEM_OR_PAT, ELEM_PAIR,
    ELEM_PAT_BLOCK, ELEM_PLUS_EXP, ELEM_PRINT, ELEM_RSHIFT_EXP, ELEM_SCOPE, ELEM_SLEIGH,
    ELEM_SOURCEFILE, ELEM_SOURCEFILES, ELEM_SPACE, ELEM_SPACES, ELEM_SPACE_OTHER,
    ELEM_SPACE_UNIQUE, ELEM_START_EXP, ELEM_START_SYM, ELEM_START_SYM_HEAD, ELEM_SUBTABLE_SYM,
    ELEM_SUBTABLE_SYM_HEAD, ELEM_SUB_EXP, ELEM_SYMBOL_TABLE, ELEM_TOKENFIELD, ELEM_USEROP,
    ELEM_USEROP_HEAD, ELEM_VALUEMAP_SYM, ELEM_VALUEMAP_SYM_HEAD, ELEM_VALUETAB, ELEM_VALUE_SYM,
    ELEM_VALUE_SYM_HEAD, ELEM_VAR, ELEM_VARLIST_SYM, ELEM_VARLIST_SYM_HEAD, ELEM_VARNODE_SYM,
    ELEM_VARNODE_SYM_HEAD, ELEM_VARNODE_TPL, ELEM_XOR_EXP,
};

/// `SlaFormat.FORMAT_VERSION`: the `.sla` format version this code reads and writes.
pub const FORMAT_VERSION: i32 = 4;

/// `SlaFormat.MAX_FILE_SIZE`: the largest decompressed `.sla` stream accepted (16 MiB).
pub const MAX_FILE_SIZE: usize = 1 << 24;

/// Port of `isSlaFormat(InputStream)`: whether `stream` starts with a current-version header.
/// Consumes the 4 header bytes.
pub fn is_sla_format(stream: &mut dyn Read) -> io::Result<bool> {
    Ok(get_sla_format(stream)? == FORMAT_VERSION)
}

/// Port of `getSlaFormat(InputStream)`: the format version in `stream`'s `sla<version>` header,
/// or -1 if there is no such header. Consumes the 4 header bytes.
pub fn get_sla_format(stream: &mut dyn Read) -> io::Result<i32> {
    let mut header = [0u8; 4];
    // Java's single `stream.read(header)`; a short read means "no header".
    let mut read_len = 0;
    while read_len < 4 {
        let n = stream.read(&mut header[read_len..])?;
        if n == 0 {
            break;
        }
        read_len += n;
    }
    if read_len < 4 {
        return Ok(-1);
    }
    if &header[..3] != b"sla" {
        return Ok(-1);
    }
    Ok(header[3] as i32)
}

/// Port of `writeSlaHeader(OutputStream)`.
pub fn write_sla_header(stream: &mut dyn Write) -> io::Result<()> {
    stream.write_all(b"sla")?;
    stream.write_all(&[FORMAT_VERSION as u8])
}

/// Port of `buildEncoder(ResourceFile)`: creates `sleigh_file`, writes the header and returns an
/// encoder whose output is deflated into the rest of the file. Finish the returned stream
/// (`into_inner().finish()`) to flush the compressed data.
pub fn build_encoder(sleigh_file: &Path) -> io::Result<PackedEncode<ZlibEncoder<File>>> {
    let mut stream = File::create(sleigh_file)?;
    write_sla_header(&mut stream)?;
    Ok(PackedEncode::new(ZlibEncoder::new(stream, Compression::default())))
}

/// Port of `buildDecoder(ResourceFile)`: reads `sleigh_file`, checks its header and returns a
/// decoder over the inflated packed stream. Java's no-factory `PackedDecode()` is completed with
/// an address factory later by the language decode; this port's [`PackedDecode`] takes one up
/// front, so the caller supplies it (an empty factory is fine: decoding a `.sla` creates the
/// language's own spaces).
///
/// # Errors
/// `"Missing SLA format header"`, an IO/inflate error, or a stream larger than
/// [`MAX_FILE_SIZE`].
pub fn build_decoder(sleigh_file: &Path, addr_factory: Arc<dyn AddressFactory>) -> io::Result<PackedDecode> {
    let mut stream = File::open(sleigh_file)?;
    if !is_sla_format(&mut stream)? {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Missing SLA format header"));
    }
    let data = inflate_limited(stream)?;
    Ok(PackedDecode::new(addr_factory, data))
}

/// Java's `decoder.open(MAX_FILE_SIZE, ".sla file loader")` + `ingestStream(InflaterInputStream)`:
/// inflates the remainder of `stream`, failing if it exceeds [`MAX_FILE_SIZE`].
fn inflate_limited(stream: impl Read) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    let read = ZlibDecoder::new(stream).take(MAX_FILE_SIZE as u64 + 1).read_to_end(&mut data)?;
    if read > MAX_FILE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            ".sla file loader: Data too large",
        ));
    }
    Ok(data)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::program::model::address::DefaultAddressFactory;
    use crate::program::model::lang::sleigh::SleighLanguage;

    #[test]
    fn header_round_trip_and_rejection() {
        let mut out = Vec::new();
        write_sla_header(&mut out).unwrap();
        assert_eq!(out, b"sla\x04");
        assert!(is_sla_format(&mut &out[..]).unwrap());
        assert_eq!(get_sla_format(&mut &b"sla\x03"[..]).unwrap(), 3);
        assert_eq!(get_sla_format(&mut &b"slb\x04"[..]).unwrap(), -1);
        assert_eq!(get_sla_format(&mut &b"sl"[..]).unwrap(), -1);
    }

    #[test]
    fn encoder_output_decodes() {
        let dir = std::env::temp_dir().join(format!("sla_format_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.sla");
        let mut enc = build_encoder(&path).unwrap();
        enc.output_stream().write_all(&[1, 2, 3, 4, 5]).unwrap();
        enc.into_inner().finish().unwrap();
        let mut f = File::open(&path).unwrap();
        assert!(is_sla_format(&mut f).unwrap());
        assert_eq!(inflate_limited(f).unwrap(), vec![1, 2, 3, 4, 5]);
        let missing = dir.join("bad.sla");
        std::fs::write(&missing, b"xxxx").unwrap();
        let err = build_decoder(&missing, Arc::new(DefaultAddressFactory::new(vec![]))).err().unwrap();
        assert_eq!(err.to_string(), "Missing SLA format header");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A `.sla` from the local (git-ignored) Ghidra distribution, when present.
    pub(crate) fn dist_sla(processor: &str, file: &str) -> Option<std::path::PathBuf> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../tools/ghidra-dist/ghidra_12.1.2_PUBLIC/Ghidra/Processors/{processor}/data/languages/{file}"
        ));
        path.exists().then_some(path)
    }

    fn decode_dist(processor: &str, file: &str, id: &str) -> Option<SleighLanguage> {
        let path = dist_sla(processor, file)?;
        let decoder = build_decoder(&path, Arc::new(DefaultAddressFactory::new(vec![]))).unwrap();
        Some(SleighLanguage::decode(&decoder, id.to_string()).unwrap())
    }

    /// Decodes the real `x86-64.sla` end to end (header, inflate, every symbol and constructor).
    #[test]
    fn decodes_real_x86_64_sla() {
        let Some(language) = decode_dist("x86", "x86-64.sla", "x86:LE:64:default") else {
            return;
        };
        use crate::program::model::address::factory::AddressFactory as _;
        let ram = language.get_address_factory().get_default_address_space().unwrap();
        assert_eq!(ram.name(), "ram");
        assert_eq!(ram.size(), 64);
        assert!(!language.is_big_endian());
    }

    #[test]
    fn decodes_real_aarch64_sla() {
        let Some(language) = decode_dist("AARCH64", "AARCH64.sla", "AARCH64:LE:64:v8A") else {
            return;
        };
        use crate::program::model::address::factory::AddressFactory as _;
        let ram = language.get_address_factory().get_default_address_space().unwrap();
        assert_eq!(ram.size(), 64);
        assert!(!language.is_big_endian());
    }
}
