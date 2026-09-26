//! Port of `ghidra.app.util.bin.format.pe.cli.blobs.CliSigAssembly`.
//!
//! Java's version `extends CliAbstractSig extends CliBlob`. Neither base class is ported yet
//! (`CliAbstractSig` in particular is a large grab-bag of CLI signature-parsing helpers this
//! type never calls into -- it only needs `CliBlob.getContentsReader()`/`getName()` and
//! `CliAbstractSig`'s four one-line [`CliRepresentable`] wrapper methods, which forward to the
//! `getRepresentationCommon` template method this class overrides). Rather than model that whole
//! hierarchy for four inherited one-liners, this type takes a
//! [`CliBlob`](crate::format::pe::cli::seam_stubs::CliBlob) forward-ref by reference at
//! construction time (matching Java's constructor argument) and implements
//! [`CliRepresentable`] directly, inlining the trivial `getRepresentationCommon` forwarding
//! `CliAbstractSig` would otherwise have provided.

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::pe::cli::cli_representable::CliRepresentable;
use crate::format::pe::cli::seam_stubs::CliBlob;
use crate::format::seam_stubs::CliStreamMetadata;
use crate::util::msg::Msg;

/// "RSA1" magic value from the `_RSAPUBKEY` structure.
const CLISIGASSEMBLY_RSA1_MAGIC: u64 = 0x3141_5352;
const CLISIGASSEMBLY_SHA1_LENGTH: usize = 20;
const BITS_PER_BYTE: i32 = 8;

/// Port of `ghidra.app.util.bin.format.pe.cli.blobs.CliSigAssembly`.
pub struct CliSigAssembly {
    name: String,
    sha1_hash: Vec<u8>,
    bit_length: i32,
    public_exponent: i32,
    public_key_signature: Vec<u8>,
}

impl CliSigAssembly {
    /// Port of `CliSigAssembly(CliBlob)`.
    ///
    /// Java's `super(blob)` chain (`CliAbstractSig(CliBlob)` -> `CliBlob(CliBlob)`, a copy
    /// constructor) is not reproduced: this type does not otherwise need to BE a `CliBlob`, only
    /// to read from one, so only the two values actually used (`getName()`, a fresh contents
    /// reader) are captured.
    pub fn new(blob: &dyn CliBlob) -> std::io::Result<Self> {
        let name = blob.get_name();
        let mut reader = blob.get_contents_reader();
        let sha1_hash = reader.read_next_byte_array(CLISIGASSEMBLY_SHA1_LENGTH)?;

        if reader.read_next_unsigned_int()? != CLISIGASSEMBLY_RSA1_MAGIC {
            Msg::warn(
                "CliSigAssembly",
                &format!("An Assembly blob was found without the expected RSA1 signature: {name}"),
            );
            return Ok(CliSigAssembly {
                name,
                sha1_hash,
                bit_length: 0,
                public_exponent: 0,
                public_key_signature: Vec::new(),
            });
        }

        let bit_length = reader.read_next_int()?;
        let public_exponent = reader.read_next_int()?;
        let public_key_signature = reader.read_next_byte_array((bit_length / BITS_PER_BYTE) as usize)?;

        Ok(CliSigAssembly { name, sha1_hash, bit_length, public_exponent, public_key_signature })
    }

    /// Port of `CliSigAssembly.getContentsDataType()`.
    ///
    /// Not yet buildable: Java's structure is `BYTE sha1[..]; DWORD magic; DWORD bitlen; DWORD
    /// pubexp; BYTE pubkey[..];`, and neither `ByteDataType` nor `DWordDataType` has a concrete,
    /// instantiable singleton in this crate yet (both are still traits -- see
    /// `crate::program::model::data::byte_data_type`/`dword_data_type`'s module docs).
    pub fn get_contents_data_type(
        &self,
    ) -> Result<
        Box<dyn crate::program::model::data::data_type::DataType>,
        crate::app::util::bin::struct_converter::ToDataTypeError,
    > {
        Err(crate::app::util::bin::struct_converter::ToDataTypeError::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "CliSigAssembly::get_contents_data_type requires BYTE/DWORD DataType singletons, \
             which are not yet ported to a concrete instantiable form",
        )))
    }

    /// Port of `CliSigAssembly.getContentsName()`.
    pub fn get_contents_name(&self) -> &'static str {
        "AssemblySig"
    }

    /// Port of `CliSigAssembly.getContentsComment()`.
    pub fn get_contents_comment(&self) -> &'static str {
        "Data describing an Assembly signature"
    }

    /// Port of `CliSigAssembly.getRepresentationCommon(CliStreamMetadata, boolean)`. `stream` and
    /// `isShort` are unused, exactly as in Java.
    fn get_representation_common(&self, _stream: Option<&dyn CliStreamMetadata>, _is_short: bool) -> String {
        format!(
            "Assembly:\r\tSHA1: {:?}\r\tBit length: {}\r\tPublic exponent: {}\r\tSignature: {:?}",
            self.sha1_hash, self.bit_length, self.public_exponent, self.public_key_signature
        )
    }
}

impl CliRepresentable for CliSigAssembly {
    fn get_representation(&self) -> String {
        self.get_representation_common(None, false)
    }

    fn get_short_representation(&self) -> String {
        self.get_representation_common(None, true)
    }

    fn get_representation_with_stream(&self, stream: &dyn CliStreamMetadata) -> String {
        self.get_representation_common(Some(stream), false)
    }

    fn get_short_representation_with_stream(&self, stream: &dyn CliStreamMetadata) -> String {
        self.get_representation_common(Some(stream), true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::filesystem::ghidra::g_binary_reader::GByteStore;

    struct VecProvider(Vec<u8>);

    impl GByteStore for VecProvider {
        fn length(&mut self) -> std::io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> std::io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> std::io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> std::io::Result<()> {
            Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> std::io::Result<()> {
            Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
        }
    }

    struct FixtureReader {
        provider: Rc<RefCell<dyn GByteStore>>,
        little_endian: bool,
        current_index: u64,
    }

    impl FixtureReader {
        fn new(data: Vec<u8>) -> Self {
            FixtureReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                little_endian: true,
                current_index: 0,
            }
        }
    }

    impl BinaryReader for FixtureReader {
        fn length(&self) -> std::io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn get_pointer_index(&self) -> u64 {
            self.current_index
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.current_index;
            self.current_index = index;
            old
        }
        fn is_little_endian(&self) -> bool {
            self.little_endian
        }
        fn set_little_endian(&mut self, is_little_endian: bool) {
            self.little_endian = is_little_endian;
        }
        fn read_byte(&self, index: u64) -> std::io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> std::io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }
        fn get_byte_provider(&self) -> Rc<RefCell<dyn GByteStore>> {
            Rc::clone(&self.provider)
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(FixtureReader {
                provider: Rc::clone(&self.provider),
                little_endian: self.little_endian,
                current_index: new_index,
            })
        }
    }

    struct FixtureBlob {
        name: String,
        bytes: Vec<u8>,
    }
    impl CliBlob for FixtureBlob {
        fn get_contents_reader(&self) -> Box<dyn BinaryReader> {
            Box::new(FixtureReader::new(self.bytes.clone()))
        }
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    fn rsa_blob_bytes(bit_length: i32, public_exponent: i32, key_byte: u8) -> Vec<u8> {
        let mut b = vec![0xAAu8; CLISIGASSEMBLY_SHA1_LENGTH];
        b.extend_from_slice(&(CLISIGASSEMBLY_RSA1_MAGIC as u32).to_le_bytes());
        b.extend_from_slice(&bit_length.to_le_bytes());
        b.extend_from_slice(&public_exponent.to_le_bytes());
        b.extend(std::iter::repeat(key_byte).take((bit_length / BITS_PER_BYTE) as usize));
        b
    }

    #[test]
    fn parses_rsa1_signature() {
        let blob = FixtureBlob { name: "AssemblySig_0".to_string(), bytes: rsa_blob_bytes(1024, 65537, 0xCD) };

        let sig = CliSigAssembly::new(&blob).unwrap();

        assert_eq!(sig.sha1_hash, vec![0xAAu8; 20]);
        assert_eq!(sig.bit_length, 1024);
        assert_eq!(sig.public_exponent, 65537);
        assert_eq!(sig.public_key_signature.len(), 1024 / 8);
        assert!(sig.public_key_signature.iter().all(|&b| b == 0xCD));
    }

    #[test]
    fn missing_rsa1_magic_leaves_key_fields_empty() {
        let mut bytes = vec![0x11u8; CLISIGASSEMBLY_SHA1_LENGTH];
        bytes.extend_from_slice(&0u32.to_le_bytes()); // wrong magic
        let blob = FixtureBlob { name: "AssemblySig_1".to_string(), bytes };

        let sig = CliSigAssembly::new(&blob).unwrap();

        assert_eq!(sig.sha1_hash, vec![0x11u8; 20]);
        assert_eq!(sig.bit_length, 0);
        assert!(sig.public_key_signature.is_empty());
    }

    #[test]
    fn contents_name_and_comment_match_java_constants() {
        let blob = FixtureBlob { name: "AssemblySig_0".to_string(), bytes: rsa_blob_bytes(8, 3, 0) };
        let sig = CliSigAssembly::new(&blob).unwrap();
        assert_eq!(sig.get_contents_name(), "AssemblySig");
        assert_eq!(sig.get_contents_comment(), "Data describing an Assembly signature");
    }

    #[test]
    fn representation_includes_hash_and_signature_fields() {
        let blob = FixtureBlob { name: "AssemblySig_0".to_string(), bytes: rsa_blob_bytes(8, 3, 0x7F) };
        let sig = CliSigAssembly::new(&blob).unwrap();
        let rep = sig.get_representation();
        assert!(rep.contains("Assembly:"));
        assert!(rep.contains("Bit length: 8"));
        assert!(rep.contains("Public exponent: 3"));
        // Short representation is identical to the long one, matching Java (both ignore isShort).
        assert_eq!(sig.get_short_representation(), rep);
    }
}
