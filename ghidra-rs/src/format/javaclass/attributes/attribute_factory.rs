//! Selects and constructs the `attribute_info` structure matching an attribute's name in the
//! constant pool.
//!
//! Ported from `ghidra.javaclass.format.attributes.AttributeFactory`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::javaclass::constantpool::abstract_constant_pool_info_java::AbstractConstantPoolInfoJava;
use crate::format::javaclass::constantpool::constant_pool_tags_java::CONSTANT_UTF8;
use crate::format::seam_stubs::{AbstractAttributeInfo, AttributeInfoKind, ConstantPoolUtf8Info};
use crate::util::msg::Msg;

/// Reads the `attribute_name_index` at the reader's current position, resolves it against
/// `constant_pool`, and constructs the `attribute_info` structure matching that name.
///
/// Mirrors `AttributeFactory.get(BinaryReader, AbstractConstantPoolInfoJava[])`.
///
/// # Errors
/// Returns an error if `attribute_name_index` is out of range for `constant_pool`, or if the
/// constant pool entry at that index is not a `CONSTANT_Utf8_info` entry.
pub fn get(
    reader: &mut BinaryReader,
    constant_pool: &[AbstractConstantPoolInfoJava],
) -> io::Result<AbstractAttributeInfo> {
    let attribute_name_index = reader.read_short(reader.get_pointer_index())?;

    if attribute_name_index < 1 || attribute_name_index as usize >= constant_pool.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid index"));
    }

    let entry = &constant_pool[attribute_name_index as usize];
    if entry.get_tag() != CONSTANT_UTF8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "constant pool entry is not a CONSTANT_Utf8_info",
        ));
    }
    let utf8 = ConstantPoolUtf8Info::from_entry(&*reader, entry)?;

    let kind = match utf8.get_string() {
        "AnnotationDefault" => AttributeInfoKind::AnnotationDefault,
        "BootstrapMethods" => AttributeInfoKind::BootstrapMethods,
        "Code" => AttributeInfoKind::Code,
        "ConstantValue" => AttributeInfoKind::ConstantValue,
        "Deprecated" => AttributeInfoKind::Deprecated,
        "EnclosingMethod" => AttributeInfoKind::EnclosingMethod,
        "Exceptions" => AttributeInfoKind::Exceptions,
        "InnerClasses" => AttributeInfoKind::InnerClasses,
        "LineNumberTable" => AttributeInfoKind::LineNumberTable,
        "LocalVariableTable" => AttributeInfoKind::LocalVariableTable,
        "LocalVariableTypeTable" => AttributeInfoKind::LocalVariableTypeTable,
        "MethodParameters" => AttributeInfoKind::MethodParameters,
        "Module" => AttributeInfoKind::Module,
        "ModuleMainClass" => AttributeInfoKind::ModuleMainClass,
        "ModulePackages" => AttributeInfoKind::ModulePackages,
        "NestHost" => AttributeInfoKind::NestHost,
        "NestMembers" => AttributeInfoKind::NestMembers,
        "RuntimeInvisibleAnnotations" => AttributeInfoKind::RuntimeInvisibleAnnotations,
        "RuntimeInvisibleParameterAnnotations" => {
            AttributeInfoKind::RuntimeInvisibleParameterAnnotations
        }
        "RuntimeVisibleAnnotations" => AttributeInfoKind::RuntimeVisibleAnnotations,
        "RuntimeVisibleParameterAnnotations" => {
            AttributeInfoKind::RuntimeVisibleParameterAnnotations
        }
        "Signature" => AttributeInfoKind::Signature,
        "SourceDebugExtension" => AttributeInfoKind::SourceDebugExtension,
        "SourceFile" => AttributeInfoKind::SourceFile,
        "StackMapTable" => AttributeInfoKind::StackMapTable,
        "Synthetic" => AttributeInfoKind::Synthetic,
        other => {
            Msg::warn(
                "AttributeFactory",
                &format!(
                    "Unknown attribute type: {} at index {}",
                    other,
                    (reader.get_pointer_index() as i64) - 2
                ),
            );
            AttributeInfoKind::Unsupported
        }
    };

    AbstractAttributeInfo::new(reader, kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a constant pool byte buffer containing a placeholder at index 0 (constant pool
    /// indices are 1-based) followed by a `CONSTANT_Utf8_info` entry for each name in `names`,
    /// then parses each entry (via the real, already-ported `AbstractConstantPoolInfoJava::new`)
    /// so the returned `Vec` lines up with `names` at indices `1..=names.len()`.
    fn build_constant_pool(names: &[&str]) -> (Vec<AbstractConstantPoolInfoJava>, Vec<u8>) {
        let mut bytes = Vec::new();
        let mut offsets = Vec::new();

        offsets.push(bytes.len() as u64);
        bytes.push(0u8); // index 0: unused by the JVM spec, harmless placeholder tag.

        for name in names {
            offsets.push(bytes.len() as u64);
            bytes.push(CONSTANT_UTF8);
            let name_bytes = name.as_bytes();
            bytes.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
            bytes.extend_from_slice(name_bytes);
        }

        let mut reader = BinaryReader::from_bytes(bytes.clone(), false);
        let entries = offsets
            .into_iter()
            .map(|offset| {
                reader.set_pointer_index(offset);
                AbstractConstantPoolInfoJava::new(&mut reader).expect("tag byte")
            })
            .collect();

        (entries, bytes)
    }

    /// Appends an `attribute_info` header (`attribute_name_index`, `attribute_length`) plus
    /// `body` bytes to `bytes`, returning the offset where the header starts.
    fn append_attribute(bytes: &mut Vec<u8>, name_index: u16, body: &[u8]) -> u64 {
        let offset = bytes.len() as u64;
        bytes.extend_from_slice(&name_index.to_be_bytes());
        bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
        bytes.extend_from_slice(body);
        offset
    }

    #[test]
    fn dispatches_known_attribute_name_to_matching_kind() {
        let (entries, mut bytes) = build_constant_pool(&["Deprecated"]);
        let offset = append_attribute(&mut bytes, 1, &[]);

        let mut reader = BinaryReader::from_bytes(bytes, false);
        reader.set_pointer_index(offset);

        let attr = get(&mut reader, &entries).expect("known attribute should dispatch");

        assert_eq!(attr.kind(), AttributeInfoKind::Deprecated);
        assert_eq!(attr.get_offset(), offset);
        assert_eq!(attr.get_attribute_name_index(), 1);
        assert_eq!(attr.get_attribute_length(), 0);
    }

    #[test]
    fn unknown_attribute_name_falls_back_to_unsupported() {
        let (entries, mut bytes) = build_constant_pool(&["TotallyMadeUpAttribute"]);
        let offset = append_attribute(&mut bytes, 1, &[]);

        let mut reader = BinaryReader::from_bytes(bytes, false);
        reader.set_pointer_index(offset);

        let attr = get(&mut reader, &entries).expect("unknown attribute should still dispatch");

        assert_eq!(attr.kind(), AttributeInfoKind::Unsupported);
    }

    #[test]
    fn skips_attribute_body_leaving_reader_at_next_attribute() {
        let (entries, mut bytes) = build_constant_pool(&["Synthetic"]);
        let body = [0xAAu8, 0xBB, 0xCC, 0xDD];
        let offset = append_attribute(&mut bytes, 1, &body);
        let next_attribute_offset = bytes.len() as u64;

        let mut reader = BinaryReader::from_bytes(bytes, false);
        reader.set_pointer_index(offset);

        let attr = get(&mut reader, &entries).expect("known attribute should dispatch");

        assert_eq!(attr.get_attribute_length(), body.len() as i32);
        assert_eq!(reader.get_pointer_index(), next_attribute_offset);
    }

    #[test]
    fn errors_on_attribute_name_index_below_one() {
        let (entries, mut bytes) = build_constant_pool(&["Deprecated"]);
        let offset = append_attribute(&mut bytes, 0, &[]);

        let mut reader = BinaryReader::from_bytes(bytes, false);
        reader.set_pointer_index(offset);

        assert!(get(&mut reader, &entries).is_err());
    }

    #[test]
    fn errors_on_attribute_name_index_beyond_constant_pool() {
        let (entries, mut bytes) = build_constant_pool(&["Deprecated"]);
        let out_of_range = entries.len() as u16;
        let offset = append_attribute(&mut bytes, out_of_range, &[]);

        let mut reader = BinaryReader::from_bytes(bytes, false);
        reader.set_pointer_index(offset);

        assert!(get(&mut reader, &entries).is_err());
    }

    #[test]
    fn errors_when_constant_pool_entry_is_not_utf8() {
        let (mut entries, mut bytes) = build_constant_pool(&["Deprecated"]);

        // Overwrite index 1's tag with CONSTANT_INTEGER instead of CONSTANT_UTF8.
        let integer_offset = entries[1].get_offset();
        bytes[integer_offset as usize] =
            crate::format::javaclass::constantpool::constant_pool_tags_java::CONSTANT_INTEGER;
        let mut reader = BinaryReader::from_bytes(bytes.clone(), false);
        reader.set_pointer_index(integer_offset);
        entries[1] = AbstractConstantPoolInfoJava::new(&mut reader).expect("tag byte");

        let offset = append_attribute(&mut bytes, 1, &[]);
        let mut reader = BinaryReader::from_bytes(bytes, false);
        reader.set_pointer_index(offset);

        assert!(get(&mut reader, &entries).is_err());
    }
}
