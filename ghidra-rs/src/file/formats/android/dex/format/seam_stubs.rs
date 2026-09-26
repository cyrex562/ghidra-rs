//! Minimal placeholder types for DEX format classes referenced by
//! [`EncodedValue`](crate::file::formats::android::dex::format::encoded_value::EncodedValue)
//! before their real ports exist. See `STUBS.tsv` for provenance.

use std::io;
use std::sync::Arc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::leb128_info::LEB128Info;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::file::formats::android::dex::format::encoded_value::EncodedValue;
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type::DataType;
use crate::sarif::seam_stubs::StructureDataType;

/// Placeholder for `ghidra.file.formats.android.dex.format.EncodedArray`, referenced by
/// [`EncodedValue`]'s `VALUE_ARRAY` case.
///
/// Byte-consumption is fully faithful to the real Java constructor (it decodes `size`
/// [`EncodedValue`]s from a cloned reader purely to measure how many bytes they occupy, then
/// re-reads that many raw bytes from the original reader -- exactly mirroring
/// `EncodedArray(BinaryReader)`, including discarding the decoded values themselves), since
/// [`EncodedValue`] -- the only real dependency this needs -- already exists. What is *not*
/// reproduced is `EncodedArray`'s own `toDataType()` name/structure derivation in full generality;
/// [`EncodedArray::to_data_type`] instead produces a structurally-equivalent placeholder (a
/// `ULEB128`-sized `size` field plus a raw byte-array `values` field, matching the *actual*
/// fields Java's own `toDataType()` emits -- the commented-out per-value expansion in the real
/// source is dead code there too), so nothing is lost relative to the real class as it stands
/// today.
pub struct EncodedArray {
    size_length: i32,
    values: Vec<u8>,
}

impl EncodedArray {
    /// Port of `EncodedArray(BinaryReader)`.
    pub fn read(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let leb128 = LEB128Info::unsigned(reader)?;
        let size = leb128.as_u_int32().map_err(io::Error::from)?;
        let size_length = leb128.get_length();

        let mut ev_reader = reader.clone_reader();
        let start = reader.get_pointer_index();
        for _ in 0..size {
            EncodedValue::new(&mut *ev_reader)?;
        }
        let n_bytes = (ev_reader.get_pointer_index() - start) as usize;
        let values = reader.read_next_byte_array(n_bytes)?;

        Ok(EncodedArray { size_length, values })
    }

    /// Port of `EncodedArray.getValues()` (the re-read raw bytes, not the transient decoded
    /// values).
    pub fn get_values(&self) -> &[u8] {
        &self.values
    }

    /// Port of `EncodedArray.toDataType()`. See the struct docs for the placeholder shape.
    pub fn to_data_type(&self) -> Box<dyn DataType> {
        let cp = CategoryPath::parse("/dex/encoded_array").expect("valid category path");
        let mut structure = StructureDataType::new(cp, &format!("encoded_array_{}", self.values.len()), 0);
        structure.add(Arc::new(UlebPlaceholderDataType), self.size_length, Some("size".to_string()), None);
        if !self.values.is_empty() {
            structure.add(
                Arc::new(ByteArrayPlaceholderDataType { length: self.values.len() as i32 }),
                self.values.len() as i32,
                Some("values".to_string()),
                None,
            );
        }
        Box::new(structure)
    }
}

/// Placeholder for `ghidra.file.formats.android.dex.format.EncodedAnnotation`, referenced by
/// [`EncodedValue`]'s `VALUE_ANNOTATION` case.
///
/// `AnnotationElement` (the real class's `List<AnnotationElement> elements` element type) is
/// itself just `uleb128(nameIndex) + EncodedValue` (see `AnnotationElement.java`) -- simple enough,
/// and dependent only on [`EncodedValue`] (already real), that its shape is inlined here directly
/// as a `(name_index_length, EncodedValue)` pair rather than adding a *second* forward-stub layer
/// for a type this class doesn't reference by name. When `EncodedAnnotation` itself is ported for
/// real (a separate, not-yet-scheduled `PORT_MANIFEST.tsv` row), it should use the real
/// `AnnotationElement` type directly; this placeholder is not registered as an importer of it.
pub struct EncodedAnnotation {
    type_index_length: i32,
    size_length: i32,
    /// `(nameIndexLength, value)` pairs, standing in for `List<AnnotationElement>`.
    elements: Vec<(i32, EncodedValue)>,
}

impl EncodedAnnotation {
    /// Port of `EncodedAnnotation(BinaryReader)`.
    pub fn read(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let leb128 = LEB128Info::unsigned(reader)?;
        let type_index_length = leb128.get_length();

        let leb128 = LEB128Info::unsigned(reader)?;
        let size = leb128.as_u_int32().map_err(io::Error::from)?;
        let size_length = leb128.get_length();

        let mut elements = Vec::with_capacity(size as usize);
        for _ in 0..size {
            let name_leb128 = LEB128Info::unsigned(reader)?;
            let name_index_length = name_leb128.get_length();
            let value = EncodedValue::new(reader)?;
            elements.push((name_index_length, value));
        }

        Ok(EncodedAnnotation { type_index_length, size_length, elements })
    }

    /// Port of `EncodedAnnotation.toDataType()`, inlining `AnnotationElement.toDataType()`'s
    /// naming/layout for each `(nameIndexLength, EncodedValue)` pair (see the struct docs).
    ///
    /// The placeholder `StructureDataType` has no rename-after-construction operation (unlike
    /// Java's `structure.setName(builder.toString())`, called only once the full name is known
    /// after visiting every element), so -- mirroring the two-pass shape this constraint forces --
    /// every element's `(name, elem_structure)` pair is computed first, the full name is
    /// assembled from those names, and the outer structure is then built once with its final name
    /// already in hand.
    pub fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let cp = CategoryPath::parse("/dex/encoded_annotation").expect("valid category path");

        let mut name = format!(
            "encoded_annotation_{}_{}_{}_",
            self.type_index_length,
            self.size_length,
            self.elements.len()
        );

        let mut built_elements: Vec<(Arc<dyn DataType>, i32)> = Vec::with_capacity(self.elements.len());
        for (name_index_length, value) in &self.elements {
            let value_dt: Arc<dyn DataType> = Arc::from(value.to_data_type()?);
            let elem_name = format!("annotation_element_{}_{}", name_index_length, value_dt.get_name());

            let mut elem_structure = StructureDataType::new(cp.clone(), &elem_name, 0);
            elem_structure.add(Arc::new(UlebPlaceholderDataType), *name_index_length, Some("nameIndex".to_string()), None);
            let value_len = value_dt.get_length();
            elem_structure.add(value_dt, value_len, Some("value".to_string()), None);

            let elem_len = elem_structure.get_length();
            built_elements.push((Arc::new(elem_structure), elem_len));
            name.push_str(&elem_name);
        }

        let mut structure = StructureDataType::new(cp, &name, 0);
        structure.add(Arc::new(UlebPlaceholderDataType), self.type_index_length, Some("typeIndex".to_string()), None);
        structure.add(Arc::new(UlebPlaceholderDataType), self.size_length, Some("size".to_string()), None);
        for (index, (elem_dt, elem_len)) in built_elements.into_iter().enumerate() {
            structure.add(elem_dt, elem_len, Some(format!("element{index}")), None);
        }

        Ok(Box::new(structure))
    }
}

/// Minimal stand-in for `ghidra.app.util.bin.StructConverter.ULEB128`
/// (`UnsignedLeb128DataType.dataType`), used with an explicit override length (mirroring
/// `Structure.add(DataType, int length, String, String)`). See
/// [`crate::format::elf::info::elf_note`]'s `DWordPlaceholderDataType` for the identical situation
/// with a different leaf type.
pub(crate) struct UlebPlaceholderDataType;

impl DataType for UlebPlaceholderDataType {
    fn get_name(&self) -> String {
        "uleb128".to_string()
    }
    fn get_length(&self) -> i32 {
        -1
    }
}

/// Minimal stand-in for `new ArrayDataType(BYTE, length, BYTE.getLength())`, used for the
/// `values` field of [`EncodedArray::to_data_type`].
struct ByteArrayPlaceholderDataType {
    length: i32,
}

impl DataType for ByteArrayPlaceholderDataType {
    fn get_name(&self) -> String {
        format!("byte[{}]", self.length.max(0))
    }
    fn get_length(&self) -> i32 {
        self.length
    }
}
