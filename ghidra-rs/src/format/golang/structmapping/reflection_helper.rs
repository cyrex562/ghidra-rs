//! The data-type half of `ghidra.app.util.bin.format.golang.structmapping.ReflectionHelper`.
//!
//! Most of the Java class wraps `java.lang.reflect` (finding getters/setters/constructors,
//! invoking them, reading and writing fields, collecting annotated methods). In this port that
//! work is done at compile time by `#[derive(StructureMapped)]`, which emits typed function
//! pointers into [`StructureMappingDescriptor`](super::structure_mapped::StructureMappingDescriptor)
//! instead. What remains here are the helpers that pick Ghidra data types for mapped fields.

use std::io;

use crate::program::model::data::array_data_type::ArrayDataType;
use crate::program::model::data::data_type::DataType;

use super::data_type_mapper::DataTypeMapper;
use super::signedness::Signedness;
use super::structure_mapped::PrimitiveKind;

/// Port of `ReflectionHelper.getDataTypeSignedness(DataType)`: the signedness of an integer
/// data type (looking through a typedef), `Signed` for anything else.
pub fn get_data_type_signedness(dt: &dyn DataType) -> Signedness {
    let base;
    let dt = if dt.is_typedef() {
        match dt.typedef_base_data_type() {
            Some(b) => {
                base = b;
                base.as_ref()
            }
            None => dt,
        }
    }
    else {
        dt
    };
    match dt.as_abstract_integer() {
        Some(int_dt) => {
            if int_dt.is_signed() {
                Signedness::Signed
            }
            else {
                Signedness::Unsigned
            }
        }
        None => Signedness::Signed, // default
    }
}

/// Port of `ReflectionHelper.getPrimitiveOutputDataType`: the data type used to output a
/// primitive field in a variable length structure.
///
/// The mapper is asked for the primitive's default type name (`long`, `int`, `word`, `byte`); if
/// that type is missing or does not match the requested length and signedness, Java falls back
/// to `AbstractIntegerDataType.getSignedDataType`/`getUnsignedDataType`.
///
/// # Errors
/// When that fallback is needed: the built-in integer data types it returns
/// (`IntegerDataType`, `ShortDataType`, ...) exist in this port only as traits, with no concrete
/// implementation to construct, so the fallback is reported instead of guessed.
pub fn get_primitive_output_data_type(
    field_kind: PrimitiveKind,
    length: i32,
    signedness: Signedness,
    data_type_mapper: &DataTypeMapper,
) -> io::Result<Box<dyn DataType>> {
    let length = if length == -1 { field_kind.size_of() } else { length };
    let signedness = if signedness == Signedness::Unspecified {
        Signedness::Signed
    }
    else {
        signedness
    };
    let dt = data_type_mapper.get_data_type(field_kind.default_data_type_name());
    match dt {
        Some(dt) if matches(dt.as_ref(), length, signedness) => Ok(dt),
        _ => Err(io::Error::other(format!(
            "No {} integer data type of length {length} available: \
             AbstractIntegerDataType.get{}DataType is not ported",
            if signedness == Signedness::Signed { "signed" } else { "unsigned" },
            if signedness == Signedness::Signed { "Signed" } else { "Unsigned" },
        ))),
    }
}

/// Port of `ReflectionHelper.getArrayOutputDataType`: an array of the primitive element type,
/// as long as the field's current array value.
pub fn get_array_output_data_type(
    array_len: usize,
    element_kind: PrimitiveKind,
    length: i32,
    signedness: Signedness,
    data_type_mapper: &DataTypeMapper,
) -> io::Result<Box<dyn DataType>> {
    let element_dt = get_primitive_output_data_type(element_kind, length, signedness, data_type_mapper)?;
    let array = ArrayDataType::with_element_length(element_dt, array_len as i32, -1)
        .map_err(io::Error::other)?;
    Ok(Box::new(array))
}

/// `ReflectionHelper.matches(DataType, int, Signedness)`.
fn matches(dt: &dyn DataType, length: i32, signedness: Signedness) -> bool {
    (length == -1 || length == dt.get_length())
        && (signedness == Signedness::Unspecified
            || dt
                .as_abstract_integer()
                .is_some_and(|int_dt| (signedness == Signedness::Signed) == int_dt.is_signed()))
}
