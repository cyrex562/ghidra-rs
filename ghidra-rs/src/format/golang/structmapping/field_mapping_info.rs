//! Port of `ghidra.app.util.bin.format.golang.structmapping.FieldMappingInfo`.

use std::io;
use std::sync::Arc;

use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::structure::Structure;
use crate::program::model::listing::CommentType;

use super::data_type_mapper::DataTypeMapper;
use super::field_context::FieldContext;
use super::markup_session::MarkupSession;
use super::reflection_helper;
use super::signedness::Signedness;
use super::structure_mapped::{FieldDescriptor, FieldReadFn, FieldValue, FieldValueKind, StructureMapped};

/// A snapshot of the parts of a Ghidra `DataTypeComponent` the mapper uses.
///
/// Java holds on to the live `DataTypeComponent`; this port copies out its field name, offset,
/// length and data type when the mapping is bound, so the mapping info stays `Send + Sync` and
/// can be shared by every instance read through it.
#[derive(Clone)]
pub struct DtcInfo {
    /// `DataTypeComponent.getFieldName()`.
    pub field_name: Option<String>,
    /// `DataTypeComponent.getOffset()`.
    pub offset: i32,
    /// `DataTypeComponent.getLength()`.
    pub length: i32,
    /// `DataTypeComponent.getDataType()`.
    pub data_type: Arc<dyn DataType>,
}

impl DtcInfo {
    /// Copies the relevant parts of `dtc`.
    pub fn from_component(dtc: &dyn DataTypeComponent) -> Self {
        DtcInfo {
            field_name: dtc.get_field_name(),
            offset: dtc.get_offset(),
            length: dtc.get_length(),
            data_type: Arc::from(dtc.get_data_type()),
        }
    }
}

impl std::fmt::Debug for DtcInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DtcInfo")
            .field("field_name", &self.field_name)
            .field("offset", &self.offset)
            .field("length", &self.length)
            .field("data_type", &self.data_type.get_name())
            .finish()
    }
}

/// One `FieldMarkupFunction` of a field, in the order Java adds them
/// (`addMarkupNestedFuncs`, `addCommentMarkupFuncs`, `addMarkupReferenceFunc`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldMarkupKind {
    /// `@Markup` on the field: mark up the nested structure value.
    Nested,
    /// `@PlateComment` on the field.
    PlateComment,
    /// `@EOLComment` on the field.
    EolComment,
    /// `@MarkupReference` on the field.
    Reference,
}

/// Immutable information needed to deserialize a field in a structure mapped class.
pub struct FieldMappingInfo<T: 'static> {
    descriptor: &'static FieldDescriptor<T>,
    dtc_field_name: String,
    dtc: Option<DtcInfo>,
    signedness: Signedness,
    length: i32,
    markup_funcs: Vec<FieldMarkupKind>,
    reader_func: Option<FieldReaderFunc<T>>,
}

/// How a field's value is deserialized (`FieldMappingInfo.readerFunc`).
enum FieldReaderFunc<T: 'static> {
    /// `getReadPrimitiveValueFunc`.
    Primitive,
    /// A custom `readFunc`, or the generated nested-structure reader.
    Func(FieldReadFn<T>),
}

impl<T: StructureMapped> FieldMappingInfo<T> {
    /// Creates a `FieldMappingInfo` for a field of a fixed-length structure.
    ///
    /// Port of `FieldMappingInfo.createEarlyBinding`: an unspecified signedness is taken from
    /// the structure field's data type, and an unspecified length (`-1`) from the structure
    /// field's length.
    pub fn create_early_binding(
        descriptor: &'static FieldDescriptor<T>,
        dtc: DtcInfo,
        signedness: Signedness,
        length: i32,
    ) -> Self {
        let signedness = if signedness == Signedness::Unspecified {
            reflection_helper::get_data_type_signedness(dtc.data_type.as_ref())
        }
        else {
            signedness
        };
        let length = if length != -1 { length } else { dtc.length };
        let name = dtc.field_name.clone().unwrap_or_default();
        Self::new(descriptor, name, Some(dtc), signedness, length)
    }

    /// Creates a `FieldMappingInfo` for a field of a variable-length structure, which has no
    /// pre-defined Ghidra structure data type.
    ///
    /// Port of `FieldMappingInfo.createLateBinding`.
    pub fn create_late_binding(
        descriptor: &'static FieldDescriptor<T>,
        field_name: &str,
        signedness: Signedness,
        length: i32,
    ) -> Self {
        Self::new(descriptor, field_name.to_string(), None, signedness, length)
    }

    fn new(
        descriptor: &'static FieldDescriptor<T>,
        dtc_field_name: String,
        dtc: Option<DtcInfo>,
        signedness: Signedness,
        length: i32,
    ) -> Self {
        FieldMappingInfo {
            descriptor,
            dtc_field_name,
            dtc,
            signedness,
            length,
            markup_funcs: Vec::new(),
            reader_func: None,
        }
    }

    /// The static description of the Rust field (Java `getField()`).
    pub fn get_field(&self) -> &'static FieldDescriptor<T> {
        self.descriptor
    }

    /// The name of the Ghidra structure field (`getFieldName()`).
    pub fn get_field_name(&self) -> &str {
        &self.dtc_field_name
    }

    /// The bound structure field, `None` for late binding (`getDtc()`).
    pub fn get_dtc(&self) -> Option<&DtcInfo> {
        self.dtc.as_ref()
    }

    /// The bound structure field, or the field of that name found in `structure` for late
    /// binding (`getDtc(Structure)`).
    pub fn get_dtc_in(&self, structure: Option<&dyn Structure>) -> Option<DtcInfo> {
        match &self.dtc {
            Some(dtc) => Some(dtc.clone()),
            None => structure.and_then(|s| self.find_dtc(s)),
        }
    }

    /// The structure field whose name matches exactly (`findDtc(Structure)`).
    pub fn find_dtc(&self, structure: &dyn Structure) -> Option<DtcInfo> {
        structure
            .get_defined_components()
            .into_iter()
            .find(|c| c.get_field_name().as_deref() == Some(self.dtc_field_name.as_str()))
            .map(|c| DtcInfo::from_component(c.as_ref()))
    }

    /// The field's markup functions (`getMarkupFuncs()`).
    pub fn get_markup_funcs(&self) -> &[FieldMarkupKind] {
        &self.markup_funcs
    }

    /// `getLength()`.
    pub fn get_length(&self) -> i32 {
        self.length
    }

    /// `getSignedness()`.
    pub fn get_signedness(&self) -> Signedness {
        self.signedness
    }

    /// `isUnsigned()`.
    pub fn is_unsigned(&self) -> bool {
        self.signedness == Signedness::Unsigned
    }

    /// `isStructureMappedType()`.
    pub fn is_structure_mapped_type(&self) -> bool {
        self.descriptor.kind == FieldValueKind::StructureMapped
    }

    /// Port of `addMarkupNestedFuncs()`.
    ///
    /// Java rejects `@Markup` on a field whose type is not structure mapped; the derive macro
    /// already requires a `#[markup]` field's type to implement the markup traits, so that check
    /// happens at compile time.
    pub fn add_markup_nested_funcs(&mut self) {
        if self.descriptor.markup_nested.is_some() {
            self.markup_funcs.push(FieldMarkupKind::Nested);
        }
    }

    /// Port of `addCommentMarkupFuncs()`: plate comment first, then EOL comment.
    pub fn add_comment_markup_funcs(&mut self) {
        if self.descriptor.plate_comment.is_some() {
            self.markup_funcs.push(FieldMarkupKind::PlateComment);
        }
        if self.descriptor.eol_comment.is_some() {
            self.markup_funcs.push(FieldMarkupKind::EolComment);
        }
    }

    /// Port of `addMarkupReferenceFunc()`.
    pub fn add_markup_reference_func(&mut self) {
        if self.descriptor.markup_reference.is_some() {
            self.markup_funcs.push(FieldMarkupKind::Reference);
        }
    }

    /// Port of `setFieldValueDeserializationInfo`: chooses how the field's value is read. A
    /// custom `read_func` wins; otherwise primitives use the primitive reader and structure
    /// mapped types the nested-structure reader. (The setter half of the Java method is resolved
    /// by the derive macro into the field's assign function.)
    pub fn set_field_value_deserialization_info(&mut self) {
        self.reader_func = if let Some(f) = self.descriptor.read_func {
            Some(FieldReaderFunc::Func(f))
        }
        else {
            match self.descriptor.kind {
                FieldValueKind::Primitive(_) => Some(FieldReaderFunc::Primitive),
                FieldValueKind::StructureMapped => self.descriptor.read_nested.map(FieldReaderFunc::Func),
                FieldValueKind::PrimitiveArray(_) => None,
            }
        };
    }

    /// Whether a read function was found (Java `getReaderFunc() != null`).
    pub fn has_reader_func(&self) -> bool {
        self.reader_func.is_some()
    }

    /// Reads this field's value through its reader function (`getReaderFunc().get(context)`).
    ///
    /// # Errors
    /// `Missing read info for field` when no reader function applies, as
    /// `StructureMappingInfo.readStructure` reports; otherwise any read error.
    pub fn read_value(&self, context: &mut FieldContext<'_, T>, mapper: &DataTypeMapper) -> io::Result<FieldValue> {
        match &self.reader_func {
            Some(FieldReaderFunc::Primitive) => {
                let len = self.length.max(0) as usize;
                let reader = context.reader_mut()?;
                let v = if self.is_unsigned() {
                    reader.read_next_unsigned_value(len)? as i64
                }
                else {
                    reader.read_next_value(len)?
                };
                Ok(FieldValue::Primitive(v))
            }
            Some(FieldReaderFunc::Func(f)) => f(context, mapper),
            None => Err(io::Error::other(format!("Missing read info for field: {}", self.descriptor.name))),
        }
    }

    /// Port of `assignField(FieldContext, Object)`: stores `value` into the instance, through
    /// the field's setter if it has one.
    pub fn assign_field(&self, instance: &mut T, value: FieldValue) -> io::Result<()> {
        (self.descriptor.assign)(instance, value)
    }

    /// Runs markup function `kind` of this field (the lambdas Java builds in `addMarkup*Func*`).
    pub fn markup_field(
        &self,
        kind: FieldMarkupKind,
        field_context: &FieldContext<'_, T>,
        session: &mut MarkupSession<'_>,
    ) -> io::Result<()> {
        let instance = field_context.get_structure_instance();
        match kind {
            FieldMarkupKind::Nested => match self.descriptor.markup_nested {
                Some(f) => f(instance, session),
                None => Ok(()),
            },
            FieldMarkupKind::PlateComment | FieldMarkupKind::EolComment => {
                let (getter, comment_type, sep) = if kind == FieldMarkupKind::PlateComment {
                    (self.descriptor.plate_comment, CommentType::Plate, "\n")
                }
                else {
                    (self.descriptor.eol_comment, CommentType::Eol, ";")
                };
                if let Some(text) = getter.map(|g| g(instance)).transpose()?.flatten() {
                    session.append_comment_at_field(field_context, comment_type, None, &text, sep)?;
                }
                Ok(())
            }
            FieldMarkupKind::Reference => {
                if let Some(addr) = self.descriptor.markup_reference.map(|g| g(instance)).transpose()?.flatten() {
                    session.add_reference(field_context, addr)?;
                }
                Ok(())
            }
        }
    }
}
