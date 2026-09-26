//! The compile-time replacement for the Java reflection that drives golang structure mapping.
//!
//! Java's `StructureMappingInfo`/`FieldMappingInfo`/`ReflectionHelper` discover a structure
//! mapped class's annotations (`@StructureMapping`, `@FieldMapping`, `@FieldOutput`, `@Markup`,
//! `@MarkupReference`, `@EOLComment`, `@PlateComment`, `@ContextField`, `@AfterStructureRead`)
//! through `java.lang.reflect` at run time, and then read and write the class's fields through
//! reflective `Field.set`/`Method.invoke` calls. In this port the `#[derive(StructureMapped)]`
//! macro (crate `ghidra-rs-macros`) reads the equivalent Rust attributes at compile time and emits
//! a static [`StructureMappingDescriptor`]: the same annotation values, plus typed function
//! pointers that stand in for each reflective `Field`/`Method` handle.
//!
//! [`StructureMappingInfo`] then binds that descriptor to the Ghidra `Structure` data type found
//! at run time, exactly as the Java class does with the annotations it reflects on.
//!
//! Ownership: each structure mapped type owns its [`StructureContext<Self>`] by value (its
//! `#[context_field]`); the context does not own or point back at the instance, and a
//! [`FieldContext`] borrows `&T` for the duration of a single call.

use std::any::Any;
use std::fmt::Display;
use std::io;
use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure::Structure;

use super::data_type_mapper::DataTypeMapper;
use super::field_context::FieldContext;
use super::field_output_info::FieldOutputInfo;
use super::markup_session::MarkupSession;
use super::signedness::Signedness;
use super::structure_context::StructureContext;

/// A type whose instances are deserialized from a Ghidra `Structure` by the structure mapper.
///
/// Implemented by `#[derive(StructureMapped)]`; stands in for "a Java class carrying a
/// `@StructureMapping` annotation" (`ReflectionHelper.hasStructureMapping`).
pub trait StructureMapped: Sized + 'static {
    /// The static annotation table for this type.
    fn descriptor() -> &'static StructureMappingDescriptor<Self>;

    /// Creates a new, not yet deserialized, instance and performs `@ContextField` injection.
    ///
    /// Stands in for `StructureMappingInfo.findInstanceCreator()` +
    /// `StructureMappingInfo.assignContextFieldValues()`: the `StructureContext` context field
    /// receives `context`, every other context field is fetched from the mapper's context values
    /// by type ([`DataTypeMapper::get_context_value`]), and all remaining fields start at their
    /// `Default` value (Java's field initializers / zero values).
    fn create_instance(context: StructureContext<Self>, mapper: &DataTypeMapper) -> io::Result<Self>;

    /// The instance's own [`StructureContext`], if the type declares a `StructureContext`
    /// context field. Stands in for `StructureMappingInfo.recoverStructureContext(T)`.
    fn structure_context(&self) -> Option<&StructureContext<Self>>;
}

/// Java primitive field types the mapper can read (`ReflectionHelper.NUM_CLASSES`, minus
/// `char`, which no Rust integer type corresponds to).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimitiveKind {
    /// Java `long` (Rust `i64`/`u64`).
    Long,
    /// Java `int` (Rust `i32`/`u32`).
    Int,
    /// Java `short` (Rust `i16`/`u16`).
    Short,
    /// Java `byte` (Rust `i8`/`u8`).
    Byte,
}

impl PrimitiveKind {
    /// Port of `ReflectionHelper.getPrimitiveSizeof(Class)`.
    pub fn size_of(self) -> i32 {
        match self {
            PrimitiveKind::Long => 8,
            PrimitiveKind::Int => 4,
            PrimitiveKind::Short => 2,
            PrimitiveKind::Byte => 1,
        }
    }

    /// `ReflectionHelper.DEFAULT_DATATYPE_NAME` for this primitive.
    pub fn default_data_type_name(self) -> &'static str {
        match self {
            PrimitiveKind::Long => "long",
            PrimitiveKind::Int => "int",
            PrimitiveKind::Short => "word",
            PrimitiveKind::Byte => "byte",
        }
    }
}

/// What kind of value a mapped field holds; replaces the `Class<?>` tests Java performs on
/// `Field.getType()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldValueKind {
    /// A Java primitive (`ReflectionHelper.isPrimitiveType`).
    Primitive(PrimitiveKind),
    /// An array of Java primitives (`fieldType.isArray()` with a primitive component type).
    PrimitiveArray(PrimitiveKind),
    /// Any other type; read as a nested structure mapped type unless a `read_func` is given.
    StructureMapped,
}

/// A deserialized field value, before it is assigned to its field.
///
/// Java passes `Object` between `FieldReadFunction.get` and `FieldMappingInfo.assignField`; the
/// primitive readers all produce a `long` which is then narrowed with a Java cast, so the
/// primitive case is carried as an `i64` and narrowed with `as` by the generated assign function.
pub enum FieldValue {
    /// A primitive value, as read by `BinaryReader.readNextValue`/`readNextUnsignedValue`.
    Primitive(i64),
    /// Any other value (a nested structure instance, or a custom `read_func` result).
    Object(Box<dyn Any>),
}

impl FieldValue {
    /// The primitive value, or the `IOException` Java's `ReflectionHelper.assignField` raises on
    /// a bad conversion.
    pub fn into_primitive(self, field_name: &str) -> io::Result<i64> {
        match self {
            FieldValue::Primitive(v) => Ok(v),
            FieldValue::Object(o) => match o.downcast::<i64>() {
                Ok(v) => Ok(*v),
                Err(_) => Err(io::Error::other(format!(
                    "Bad conversion from object to primitive field {field_name}"
                ))),
            },
        }
    }

    /// The object value as `R`, or the `IOException` Java's `ReflectionHelper.assignField`
    /// raises when `fieldType.isInstance(value)` fails.
    pub fn downcast<R: 'static>(self, field_name: &str) -> io::Result<R> {
        let bad = || {
            io::Error::other(format!(
                "Bad conversion to field {field_name}:{}",
                std::any::type_name::<R>()
            ))
        };
        match self {
            FieldValue::Object(o) => o.downcast::<R>().map(|b| *b).map_err(|_| bad()),
            FieldValue::Primitive(v) => (Box::new(v) as Box<dyn Any>)
                .downcast::<R>()
                .map(|b| *b)
                .map_err(|_| bad()),
        }
    }
}

/// `FieldReadFunction`: deserializes one field's value.
pub type FieldReadFn<T> =
    for<'a, 'b> fn(&'a mut FieldContext<'b, T>, &'a DataTypeMapper) -> io::Result<FieldValue>;
/// Assigns a deserialized value to its field, directly or through a `setter`
/// (`FieldMappingInfo.assignField`).
pub type FieldAssignFn<T> = fn(&mut T, FieldValue) -> io::Result<()>;
/// Marks up something reachable from an instance (`@Markup` fields and getters, and the
/// `StructureMarkup` hooks).
pub type MarkupGetterFn<T> = for<'a, 'b> fn(&'a T, &'a mut MarkupSession<'b>) -> io::Result<()>;
/// Produces comment text from an instance (`@EOLComment`/`@PlateComment` getters).
pub type CommentGetterFn<T> = fn(&T) -> io::Result<Option<String>>;
/// Produces a reference destination from an instance (`@MarkupReference` getters).
pub type ReferenceGetterFn<T> = fn(&T) -> io::Result<Option<Address>>;
/// Produces a field's output data type (`@FieldOutput(getter = ..)`).
pub type OutputGetterFn<T> = fn(&T) -> io::Result<Option<OutputDataType>>;
/// A custom `FieldOutputFunction` (`@FieldOutput(fieldOutputFunc = ..)`).
pub type FieldOutputFn<T> = fn(
    &StructureContext<T>,
    &T,
    &DataTypeMapper,
    &mut dyn Structure,
    &FieldOutputInfo<T>,
) -> io::Result<()>;
/// The structure data type of a nested structure mapped field value, `None` when the value is
/// absent (Java `null`).
pub type NestedDataTypeFn<T> = fn(&T, &DataTypeMapper) -> io::Result<Option<Arc<dyn DataType>>>;
/// The length of a primitive array field (`Array.getLength`).
pub type ArrayLenFn<T> = fn(&T) -> usize;
/// An `@AfterStructureRead` method.
pub type AfterReadFn<T> = fn(&mut T) -> io::Result<()>;
/// `StructureReader.readStructure()`.
pub type ReadStructureFn<T> =
    fn(&mut T, &mut dyn crate::app::util::bin::binary_reader::BinaryReader, &DataTypeMapper) -> io::Result<()>;

/// The `@FieldMapping` annotation values of one field.
#[derive(Debug, Clone, Copy)]
pub struct FieldMappingAttr {
    /// `fieldName()`: names to search for in the Ghidra structure (first match wins).
    pub field_names: &'static [&'static str],
    /// `optional()`.
    pub optional: bool,
    /// `presentWhen()`.
    pub present_when: &'static str,
    /// `length()`, `-1` when not overridden.
    pub length: i32,
    /// `signedness()`.
    pub signedness: Signedness,
}

/// The `@FieldOutput` annotation values of one field.
pub struct FieldOutputAttr<T: 'static> {
    /// `ordinal()`, `-1` when unspecified.
    pub ordinal: i32,
    /// `offset()`, `-1` when unspecified.
    pub offset: i32,
    /// `dataTypeName()`, empty when unspecified.
    pub data_type_name: &'static str,
    /// `isVariableLength()`.
    pub is_variable_length: bool,
    /// `getter()`, resolved to a function.
    pub getter: Option<OutputGetterFn<T>>,
    /// `fieldOutputFunc()`, resolved to a function.
    pub output_func: Option<FieldOutputFn<T>>,
}

/// Everything the Java reflection code learns about one mapped field.
pub struct FieldDescriptor<T: 'static> {
    /// The Rust field name (Java `Field.getName()`).
    pub name: &'static str,
    /// The structure field name searched for when `@FieldMapping.fieldName` is not given (the
    /// Java field name, i.e. the Rust name in lower camel case), or the first explicit name.
    pub search_name: &'static str,
    /// What the field holds.
    pub kind: FieldValueKind,
    /// `@FieldMapping`, if present.
    pub mapping: Option<FieldMappingAttr>,
    /// `@FieldOutput`, if present.
    pub output: Option<FieldOutputAttr<T>>,
    /// `@FieldMapping(readFunc = ..)`.
    pub read_func: Option<FieldReadFn<T>>,
    /// The nested-structure reader generated for [`FieldValueKind::StructureMapped`] fields
    /// (`FieldMappingInfo.readStructureMappedTypeFunc`).
    pub read_nested: Option<FieldReadFn<T>>,
    /// Assigns a value to the field.
    pub assign: FieldAssignFn<T>,
    /// `@Markup` on the field (`FieldMappingInfo.markupNestedStructure`).
    pub markup_nested: Option<MarkupGetterFn<T>>,
    /// `@PlateComment` on the field.
    pub plate_comment: Option<CommentGetterFn<T>>,
    /// `@EOLComment` on the field.
    pub eol_comment: Option<CommentGetterFn<T>>,
    /// `@MarkupReference` on the field.
    pub markup_reference: Option<ReferenceGetterFn<T>>,
    /// The nested value's structure data type, for `@FieldOutput` on a nested field.
    pub nested_data_type: Option<NestedDataTypeFn<T>>,
    /// The array length, for `@FieldOutput` on a primitive array field.
    pub array_len: Option<ArrayLenFn<T>>,
}

/// The `StructureMarkup` hooks of a type that implements it.
pub struct StructureMarkupHooks<T: 'static> {
    /// `StructureMarkup.getStructureLabel()`.
    pub structure_label: fn(&T) -> io::Result<Option<String>>,
    /// `StructureMarkup.getStructureNamespace()`.
    pub structure_namespace: fn(&T) -> io::Result<Option<String>>,
    /// `StructureMarkup.additionalMarkup(MarkupSession)`.
    pub additional_markup: MarkupGetterFn<T>,
    /// Marks up each of `StructureMarkup.getExternalInstancesToMarkup()`.
    pub external_instances_to_markup: MarkupGetterFn<T>,
}

/// The static annotation table of a structure mapped type.
pub struct StructureMappingDescriptor<T: 'static> {
    /// `Class.getSimpleName()`.
    pub type_name: &'static str,
    /// `@StructureMapping.structureName()`.
    pub structure_names: &'static [&'static str],
    /// `StructureReader.class.isAssignableFrom(targetClass)`.
    pub is_structure_reader: bool,
    /// Mapped fields in declaration order (Java walks superclass fields first; a Rust type that
    /// composes a base declares the base's fields itself).
    pub fields: &'static [FieldDescriptor<T>],
    /// `@AfterStructureRead` methods.
    pub after_read: &'static [AfterReadFn<T>],
    /// `@Markup` getter methods.
    pub markup_getters: &'static [MarkupGetterFn<T>],
    /// A type-level `@PlateComment`.
    pub plate_comment: Option<CommentGetterFn<T>>,
    /// `StructureReader.readStructure()`, for self-reading types.
    pub read_structure: Option<ReadStructureFn<T>>,
    /// `StructureVerifier.isValid()`, for self-verifying types.
    pub is_valid: Option<fn(&T) -> bool>,
    /// `StructureMarkup`, for types that control their own markup.
    pub structure_markup: Option<StructureMarkupHooks<T>>,
}

/// A data type produced by a `@FieldOutput(getter = ..)` getter: Java accepts either a
/// `DataType` or a `DataTypeInstance` from the getter.
pub enum OutputDataType {
    /// A fixed-size data type.
    DataType(Box<dyn DataType>),
    /// A data type plus an explicit length (Java `DataTypeInstance`).
    Instance(Box<dyn DataType>, i32),
}

/// Converts a `@FieldOutput` getter's result into an [`OutputDataType`].
pub trait IntoOutputDataType {
    /// The data type, `None` for Java `null` (nothing is added).
    fn into_output_data_type(self) -> io::Result<Option<OutputDataType>>;
}

impl IntoOutputDataType for OutputDataType {
    fn into_output_data_type(self) -> io::Result<Option<OutputDataType>> {
        Ok(Some(self))
    }
}

impl IntoOutputDataType for Box<dyn DataType> {
    fn into_output_data_type(self) -> io::Result<Option<OutputDataType>> {
        Ok(Some(OutputDataType::DataType(self)))
    }
}

impl<X: IntoOutputDataType> IntoOutputDataType for Option<X> {
    fn into_output_data_type(self) -> io::Result<Option<OutputDataType>> {
        match self {
            Some(x) => x.into_output_data_type(),
            None => Ok(None),
        }
    }
}

impl<X: IntoOutputDataType> IntoOutputDataType for io::Result<X> {
    fn into_output_data_type(self) -> io::Result<Option<OutputDataType>> {
        self?.into_output_data_type()
    }
}

/// Something that can be marked up by a [`MarkupSession`]: a structure mapped instance, or a
/// collection of them. Replaces the `instanceof Collection`/array/`Iterator` dispatch in
/// `MarkupSession.markup(Object, boolean)`.
pub trait MarkupTarget {
    /// Marks up `self` (`MarkupSession.markup(obj, nested)`).
    fn markup_target(self, session: &mut MarkupSession<'_>, nested: bool) -> io::Result<()>;
}

impl<X: MarkupTarget> MarkupTarget for Option<X> {
    fn markup_target(self, session: &mut MarkupSession<'_>, nested: bool) -> io::Result<()> {
        match self {
            Some(x) => x.markup_target(session, nested),
            None => Ok(()),
        }
    }
}

impl<'a, X> MarkupTarget for &'a Option<X>
where
    &'a X: MarkupTarget,
{
    fn markup_target(self, session: &mut MarkupSession<'_>, nested: bool) -> io::Result<()> {
        match self {
            Some(x) => x.markup_target(session, nested),
            None => Ok(()),
        }
    }
}

impl<X: MarkupTarget> MarkupTarget for Vec<X> {
    fn markup_target(self, session: &mut MarkupSession<'_>, nested: bool) -> io::Result<()> {
        for x in self {
            x.markup_target(session, nested)?;
        }
        Ok(())
    }
}

impl<'a, X> MarkupTarget for &'a Vec<X>
where
    &'a X: MarkupTarget,
{
    fn markup_target(self, session: &mut MarkupSession<'_>, nested: bool) -> io::Result<()> {
        for x in self {
            x.markup_target(session, nested)?;
        }
        Ok(())
    }
}

impl<X: MarkupTarget> MarkupTarget for Box<X> {
    fn markup_target(self, session: &mut MarkupSession<'_>, nested: bool) -> io::Result<()> {
        (*self).markup_target(session, nested)
    }
}

impl<X: MarkupTarget> MarkupTarget for io::Result<X> {
    fn markup_target(self, session: &mut MarkupSession<'_>, nested: bool) -> io::Result<()> {
        self?.markup_target(session, nested)
    }
}

/// An object-safe [`MarkupTarget`], used for `StructureMarkup.getExternalInstancesToMarkup()`'s
/// heterogeneous `List<?>`.
pub trait MarkupItem {
    /// Marks up this item.
    fn markup_item(&self, session: &mut MarkupSession<'_>, nested: bool) -> io::Result<()>;
}

impl<X> MarkupItem for X
where
    for<'a> &'a X: MarkupTarget,
{
    fn markup_item(&self, session: &mut MarkupSession<'_>, nested: bool) -> io::Result<()> {
        self.markup_target(session, nested)
    }
}

/// A `@MarkupReference` getter result: an `Address`, or a structure mapped instance whose
/// address is used (`DataTypeMapper.getAddressOfStructure`). Anything else yields no reference,
/// as Java's `getAddressOfStructure` returns `null` for unmapped objects.
pub trait ReferenceTarget {
    /// The reference destination, `None` for Java `null`.
    fn reference_address(self) -> io::Result<Option<Address>>;
}

impl ReferenceTarget for Address {
    fn reference_address(self) -> io::Result<Option<Address>> {
        Ok(Some(self))
    }
}

impl ReferenceTarget for &Address {
    fn reference_address(self) -> io::Result<Option<Address>> {
        Ok(Some(self.clone()))
    }
}

impl<X: ReferenceTarget> ReferenceTarget for Option<X> {
    fn reference_address(self) -> io::Result<Option<Address>> {
        match self {
            Some(x) => x.reference_address(),
            None => Ok(None),
        }
    }
}

impl<'a, X> ReferenceTarget for &'a Option<X>
where
    &'a X: ReferenceTarget,
{
    fn reference_address(self) -> io::Result<Option<Address>> {
        match self {
            Some(x) => x.reference_address(),
            None => Ok(None),
        }
    }
}

impl<X: ReferenceTarget> ReferenceTarget for io::Result<X> {
    fn reference_address(self) -> io::Result<Option<Address>> {
        self?.reference_address()
    }
}

impl<X: ReferenceTarget> ReferenceTarget for Box<X> {
    fn reference_address(self) -> io::Result<Option<Address>> {
        (*self).reference_address()
    }
}

/// A comment getter result, rendered the way Java's `Object.toString()` renders it.
/// `FieldMappingInfo.createCommentMarkupFunc` skips `null` values and empty collections.
pub trait CommentValue {
    /// The comment text, `None` when nothing should be added.
    fn comment_text(self) -> io::Result<Option<String>>;
}

impl CommentValue for String {
    fn comment_text(self) -> io::Result<Option<String>> {
        Ok(Some(self))
    }
}

impl CommentValue for &String {
    fn comment_text(self) -> io::Result<Option<String>> {
        Ok(Some(self.clone()))
    }
}

impl CommentValue for &str {
    fn comment_text(self) -> io::Result<Option<String>> {
        Ok(Some(self.to_string()))
    }
}

impl<X: CommentValue> CommentValue for Option<X> {
    fn comment_text(self) -> io::Result<Option<String>> {
        match self {
            Some(x) => x.comment_text(),
            None => Ok(None),
        }
    }
}

impl<'a, X> CommentValue for &'a Option<X>
where
    &'a X: CommentValue,
{
    fn comment_text(self) -> io::Result<Option<String>> {
        match self {
            Some(x) => x.comment_text(),
            None => Ok(None),
        }
    }
}

impl<X: CommentValue> CommentValue for io::Result<X> {
    fn comment_text(self) -> io::Result<Option<String>> {
        self?.comment_text()
    }
}

/// Java's `AbstractCollection.toString()`: `[a, b, c]`; empty collections add no comment.
fn list_comment<X: Display>(items: &[X]) -> Option<String> {
    if items.is_empty() {
        return None;
    }
    let parts: Vec<String> = items.iter().map(ToString::to_string).collect();
    Some(format!("[{}]", parts.join(", ")))
}

impl<X: Display> CommentValue for Vec<X> {
    fn comment_text(self) -> io::Result<Option<String>> {
        Ok(list_comment(&self))
    }
}

impl<X: Display> CommentValue for &Vec<X> {
    fn comment_text(self) -> io::Result<Option<String>> {
        Ok(list_comment(self))
    }
}

macro_rules! display_comment_value {
    ($($t:ty),*) => {$(
        impl CommentValue for $t {
            fn comment_text(self) -> io::Result<Option<String>> {
                Ok(Some(self.to_string()))
            }
        }
        impl CommentValue for &$t {
            fn comment_text(self) -> io::Result<Option<String>> {
                Ok(Some(self.to_string()))
            }
        }
    )*};
}
display_comment_value!(i8, u8, i16, u16, i32, u32, i64, u64, bool);

/// Converts a setter's or `@AfterStructureRead` method's return value into an `io::Result`.
pub trait IntoIoResult {
    /// The result, with any error converted to `io::Error`.
    fn into_io_result(self) -> io::Result<()>;
}

impl IntoIoResult for () {
    fn into_io_result(self) -> io::Result<()> {
        Ok(())
    }
}

impl IntoIoResult for io::Result<()> {
    fn into_io_result(self) -> io::Result<()> {
        self
    }
}

impl IntoIoResult for anyhow::Result<()> {
    fn into_io_result(self) -> io::Result<()> {
        self.map_err(|e| io::Error::other(e.to_string()))
    }
}

/// A `@FieldOutput` nested field: its value's structure data type
/// (`FieldOutputInfo.nestedStructureOutputFunc`).
pub trait NestedStructure {
    /// The value's structure data type, `None` when the value is absent (Java `null`).
    fn nested_structure_data_type(&self, mapper: &DataTypeMapper) -> io::Result<Option<Arc<dyn DataType>>>;
}

impl<X: NestedStructure> NestedStructure for Option<X> {
    fn nested_structure_data_type(&self, mapper: &DataTypeMapper) -> io::Result<Option<Arc<dyn DataType>>> {
        match self {
            Some(x) => x.nested_structure_data_type(mapper),
            None => Ok(None),
        }
    }
}

/// The structure data type of a nested structure mapped value, from its own
/// [`StructureContext`]; the `IOException` Java raises when the value has no context.
pub fn nested_structure_data_type_of<X: StructureMapped>(
    value: &X,
    mapper: &DataTypeMapper,
) -> io::Result<Option<Arc<dyn DataType>>> {
    let ctx = value.structure_context().ok_or_else(|| {
        io::Error::other(format!("Missing StructureContext for {}", X::descriptor().type_name))
    })?;
    ctx.get_structure_data_type_for(value, mapper).map(Some)
}

/// Paths the derive macro's generated code uses. Not part of the public API.
#[doc(hidden)]
pub mod __private {
    pub use super::{
        nested_structure_data_type_of, AfterReadFn, ArrayLenFn, CommentGetterFn, CommentValue,
        FieldAssignFn, FieldDescriptor, FieldMappingAttr, FieldOutputAttr, FieldOutputFn, FieldReadFn,
        FieldValue, FieldValueKind, IntoIoResult, IntoOutputDataType, MarkupGetterFn, MarkupTarget,
        NestedDataTypeFn, NestedStructure, OutputDataType, OutputGetterFn, PrimitiveKind,
        ReadStructureFn, ReferenceGetterFn, ReferenceTarget, StructureMapped,
        StructureMappingDescriptor, StructureMarkupHooks,
    };
    pub use crate::app::util::bin::binary_reader::BinaryReader;
    pub use crate::program::model::address::Address;
    pub use crate::program::model::data::data_type::DataType;
    pub use super::super::data_type_mapper::DataTypeMapper;
    pub use super::super::field_context::FieldContext;
    pub use super::super::markup_session::MarkupSession;
    pub use super::super::signedness::Signedness;
    pub use super::super::structure_context::StructureContext;
    pub use super::super::structure_markup::StructureMarkup;
    pub use super::super::structure_reader::StructureReader;
    pub use super::super::structure_verifier::StructureVerifier;
}
