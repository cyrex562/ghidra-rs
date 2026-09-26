//! Port of `ghidra.formats.gfilesystem.fileinfo.FileAttributes`.
//!
//! A collection of [`FileAttributeType`]-tagged values describing a file inside a
//! `GFileSystem`. Java stores each entry as a `FileAttribute<?>` whose value is an `Object`
//! checked against [`FileAttributeType::value_type`]; here the value is the closed
//! [`FileAttributeValue`] enum naming the classes Java actually uses, and the type check is
//! performed by [`FileAttributeValue::matches`].

use crate::filesystem::gfilesystem::fsrl::Fsrl;

use super::file_attribute_type::{FileAttributeType, FileAttributeValueType};
use super::file_type::FileType;

/// A value carried by a [`FileAttributes`] entry.
///
/// Java's `FileAttributes.add` takes an `Object` whose class is expected to match the
/// attribute type's `getValueType()`. The Java value classes are `FSRL`, `String`, `FileType`,
/// `Long`, `Date` and `Boolean` (plus `Object` for [`FileAttributeType::UnknownAttribute`],
/// whose values are only ever displayed via `toString()` and are therefore carried as
/// [`FileAttributeValue::Str`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileAttributeValue {
    /// A `java.lang.String`.
    Str(String),
    /// A [`FileType`].
    FileType(FileType),
    /// A `java.lang.Boolean`.
    Boolean(bool),
    /// A `java.lang.Long`.
    Long(i64),
    /// A `java.util.Date`, as epoch milliseconds.
    Date(i64),
    /// A `ghidra.formats.gfilesystem.FSRL`.
    Fsrl(Fsrl),
}

impl FileAttributeValue {
    /// The Java value class this value corresponds to.
    pub fn value_type(&self) -> FileAttributeValueType {
        match self {
            FileAttributeValue::Str(_) => FileAttributeValueType::Str,
            FileAttributeValue::FileType(_) => FileAttributeValueType::FileType,
            FileAttributeValue::Boolean(_) => FileAttributeValueType::Boolean,
            FileAttributeValue::Long(_) => FileAttributeValueType::Long,
            FileAttributeValue::Date(_) => FileAttributeValueType::Date,
            FileAttributeValue::Fsrl(_) => FileAttributeValueType::Fsrl,
        }
    }

    /// `true` if this value is acceptable for an attribute of `attribute_type`, mirroring
    /// `attributeType.getValueType().isInstance(value)` in `FileAttribute.create` (every value
    /// is an instance of `Object`).
    pub fn matches(&self, attribute_type: FileAttributeType) -> bool {
        let expected = attribute_type.value_type();
        expected == FileAttributeValueType::Object || expected == self.value_type()
    }
}

impl From<&str> for FileAttributeValue {
    fn from(s: &str) -> Self {
        FileAttributeValue::Str(s.to_string())
    }
}

impl From<String> for FileAttributeValue {
    fn from(s: String) -> Self {
        FileAttributeValue::Str(s)
    }
}

impl From<FileType> for FileAttributeValue {
    fn from(t: FileType) -> Self {
        FileAttributeValue::FileType(t)
    }
}

impl From<bool> for FileAttributeValue {
    fn from(b: bool) -> Self {
        FileAttributeValue::Boolean(b)
    }
}

impl From<i64> for FileAttributeValue {
    fn from(v: i64) -> Self {
        FileAttributeValue::Long(v)
    }
}

impl From<Fsrl> for FileAttributeValue {
    fn from(f: Fsrl) -> Self {
        FileAttributeValue::Fsrl(f)
    }
}

/// A collection of file attribute values, in insertion order.
///
/// Mirrors `ghidra.formats.gfilesystem.fileinfo.FileAttributes`. Each entry is the
/// `(type, display name, value)` triple a Java `FileAttribute` holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileAttributes {
    attributes: Vec<(FileAttributeType, String, FileAttributeValue)>,
}

/// The shared empty instance. Mirrors `FileAttributes.EMPTY` (read-only in Java because it
/// wraps `List.of()`; read-only here because it is only reachable through a shared reference).
pub static EMPTY: FileAttributes = FileAttributes::new();

impl FileAttributes {
    /// Creates a new, empty instance. Mirrors `new FileAttributes()`.
    pub const fn new() -> Self {
        FileAttributes { attributes: Vec::new() }
    }

    /// The shared empty instance. Mirrors `FileAttributes.EMPTY`.
    pub fn empty() -> &'static FileAttributes {
        &EMPTY
    }

    /// Creates an instance holding the given attributes, skipping entries whose value is
    /// `None`.
    ///
    /// Mirrors `FileAttributes.of(FileAttribute<?>...)` fed by `FileAttribute.create(type,
    /// value)`, which returns `null` (and is then skipped) for a `null` value.
    ///
    /// # Panics
    /// If a value does not match its type's value class; see [`add`](Self::add).
    pub fn of<I>(attribs: I) -> Self
    where
        I: IntoIterator<Item = (FileAttributeType, Option<FileAttributeValue>)>,
    {
        let mut result = FileAttributes::new();
        for (attribute_type, value) in attribs {
            result.add(attribute_type, value);
        }
        result
    }

    /// Adds a custom named attribute. Mirrors `add(String, Object)`, which records the value
    /// under [`FileAttributeType::UnknownAttribute`] with `name` as its display label.
    pub fn add_named(&mut self, name: &str, value: Option<FileAttributeValue>) {
        self.add_with_display_name(FileAttributeType::UnknownAttribute, name.to_string(), value);
    }

    /// Adds a typed attribute, labelled with the type's own display name. Mirrors
    /// `add(FileAttributeType, Object)`; a `None` value is silently skipped.
    ///
    /// # Panics
    /// If `value` does not match `attribute_type`'s value class; see
    /// [`add_with_display_name`](Self::add_with_display_name).
    pub fn add(&mut self, attribute_type: FileAttributeType, value: Option<FileAttributeValue>) {
        let display_name = attribute_type.display_name().to_string();
        self.add_with_display_name(attribute_type, display_name, value);
    }

    /// Adds a typed attribute with an explicit display name. Mirrors
    /// `add(FileAttributeType, String, Object)`; a `None` value is silently skipped.
    ///
    /// # Panics
    /// If `value` does not match `attribute_type`'s value class. Java throws the unchecked
    /// `IllegalArgumentException` here -- a caller contract violation, not a recoverable
    /// condition.
    pub fn add_with_display_name(
        &mut self,
        attribute_type: FileAttributeType,
        display_name: String,
        value: Option<FileAttributeValue>,
    ) {
        let Some(value) = value else {
            return;
        };
        assert!(
            value.matches(attribute_type),
            "FileAttribute type {attribute_type:?} does not match value: {:?}",
            value.value_type()
        );
        self.attributes.push((attribute_type, display_name, value));
    }

    /// The value of the first attribute of `attribute_type`, or `None`.
    ///
    /// Mirrors `get(FileAttributeType, Class<T>, T)`: Java stops at the first attribute of the
    /// requested type and falls back to the default when its class does not match, which the
    /// caller expresses by matching on the returned variant.
    pub fn get(&self, attribute_type: FileAttributeType) -> Option<&FileAttributeValue> {
        self.attributes
            .iter()
            .find(|(t, _, _)| *t == attribute_type)
            .map(|(_, _, v)| v)
    }

    /// The first attribute of `attribute_type` as a string, or `default_value` when absent or
    /// not a string. Convenience for `get(type, String.class, default)`.
    pub fn get_str<'a>(&'a self, attribute_type: FileAttributeType, default_value: &'a str) -> &'a str {
        match self.get(attribute_type) {
            Some(FileAttributeValue::Str(s)) => s,
            _ => default_value,
        }
    }

    /// The first attribute of `attribute_type` as a long, or `default_value` when absent or
    /// not a long. Convenience for `get(type, Long.class, default)`.
    pub fn get_long(&self, attribute_type: FileAttributeType, default_value: i64) -> i64 {
        match self.get(attribute_type) {
            Some(FileAttributeValue::Long(v)) => *v,
            _ => default_value,
        }
    }

    /// The value of the first custom-named ([`FileAttributeType::UnknownAttribute`]) attribute
    /// labelled `name`, or `None`.
    pub fn get_named(&self, name: &str) -> Option<&FileAttributeValue> {
        self.attributes
            .iter()
            .find(|(t, n, _)| *t == FileAttributeType::UnknownAttribute && n == name)
            .map(|(_, _, v)| v)
    }

    /// All accumulated `(type, display name, value)` triples, in insertion order.
    /// Mirrors `getAttributes()`.
    pub fn get_attributes(&self) -> &[(FileAttributeType, String, FileAttributeValue)] {
        &self.attributes
    }

    /// `true` if an attribute of `attribute_type` is present. Mirrors `contains()`.
    pub fn contains(&self, attribute_type: FileAttributeType) -> bool {
        self.attributes.iter().any(|(t, _, _)| *t == attribute_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_has_no_attributes() {
        assert!(FileAttributes::empty().get_attributes().is_empty());
        assert!(!EMPTY.contains(FileAttributeType::NameAttr));
        assert_eq!(FileAttributes::new(), EMPTY);
    }

    #[test]
    fn of_skips_none_values_and_keeps_order() {
        let attrs = FileAttributes::of([
            (FileAttributeType::NameAttr, Some("a.bin".into())),
            (FileAttributeType::ModifiedDateAttr, None),
            (FileAttributeType::CompressedSizeAttr, Some(10i64.into())),
            (FileAttributeType::CommentAttr, None),
        ]);
        let attribs = attrs.get_attributes();
        assert_eq!(attribs.len(), 2);
        assert_eq!(attribs[0].0, FileAttributeType::NameAttr);
        assert_eq!(attribs[0].1, "Name");
        assert_eq!(attribs[1].0, FileAttributeType::CompressedSizeAttr);
        assert!(!attrs.contains(FileAttributeType::ModifiedDateAttr));
    }

    #[test]
    fn add_uses_type_display_name_and_skips_none() {
        let mut attrs = FileAttributes::new();
        attrs.add(FileAttributeType::SizeAttr, Some(FileAttributeValue::Long(42)));
        attrs.add(FileAttributeType::CommentAttr, None);
        assert_eq!(attrs.get_attributes().len(), 1);
        assert_eq!(attrs.get_attributes()[0].1, FileAttributeType::SizeAttr.display_name());
        assert_eq!(attrs.get_long(FileAttributeType::SizeAttr, -1), 42);
    }

    #[test]
    fn add_named_is_unknown_attribute_with_custom_label() {
        let mut attrs = FileAttributes::new();
        attrs.add_named("Address Range", Some("0x0-0x10".into()));
        assert!(attrs.contains(FileAttributeType::UnknownAttribute));
        assert_eq!(attrs.get_named("Address Range"), Some(&FileAttributeValue::Str("0x0-0x10".into())));
        assert_eq!(attrs.get_named("Other"), None);
    }

    #[test]
    fn get_returns_first_match_and_typed_defaults() {
        let mut attrs = FileAttributes::new();
        attrs.add(FileAttributeType::NameAttr, Some("first".into()));
        attrs.add(FileAttributeType::NameAttr, Some("second".into()));
        assert_eq!(attrs.get_str(FileAttributeType::NameAttr, "dflt"), "first");
        assert_eq!(attrs.get_str(FileAttributeType::PathAttr, "dflt"), "dflt");
        assert_eq!(attrs.get_long(FileAttributeType::SizeAttr, 7), 7);
    }

    #[test]
    #[should_panic(expected = "does not match value")]
    fn add_rejects_mismatched_value_class() {
        let mut attrs = FileAttributes::new();
        attrs.add(FileAttributeType::SizeAttr, Some("not a long".into()));
    }

    #[test]
    fn unknown_attribute_accepts_any_value_class() {
        let mut attrs = FileAttributes::new();
        attrs.add_named("flag", Some(true.into()));
        attrs.add_named("count", Some(3i64.into()));
        assert_eq!(attrs.get_attributes().len(), 2);
    }

    #[test]
    fn clone_is_independent() {
        let mut a = FileAttributes::new();
        a.add(FileAttributeType::NameAttr, Some("x".into()));
        let mut b = a.clone();
        b.add(FileAttributeType::PathAttr, Some("/x".into()));
        assert_eq!(a.get_attributes().len(), 1);
        assert_eq!(b.get_attributes().len(), 2);
    }

    #[test]
    fn file_type_value_round_trips() {
        let attrs = FileAttributes::of([(FileAttributeType::FileTypeAttr, Some(FileType::Directory.into()))]);
        assert_eq!(
            attrs.get(FileAttributeType::FileTypeAttr),
            Some(&FileAttributeValue::FileType(FileType::Directory))
        );
    }
}
