//! Port of `ghidra.framework.options.GProperties`.
//!
//! A named, ordered map of typed name/value pairs that can be saved to and restored from XML (a
//! JDOM-style [`Element`]) or JSON. Java stores `Object` values and dispatches on `instanceof`;
//! here the closed set of supported value classes is the [`GPropertyValue`] enum.
//!
//! Java's subclass hooks (`processElement`, `createElement(String, Object)`, used by
//! [`SaveState`]) are modeled by a private [`Flavor`] passed through the XML (de)serializer: a
//! `SaveState` restores and writes nested `<SAVE_STATE>` elements, a plain `GProperties` does not.
//!
//! Divergences from Java, all forced by the absence of reflection or of `java.awt` types:
//! - Enum values are kept as their Java class name plus constant name
//!   ([`EnumOptionValue`]) and resolved to a Rust enum only when read through
//!   [`GProperties::get_enum`] (Java resolves them via reflection when restoring and drops
//!   unresolvable constants then).
//! - `java.awt.Color`, `java.awt.Font` and `javax.swing.KeyStroke` values have no Rust types yet;
//!   they are preserved losslessly in their persisted form ([`GPropertyValue::Color`] holds
//!   `Color.getRGB()`, [`GPropertyValue::Font`]/[`GPropertyValue::KeyStroke`] the strings Java
//!   writes) so restore/save round-trips keep them, but the typed `putColor`/`getFont`/... accessors
//!   are not provided.
//! - Rust strings cannot be null, so string arrays hold no null elements (Java drops them on save).
//! - Reading a primitive whose stored value is null returns the default (Java unboxes a null and
//!   throws), and reading an array of the wrong type returns the default (Java's unchecked cast
//!   throws `ClassCastException`).
//! - `Date` values use whole seconds, as `DATE_FORMAT` does, and are written in UTC (`+0000`);
//!   Java writes the JVM's default zone. Both parse back to the same instant.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde_json::{json, Map, Value};

use crate::framework::options::enum_editor::EnumValues;
use crate::framework::options::option_type::{
    date_from_millis, date_to_millis, java_double_to_string, java_float_to_string,
    java_parse_double, EnumOptionValue,
};
use crate::framework::options::save_state::SaveState;
use crate::util::msg::Msg;
use crate::util::seam_stubs::NumericUtilities;
use crate::util::xml::element::{has_invalid_xml_characters, Element};

const G_PROPERTIES_TYPE: &str = "GProperties";
const SAVE_STATE_LEGACY_TYPE: &str = "SaveState";
const GPROPERTIES_TAG: &str = "GPROPERTIES";
const PROPERTIES_NAME: &str = "GPROPERTIES_NAME";
const LEGACY_PROPERTIES_NAME: &str = "SAVE_STATE_NAME";
/// `GProperties.STATE`: the tag of a primitive (or string, date, ...) value.
pub(crate) const STATE: &str = "STATE";
/// `GProperties.ATTRIBUTE_TYPE`.
pub(crate) const ATTRIBUTE_TYPE: &str = "TYPE";
/// `GProperties.ATTRIBUTE_KEY`.
pub(crate) const ATTRIBUTE_KEY: &str = "KEY";
/// `GProperties.ATTRIBUTE_NAME`.
pub(crate) const ATTRIBUTE_NAME: &str = "NAME";
/// `GProperties.ATTRIBUTE_VALUE`.
pub(crate) const ATTRIBUTE_VALUE: &str = "VALUE";
const ARRAY_ELEMENT_NAME: &str = "A";

/// A Rust enum that can be stored in a [`GProperties`] the way Java stores an `Enum<?>`: by its
/// fully-qualified Java class name and constant name.
///
/// Stands in for the reflection Java's `getEnumValue` does (`ClassSearcher.forNameSafe` +
/// `valueOf`): the class name identifies the enum type and [`EnumValues`] supplies `valueOf`.
pub trait PersistableEnum: EnumValues + Clone + 'static {
    /// The fully-qualified Java class name (`Enum.getClass().getName()`) this enum persists as.
    fn java_class_name() -> &'static str;

    /// `Enum.valueOf(Class, String)`: the constant with the given `name()`.
    fn value_of(name: &str) -> Option<Self> {
        Self::all_values().iter().find(|v| v.variant_name() == name).cloned()
    }

    /// This constant as the stored class-name/constant-name pair.
    fn to_enum_value(&self) -> EnumOptionValue {
        EnumOptionValue {
            class_name: Self::java_class_name().to_string(),
            name: self.variant_name().to_string(),
        }
    }
}

/// A value stored in a [`GProperties`]: one variant per value class Java's `GProperties`
/// supports (`null` is [`GPropertyValue::Null`]).
#[derive(Debug, Clone, PartialEq)]
pub enum GPropertyValue {
    /// A stored Java `null`.
    Null,
    /// An `org.jdom2.Element`.
    Xml(Element),
    /// A `Byte`.
    Byte(i8),
    /// A `Short`.
    Short(i16),
    /// An `Integer`.
    Int(i32),
    /// A `Long`.
    Long(i64),
    /// A `Float`.
    Float(f32),
    /// A `Double`.
    Double(f64),
    /// A `Boolean`.
    Boolean(bool),
    /// A `String`.
    String(String),
    /// A `java.awt.Color`, as `Color.getRGB()` (no Rust `Color` type yet).
    Color(i32),
    /// A `java.util.Date`.
    Date(SystemTime),
    /// A `java.io.File`.
    File(PathBuf),
    /// A `javax.swing.KeyStroke`, as `KeyStroke.toString()` (no Rust `KeyStroke` type yet).
    KeyStroke(String),
    /// A `java.awt.Font`, as `"name-STYLE-size"` (no Rust `Font` type yet).
    Font(String),
    /// A `byte[]`.
    Bytes(Vec<u8>),
    /// A `short[]`.
    Shorts(Vec<i16>),
    /// An `int[]`.
    Ints(Vec<i32>),
    /// A `long[]`.
    Longs(Vec<i64>),
    /// A `float[]`.
    Floats(Vec<f32>),
    /// A `double[]`.
    Doubles(Vec<f64>),
    /// A `boolean[]`.
    Booleans(Vec<bool>),
    /// A `String[]`.
    Strings(Vec<String>),
    /// An `Enum<?>` constant.
    Enum(EnumOptionValue),
    /// A nested `GProperties`.
    GProperties(Box<GProperties>),
    /// A nested [`SaveState`] (a `GProperties` subclass in Java).
    SaveState(Box<SaveState>),
}

impl GPropertyValue {
    /// The Java class name of the value, for type-mismatch diagnostics.
    fn java_class(&self) -> &'static str {
        match self {
            GPropertyValue::Null => "null",
            GPropertyValue::Xml(_) => "org.jdom2.Element",
            GPropertyValue::Byte(_) => "java.lang.Byte",
            GPropertyValue::Short(_) => "java.lang.Short",
            GPropertyValue::Int(_) => "java.lang.Integer",
            GPropertyValue::Long(_) => "java.lang.Long",
            GPropertyValue::Float(_) => "java.lang.Float",
            GPropertyValue::Double(_) => "java.lang.Double",
            GPropertyValue::Boolean(_) => "java.lang.Boolean",
            GPropertyValue::String(_) => "java.lang.String",
            GPropertyValue::Color(_) => "java.awt.Color",
            GPropertyValue::Date(_) => "java.util.Date",
            GPropertyValue::File(_) => "java.io.File",
            GPropertyValue::KeyStroke(_) => "javax.swing.KeyStroke",
            GPropertyValue::Font(_) => "java.awt.Font",
            GPropertyValue::Bytes(_) => "[B",
            GPropertyValue::Shorts(_) => "[S",
            GPropertyValue::Ints(_) => "[I",
            GPropertyValue::Longs(_) => "[J",
            GPropertyValue::Floats(_) => "[F",
            GPropertyValue::Doubles(_) => "[D",
            GPropertyValue::Booleans(_) => "[Z",
            GPropertyValue::Strings(_) => "[Ljava.lang.String;",
            GPropertyValue::Enum(_) => "java.lang.Enum",
            GPropertyValue::GProperties(_) => "ghidra.framework.options.GProperties",
            GPropertyValue::SaveState(_) => "ghidra.framework.options.SaveState",
        }
    }
}

/// Which Java class's `processElement`/`createElement` overrides apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flavor {
    /// `GProperties` (and `XmlProperties`/`JSonProperties`, which do not override them).
    Plain,
    /// `SaveState`.
    SaveState,
}

/// Why JSON could not be restored into a [`GProperties`] (Java throws `AssertException` or a
/// Gson exception).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GPropertiesJsonError(pub String);

impl std::fmt::Display for GPropertiesJsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for GPropertiesJsonError {}

/// Port of `ghidra.framework.options.GProperties`: a named set of typed name/value pairs,
/// ordered by name for deterministic serialization (Java's `TreeMap`).
///
/// Since the getters take a default, an object restoring its state is fully initialized even when
/// a value is missing. Putting a value under an existing name replaces it.
#[derive(Debug, Clone, PartialEq)]
pub struct GProperties {
    pub(crate) map: BTreeMap<String, GPropertyValue>,
    properties_name: String,
}

macro_rules! scalar_accessors {
    ($($put:ident, $get:ident, $variant:ident, $ty:ty, $java:literal;)*) => {$(
        #[doc = concat!("`put", $java, "(String, ", stringify!($ty), ")`.")]
        pub fn $put(&mut self, name: &str, value: $ty) {
            self.map.insert(name.to_string(), GPropertyValue::$variant(value));
        }

        #[doc = concat!("`get", $java, "(String, default)`: the stored value, or `default_value` if \
            there is none (or it has another type, or is null).")]
        pub fn $get(&self, name: &str, default_value: $ty) -> $ty {
            match self.get_checked(name) {
                Some(GPropertyValue::$variant(v)) => v.clone(),
                _ => default_value,
            }
        }
    )*};
}

macro_rules! array_accessors {
    ($($put:ident, $get:ident, $variant:ident, $ty:ty, $java:literal;)*) => {$(
        #[doc = concat!("`put", $java, "(String, ", stringify!($ty), "[])`; `None` stores a null.")]
        pub fn $put(&mut self, name: &str, value: Option<&[$ty]>) {
            let v = value.map_or(GPropertyValue::Null, |v| GPropertyValue::$variant(v.to_vec()));
            self.map.insert(name.to_string(), v);
        }

        #[doc = concat!("`get", $java, "(String, default)`: the stored array (`None` for a stored \
            null), or `default_value` if there is none.")]
        pub fn $get(&self, name: &str, default_value: Option<&[$ty]>) -> Option<Vec<$ty>> {
            match self.map.get(name) {
                Some(GPropertyValue::$variant(v)) => Some(v.clone()),
                Some(GPropertyValue::Null) => None,
                _ => default_value.map(<[$ty]>::to_vec),
            }
        }
    )*};
}

impl GProperties {
    /// `new GProperties(String name)`: an empty property set. The name is only a hint of what
    /// the properties represent (and the XML root tag).
    pub fn new(name: impl Into<String>) -> Self {
        GProperties { map: BTreeMap::new(), properties_name: name.into() }
    }

    /// `new GProperties(Element root)`: restores the properties saved by
    /// [`save_to_xml`](Self::save_to_xml).
    pub fn from_xml(root: &Element) -> Self {
        Self::from_xml_flavored(root, Flavor::Plain)
    }

    pub(crate) fn from_xml_flavored(root: &Element, flavor: Flavor) -> Self {
        let mut props = GProperties::new(root.get_name());
        for elem in root.get_children() {
            props.process_element(elem, flavor);
        }
        props
    }

    /// `new GProperties(JsonObject root)`: restores the properties saved by
    /// [`save_to_json`](Self::save_to_json).
    pub fn from_json(root: &Value) -> Result<Self, GPropertiesJsonError> {
        let err = |m: &str| GPropertiesJsonError(m.to_string());
        let name = root
            .get(LEGACY_PROPERTIES_NAME)
            .or_else(|| root.get(PROPERTIES_NAME))
            .and_then(Value::as_str)
            .ok_or_else(|| err("missing properties name"))?;
        let mut props = GProperties::new(name);
        let values = root.get("VALUES").and_then(Value::as_object).ok_or_else(|| err("missing VALUES"))?;
        let types = root.get("TYPES").and_then(Value::as_object).ok_or_else(|| err("missing TYPES"))?;
        let empty = Map::new();
        let enum_classes = root.get("ENUM_CLASSES").and_then(Value::as_object).unwrap_or(&empty);
        for (name, value) in values {
            let ty = types
                .get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| GPropertiesJsonError(format!("missing type for {name}")))?;
            if let Some(v) = Self::object_from_json(ty, value, enum_classes.get(name))? {
                props.map.insert(name.clone(), v);
            }
        }
        Ok(props)
    }

    /// `processElement(Element)`, including `SaveState`'s override for [`Flavor::SaveState`].
    pub(crate) fn process_element(&mut self, elem: &Element, flavor: Flavor) {
        let tag = elem.get_name();
        if flavor == Flavor::SaveState && tag == SaveState::SAVE_STATE_TAG_NAME {
            SaveState::process_save_state_element(self, elem);
            return;
        }
        let name = elem.get_attribute_value(ATTRIBUTE_NAME).unwrap_or_default().to_string();
        let ty = elem.get_attribute_value(ATTRIBUTE_TYPE);
        let value = elem.get_attribute_value(ATTRIBUTE_VALUE);
        match tag {
            "XML" => {
                if let Some(child) = elem.get_children().first() {
                    self.map.insert(name, GPropertyValue::Xml(child.clone()));
                }
            }
            "BYTES" => {
                if let Some(value) = value {
                    match convert_string_to_bytes(value) {
                        Some(bytes) => {
                            self.map.insert(name, GPropertyValue::Bytes(bytes));
                        }
                        None => warn_bad("byte array", value),
                    }
                }
            }
            STATE => {
                let Some(ty) = ty else { return };
                match Self::parse_state(ty, value, elem) {
                    Ok(Some(v)) => {
                        self.map.insert(name, v);
                    }
                    Ok(None) => {}
                    Err(()) => Msg::warn(
                        "GProperties",
                        &format!("Error processing primitive value in GProperties: {ty} {value:?}"),
                    ),
                }
            }
            "ARRAY" => {
                let Some(ty) = ty else { return };
                match Self::parse_array(ty, elem) {
                    Ok(Some(v)) => {
                        self.map.insert(name, v);
                    }
                    Ok(None) => {}
                    Err(()) => Msg::warn(
                        "GProperties",
                        &format!("Error processing array value in GProperties: {ty}"),
                    ),
                }
            }
            "ENUM" => {
                if ty == Some("enum") {
                    if let (Some(class_name), Some(value)) = (elem.get_attribute_value("CLASS"), value)
                    {
                        self.map.insert(
                            name,
                            GPropertyValue::Enum(EnumOptionValue {
                                class_name: class_name.to_string(),
                                name: value.to_string(),
                            }),
                        );
                    }
                }
            }
            GPROPERTIES_TAG => {
                if let Some(child) = elem.get_children().first() {
                    let nested = GProperties::from_xml(child);
                    self.map.insert(name, GPropertyValue::GProperties(Box::new(nested)));
                }
            }
            "NULL" => {
                self.map.insert(name, GPropertyValue::Null);
            }
            _ => {}
        }
    }

    fn parse_state(ty: &str, value: Option<&str>, elem: &Element) -> Result<Option<GPropertyValue>, ()> {
        let v = || value.ok_or(());
        Ok(Some(match ty {
            "byte" => GPropertyValue::Byte(v()?.parse().map_err(|_| ())?),
            "short" => GPropertyValue::Short(v()?.parse().map_err(|_| ())?),
            "int" => GPropertyValue::Int(v()?.parse().map_err(|_| ())?),
            "long" => GPropertyValue::Long(v()?.parse().map_err(|_| ())?),
            "float" => GPropertyValue::Float(java_parse_double(v()?).ok_or(())? as f32),
            "double" => GPropertyValue::Double(java_parse_double(v()?).ok_or(())?),
            "boolean" => GPropertyValue::Boolean(value.is_some_and(|v| v.eq_ignore_ascii_case("true"))),
            "string" => {
                let encoded = elem.get_attribute_value("ENCODED_VALUE");
                match (value, encoded) {
                    (Some(v), _) => GPropertyValue::String(v.to_string()),
                    (None, Some(enc)) => {
                        let bytes = convert_string_to_bytes(enc).ok_or(())?;
                        GPropertyValue::String(String::from_utf8_lossy(&bytes).into_owned())
                    }
                    (None, None) => GPropertyValue::Null,
                }
            }
            "Color" => GPropertyValue::Color(v()?.parse().map_err(|_| ())?),
            "Date" => GPropertyValue::Date(parse_date(v()?).ok_or(())?),
            "File" => GPropertyValue::File(PathBuf::from(v()?)),
            "KeyStroke" => GPropertyValue::KeyStroke(v()?.to_string()),
            "Font" => GPropertyValue::Font(v()?.to_string()),
            _ => return Ok(None),
        }))
    }

    fn parse_array(ty: &str, elem: &Element) -> Result<Option<GPropertyValue>, ()> {
        let items = || elem.get_children_named(ARRAY_ELEMENT_NAME).map(|e| e.get_attribute_value(ATTRIBUTE_VALUE));
        fn all<'a, T>(it: impl Iterator<Item = Option<&'a str>>, f: impl Fn(&str) -> Option<T>) -> Result<Vec<T>, ()> {
            it.map(|v| v.and_then(&f).ok_or(())).collect()
        }
        Ok(Some(match ty {
            "short" => GPropertyValue::Shorts(all(items(), |s| s.parse().ok())?),
            "int" => GPropertyValue::Ints(all(items(), |s| s.parse().ok())?),
            "long" => GPropertyValue::Longs(all(items(), |s| s.parse().ok())?),
            "float" => GPropertyValue::Floats(all(items(), |s| java_parse_double(s).map(|d| d as f32))?),
            "double" => GPropertyValue::Doubles(all(items(), java_parse_double)?),
            "boolean" => GPropertyValue::Booleans(
                items().map(|v| v.is_some_and(|v| v.eq_ignore_ascii_case("true"))).collect(),
            ),
            "string" => GPropertyValue::Strings(items().flatten().map(str::to_string).collect()),
            _ => return Ok(None),
        }))
    }

    fn object_from_json(
        ty: &str,
        value: &Value,
        enum_class: Option<&Value>,
    ) -> Result<Option<GPropertyValue>, GPropertiesJsonError> {
        let bad = || GPropertiesJsonError(format!("bad {ty} value: {value}"));
        let int = |v: &Value| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)).ok_or_else(bad);
        let float = |v: &Value| v.as_f64().ok_or_else(bad);
        let arr = || value.as_array().ok_or_else(bad);
        Ok(Some(match ty {
            "null" => return Ok(None),
            "String" => GPropertyValue::String(value.as_str().ok_or_else(bad)?.to_string()),
            "Color" => GPropertyValue::Color(int(value)? as i32),
            "Date" => GPropertyValue::Date(
                parse_date(value.as_str().ok_or_else(bad)?)
                    .ok_or_else(|| GPropertiesJsonError(format!("Can't parse date string: {value}")))?,
            ),
            "File" => GPropertyValue::File(PathBuf::from(value.as_str().ok_or_else(bad)?)),
            "KeyStroke" => GPropertyValue::KeyStroke(value.as_str().ok_or_else(bad)?.to_string()),
            "Font" => GPropertyValue::Font(value.as_str().ok_or_else(bad)?.to_string()),
            "byte" => GPropertyValue::Byte(int(value)? as i8),
            "short" => GPropertyValue::Short(int(value)? as i16),
            "int" => GPropertyValue::Int(int(value)? as i32),
            "long" => GPropertyValue::Long(int(value)?),
            "float" => GPropertyValue::Float(float(value)? as f32),
            "double" => GPropertyValue::Double(float(value)?),
            "boolean" => GPropertyValue::Boolean(value.as_bool().ok_or_else(bad)?),
            "byte[]" => GPropertyValue::Bytes(arr()?.iter().map(|v| int(v).map(|i| i as u8)).collect::<Result<_, _>>()?),
            "short[]" => GPropertyValue::Shorts(arr()?.iter().map(|v| int(v).map(|i| i as i16)).collect::<Result<_, _>>()?),
            "int[]" => GPropertyValue::Ints(arr()?.iter().map(|v| int(v).map(|i| i as i32)).collect::<Result<_, _>>()?),
            "long[]" => GPropertyValue::Longs(arr()?.iter().map(int).collect::<Result<_, _>>()?),
            "float[]" => GPropertyValue::Floats(arr()?.iter().map(|v| float(v).map(|f| f as f32)).collect::<Result<_, _>>()?),
            "double[]" => GPropertyValue::Doubles(arr()?.iter().map(float).collect::<Result<_, _>>()?),
            "boolean[]" => GPropertyValue::Booleans(
                arr()?.iter().map(|v| v.as_bool().ok_or_else(bad)).collect::<Result<_, _>>()?,
            ),
            "String[]" => GPropertyValue::Strings(
                arr()?.iter().map(|v| v.as_str().map(str::to_string).ok_or_else(bad)).collect::<Result<_, _>>()?,
            ),
            "xml" => GPropertyValue::Xml(
                Element::parse_str(value.as_str().ok_or_else(bad)?)
                    .map_err(|_| GPropertiesJsonError("Error processing embedded XML".into()))?,
            ),
            "enum" => {
                let class_name = enum_class.and_then(Value::as_str).ok_or_else(bad)?;
                GPropertyValue::Enum(EnumOptionValue {
                    class_name: class_name.to_string(),
                    name: value.as_str().ok_or_else(bad)?.to_string(),
                })
            }
            G_PROPERTIES_TYPE | SAVE_STATE_LEGACY_TYPE => {
                GPropertyValue::GProperties(Box::new(GProperties::from_json(value)?))
            }
            _ => return Err(GPropertiesJsonError(format!("Unknown type: {ty}"))),
        }))
    }

    /// `saveToJsonFile(File)`: writes [`save_to_json`](Self::save_to_json) pretty-printed.
    pub fn save_to_json_file(&self, file: &Path) -> io::Result<()> {
        let text = serde_json::to_string_pretty(&self.save_to_json())
            .map_err(|e| io::Error::other(e.to_string()))?;
        std::fs::write(file, text)
    }

    /// `saveToXmlFile(File)`: writes [`save_to_xml`](Self::save_to_xml) as an XML document.
    pub fn save_to_xml_file(&self, file: &Path) -> io::Result<()> {
        std::fs::write(file, self.save_to_xml().to_document_bytes())
    }

    /// `saveToXml()`: an element named for these properties with one child per value.
    pub fn save_to_xml(&self) -> Element {
        self.save_to_xml_flavored(Flavor::Plain)
    }

    pub(crate) fn save_to_xml_flavored(&self, flavor: Flavor) -> Element {
        let mut root = Element::new(self.properties_name.clone());
        for (key, value) in &self.map {
            root.add_content(Self::create_element(key, value, flavor));
        }
        root
    }

    /// `createElement(String, Object)`, including `SaveState`'s override.
    fn create_element(key: &str, value: &GPropertyValue, flavor: Flavor) -> Element {
        if let (Flavor::SaveState, GPropertyValue::SaveState(s)) = (flavor, value) {
            return s.create_nested_element(key);
        }
        use GPropertyValue as V;
        match value {
            V::Xml(e) => {
                let mut elem = create_named(GPROPERTIES_XML_TAG, key);
                elem.add_content(e.clone());
                elem
            }
            V::Byte(v) => set_attributes(key, "byte", &v.to_string()),
            V::Short(v) => set_attributes(key, "short", &v.to_string()),
            V::Int(v) => set_attributes(key, "int", &v.to_string()),
            V::Long(v) => set_attributes(key, "long", &v.to_string()),
            V::Float(v) => set_attributes(key, "float", &java_float_to_string(*v)),
            V::Double(v) => set_attributes(key, "double", &java_double_to_string(*v)),
            V::Boolean(v) => set_attributes(key, "boolean", &v.to_string()),
            V::String(s) => {
                let mut elem = create_named(STATE, key);
                elem.set_attribute(ATTRIBUTE_TYPE, "string");
                if has_invalid_xml_characters(s) {
                    elem.set_attribute(
                        "ENCODED_VALUE",
                        NumericUtilities::convert_bytes_to_string(s.as_bytes(), ""),
                    );
                } else {
                    elem.set_attribute(ATTRIBUTE_VALUE, s.as_str());
                }
                elem
            }
            V::Color(rgb) => set_attributes(key, "Color", &rgb.to_string()),
            V::Date(d) => set_attributes(key, "Date", &format_date(*d)),
            V::File(f) => set_attributes(key, "File", &absolute_path(f)),
            V::KeyStroke(k) => set_attributes(key, "KeyStroke", k),
            V::Font(f) => set_attributes(key, "Font", f),
            V::Bytes(b) => {
                let mut elem = create_named("BYTES", key);
                elem.set_attribute(ATTRIBUTE_VALUE, NumericUtilities::convert_bytes_to_string(b, ""));
                elem
            }
            V::Shorts(v) => set_array_attributes(key, "short", v.iter().map(|x| x.to_string())),
            V::Ints(v) => set_array_attributes(key, "int", v.iter().map(|x| x.to_string())),
            V::Longs(v) => set_array_attributes(key, "long", v.iter().map(|x| x.to_string())),
            V::Floats(v) => set_array_attributes(key, "float", v.iter().map(|x| java_float_to_string(*x))),
            V::Doubles(v) => set_array_attributes(key, "double", v.iter().map(|x| java_double_to_string(*x))),
            V::Booleans(v) => set_array_attributes(key, "boolean", v.iter().map(|x| x.to_string())),
            V::Strings(v) => set_array_attributes(key, "string", v.iter().cloned()),
            V::Enum(e) => {
                let mut elem = create_named("ENUM", key);
                elem.set_attribute(ATTRIBUTE_TYPE, "enum");
                elem.set_attribute("CLASS", e.class_name.as_str());
                elem.set_attribute(ATTRIBUTE_VALUE, e.name.as_str());
                elem
            }
            V::GProperties(p) => {
                let mut elem = create_named(GPROPERTIES_TAG, key);
                elem.set_attribute(ATTRIBUTE_TYPE, G_PROPERTIES_TYPE);
                elem.add_content(p.save_to_xml());
                elem
            }
            V::SaveState(s) => {
                // A SaveState held by a plain GProperties is written as any other GProperties.
                let mut elem = create_named(GPROPERTIES_TAG, key);
                elem.set_attribute(ATTRIBUTE_TYPE, G_PROPERTIES_TYPE);
                elem.add_content(s.save_to_xml());
                elem
            }
            V::Null => create_named("NULL", key),
        }
    }

    /// `saveToJson()`: `{GPROPERTIES_NAME, VALUES, TYPES, ENUM_CLASSES}`.
    pub fn save_to_json(&self) -> Value {
        let mut types = Map::new();
        let mut values = Map::new();
        let mut enum_classes = Map::new();
        for (key, value) in &self.map {
            use GPropertyValue as V;
            let (ty, v): (&str, Value) = match value {
                V::Null => ("null", json!("null")),
                V::Xml(e) => ("xml", json!(e.output_string_raw())),
                V::Color(rgb) => ("Color", json!(rgb)),
                V::Date(d) => ("Date", json!(format_date(*d))),
                V::File(f) => ("File", json!(absolute_path(f))),
                V::KeyStroke(k) => ("KeyStroke", json!(k)),
                V::Font(f) => ("Font", json!(f)),
                V::Byte(b) => ("byte", json!(b)),
                V::Short(s) => ("short", json!(s)),
                V::Int(i) => ("int", json!(i)),
                V::Long(l) => ("long", json!(l)),
                V::Float(f) => ("float", json!(f)),
                V::Double(d) => ("double", json!(d)),
                V::Boolean(b) => ("boolean", json!(b)),
                V::String(s) => ("String", json!(s)),
                V::Bytes(b) => ("byte[]", json!(b.iter().map(|x| *x as i8).collect::<Vec<_>>())),
                V::Shorts(v) => ("short[]", json!(v)),
                V::Ints(v) => ("int[]", json!(v)),
                V::Longs(v) => ("long[]", json!(v)),
                V::Floats(v) => ("float[]", json!(v)),
                V::Doubles(v) => ("double[]", json!(v)),
                V::Booleans(v) => ("boolean[]", json!(v)),
                V::Strings(v) => ("String[]", json!(v)),
                V::Enum(e) => {
                    enum_classes.insert(key.clone(), json!(e.class_name));
                    ("enum", json!(e.name))
                }
                V::GProperties(p) => (G_PROPERTIES_TYPE, p.save_to_json()),
                V::SaveState(s) => (G_PROPERTIES_TYPE, s.save_to_json()),
            };
            types.insert(key.clone(), json!(ty));
            values.insert(key.clone(), v);
        }
        json!({
            PROPERTIES_NAME: self.properties_name,
            "VALUES": values,
            "TYPES": types,
            "ENUM_CLASSES": enum_classes,
        })
    }

    /// `isEmpty()`.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// `remove(String)`.
    pub fn remove(&mut self, name: &str) {
        self.map.remove(name);
    }

    /// `clear()`.
    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// `size()`.
    pub fn size(&self) -> usize {
        self.map.len()
    }

    /// `getName()`.
    pub fn get_name(&self) -> &str {
        &self.properties_name
    }

    /// `getNames()`: the value names, sorted.
    pub fn get_names(&self) -> Vec<String> {
        self.map.keys().cloned().collect()
    }

    /// `putObject(String, Object)`: stores any supported value.
    pub fn put_object(&mut self, name: &str, value: GPropertyValue) {
        self.map.insert(name.to_string(), value);
    }

    /// `getObject(String)`.
    pub fn get_object(&self, name: &str) -> Option<&GPropertyValue> {
        self.map.get(name)
    }

    /// `hasValue(String)`.
    pub fn has_value(&self, name: &str) -> bool {
        self.map.contains_key(name)
    }

    scalar_accessors! {
        put_int, get_int, Int, i32, "Int";
        put_byte, get_byte, Byte, i8, "Byte";
        put_short, get_short, Short, i16, "Short";
        put_long, get_long, Long, i64, "Long";
        put_boolean, get_boolean, Boolean, bool, "Boolean";
        put_float, get_float, Float, f32, "Float";
        put_double, get_double, Double, f64, "Double";
    }

    array_accessors! {
        put_ints, get_ints, Ints, i32, "Ints";
        put_bytes, get_bytes, Bytes, u8, "Bytes";
        put_shorts, get_shorts, Shorts, i16, "Shorts";
        put_longs, get_longs, Longs, i64, "Longs";
        put_booleans, get_booleans, Booleans, bool, "Booleans";
        put_floats, get_floats, Floats, f32, "Floats";
        put_doubles, get_doubles, Doubles, f64, "Doubles";
        put_strings, get_strings, Strings, String, "Strings";
    }

    /// `putString(String, String)`; `None` stores a null.
    pub fn put_string(&mut self, name: &str, value: Option<&str>) {
        let v = value.map_or(GPropertyValue::Null, |s| GPropertyValue::String(s.to_string()));
        self.map.insert(name.to_string(), v);
    }

    /// `getString(String, String)`: the stored string (`None` for a stored null), or
    /// `default_value` if there is none or it has another type.
    pub fn get_string(&self, name: &str, default_value: Option<&str>) -> Option<String> {
        match self.get_checked(name) {
            Some(GPropertyValue::String(s)) => Some(s.clone()),
            Some(GPropertyValue::Null) => None,
            _ => default_value.map(str::to_string),
        }
    }

    /// `putDate(String, Date)`; `None` stores a null.
    pub fn put_date(&mut self, name: &str, value: Option<SystemTime>) {
        self.map.insert(name.to_string(), value.map_or(GPropertyValue::Null, GPropertyValue::Date));
    }

    /// `getDate(String, Date)`.
    pub fn get_date(&self, name: &str, default_value: Option<SystemTime>) -> Option<SystemTime> {
        match self.get_checked(name) {
            Some(GPropertyValue::Date(d)) => Some(*d),
            Some(GPropertyValue::Null) => None,
            _ => default_value,
        }
    }

    /// `putFile(String, File)`; `None` stores a null.
    pub fn put_file(&mut self, name: &str, value: Option<&Path>) {
        let v = value.map_or(GPropertyValue::Null, |p| GPropertyValue::File(p.to_path_buf()));
        self.map.insert(name.to_string(), v);
    }

    /// `getFile(String, File)`.
    pub fn get_file(&self, name: &str, default_value: Option<&Path>) -> Option<PathBuf> {
        match self.get_checked(name) {
            Some(GPropertyValue::File(f)) => Some(f.clone()),
            Some(GPropertyValue::Null) => None,
            _ => default_value.map(Path::to_path_buf),
        }
    }

    /// `putEnum(String, Enum)`.
    pub fn put_enum<E: PersistableEnum>(&mut self, name: &str, value: &E) {
        self.map.insert(name.to_string(), GPropertyValue::Enum(value.to_enum_value()));
    }

    /// `getEnum(String, T)`: the stored constant of enum `E` (`None` for a stored null), or
    /// `default_value` if there is none, it is not an `E`, or `E` has no such constant.
    pub fn get_enum<E: PersistableEnum>(&self, name: &str, default_value: Option<E>) -> Option<E> {
        match self.map.get(name) {
            Some(GPropertyValue::Enum(e)) if e.class_name == E::java_class_name() => {
                E::value_of(&e.name).or(default_value)
            }
            Some(GPropertyValue::Null) => None,
            _ => default_value,
        }
    }

    /// Type-erased `putEnum`: stores an enum constant given as its Java class and constant name.
    pub fn put_enum_value(&mut self, name: &str, value: EnumOptionValue) {
        self.map.insert(name.to_string(), GPropertyValue::Enum(value));
    }

    /// Type-erased `getEnum`: the stored enum constant's Java class and constant name.
    pub fn get_enum_value(&self, name: &str) -> Option<&EnumOptionValue> {
        match self.map.get(name) {
            Some(GPropertyValue::Enum(e)) => Some(e),
            _ => None,
        }
    }

    /// `putXmlElement(String, Element)`.
    pub fn put_xml_element(&mut self, name: &str, element: Element) {
        self.map.insert(name.to_string(), GPropertyValue::Xml(element));
    }

    /// `getXmlElement(String)`.
    pub fn get_xml_element(&self, name: &str) -> Option<&Element> {
        match self.get_checked(name) {
            Some(GPropertyValue::Xml(e)) => Some(e),
            _ => None,
        }
    }

    /// `putGProperties(String, GProperties)`.
    pub fn put_g_properties(&mut self, name: &str, value: GProperties) {
        self.map.insert(name.to_string(), GPropertyValue::GProperties(Box::new(value)));
    }

    /// `getGProperties(String)`: a nested `GProperties` (or `SaveState`, a subclass in Java).
    pub fn get_g_properties(&self, name: &str) -> Option<&GProperties> {
        match self.get_checked(name) {
            Some(GPropertyValue::GProperties(p)) => Some(p),
            Some(GPropertyValue::SaveState(s)) => Some(s.as_g_properties()),
            _ => None,
        }
    }

    /// `getAsType`'s lookup: the stored value, if any. Callers fall back to their default when it
    /// has another type (Java's `isExpectedType` mismatch, which it only logs at debug level).
    fn get_checked(&self, name: &str) -> Option<&GPropertyValue> {
        self.map.get(name)
    }
}

impl std::fmt::Display for GProperties {
    /// `toString()`: `XmlUtilities.toString(saveToXml())`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.save_to_xml().output_string())
    }
}

const GPROPERTIES_XML_TAG: &str = "XML";

/// `createElement(String tag, String name)` (with the no-op `initializeElement`).
fn create_named(tag: &str, name: &str) -> Element {
    let mut e = Element::new(tag);
    e.set_attribute(ATTRIBUTE_NAME, name);
    e
}

/// `setAttributes(String, String, String)`.
fn set_attributes(name: &str, ty: &str, value: &str) -> Element {
    let mut elem = create_named(STATE, name);
    elem.set_attribute(ATTRIBUTE_TYPE, ty);
    elem.set_attribute(ATTRIBUTE_VALUE, value);
    elem
}

/// `setArrayAttributes(String, String, Object)`.
fn set_array_attributes(name: &str, ty: &str, values: impl Iterator<Item = String>) -> Element {
    let mut elem = create_named("ARRAY", name);
    elem.set_attribute(ATTRIBUTE_TYPE, ty);
    for v in values {
        let mut a = Element::new(ARRAY_ELEMENT_NAME);
        a.set_attribute(ATTRIBUTE_VALUE, v);
        elem.add_content(a);
    }
    elem
}

fn warn_bad(what: &str, value: &str) {
    Msg::warn("GProperties", &format!("Error processing {what} value in GProperties: {value}"));
}

/// `File.getAbsolutePath()`.
fn absolute_path(path: &Path) -> String {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf()).to_string_lossy().into_owned()
}

/// `NumericUtilities.convertStringToBytes(String)`: hex digits, optionally separated by spaces or
/// commas (a single-digit group is zero-padded). `None` where Java throws
/// `IllegalArgumentException`.
pub(crate) fn convert_string_to_bytes(hex: &str) -> Option<Vec<u8>> {
    let condensed: String = if hex.contains([' ', ',']) {
        hex.split([' ', ','])
            .map(|s| if s.len() == 1 { format!("0{s}") } else { s.to_string() })
            .collect()
    } else {
        hex.to_string()
    };
    if condensed.len() % 2 == 1 || !condensed.is_ascii() {
        return None;
    }
    (0..condensed.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&condensed[i..i + 2], 16).ok())
        .collect()
}

/// `GProperties.DATE_FORMAT.format(Date)` (`yyyy-MM-dd'T'HH:mm:ssZ`), in UTC.
fn format_date(date: SystemTime) -> String {
    let secs = date_to_millis(date).div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}+0000",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// `GProperties.DATE_FORMAT.parse(String)`: `yyyy-MM-dd'T'HH:mm:ss` followed by an RFC 822 zone
/// offset (`+HHMM`/`-HHMM`).
fn parse_date(s: &str) -> Option<SystemTime> {
    let s = s.trim();
    if s.len() < 24 || !s.is_ascii() {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (b, t) = (s.as_bytes(), s.as_bytes());
    if b[4] != b'-' || b[7] != b'-' || t[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, se) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let sign = match b[19] {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let (oh, om) = (num(20..22)?, num(22..24)?);
    let local = days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se;
    let utc = local - sign * (oh * 3600 + om * 60);
    Some(date_from_millis(utc * 1000))
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of [`days_from_civil`].
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    //! Ported from `GPropertiesTest` (Features/Base test tree).
    use super::*;
    use crate::framework::options::json_properties::JSonProperties;
    use crate::framework::options::xml_properties::XmlProperties;
    use std::time::Duration;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Endian {
        Big,
        Little,
    }

    impl EnumValues for Endian {
        fn all_values() -> &'static [Self] {
            &[Endian::Big, Endian::Little]
        }
        fn variant_name(&self) -> &'static str {
            match self {
                Endian::Big => "BIG",
                Endian::Little => "LITTLE",
            }
        }
    }

    impl PersistableEnum for Endian {
        fn java_class_name() -> &'static str {
            "ghidra.program.model.lang.Endian"
        }
    }

    fn props() -> GProperties {
        GProperties::new("foo")
    }

    /// `saveAndRestoreToXml()`: through a document written with GenericXMLOutputter and read
    /// back with the secure SAX builder.
    fn xml_round_trip(p: &GProperties) -> GProperties {
        let bytes = p.save_to_xml().to_document_bytes();
        GProperties::from_xml(&Element::parse_bytes(&bytes).unwrap())
    }

    fn json_round_trip(p: &GProperties) -> GProperties {
        let text = serde_json::to_string(&p.save_to_json()).unwrap();
        GProperties::from_json(&serde_json::from_str(&text).unwrap()).unwrap()
    }

    #[test]
    fn test_string() {
        let mut p = props();
        p.put_string("TEST", None);
        assert_eq!(p.get_string("TEST", Some("FRED")), None);
        p.put_string("TEST2", Some("Value"));
        assert_eq!(p.get_string("TEST2", None).as_deref(), Some("Value"));
        let r = xml_round_trip(&p);
        assert_eq!(r.get_string("TEST2", None).as_deref(), Some("Value"));
        assert!(r.has_value("TEST"), "a stored null round-trips as NULL");
        assert_eq!(r.get_string("TEST", Some("FRED")), None);
    }

    #[test]
    fn test_date() {
        let date = parse_date("2020-12-22T14:20:24-0500").unwrap();
        assert_eq!(date, UNIX_EPOCH_PLUS(1_608_664_824));
        let mut p = props();
        p.put_date("TEST", Some(date));
        assert_eq!(p.get_date("TEST", None), Some(date));
        assert_eq!(xml_round_trip(&p).get_date("TEST", None), Some(date));
        assert_eq!(json_round_trip(&p).get_date("TEST", None), Some(date));
        assert_eq!(format_date(date), "2020-12-22T19:20:24+0000");
    }

    #[allow(non_snake_case)]
    fn UNIX_EPOCH_PLUS(secs: u64) -> SystemTime {
        std::time::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn test_file() {
        let file = std::env::current_dir().unwrap().join("myFile.txt");
        let mut p = props();
        p.put_file("TEST", Some(&file));
        assert_eq!(p.get_file("TEST", None), Some(file.clone()));
        assert_eq!(xml_round_trip(&p).get_file("TEST", None), Some(file.clone()));
        assert_eq!(json_round_trip(&p).get_file("TEST", None), Some(file));
    }

    #[test]
    fn awt_values_are_preserved_in_persisted_form() {
        let mut p = props();
        p.put_object("C", GPropertyValue::Color(0xFFFF0000u32 as i32));
        p.put_object("F", GPropertyValue::Font("Dialog-BOLD-12".into()));
        p.put_object("K", GPropertyValue::KeyStroke("ctrl pressed X".into()));
        let xml = p.save_to_xml().output_string();
        assert!(xml.contains("<STATE NAME=\"C\" TYPE=\"Color\" VALUE=\"-65536\" />"), "{xml}");
        assert_eq!(xml_round_trip(&p), p);
        assert_eq!(json_round_trip(&p), p);
    }

    #[test]
    fn test_sub_g_properties() {
        let mut sub = GProperties::new("sub");
        sub.put_int("a", 5);
        sub.put_string("foo", Some("bar"));
        let mut p = props();
        p.put_g_properties("TEST", sub);
        p.put_string("xxx", Some("zzzz"));
        for r in [xml_round_trip(&p), json_round_trip(&p)] {
            assert_eq!(r.get_string("xxx", None).as_deref(), Some("zzzz"));
            let rs = r.get_g_properties("TEST").unwrap();
            assert_eq!(rs.get_names().len(), 2);
            assert_eq!(rs.get_int("a", 0), 5);
            assert_eq!(rs.get_string("foo", Some("")).as_deref(), Some("bar"));
        }
    }

    #[test]
    fn test_string_array() {
        let array = vec!["Dennis", "Bill", "Brian", "Mike", "Ellen", "Steve"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>();
        let mut p = props();
        p.put_strings("ARRAY", Some(&array));
        assert_eq!(p.get_strings("ARRAY", None), Some(array.clone()));
        assert_eq!(xml_round_trip(&p).get_strings("ARRAY", None), Some(array.clone()));
        assert_eq!(json_round_trip(&p).get_strings("ARRAY", None), Some(array));
    }

    #[test]
    fn test_scalars() {
        let mut p = props();
        p.put_byte("FOURTYTWO", 42);
        assert!(p.has_value("FOURTYTWO"));
        assert_eq!(p.get_byte("FOURTYTWO", 0), 42);
        assert!(!p.has_value("XXX"));
        assert_eq!(p.get_byte("XXX", 5), 5);
        p.put_short("S", 42);
        p.put_int("I", 42);
        p.put_long("L", 12_345_678_901_234);
        p.put_float("F", 3.14159);
        p.put_double("D", 3.14159);
        p.put_boolean("B", true);
        for r in [xml_round_trip(&p), json_round_trip(&p)] {
            assert_eq!(r.get_byte("FOURTYTWO", 0), 42);
            assert_eq!(r.get_short("S", 0), 42);
            assert_eq!(r.get_int("I", 0), 42);
            assert_eq!(r.get_long("L", 0), 12_345_678_901_234);
            assert_eq!(r.get_float("F", 0.0), 3.14159);
            assert_eq!(r.get_double("D", 0.0), 3.14159);
            assert!(r.get_boolean("B", false));
        }
        // getAsType: a value of another type yields the default.
        assert_eq!(p.get_int("L", 7), 7);
    }

    #[test]
    fn test_arrays() {
        let mut p = props();
        p.put_bytes("BYTES", Some(&[0, 5, 9, 42, 77, 0xEE]));
        p.put_shorts("S", Some(&[1, 2, 3]));
        p.put_ints("I", Some(&[0, 5, 9, 42, 77]));
        p.put_longs("L", Some(&[1, 2, 3, 4, 5]));
        p.put_floats("F", Some(&[1.1, 2.2, 3.3]));
        p.put_doubles("D", Some(&[1.1, 2.2, 3.3]));
        p.put_booleans("B", Some(&[true, false, true]));
        let xml = p.save_to_xml().output_string();
        assert!(xml.contains("<BYTES NAME=\"BYTES\" VALUE=\"0005092a4dee\" />"), "{xml}");
        assert!(xml.contains("<A VALUE=\"1.1\" />"), "{xml}");
        assert_eq!(xml_round_trip(&p), p);
        assert_eq!(json_round_trip(&p), p);
        assert_eq!(p.get_ints("missing", Some(&[9])), Some(vec![9]));
        p.put_ints("NULL", None);
        assert_eq!(p.get_ints("NULL", Some(&[9])), None);
    }

    #[test]
    fn test_some() {
        let mut p = props();
        p.put_double("PI", 3.14159);
        p.put_byte("BYTE", 0xEEu8 as i8);
        p.put_long("LONG", 65536);
        p.put_string("STRING", Some("See Jane Run"));
        p.put_boolean("BOOL_A", false);
        p.put_boolean("BOOL_B", true);
        assert_eq!(p.get_string("STRING", Some("BOB")).as_deref(), Some("See Jane Run"));
        assert!(p.get_boolean("BOOL_B", false));
        assert_eq!(p.get_byte("BYTE", 0), 0xEEu8 as i8);
        assert!(!p.get_boolean("BOOL_A", true));
        assert_eq!(p.get_long("LONG", 0), 65536);
    }

    #[test]
    fn test_xml() {
        let mut elem1 = Element::new("ELEM_1");
        elem1.set_attribute("NAME", "VALUE");
        elem1.add_content(Element::new("ELEM_2"));
        let mut p = props();
        p.put_xml_element("XML", elem1.clone());
        let elem3 = p.get_xml_element("XML").unwrap();
        assert_eq!(*elem3, elem1);
        assert_eq!(elem3.get_children()[0].get_name(), "ELEM_2");
        // Through the indented document the element gains whitespace text, as with JDOM.
        let r = xml_round_trip(&p);
        let restored = r.get_xml_element("XML").unwrap();
        assert_eq!(restored.get_attribute_value("NAME"), Some("VALUE"));
        assert_eq!(restored.get_children(), elem1.get_children());
        assert_eq!(json_round_trip(&p).get_xml_element("XML"), Some(&elem1));
    }

    #[test]
    fn test_xml_entity_escaping_for_scr_4675() {
        let a = "The following statement is true: 1 < 3 > 2 with some trailing text";
        let b = "The following is a large hex digit: \u{0128}, \u{0132}, \u{c7} and \u{ab} \
                 \u{1D4C8} with some trailing text &#xFF;";
        let c = "That is the Jones' \"love & happiness\".";
        let mut p = props();
        p.put_string("GT_LT_KEY", Some(a));
        p.put_string("HEX_DIGIT_KEY", Some(b));
        p.put_string("AMP_APOS_KEY", Some(c));
        let r = xml_round_trip(&p);
        assert_eq!(r.get_string("GT_LT_KEY", None).as_deref(), Some(a));
        assert_eq!(r.get_string("HEX_DIGIT_KEY", None).as_deref(), Some(b));
        assert_eq!(r.get_string("AMP_APOS_KEY", None).as_deref(), Some(c));
    }

    #[test]
    fn invalid_xml_characters_use_encoded_value() {
        let mut p = props();
        p.put_string("BELL", Some("a\u{7}b"));
        let xml = p.save_to_xml().output_string();
        assert!(xml.contains("ENCODED_VALUE=\"610762\""), "{xml}");
        assert_eq!(xml_round_trip(&p).get_string("BELL", None).as_deref(), Some("a\u{7}b"));
    }

    #[test]
    fn test_is_empty() {
        let mut p = props();
        assert!(p.is_empty());
        p.put_boolean("BOOL", false);
        assert!(!p.is_empty());
        assert_eq!(p.size(), 1);
        p.remove("BOOL");
        assert!(p.is_empty());
    }

    #[test]
    fn test_enum() {
        let mut p = props();
        p.put_enum("Endian", &Endian::Big);
        assert_eq!(p.get_enum("Endian", Some(Endian::Little)), Some(Endian::Big));
        let xml = p.save_to_xml().output_string();
        assert!(xml.contains(
            "<ENUM NAME=\"Endian\" TYPE=\"enum\" CLASS=\"ghidra.program.model.lang.Endian\" VALUE=\"BIG\" />"
        ));
        assert_eq!(xml_round_trip(&p).get_enum("Endian", None::<Endian>), Some(Endian::Big));
        assert_eq!(json_round_trip(&p).get_enum("Endian", None::<Endian>), Some(Endian::Big));
        // An unknown constant falls back to the default.
        p.put_enum_value(
            "bad",
            EnumOptionValue { class_name: Endian::java_class_name().into(), name: "MIDDLE".into() },
        );
        assert_eq!(p.get_enum("bad", Some(Endian::Little)), Some(Endian::Little));
    }

    #[test]
    fn test_file_input_output() {
        let dir = std::env::temp_dir();
        let file = dir.join(format!("GPropertiesTest-{}.xml", std::process::id()));
        let mut p = props();
        p.put_boolean("B1", true);
        p.put_int("I1", 7);
        p.put_string("S1", Some("Hey There"));
        p.save_to_xml_file(&file).unwrap();
        let ss2 = XmlProperties::from_file(&file).unwrap();
        std::fs::remove_file(&file).unwrap();
        assert!(ss2.get_boolean("B1", false));
        assert_eq!(ss2.get_int("I1", 1), 7);
        assert_eq!(ss2.get_string("S1", Some("")).as_deref(), Some("Hey There"));
        assert_eq!(ss2.get_name(), "foo");
    }

    #[test]
    fn test_json_full_round_trip_through_file() {
        let file = std::env::temp_dir().join(format!("GPropertiesTest-{}.json", std::process::id()));
        let mut p = props();
        p.put_string("Name", Some("Bob"));
        p.put_boolean("Retired", true);
        p.put_int("Age", 65);
        p.put_enum("Endian", &Endian::Big);
        p.put_ints("grades", Some(&[90, 95, 82, 93]));
        p.save_to_json_file(&file).unwrap();
        let r = JSonProperties::from_file(&file).unwrap();
        std::fs::remove_file(&file).unwrap();
        assert_eq!(r.get_string("Name", Some("")).as_deref(), Some("Bob"));
        assert!(r.get_boolean("Retired", false));
        assert_eq!(r.get_int("Age", 0), 65);
        assert_eq!(r.get_enum("Endian", Some(Endian::Little)), Some(Endian::Big));
        assert_eq!(r.get_ints("grades", None), Some(vec![90, 95, 82, 93]));
    }

    #[test]
    fn json_shape_and_null_handling() {
        let mut p = props();
        p.put_string("n", None);
        p.put_float("f", 12.123);
        let json = p.save_to_json();
        assert_eq!(json["GPROPERTIES_NAME"], "foo");
        assert_eq!(json["TYPES"]["n"], "null");
        assert_eq!(json["VALUES"]["n"], "null");
        assert_eq!(json["TYPES"]["f"], "float");
        // Java's constructor drops null values on restore.
        let r = json_round_trip(&p);
        assert!(!r.has_value("n"));
        assert_eq!(r.get_float("f", 0.0), 12.123);
        // Legacy name key and unknown types.
        let legacy = serde_json::json!({"SAVE_STATE_NAME": "old", "VALUES": {}, "TYPES": {},
            "ENUM_CLASSES": {}});
        assert_eq!(GProperties::from_json(&legacy).unwrap().get_name(), "old");
        let bad = serde_json::json!({"GPROPERTIES_NAME": "x", "VALUES": {"a": 1},
            "TYPES": {"a": "Widget"}, "ENUM_CLASSES": {}});
        assert!(GProperties::from_json(&bad).is_err());
    }

    #[test]
    fn convert_string_to_bytes_matches_numeric_utilities() {
        assert_eq!(convert_string_to_bytes("0a0B"), Some(vec![0x0a, 0x0b]));
        assert_eq!(convert_string_to_bytes("a b,c"), Some(vec![0x0a, 0x0b, 0x0c]));
        assert_eq!(convert_string_to_bytes("abc"), None);
        assert_eq!(convert_string_to_bytes("zz"), None);
    }
}
