//! Port of `ghidra.trace.model.target.schema.PrimitiveTraceObjectSchema`: the schemas common to
//! all contexts, as they describe the primitive and built-in types.
//!
//! Java `Class<?>` tokens are represented by class names: `Class.getName()` for scalar types and
//! `Class.getCanonicalName()` (e.g. `boolean[]`) for arrays, so that
//! [`PrimitiveTraceObjectSchema::schema_for_primitive`] can be queried with readable names.
use std::sync::OnceLock;

use crate::debug::api::tracermi::SchemaName;
use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
use crate::trace::model::target::schema::default_schema_context::DefaultSchemaContext;
use crate::trace::model::target::schema::trace_object_schema::{
    AttributeSchema, TraceObjectSchema, TRACE_OBJECT_TYPE,
};

/// The built-in schemas. Mirrors the Java enum constant-for-constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PrimitiveTraceObjectSchema {
    /// The top-most type descriptor: any primitive or a `TraceObject`.
    Any,
    /// The least restrictive, but least informative object schema.
    Object,
    /// A Java class.
    Type,
    /// No value.
    Void,
    /// `boolean`.
    Bool,
    /// `byte`.
    Byte,
    /// `short`.
    Short,
    /// `int`.
    Int,
    /// `long`.
    Long,
    /// `String`.
    String,
    /// `Address`.
    Address,
    /// `AddressRange`.
    Range,
    /// `TraceExecutionState`.
    ExecutionState,
    /// Method parameter maps (not yet described in Java either: `Unfinished`).
    MapParameters,
    /// `char` (additional types supported by the Trace database follow).
    Char,
    /// `boolean[]`.
    BoolArr,
    /// `byte[]`.
    ByteArr,
    /// `char[]`.
    CharArr,
    /// `short[]`.
    ShortArr,
    /// `int[]`.
    IntArr,
    /// `long[]`.
    LongArr,
    /// `String[]`.
    StringArr,
}

impl PrimitiveTraceObjectSchema {
    /// All constants in declaration order. Mirrors `values()`.
    pub const VALUES: [PrimitiveTraceObjectSchema; 22] = [
        Self::Any,
        Self::Object,
        Self::Type,
        Self::Void,
        Self::Bool,
        Self::Byte,
        Self::Short,
        Self::Int,
        Self::Long,
        Self::String,
        Self::Address,
        Self::Range,
        Self::ExecutionState,
        Self::MapParameters,
        Self::Char,
        Self::BoolArr,
        Self::ByteArr,
        Self::CharArr,
        Self::ShortArr,
        Self::IntArr,
        Self::LongArr,
        Self::StringArr,
    ];

    /// The Java constant name, which is also the schema name. Mirrors `name()`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Any => "ANY",
            Self::Object => "OBJECT",
            Self::Type => "TYPE",
            Self::Void => "VOID",
            Self::Bool => "BOOL",
            Self::Byte => "BYTE",
            Self::Short => "SHORT",
            Self::Int => "INT",
            Self::Long => "LONG",
            Self::String => "STRING",
            Self::Address => "ADDRESS",
            Self::Range => "RANGE",
            Self::ExecutionState => "EXECUTION_STATE",
            Self::MapParameters => "MAP_PARAMETERS",
            Self::Char => "CHAR",
            Self::BoolArr => "BOOL_ARR",
            Self::ByteArr => "BYTE_ARR",
            Self::CharArr => "CHAR_ARR",
            Self::ShortArr => "SHORT_ARR",
            Self::IntArr => "INT_ARR",
            Self::LongArr => "LONG_ARR",
            Self::StringArr => "STRING_ARR",
        }
    }

    /// The Java classes this schema accepts, the preferred one first. Mirrors `getTypes()`.
    pub fn get_types(self) -> &'static [&'static str] {
        match self {
            Self::Any => &["java.lang.Object"],
            Self::Object => &[TRACE_OBJECT_TYPE],
            Self::Type => &["java.lang.Class"],
            Self::Void => &["java.lang.Void", "void"],
            Self::Bool => &["java.lang.Boolean", "boolean"],
            Self::Byte => &["java.lang.Byte", "byte"],
            Self::Short => &["java.lang.Short", "short"],
            Self::Int => &["java.lang.Integer", "int"],
            Self::Long => &["java.lang.Long", "long"],
            Self::String => &["java.lang.String"],
            Self::Address => &["ghidra.program.model.address.Address"],
            Self::Range => &["ghidra.program.model.address.AddressRange"],
            Self::ExecutionState => &["ghidra.trace.model.TraceExecutionState"],
            Self::MapParameters => &["ghidra.lifecycle.Unfinished"],
            Self::Char => &["java.lang.Character", "char"],
            Self::BoolArr => &["boolean[]"],
            Self::ByteArr => &["byte[]"],
            Self::CharArr => &["char[]"],
            Self::ShortArr => &["short[]"],
            Self::IntArr => &["int[]"],
            Self::LongArr => &["long[]"],
            Self::StringArr => &["java.lang.String[]"],
        }
    }

    /// Look up the schema whose [types](Self::get_types) include `cls`. Mirrors
    /// `schemaForPrimitive(Class)`.
    pub fn schema_for_primitive(cls: &str) -> Option<PrimitiveTraceObjectSchema> {
        Self::VALUES.into_iter().find(|s| s.get_types().contains(&cls))
    }

    /// The name of the schema for `cls`, if any. Mirrors `nameForPrimitive(Class)`.
    pub fn name_for_primitive(cls: &str) -> Option<SchemaName> {
        Self::schema_for_primitive(cls).map(|s| SchemaName::new(s.name()))
    }

    /// Look up a primitive by its schema name.
    pub fn from_name(name: &SchemaName) -> Option<PrimitiveTraceObjectSchema> {
        Self::VALUES.into_iter().find(|s| s.name() == name.as_str())
    }

    /// The context holding exactly the primitives. Mirrors
    /// `MinimalSchemaContext.INSTANCE`.
    pub fn minimal_context() -> DefaultSchemaContext {
        static INSTANCE: OnceLock<DefaultSchemaContext> = OnceLock::new();
        INSTANCE.get_or_init(DefaultSchemaContext::new).clone()
    }
}

impl TraceObjectSchema for PrimitiveTraceObjectSchema {
    fn get_context(&self) -> DefaultSchemaContext {
        Self::minimal_context()
    }

    fn get_name(&self) -> SchemaName {
        SchemaName::new(self.name())
    }

    fn get_type(&self) -> &'static str {
        self.get_types()[0]
    }

    fn get_interfaces(&self) -> Vec<TraceObjectInfo> {
        Vec::new()
    }

    fn is_canonical_container(&self) -> bool {
        false
    }

    fn get_element_schemas(&self) -> &[(String, SchemaName)] {
        &[]
    }

    fn get_default_element_schema(&self) -> SchemaName {
        match self {
            Self::Any | Self::Object => Self::Object.get_name(),
            _ => Self::Void.get_name(),
        }
    }

    fn get_attribute_schemas(&self) -> &[(String, AttributeSchema)] {
        &[]
    }

    fn get_attribute_aliases(&self) -> &[(String, String)] {
        &[]
    }

    fn get_default_attribute_schema(&self) -> AttributeSchema {
        match self {
            Self::Any | Self::Object => AttributeSchema::default_any(),
            _ => AttributeSchema::default_void(),
        }
    }

    fn is_primitive(&self) -> bool {
        true
    }

    fn to_string(&self) -> String {
        self.name().to_string()
    }

    fn is_assignable_from(&self, that: &dyn TraceObjectSchema) -> bool {
        match self {
            // OBJECT: "That it has a schema implies it's a TraceObject"
            Self::Any | Self::Object => true,
            _ => that.is_primitive() && that.get_name().as_str() == self.name(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::model::target::path::KeyPath;
    use crate::trace::model::target::schema::schema_context::SchemaContext;
    use crate::trace::model::target::schema::trace_object_schema::{
        Hidden, TraceObjectSchemaExt,
    };

    #[test]
    fn names_match_java_constants() {
        assert_eq!(PrimitiveTraceObjectSchema::Any.get_name(), SchemaName::new("ANY"));
        assert_eq!(PrimitiveTraceObjectSchema::ExecutionState.name(), "EXECUTION_STATE");
        assert_eq!(PrimitiveTraceObjectSchema::StringArr.name(), "STRING_ARR");
        assert_eq!(PrimitiveTraceObjectSchema::VALUES.len(), 22);
    }

    #[test]
    fn any_and_object_override_defaults() {
        let any = PrimitiveTraceObjectSchema::Any;
        assert!(any.is_assignable_from(&PrimitiveTraceObjectSchema::Void));
        assert_eq!(any.get_default_element_schema(), SchemaName::new("OBJECT"));
        assert_eq!(any.get_default_attribute_schema(), AttributeSchema::default_any());
        assert_eq!(any.get_type(), "java.lang.Object");
        let obj = PrimitiveTraceObjectSchema::Object;
        assert!(obj.is_assignable_from(&PrimitiveTraceObjectSchema::Int));
        assert_eq!(obj.get_type(), TRACE_OBJECT_TYPE);
    }

    #[test]
    fn other_primitives_forbid_successors() {
        let void = PrimitiveTraceObjectSchema::Void;
        assert!(!void.is_assignable_from(&PrimitiveTraceObjectSchema::Any));
        assert!(void.is_assignable_from(&PrimitiveTraceObjectSchema::Void));
        assert_eq!(void.get_default_element_schema(), SchemaName::new("VOID"));
        let das = PrimitiveTraceObjectSchema::Int.get_default_attribute_schema();
        assert_eq!(das, AttributeSchema::default_void());
        assert_eq!(das.get_hidden(), Hidden::True);
        assert!(das.is_fixed());
        assert!(!void.is_canonical_container());
        assert!(void.get_element_schemas().is_empty());
        assert!(void.search_for("Process", false).is_none());
        assert!(void.search_for_canonical_container("Process").is_none());
        assert!(void.search_for_suitable("Process", &KeyPath::root()).is_none());
    }

    #[test]
    fn get_type_is_first_of_types() {
        assert_eq!(PrimitiveTraceObjectSchema::Bool.get_types(), &["java.lang.Boolean", "boolean"]);
        assert_eq!(PrimitiveTraceObjectSchema::Bool.get_type(), "java.lang.Boolean");
    }

    #[test]
    fn schema_for_primitive_searches_all_types() {
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_primitive("int"),
            Some(PrimitiveTraceObjectSchema::Int)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::name_for_primitive("java.lang.Long"),
            Some(SchemaName::new("LONG"))
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::name_for_primitive("byte[]"),
            Some(SchemaName::new("BYTE_ARR"))
        );
        assert_eq!(PrimitiveTraceObjectSchema::schema_for_primitive("java.util.List"), None);
    }

    #[test]
    fn minimal_context_holds_exactly_the_primitives() {
        let ctx = PrimitiveTraceObjectSchema::Long.get_context();
        let all = ctx.get_all_schema_names();
        assert_eq!(all.len(), 22);
        assert_eq!(all[0], SchemaName::new("ANY"));
        assert!(ctx.get_schema_or_null(&SchemaName::new("STRING")).is_some());
    }

    #[test]
    fn child_schema_of_any_is_object() {
        let any = PrimitiveTraceObjectSchema::Any;
        assert_eq!(any.get_child_schema("[0]").get_name(), SchemaName::new("OBJECT"));
        assert_eq!(any.get_child_schema("foo").get_name(), SchemaName::new("ANY"));
        assert!(any.is_hidden("_foo"));
        assert!(!any.is_hidden("foo"));
        assert!(!any.is_hidden("[_0]"));
    }
}
