//! Port of `ghidra.trace.model.target.schema.SchemaBuilder`.
//!
//! Java's "origin" arguments are arbitrary objects (in practice the XML element a declaration
//! came from) used only in duplicate-declaration messages; they are their `toString()` here.
use crate::debug::api::tracermi::SchemaName;
use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
use crate::trace::model::target::schema::default_schema_context::DefaultSchemaContext;
use crate::trace::model::target::schema::default_trace_object_schema::DefaultTraceObjectSchema;
use crate::trace::model::target::schema::primitive_trace_object_schema::PrimitiveTraceObjectSchema;
use crate::trace::model::target::schema::trace_object_schema::{
    AttributeSchema, SchemaArgumentError, TraceObjectSchema, TRACE_OBJECT_TYPE,
};

fn lookup<'a, V>(entries: &'a [(String, V)], key: &str) -> Option<&'a V> {
    entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn put<V>(entries: &mut Vec<(String, V)>, key: &str, value: V) {
    match entries.iter_mut().find(|(k, _)| k == key) {
        Some(entry) => entry.1 = value,
        None => entries.push((key.to_string(), value)),
    }
}

fn remove<V>(entries: &mut Vec<(String, V)>, key: &str) {
    entries.retain(|(k, _)| k != key);
}

/// A builder for a [`TraceObjectSchema`]. Mirrors
/// `ghidra.trace.model.target.schema.SchemaBuilder`.
#[derive(Debug)]
pub struct SchemaBuilder {
    context: DefaultSchemaContext,
    name: SchemaName,
    type_name: &'static str,
    interfaces: Vec<TraceObjectInfo>,
    is_canonical_container: bool,
    element_schemas: Vec<(String, SchemaName)>,
    default_element_schema: SchemaName,
    attribute_schemas: Vec<(String, AttributeSchema)>,
    attribute_aliases: Vec<(String, String)>,
    default_attribute_schema: AttributeSchema,
    element_origins: Vec<(String, String)>,
    attribute_origins: Vec<(String, String)>,
}

impl SchemaBuilder {
    /// Mirrors `DEFAULT_ELEMENT_SCHEMA`: `OBJECT`.
    pub fn default_element_schema_name() -> SchemaName {
        PrimitiveTraceObjectSchema::Object.get_name()
    }

    /// Mirrors `DEFAULT_ATTRIBUTE_SCHEMA`: `AttributeSchema.DEFAULT_ANY`.
    pub fn default_attribute_schema_value() -> AttributeSchema {
        AttributeSchema::default_any()
    }

    /// A fresh builder. Mirrors `SchemaBuilder(DefaultSchemaContext, SchemaName)`.
    pub fn new(context: DefaultSchemaContext, name: SchemaName) -> Self {
        SchemaBuilder {
            context,
            name,
            type_name: TRACE_OBJECT_TYPE,
            interfaces: Vec::new(),
            is_canonical_container: false,
            element_schemas: Vec::new(),
            default_element_schema: Self::default_element_schema_name(),
            attribute_schemas: Vec::new(),
            attribute_aliases: Vec::new(),
            default_attribute_schema: Self::default_attribute_schema_value(),
            element_origins: Vec::new(),
            attribute_origins: Vec::new(),
        }
    }

    /// A builder initialized from `schema`. Mirrors
    /// `SchemaBuilder(DefaultSchemaContext, TraceObjectSchema)`: like Java, the aliases are not
    /// copied (their resolved entries are among the attribute schemas).
    pub fn from_schema(context: DefaultSchemaContext, schema: &dyn TraceObjectSchema) -> Self {
        let mut b = Self::new(context, schema.get_name());
        b.set_type(schema.get_type());
        b.set_interfaces(schema.get_interfaces());
        b.set_canonical_container(schema.is_canonical_container());
        for (k, v) in schema.get_element_schemas() {
            put(&mut b.element_schemas, k, v.clone());
        }
        b.set_default_element_schema(schema.get_default_element_schema());
        for (k, v) in schema.get_attribute_schemas() {
            put(&mut b.attribute_schemas, k, v.clone());
        }
        b.set_default_attribute_schema(schema.get_default_attribute_schema());
        b
    }

    /// Mirrors `setType(Class)`.
    pub fn set_type(&mut self, type_name: &'static str) -> &mut Self {
        self.type_name = type_name;
        self
    }

    /// Mirrors `getType()`.
    pub fn get_type(&self) -> &'static str {
        self.type_name
    }

    /// Replace the interfaces. Mirrors `setInterfaces(Set)`.
    pub fn set_interfaces(&mut self, interfaces: Vec<TraceObjectInfo>) -> &mut Self {
        self.interfaces.clear();
        for iface in interfaces {
            self.add_interface(iface);
        }
        self
    }

    /// Mirrors `getInterfaces()`.
    pub fn get_interfaces(&self) -> Vec<TraceObjectInfo> {
        self.interfaces.clone()
    }

    /// Add an interface (a set: adding one twice has no effect). Mirrors `addInterface(Class)`.
    pub fn add_interface(&mut self, iface: TraceObjectInfo) -> &mut Self {
        if !self.interfaces.iter().any(|i| i.schema_name == iface.schema_name) {
            self.interfaces.push(iface);
        }
        self
    }

    /// Remove the interface with the given schema name. Mirrors `removeInterface(Class)`.
    pub fn remove_interface(&mut self, schema_name: &str) -> &mut Self {
        self.interfaces.retain(|i| i.schema_name != schema_name);
        self
    }

    /// Mirrors `setCanonicalContainer(boolean)`.
    pub fn set_canonical_container(&mut self, is_canonical_container: bool) -> &mut Self {
        self.is_canonical_container = is_canonical_container;
        self
    }

    /// Mirrors `isCanonicalContaineration()` (sic).
    pub fn is_canonical_container(&self) -> bool {
        self.is_canonical_container
    }

    /// Declare the schema of element `index`; the empty index sets the default. Mirrors
    /// `addElementSchema(String, SchemaName, Object)`: fails on a duplicate index.
    pub fn add_element_schema(
        &mut self,
        index: &str,
        schema: SchemaName,
        origin: impl ToString,
    ) -> Result<&mut Self, SchemaArgumentError> {
        if index.is_empty() {
            return Ok(self.set_default_element_schema(schema));
        }
        if lookup(&self.element_schemas, index).is_some() {
            let origin1 = lookup(&self.element_origins, index).cloned().unwrap_or_default();
            return Err(SchemaArgumentError(format!(
                "Duplicate element index '{index}' origin1={origin1} origin2={}",
                origin.to_string()
            )));
        }
        put(&mut self.element_schemas, index, schema);
        put(&mut self.element_origins, index, origin.to_string());
        Ok(self)
    }

    /// Mirrors `removeElementSchema(String)`; the empty index resets the default to `OBJECT`.
    pub fn remove_element_schema(&mut self, index: &str) -> &mut Self {
        if index.is_empty() {
            return self.set_default_element_schema(PrimitiveTraceObjectSchema::Object.get_name());
        }
        remove(&mut self.element_schemas, index);
        remove(&mut self.element_origins, index);
        self
    }

    /// Mirrors `getElementSchemas()`.
    pub fn get_element_schemas(&self) -> &[(String, SchemaName)] {
        &self.element_schemas
    }

    /// Mirrors `setDefaultElementSchema(SchemaName)`.
    pub fn set_default_element_schema(&mut self, schema: SchemaName) -> &mut Self {
        self.default_element_schema = schema;
        self
    }

    /// Mirrors `getDefaultElementSchema()`.
    pub fn get_default_element_schema(&self) -> &SchemaName {
        &self.default_element_schema
    }

    /// Declare an attribute; an empty-named one sets the default. Mirrors
    /// `addAttributeSchema(AttributeSchema, Object)`: fails if the name is already declared (as
    /// an attribute or alias).
    pub fn add_attribute_schema(
        &mut self,
        schema: AttributeSchema,
        origin: impl ToString,
    ) -> Result<&mut Self, SchemaArgumentError> {
        if schema.get_name().is_empty() {
            return Ok(self.set_default_attribute_schema(schema));
        }
        let name = schema.get_name().to_string();
        if let Some(origin1) = lookup(&self.attribute_origins, &name) {
            return Err(SchemaArgumentError(format!(
                "Duplicate attribute name '{name}' adding schema origin1={origin1} origin2={}",
                origin.to_string()
            )));
        }
        put(&mut self.attribute_schemas, &name, schema);
        put(&mut self.attribute_origins, &name, origin.to_string());
        Ok(self)
    }

    /// Mirrors `removeAttributeSchema(String)`; the empty name resets the default to
    /// `DEFAULT_ANY`.
    pub fn remove_attribute_schema(&mut self, name: &str) -> &mut Self {
        if name.is_empty() {
            return self.set_default_attribute_schema(AttributeSchema::default_any());
        }
        remove(&mut self.attribute_schemas, name);
        remove(&mut self.attribute_aliases, name);
        remove(&mut self.attribute_origins, name);
        self
    }

    /// Mirrors `getAttributeSchemas()`.
    pub fn get_attribute_schemas(&self) -> &[(String, AttributeSchema)] {
        &self.attribute_schemas
    }

    /// Mirrors `getAttributeSchema(String)`.
    pub fn get_attribute_schema(&self, name: &str) -> Option<&AttributeSchema> {
        lookup(&self.attribute_schemas, name)
    }

    /// Declare or replace an attribute (dropping any alias of that name). Mirrors
    /// `replaceAttributeSchema(AttributeSchema, Object)`.
    pub fn replace_attribute_schema(
        &mut self,
        schema: AttributeSchema,
        origin: impl ToString,
    ) -> &mut Self {
        if schema.get_name().is_empty() {
            return self.set_default_attribute_schema(schema);
        }
        let name = schema.get_name().to_string();
        remove(&mut self.attribute_aliases, &name);
        put(&mut self.attribute_schemas, &name, schema);
        put(&mut self.attribute_origins, &name, origin.to_string());
        self
    }

    fn validate_alias(from: &str, to: &str) -> Result<(), SchemaArgumentError> {
        if from.is_empty() {
            return Err(SchemaArgumentError("Key '' cannot be an alias".into()));
        }
        if to.is_empty() {
            return Err(SchemaArgumentError(format!("Cannot alias to key '' (from {from})")));
        }
        Ok(())
    }

    /// Declare an alias. Mirrors `addAttributeAlias(String, String, Object)`: fails if `from`
    /// is already declared.
    pub fn add_attribute_alias(
        &mut self,
        from: &str,
        to: &str,
        origin: impl ToString,
    ) -> Result<&mut Self, SchemaArgumentError> {
        Self::validate_alias(from, to)?;
        if let Some(origin1) = lookup(&self.attribute_origins, from) {
            return Err(SchemaArgumentError(format!(
                "Duplicate attribute name '{from}' adding alias origin1={origin1} origin2={}",
                origin.to_string()
            )));
        }
        put(&mut self.attribute_aliases, from, to.to_string());
        put(&mut self.attribute_origins, from, origin.to_string());
        Ok(self)
    }

    /// Declare or replace an alias (dropping any attribute of that name). Mirrors
    /// `replaceAttributeAlias(String, String, Object)`.
    pub fn replace_attribute_alias(
        &mut self,
        from: &str,
        to: &str,
        origin: impl ToString,
    ) -> Result<&mut Self, SchemaArgumentError> {
        Self::validate_alias(from, to)?;
        remove(&mut self.attribute_schemas, from);
        put(&mut self.attribute_aliases, from, to.to_string());
        put(&mut self.attribute_origins, from, origin.to_string());
        Ok(self)
    }

    /// Mirrors `setDefaultAttributeSchema(AttributeSchema)`.
    pub fn set_default_attribute_schema(&mut self, schema: AttributeSchema) -> &mut Self {
        self.default_attribute_schema = schema;
        self
    }

    /// Mirrors `getDefaultAttributeSchema()`.
    pub fn get_default_attribute_schema(&self) -> &AttributeSchema {
        &self.default_attribute_schema
    }

    /// Build the schema and add it to the context. Mirrors `buildAndAdd()`.
    pub fn build_and_add(&self) -> Result<DefaultTraceObjectSchema, SchemaArgumentError> {
        let schema = self.build()?;
        self.context.put_schema(&schema)?;
        Ok(schema)
    }

    /// Build the schema and add or replace it in the context. Mirrors `buildAndReplace()`.
    pub fn build_and_replace(&self) -> Result<DefaultTraceObjectSchema, SchemaArgumentError> {
        let schema = self.build()?;
        self.context.replace_schema(&schema);
        Ok(schema)
    }

    /// Build the schema without adding it. Mirrors `build()`.
    pub fn build(&self) -> Result<DefaultTraceObjectSchema, SchemaArgumentError> {
        DefaultTraceObjectSchema::new(
            self.context.clone(),
            self.name.clone(),
            self.type_name,
            &self.interfaces,
            self.is_canonical_container,
            &self.element_schemas,
            self.default_element_schema.clone(),
            &self.attribute_schemas,
            &self.attribute_aliases,
            self.default_attribute_schema.clone(),
        )
    }
}

/// Test support: a plain object schema named `name` (all builder defaults), added to a fresh
/// context.
#[cfg(test)]
pub(crate) fn plain_schema(name: &str) -> DefaultTraceObjectSchema {
    DefaultSchemaContext::new()
        .builder(SchemaName::new(name))
        .build_and_add()
        .expect("fresh context has no schema of this name")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::model::target::schema::trace_object_schema::Hidden;

    fn info(name: &str) -> TraceObjectInfo {
        TraceObjectInfo::new(name, name.to_lowercase(), [] as [&str; 0], [] as [&str; 0])
    }

    #[test]
    fn defaults_match_java() {
        let b = SchemaBuilder::new(DefaultSchemaContext::new(), SchemaName::new("X"));
        assert_eq!(b.get_type(), TRACE_OBJECT_TYPE);
        assert_eq!(b.get_default_element_schema(), &SchemaName::new("OBJECT"));
        assert_eq!(b.get_default_attribute_schema(), &AttributeSchema::default_any());
        assert!(!b.is_canonical_container());
    }

    #[test]
    fn empty_keys_set_defaults() {
        let mut b = SchemaBuilder::new(DefaultSchemaContext::new(), SchemaName::new("X"));
        b.add_element_schema("", SchemaName::new("VOID"), "o").unwrap();
        b.add_attribute_schema(AttributeSchema::default_void(), "o").unwrap();
        assert_eq!(b.get_default_element_schema(), &SchemaName::new("VOID"));
        assert_eq!(b.get_default_attribute_schema(), &AttributeSchema::default_void());
        b.remove_element_schema("").remove_attribute_schema("");
        assert_eq!(b.get_default_element_schema(), &SchemaName::new("OBJECT"));
        assert_eq!(b.get_default_attribute_schema(), &AttributeSchema::default_any());
    }

    #[test]
    fn duplicates_are_rejected_with_origins() {
        let mut b = SchemaBuilder::new(DefaultSchemaContext::new(), SchemaName::new("X"));
        b.add_element_schema("0", SchemaName::new("A"), "e1").unwrap();
        let err = b.add_element_schema("0", SchemaName::new("B"), "e2").unwrap_err();
        assert_eq!(err.0, "Duplicate element index '0' origin1=e1 origin2=e2");
        let a = AttributeSchema::new("Name", SchemaName::new("STRING"), true, false,
            Hidden::Default).unwrap();
        b.add_attribute_schema(a.clone(), "a1").unwrap();
        let err = b.add_attribute_alias("Name", "Other", "a2").unwrap_err();
        assert_eq!(err.0, "Duplicate attribute name 'Name' adding alias origin1=a1 origin2=a2");
        let err = b.add_attribute_schema(a, "a3").unwrap_err();
        assert_eq!(err.0, "Duplicate attribute name 'Name' adding schema origin1=a1 origin2=a3");
    }

    #[test]
    fn replace_swaps_between_attribute_and_alias() {
        let mut b = SchemaBuilder::new(DefaultSchemaContext::new(), SchemaName::new("X"));
        b.add_attribute_alias("n", "Name", "o").unwrap();
        let a = AttributeSchema::new("n", SchemaName::new("INT"), false, false, Hidden::True)
            .unwrap();
        b.replace_attribute_schema(a, "o2");
        let s = b.build().unwrap();
        assert!(s.get_attribute_aliases().is_empty());
        assert_eq!(s.get_attribute_schema("n").get_schema(), &SchemaName::new("INT"));
        b.replace_attribute_alias("n", "Name", "o3").unwrap();
        assert!(b.get_attribute_schema("n").is_none());
    }

    #[test]
    fn interfaces_are_a_set() {
        let mut b = SchemaBuilder::new(DefaultSchemaContext::new(), SchemaName::new("X"));
        b.add_interface(info("Process")).add_interface(info("Aggregate"));
        b.add_interface(info("Process"));
        assert_eq!(b.get_interfaces().len(), 2);
        b.remove_interface("Process");
        assert_eq!(b.get_interfaces()[0].schema_name, "Aggregate");
    }

    #[test]
    fn from_schema_copies_everything_but_aliases() {
        let ctx = DefaultSchemaContext::new();
        let mut b = ctx.builder(SchemaName::new("X"));
        b.add_interface(info("Process")).set_canonical_container(true);
        b.add_element_schema("0", SchemaName::new("Thread"), "o").unwrap();
        b.add_attribute_alias("pid", "_pid", "o").unwrap();
        let s = b.build().unwrap();
        let copy = SchemaBuilder::from_schema(ctx.clone(), &s);
        assert!(copy.is_canonical_container());
        assert_eq!(copy.get_element_schemas(), s.get_element_schemas());
        // The resolved alias entry became a plain attribute.
        assert_eq!(copy.get_attribute_schemas().len(), 1);
        assert_eq!(copy.build().unwrap().get_attribute_aliases().len(), 0);
    }
}
