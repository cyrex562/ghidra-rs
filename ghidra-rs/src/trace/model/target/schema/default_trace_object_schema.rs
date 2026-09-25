//! Port of `ghidra.trace.model.target.schema.DefaultTraceObjectSchema` (with its nested
//! `AliasResolver`; the nested `DefaultAttributeSchema` is
//! [`AttributeSchema`](crate::trace::model::target::schema::trace_object_schema::AttributeSchema)).
use std::cmp::Ordering;
use std::fmt;
use std::sync::Arc;

use crate::debug::api::tracermi::SchemaName;
use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
use crate::trace::model::target::schema::default_schema_context::DefaultSchemaContext;
use crate::trace::model::target::schema::trace_object_schema::{
    AttributeSchema, SchemaArgumentError, TraceObjectSchema,
};

const INDENT: &str = "  ";

/// Looks up `key` in an insertion-ordered association list.
fn lookup<'a, V>(entries: &'a [(String, V)], key: &str) -> Option<&'a V> {
    entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// Java `LinkedHashMap.put`: replace in place, or append.
fn put<V>(entries: &mut Vec<(String, V)>, key: String, value: V) {
    match entries.iter_mut().find(|(k, _)| *k == key) {
        Some(entry) => entry.1 = value,
        None => entries.push((key, value)),
    }
}

/// Resolves attribute alias chains. Mirrors `DefaultTraceObjectSchema.AliasResolver`.
struct AliasResolver<'a> {
    schemas: &'a [(String, AttributeSchema)],
    aliases: &'a [(String, String)],
    default_schema: &'a AttributeSchema,
    resolved_aliases: Vec<(String, String)>,
}

impl<'a> AliasResolver<'a> {
    fn resolve_aliases(&mut self) -> Result<Vec<(String, String)>, SchemaArgumentError> {
        self.resolved_aliases = Vec::new();
        for (alias, _) in self.aliases {
            if alias.is_empty() {
                return Err(SchemaArgumentError("Key '' cannot be an alias".into()));
            }
            if lookup(self.schemas, alias).is_some() {
                return Err(SchemaArgumentError(format!(
                    "Key '{alias}' cannot be both an attribute and an alias"
                )));
            }
            self.resolve_alias(alias, &mut Vec::new())?;
        }
        Ok(self.resolved_aliases.clone())
    }

    fn resolve_alias(
        &mut self,
        alias: &str,
        visited: &mut Vec<String>,
    ) -> Result<String, SchemaArgumentError> {
        if let Some(already) = lookup(&self.resolved_aliases, alias) {
            return Ok(already.clone());
        }
        if visited.iter().any(|v| v == alias) {
            return Err(SchemaArgumentError(format!(
                "Cycle of aliases: [{}]",
                visited.join(", ")
            )));
        }
        visited.push(alias.to_string());
        let Some(to) = lookup(self.aliases, alias) else {
            return Ok(alias.to_string());
        };
        if to.is_empty() {
            return Err(SchemaArgumentError(format!(
                "Cannot alias to key '' (from {alias})"
            )));
        }
        let result = self.resolve_alias(&to.clone(), visited)?;
        put(&mut self.resolved_aliases, alias.to_string(), result.clone());
        Ok(result)
    }

    fn resolve_schemas(&self) -> Vec<(String, AttributeSchema)> {
        let mut resolved = self.schemas.to_vec();
        for (alias, target) in &self.resolved_aliases {
            let schema = lookup(self.schemas, target).unwrap_or(self.default_schema).clone();
            put(&mut resolved, alias.clone(), schema);
        }
        resolved
    }
}

/// The context-free content of a [`DefaultTraceObjectSchema`], as stored in its context.
#[derive(Debug, PartialEq, Eq)]
pub struct DefaultSchemaData {
    name: SchemaName,
    type_name: &'static str,
    interfaces: Vec<TraceObjectInfo>,
    is_canonical_container: bool,
    element_schemas: Vec<(String, SchemaName)>,
    default_element_schema: SchemaName,
    attribute_schemas: Vec<(String, AttributeSchema)>,
    attribute_aliases: Vec<(String, String)>,
    default_attribute_schema: AttributeSchema,
}

/// A schema for trace objects, built by a
/// [`SchemaBuilder`](crate::trace::model::target::schema::schema_builder::SchemaBuilder).
///
/// Mirrors `ghidra.trace.model.target.schema.DefaultTraceObjectSchema`. Cloning is cheap: the
/// content is shared.
#[derive(Clone)]
pub struct DefaultTraceObjectSchema {
    data: Arc<DefaultSchemaData>,
    context: DefaultSchemaContext,
}

impl DefaultTraceObjectSchema {
    /// Mirrors the package-private constructor: interfaces are de-duplicated (by schema name,
    /// first occurrence wins) and aliases are resolved, which fails for an empty-named alias, an
    /// alias that is also an attribute, an alias to `''`, or a cycle of aliases.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        context: DefaultSchemaContext,
        name: SchemaName,
        type_name: &'static str,
        interfaces: &[TraceObjectInfo],
        is_canonical_container: bool,
        element_schemas: &[(String, SchemaName)],
        default_element_schema: SchemaName,
        attribute_schemas: &[(String, AttributeSchema)],
        attribute_aliases: &[(String, String)],
        default_attribute_schema: AttributeSchema,
    ) -> Result<Self, SchemaArgumentError> {
        let mut unique: Vec<TraceObjectInfo> = Vec::new();
        for iface in interfaces {
            if !unique.iter().any(|i| i.schema_name == iface.schema_name) {
                unique.push(iface.clone());
            }
        }
        let mut resolver = AliasResolver {
            schemas: attribute_schemas,
            aliases: attribute_aliases,
            default_schema: &default_attribute_schema,
            resolved_aliases: Vec::new(),
        };
        let resolved_aliases = resolver.resolve_aliases()?;
        let resolved_schemas = resolver.resolve_schemas();
        let data = DefaultSchemaData {
            name,
            type_name,
            interfaces: unique,
            is_canonical_container,
            element_schemas: element_schemas.to_vec(),
            default_element_schema,
            attribute_schemas: resolved_schemas,
            attribute_aliases: resolved_aliases,
            default_attribute_schema,
        };
        Ok(DefaultTraceObjectSchema { data: Arc::new(data), context })
    }

    pub(super) fn from_parts(data: Arc<DefaultSchemaData>, context: DefaultSchemaContext) -> Self {
        DefaultTraceObjectSchema { data, context }
    }

    pub(super) fn data(&self) -> &Arc<DefaultSchemaData> {
        &self.data
    }
}

fn map_to_string<V: fmt::Display>(entries: &[(String, V)]) -> String {
    let inner: Vec<String> = entries.iter().map(|(k, v)| format!("{k}={v}")).collect();
    format!("{{{}}}", inner.join(", "))
}

impl TraceObjectSchema for DefaultTraceObjectSchema {
    fn get_context(&self) -> DefaultSchemaContext {
        self.context.clone()
    }

    fn get_name(&self) -> SchemaName {
        self.data.name.clone()
    }

    fn get_type(&self) -> &'static str {
        self.data.type_name
    }

    fn get_interfaces(&self) -> Vec<TraceObjectInfo> {
        self.data.interfaces.clone()
    }

    fn is_canonical_container(&self) -> bool {
        self.data.is_canonical_container
    }

    fn get_element_schemas(&self) -> &[(String, SchemaName)] {
        &self.data.element_schemas
    }

    fn get_default_element_schema(&self) -> SchemaName {
        self.data.default_element_schema.clone()
    }

    fn get_attribute_schemas(&self) -> &[(String, AttributeSchema)] {
        &self.data.attribute_schemas
    }

    fn get_attribute_aliases(&self) -> &[(String, String)] {
        &self.data.attribute_aliases
    }

    fn get_default_attribute_schema(&self) -> AttributeSchema {
        self.data.default_attribute_schema.clone()
    }

    fn to_string(&self) -> String {
        let d = &self.data;
        let mut sb = String::new();
        sb.push_str("schema ");
        sb.push_str(d.name.as_str());
        if d.is_canonical_container {
            sb.push('*');
        }
        sb.push_str(" {\n");
        sb.push_str(INDENT);
        sb.push_str("ifaces = [");
        for iface in &d.interfaces {
            sb.push_str(&iface.schema_name);
            sb.push(' ');
        }
        sb.push_str("]\n");
        sb.push_str(INDENT);
        sb.push_str("elements = ");
        sb.push_str(&map_to_string(&d.element_schemas));
        sb.push_str(&format!(" default {}", d.default_element_schema));
        sb.push('\n');
        sb.push_str(INDENT);
        sb.push_str("attributes = ");
        sb.push_str(&map_to_string(&d.attribute_schemas));
        sb.push_str(&format!(" default {}", d.default_attribute_schema));
        sb.push_str(&format!(" aliases {}", map_to_string(&d.attribute_aliases)));
        sb.push_str("\n}");
        sb
    }
}

impl fmt::Debug for DefaultTraceObjectSchema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&TraceObjectSchema::to_string(self))
    }
}

impl PartialEq for DefaultTraceObjectSchema {
    /// Mirrors `equals`: every field but the context. (Map equality is order-insensitive in
    /// Java; declaration order is part of the data here, as it is for serialization.)
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl Eq for DefaultTraceObjectSchema {}

impl std::hash::Hash for DefaultTraceObjectSchema {
    /// Mirrors `hashCode()`: the name's hash.
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.data.name.hash(state);
    }
}

impl PartialOrd for DefaultTraceObjectSchema {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DefaultTraceObjectSchema {
    /// Mirrors `compareTo`: by name.
    fn cmp(&self, other: &Self) -> Ordering {
        self.data.name.cmp(&other.data.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::model::target::schema::trace_object_schema::{Hidden, TRACE_OBJECT_TYPE};

    fn attr(name: &str, schema: &str) -> AttributeSchema {
        AttributeSchema::new(name, SchemaName::new(schema), false, false, Hidden::Default).unwrap()
    }

    fn build(
        attrs: &[(String, AttributeSchema)],
        aliases: &[(&str, &str)],
    ) -> Result<DefaultTraceObjectSchema, SchemaArgumentError> {
        let aliases: Vec<(String, String)> =
            aliases.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
        DefaultTraceObjectSchema::new(
            DefaultSchemaContext::new(),
            SchemaName::new("Process"),
            TRACE_OBJECT_TYPE,
            &[],
            false,
            &[],
            SchemaName::new("OBJECT"),
            attrs,
            &aliases,
            AttributeSchema::default_any(),
        )
    }

    #[test]
    fn alias_chains_resolve_to_their_final_target() {
        let attrs = vec![("Exit Code".to_string(), attr("Exit Code", "LONG"))];
        let s = build(&attrs, &[("_exit_code", "code"), ("code", "Exit Code")]).unwrap();
        // Inner aliases complete first, as in Java's LinkedHashMap.
        assert_eq!(
            s.get_attribute_aliases(),
            &[
                ("code".to_string(), "Exit Code".to_string()),
                ("_exit_code".to_string(), "Exit Code".to_string())
            ]
        );
        assert_eq!(s.check_aliased_attribute("_exit_code"), "Exit Code");
        assert_eq!(s.get_attribute_schema("_exit_code").get_schema(), &SchemaName::new("LONG"));
        assert_eq!(s.get_attribute_schema("_exit_code").get_name(), "Exit Code");
    }

    #[test]
    fn alias_to_undeclared_attribute_gets_default_schema() {
        let s = build(&[], &[("a", "b")]).unwrap();
        assert_eq!(s.get_attribute_schemas()[0].1, AttributeSchema::default_any());
    }

    #[test]
    fn alias_errors_match_java_messages() {
        let attrs = vec![("x".to_string(), attr("x", "INT"))];
        assert_eq!(build(&attrs, &[("x", "y")]).unwrap_err().0,
            "Key 'x' cannot be both an attribute and an alias");
        assert_eq!(build(&[], &[("", "y")]).unwrap_err().0, "Key '' cannot be an alias");
        assert_eq!(build(&[], &[("a", "")]).unwrap_err().0, "Cannot alias to key '' (from a)");
        assert_eq!(build(&[], &[("a", "b"), ("b", "a")]).unwrap_err().0,
            "Cycle of aliases: [a, b]");
    }

    #[test]
    fn to_string_matches_java_format() {
        let attrs = vec![("_pid".to_string(), attr("_pid", "LONG"))];
        let s = build(&attrs, &[("pid", "_pid")]).unwrap();
        assert_eq!(
            TraceObjectSchema::to_string(&s),
            "schema Process {\n  ifaces = []\n  elements = {} default OBJECT\n  \
             attributes = {_pid=<attr name=_pid schema=LONG required=false fixed=false \
             hidden=false>, pid=<attr name=_pid schema=LONG required=false fixed=false \
             hidden=false>} default <attr name= schema=ANY required=false fixed=false \
             hidden=default> aliases {pid=_pid}\n}"
        );
    }

    #[test]
    fn equality_ignores_context_and_ordering_is_by_name() {
        let a = build(&[], &[]).unwrap();
        let b = build(&[], &[]).unwrap();
        assert!(!a.get_context().same_context(&b.get_context()));
        assert_eq!(a, b);
        assert_eq!(a.cmp(&b), Ordering::Equal);
    }
}
