//! Port of `ghidra.trace.model.target.schema.TraceObjectSchema` and its nested types
//! (`SchemaName` lives in [`crate::debug::api::tracermi::SchemaName`], `Hidden`,
//! `AttributeSchema`, and the search helpers of the nested `Private` class).
//!
//! # Representation decisions
//!
//! - **`Class<?>` tokens.** `getType()` names a Java class. Rust has no reflection, so a type is
//!   its fully-qualified Java class name (a `&'static str`); the only assignability question the
//!   schema machinery ever asks is "is this a `TraceObject` (or `TraceObjectInterface`) type?",
//!   answered by [`is_trace_object_type`].
//! - **Interface class tokens.** `getInterfaces()` returns `Set<Class<? extends
//!   TraceObjectInterface>>`. Every such class carries exactly one `@TraceObjectInfo` annotation
//!   whose `schemaName` is unique among registered interfaces (Java builds its by-name registry on
//!   that bijection), so an interface is represented by its reified annotation,
//!   [`TraceObjectInfo`], and "contains the class" is "contains the schema name". The search
//!   methods therefore take the interface's schema name.
//! - **Context back-reference.** Java schemas hold their `SchemaContext`. Here a context is a
//!   shared handle ([`DefaultSchemaContext`]); schemas handed out by a context carry a clone of
//!   that handle, while the context stores only the schemas' data -- so there is no reference
//!   cycle.
//! - **Schema identity.** Java's search sets (`Set<TraceObjectSchema>`) compare schemas with
//!   `equals`, which for a well-formed context is the same as comparing names. They are keyed by
//!   [`SchemaName`] here.
use std::collections::HashSet;
use std::fmt;
use std::ops::Deref;

use crate::debug::api::tracermi::SchemaName;
use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
use crate::trace::model::target::path::{KeyPath, PathMatcher, PathPattern};
use crate::trace::model::target::path::path_pattern::Align;
use crate::trace::model::target::schema::default_schema_context::DefaultSchemaContext;
use crate::trace::model::target::schema::schema_context::SchemaContext;
use crate::trace::model::target::schema::primitive_trace_object_schema::PrimitiveTraceObjectSchema;

/// Java class name of `ghidra.trace.model.target.TraceObject`, the type of every object schema.
pub const TRACE_OBJECT_TYPE: &str = "ghidra.trace.model.target.TraceObject";

/// Java class name of `ghidra.trace.model.target.iface.TraceObjectInterface`.
pub const TRACE_OBJECT_INTERFACE_TYPE: &str =
    "ghidra.trace.model.target.iface.TraceObjectInterface";

/// Schema name of `TraceAggregate` (from its `@TraceObjectInfo`).
pub const AGGREGATE_SCHEMA_NAME: &str = "Aggregate";
/// Schema name of `TraceObjectInterface` itself (from its `@TraceObjectInfo`).
pub const OBJECT_INTERFACE_SCHEMA_NAME: &str = "OBJECT";
/// Schema name of `TraceRegisterContainer`.
pub const REGISTER_CONTAINER_SCHEMA_NAME: &str = "RegisterContainer";
/// Schema name of `TraceStack`.
pub const STACK_SCHEMA_NAME: &str = "Stack";
/// Schema name of `TraceStackFrame`.
pub const STACK_FRAME_SCHEMA_NAME: &str = "StackFrame";

/// Whether a value of Java type `ty` is a trace object, i.e. whether
/// `TraceObjectInterface.class.isAssignableFrom(ty) || TraceObject.class.isAssignableFrom(ty)`
/// for the types schemas are declared with.
pub fn is_trace_object_type(ty: &str) -> bool {
    ty == TRACE_OBJECT_TYPE || ty == TRACE_OBJECT_INTERFACE_TYPE
}

/// An illegal argument while building or resolving a schema. Mirrors the
/// `IllegalArgumentException`s thrown by the schema classes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaArgumentError(pub String);

impl fmt::Display for SchemaArgumentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SchemaArgumentError {}

/// A mode describing what "promotes" an object to the top level, i.e., whether an attribute is
/// hidden. Mirrors `TraceObjectSchema.Hidden`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Hidden {
    /// Hidden if the key starts with `_`.
    Default,
    /// Always hidden.
    True,
    /// Never hidden.
    False,
}

impl Hidden {
    /// Check if the given key is hidden. Mirrors `isHidden(String)`.
    pub fn is_hidden(self, name: &str) -> bool {
        match self {
            Hidden::Default => name.starts_with('_'),
            Hidden::True => true,
            Hidden::False => false,
        }
    }

    /// Adjust this mode for an attribute of the given name. Mirrors `adjust(String)`: `DEFAULT`
    /// stays `DEFAULT` only for the default attribute schema (empty name); a named attribute is
    /// never hidden by default.
    pub fn adjust(self, name: &str) -> Hidden {
        match self {
            Hidden::Default if !name.is_empty() => Hidden::False,
            other => other,
        }
    }
}

impl fmt::Display for Hidden {
    /// Java's `name()`, which is what `toString()` returns for an enum.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Hidden::Default => "DEFAULT",
            Hidden::True => "TRUE",
            Hidden::False => "FALSE",
        })
    }
}

/// Schema descriptor for a child attribute.
///
/// Port of the interface `TraceObjectSchema.AttributeSchema` together with its only
/// implementation, `DefaultTraceObjectSchema.DefaultAttributeSchema` (an interface with one
/// implementer is a concrete type in Rust).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeSchema {
    name: String,
    schema: SchemaName,
    is_required: bool,
    is_fixed: bool,
    hidden: Hidden,
}

impl AttributeSchema {
    /// Mirrors the `DefaultAttributeSchema` constructor. The given `hidden` mode is
    /// [adjusted](Hidden::adjust) for `name`.
    ///
    /// Fails, as Java throws `IllegalArgumentException`, if the default attribute schema (empty
    /// name) is marked required.
    pub fn new(
        name: impl Into<String>,
        schema: SchemaName,
        is_required: bool,
        is_fixed: bool,
        hidden: Hidden,
    ) -> Result<Self, SchemaArgumentError> {
        let name = name.into();
        if name.is_empty() && is_required {
            return Err(SchemaArgumentError(
                "The default attribute schema cannot be required".into(),
            ));
        }
        let hidden = hidden.adjust(&name);
        Ok(AttributeSchema { name, schema, is_required, is_fixed, hidden })
    }

    /// `AttributeSchema.DEFAULT_ANY`: allow any attribute of any schema, hidden by default.
    pub fn default_any() -> Self {
        AttributeSchema {
            name: String::new(),
            schema: PrimitiveTraceObjectSchema::Any.get_name(),
            is_required: false,
            is_fixed: false,
            hidden: Hidden::Default,
        }
    }

    /// `AttributeSchema.DEFAULT_OBJECT`: allow any object attribute, hidden by default.
    pub fn default_object() -> Self {
        AttributeSchema {
            name: String::new(),
            schema: PrimitiveTraceObjectSchema::Object.get_name(),
            is_required: false,
            is_fixed: false,
            hidden: Hidden::Default,
        }
    }

    /// `AttributeSchema.DEFAULT_VOID`: forbid any additional attributes.
    pub fn default_void() -> Self {
        AttributeSchema {
            name: String::new(),
            schema: PrimitiveTraceObjectSchema::Void.get_name(),
            is_required: false,
            is_fixed: true,
            hidden: Hidden::True,
        }
    }

    /// The name of the attribute, or empty for the default attribute schema.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// The name of the schema for the attribute's value.
    pub fn get_schema(&self) -> &SchemaName {
        &self.schema
    }

    /// Whether the attribute must be present.
    pub fn is_required(&self) -> bool {
        self.is_required
    }

    /// Whether the attribute's value may never change once set.
    pub fn is_fixed(&self) -> bool {
        self.is_fixed
    }

    /// Whether the given key (named by this schema) is hidden. Mirrors `isHidden(String)`.
    pub fn is_hidden(&self, name: &str) -> bool {
        self.hidden.is_hidden(name)
    }

    /// The (adjusted) hidden mode.
    pub fn get_hidden(&self) -> Hidden {
        self.hidden
    }
}

impl fmt::Display for AttributeSchema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<attr name={} schema={} required={} fixed={} hidden={}>",
            self.name,
            self.schema,
            self.is_required,
            self.is_fixed,
            self.hidden.to_string().to_lowercase()
        )
    }
}

/// A schema either borrowed from the caller or resolved (owned) from a context.
///
/// Java passes `TraceObjectSchema` references around freely; `this` among them. Schemas resolved
/// through a context come back boxed, but `this` can only be borrowed, so sequences that start at
/// `this` (e.g. [`TraceObjectSchema::get_successor_schemas`]) hold this instead.
pub enum SchemaRef<'a> {
    /// The schema the operation was invoked on.
    Borrowed(&'a dyn TraceObjectSchema),
    /// A schema resolved from a context.
    Owned(Box<dyn TraceObjectSchema>),
}

impl<'a> Deref for SchemaRef<'a> {
    type Target = dyn TraceObjectSchema + 'a;

    fn deref(&self) -> &Self::Target {
        match self {
            SchemaRef::Borrowed(s) => *s,
            SchemaRef::Owned(s) => s.as_ref(),
        }
    }
}

fn has_interface(schema: &dyn TraceObjectSchema, iface: &str) -> bool {
    schema.get_interfaces().iter().any(|i| i.schema_name == iface)
}

fn require_specific_interface(iface: &str) {
    assert!(
        iface != OBJECT_INTERFACE_SCHEMA_NAME,
        "Must provide a specific interface"
    );
}

/// Parses a Java integer literal the way `Integer.decode` does: optional sign, then `0x`/`0X`/`#`
/// for hex, a leading `0` for octal, else decimal.
fn java_integer_decode(s: &str) -> Result<i32, String> {
    let (neg, rest) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let (radix, digits) = if let Some(d) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
        (16, d)
    } else if let Some(d) = rest.strip_prefix('#') {
        (16, d)
    } else if rest.len() > 1 && rest.starts_with('0') {
        (8, &rest[1..])
    } else {
        (10, rest)
    };
    if digits.is_empty() || digits.starts_with('-') || digits.starts_with('+') {
        return Err(format!("For input string: \"{s}\""));
    }
    let magnitude =
        i64::from_str_radix(digits, radix).map_err(|_| format!("For input string: \"{s}\""))?;
    let value = if neg { -magnitude } else { magnitude };
    i32::try_from(value).map_err(|_| format!("For input string: \"{s}\""))
}

/// Type information for a particular value or trace object.
///
/// Mirrors `ghidra.trace.model.target.schema.TraceObjectSchema`. Its two implementations are
/// [`PrimitiveTraceObjectSchema`] and
/// [`DefaultTraceObjectSchema`](crate::trace::model::target::schema::default_trace_object_schema::DefaultTraceObjectSchema).
///
/// The Java default methods that need `this` as a schema value (the successor walks and the
/// `searchFor*` family) are on [`TraceObjectSchemaExt`], implemented for every schema and for
/// `dyn TraceObjectSchema`. `PrimitiveTraceObjectSchema`'s Java overrides of `searchFor`,
/// `searchForCanonicalContainer` and `searchForSuitable` return exactly what those defaults
/// compute for a primitive (nothing), so they need no override here.
pub trait TraceObjectSchema: Send + Sync {
    /// The context of which this schema is a member. Mirrors `getContext()`.
    fn get_context(&self) -> DefaultSchemaContext;

    /// The name of this schema. Mirrors `getName()`.
    fn get_name(&self) -> SchemaName;

    /// The Java type (fully-qualified class name) describing the value. Mirrors `getType()`.
    fn get_type(&self) -> &'static str;

    /// The minimum interfaces supported by a conforming object, in declaration order.
    /// Mirrors `getInterfaces()`.
    fn get_interfaces(&self) -> Vec<TraceObjectInfo>;

    /// Whether this is the canonical container for its elements. Mirrors
    /// `isCanonicalContainer()`.
    fn is_canonical_container(&self) -> bool;

    /// The declared element schemas, by index, in declaration order. Mirrors
    /// `getElementSchemas()`.
    fn get_element_schemas(&self) -> &[(String, SchemaName)];

    /// The schema for elements not declared in [`Self::get_element_schemas`]. Mirrors
    /// `getDefaultElementSchema()`.
    fn get_default_element_schema(&self) -> SchemaName {
        PrimitiveTraceObjectSchema::Object.get_name()
    }

    /// The schema for the element at `index`. Mirrors `getElementSchema(String)`.
    fn get_element_schema(&self, index: &str) -> SchemaName {
        self.get_element_schemas()
            .iter()
            .find(|(k, _)| k == index)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| self.get_default_element_schema())
    }

    /// The declared attribute schemas, by name (aliases included, mapped to their targets'
    /// schemas), in declaration order. Mirrors `getAttributeSchemas()`.
    fn get_attribute_schemas(&self) -> &[(String, AttributeSchema)];

    /// The (resolved) attribute aliases. Mirrors `getAttributeAliases()`.
    fn get_attribute_aliases(&self) -> &[(String, String)];

    /// Resolve `name` through the aliases, if it is one. Mirrors
    /// `checkAliasedAttribute(String)`.
    fn check_aliased_attribute(&self, name: &str) -> String {
        self.get_attribute_aliases()
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| name.to_string())
    }

    /// The schema for attributes not declared in [`Self::get_attribute_schemas`]. Mirrors
    /// `getDefaultAttributeSchema()`.
    fn get_default_attribute_schema(&self) -> AttributeSchema {
        AttributeSchema::default_any()
    }

    /// The schema for the attribute `name`. Mirrors `getAttributeSchema(String)`.
    fn get_attribute_schema(&self, name: &str) -> AttributeSchema {
        self.get_attribute_schemas()
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| self.get_default_attribute_schema())
    }

    /// The name of the schema for the child `key` (element key or attribute name). Mirrors
    /// `getChildSchemaName(String)`.
    fn get_child_schema_name(&self, key: &str) -> SchemaName {
        if KeyPath::is_index(key) {
            // An index key always parses.
            let index = KeyPath::parse_index(key).unwrap_or(key);
            return self.get_element_schema(index);
        }
        self.get_attribute_schema(key).get_schema().clone()
    }

    /// The schema for the child `key`. Mirrors `getChildSchema(String)`.
    fn get_child_schema(&self, key: &str) -> Box<dyn TraceObjectSchema> {
        let name = self.get_child_schema_name(key);
        self.get_context().get_schema(&name)
    }

    /// Whether this is a [`PrimitiveTraceObjectSchema`] (Java's `instanceof` checks).
    fn is_primitive(&self) -> bool {
        false
    }

    /// Mirrors `toString()`.
    fn to_string(&self) -> String;

    /// Whether a value conforming to `that` conforms to this schema. Mirrors
    /// `isAssignableFrom(TraceObjectSchema)`, which defaults to equality.
    fn is_assignable_from(&self, that: &dyn TraceObjectSchema) -> bool {
        same_schema(self.get_name(), self.is_primitive(), that)
    }

    /// Whether the given child key is hidden. Mirrors `isHidden(String)`: elements never are.
    fn is_hidden(&self, key: &str) -> bool {
        if KeyPath::is_index(key) {
            return false;
        }
        self.get_attribute_schema(key).is_hidden(key)
    }
}

fn same_schema(name: SchemaName, primitive: bool, that: &dyn TraceObjectSchema) -> bool {
    name == that.get_name() && primitive == that.is_primitive()
}

/// Upcast of any schema -- a sized implementor or `dyn TraceObjectSchema` itself -- to a trait
/// object, so the shared default algorithms can be written once.
pub trait AsTraceObjectSchema {
    /// This schema as a trait object.
    fn as_schema(&self) -> &dyn TraceObjectSchema;
}

impl<T: TraceObjectSchema> AsTraceObjectSchema for T {
    fn as_schema(&self) -> &dyn TraceObjectSchema {
        self
    }
}

impl<'a> AsTraceObjectSchema for dyn TraceObjectSchema + 'a {
    fn as_schema(&self) -> &dyn TraceObjectSchema {
        self
    }
}

/// The default methods of `TraceObjectSchema` that need `this` as a schema value: the successor
/// walks and the `searchFor*` family. Implemented for every schema, sized or not.
pub trait TraceObjectSchemaExt: AsTraceObjectSchema {
    /// The schemas of each successor along `path`, starting with this one. Mirrors
    /// `getSuccessorSchemas(KeyPath)`.
    fn get_successor_schemas(&self, path: &KeyPath) -> Vec<SchemaRef<'_>> {
        let mut result = vec![SchemaRef::Borrowed(self.as_schema())];
        for key in path {
            let next = result.last().expect("non-empty").get_child_schema(key);
            result.push(SchemaRef::Owned(next));
        }
        result
    }

    /// The schema of the successor at `path`. Mirrors `getSuccessorSchema(KeyPath)`.
    fn get_successor_schema(&self, path: &KeyPath) -> SchemaRef<'_> {
        self.get_successor_schemas(path).pop().expect("successor schemas include the start")
    }

    /// Search for all schemas providing `iface` among successors. Mirrors
    /// `searchFor(Class, boolean)`.
    ///
    /// # Panics
    ///
    /// If `iface` names `TraceObjectInterface` itself, as Java throws.
    fn search_for(&self, iface: &str, require_canonical: bool) -> PathMatcher {
        self.search_for_from(iface, &KeyPath::root(), require_canonical)
    }

    /// As [`Self::search_for`], relative to `prefix`. Mirrors
    /// `searchFor(Class, KeyPath, boolean)`.
    fn search_for_from(
        &self,
        iface: &str,
        prefix: &KeyPath,
        require_canonical: bool,
    ) -> PathMatcher {
        require_specific_interface(iface);
        let mut patterns = HashSet::new();
        private_search_for(
            self.as_schema(),
            &mut patterns,
            prefix,
            true,
            iface,
            false,
            require_canonical,
            &mut HashSet::new(),
        );
        PathMatcher::any_of_patterns(patterns.into_iter())
    }

    /// Find the (unique, shortest) canonical container of objects providing `iface`. Mirrors
    /// `searchForCanonicalContainer(Class)`.
    ///
    /// # Panics
    ///
    /// If `iface` names `TraceObjectInterface` itself, as Java throws.
    fn search_for_canonical_container(&self, iface: &str) -> Option<KeyPath> {
        require_specific_interface(iface);
        let this = self.as_schema();
        let ctx = this.get_context();
        let mut visited: HashSet<SchemaName> = HashSet::new();
        let mut visited_as_element: HashSet<SchemaName> = HashSet::new();
        let mut all_on_level: Vec<(KeyPath, bool, SchemaRef<'_>)> =
            vec![(KeyPath::root(), false, SchemaRef::Borrowed(this))];
        while !all_on_level.is_empty() {
            let mut found: Option<Option<KeyPath>> = None;
            for (path, parent_is_canonical, schema) in &all_on_level {
                if has_interface(&**schema, iface) && *parent_is_canonical {
                    if found.is_some() {
                        return None; // Non-unique answer
                    }
                    found = Some(path.parent());
                }
            }
            if let Some(found) = found {
                return found; // Unique shortest answer
            }
            let mut next_level = Vec::new();
            for (path, _, schema) in &all_on_level {
                if path.last_key().is_some_and(PathPattern::is_wildcard) {
                    continue;
                }
                for (key, attr) in schema.get_attribute_schemas() {
                    let attr_schema = ctx.get_schema(attr.get_schema());
                    if is_trace_object_type(attr_schema.get_type())
                        && visited.insert(attr_schema.get_name())
                    {
                        // If child is not element, this is not its canonical container
                        next_level.push((path.with_key(key), false, SchemaRef::Owned(attr_schema)));
                    }
                }
                for (index, name) in schema.get_element_schemas() {
                    let elem_schema = ctx.get_schema(name);
                    visited.insert(elem_schema.get_name()); // Add but do not condition
                    if visited_as_element.insert(elem_schema.get_name()) {
                        next_level.push((
                            path.with_index(index),
                            schema.is_canonical_container(),
                            SchemaRef::Owned(elem_schema),
                        ));
                    }
                }
                let de_schema = ctx.get_schema(&schema.get_default_element_schema());
                visited.insert(de_schema.get_name());
                if visited_as_element.insert(de_schema.get_name()) {
                    next_level.push((
                        path.with_index(""),
                        schema.is_canonical_container(),
                        SchemaRef::Owned(de_schema),
                    ));
                }
            }
            all_on_level = next_level;
        }
        // We exhausted the reachable schemas
        None
    }

    /// Search this (root) schema for the unique path of an object suitable to provide `iface`
    /// in the context of the object at `path`. Mirrors `searchForSuitable(Class, KeyPath)`.
    fn search_for_suitable(&self, iface: &str, path: &KeyPath) -> Option<KeyPath> {
        let schemas = self.get_successor_schemas(path);
        let mut cur = Some(path.clone());
        while let Some(p) = cur {
            let schema = &*schemas[p.size()];
            if has_interface(schema, iface) {
                return Some(p);
            }
            if let Some(in_agg) =
                search_for_in_aggregate(schema, |s| has_interface(s, iface))
            {
                return Some(p.extend(&in_agg));
            }
            cur = p.parent();
        }
        None
    }

    /// As [`Self::search_for_suitable`], but for an object whose schema `schema` is assignable
    /// from. Mirrors `searchForSuitable(TraceObjectSchema, KeyPath)`.
    fn search_for_suitable_schema(
        &self,
        schema: &dyn TraceObjectSchema,
        path: &KeyPath,
    ) -> Option<KeyPath> {
        let schemas = self.get_successor_schemas(path);
        let mut cur = Some(path.clone());
        while let Some(p) = cur {
            let check = &*schemas[p.size()];
            if schema.is_assignable_from(check) {
                return Some(p);
            }
            let name = schema.get_name();
            let primitive = schema.is_primitive();
            if let Some(in_agg) =
                search_for_in_aggregate(check, |s| same_schema(name.clone(), primitive, s))
            {
                return Some(p.extend(&in_agg));
            }
            cur = p.parent();
        }
        None
    }

    /// Like [`Self::search_for`], but only among the aggregates of the ancestry of `path`.
    /// Mirrors `filterForSuitable(Class, KeyPath)`.
    fn filter_for_suitable(&self, iface: &str, path: &KeyPath) -> PathMatcher {
        let mut patterns = HashSet::new();
        let mut visited = HashSet::new();
        let schemas = self.get_successor_schemas(path);
        let mut cur = Some(path.clone());
        while let Some(p) = cur {
            private_search_for(
                &*schemas[p.size()],
                &mut patterns,
                &p,
                false,
                iface,
                true,
                false,
                &mut visited,
            );
            cur = p.parent();
        }
        PathMatcher::any_of_patterns(patterns.into_iter())
    }

    /// As [`Self::search_for_suitable`], but for the canonical container of `iface`. Mirrors
    /// `searchForSuitableContainer(Class, KeyPath)`.
    fn search_for_suitable_container(&self, iface: &str, path: &KeyPath) -> Option<KeyPath> {
        let schemas = self.get_successor_schemas(path);
        let mut cur = Some(path.clone());
        while let Some(p) = cur {
            let schema = &*schemas[p.size()];
            let de_schema = schema.get_context().get_schema(&schema.get_default_element_schema());
            if has_interface(de_schema.as_ref(), iface) && schema.is_canonical_container() {
                return Some(p);
            }
            if let Some(in_agg) = search_for_in_aggregate(schema, |s| {
                if !s.is_canonical_container() {
                    return false;
                }
                let de = s.get_context().get_schema(&s.get_default_element_schema());
                has_interface(de.as_ref(), iface)
            }) {
                return Some(p.extend(&in_agg));
            }
            cur = p.parent();
        }
        None
    }

    /// Search the ancestry of `path` for an object providing `iface`. Mirrors
    /// `searchForAncestor(Class, KeyPath)`.
    fn search_for_ancestor(&self, iface: &str, path: &KeyPath) -> Option<KeyPath> {
        let mut cur = Some(path.clone());
        while let Some(p) = cur {
            if has_interface(&*self.get_successor_schema(&p), iface) {
                return Some(p);
            }
            cur = p.parent();
        }
        None
    }

    /// Search the ancestry of `path` for a canonical container of `iface`. Mirrors
    /// `searchForAncestorContainer(Class, KeyPath)`.
    fn search_for_ancestor_container(&self, iface: &str, path: &KeyPath) -> Option<KeyPath> {
        let mut cur = Some(path.clone());
        while let Some(p) = cur {
            let schema = self.get_successor_schema(&p);
            if schema.is_canonical_container() {
                let de_schema =
                    schema.get_context().get_schema(&schema.get_default_element_schema());
                if has_interface(de_schema.as_ref(), iface) {
                    return Some(p);
                }
            }
            cur = p.parent();
        }
        None
    }

    /// Search this (root) schema for the register container(s) applicable to the object at
    /// `path` at the given frame level. Mirrors `searchForRegisterContainer(int, KeyPath)`.
    ///
    /// Java returns a `PathFilter` whose patterns are the answer (its only caller enumerates
    /// them), so the patterns are returned directly. Java's `null` (a frame pattern with other
    /// than one wildcard) is returned as no patterns.
    fn search_for_register_container(&self, frame_level: i32, path: &KeyPath) -> Vec<PathPattern> {
        let simple = self.search_for_suitable(REGISTER_CONTAINER_SCHEMA_NAME, path);
        // NB: This is technically not correct. It's possible, although unlikely, that the target
        // has an accessible stack but no stack in its schema. If so, this method should be
        // called with 0 instead of the actual stack level.
        if let Some(simple) = simple {
            if frame_level == 0 {
                return vec![PathPattern::new(simple)];
            }
        }
        let Some(stack_path) = self.search_for_suitable(STACK_SCHEMA_NAME, path) else {
            return Vec::new();
        };
        let frame_matcher =
            self.get_successor_schema(&stack_path).search_for(STACK_FRAME_SCHEMA_NAME, false);
        let Some(frame_pattern_rel_stack) = frame_matcher.get_singleton_pattern() else {
            return Vec::new();
        };
        if frame_pattern_rel_stack.count_wildcards() != 1 {
            return Vec::new();
        }
        let mut patterns = HashSet::new();
        for index in [frame_level.to_string(), format!("0x{:x}", frame_level)] {
            let Some(frame_path_rel_stack) =
                frame_pattern_rel_stack.apply_keys(Align::Left, &[index]).get_singleton_path()
            else {
                continue;
            };
            let frame_path = stack_path.extend(&frame_path_rel_stack);
            if let Some(regs_path) =
                self.search_for_suitable(REGISTER_CONTAINER_SCHEMA_NAME, &frame_path)
            {
                if stack_path.is_ancestor(&regs_path) {
                    patterns.insert(PathPattern::new(regs_path));
                }
            }
        }
        patterns.into_iter().collect()
    }

    /// The frame level of the object at `path`: the first index between the stack and the
    /// frame. Mirrors `computeFrameLevel(KeyPath)`; errors where Java throws.
    fn compute_frame_level(&self, path: &KeyPath) -> Result<i32, String> {
        let Some(frame_path) = self.search_for_ancestor(STACK_FRAME_SCHEMA_NAME, path) else {
            return Ok(0);
        };
        let stack_path = self.search_for_ancestor(STACK_SCHEMA_NAME, &frame_path);
        let start = stack_path.map_or(0, |p| p.size());
        for i in start..frame_path.size() {
            let key = frame_path.key(i);
            if KeyPath::is_index(key) {
                return java_integer_decode(KeyPath::parse_index(key)?);
            }
        }
        Err("No index between stack and frame".into())
    }
}

impl<T: AsTraceObjectSchema + ?Sized> TraceObjectSchemaExt for T {}

/// Mirrors `Private.searchFor(...)`.
#[allow(clippy::too_many_arguments)]
fn private_search_for(
    sch: &dyn TraceObjectSchema,
    patterns: &mut HashSet<PathPattern>,
    prefix: &KeyPath,
    parent_is_canonical: bool,
    iface: &str,
    require_aggregate: bool,
    require_canonical: bool,
    visited: &mut HashSet<SchemaName>,
) {
    if sch.is_primitive() {
        return;
    }
    if has_interface(sch, iface) && (parent_is_canonical || !require_canonical) {
        patterns.insert(PathPattern::new(prefix.clone()));
        return;
    }
    let name = sch.get_name();
    if !visited.insert(name.clone()) {
        return;
    }
    if require_aggregate && !has_interface(sch, AGGREGATE_SCHEMA_NAME) {
        // As in Java, the schema stays in `visited` here.
        return;
    }
    let ctx = sch.get_context();
    let is_canonical = sch.is_canonical_container();
    let mut recurse = |child: &SchemaName, extended: KeyPath, visited: &mut HashSet<SchemaName>| {
        let child_schema = ctx.get_schema(child);
        private_search_for(
            child_schema.as_ref(),
            patterns,
            &extended,
            is_canonical,
            iface,
            require_aggregate,
            require_canonical,
            visited,
        );
    };
    for (index, elem) in sch.get_element_schemas() {
        recurse(elem, prefix.with_index(index), visited);
    }
    recurse(&sch.get_default_element_schema(), prefix.with_key("[]"), visited);
    for (key, attr) in sch.get_attribute_schemas() {
        recurse(attr.get_schema(), prefix.with_key(key), visited);
    }
    recurse(sch.get_default_attribute_schema().get_schema(), prefix.with_key(""), visited);
    visited.remove(&name);
}

/// Mirrors `Private.searchForInAggregate(seed, predicate)` with its `InAggregateSearch`
/// breadth-first walk: descend only into attributes of aggregates, return the path of the
/// unique entry on the first level where any entry satisfies `predicate`.
fn search_for_in_aggregate(
    seed: &dyn TraceObjectSchema,
    predicate: impl Fn(&dyn TraceObjectSchema) -> bool,
) -> Option<KeyPath> {
    let mut visited: HashSet<SchemaName> = HashSet::new();
    let mut all_on_level: Vec<(KeyPath, SchemaRef<'_>)> =
        vec![(KeyPath::root(), SchemaRef::Borrowed(seed))];
    while !all_on_level.is_empty() {
        let mut found = all_on_level.iter().filter(|(_, s)| predicate(&**s));
        if let Some((path, _)) = found.next() {
            return if found.next().is_none() { Some(path.clone()) } else { None };
        }
        let mut next_level = Vec::new();
        for (path, schema) in &all_on_level {
            // descendAttributes: only aggregates; the default attribute is not expanded.
            if has_interface(&**schema, AGGREGATE_SCHEMA_NAME) {
                let ctx = schema.get_context();
                for (_, attr) in schema.get_attribute_schemas() {
                    let child = ctx.get_schema(attr.get_schema());
                    if visited.insert(child.get_name()) {
                        next_level.push((path.with_key(attr.get_name()), SchemaRef::Owned(child)));
                    }
                }
            }
            // descendElements (canonical containers) expands nothing in InAggregateSearch.
        }
        all_on_level = next_level;
    }
    None
}
