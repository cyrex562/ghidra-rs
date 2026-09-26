//! Port of `ghidra.trace.model.target.schema.XmlSchemaContext`: a schema context read from, and
//! written to, XML.
//!
//! Java reads the document into a JDOM tree and writes one with `XmlUtilities.toString`
//! (`GenericXMLOutputter`: compact format, four-space indent, JDOM's default `\r\n` line
//! separator, empty elements as `<e />`). Reading goes through this crate's XML pull parser into
//! a minimal element tree; writing reproduces the JDOM output byte-for-byte.
use std::fmt;
use std::ops::Deref;

use crate::debug::api::tracermi::SchemaName;
use crate::trace::model::target::info::trace_object_interface_utils;
use crate::trace::model::target::schema::default_schema_context::DefaultSchemaContext;
use crate::trace::model::target::schema::default_trace_object_schema::DefaultTraceObjectSchema;
use crate::trace::model::target::schema::primitive_trace_object_schema::PrimitiveTraceObjectSchema;
use crate::trace::model::target::schema::schema_builder::SchemaBuilder;
use crate::trace::model::target::schema::schema_context::SchemaContext;
use crate::trace::model::target::schema::trace_object_schema::{
    is_trace_object_type, AttributeSchema, Hidden, SchemaArgumentError, TraceObjectSchema,
};
use crate::util::msg::Msg;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_pull_parser::XmlPullParser;
use crate::util::xml::xml_pull_parser_factory;

const ELEM_CONTEXT: &str = "context";
const ATTR_CANONICAL: &str = "canonical";
const ELEM_SCHEMA: &str = "schema";
const ELEM_INTERFACE: &str = "interface";
const ELEM_ELEMENT: &str = "element";
const ATTR_INDEX: &str = "index";
const ELEM_ATTRIBUTE: &str = "attribute";
const ATTR_NAME: &str = "name";
const ATTR_SCHEMA: &str = "schema";
const ATTR_REQUIRED: &str = "required";
const ATTR_FIXED: &str = "fixed";
const ATTR_HIDDEN: &str = "hidden";
const ELEM_ATTRIBUTE_ALIAS: &str = "attribute-alias";
const ATTR_FROM: &str = "from";
const ATTR_TO: &str = "to";
const YES: &str = "yes";
const NO: &str = "no";
const DEFAULT: &str = "default";
const TRUES: [&str; 4] = ["true", YES, "y", "1"];
const FALSES: [&str; 4] = ["false", NO, "n", "0"];

/// JDOM's default line separator.
const LINE_SEPARATOR: &str = "\r\n";
/// `GenericXMLOutputter.DEFAULT_INDENT`.
const XML_INDENT: &str = "    ";

/// An error reading a schema context. Java surfaces `JDOMException` for malformed XML and
/// `IllegalArgumentException` for malformed schemas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XmlSchemaError {
    /// The document is not well-formed XML.
    Xml(String),
    /// The document describes an invalid schema.
    Schema(SchemaArgumentError),
}

impl fmt::Display for XmlSchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XmlSchemaError::Xml(msg) => write!(f, "{msg}"),
            XmlSchemaError::Schema(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for XmlSchemaError {}

impl From<SchemaArgumentError> for XmlSchemaError {
    fn from(e: SchemaArgumentError) -> Self {
        XmlSchemaError::Schema(e)
    }
}

/// A minimal XML element: name, attributes in document order, child elements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlNode {
    name: String,
    attributes: Vec<(String, String)>,
    children: Vec<XmlNode>,
}

impl XmlNode {
    fn new(name: &str) -> Self {
        XmlNode { name: name.to_string(), attributes: Vec::new(), children: Vec::new() }
    }

    /// Mirrors JDOM `getAttributeValue(name)`.
    fn attr(&self, name: &str) -> Option<&str> {
        self.attributes.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// Mirrors JDOM `getAttributeValue(name, def)`.
    fn attr_or<'a>(&'a self, name: &str, def: &'a str) -> &'a str {
        self.attr(name).unwrap_or(def)
    }

    /// Mirrors `XmlUtilities.setStringAttr` / JDOM `setAttribute`.
    fn set_attr(&mut self, name: &str, value: &str) {
        match self.attributes.iter_mut().find(|(k, _)| k == name) {
            Some(entry) => entry.1 = value.to_string(),
            None => self.attributes.push((name.to_string(), value.to_string())),
        }
    }

    /// Mirrors JDOM `getChildren(name)`.
    fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a XmlNode> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }

    fn write(&self, out: &mut String, depth: usize) {
        for _ in 0..depth {
            out.push_str(XML_INDENT);
        }
        out.push('<');
        out.push_str(&self.name);
        for (k, v) in &self.attributes {
            out.push(' ');
            out.push_str(k);
            out.push_str("=\"");
            escape_attribute(v, out);
            out.push('"');
        }
        if self.children.is_empty() {
            out.push_str(" />");
            return;
        }
        out.push('>');
        for child in &self.children {
            out.push_str(LINE_SEPARATOR);
            child.write(out, depth + 1);
        }
        out.push_str(LINE_SEPARATOR);
        for _ in 0..depth {
            out.push_str(XML_INDENT);
        }
        out.push_str("</");
        out.push_str(&self.name);
        out.push('>');
    }
}

impl fmt::Display for XmlNode {
    /// Mirrors JDOM `Element.toString()`, which is what Java's builder origins print as.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[Element: <{}/>]", self.name)
    }
}

/// JDOM's attribute escaping.
fn escape_attribute(value: &str, out: &mut String) {
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

fn parse_document(xml: &str) -> Result<XmlNode, XmlSchemaError> {
    let mut parser = xml_pull_parser_factory::create_from_str(xml, "schema", None, false)
        .map_err(|e| XmlSchemaError::Xml(e.to_string()))?;
    let mut stack: Vec<XmlNode> = Vec::new();
    let mut root = None;
    while parser.has_next() {
        let ele = parser.next();
        if ele.is_start() {
            let mut node = XmlNode::new(ele.get_name());
            for (k, v) in ele.get_attribute_iter() {
                node.attributes.push((k, v));
            }
            stack.push(node);
        } else if ele.is_end() {
            let node = stack.pop().ok_or_else(|| XmlSchemaError::Xml("Unbalanced end".into()))?;
            match stack.last_mut() {
                Some(parent) => parent.children.push(node),
                None => root = Some(node),
            }
        }
    }
    parser.dispose();
    root.ok_or_else(|| XmlSchemaError::Xml("Document has no root element".into()))
}

fn parse_boolean(ele: &XmlNode, attr_name: &str) -> bool {
    TRUES.contains(&ele.attr_or(attr_name, NO).to_lowercase().as_str())
}

fn parse_hidden(ele: &XmlNode, attr_name: &str) -> Hidden {
    let value = ele.attr_or(attr_name, DEFAULT).to_lowercase();
    if TRUES.contains(&value.as_str()) {
        return Hidden::True;
    }
    if FALSES.contains(&value.as_str()) {
        return Hidden::False;
    }
    Hidden::Default
}

fn require_attribute_value<'a>(elem: &'a XmlNode, name: &str) -> Result<&'a str, XmlSchemaError> {
    elem.attr(name).ok_or_else(|| {
        XmlSchemaError::Schema(SchemaArgumentError(format!(
            "Missing attribute '{name}' in {elem}"
        )))
    })
}

/// A schema context read from XML. Mirrors
/// `ghidra.trace.model.target.schema.XmlSchemaContext`, which extends `DefaultSchemaContext`;
/// the base context is reachable through `Deref`.
pub struct XmlSchemaContext {
    base: DefaultSchemaContext,
}

impl XmlSchemaContext {
    /// An empty (primitives-only) context.
    pub fn new() -> Self {
        XmlSchemaContext { base: DefaultSchemaContext::new() }
    }

    /// The underlying context handle.
    pub fn context(&self) -> &DefaultSchemaContext {
        &self.base
    }

    /// Serialize a context to XML. Mirrors `serialize(SchemaContext)`.
    pub fn serialize(ctx: &dyn SchemaContext) -> String {
        let mut out = String::new();
        Self::context_to_xml(ctx).write(&mut out, 0);
        out
    }

    /// Mirrors `contextToXml(SchemaContext)`.
    pub fn context_to_xml(ctx: &dyn SchemaContext) -> XmlNode {
        let mut result = XmlNode::new(ELEM_CONTEXT);
        for schema in ctx.get_all_schemas() {
            if let Some(schema_elem) = Self::schema_to_xml(schema.as_ref()) {
                result.children.push(schema_elem);
            }
        }
        result
    }

    /// Mirrors `attributeSchemaToXml(AttributeSchema)`.
    pub fn attribute_schema_to_xml(attr: &AttributeSchema) -> XmlNode {
        let mut attr_elem = XmlNode::new(ELEM_ATTRIBUTE);
        if !attr.get_name().is_empty() {
            attr_elem.set_attr(ATTR_NAME, attr.get_name());
        }
        attr_elem.set_attr(ATTR_SCHEMA, attr.get_schema().as_str());
        if attr.is_required() {
            attr_elem.set_attr(ATTR_REQUIRED, YES);
        }
        if attr.is_fixed() {
            attr_elem.set_attr(ATTR_FIXED, YES);
        }
        match attr.get_hidden() {
            Hidden::True => attr_elem.set_attr(ATTR_HIDDEN, YES),
            Hidden::False => {
                if attr.get_name().is_empty() {
                    attr_elem.set_attr(ATTR_HIDDEN, NO);
                }
            }
            Hidden::Default => {}
        }
        attr_elem
    }

    /// Mirrors `aliasToXml(Map.Entry)`.
    pub fn alias_to_xml(from: &str, to: &str) -> XmlNode {
        let mut alias_elem = XmlNode::new(ELEM_ATTRIBUTE_ALIAS);
        alias_elem.set_attr(ATTR_FROM, from);
        alias_elem.set_attr(ATTR_TO, to);
        alias_elem
    }

    /// Mirrors `schemaToXml(TraceObjectSchema)`: `None` for non-object schemas and for `OBJECT`.
    pub fn schema_to_xml(schema: &dyn TraceObjectSchema) -> Option<XmlNode> {
        if !is_trace_object_type(schema.get_type()) {
            return None;
        }
        if schema.is_primitive() && schema.get_name() == PrimitiveTraceObjectSchema::Object.get_name()
        {
            return None;
        }
        let mut result = XmlNode::new(ELEM_SCHEMA);
        result.set_attr(ATTR_NAME, schema.get_name().as_str());
        for iface in schema.get_interfaces() {
            let mut if_elem = XmlNode::new(ELEM_INTERFACE);
            if_elem.set_attr(ATTR_NAME, &iface.schema_name);
            result.children.push(if_elem);
        }
        if schema.is_canonical_container() {
            result.set_attr(ATTR_CANONICAL, YES);
        }
        for (index, elem_schema) in schema.get_element_schemas() {
            let mut elem_elem = XmlNode::new(ELEM_ELEMENT);
            elem_elem.set_attr(ATTR_INDEX, index);
            elem_elem.set_attr(ATTR_SCHEMA, elem_schema.as_str());
            result.children.push(elem_elem);
        }
        let des = schema.get_default_element_schema();
        if des != SchemaBuilder::default_element_schema_name() {
            let mut de_elem = XmlNode::new(ELEM_ELEMENT);
            de_elem.set_attr(ATTR_SCHEMA, des.as_str());
            result.children.push(de_elem);
        }
        for (key, attr) in schema.get_attribute_schemas() {
            if key != attr.get_name() {
                // Exclude aliases here
                continue;
            }
            result.children.push(Self::attribute_schema_to_xml(attr));
        }
        let das = schema.get_default_attribute_schema();
        if das != SchemaBuilder::default_attribute_schema_value() {
            result.children.push(Self::attribute_schema_to_xml(&das));
        }
        // Yes, these will be the "resolved" aliases, but I think that's okay.
        for (from, to) in schema.get_attribute_aliases() {
            result.children.push(Self::alias_to_xml(from, to));
        }
        Some(result)
    }

    /// Read a context from XML text. Mirrors `deserialize(String)` / `deserialize(byte[])`.
    pub fn deserialize(xml: &str) -> Result<XmlSchemaContext, XmlSchemaError> {
        Self::context_from_xml(&parse_document(xml)?)
    }

    /// Read a context from an XML file. Mirrors `deserialize(File)`.
    pub fn deserialize_file(path: &std::path::Path) -> Result<XmlSchemaContext, XmlSchemaError> {
        let xml = std::fs::read_to_string(path).map_err(|e| XmlSchemaError::Xml(e.to_string()))?;
        Self::deserialize(&xml)
    }

    /// Mirrors `contextFromXml(Element)`.
    pub fn context_from_xml(context_elem: &XmlNode) -> Result<XmlSchemaContext, XmlSchemaError> {
        let ctx = XmlSchemaContext::new();
        for schema_elem in context_elem.children_named(ELEM_SCHEMA) {
            ctx.schema_from_xml(schema_elem)?;
        }
        Ok(ctx)
    }

    /// Mirrors `name(String)`. Java interns names so equal names share one instance;
    /// [`SchemaName`] is a value type, so this just constructs one.
    pub fn name(&self, name: &str) -> SchemaName {
        SchemaName::new(name)
    }

    /// Build and add one schema from its element. Mirrors `schemaFromXml(Element)`: unknown
    /// interface names are warned about and skipped.
    pub fn schema_from_xml(
        &self,
        schema_elem: &XmlNode,
    ) -> Result<DefaultTraceObjectSchema, XmlSchemaError> {
        let mut builder = self.base.builder(self.name(schema_elem.attr_or(ATTR_NAME, "")));
        for iface_elem in schema_elem.children_named(ELEM_INTERFACE) {
            let iface_name = require_attribute_value(iface_elem, ATTR_NAME)?;
            match trace_object_interface_utils::get_info_by_name(iface_name) {
                None => Msg::warn(
                    "XmlSchemaContext",
                    &format!("Unknown interface name: '{iface_name}'"),
                ),
                Some(info) => {
                    builder.add_interface(info.clone());
                }
            }
        }
        builder.set_canonical_container(parse_boolean(schema_elem, ATTR_CANONICAL));
        for elem_elem in schema_elem.children_named(ELEM_ELEMENT) {
            let schema = self.name(require_attribute_value(elem_elem, ATTR_SCHEMA)?);
            let index = elem_elem.attr_or(ATTR_INDEX, "");
            builder.add_element_schema(index, schema, elem_elem)?;
        }
        for attr_elem in schema_elem.children_named(ELEM_ATTRIBUTE) {
            let schema = self.name(require_attribute_value(attr_elem, ATTR_SCHEMA)?);
            let required = parse_boolean(attr_elem, ATTR_REQUIRED);
            let fixed = parse_boolean(attr_elem, ATTR_FIXED);
            let hidden = parse_hidden(attr_elem, ATTR_HIDDEN);
            let name = attr_elem.attr_or(ATTR_NAME, "");
            builder.add_attribute_schema(
                AttributeSchema::new(name, schema, required, fixed, hidden)?,
                attr_elem,
            )?;
        }
        for alias_elem in schema_elem.children_named(ELEM_ATTRIBUTE_ALIAS) {
            let from = require_attribute_value(alias_elem, ATTR_FROM)?;
            let to = require_attribute_value(alias_elem, ATTR_TO)?;
            builder.add_attribute_alias(from, to, alias_elem)?;
        }
        Ok(builder.build_and_add()?)
    }
}

impl Default for XmlSchemaContext {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for XmlSchemaContext {
    type Target = DefaultSchemaContext;

    fn deref(&self) -> &DefaultSchemaContext {
        &self.base
    }
}

impl SchemaContext for XmlSchemaContext {
    fn get_schema(&self, name: &SchemaName) -> Box<dyn TraceObjectSchema> {
        self.base.get_schema(name)
    }

    fn get_schema_or_null(&self, name: &SchemaName) -> Option<Box<dyn TraceObjectSchema>> {
        self.base.get_schema_or_null(name)
    }

    fn get_all_schemas(&self) -> Vec<Box<dyn TraceObjectSchema>> {
        self.base.get_all_schemas()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::model::target::path::KeyPath;
    use crate::trace::model::target::schema::trace_object_schema::TraceObjectSchemaExt;

    const GDB_SCHEMA: &str = include_str!(
        "../../../../../../orig_src/Ghidra/Debug/Debugger-agent-gdb/src/main/py/src/ghidragdb/schema.xml"
    );
    const LLDB_SCHEMA: &str = include_str!(
        "../../../../../../orig_src/Ghidra/Debug/Debugger-agent-lldb/src/main/py/src/ghidralldb/schema.xml"
    );

    fn names(schema: &dyn TraceObjectSchema) -> Vec<String> {
        schema.get_interfaces().into_iter().map(|i| i.schema_name).collect()
    }

    #[test]
    fn gdb_session_schema() {
        let ctx = XmlSchemaContext::deserialize(GDB_SCHEMA).unwrap();
        let session = ctx.get_schema(&SchemaName::new("GdbSession"));
        assert!(!session.is_primitive());
        assert_eq!(names(session.as_ref()), vec!["EventScope", "FocusScope", "Aggregate"]);
        assert!(!session.is_canonical_container());
        assert_eq!(session.get_default_element_schema(), SchemaName::new("VOID"));
        let inferiors = session.get_attribute_schema("Inferiors");
        assert_eq!(inferiors.get_schema(), &SchemaName::new("ProcessContainer"));
        assert!(inferiors.is_required());
        assert!(inferiors.is_fixed());
        assert_eq!(inferiors.get_hidden(), Hidden::False);
        let focus = session.get_attribute_schema("_focus");
        assert_eq!(focus.get_schema(), &SchemaName::new("Selectable"));
        assert!(focus.is_required());
        assert!(!focus.is_fixed());
        assert!(session.is_hidden("_focus"));
        assert!(session.is_hidden("_display"));
        // <attribute schema="VOID"/> is the default attribute schema.
        let das = session.get_default_attribute_schema();
        assert_eq!(das.get_schema(), &SchemaName::new("VOID"));
        assert_eq!(das.get_hidden(), Hidden::Default);
        assert!(session.is_hidden("_undeclared"));
        assert!(!session.is_hidden("Undeclared"));
    }

    #[test]
    fn gdb_process_schema_with_alias() {
        let ctx = XmlSchemaContext::deserialize(GDB_SCHEMA).unwrap();
        let process = ctx.get_schema(&SchemaName::new("Process"));
        assert_eq!(
            names(process.as_ref()),
            vec!["Activatable", "Process", "Aggregate", "ExecutionStateful"]
        );
        assert_eq!(process.check_aliased_attribute("_exit_code"), "Exit Code");
        assert_eq!(
            process.get_attribute_schema("_exit_code").get_schema(),
            &SchemaName::new("LONG")
        );
        assert_eq!(process.get_child_schema("Threads").get_name(), SchemaName::new("ThreadContainer"));
    }

    #[test]
    fn canonical_containers_and_searches() {
        let ctx = XmlSchemaContext::deserialize(GDB_SCHEMA).unwrap();
        let container = ctx.get_schema(&SchemaName::new("ProcessContainer"));
        assert!(container.is_canonical_container());
        assert_eq!(container.get_child_schema("[1]").get_name(), SchemaName::new("Process"));

        let root = ctx.get_schema(&SchemaName::new("GdbSession"));
        let inferiors = KeyPath::of(&["Inferiors"]);
        assert_eq!(root.search_for_canonical_container("Process"), Some(inferiors.clone()));
        let thread_path = KeyPath::parse("Inferiors[1].Threads[1]").unwrap();
        assert_eq!(
            root.search_for_suitable("Process", &thread_path),
            Some(KeyPath::parse("Inferiors[1]").unwrap())
        );
        assert_eq!(
            root.get_successor_schema(&thread_path).get_name(),
            SchemaName::new("Thread")
        );
        let procs = root.search_for("Process", true);
        assert_eq!(procs.get_singleton_pattern().unwrap().as_path().to_string(), "Inferiors[]");
    }

    #[test]
    fn register_container_for_frame() {
        let ctx = XmlSchemaContext::deserialize(GDB_SCHEMA).unwrap();
        let root = ctx.get_schema(&SchemaName::new("GdbSession"));
        let thread_path = KeyPath::parse("Inferiors[1].Threads[1]").unwrap();
        // Java tries both the decimal and the hex spelling of the frame index.
        let mut regs: Vec<String> = root
            .search_for_register_container(0, &thread_path)
            .iter()
            .map(|p| p.as_path().to_string())
            .collect();
        regs.sort();
        assert_eq!(
            regs,
            vec![
                "Inferiors[1].Threads[1].Stack[0].Registers",
                "Inferiors[1].Threads[1].Stack[0x0].Registers"
            ]
        );
        assert_eq!(
            root.compute_frame_level(
                &KeyPath::parse("Inferiors[1].Threads[1].Stack[2].Registers").unwrap()
            ),
            Ok(2)
        );
    }

    #[test]
    fn lldb_schema_parses_and_round_trips() {
        let ctx = XmlSchemaContext::deserialize(LLDB_SCHEMA).unwrap();
        let xml = XmlSchemaContext::serialize(&*ctx);
        let again = XmlSchemaContext::deserialize(&xml).unwrap();
        assert_eq!(*again, *ctx);
        assert_eq!(XmlSchemaContext::serialize(&*again), xml);
    }

    #[test]
    fn serialize_matches_jdom_output() {
        let ctx = XmlSchemaContext::deserialize(
            "<context><schema name='Session' canonical='yes'>\
               <interface name='Aggregate'/><interface name='NotAnInterface'/>\
               <element index='0' schema='Process'/><element schema='VOID'/>\
               <attribute name='_x' schema='INT' required='yes' hidden='yes'/>\
               <attribute schema='VOID' hidden='no'/>\
               <attribute-alias from='x' to='_x'/>\
             </schema></context>",
        )
        .unwrap();
        assert_eq!(
            XmlSchemaContext::serialize(&*ctx),
            "<context>\r\n    <schema name=\"Session\" canonical=\"yes\">\r\n        \
             <interface name=\"Aggregate\" />\r\n        \
             <element index=\"0\" schema=\"Process\" />\r\n        \
             <element schema=\"VOID\" />\r\n        \
             <attribute name=\"_x\" schema=\"INT\" required=\"yes\" hidden=\"yes\" />\r\n        \
             <attribute schema=\"VOID\" hidden=\"no\" />\r\n        \
             <attribute-alias from=\"x\" to=\"_x\" />\r\n    </schema>\r\n</context>"
        );
        assert_eq!(XmlSchemaContext::serialize(&DefaultSchemaContext::new()), "<context />");
    }

    #[test]
    fn schema_errors_surface() {
        let err = XmlSchemaContext::deserialize(
            "<context><schema name='S'><element/></schema></context>",
        )
        .err()
        .unwrap();
        assert_eq!(
            err,
            XmlSchemaError::Schema(SchemaArgumentError(
                "Missing attribute 'schema' in [Element: <element/>]".into()
            ))
        );
        let err = XmlSchemaContext::deserialize(
            "<context><schema name='S'/><schema name='S'/></context>",
        )
        .err()
        .unwrap();
        assert_eq!(err.to_string(), "Name already in context: S");
        assert!(matches!(
            XmlSchemaContext::deserialize("<context><schema").err().unwrap(),
            XmlSchemaError::Xml(_)
        ));
    }
}
