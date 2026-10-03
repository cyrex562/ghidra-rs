//! A RELAX NG validator for the XML-syntax schema subset Ghidra's language schemas use.
//!
//! Not the port of a Ghidra class: Java's `SleighLanguageValidator` hands its `.rxg` schemas to
//! the Sun Multi-Schema Validator (MSV) through the `org.iso_relax.verifier` API. This module
//! stands in for that library, as [`sax_parser`](super::sax_parser) stands in for the JDK's SAX
//! parser.
//!
//! # Supported schema language
//! The patterns of the RELAX NG XML syntax that `compiler_spec.rxg`, `processor_spec.rxg`,
//! `language_definitions.rxg` and `language_common.rxg` use: `grammar`, `start`, `define`,
//! `ref`, `include` (without overriding content), `element` and `attribute` with a `name`
//! attribute, `group`, `interleave`, `choice`, `optional`, `zeroOrMore`, `oneOrMore`, `empty`,
//! `text`, `notAllowed`, and `value` with the built-in `token` (the default) or `string` type.
//! Anything else (name classes, `data`, `list`, `mixed`, `parentRef`, `externalRef`, combined
//! definitions, other datatype libraries, namespaces) is rejected when the schema is compiled,
//! so a schema is never validated only partially.
//!
//! # Algorithm
//! Validation computes pattern derivatives as in James Clark's "An algorithm for RELAX NG
//! validation" (2002), streaming over SAX events: the document is valid when the derivative of
//! the start pattern by the whole document is nullable. Patterns are hash-consed in an arena so
//! equal patterns share one id, which keeps `choice` deduplication exact and the derivatives
//! small. Element content is held in a side table so recursive element definitions stay finite.

use std::collections::{BTreeSet, HashMap};
use std::fmt;

use super::sax_parser::{self, SaxConfig, SaxContentHandler, SaxError, SaxLocation};

/// A schema compilation or document validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelaxNgError {
    /// 1-based line of the failure in the document (or schema), 0 if unknown.
    pub(crate) line: i32,
    /// 1-based column of the failure, 0 if unknown.
    pub(crate) column: i32,
    /// What went wrong.
    pub(crate) message: String,
}

impl RelaxNgError {
    /// An error without a location.
    pub(crate) fn new(message: impl Into<String>) -> Self {
        RelaxNgError { line: 0, column: 0, message: message.into() }
    }

    fn at(location: SaxLocation, message: impl Into<String>) -> Self {
        RelaxNgError { line: location.line, column: location.column, message: message.into() }
    }
}

impl fmt::Display for RelaxNgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.line > 0 {
            write!(f, "{}:{}: {}", self.line, self.column, self.message)
        } else {
            f.write_str(&self.message)
        }
    }
}

impl std::error::Error for RelaxNgError {}

impl From<SaxError> for RelaxNgError {
    fn from(e: SaxError) -> Self {
        match e {
            SaxError::Fatal { line, column, message } => RelaxNgError { line, column, message },
            SaxError::Handler(e) => RelaxNgError::new(e.to_string()),
        }
    }
}

type PatId = u32;
type NameId = u32;
/// A document name the schema never mentions: it matches no `element`/`attribute` pattern.
const UNKNOWN_NAME: NameId = NameId::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Pat {
    Empty,
    NotAllowed,
    Text,
    Choice(PatId, PatId),
    Interleave(PatId, PatId),
    Group(PatId, PatId),
    OneOrMore(PatId),
    /// An element pattern: index into the element table (name and content).
    Element(u32),
    Attribute(NameId, PatId),
    /// A `value` pattern: `token` comparison (whitespace-normalized) or exact `string`.
    Value { token: bool, value: u32 },
    After(PatId, PatId),
}

const EMPTY: PatId = 0;
const NOT_ALLOWED: PatId = 1;
const TEXT: PatId = 2;

/// The hash-consed pattern store. A compiled schema owns one; each validation works on a copy.
#[derive(Debug, Clone)]
struct Arena {
    pats: Vec<Pat>,
    ids: HashMap<Pat, PatId>,
    /// `(name, content)` for each element pattern.
    elements: Vec<(NameId, PatId)>,
    /// Names used by element and attribute patterns.
    names: Vec<String>,
    name_ids: HashMap<String, NameId>,
    /// Values of value patterns.
    values: Vec<String>,
    /// Memoized start-tag-open derivatives.
    start_tag_open_memo: HashMap<(PatId, NameId), PatId>,
}

impl Arena {
    fn new() -> Self {
        let mut arena = Arena {
            pats: Vec::new(),
            ids: HashMap::new(),
            elements: Vec::new(),
            names: Vec::new(),
            name_ids: HashMap::new(),
            values: Vec::new(),
            start_tag_open_memo: HashMap::new(),
        };
        // Fixed ids for the leaves (EMPTY, NOT_ALLOWED, TEXT).
        arena.intern(Pat::Empty);
        arena.intern(Pat::NotAllowed);
        arena.intern(Pat::Text);
        arena
    }

    fn intern(&mut self, pat: Pat) -> PatId {
        if let Some(&id) = self.ids.get(&pat) {
            return id;
        }
        let id = self.pats.len() as PatId;
        self.pats.push(pat);
        self.ids.insert(pat, id);
        id
    }

    fn pat(&self, id: PatId) -> Pat {
        self.pats[id as usize]
    }

    fn name_id(&mut self, name: &str) -> NameId {
        if let Some(&id) = self.name_ids.get(name) {
            return id;
        }
        let id = self.names.len() as NameId;
        self.names.push(name.to_string());
        self.name_ids.insert(name.to_string(), id);
        id
    }

    fn lookup_name(&self, name: &str) -> NameId {
        self.name_ids.get(name).copied().unwrap_or(UNKNOWN_NAME)
    }

    // ---- constructors (with the algorithm's simplifications) ----

    fn choice(&mut self, p1: PatId, p2: PatId) -> PatId {
        if p1 == NOT_ALLOWED {
            return p2;
        }
        if p2 == NOT_ALLOWED || p1 == p2 {
            return p1;
        }
        // Flatten and deduplicate, then rebuild in a canonical (sorted, right-nested) order so
        // equal sets of alternatives intern to one id.
        let mut alternatives = BTreeSet::new();
        self.collect_choice(p1, &mut alternatives);
        self.collect_choice(p2, &mut alternatives);
        let mut iter = alternatives.into_iter().rev();
        let mut result = iter.next().expect("a choice has alternatives");
        for alternative in iter {
            result = self.intern(Pat::Choice(alternative, result));
        }
        result
    }

    fn collect_choice(&self, p: PatId, out: &mut BTreeSet<PatId>) {
        match self.pat(p) {
            Pat::Choice(a, b) => {
                self.collect_choice(a, out);
                self.collect_choice(b, out);
            }
            Pat::NotAllowed => {}
            _ => {
                out.insert(p);
            }
        }
    }

    fn group(&mut self, p1: PatId, p2: PatId) -> PatId {
        if p1 == NOT_ALLOWED || p2 == NOT_ALLOWED {
            NOT_ALLOWED
        } else if p1 == EMPTY {
            p2
        } else if p2 == EMPTY {
            p1
        } else {
            self.intern(Pat::Group(p1, p2))
        }
    }

    fn interleave(&mut self, p1: PatId, p2: PatId) -> PatId {
        if p1 == NOT_ALLOWED || p2 == NOT_ALLOWED {
            NOT_ALLOWED
        } else if p1 == EMPTY {
            p2
        } else if p2 == EMPTY {
            p1
        } else {
            self.intern(Pat::Interleave(p1, p2))
        }
    }

    fn after(&mut self, p1: PatId, p2: PatId) -> PatId {
        if p1 == NOT_ALLOWED || p2 == NOT_ALLOWED {
            NOT_ALLOWED
        } else {
            self.intern(Pat::After(p1, p2))
        }
    }

    fn one_or_more(&mut self, p: PatId) -> PatId {
        if p == NOT_ALLOWED || p == EMPTY {
            p
        } else {
            self.intern(Pat::OneOrMore(p))
        }
    }

    // ---- derivatives ----

    fn nullable(&self, p: PatId) -> bool {
        match self.pat(p) {
            Pat::Empty | Pat::Text => true,
            Pat::NotAllowed | Pat::Element(_) | Pat::Attribute(..) | Pat::Value { .. } | Pat::After(..) => false,
            Pat::Choice(a, b) => self.nullable(a) || self.nullable(b),
            Pat::Interleave(a, b) | Pat::Group(a, b) => self.nullable(a) && self.nullable(b),
            Pat::OneOrMore(a) => self.nullable(a),
        }
    }

    /// `applyAfter` with the continuation `f` applied to every `After`'s second pattern.
    fn apply_after(&mut self, p: PatId, f: &dyn Fn(&mut Arena, PatId) -> PatId) -> PatId {
        match self.pat(p) {
            Pat::After(a, b) => {
                let b = f(self, b);
                self.after(a, b)
            }
            Pat::Choice(a, b) => {
                let a = self.apply_after(a, f);
                let b = self.apply_after(b, f);
                self.choice(a, b)
            }
            _ => NOT_ALLOWED,
        }
    }

    fn start_tag_open(&mut self, p: PatId, name: NameId) -> PatId {
        if let Some(&d) = self.start_tag_open_memo.get(&(p, name)) {
            return d;
        }
        let d = match self.pat(p) {
            Pat::Choice(a, b) => {
                let a = self.start_tag_open(a, name);
                let b = self.start_tag_open(b, name);
                self.choice(a, b)
            }
            Pat::Element(index) => {
                let (element_name, content) = self.elements[index as usize];
                if element_name == name {
                    self.after(content, EMPTY)
                } else {
                    NOT_ALLOWED
                }
            }
            Pat::Interleave(a, b) => {
                let da = self.start_tag_open(a, name);
                let x = self.apply_after(da, &|arena, q| arena.interleave(q, b));
                let db = self.start_tag_open(b, name);
                let y = self.apply_after(db, &|arena, q| arena.interleave(a, q));
                self.choice(x, y)
            }
            Pat::OneOrMore(a) => {
                let da = self.start_tag_open(a, name);
                self.apply_after(da, &|arena, q| {
                    let rest = arena.choice(p, EMPTY);
                    arena.group(q, rest)
                })
            }
            Pat::Group(a, b) => {
                let da = self.start_tag_open(a, name);
                let x = self.apply_after(da, &|arena, q| arena.group(q, b));
                if self.nullable(a) {
                    let db = self.start_tag_open(b, name);
                    self.choice(x, db)
                } else {
                    x
                }
            }
            Pat::After(a, b) => {
                let da = self.start_tag_open(a, name);
                self.apply_after(da, &|arena, q| arena.after(q, b))
            }
            _ => NOT_ALLOWED,
        };
        self.start_tag_open_memo.insert((p, name), d);
        d
    }

    fn att(&mut self, p: PatId, name: NameId, value: &str) -> PatId {
        match self.pat(p) {
            Pat::After(a, b) => {
                let a = self.att(a, name, value);
                self.after(a, b)
            }
            Pat::Choice(a, b) => {
                let a = self.att(a, name, value);
                let b = self.att(b, name, value);
                self.choice(a, b)
            }
            Pat::Group(a, b) => {
                let da = self.att(a, name, value);
                let x = self.group(da, b);
                let db = self.att(b, name, value);
                let y = self.group(a, db);
                self.choice(x, y)
            }
            Pat::Interleave(a, b) => {
                let da = self.att(a, name, value);
                let x = self.interleave(da, b);
                let db = self.att(b, name, value);
                let y = self.interleave(a, db);
                self.choice(x, y)
            }
            Pat::OneOrMore(a) => {
                let da = self.att(a, name, value);
                let rest = self.choice(p, EMPTY);
                self.group(da, rest)
            }
            Pat::Attribute(attribute_name, content) => {
                if attribute_name == name && self.value_match(content, value) {
                    EMPTY
                } else {
                    NOT_ALLOWED
                }
            }
            _ => NOT_ALLOWED,
        }
    }

    fn value_match(&mut self, p: PatId, s: &str) -> bool {
        (self.nullable(p) && is_whitespace(s)) || {
            let d = self.text(p, s);
            self.nullable(d)
        }
    }

    fn start_tag_close(&mut self, p: PatId) -> PatId {
        match self.pat(p) {
            Pat::After(a, b) => {
                let a = self.start_tag_close(a);
                self.after(a, b)
            }
            Pat::Choice(a, b) => {
                let a = self.start_tag_close(a);
                let b = self.start_tag_close(b);
                self.choice(a, b)
            }
            Pat::Group(a, b) => {
                let a = self.start_tag_close(a);
                let b = self.start_tag_close(b);
                self.group(a, b)
            }
            Pat::Interleave(a, b) => {
                let a = self.start_tag_close(a);
                let b = self.start_tag_close(b);
                self.interleave(a, b)
            }
            Pat::OneOrMore(a) => {
                let a = self.start_tag_close(a);
                self.one_or_more(a)
            }
            Pat::Attribute(..) => NOT_ALLOWED,
            _ => p,
        }
    }

    fn text(&mut self, p: PatId, s: &str) -> PatId {
        match self.pat(p) {
            Pat::Choice(a, b) => {
                let a = self.text(a, s);
                let b = self.text(b, s);
                self.choice(a, b)
            }
            Pat::Interleave(a, b) => {
                let da = self.text(a, s);
                let x = self.interleave(da, b);
                let db = self.text(b, s);
                let y = self.interleave(a, db);
                self.choice(x, y)
            }
            Pat::Group(a, b) => {
                let da = self.text(a, s);
                let x = self.group(da, b);
                if self.nullable(a) {
                    let db = self.text(b, s);
                    self.choice(x, db)
                } else {
                    x
                }
            }
            Pat::After(a, b) => {
                let a = self.text(a, s);
                self.after(a, b)
            }
            Pat::OneOrMore(a) => {
                let da = self.text(a, s);
                let rest = self.choice(p, EMPTY);
                self.group(da, rest)
            }
            Pat::Text => TEXT,
            Pat::Value { token, value } => {
                let expected = &self.values[value as usize];
                let matches = if token { normalize_token(expected) == normalize_token(s) } else { expected == s };
                if matches {
                    EMPTY
                } else {
                    NOT_ALLOWED
                }
            }
            _ => NOT_ALLOWED,
        }
    }

    /// The derivative by a run of character data between tags (whitespace may be ignored).
    fn children_text(&mut self, p: PatId, s: &str) -> PatId {
        let d = self.text(p, s);
        if is_whitespace(s) {
            self.choice(p, d)
        } else {
            d
        }
    }

    fn end_tag(&mut self, p: PatId) -> PatId {
        match self.pat(p) {
            Pat::Choice(a, b) => {
                let a = self.end_tag(a);
                let b = self.end_tag(b);
                self.choice(a, b)
            }
            Pat::After(a, b) => {
                if self.nullable(a) {
                    b
                } else {
                    NOT_ALLOWED
                }
            }
            _ => NOT_ALLOWED,
        }
    }
}

fn is_whitespace(s: &str) -> bool {
    s.chars().all(|c| matches!(c, ' ' | '\t' | '\n' | '\r'))
}

/// The built-in `token` datatype's normalization: whitespace runs collapse, ends are trimmed.
fn normalize_token(s: &str) -> String {
    s.split([' ', '\t', '\n', '\r']).filter(|t| !t.is_empty()).collect::<Vec<_>>().join(" ")
}

// ---------------------------------------------------------------------------------------------
// Schema document model and compilation
// ---------------------------------------------------------------------------------------------

/// One element of a schema document.
#[derive(Debug, Clone)]
struct SchemaNode {
    name: String,
    attributes: Vec<(String, String)>,
    children: Vec<usize>,
    text: String,
    location: SaxLocation,
}

impl SchemaNode {
    fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

/// All schema elements of every loaded schema document, by index.
#[derive(Debug, Default)]
struct SchemaDom {
    nodes: Vec<SchemaNode>,
}

struct DomBuilder<'a> {
    dom: &'a mut SchemaDom,
    stack: Vec<usize>,
    root: Option<usize>,
}

impl SaxContentHandler for DomBuilder<'_> {
    fn start_element(&mut self, name: &str, attributes: Vec<(String, String)>, location: SaxLocation) -> Result<(), SaxError> {
        let index = self.dom.nodes.len();
        self.dom.nodes.push(SchemaNode {
            name: name.to_string(),
            attributes,
            children: Vec::new(),
            text: String::new(),
            location,
        });
        match self.stack.last() {
            Some(&parent) => self.dom.nodes[parent].children.push(index),
            None => self.root = Some(index),
        }
        self.stack.push(index);
        Ok(())
    }

    fn end_element(&mut self, _name: &str, _location: SaxLocation) -> Result<(), SaxError> {
        self.stack.pop();
        Ok(())
    }

    fn characters(&mut self, text: &str) -> Result<(), SaxError> {
        if let Some(&current) = self.stack.last() {
            self.dom.nodes[current].text.push_str(text);
        }
        Ok(())
    }

    fn processing_instruction(&mut self, _target: &str, _data: &str) -> Result<(), SaxError> {
        Ok(())
    }
}

/// Supplies the text of a schema document named by an `include href`.
pub(crate) trait SchemaResolver {
    /// The document `href` (relative to the including document `base`), or `None` if absent.
    fn resolve(&self, base: &str, href: &str) -> Option<(String, Vec<u8>)>;
}

/// A compiled RELAX NG schema, ready to validate any number of documents.
#[derive(Debug, Clone)]
pub(crate) struct RelaxNgSchema {
    arena: Arena,
    start: PatId,
}

struct Compiler<'a> {
    dom: SchemaDom,
    arena: Arena,
    resolver: &'a dyn SchemaResolver,
    defines: HashMap<String, usize>,
    /// Element patterns already allocated, by schema node.
    element_memo: HashMap<usize, u32>,
    /// Definitions being expanded (to reject recursion not guarded by an element).
    expanding: Vec<String>,
}

const RNG_NS: &str = "http://relaxng.org/ns/structure/1.0";

impl<'a> Compiler<'a> {
    fn err(&self, node: usize, message: impl Into<String>) -> RelaxNgError {
        RelaxNgError::at(self.dom.nodes[node].location, message)
    }

    fn load(&mut self, name: &str, text: &[u8]) -> Result<usize, RelaxNgError> {
        let mut builder = DomBuilder { dom: &mut self.dom, stack: Vec::new(), root: None };
        sax_parser::parse(text, SaxConfig::default(), &mut builder).map_err(|e| {
            let e = RelaxNgError::from(e);
            RelaxNgError { message: format!("{name}: {}", e.message), ..e }
        })?;
        builder.root.ok_or_else(|| RelaxNgError::new(format!("{name}: empty schema")))
    }

    /// Collects the `define`s and `start` of a `grammar` (following `include`s).
    fn collect_grammar(&mut self, base: &str, grammar: usize, start: &mut Option<usize>) -> Result<(), RelaxNgError> {
        let node = &self.dom.nodes[grammar];
        if node.name != "grammar" {
            return Err(self.err(grammar, format!("expected <grammar>, found <{}>", node.name)));
        }
        if let Some(ns) = node.attribute("xmlns") {
            if ns != RNG_NS {
                return Err(self.err(grammar, format!("unsupported schema namespace {ns}")));
            }
        }
        for child in self.dom.nodes[grammar].children.clone() {
            let child_node = self.dom.nodes[child].clone();
            match child_node.name.as_str() {
                "define" => {
                    if child_node.attribute("combine").is_some() {
                        return Err(self.err(child, "combined definitions are not supported"));
                    }
                    let name = self.required(child, "name")?.to_string();
                    if self.defines.insert(name.clone(), child).is_some() {
                        return Err(self.err(child, format!("duplicate definition {name}")));
                    }
                }
                "start" => {
                    if child_node.attribute("combine").is_some() || start.is_some() {
                        return Err(self.err(child, "multiple or combined <start> elements are not supported"));
                    }
                    *start = Some(child);
                }
                "include" => {
                    if !child_node.children.is_empty() {
                        return Err(self.err(child, "<include> with overriding content is not supported"));
                    }
                    let href = self.required(child, "href")?.to_string();
                    let Some((name, text)) = self.resolver.resolve(base, &href) else {
                        return Err(self.err(child, format!("cannot resolve included schema {href}")));
                    };
                    let included = self.load(&name, &text)?;
                    self.collect_grammar(&name, included, start)?;
                }
                other => return Err(self.err(child, format!("unsupported grammar content <{other}>"))),
            }
        }
        Ok(())
    }

    fn required(&self, node: usize, attribute: &str) -> Result<&str, RelaxNgError> {
        self.dom.nodes[node]
            .attribute(attribute)
            .ok_or_else(|| self.err(node, format!("<{}> is missing its {attribute} attribute", self.dom.nodes[node].name)))
    }

    /// The pattern of `nodes` taken as an implicit `group`.
    fn group_of(&mut self, nodes: &[usize]) -> Result<PatId, RelaxNgError> {
        let mut result = EMPTY;
        for &node in nodes.iter().rev() {
            let p = self.pattern(node)?;
            result = self.arena.group(p, result);
        }
        Ok(result)
    }

    fn check_no_unsupported_attributes(&self, node: usize) -> Result<(), RelaxNgError> {
        let n = &self.dom.nodes[node];
        for (key, value) in &n.attributes {
            match key.as_str() {
                "ns" if !value.is_empty() => return Err(self.err(node, "namespaces are not supported")),
                "datatypeLibrary" if !value.is_empty() => {
                    return Err(self.err(node, format!("datatype library {value} is not supported")))
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn pattern(&mut self, node: usize) -> Result<PatId, RelaxNgError> {
        self.check_no_unsupported_attributes(node)?;
        let n = self.dom.nodes[node].clone();
        let children = n.children.clone();
        match n.name.as_str() {
            "element" => {
                if let Some(&index) = self.element_memo.get(&node) {
                    return Ok(self.arena.intern(Pat::Element(index)));
                }
                let name = self.required(node, "name")?.to_string();
                let name = self.arena.name_id(&name);
                let index = self.arena.elements.len() as u32;
                self.arena.elements.push((name, NOT_ALLOWED));
                self.element_memo.insert(node, index);
                // Element content is a fresh context for recursion through definitions.
                let saved = std::mem::take(&mut self.expanding);
                let content = self.group_of(&children);
                self.expanding = saved;
                self.arena.elements[index as usize].1 = content?;
                Ok(self.arena.intern(Pat::Element(index)))
            }
            "attribute" => {
                let name = self.required(node, "name")?.to_string();
                let name = self.arena.name_id(&name);
                let content = match children.as_slice() {
                    [] => TEXT,
                    [only] => self.pattern(*only)?,
                    _ => return Err(self.err(node, "<attribute> must have at most one pattern")),
                };
                Ok(self.arena.intern(Pat::Attribute(name, content)))
            }
            "group" => self.group_of(&children),
            "interleave" => {
                let mut result = EMPTY;
                for &child in children.iter().rev() {
                    let p = self.pattern(child)?;
                    result = self.arena.interleave(p, result);
                }
                Ok(result)
            }
            "choice" => {
                if children.is_empty() {
                    return Err(self.err(node, "<choice> needs at least one pattern"));
                }
                let mut result = NOT_ALLOWED;
                for &child in &children {
                    let p = self.pattern(child)?;
                    result = self.arena.choice(result, p);
                }
                Ok(result)
            }
            "optional" => {
                let p = self.group_of(&children)?;
                Ok(self.arena.choice(p, EMPTY))
            }
            "zeroOrMore" => {
                let p = self.group_of(&children)?;
                let p = self.arena.one_or_more(p);
                Ok(self.arena.choice(p, EMPTY))
            }
            "oneOrMore" => {
                let p = self.group_of(&children)?;
                Ok(self.arena.one_or_more(p))
            }
            "empty" => Ok(EMPTY),
            "text" => Ok(TEXT),
            "notAllowed" => Ok(NOT_ALLOWED),
            "value" => {
                let token = match n.attribute("type") {
                    None | Some("token") => true,
                    Some("string") => false,
                    Some(other) => return Err(self.err(node, format!("value type {other} is not supported"))),
                };
                let value = self.arena.values.len() as u32;
                self.arena.values.push(n.text.clone());
                Ok(self.arena.intern(Pat::Value { token, value }))
            }
            "ref" => {
                let name = self.required(node, "name")?.to_string();
                let Some(&define) = self.defines.get(&name) else {
                    return Err(self.err(node, format!("reference to undefined pattern {name}")));
                };
                if self.expanding.contains(&name) {
                    return Err(self.err(node, format!("recursive reference to {name} outside an element")));
                }
                self.expanding.push(name);
                let define_children = self.dom.nodes[define].children.clone();
                let result = self.group_of(&define_children);
                self.expanding.pop();
                result
            }
            other => Err(self.err(node, format!("unsupported RELAX NG pattern <{other}>"))),
        }
    }
}

impl RelaxNgSchema {
    /// Compiles the schema document `text` (named `name`, against which includes resolve).
    ///
    /// # Errors
    /// If the schema is not well-formed XML, uses a construct outside the supported subset (see
    /// the module docs), or is inconsistent (undefined references, no `start`).
    pub(crate) fn compile(name: &str, text: &[u8], resolver: &dyn SchemaResolver) -> Result<Self, RelaxNgError> {
        let mut compiler = Compiler {
            dom: SchemaDom::default(),
            arena: Arena::new(),
            resolver,
            defines: HashMap::new(),
            element_memo: HashMap::new(),
            expanding: Vec::new(),
        };
        let root = compiler.load(name, text)?;
        let start = match compiler.dom.nodes[root].name.as_str() {
            "grammar" => {
                let mut start = None;
                compiler.collect_grammar(name, root, &mut start)?;
                let Some(start) = start else {
                    return Err(RelaxNgError::new(format!("{name}: grammar has no <start>")));
                };
                let children = compiler.dom.nodes[start].children.clone();
                compiler.group_of(&children)?
            }
            _ => compiler.pattern(root)?,
        };
        Ok(RelaxNgSchema { arena: compiler.arena, start })
    }

    /// Validates the XML document `input` (raw bytes; encoding detected as by the SAX parser).
    ///
    /// # Errors
    /// The first violation: a well-formedness error, or the element/attribute/text where the
    /// document stops matching the schema, with its location.
    pub(crate) fn validate(&self, input: &[u8]) -> Result<(), RelaxNgError> {
        let mut validator = Validator { arena: self.arena.clone(), state: self.start, frames: Vec::new() };
        sax_parser::parse(input, SaxConfig::default(), &mut validator)?;
        if !validator.arena.nullable(validator.state) {
            return Err(RelaxNgError::new("document is incomplete"));
        }
        Ok(())
    }
}

/// Per-open-element bookkeeping while validating.
struct Frame {
    name: String,
    had_children: bool,
    text: String,
}

struct Validator {
    arena: Arena,
    state: PatId,
    frames: Vec<Frame>,
}

impl Validator {
    fn fail(location: SaxLocation, message: String) -> SaxError {
        SaxError::Fatal { line: location.line, column: location.column, message }
    }

    /// Applies the character data collected in the current element since its last tag.
    fn flush_text(&mut self, location: SaxLocation, at_end: bool) -> Result<(), SaxError> {
        let Some(frame) = self.frames.last_mut() else {
            return Ok(());
        };
        if frame.text.is_empty() && (frame.had_children || !at_end) {
            return Ok(());
        }
        let text = std::mem::take(&mut frame.text);
        let element = frame.name.clone();
        self.state = self.arena.children_text(self.state, &text);
        if self.state == NOT_ALLOWED {
            return Err(Self::fail(location, format!("text not allowed in element \"{element}\"")));
        }
        Ok(())
    }
}

impl SaxContentHandler for Validator {
    fn start_element(&mut self, name: &str, attributes: Vec<(String, String)>, location: SaxLocation) -> Result<(), SaxError> {
        self.flush_text(location, false)?;
        if let Some(parent) = self.frames.last_mut() {
            parent.had_children = true;
        }
        let name_id = self.arena.lookup_name(name);
        let state = self.arena.start_tag_open(self.state, name_id);
        if state == NOT_ALLOWED {
            let context = match self.frames.last() {
                Some(parent) => format!(" in element \"{}\"", parent.name),
                None => String::new(),
            };
            return Err(Self::fail(location, format!("element \"{name}\" not allowed here{context}")));
        }
        let mut state = state;
        for (attribute, value) in &attributes {
            let attribute_id = self.arena.lookup_name(attribute);
            state = self.arena.att(state, attribute_id, value);
            if state == NOT_ALLOWED {
                return Err(Self::fail(
                    location,
                    format!("attribute \"{attribute}\" with value \"{value}\" not allowed in element \"{name}\""),
                ));
            }
        }
        state = self.arena.start_tag_close(state);
        if state == NOT_ALLOWED {
            return Err(Self::fail(location, format!("element \"{name}\" is missing a required attribute")));
        }
        self.state = state;
        self.frames.push(Frame { name: name.to_string(), had_children: false, text: String::new() });
        Ok(())
    }

    fn end_element(&mut self, name: &str, location: SaxLocation) -> Result<(), SaxError> {
        self.flush_text(location, true)?;
        self.frames.pop();
        let state = self.arena.end_tag(self.state);
        if state == NOT_ALLOWED {
            return Err(Self::fail(location, format!("element \"{name}\" is incomplete: required content is missing")));
        }
        self.state = state;
        Ok(())
    }

    fn characters(&mut self, text: &str) -> Result<(), SaxError> {
        if let Some(frame) = self.frames.last_mut() {
            frame.text.push_str(text);
        }
        Ok(())
    }

    fn processing_instruction(&mut self, _target: &str, _data: &str) -> Result<(), SaxError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoIncludes;
    impl SchemaResolver for NoIncludes {
        fn resolve(&self, _base: &str, _href: &str) -> Option<(String, Vec<u8>)> {
            None
        }
    }

    struct MapResolver(Vec<(&'static str, &'static str)>);
    impl SchemaResolver for MapResolver {
        fn resolve(&self, _base: &str, href: &str) -> Option<(String, Vec<u8>)> {
            self.0.iter().find(|(n, _)| *n == href).map(|(n, t)| (n.to_string(), t.as_bytes().to_vec()))
        }
    }

    fn schema(text: &str) -> RelaxNgSchema {
        RelaxNgSchema::compile("test.rng", text.as_bytes(), &NoIncludes).unwrap()
    }

    fn check(schema: &RelaxNgSchema, doc: &str) -> Result<(), String> {
        schema.validate(doc.as_bytes()).map_err(|e| e.to_string())
    }

    const RNG: &str = r#"xmlns="http://relaxng.org/ns/structure/1.0""#;

    #[test]
    fn elements_attributes_and_ordering() {
        let s = schema(&format!(
            r#"<grammar {RNG}><start><element name="a">
                 <attribute name="x"/>
                 <optional><attribute name="y"><choice><value>big</value><value>little</value></choice></attribute></optional>
                 <element name="b"><empty/></element>
                 <zeroOrMore><element name="c"><text/></element></zeroOrMore>
               </element></start></grammar>"#
        ));
        assert_eq!(check(&s, r#"<a x="1"><b/></a>"#), Ok(()));
        assert_eq!(check(&s, "<a x='1' y=' big '>\n  <b/>\n  <c>hi</c><c/>\n</a>"), Ok(()));
        // Missing required attribute / child, wrong order, bad value, unknown attribute, text.
        assert!(check(&s, "<a><b/></a>").unwrap_err().contains("missing a required attribute"));
        assert!(check(&s, r#"<a x="1"/>"#).unwrap_err().contains("element \"a\" is incomplete"));
        assert!(check(&s, r#"<a x="1"><c/><b/></a>"#).unwrap_err().contains("element \"c\" not allowed here in element \"a\""));
        assert!(check(&s, r#"<a x="1" y="middle"><b/></a>"#).unwrap_err().contains("attribute \"y\" with value \"middle\""));
        assert!(check(&s, r#"<a x="1" z="0"><b/></a>"#).unwrap_err().contains("attribute \"z\""));
        assert!(check(&s, r#"<a x="1">words<b/></a>"#).unwrap_err().contains("text not allowed in element \"a\""));
        assert!(check(&s, r#"<a x="1"><b>x</b></a>"#).unwrap_err().contains("text not allowed in element \"b\""));
        let err = check(&s, r#"<z/>"#).unwrap_err();
        assert!(err.starts_with("1:") && err.contains("element \"z\" not allowed here"), "{err}");
    }

    #[test]
    fn string_values_compare_exactly_and_tokens_normalize() {
        let s = schema(&format!(
            r#"<element name="a" {RNG}><attribute name="s"><value type="string">x y</value></attribute>
                 <attribute name="t"><value>x y</value></attribute></element>"#
        ));
        assert_eq!(check(&s, r#"<a s="x y" t="  x   y "/>"#), Ok(()));
        assert!(check(&s, r#"<a s="x  y" t="x y"/>"#).is_err());
    }

    #[test]
    fn interleave_accepts_any_order() {
        let s = schema(&format!(
            r#"<element name="r" {RNG}><interleave>
                 <optional><element name="a"><empty/></element></optional>
                 <zeroOrMore><element name="b"><empty/></element></zeroOrMore>
                 <element name="c"><empty/></element>
               </interleave></element>"#
        ));
        for ok in ["<r><c/></r>", "<r><b/><c/><a/><b/></r>", "<r><a/><b/><b/><c/></r>"] {
            assert_eq!(check(&s, ok), Ok(()), "{ok}");
        }
        assert!(check(&s, "<r><a/><c/><a/></r>").is_err());
        assert!(check(&s, "<r><a/><b/></r>").is_err());
    }

    #[test]
    fn definitions_recursion_and_includes() {
        let common = format!(r#"<grammar {RNG}><define name="leaf"><element name="leaf"><attribute name="v"/></element></define></grammar>"#);
        let common: &'static str = Box::leak(common.into_boxed_str());
        let main = format!(
            r#"<grammar {RNG}><include href="common.rng"/>
                 <start><ref name="node"/></start>
                 <define name="node"><element name="node"><zeroOrMore><choice><ref name="node"/><ref name="leaf"/></choice></zeroOrMore></element></define>
               </grammar>"#
        );
        let s = RelaxNgSchema::compile("main.rng", main.as_bytes(), &MapResolver(vec![("common.rng", common)])).unwrap();
        assert_eq!(s.validate(br#"<node><node><leaf v="1"/></node><leaf v="2"/></node>"#), Ok(()));
        assert!(s.validate(br#"<node><leaf/></node>"#).is_err());
    }

    #[test]
    fn unsupported_and_broken_schemas_are_rejected() {
        let err = |text: String| RelaxNgSchema::compile("t.rng", text.as_bytes(), &NoIncludes).unwrap_err().message;
        assert!(err(format!(r#"<element name="a" {RNG}><data type="int"/></element>"#)).contains("unsupported RELAX NG pattern <data>"));
        assert!(err(format!(r#"<element {RNG}><anyName/></element>"#)).contains("missing its name attribute"));
        assert!(err(format!(r#"<grammar {RNG}><start><ref name="nope"/></start></grammar>"#)).contains("undefined pattern nope"));
        assert!(err(format!(r#"<grammar {RNG}><define name="d"><ref name="d"/></define><start><ref name="d"/></start></grammar>"#))
            .contains("recursive reference to d"));
        assert!(err(format!(r#"<grammar {RNG}><include href="x.rng"/></grammar>"#)).contains("cannot resolve included schema x.rng"));
        assert!(err(format!(r#"<grammar {RNG}><define name="d"><empty/></define></grammar>"#)).contains("no <start>"));
    }
}
