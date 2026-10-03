//! A single Swift demangled symbol tree node.
//!
//! Port of `ghidra.app.util.demangler.swift.nodes.SwiftNode`.

use std::cell::{Cell, Ref, RefCell};
use std::rc::{Rc, Weak};

use crate::demangler::demangle_exception::DemangledException;
use crate::demangler::demangled::Demangled;
use crate::demangler::seam_stubs::DemangledUnknown;
use crate::demangler::swift::swift_demangler::SwiftDemangler;
use crate::demangler::swift::swift_demangled_node_kind::SwiftDemangledNodeKind;

/// The properties of a [`SwiftNode`].
///
/// Mirrors the `SwiftNode.NodeProperties` record. Records are immutable value carriers, so the
/// fields are public rather than hidden behind the record's accessor methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeProperties {
    /// The kind of [`SwiftNode`].
    pub kind: SwiftDemangledNodeKind,

    /// The "text" attribute, or `None` if it does not exist.
    pub text: Option<String>,

    /// The "index" attribute, or `None` if it does not exist.
    pub index: Option<String>,

    /// The depth of the [`SwiftNode`] in the demangled symbol tree (root depth is 0).
    pub depth: usize,

    /// The mangled string associated with this [`SwiftNode`].
    pub mangled: String,

    /// The natively demangled string.
    pub original_demangled: String,

    /// Whether the mangled string is from a 64-bit program.
    pub is_64bit: bool,
}

impl NodeProperties {
    /// Mirrors the canonical `NodeProperties(...)` record constructor.
    pub fn new(
        kind: SwiftDemangledNodeKind,
        text: Option<String>,
        index: Option<String>,
        depth: usize,
        mangled: impl Into<String>,
        original_demangled: impl Into<String>,
        is_64bit: bool,
    ) -> Self {
        Self {
            kind,
            text,
            index,
            depth,
            mangled: mangled.into(),
            original_demangled: original_demangled.into(),
            is_64bit,
        }
    }
}

/// A single Swift demangled symbol tree node.
///
/// Port of the abstract class `ghidra.app.util.demangler.swift.nodes.SwiftNode`, split in two:
/// this trait carries the one abstract operation (`demangle`), while the shared state and the
/// concrete methods live in [`SwiftNodeBase`], which every implementor owns and exposes through
/// [`SwiftNode::base`].
///
/// Nodes are shared (a child is reachable both from its parent's child list and from the parent
/// pointer of its own children) and are mutated after construction while already shared, so the
/// tree is wired with `Rc`/`Weak` and interior mutability rather than plain ownership.
pub trait SwiftNode {
    /// Returns the shared node state.
    ///
    /// Stands in for the field access an abstract Java superclass provides directly; Rust has no
    /// struct inheritance.
    fn base(&self) -> &SwiftNodeBase;

    /// Demangles this node.
    ///
    /// Mirrors the abstract `demangle(SwiftDemangler)`. `None` mirrors the original's `null`
    /// return, which several subclasses use for nodes that contribute nothing.
    fn demangle(
        &self,
        demangler: &SwiftDemangler,
    ) -> Result<Option<Box<dyn Demangled>>, DemangledException>;
}

/// The state and concrete behaviour shared by every [`SwiftNode`].
///
/// Holds what the Java abstract class `SwiftNode` declares as fields, plus the methods that
/// operate purely on those fields.
pub struct SwiftNodeBase {
    /// Mirrors the `protected NodeProperties properties` field. Assigned once by the factory in
    /// Java and never reassigned, so it is a plain owned value here.
    pub properties: NodeProperties,

    /// Mirrors the `private SwiftNode parent` field. A back-edge into an already-shared tree,
    /// hence `Weak`; `RefCell` because `setParent` is called on a node that is already inside an
    /// `Rc`.
    parent: RefCell<Weak<dyn SwiftNode>>,

    /// Mirrors the `private List<SwiftNode> children` field. Java hands out the live list from
    /// `getChildren()` for callers to append to, so it needs interior mutability here.
    children: RefCell<Vec<Rc<dyn SwiftNode>>>,

    /// Mirrors the `private boolean childSkipped` field. `skip` is called through a shared
    /// reference during demangling, hence `Cell`.
    child_skipped: Cell<bool>,
}

impl SwiftNodeBase {
    /// Creates the shared state for a node with the given properties.
    ///
    /// Mirrors the implicit no-arg superclass constructor plus the `node.properties = props`
    /// assignment the `SwiftNode.get(NodeProperties)` factory performs.
    pub fn new(properties: NodeProperties) -> Self {
        Self {
            properties,
            parent: RefCell::new(Weak::<SwiftNodeBaseNever>::new()),
            children: RefCell::new(Vec::new()),
            child_skipped: Cell::new(false),
        }
    }

    /// Gets the kind of node.
    ///
    /// Mirrors `getKind()`.
    pub fn kind(&self) -> SwiftDemangledNodeKind {
        self.properties.kind
    }

    /// Gets the "text" property, or `None` if it does not exist.
    ///
    /// Mirrors `getText()`.
    pub fn text(&self) -> Option<&str> {
        self.properties.text.as_deref()
    }

    /// Gets the "index" property, or `None` if it does not exist.
    ///
    /// Mirrors `getIndex()`.
    pub fn index(&self) -> Option<&str> {
        self.properties.index.as_deref()
    }

    /// Gets the depth of the node in the demangled symbol tree (root depth is 0).
    ///
    /// Mirrors `getDepth()`.
    pub fn depth(&self) -> usize {
        self.properties.depth
    }

    /// Gets the parent node, or `None` if this is the root node.
    ///
    /// Mirrors `getParent()`.
    pub fn parent(&self) -> Option<Rc<dyn SwiftNode>> {
        self.parent.borrow().upgrade()
    }

    /// Sets the parent node.
    ///
    /// Mirrors `setParent(SwiftNode)`.
    pub fn set_parent(&self, parent: &Rc<dyn SwiftNode>) {
        *self.parent.borrow_mut() = Rc::downgrade(parent);
    }

    /// Gets the child nodes.
    ///
    /// Mirrors `getChildren()`, which returns the original list rather than a copy; append with
    /// [`SwiftNodeBase::add_child`].
    pub fn children(&self) -> Ref<'_, Vec<Rc<dyn SwiftNode>>> {
        self.children.borrow()
    }

    /// Appends a child node.
    ///
    /// Mirrors `getChildren().add(child)`, the only mutation callers perform on the list the
    /// original's `getChildren()` hands out.
    pub fn add_child(&self, child: Rc<dyn SwiftNode>) {
        self.children.borrow_mut().push(child);
    }

    /// Checks whether the node has any direct children of the given kind.
    ///
    /// Mirrors `hasChild(SwiftDemangledNodeKind)`.
    pub fn has_child(&self, child_kind: SwiftDemangledNodeKind) -> bool {
        self.children.borrow().iter().any(|child| child.base().kind() == child_kind)
    }

    /// Gets the first direct child node of the given kind, or `None` if there is none.
    ///
    /// Mirrors `getChild(SwiftDemangledNodeKind)`.
    pub fn child(&self, child_kind: SwiftDemangledNodeKind) -> Option<Rc<dyn SwiftNode>> {
        self.children
            .borrow()
            .iter()
            .find(|child| child.base().kind() == child_kind)
            .map(Rc::clone)
    }

    /// Gets the first ancestor node of any of the given kinds.
    ///
    /// Mirrors `getFirstAncestor(SwiftDemangledNodeKind...)`; an empty slice mirrors the
    /// original's `null`/empty varargs guard and yields `None`.
    pub fn first_ancestor(
        &self,
        ancestor_kinds: &[SwiftDemangledNodeKind],
    ) -> Option<Rc<dyn SwiftNode>> {
        if ancestor_kinds.is_empty() {
            return None;
        }
        let mut current = self.parent();
        while let Some(node) = current {
            if ancestor_kinds.contains(&node.base().kind()) {
                return Some(node);
            }
            current = node.base().parent();
        }
        None
    }

    /// Records that this node skipped processing a child during demangling. Used to identify
    /// and/or debug missing implementations.
    ///
    /// Mirrors `skip(SwiftNode)`, which likewise ignores the child it is handed.
    pub fn skip(&self, _child: &dyn SwiftNode) {
        self.child_skipped.set(true);
    }

    /// Returns whether this node skipped processing any children during demangling.
    ///
    /// Mirrors `childWasSkipped()`.
    pub fn child_was_skipped(&self) -> bool {
        self.child_skipped.get()
    }

    /// Gets a new `DemangledUnknown` created from this node.
    ///
    /// Mirrors `getUnknown()`.
    pub fn unknown(&self) -> DemangledUnknown {
        DemangledUnknown::new(
            self.properties.mangled.clone(),
            Some(self.properties.original_demangled.clone()),
            Some(&self.properties.original_demangled),
        )
    }

    /// Demangles the first child node, skipping the rest.
    ///
    /// Mirrors the protected `demangleFirstChild(SwiftDemangler)`, including its quirk of
    /// marking each skipped child as having skipped a child (`child.skip(child)`) rather than
    /// marking this node.
    ///
    /// # Errors
    /// Returns a `DemangledException` if there are no children, if the first child demangled to
    /// nothing, or if demangling the first child failed.
    pub fn demangle_first_child(
        &self,
        demangler: &SwiftDemangler,
    ) -> Result<Box<dyn Demangled>, DemangledException> {
        let children: Vec<Rc<dyn SwiftNode>> = self.children.borrow().clone();
        let mut first = None;
        for (i, child) in children.iter().enumerate() {
            if i == 0 {
                first = child.demangle(demangler)?;
            } else {
                child.base().skip(&**child);
            }
        }
        first.ok_or_else(|| DemangledException::from_message("No children"))
    }
}

impl std::fmt::Display for SwiftNodeBase {
    /// Mirrors `toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", " ".repeat(self.properties.depth * 2))?;
        write!(f, "kind={}", self.properties.kind)?;
        if let Some(text) = &self.properties.text {
            write!(f, ", text=\"{text}\"")?;
        }
        if let Some(index) = &self.properties.index {
            write!(f, ", index={index}")?;
        }
        Ok(())
    }
}

/// Walks down the tree rooted at `node`, returning true if `predicate` holds for any node
/// encountered.
///
/// Mirrors `walkAndTest(Predicate<SwiftNode>)`. A free function rather than a method because the
/// predicate is applied to the node itself, which an object-safe default method cannot hand out
/// as a `&dyn SwiftNode`.
pub fn walk_and_test(node: &dyn SwiftNode, predicate: &mut dyn FnMut(&dyn SwiftNode) -> bool) -> bool {
    if predicate(node) {
        return true;
    }
    let children = node.base().children();
    children.iter().any(|child| walk_and_test(&**child, predicate))
}

/// Joins the first demangled object with the second: the name of the first becomes the top-level
/// namespace of the second.
///
/// Mirrors the static `join(Demangled, Demangled)`.
pub fn join(
    a: Option<Box<dyn Demangled>>,
    b: Option<Box<dyn Demangled>>,
) -> Option<Box<dyn Demangled>> {
    let (a, mut b) = match (a, b) {
        (None, b) => return b,
        (a, None) => return a,
        (Some(a), Some(b)) => (a, b),
    };

    set_top_namespace(b.as_mut(), a);
    Some(b)
}

/// Walks `node`'s namespace chain to its top and sets `namespace` there.
///
/// Mirrors the `while (topNamespace.getNamespace() != null)` loop in `join`, written as recursion
/// since the chain is walked through `&mut` borrows.
fn set_top_namespace(node: &mut (dyn Demangled + 'static), namespace: Box<dyn Demangled>) {
    if node.get_namespace().is_some() {
        let parent = node.get_namespace_mut().expect("namespace present");
        set_top_namespace(parent, namespace);
    } else {
        node.set_namespace(Some(namespace));
    }
}

/// Converts `node` to a string, optionally recursing into its children.
///
/// Mirrors the static `toString(SwiftNode, boolean)`.
pub fn to_string(node: &dyn SwiftNode, recurse: bool) -> String {
    let mut buffer = node.base().to_string();
    if recurse {
        buffer.push('\n');
        let children = node.base().children();
        for child in children.iter() {
            buffer.push_str(&to_string(&**child, true));
        }
    }
    buffer
}

/// Uninhabited stand-in used only to spell a null `Weak<dyn SwiftNode>`.
///
/// `Weak::new()` needs a sized type to coerce from; this one can never be constructed, so the
/// resulting weak reference is permanently dangling, exactly like the Java `null` parent it
/// stands for.
enum SwiftNodeBaseNever {}

impl SwiftNode for SwiftNodeBaseNever {
    fn base(&self) -> &SwiftNodeBase {
        match *self {}
    }

    fn demangle(
        &self,
        _demangler: &SwiftDemangler,
    ) -> Result<Option<Box<dyn Demangled>>, DemangledException> {
        match *self {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in for one of the 43 not-yet-ported concrete node types: it demangles to its
    /// first child if it has one, and to `getUnknown()` otherwise.
    struct TestNode {
        base: SwiftNodeBase,
    }

    impl TestNode {
        fn new(
            kind: SwiftDemangledNodeKind,
            text: Option<&str>,
            index: Option<&str>,
            depth: usize,
        ) -> Rc<dyn SwiftNode> {
            Rc::new(Self {
                base: SwiftNodeBase::new(NodeProperties::new(
                    kind,
                    text.map(str::to_string),
                    index.map(str::to_string),
                    depth,
                    "$s4main3FooV",
                    "main.Foo",
                    true,
                )),
            })
        }
    }

    impl SwiftNode for TestNode {
        fn base(&self) -> &SwiftNodeBase {
            &self.base
        }

        fn demangle(
            &self,
            demangler: &SwiftDemangler,
        ) -> Result<Option<Box<dyn Demangled>>, DemangledException> {
            if self.base.children().is_empty() {
                return Ok(Some(Box::new(self.base.unknown())));
            }
            self.base.demangle_first_child(demangler).map(Some)
        }
    }

    fn link(parent: &Rc<dyn SwiftNode>, child: Rc<dyn SwiftNode>) {
        child.base().set_parent(parent);
        parent.base().add_child(child);
    }

    /// `$s4main3FooV` demangles to a tree shaped like
    /// `Global -> Type -> Structure -> (Module "main", Identifier "Foo")`.
    fn sample_tree() -> Rc<dyn SwiftNode> {
        let global = TestNode::new(SwiftDemangledNodeKind::Global, None, None, 0);
        let ty = TestNode::new(SwiftDemangledNodeKind::Type, None, None, 1);
        let structure = TestNode::new(SwiftDemangledNodeKind::Structure, None, None, 2);
        let module = TestNode::new(SwiftDemangledNodeKind::Module, Some("main"), None, 3);
        let identifier = TestNode::new(SwiftDemangledNodeKind::Identifier, Some("Foo"), None, 3);

        link(&structure, module);
        link(&structure, identifier);
        link(&ty, structure);
        link(&global, ty);
        global
    }

    #[test]
    fn to_string_indents_by_depth_and_appends_present_attributes() {
        let node = TestNode::new(SwiftDemangledNodeKind::Identifier, Some("Foo"), None, 2);
        assert_eq!(node.base().to_string(), "    kind=Identifier, text=\"Foo\"");

        let numbered = TestNode::new(SwiftDemangledNodeKind::Number, None, Some("7"), 0);
        assert_eq!(numbered.base().to_string(), "kind=Number, index=7");
    }

    #[test]
    fn to_string_recurses_depth_first() {
        let global = sample_tree();
        assert_eq!(
            to_string(&*global, true),
            concat!(
                "kind=Global\n",
                "  kind=Type\n",
                "    kind=Structure\n",
                "      kind=Module, text=\"main\"\n",
                "      kind=Identifier, text=\"Foo\"\n",
            )
        );
        assert_eq!(to_string(&*global, false), "kind=Global");
    }

    #[test]
    fn child_lookup_matches_on_kind() {
        let global = sample_tree();
        let ty = global.base().child(SwiftDemangledNodeKind::Type).expect("Type child");
        let structure = ty.base().child(SwiftDemangledNodeKind::Structure).expect("Structure child");

        assert!(structure.base().has_child(SwiftDemangledNodeKind::Identifier));
        assert!(!structure.base().has_child(SwiftDemangledNodeKind::Class));
        assert_eq!(
            structure.base().child(SwiftDemangledNodeKind::Identifier).unwrap().base().text(),
            Some("Foo")
        );
        assert!(structure.base().child(SwiftDemangledNodeKind::Class).is_none());
    }

    #[test]
    fn first_ancestor_walks_up_and_stops_at_the_nearest_match() {
        let global = sample_tree();
        let identifier = global
            .base()
            .child(SwiftDemangledNodeKind::Type)
            .and_then(|ty| ty.base().child(SwiftDemangledNodeKind::Structure))
            .and_then(|s| s.base().child(SwiftDemangledNodeKind::Identifier))
            .expect("Identifier");

        let nearest = identifier
            .base()
            .first_ancestor(&[SwiftDemangledNodeKind::Global, SwiftDemangledNodeKind::Structure])
            .expect("ancestor");
        assert_eq!(nearest.base().kind(), SwiftDemangledNodeKind::Structure);

        assert_eq!(
            identifier
                .base()
                .first_ancestor(&[SwiftDemangledNodeKind::Global])
                .unwrap()
                .base()
                .kind(),
            SwiftDemangledNodeKind::Global
        );
        assert!(identifier.base().first_ancestor(&[SwiftDemangledNodeKind::Class]).is_none());
        assert!(identifier.base().first_ancestor(&[]).is_none());
        assert!(global.base().first_ancestor(&[SwiftDemangledNodeKind::Global]).is_none());
    }

    #[test]
    fn walk_and_test_finds_a_deep_descendant_and_reports_absence() {
        let global = sample_tree();
        assert!(walk_and_test(&*global, &mut |node| node.base().text() == Some("Foo")));
        assert!(walk_and_test(&*global, &mut |node| node.base().kind()
            == SwiftDemangledNodeKind::Global));
        assert!(!walk_and_test(&*global, &mut |node| node.base().kind()
            == SwiftDemangledNodeKind::Protocol));
    }

    #[test]
    fn demangle_first_child_uses_the_first_and_marks_the_rest_skipped() {
        let global = sample_tree();
        let structure = global
            .base()
            .child(SwiftDemangledNodeKind::Type)
            .and_then(|ty| ty.base().child(SwiftDemangledNodeKind::Structure))
            .expect("Structure");
        let module = structure.base().child(SwiftDemangledNodeKind::Module).unwrap();
        let identifier = structure.base().child(SwiftDemangledNodeKind::Identifier).unwrap();

        let demangled = structure
            .base()
            .demangle_first_child(&SwiftDemangler::new())
            .expect("first child demangles");

        // The `Module` child is first, so it -- not `Identifier` -- produced the result.
        assert_eq!(demangled.get_original_demangled(), "main.Foo");
        assert!(!module.base().child_was_skipped());
        assert!(identifier.base().child_was_skipped());
    }

    #[test]
    fn demangle_first_child_fails_without_children() {
        let leaf = TestNode::new(SwiftDemangledNodeKind::Identifier, Some("Foo"), None, 0);
        let error = match leaf.base().demangle_first_child(&SwiftDemangler::new()) {
            Ok(_) => panic!("expected a `No children` failure"),
            Err(error) => error,
        };
        assert_eq!(error.to_string(), "No children");
    }

    #[test]
    fn unknown_carries_the_original_demangled_string() {
        let node = TestNode::new(SwiftDemangledNodeKind::Unsupported, None, None, 0);
        let unknown = node.base().unknown();

        assert_eq!(unknown.get_mangled_string(), "$s4main3FooV");
        assert_eq!(unknown.get_original_demangled(), "main.Foo");
        assert_eq!(unknown.get_signature_formatted(true), "main.Foo");
        assert_eq!(unknown.get_name(), "main.Foo");
    }

    #[test]
    fn join_makes_the_first_the_top_level_namespace_of_the_second() {
        use crate::demangler::demangled_type::DemangledType;

        let a = DemangledType::new("$sA", "A", "A");
        let mut inner = DemangledType::new("$sB", "B", "B");
        inner.set_namespace(Some(Box::new(DemangledType::new("$sC", "C", "C"))));

        let joined = join(Some(Box::new(a)), Some(Box::new(inner))).expect("joined");

        // `b` is returned, and `a` is spliced in beneath `b`'s deepest namespace (`C`).
        assert_eq!(joined.get_name(), "B");
        assert_eq!(joined.get_namespace_string(), "A::C::B");
    }

    #[test]
    fn join_passes_through_when_either_side_is_absent() {
        use crate::demangler::demangled_type::DemangledType;

        let only_b = join(None, Some(Box::new(DemangledType::new("$sB", "B", "B"))));
        assert_eq!(only_b.expect("b").get_name(), "B");

        let only_a = join(Some(Box::new(DemangledType::new("$sA", "A", "A"))), None);
        assert_eq!(only_a.expect("a").get_name(), "A");

        assert!(join(None, None).is_none());
    }
}
