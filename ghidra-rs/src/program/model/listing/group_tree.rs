//! Arena + typed-ID replacement for the `Group`/`ProgramModule`/`ProgramFragment` object graph.
//!
//! Ghidra's Program Tree is a genuine multi-parent DAG: a `ProgramModule` groups
//! `ProgramFragment`s and other `ProgramModule`s, and a fragment or module "may be contained in
//! more than one module" (see `ProgramModule`'s Java class doc). Translated as
//! `Box<dyn Group>`, every parent link recursively boxes/clones the whole ancestor chain just to
//! hand one back -- see `Group::get_parents` and its `collect_ancestor_names` helper in
//! `group.rs`, which allocate on every traversal, and would reach for `Rc<RefCell<dyn Group>>`
//! the moment a real (non-mock) implementation needed to mutate shared nodes. This module is the
//! `OWNERSHIP_MIGRATION.md` Phase 1 pilot: one arena (`GroupTree`) owns every node; everything
//! else holds a small `Copy` `GroupId` and looks up behavior through the arena, per the
//! "arena + typed ID for shared/graph types" convention, with `GroupKind` as the enum-dispatch
//! answer for the closed module-vs-fragment hierarchy.
//!
//! Scope: this ports `Group`'s full interface and a representative subset of
//! `ProgramModule`/`ProgramFragment` sufficient to validate the pattern against a real
//! multi-parent graph. It intentionally does NOT port child reordering (`moveChild`),
//! reparenting, `getVersionTag`/`getModificationNumber`/tree-ID bookkeeping, the
//! last-fragment-can't-be-removed invariant, or `ProgramFragment`'s `CodeUnit`-level operations
//! (`getCodeUnits`, `moveCodeUnits`) -- those need `Listing`/`CodeUnit` wiring, which is Phase 2
//! scope (migrating `Listing` itself), not this pilot. The existing `Group`/`ProgramModule`/
//! `ProgramFragment` traits in sibling files are unchanged and unaffected by this file; it is an
//! additive, independent implementation, not a replacement. Wiring `Listing` to hand out
//! `GroupId`s instead of `Arc<dyn ProgramFragment>`/`Arc<dyn ProgramModule>` is tracked as Phase
//! 2 follow-up work, not done here.

use slotmap::{new_key_type, SlotMap};
use thiserror::Error;

use crate::program::model::address::{Address, AddressSet, AddressSetView};
use crate::program::model::listing::circular_dependency_exception::CircularDependencyException;
use crate::program::model::listing::duplicate_group_exception::DuplicateGroupException;
use crate::program::seam_stubs::GroupPath;
use crate::util::exception::DuplicateNameException;

new_key_type! {
    /// A `Copy` handle to one node (module or fragment) in a [`GroupTree`]. Cheap to pass around
    /// and store as a parent/child link -- the arena is the only owner of the real data. Only
    /// meaningful against the `GroupTree` that minted it.
    pub struct GroupId;
}

/// The two closed Java kinds `Group` has: a folder-like grouping (`ProgramModule`) or a leaf set
/// of addresses (`ProgramFragment`). A fixed, known set of implementers in the real Ghidra source
/// -- exactly the case `OWNERSHIP_MIGRATION.md` calls out for enum dispatch instead of
/// `Box<dyn Group>`.
enum GroupKind {
    Module { children: Vec<GroupId> },
    Fragment { addresses: AddressSet },
}

struct GroupNode {
    name: String,
    comment: Option<String>,
    parents: Vec<GroupId>,
    deleted: bool,
    kind: GroupKind,
}

/// Owns every module/fragment node for one program tree. Mirrors what a `Program`'s internal
/// tree manager would hold.
pub struct GroupTree {
    tree_name: String,
    nodes: SlotMap<GroupId, GroupNode>,
    root: GroupId,
}

/// Errors from the child-mutating `GroupId` methods below. Consolidates what Java spreads across
/// `CircularDependencyException`/`DuplicateGroupException`/`DuplicateNameException` plus an
/// IllegalArgumentException-shaped "that's a fragment, not a module" case.
#[derive(Debug, PartialEq, Error)]
pub enum GroupTreeError {
    #[error(transparent)]
    Circular(#[from] CircularDependencyException),
    #[error(transparent)]
    AlreadyChild(#[from] DuplicateGroupException),
    #[error(transparent)]
    DuplicateName(#[from] DuplicateNameException),
    #[error("'{0}' is a fragment and cannot contain children")]
    NotAModule(String),
}

impl GroupTree {
    /// Creates a new tree with a single root module named `root_name`.
    pub fn new(tree_name: impl Into<String>, root_name: impl Into<String>) -> Self {
        let mut nodes = SlotMap::with_key();
        let root = nodes.insert(GroupNode {
            name: root_name.into(),
            comment: None,
            parents: Vec::new(),
            deleted: false,
            kind: GroupKind::Module { children: Vec::new() },
        });
        Self { tree_name: tree_name.into(), nodes, root }
    }

    /// The root module of this tree.
    pub fn root(&self) -> GroupId {
        self.root
    }

    fn node(&self, id: GroupId) -> &GroupNode {
        &self.nodes[id]
    }

    fn node_mut(&mut self, id: GroupId) -> &mut GroupNode {
        &mut self.nodes[id]
    }

    /// Names are unique across the whole tree (fragments and modules share one namespace), per
    /// `Group`'s class doc.
    fn name_in_use(&self, name: &str) -> bool {
        self.nodes.values().any(|n| n.name == name)
    }
}

fn collect_fragment_addresses<'a>(id: GroupId, tree: &'a GroupTree, out: &mut Vec<&'a AddressSet>) {
    match &tree.node(id).kind {
        GroupKind::Fragment { addresses } => out.push(addresses),
        GroupKind::Module { children } => {
            for &child in children {
                collect_fragment_addresses(child, tree, out);
            }
        }
    }
}

impl GroupId {
    // --- Group (both kinds) ---

    /// Port of `Group.getName`.
    pub fn name<'a>(self, tree: &'a GroupTree) -> &'a str {
        &tree.node(self).name
    }

    /// Port of `Group.setName`. Errors if another node in the tree already has this name.
    pub fn set_name(self, tree: &mut GroupTree, name: &str) -> Result<(), DuplicateNameException> {
        if tree.node(self).name != name && tree.name_in_use(name) {
            return Err(DuplicateNameException::with_message(format!(
                "A module or fragment named '{name}' already exists."
            )));
        }
        tree.node_mut(self).name = name.to_string();
        Ok(())
    }

    /// Port of `Group.getComment`.
    pub fn comment<'a>(self, tree: &'a GroupTree) -> Option<&'a str> {
        tree.node(self).comment.as_deref()
    }

    /// Port of `Group.setComment`.
    pub fn set_comment(self, tree: &mut GroupTree, comment: Option<&str>) {
        tree.node_mut(self).comment = comment.map(str::to_string);
    }

    /// Port of `Group.getParents`. Cheap: this is exactly the case that recursively cloned
    /// `Box<dyn Group>` subtrees under the old trait-object design -- here it's copying `GroupId`s.
    pub fn parents(self, tree: &GroupTree) -> &[GroupId] {
        &tree.node(self).parents
    }

    /// Port of `Group.getParentNames`.
    pub fn parent_names(self, tree: &GroupTree) -> Vec<String> {
        self.parents(tree).iter().map(|p| p.name(tree).to_string()).collect()
    }

    /// Port of `Group.getNumParents`.
    pub fn num_parents(self, tree: &GroupTree) -> usize {
        tree.node(self).parents.len()
    }

    /// Port of `Group.getTreeName`.
    pub fn tree_name(self, tree: &GroupTree) -> &str {
        &tree.tree_name
    }

    /// Port of `Group.isDeleted`: true once a non-root node has no parents left.
    pub fn is_deleted(self, tree: &GroupTree) -> bool {
        tree.node(self).deleted
    }

    /// True if this node is a `ProgramModule` per the enum-dispatch `GroupKind`.
    pub fn is_module(self, tree: &GroupTree) -> bool {
        matches!(tree.node(self).kind, GroupKind::Module { .. })
    }

    /// True if this node is a `ProgramFragment` per the enum-dispatch `GroupKind`.
    pub fn is_fragment(self, tree: &GroupTree) -> bool {
        matches!(tree.node(self).kind, GroupKind::Fragment { .. })
    }

    /// Port of `Group.getGroupPath` / its private `getParentNames` walk: arbitrarily follows the
    /// first parent at each level (fragments/modules can have multiple parents; this returns one
    /// valid path), oldest ancestor first.
    pub fn group_path(self, tree: &GroupTree) -> GroupPath {
        let mut chain = vec![self];
        let mut current = self;
        while let Some(parent) = tree.node(current).parents.first().copied() {
            chain.push(parent);
            current = parent;
        }
        let names = chain.into_iter().rev().map(|id| id.name(tree).to_string()).collect();
        GroupPath::new(names)
    }

    /// Port of `Group.getMinAddress` (and `ProgramModule.getMinAddress`, which is defined the
    /// same way): the fragment's own minimum, or the minimum across all descendant fragments for
    /// a module.
    pub fn min_address(self, tree: &GroupTree) -> Option<Address> {
        let mut addrs = Vec::new();
        collect_fragment_addresses(self, tree, &mut addrs);
        addrs.into_iter().filter_map(|a| a.min_address()).min()
    }

    /// Port of `Group.getMaxAddress` / `ProgramModule.getMaxAddress`.
    pub fn max_address(self, tree: &GroupTree) -> Option<Address> {
        let mut addrs = Vec::new();
        collect_fragment_addresses(self, tree, &mut addrs);
        addrs.into_iter().filter_map(|a| a.max_address()).max()
    }

    /// Adapts `Group.contains(CodeUnit)` to address-level containment (does `address` fall
    /// within this node's own addresses, or any descendant fragment's, for a module). Full
    /// `CodeUnit` containment needs `Listing` wiring -- Phase 2 scope, not this pilot.
    pub fn contains(self, tree: &GroupTree, address: &Address) -> bool {
        let mut addrs = Vec::new();
        collect_fragment_addresses(self, tree, &mut addrs);
        addrs.into_iter().any(|a| a.contains(address))
    }

    // --- ProgramModule-only ---

    /// Port of `ProgramModule.getChildren`. Empty for a fragment.
    pub fn children(self, tree: &GroupTree) -> &[GroupId] {
        match &tree.node(self).kind {
            GroupKind::Module { children } => children,
            GroupKind::Fragment { .. } => &[],
        }
    }

    /// Port of `ProgramModule.getNumChildren`.
    pub fn num_children(self, tree: &GroupTree) -> usize {
        self.children(tree).len()
    }

    /// Port of `ProgramModule.getIndex`.
    pub fn index_of(self, tree: &GroupTree, name: &str) -> Option<usize> {
        self.children(tree).iter().position(|c| c.name(tree) == name)
    }

    /// Port of `ProgramModule.contains(ProgramModule)`.
    pub fn contains_module(self, tree: &GroupTree, other: GroupId) -> bool {
        other == self || self.is_descendant(tree, other)
    }

    /// Port of `ProgramModule.contains(ProgramFragment)`: true only for a *direct* child.
    pub fn contains_fragment(self, tree: &GroupTree, other: GroupId) -> bool {
        self.children(tree).contains(&other)
    }

    /// Port of `ProgramModule.isDescendant` (both overloads collapse to one, since `GroupId`
    /// doesn't distinguish module/fragment at the type level).
    pub fn is_descendant(self, tree: &GroupTree, other: GroupId) -> bool {
        self.children(tree).iter().any(|&c| c == other || c.is_descendant(tree, other))
    }

    /// Adds an existing node as a child of this module -- the arena/ID equivalent of Java's
    /// `add(ProgramModule)`/`add(ProgramFragment)`, which reparent an existing object rather than
    /// constructing a copy. Rejects a cycle (making an ancestor a child) or a duplicate (already
    /// a direct child), matching `ProgramModule.add`'s checked exceptions.
    pub fn add_child(self, tree: &mut GroupTree, child: GroupId) -> Result<(), GroupTreeError> {
        if !self.is_module(tree) {
            return Err(GroupTreeError::NotAModule(self.name(tree).to_string()));
        }
        if child == self || child.is_descendant(tree, self) {
            return Err(CircularDependencyException::default().into());
        }
        if self.children(tree).contains(&child) {
            return Err(DuplicateGroupException::default().into());
        }
        if let GroupKind::Module { children } = &mut tree.node_mut(self).kind {
            children.push(child);
        }
        tree.node_mut(child).parents.push(self);
        Ok(())
    }

    /// Port of `ProgramModule.createModule`.
    pub fn create_module(self, tree: &mut GroupTree, name: &str) -> Result<GroupId, GroupTreeError> {
        if !self.is_module(tree) {
            return Err(GroupTreeError::NotAModule(self.name(tree).to_string()));
        }
        if tree.name_in_use(name) {
            return Err(DuplicateNameException::with_message(format!(
                "A module or fragment named '{name}' already exists."
            ))
            .into());
        }
        let id = tree.nodes.insert(GroupNode {
            name: name.to_string(),
            comment: None,
            parents: vec![self],
            deleted: false,
            kind: GroupKind::Module { children: Vec::new() },
        });
        if let GroupKind::Module { children } = &mut tree.node_mut(self).kind {
            children.push(id);
        }
        Ok(id)
    }

    /// Port of `ProgramModule.createFragment`.
    pub fn create_fragment(self, tree: &mut GroupTree, name: &str) -> Result<GroupId, GroupTreeError> {
        if !self.is_module(tree) {
            return Err(GroupTreeError::NotAModule(self.name(tree).to_string()));
        }
        if tree.name_in_use(name) {
            return Err(DuplicateNameException::with_message(format!(
                "A module or fragment named '{name}' already exists."
            ))
            .into());
        }
        let id = tree.nodes.insert(GroupNode {
            name: name.to_string(),
            comment: None,
            parents: vec![self],
            deleted: false,
            kind: GroupKind::Fragment { addresses: AddressSet::new() },
        });
        if let GroupKind::Module { children } = &mut tree.node_mut(self).kind {
            children.push(id);
        }
        Ok(id)
    }

    /// Port of `ProgramModule.removeChild`: removes a direct child by name, unlinking this
    /// module as one of its parents. Marks the child deleted once it has no parents left. Unlike
    /// Java, does not enforce "the tree's last fragment can't be removed" -- out of pilot scope.
    pub fn remove_child(self, tree: &mut GroupTree, name: &str) -> bool {
        let Some(idx) = self.index_of(tree, name) else { return false };
        let child = self.children(tree)[idx];
        if let GroupKind::Module { children } = &mut tree.node_mut(self).kind {
            children.remove(idx);
        }
        tree.node_mut(child).parents.retain(|&p| p != self);
        if child.num_parents(tree) == 0 {
            tree.node_mut(child).deleted = true;
        }
        true
    }

    // --- ProgramFragment-only ---

    /// The fragment's address set (`None` for a module). Port of the state backing
    /// `ProgramFragment`'s `AddressSetView` supertrait methods.
    pub fn address_set<'a>(self, tree: &'a GroupTree) -> Option<&'a AddressSet> {
        match &tree.node(self).kind {
            GroupKind::Fragment { addresses } => Some(addresses),
            GroupKind::Module { .. } => None,
        }
    }

    /// Adds an address range to this fragment. Errors if called on a module.
    pub fn add_address_range(
        self,
        tree: &mut GroupTree,
        start: &Address,
        end: &Address,
    ) -> Result<(), GroupTreeError> {
        match &mut tree.node_mut(self).kind {
            GroupKind::Fragment { addresses } => {
                addresses.add_range(start, end);
                Ok(())
            }
            GroupKind::Module { .. } => Err(GroupTreeError::NotAModule(String::new())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn addr(space: &std::sync::Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
    }

    fn ram_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    #[test]
    fn root_starts_as_empty_module() {
        let tree = GroupTree::new("Program Tree", "Program Tree");
        let root = tree.root();

        assert!(root.is_module(&tree));
        assert_eq!(root.name(&tree), "Program Tree");
        assert_eq!(root.num_children(&tree), 0);
        assert_eq!(root.num_parents(&tree), 0);
        assert!(!root.is_deleted(&tree));
    }

    #[test]
    fn create_module_and_fragment_children() {
        let mut tree = GroupTree::new("Program Tree", "root");
        let root = tree.root();

        let child_mod = root.create_module(&mut tree, "child_mod").unwrap();
        let frag = root.create_fragment(&mut tree, "frag").unwrap();

        assert_eq!(root.num_children(&tree), 2);
        assert!(child_mod.is_module(&tree));
        assert!(frag.is_fragment(&tree));
        assert_eq!(child_mod.parents(&tree), &[root]);
        assert_eq!(root.index_of(&tree, "frag"), Some(1));
        assert!(root.contains_fragment(&tree, frag));
        assert!(root.contains_module(&tree, child_mod));
    }

    #[test]
    fn fragment_can_have_multiple_parents() {
        // The actual multi-parent DAG case: a fragment shared by two modules. Under the old
        // Box<dyn Group>-returning design this would need Rc<RefCell<dyn Group>> to mutate
        // through two owners; here it's two GroupIds pointing at one arena slot.
        let mut tree = GroupTree::new("Program Tree", "root");
        let root = tree.root();
        let mod_a = root.create_module(&mut tree, "a").unwrap();
        let mod_b = root.create_module(&mut tree, "b").unwrap();
        let frag = mod_a.create_fragment(&mut tree, "shared").unwrap();

        mod_b.add_child(&mut tree, frag).unwrap();

        assert_eq!(frag.num_parents(&tree), 2);
        let mut parent_names = frag.parent_names(&tree);
        parent_names.sort();
        assert_eq!(parent_names, vec!["a".to_string(), "b".to_string()]);
        assert!(mod_a.contains_fragment(&tree, frag));
        assert!(mod_b.contains_fragment(&tree, frag));
    }

    #[test]
    fn add_child_rejects_cycle() {
        let mut tree = GroupTree::new("Program Tree", "root");
        let root = tree.root();
        let child = root.create_module(&mut tree, "child").unwrap();
        let grandchild = child.create_module(&mut tree, "grandchild").unwrap();

        let err = grandchild.add_child(&mut tree, root).unwrap_err();
        assert!(matches!(err, GroupTreeError::Circular(_)));
    }

    #[test]
    fn add_child_rejects_duplicate() {
        let mut tree = GroupTree::new("Program Tree", "root");
        let root = tree.root();
        let mod_a = root.create_module(&mut tree, "a").unwrap();
        let frag = root.create_fragment(&mut tree, "frag").unwrap();

        mod_a.add_child(&mut tree, frag).unwrap();
        let err = mod_a.add_child(&mut tree, frag).unwrap_err();
        assert!(matches!(err, GroupTreeError::AlreadyChild(_)));
    }

    #[test]
    fn create_module_rejects_duplicate_name_anywhere_in_tree() {
        let mut tree = GroupTree::new("Program Tree", "root");
        let root = tree.root();
        root.create_fragment(&mut tree, "dup").unwrap();

        let err = root.create_module(&mut tree, "dup").unwrap_err();
        assert!(matches!(err, GroupTreeError::DuplicateName(_)));
    }

    #[test]
    fn create_fragment_on_a_fragment_errors() {
        let mut tree = GroupTree::new("Program Tree", "root");
        let root = tree.root();
        let frag = root.create_fragment(&mut tree, "leaf").unwrap();

        let err = frag.create_fragment(&mut tree, "nested").unwrap_err();
        assert!(matches!(err, GroupTreeError::NotAModule(_)));
    }

    #[test]
    fn remove_child_unlinks_and_marks_deleted_when_no_parents_remain() {
        let mut tree = GroupTree::new("Program Tree", "root");
        let root = tree.root();
        let frag = root.create_fragment(&mut tree, "frag").unwrap();

        assert!(root.remove_child(&mut tree, "frag"));
        assert_eq!(root.num_children(&tree), 0);
        assert_eq!(frag.num_parents(&tree), 0);
        assert!(frag.is_deleted(&tree));
        assert!(!root.remove_child(&mut tree, "frag"));
    }

    #[test]
    fn remove_child_keeps_shared_fragment_alive_via_other_parent() {
        let mut tree = GroupTree::new("Program Tree", "root");
        let root = tree.root();
        let mod_a = root.create_module(&mut tree, "a").unwrap();
        let mod_b = root.create_module(&mut tree, "b").unwrap();
        let frag = mod_a.create_fragment(&mut tree, "shared").unwrap();
        mod_b.add_child(&mut tree, frag).unwrap();

        assert!(mod_a.remove_child(&mut tree, "shared"));

        assert_eq!(frag.num_parents(&tree), 1);
        assert!(!frag.is_deleted(&tree));
        assert!(mod_b.contains_fragment(&tree, frag));
    }

    #[test]
    fn group_path_walks_first_parent_chain() {
        let mut tree = GroupTree::new("Program Tree", "root");
        let root = tree.root();
        let mid = root.create_module(&mut tree, "middle").unwrap();
        let leaf = mid.create_fragment(&mut tree, "leaf").unwrap();

        let path = leaf.group_path(&tree);
        assert_eq!(
            path.get_path(),
            &["root".to_string(), "middle".to_string(), "leaf".to_string()]
        );
    }

    #[test]
    fn module_min_max_address_aggregate_descendant_fragments() {
        let mut tree = GroupTree::new("Program Tree", "root");
        let root = tree.root();
        let space = ram_space();
        let frag_a = root.create_fragment(&mut tree, "a").unwrap();
        let frag_b = root.create_fragment(&mut tree, "b").unwrap();
        frag_a.add_address_range(&mut tree, &addr(&space, 0x1000), &addr(&space, 0x1fff)).unwrap();
        frag_b.add_address_range(&mut tree, &addr(&space, 0x3000), &addr(&space, 0x3fff)).unwrap();

        assert_eq!(root.min_address(&tree), Some(addr(&space, 0x1000)));
        assert_eq!(root.max_address(&tree), Some(addr(&space, 0x3fff)));
        assert!(root.contains(&tree, &addr(&space, 0x1500)));
        assert!(!root.contains(&tree, &addr(&space, 0x2500)));
    }

    #[test]
    fn set_name_rejects_duplicate_but_allows_self_rename() {
        let mut tree = GroupTree::new("Program Tree", "root");
        let root = tree.root();
        let a = root.create_module(&mut tree, "a").unwrap();
        root.create_module(&mut tree, "b").unwrap();

        assert!(a.set_name(&mut tree, "a").is_ok());
        assert!(a.set_name(&mut tree, "b").is_err());
        assert!(a.set_name(&mut tree, "c").is_ok());
        assert_eq!(a.name(&tree), "c");
    }

    #[test]
    fn comment_round_trips() {
        let mut tree = GroupTree::new("Program Tree", "root");
        let root = tree.root();

        assert_eq!(root.comment(&tree), None);
        root.set_comment(&mut tree, Some("hello"));
        assert_eq!(root.comment(&tree), Some("hello"));
        root.set_comment(&mut tree, None);
        assert_eq!(root.comment(&tree), None);
    }
}
