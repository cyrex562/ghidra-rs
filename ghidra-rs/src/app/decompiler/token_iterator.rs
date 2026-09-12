//! Port of `ghidra.app.decompiler.TokenIterator`.
//!
//! An iterator over `ClangToken` leaves. The iterator walks a tree of `ClangNode` objects based
//! on `Parent()`/`Child()`, returning successive leaf tokens. It can run forward or backward.
//!
//! # Shape
//!
//! Java hand-rolls `hasNext()`/`next()` (`implements Iterator<ClangToken>`). Per this crate's
//! established convention for Java iterators (see
//! [`DistinctIterator`](crate::util::distinct_iterator::DistinctIterator)), this ports directly
//! onto Rust's native [`Iterator`] trait instead: `hasNext()` has no separate counterpart --
//! [`Iterator::next`] returning `None` at the end serves both roles. This actually matches a
//! subtle, real Java quirk: `TokenIterator.next()` does not check `hasNext()` and throw
//! `NoSuchElementException` when exhausted (as a well-behaved Java `Iterator` normally would) --
//! it just returns the already-`null` `currentToken`. Rust's `Iterator::next` returning
//! `Option::None` on exhaustion is exactly that same "quiet null" behavior, so no extra work (or
//! bug reproduction) is needed to preserve it here; it falls out of using the trait as intended.
//!
//! Java types `nodeStack` as `ClangTokenGroup[]`, relying on the real class hierarchy (every
//! group-shaped `ClangNode` -- `ClangTokenGroup` and everything that `extends` it -- literally
//! *is* a `ClangTokenGroup`). This crate's composition-over-inheritance convention means
//! `ClangFunction`/`ClangFuncProto` merely *contain* a `ClangTokenGroup` rather than being one, so
//! that can't be reproduced with a concrete stack type. Instead the stack holds `&dyn ClangNode`
//! (every operation `TokenIterator` actually performs on stack entries --
//! [`ClangNode::num_children`], [`ClangNode::child`] -- is already declared on the trait), and
//! the `instanceof ClangToken` / `instanceof ClangTokenGroup` checks are replaced by
//! [`ClangNode::is_clang_token`], a new trait method each implementor answers directly instead of
//! relying on Rust reproducing Java's class hierarchy.
//!
//! Java's `expand()` manually doubles the backing arrays as the walk descends deeper than the
//! stack the constructor originally sized. [`Vec`] grows on its own, so `expand()`/the
//! fixed-size-array dance it works around have no counterpart here -- [`push_group`](TokenIterator::push_group)
//! just calls `Vec::push`. This is a pure implementation-detail simplification (identical
//! observable behavior for every input), not a behavior change.
//!
//! [`normalize`](TokenIterator::normalize) is written as a loop rather than mirroring Java's
//! recursion, for the same reason: identical observable behavior, but without the tree-depth
//! recursion limit a literal port would carry.

use crate::app::decompiler::clang_node::ClangNode;

/// An iterator over `ClangToken` leaves of a `ClangNode` tree, walking forward or backward in
/// display order. Port of `ghidra.app.decompiler.TokenIterator`.
pub struct TokenIterator<'a> {
    /// Ancestry of the current token; `node_stack[node_stack.len() - 1]` is the immediate parent
    /// group of `current_token` (or, before the first `next()` call following construction, the
    /// group currently being explored). Mirrors Java's `nodeStack`, but sized exactly to the
    /// current depth (no unused trailing capacity) since [`Vec`] grows on demand -- see the
    /// module docs.
    node_stack: Vec<&'a dyn ClangNode>,
    /// `index_stack[i]` is the child index into `node_stack[i]` currently being visited (or about
    /// to be visited/backtracked from). Mirrors Java's `indexStack`.
    index_stack: Vec<i32>,
    /// The token [`Iterator::next`] will return, or `None` if the walk is exhausted. Mirrors
    /// Java's `currentToken`.
    current_token: Option<&'a dyn ClangNode>,
    /// `1` for a forward iterator, `-1` for a backward one. Mirrors Java's `direction`.
    direction: i32,
}

impl<'a> TokenIterator<'a> {
    /// Add a new group to the node stack. Port of `TokenIterator.pushGroup(ClangTokenGroup)`
    /// (Java's manual array-growth dance via `expand()` has no counterpart -- see the module
    /// docs).
    fn push_group(&mut self, group: &'a dyn ClangNode) {
        let start_index = if self.direction < 0 {
            group.num_children() as i32 - 1
        } else {
            0
        };
        self.node_stack.push(group);
        self.index_stack.push(start_index);
    }

    /// Backtrack until all indices indicate a proper child for their respective group, then push
    /// forward until the active node at the current depth is a leaf token. Port of
    /// `TokenIterator.normalize()`, restructured as a loop instead of recursion (see the module
    /// docs) -- each `continue`/`return` below corresponds to one of Java's four branches.
    fn normalize(&mut self) {
        loop {
            let Some(depth) = self.node_stack.len().checked_sub(1) else {
                self.current_token = None;
                return;
            };
            let index = self.index_stack[depth];

            if index < 0 {
                self.node_stack.pop();
                self.index_stack.pop();
                let Some(parent_depth) = self.index_stack.len().checked_sub(1) else {
                    self.current_token = None;
                    return;
                };
                self.index_stack[parent_depth] -= 1;
                continue;
            }

            let group = self.node_stack[depth];
            if index as usize >= group.num_children() {
                self.node_stack.pop();
                self.index_stack.pop();
                let Some(parent_depth) = self.index_stack.len().checked_sub(1) else {
                    self.current_token = None;
                    return;
                };
                self.index_stack[parent_depth] += 1;
                continue;
            }

            let node = group.child(index as usize);
            if node.is_clang_token() {
                self.current_token = Some(node);
                return;
            }
            self.push_group(node);
        }
    }

    /// Update the node stack so it points at the next token (the predecessor or successor
    /// depending on [`direction`](Self::direction)). Sets `current_token` to the next token, or
    /// `None` if there is none. Port of `TokenIterator.advanceToken()`.
    ///
    /// # Panics
    /// If called with an empty stack (i.e. the iterator was constructed over a single token with
    /// no parent, and has already yielded that one token) this indexes `index_stack` at `usize`
    /// `0 - 1` and panics. This mirrors Java's `indexStack[depth]` with `depth == -1`, which
    /// throws `ArrayIndexOutOfBoundsException` in the identical scenario -- a real quirk of the
    /// Java source (a "single orphan token" iterator is not usable past its first element), not
    /// something this port silently smooths over. See
    /// `next_panics_after_exhausting_a_single_parentless_token` below.
    fn advance_token(&mut self) {
        if self.current_token.is_none() {
            return;
        }
        let depth = self.index_stack.len() - 1;
        self.index_stack[depth] += self.direction;
        self.normalize();
    }

    /// Port of `TokenIterator.findIndex(ClangNode, ClangNode)`. Compares by reference identity,
    /// matching Java's `==` (not `equals()`).
    fn find_index(group: &dyn ClangNode, node: &dyn ClangNode) -> i32 {
        for i in 0..group.num_children() {
            if std::ptr::eq(group.child(i), node) {
                return i as i32;
            }
        }
        -1
    }

    /// Initialize an iterator to point at a specific token, which may be anywhere in the
    /// sequence. Port of `TokenIterator(ClangToken, boolean)`.
    ///
    /// Typed as `&dyn ClangNode` rather than a hypothetical `&dyn ClangToken`, consistent with
    /// [`ClangTokenGroup::flatten`](crate::app::decompiler::ClangTokenGroup::flatten) and
    /// [`ClangNode::flatten`] already doing the same -- children throughout this crate's markup
    /// tree are stored as `ClangNode`s.
    pub fn from_token(token: &'a dyn ClangNode, forward: bool) -> Self {
        let mut group_list: Vec<&'a dyn ClangNode> = Vec::new();
        let mut node = token.parent();
        while let Some(n) = node {
            group_list.push(n);
            node = n.parent();
        }

        let len = group_list.len();
        let mut node_stack: Vec<Option<&'a dyn ClangNode>> = vec![None; len];
        let mut index_stack: Vec<i32> = vec![0; len];
        let mut cur: &'a dyn ClangNode = token;
        for (i, group) in group_list.iter().enumerate() {
            let slot = len - 1 - i;
            node_stack[slot] = Some(*group);
            index_stack[slot] = Self::find_index(*group, cur);
            cur = *group;
        }
        let node_stack: Vec<&'a dyn ClangNode> = node_stack
            .into_iter()
            .map(|slot| slot.expect("every slot filled by the loop above"))
            .collect();

        Self {
            node_stack,
            index_stack,
            current_token: Some(token),
            direction: if forward { 1 } else { -1 },
        }
    }

    /// Create an iterator across all tokens under the given group, in display order
    /// (`forward=true`) or reverse of display order (`forward=false`). Port of
    /// `TokenIterator(ClangTokenGroup, boolean)`.
    ///
    /// # Panics
    /// If `group` (or a group reached while descending its first/last child) has zero children,
    /// this calls [`ClangNode::child`] with an out-of-range index, which panics -- mirroring
    /// Java's identical `ArrayList.get(0)`/`get(numChildren()-1)` throwing
    /// `IndexOutOfBoundsException` for a totally empty group in the same position. Neither side
    /// guards against this; it is a genuine (if obscure) shared limitation, not something to
    /// silently fix here.
    pub fn from_group(group: &'a dyn ClangNode, forward: bool) -> Self {
        let mut node_stack: Vec<&'a dyn ClangNode> = Vec::new();
        let mut node: &'a dyn ClangNode = group;
        while !node.is_clang_token() {
            node_stack.push(node);
            node = if forward {
                node.child(0)
            } else {
                node.child(node.num_children() - 1)
            };
        }

        let index_stack: Vec<i32> = node_stack
            .iter()
            .map(|g| {
                if forward {
                    0
                } else {
                    g.num_children() as i32 - 1
                }
            })
            .collect();

        Self {
            node_stack,
            index_stack,
            current_token: Some(node),
            direction: if forward { 1 } else { -1 },
        }
    }
}

impl<'a> Iterator for TokenIterator<'a> {
    type Item = &'a dyn ClangNode;

    /// Port of `TokenIterator.next()`. Does not check `hasNext()` first, matching Java -- see the
    /// module docs for why that's not a gap here.
    fn next(&mut self) -> Option<Self::Item> {
        let res = self.current_token;
        self.advance_token();
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::decompiler::clang_token::ClangTokenBase;
    use crate::app::decompiler::clang_token_group::ClangTokenGroup;
    use std::sync::Arc;

    fn leaf(text: &str) -> Box<dyn ClangNode> {
        Box::new(ClangTokenBase::with_text(None, text))
    }

    fn texts(iter: TokenIterator<'_>) -> Vec<String> {
        iter.map(|n| n.to_string()).collect()
    }

    #[test]
    fn forward_over_flat_group_yields_children_in_order() {
        let mut group = ClangTokenGroup::new(None);
        group.add_token_group(leaf("a"));
        group.add_token_group(leaf("b"));
        group.add_token_group(leaf("c"));

        assert_eq!(
            texts(TokenIterator::from_group(&group, true)),
            vec!["a", "b", "c"]
        );
    }

    #[test]
    fn backward_over_flat_group_yields_children_reversed() {
        let mut group = ClangTokenGroup::new(None);
        group.add_token_group(leaf("a"));
        group.add_token_group(leaf("b"));
        group.add_token_group(leaf("c"));

        assert_eq!(
            texts(TokenIterator::from_group(&group, false)),
            vec!["c", "b", "a"]
        );
    }

    #[test]
    fn descends_into_nested_groups_in_document_order() {
        let mut inner = ClangTokenGroup::new(None);
        inner.add_token_group(leaf("b"));
        inner.add_token_group(leaf("c"));

        let mut outer = ClangTokenGroup::new(None);
        outer.add_token_group(leaf("a"));
        outer.add_token_group(Box::new(inner));
        outer.add_token_group(leaf("d"));

        assert_eq!(
            texts(TokenIterator::from_group(&outer, true)),
            vec!["a", "b", "c", "d"]
        );
        assert_eq!(
            texts(TokenIterator::from_group(&outer, false)),
            vec!["d", "c", "b", "a"]
        );
    }

    /// An empty nested group contributes no tokens and must be skipped entirely, in both
    /// directions -- this is `normalize()`'s backtrack-on-out-of-range-index behavior, not just a
    /// side effect of `flatten()`.
    #[test]
    fn empty_nested_group_is_skipped_without_producing_a_spurious_item() {
        let empty = ClangTokenGroup::new(None);

        let mut outer = ClangTokenGroup::new(None);
        outer.add_token_group(leaf("a"));
        outer.add_token_group(Box::new(empty));
        outer.add_token_group(leaf("b"));

        assert_eq!(
            texts(TokenIterator::from_group(&outer, true)),
            vec!["a", "b"]
        );
        assert_eq!(
            texts(TokenIterator::from_group(&outer, false)),
            vec!["b", "a"]
        );
    }

    /// Guards against the classic double-advance bug: exhausting the iterator must yield `None`
    /// repeatedly afterward, not panic or resurrect a stale token.
    #[test]
    fn exhausted_iterator_keeps_returning_none() {
        let mut group = ClangTokenGroup::new(None);
        group.add_token_group(leaf("only"));

        let mut it = TokenIterator::from_group(&group, true);
        assert_eq!(it.next().map(|n| n.to_string()), Some("only".to_string()));
        assert_eq!(it.next().map(|n| n.to_string()), None);
        assert_eq!(it.next().map(|n| n.to_string()), None);
    }

    /// A group holding its children by `Arc<dyn ClangNode>` (rather than the real
    /// [`ClangTokenGroup`]'s owned `Box<dyn ClangNode>`), paired with [`MockLeaf`] to build a
    /// genuinely bidirectional parent/child link for [`TokenIterator::from_token`] to climb.
    ///
    /// The real `ClangTokenGroup`/`ClangTokenBase` can't do this today: children are moved into
    /// the group by value at construction, so a child would need its parent's address *before*
    /// the parent exists as a stable, shareable value -- exactly the "no token built by this
    /// crate currently has a wired-up parent" gap
    /// [`taint_state::get_parent_token`](crate::app::plugin::core::decompiler::taint::taint_state::get_parent_token)'s
    /// doc comment describes. This mock sidesteps it (test-only) two ways: children are `Arc`s
    /// cloned into the group *and* into each leaf's own `parent` slot, and each leaf's `parent`
    /// is a [`std::sync::OnceLock`] -- set once, after the group already exists, but from then on
    /// readable as a plain `&dyn ClangNode` tied to `&self` (not to a lock guard), which
    /// satisfies [`ClangNode::parent`]'s signature the way a `RefCell`/`Mutex` guard could not.
    struct MockGroup {
        children: Vec<Arc<dyn ClangNode>>,
    }

    impl std::fmt::Display for MockGroup {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "<group>")
        }
    }

    impl ClangNode for MockGroup {
        fn parent(&self) -> Option<&dyn ClangNode> {
            None
        }
        fn get_min_address(&self) -> Option<crate::program::model::address::Address> {
            None
        }
        fn get_max_address(&self) -> Option<crate::program::model::address::Address> {
            None
        }
        fn num_children(&self) -> usize {
            self.children.len()
        }
        fn child(&self, i: usize) -> &dyn ClangNode {
            self.children[i].as_ref()
        }
        fn get_clang_function(&self) -> Box<dyn crate::app::seam_stubs::ClangFunction> {
            unimplemented!("not exercised by this test")
        }
        fn flatten<'b>(&'b self, list: &mut Vec<&'b dyn ClangNode>) {
            for child in &self.children {
                child.flatten(list);
            }
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    /// A leaf token whose `Parent()` is filled in after construction; see [`MockGroup`]'s doc
    /// comment for why.
    struct MockLeaf {
        text: &'static str,
        parent: std::sync::OnceLock<Arc<dyn ClangNode>>,
    }

    impl std::fmt::Display for MockLeaf {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.text)
        }
    }

    impl ClangNode for MockLeaf {
        fn parent(&self) -> Option<&dyn ClangNode> {
            self.parent.get().map(|arc| arc.as_ref())
        }
        fn get_min_address(&self) -> Option<crate::program::model::address::Address> {
            None
        }
        fn get_max_address(&self) -> Option<crate::program::model::address::Address> {
            None
        }
        fn num_children(&self) -> usize {
            0
        }
        fn child(&self, i: usize) -> &dyn ClangNode {
            panic!("MockLeaf has no children, requested index {i}")
        }
        fn get_clang_function(&self) -> Box<dyn crate::app::seam_stubs::ClangFunction> {
            unimplemented!("not exercised by this test")
        }
        fn flatten<'b>(&'b self, list: &mut Vec<&'b dyn ClangNode>) {
            list.push(self);
        }
        fn is_clang_token(&self) -> bool {
            true
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[test]
    fn from_token_starting_mid_sequence_continues_in_either_direction() {
        let leaf_a = Arc::new(MockLeaf {
            text: "a",
            parent: std::sync::OnceLock::new(),
        });
        let leaf_b = Arc::new(MockLeaf {
            text: "b",
            parent: std::sync::OnceLock::new(),
        });
        let leaf_c = Arc::new(MockLeaf {
            text: "c",
            parent: std::sync::OnceLock::new(),
        });

        let children: Vec<Arc<dyn ClangNode>> = vec![
            leaf_a.clone() as Arc<dyn ClangNode>,
            leaf_b.clone() as Arc<dyn ClangNode>,
            leaf_c.clone() as Arc<dyn ClangNode>,
        ];
        let group = Arc::new(MockGroup { children });
        let group_dyn: Arc<dyn ClangNode> = group;
        assert!(leaf_a.parent.set(group_dyn.clone()).is_ok());
        assert!(leaf_b.parent.set(group_dyn.clone()).is_ok());
        assert!(leaf_c.parent.set(group_dyn).is_ok());

        let start: &dyn ClangNode = leaf_b.as_ref();

        let forward: Vec<String> = TokenIterator::from_token(start, true)
            .map(|n| n.to_string())
            .collect();
        assert_eq!(forward, vec!["b", "c"]);

        let backward: Vec<String> = TokenIterator::from_token(start, false)
            .map(|n| n.to_string())
            .collect();
        assert_eq!(backward, vec!["b", "a"]);
    }

    /// See [`TokenIterator::advance_token`]'s doc comment: a `TokenIterator` built over a token
    /// with no `Parent()` chain has an empty stack, and asking it to advance past that single
    /// token panics -- exactly mirroring Java's `ArrayIndexOutOfBoundsException` for
    /// `indexStack[-1]` in the same scenario. This is a genuine Java quirk, faithfully
    /// reproduced rather than guarded against.
    #[test]
    #[should_panic]
    fn next_panics_after_exhausting_a_single_parentless_token() {
        let token = ClangTokenBase::with_text(None, "solo");
        let mut it = TokenIterator::from_token(&token, true);
        assert_eq!(it.next().map(|n| n.to_string()), Some("solo".to_string()));
        it.next(); // panics: no parent chain to backtrack into.
    }
}
