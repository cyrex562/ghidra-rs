//! Port of `ghidra.app.decompiler.ClangFuncProto`.
//!
//! A grouping of source code tokens representing a function prototype.
//!
//! Java's `ClangFuncProto extends ClangTokenGroup`, adding nothing beyond a one-line constructor
//! (`super(par)`). Per this crate's composition-over-inheritance convention, [`ClangFuncProto`]
//! instead *has* a [`ClangTokenGroup`] and delegates every operation to it untouched -- there is
//! no behavior of its own to add, unlike [`ClangFunction`](crate::app::decompiler::ClangFunction),
//! whose `getClangFunction()` override needed a real deviation.
//!
//! [`crate::app::decompiler::ClangTokenGroup::decode`] constructs a real `ClangFuncProto` (rather
//! than a plain `ClangTokenGroup`) for `ELEM_FUNCPROTO` children, now that this class exists;
//! `ELEM_RETURN_TYPE`/`ELEM_VARDECL`/`ELEM_STATEMENT` remain collapsed into plain
//! `ClangTokenGroup`s pending `ClangReturnType`/`ClangVariableDecl`/`ClangStatement`'s own ports.

use std::sync::Arc;

use crate::app::decompiler::clang_node::ClangNode;
use crate::app::decompiler::clang_token_group::{ClangTokenGroup, ClangTokenGroupIter};
use crate::app::decompiler::token_iterator::TokenIterator;
use crate::program::model::address::Address;
use crate::program::model::pcode::{Decoder, DecoderException, PcodeFactory};

/// A grouping of source code tokens representing a function prototype. Port of
/// `ghidra.app.decompiler.ClangFuncProto`.
pub struct ClangFuncProto {
    token_group: ClangTokenGroup,
}

impl ClangFuncProto {
    /// Port of `ClangFuncProto(ClangNode)`.
    pub fn new(par: Option<Arc<dyn ClangNode>>) -> Self {
        Self {
            token_group: ClangTokenGroup::new(par),
        }
    }

    /// Port of `ClangTokenGroup.getMinAddress()` (inherited).
    pub fn get_min_address(&self) -> Option<Address> {
        self.token_group.get_min_address()
    }

    /// Port of `ClangTokenGroup.getMaxAddress()` (inherited).
    pub fn get_max_address(&self) -> Option<Address> {
        self.token_group.get_max_address()
    }

    /// Port of `ClangTokenGroup.AddTokenGroup(ClangNode)` (inherited).
    pub fn add_token_group(&mut self, obj: Box<dyn ClangNode>) {
        self.token_group.add_token_group(obj)
    }

    /// Port of `ClangTokenGroup.Parent()` (inherited).
    pub fn parent(&self) -> Option<&dyn ClangNode> {
        self.token_group.parent()
    }

    /// Port of `ClangTokenGroup.numChildren()` (inherited).
    pub fn num_children(&self) -> usize {
        self.token_group.num_children()
    }

    /// Port of `ClangTokenGroup.Child(int)` (inherited).
    pub fn child(&self, i: usize) -> &dyn ClangNode {
        self.token_group.child(i)
    }

    /// Port of `ClangTokenGroup.getClangFunction()` (inherited): climbs `Parent()` unchanged.
    pub fn get_clang_function(&self) -> Box<dyn crate::app::seam_stubs::ClangFunction> {
        self.token_group.get_clang_function()
    }

    /// Port of `ClangTokenGroup.flatten(List<ClangNode>)` (inherited).
    pub fn flatten<'a>(&'a self, list: &mut Vec<&'a dyn ClangNode>) {
        self.token_group.flatten(list)
    }

    /// Port of `ClangTokenGroup.decode(Decoder, PcodeFactory)` (inherited).
    pub fn decode(
        &mut self,
        decoder: &dyn Decoder,
        pfactory: &dyn PcodeFactory,
    ) -> Result<(), DecoderException> {
        self.token_group.decode(decoder, pfactory)
    }

    /// Port of `ClangTokenGroup.iterator()` (inherited).
    pub fn iter(&self) -> ClangTokenGroupIter<'_> {
        self.token_group.iter()
    }

    /// Port of `ClangTokenGroup.stream()` (inherited).
    pub fn stream(&self) -> ClangTokenGroupIter<'_> {
        self.token_group.stream()
    }

    /// Port of `ClangTokenGroup.tokenIterator(boolean)` (inherited).
    pub fn token_iterator(&self, forward: bool) -> TokenIterator<'_> {
        TokenIterator::from_group(self, forward)
    }
}

impl ClangNode for ClangFuncProto {
    fn parent(&self) -> Option<&dyn ClangNode> {
        ClangFuncProto::parent(self)
    }

    fn get_min_address(&self) -> Option<Address> {
        ClangFuncProto::get_min_address(self)
    }

    fn get_max_address(&self) -> Option<Address> {
        ClangFuncProto::get_max_address(self)
    }

    fn num_children(&self) -> usize {
        ClangFuncProto::num_children(self)
    }

    fn child(&self, i: usize) -> &dyn ClangNode {
        ClangFuncProto::child(self, i)
    }

    fn get_clang_function(&self) -> Box<dyn crate::app::seam_stubs::ClangFunction> {
        ClangFuncProto::get_clang_function(self)
    }

    fn flatten<'a>(&'a self, list: &mut Vec<&'a dyn ClangNode>) {
        ClangFuncProto::flatten(self, list)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl std::fmt::Display for ClangFuncProto {
    /// Port of `ClangTokenGroup.toString()` (inherited).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.token_group)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::decompiler::clang_token::ClangTokenBase;

    #[test]
    fn new_starts_empty_with_no_addresses() {
        let proto = ClangFuncProto::new(None);
        assert_eq!(proto.num_children(), 0);
        assert_eq!(proto.get_min_address(), None);
        assert_eq!(proto.get_max_address(), None);
        assert!(proto.parent().is_none());
    }

    #[test]
    fn add_token_group_and_child_and_display_delegate_to_the_inner_group() {
        let mut proto = ClangFuncProto::new(None);
        proto.add_token_group(Box::new(ClangTokenBase::with_text(None, "int")));
        proto.add_token_group(Box::new(ClangTokenBase::with_text(None, "foo")));
        proto.add_token_group(Box::new(ClangTokenBase::with_text(None, "(")));

        assert_eq!(proto.num_children(), 3);
        assert_eq!(proto.child(0).to_string(), "int");
        assert_eq!(proto.to_string(), "int foo(");
    }

    #[test]
    fn token_iterator_walks_children_forward_and_backward() {
        let mut proto = ClangFuncProto::new(None);
        proto.add_token_group(Box::new(ClangTokenBase::with_text(None, "a")));
        proto.add_token_group(Box::new(ClangTokenBase::with_text(None, "b")));

        let forward: Vec<String> = proto.token_iterator(true).map(|n| n.to_string()).collect();
        assert_eq!(forward, vec!["a", "b"]);

        let backward: Vec<String> = proto.token_iterator(false).map(|n| n.to_string()).collect();
        assert_eq!(backward, vec!["b", "a"]);
    }

    /// With no parent, `getClangFunction()` faithfully panics -- matching
    /// [`ClangTokenGroup::get_clang_function`]'s identical documented behavior, which this
    /// delegates to unchanged.
    #[test]
    #[should_panic]
    fn get_clang_function_panics_with_no_parent() {
        let proto = ClangFuncProto::new(None);
        proto.get_clang_function();
    }
}
