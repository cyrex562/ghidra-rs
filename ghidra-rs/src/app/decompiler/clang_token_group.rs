//! Port of `ghidra.app.decompiler.ClangTokenGroup`.
//!
//! A sequence of tokens that form a meaningful group in source code. This group may break up
//! into subgroups and may be part of a larger group.
//!
//! [`ClangFunction`] is a minimal placeholder (see
//! [`crate::app::seam_stubs`]) since the real class is not ported yet -- this file
//! sits on a dependency cycle with it. [`decode`](ClangTokenGroup::decode) additionally
//! collapses `ClangFuncProto`/`ClangReturnType`/`ClangStatement`/`ClangVariableDecl` (all of
//! which `extends ClangTokenGroup` in Java, adding only extra attribute-derived fields such as a
//! return data type or a bound `HighSymbol`) into plain nested `ClangTokenGroup` children, since
//! those subclasses are not ported either: the shared tree/token-group structure they inherit
//! from `ClangTokenGroup` is preserved faithfully, but their own extra accessors are not
//! available until each is ported in its own right.

use std::sync::Arc;

use crate::app::decompiler::clang_node::ClangNode;
use crate::app::seam_stubs::{ClangFunction, ClangToken};
use crate::program::model::address::Address;
use crate::program::model::pcode::{
    Decoder, DecoderError, DecoderException, PcodeFactory, ELEM_BLOCK, ELEM_FUNCPROTO,
    ELEM_RETURN_TYPE, ELEM_STATEMENT, ELEM_VARDECL,
};

/// A sequence of tokens that form a meaningful group in source code. Port of
/// `ghidra.app.decompiler.ClangTokenGroup`.
pub struct ClangTokenGroup {
    parent: Option<Arc<dyn ClangNode>>,
    min_address: Option<Address>,
    max_address: Option<Address>,
    tokgroup: Vec<Box<dyn ClangNode>>,
}

impl ClangTokenGroup {
    /// Port of `ClangTokenGroup(ClangNode)`.
    pub fn new(parent: Option<Arc<dyn ClangNode>>) -> Self {
        Self {
            parent,
            min_address: None,
            max_address: None,
            tokgroup: Vec::new(),
        }
    }

    /// Port of `ClangTokenGroup.getMinAddress()`.
    pub fn get_min_address(&self) -> Option<Address> {
        self.min_address.clone()
    }

    /// Port of `ClangTokenGroup.getMaxAddress()`.
    pub fn get_max_address(&self) -> Option<Address> {
        self.max_address.clone()
    }

    /// Add additional text to this group. Port of `ClangTokenGroup.AddTokenGroup(ClangNode)`.
    pub fn add_token_group(&mut self, obj: Box<dyn ClangNode>) {
        if let Some(minaddr) = obj.get_min_address() {
            self.min_address = Some(match self.min_address.take() {
                None => minaddr,
                Some(cur) => {
                    if minaddr < cur {
                        minaddr
                    } else {
                        cur
                    }
                }
            });
        }
        if let Some(maxaddr) = obj.get_max_address() {
            self.max_address = Some(match self.max_address.take() {
                None => maxaddr,
                Some(cur) => {
                    if cur < maxaddr {
                        maxaddr
                    } else {
                        cur
                    }
                }
            });
        }
        self.tokgroup.push(obj);
    }

    /// Port of `ClangTokenGroup.Parent()`.
    pub fn parent(&self) -> Option<&dyn ClangNode> {
        self.parent.as_deref()
    }

    /// Port of `ClangTokenGroup.numChildren()`.
    pub fn num_children(&self) -> usize {
        self.tokgroup.len()
    }

    /// Port of `ClangTokenGroup.Child(int)`.
    pub fn child(&self, i: usize) -> &dyn ClangNode {
        self.tokgroup[i].as_ref()
    }

    /// Port of `ClangTokenGroup.getClangFunction()`.
    ///
    /// # Panics
    /// Panics if this group has no parent, mirroring the `NullPointerException` Java raises for
    /// `parent.getClangFunction()` when `parent` is `null` (the root document group).
    pub fn get_clang_function(&self) -> Box<dyn ClangFunction> {
        self.parent
            .as_ref()
            .expect("ClangTokenGroup.getClangFunction() called with no parent")
            .get_clang_function()
    }

    /// Flatten this text into a list of leaf tokens. Port of
    /// `ClangTokenGroup.flatten(List<ClangNode>)`.
    pub fn flatten<'a>(&'a self, list: &mut Vec<&'a dyn ClangNode>) {
        for element in &self.tokgroup {
            element.flatten(list);
        }
    }

    /// `true` if the given character is a letter, digit, or underscore. Port of
    /// `ClangTokenGroup.isLetterDigitOrUnderscore(char)`.
    fn is_letter_digit_or_underscore(c: char) -> bool {
        c.is_alphanumeric() || c == '_'
    }

    /// Decode this text from an encoded stream. Port of
    /// `ClangTokenGroup.decode(Decoder, PcodeFactory)`.
    ///
    /// See the module docs: sub-elements that map to `ClangFuncProto`/`ClangReturnType`/
    /// `ClangStatement`/`ClangVariableDecl` in Java are decoded here as plain nested
    /// `ClangTokenGroup` children instead, since those subclasses are not ported yet.
    pub fn decode(
        &mut self,
        decoder: &dyn Decoder,
        pfactory: &dyn PcodeFactory,
    ) -> Result<(), DecoderException> {
        loop {
            let elem = decoder.open_element().map_err(decode_err)?;
            if elem == 0 {
                break;
            }
            if elem == ELEM_RETURN_TYPE.id
                || elem == ELEM_VARDECL.id
                || elem == ELEM_STATEMENT.id
                || elem == ELEM_FUNCPROTO.id
                || elem == ELEM_BLOCK.id
            {
                let mut child = ClangTokenGroup::new(None);
                child.decode(decoder, pfactory)?;
                self.add_token_group(Box::new(child));
            } else {
                let tok = ClangToken::build_token(elem, decoder, pfactory)?;
                self.add_token_group(tok);
            }
            decoder.close_element(elem).map_err(decode_err)?;
        }
        Ok(())
    }

    /// Returns a borrowing iterator over this group's immediate children. Port of
    /// `ClangTokenGroup.iterator()`.
    pub fn iter(&self) -> ClangTokenGroupIter<'_> {
        self.into_iter()
    }

    /// Port of `ClangTokenGroup.stream()`. Rust's `Iterator` already provides the combinators
    /// Java's `Stream` offered, so this is just an alias for [`Self::iter`].
    pub fn stream(&self) -> ClangTokenGroupIter<'_> {
        self.iter()
    }

    /// Create an iterator across all leaf tokens in this group, in display order
    /// (`forward=true`) or in reverse of display order (`forward=false`). Port of
    /// `ClangTokenGroup.tokenIterator(boolean)`.
    ///
    /// The real `TokenIterator` walks the `Parent()`/`Child()` tree lazily with an explicit
    /// ancestor stack. Since [`Self::flatten`] already performs the identical depth-first,
    /// leaf-order enumeration eagerly -- and reversing a full forward enumeration is exactly a
    /// backward enumeration for a tree -- this reuses it instead of porting `TokenIterator`'s
    /// stack machinery. Typed as `ClangNode` rather than `ClangToken` since the leaf/group
    /// distinction is not yet independently trackable without the real `ClangToken` port.
    pub fn token_iterator(&self, forward: bool) -> std::vec::IntoIter<&dyn ClangNode> {
        let mut list = Vec::new();
        self.flatten(&mut list);
        if !forward {
            list.reverse();
        }
        list.into_iter()
    }
}

fn decode_err(e: DecoderError) -> DecoderException {
    DecoderException::with_cause("failed to decode ClangTokenGroup", e)
}

impl ClangNode for ClangTokenGroup {
    fn parent(&self) -> Option<&dyn ClangNode> {
        ClangTokenGroup::parent(self)
    }

    fn get_min_address(&self) -> Option<Address> {
        ClangTokenGroup::get_min_address(self)
    }

    fn get_max_address(&self) -> Option<Address> {
        ClangTokenGroup::get_max_address(self)
    }

    fn num_children(&self) -> usize {
        ClangTokenGroup::num_children(self)
    }

    fn child(&self, i: usize) -> &dyn ClangNode {
        ClangTokenGroup::child(self, i)
    }

    fn get_clang_function(&self) -> Box<dyn ClangFunction> {
        ClangTokenGroup::get_clang_function(self)
    }

    fn flatten<'a>(&'a self, list: &mut Vec<&'a dyn ClangNode>) {
        ClangTokenGroup::flatten(self, list)
    }
}

impl std::fmt::Display for ClangTokenGroup {
    /// Port of `ClangTokenGroup.toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut last_token_str: Option<String> = None;
        for node in &self.tokgroup {
            let token_str = node.to_string();
            if token_str.is_empty() {
                continue;
            }
            if let Some(last) = &last_token_str {
                let first = token_str.chars().next().expect("checked non-empty above");
                let last_char = last.chars().next_back().expect("checked non-empty above");
                if Self::is_letter_digit_or_underscore(first)
                    && Self::is_letter_digit_or_underscore(last_char)
                {
                    // avoid concatenating names together
                    write!(f, " ")?;
                }
            }
            write!(f, "{token_str}")?;
            last_token_str = Some(token_str);
        }
        Ok(())
    }
}

/// Borrowing iterator over a [`ClangTokenGroup`]'s immediate children.
pub struct ClangTokenGroupIter<'a> {
    inner: std::slice::Iter<'a, Box<dyn ClangNode>>,
}

impl<'a> Iterator for ClangTokenGroupIter<'a> {
    type Item = &'a dyn ClangNode;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|b| b.as_ref())
    }
}

impl<'a> IntoIterator for &'a ClangTokenGroup {
    type Item = &'a dyn ClangNode;
    type IntoIter = ClangTokenGroupIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        ClangTokenGroupIter {
            inner: self.tokgroup.iter(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressFactory, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::ids::{AttributeId, ElementId};

    struct MockNode {
        min: Option<Address>,
        max: Option<Address>,
        text: String,
        children: Vec<Box<dyn ClangNode>>,
    }

    impl MockNode {
        fn leaf(text: &str) -> Self {
            Self {
                min: None,
                max: None,
                text: text.to_string(),
                children: Vec::new(),
            }
        }

        fn with_addresses(text: &str, min: Address, max: Address) -> Self {
            Self {
                min: Some(min),
                max: Some(max),
                text: text.to_string(),
                children: Vec::new(),
            }
        }

        fn group(children: Vec<Box<dyn ClangNode>>) -> Self {
            Self {
                min: None,
                max: None,
                text: String::new(),
                children,
            }
        }
    }

    impl ClangNode for MockNode {
        fn parent(&self) -> Option<&dyn ClangNode> {
            None
        }
        fn get_min_address(&self) -> Option<Address> {
            self.min.clone()
        }
        fn get_max_address(&self) -> Option<Address> {
            self.max.clone()
        }
        fn num_children(&self) -> usize {
            self.children.len()
        }
        fn child(&self, i: usize) -> &dyn ClangNode {
            self.children[i].as_ref()
        }
        fn get_clang_function(&self) -> Box<dyn ClangFunction> {
            unimplemented!("not needed for this smoke test")
        }
        fn flatten<'a>(&'a self, list: &mut Vec<&'a dyn ClangNode>) {
            if self.children.is_empty() {
                list.push(self);
            } else {
                for c in &self.children {
                    c.flatten(list);
                }
            }
        }
    }

    impl std::fmt::Display for MockNode {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.text)
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
    }

    #[test]
    fn add_token_group_tracks_widest_min_and_max_address() {
        let space = ram_space();
        let mut group = ClangTokenGroup::new(None);

        group.add_token_group(Box::new(MockNode::with_addresses(
            "a",
            addr(&space, 100),
            addr(&space, 200),
        )));
        group.add_token_group(Box::new(MockNode::with_addresses(
            "b",
            addr(&space, 50),
            addr(&space, 150),
        )));

        assert_eq!(group.get_min_address(), Some(addr(&space, 50)));
        assert_eq!(group.get_max_address(), Some(addr(&space, 200)));
    }

    #[test]
    fn add_token_group_ignores_children_with_no_address() {
        let mut group = ClangTokenGroup::new(None);
        group.add_token_group(Box::new(MockNode::leaf("plain")));
        assert_eq!(group.get_min_address(), None);
        assert_eq!(group.get_max_address(), None);
    }

    #[test]
    fn num_children_and_child_reflect_added_order() {
        let mut group = ClangTokenGroup::new(None);
        group.add_token_group(Box::new(MockNode::leaf("first")));
        group.add_token_group(Box::new(MockNode::leaf("second")));

        assert_eq!(group.num_children(), 2);
        assert_eq!(group.child(0).to_string(), "first");
        assert_eq!(group.child(1).to_string(), "second");
    }

    #[test]
    fn to_string_inserts_space_only_between_alnum_boundaries() {
        let mut group = ClangTokenGroup::new(None);
        group.add_token_group(Box::new(MockNode::leaf("int")));
        group.add_token_group(Box::new(MockNode::leaf("x")));
        assert_eq!(group.to_string(), "int x");

        let mut group2 = ClangTokenGroup::new(None);
        group2.add_token_group(Box::new(MockNode::leaf("(")));
        group2.add_token_group(Box::new(MockNode::leaf("x")));
        group2.add_token_group(Box::new(MockNode::leaf(")")));
        assert_eq!(group2.to_string(), "(x)");
    }

    #[test]
    fn to_string_skips_empty_tokens() {
        let mut group = ClangTokenGroup::new(None);
        group.add_token_group(Box::new(MockNode::leaf("(")));
        group.add_token_group(Box::new(MockNode::leaf("")));
        group.add_token_group(Box::new(MockNode::leaf("x")));
        // The empty token is skipped entirely (not just its text), so `last_token_str` still
        // reflects "(" when checking the boundary against "x" -- no space is inserted since '('
        // is not alnum/underscore.
        assert_eq!(group.to_string(), "(x");
    }

    /// Guards against the classic `hasNext()`/`next()` double-advance bug: iterating must yield
    /// each child exactly once, in order, and keep reporting `None` afterward.
    #[test]
    fn iterator_yields_each_child_exactly_once_in_order() {
        let mut group = ClangTokenGroup::new(None);
        group.add_token_group(Box::new(MockNode::leaf("a")));
        group.add_token_group(Box::new(MockNode::leaf("b")));
        group.add_token_group(Box::new(MockNode::leaf("c")));

        let mut it = group.iter();
        assert_eq!(it.next().map(|n| n.to_string()), Some("a".to_string()));
        assert_eq!(it.next().map(|n| n.to_string()), Some("b".to_string()));
        assert_eq!(it.next().map(|n| n.to_string()), Some("c".to_string()));
        assert_eq!(it.next().map(|n| n.to_string()), None);
        assert_eq!(it.next().map(|n| n.to_string()), None);

        let collected: Vec<String> = (&group).into_iter().map(|n| n.to_string()).collect();
        assert_eq!(collected, vec!["a", "b", "c"]);
    }

    #[test]
    fn flatten_collects_leaf_descendants_in_document_order() {
        let nested: Box<dyn ClangNode> = Box::new(MockNode::group(vec![
            Box::new(MockNode::leaf("b")),
            Box::new(MockNode::leaf("c")),
        ]));
        let mut group = ClangTokenGroup::new(None);
        group.add_token_group(Box::new(MockNode::leaf("a")));
        group.add_token_group(nested);
        group.add_token_group(Box::new(MockNode::leaf("d")));

        let mut list = Vec::new();
        group.flatten(&mut list);
        let texts: Vec<String> = list.iter().map(|n| n.to_string()).collect();
        assert_eq!(texts, vec!["a", "b", "c", "d"]);
    }

    #[test]
    fn token_iterator_backward_is_exact_reverse_of_forward() {
        let mut group = ClangTokenGroup::new(None);
        group.add_token_group(Box::new(MockNode::leaf("a")));
        group.add_token_group(Box::new(MockNode::leaf("b")));
        group.add_token_group(Box::new(MockNode::leaf("c")));

        let forward: Vec<String> = group
            .token_iterator(true)
            .map(|n| n.to_string())
            .collect();
        let backward: Vec<String> = group
            .token_iterator(false)
            .map(|n| n.to_string())
            .collect();

        assert_eq!(forward, vec!["a", "b", "c"]);
        assert_eq!(backward, vec!["c", "b", "a"]);
    }

    /// A [`Decoder`] driven by a scripted sequence of `openElement()` results, mirroring the
    /// shape of `MockSymrefDecoder` in `high_constant.rs`'s tests.
    struct ScriptedDecoder {
        elems: Vec<i32>,
        idx: std::sync::atomic::AtomicUsize,
        open_calls: std::sync::atomic::AtomicUsize,
        close_calls: std::sync::atomic::AtomicUsize,
    }

    impl Decoder for ScriptedDecoder {
        fn get_address_factory(&self) -> Arc<dyn AddressFactory> {
            unimplemented!()
        }
        fn set_address_factory(&self, _factory: Arc<dyn AddressFactory>) {}
        fn peek_element(&self) -> Result<i32, DecoderError> {
            unimplemented!()
        }
        fn open_element(&self) -> Result<i32, DecoderError> {
            let i = self.idx.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.open_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self.elems[i])
        }
        fn open_element_with_id(&self, _elem_id: ElementId) -> Result<i32, DecoderError> {
            unimplemented!()
        }
        fn close_element(&self, _id: i32) -> Result<(), DecoderError> {
            self.close_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        fn close_element_skipping(&self, _id: i32) -> Result<(), DecoderError> {
            unimplemented!()
        }
        fn get_next_attribute_id(&self) -> Result<i32, DecoderError> {
            Ok(0)
        }
        fn rewind_attributes(&self) {}
        fn read_bool(&self) -> Result<bool, DecoderError> {
            unimplemented!()
        }
        fn read_bool_with_id(&self, _attrib_id: AttributeId) -> Result<bool, DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer(&self) -> Result<i64, DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer_with_id(
            &self,
            _attrib_id: AttributeId,
        ) -> Result<i64, DecoderError> {
            unimplemented!()
        }
        fn read_unsigned_integer(&self) -> Result<u64, DecoderError> {
            unimplemented!()
        }
        fn read_unsigned_integer_with_id(
            &self,
            _attrib_id: AttributeId,
        ) -> Result<u64, DecoderError> {
            unimplemented!()
        }
        fn read_string(&self) -> Result<String, DecoderError> {
            unimplemented!()
        }
        fn read_string_with_id(&self, _attrib_id: AttributeId) -> Result<String, DecoderError> {
            unimplemented!()
        }
        fn read_space(&self) -> Result<Arc<AddressSpace>, DecoderError> {
            unimplemented!()
        }
        fn read_space_with_id(
            &self,
            _attrib_id: AttributeId,
        ) -> Result<Arc<AddressSpace>, DecoderError> {
            unimplemented!()
        }
    }

    struct StubPcodeFactory;

    impl PcodeFactory for StubPcodeFactory {
        fn get_address_factory(&self) -> Arc<dyn AddressFactory> {
            unimplemented!()
        }
        fn get_data_type_manager(
            &self,
        ) -> Arc<dyn crate::program::model::pcode::PcodeDataTypeManager> {
            unimplemented!()
        }
        fn new_varnode_with_ref(
            &self,
            _sz: i32,
            _addr: Address,
            _ref_id: i32,
        ) -> crate::program::model::pcode::Varnode {
            unimplemented!()
        }
        fn get_join_address(
            &self,
            _storage: &dyn crate::program::model::listing::variable_storage::VariableStorage,
        ) -> Option<Address> {
            unimplemented!()
        }
        fn build_storage(
            &self,
            _vn: &crate::program::model::pcode::Varnode,
        ) -> Result<
            Box<dyn crate::program::model::listing::variable_storage::VariableStorage>,
            crate::util::exception::InvalidInputException,
        > {
            unimplemented!()
        }
        fn get_ref(&self, _refid: i32) -> Option<crate::program::model::pcode::Varnode> {
            unimplemented!()
        }
        fn get_op_ref(&self, _refid: i32) -> Option<crate::program::model::pcode::PcodeOp> {
            unimplemented!()
        }
        fn get_symbol(&self, _symbol_id: i64) -> Option<Arc<dyn crate::program::seam_stubs::HighSymbol>> {
            unimplemented!()
        }
        fn new_op(
            &self,
            _sq: crate::program::model::pcode::SequenceNumber,
            _opc: crate::program::model::pcode::OpCode,
            _inputs: Vec<crate::program::model::pcode::Varnode>,
            _output: Option<crate::program::model::pcode::Varnode>,
        ) -> crate::program::model::pcode::PcodeOp {
            unimplemented!()
        }
    }

    /// Exercises `decode`'s dispatch loop: one nested `ELEM_BLOCK` group (itself empty) followed
    /// by one leaf token, then end-of-elements. Checks the resulting tree shape and that
    /// `openElement`/`closeElement` were each called the expected number of times (guards
    /// against an off-by-one termination bug in the loop).
    #[test]
    fn decode_builds_nested_group_and_leaf_token_then_stops() {
        let decoder = ScriptedDecoder {
            elems: vec![ELEM_BLOCK.id, 0, 999, 0],
            idx: std::sync::atomic::AtomicUsize::new(0),
            open_calls: std::sync::atomic::AtomicUsize::new(0),
            close_calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let pfactory = StubPcodeFactory;

        let mut group = ClangTokenGroup::new(None);
        group
            .decode(&decoder, &pfactory)
            .expect("decode should succeed");

        assert_eq!(group.num_children(), 2, "one nested group + one leaf token");
        assert_eq!(decoder.open_calls.load(std::sync::atomic::Ordering::SeqCst), 4);
        assert_eq!(
            decoder.close_calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "one close per decoded child, not per open"
        );
    }
}
