//! Port of `ghidra.app.decompiler.ClangFunction`.
//!
//! A grouping of source code tokens representing an entire function.
//!
//! # Shape
//!
//! Java's `ClangFunction extends ClangTokenGroup`, adding only a `HighFunction` field and a
//! covariant override of `getClangFunction()` that returns `this`. Per this crate's
//! composition-over-inheritance convention, [`ClangFunction`] instead *has* a
//! [`ClangTokenGroup`] and delegates the entire group-shaped surface to it, exposing the
//! delegated methods as inherent methods of the same name (mirroring how [`ClangTokenGroup`]
//! itself both implements [`ClangNode`] and exposes the same operations as inherent methods).
//!
//! # `getClangFunction()`: two answers for two callers
//!
//! Java's override (`@Override public ClangFunction getClangFunction() { return this; }`) is
//! reachable two ways in this port, with different fidelity:
//!
//! - [`ClangFunction::get_clang_function`] (inherent) borrows and returns `self` directly --
//!   exactly `this`, byte-for-byte faithful, reachable whenever a caller holds a concrete
//!   `&ClangFunction` (Rust resolves inherent methods before trait methods of the same name, so
//!   this is what such a caller gets even without qualifying the call).
//! - The [`ClangNode::get_clang_function`] trait method (reachable through `&dyn ClangNode`,
//!   e.g. while climbing a `Parent()` chain from an arbitrary descendant) is bound by a
//!   pre-existing constraint: its signature -- inherited unchanged from before this class
//!   existed, see [`ClangTokenGroup::get_clang_function`](crate::app::decompiler::ClangTokenGroup::get_clang_function)
//!   -- returns an *owned* `Box<dyn` [`crate::app::seam_stubs::ClangFunction`]`>`. An owned box
//!   cannot be produced from `&self` without either cloning the whole subtree (impossible:
//!   descendants are `Box<dyn ClangNode>`, not `Clone`) or reworking every `ClangNode`
//!   implementor in the crate to share nodes via `Arc` (out of scope here -- it reaches files
//!   outside `app/decompiler/`, e.g. `app/plugin/core/decompiler/taint/taint_state.rs`'s own
//!   `ClangNode` implementors). Since that marker trait declares zero methods, no caller can
//!   actually observe *which* object came back anyway, so the trait method returns a cheap
//!   placeholder handle instead. Callers reaching a node through the generic tree walk only ever
//!   need *a* value satisfying the marker trait, never this one specifically.

use std::sync::Arc;

use crate::app::decompiler::clang_node::ClangNode;
use crate::app::decompiler::clang_token_group::{ClangTokenGroup, ClangTokenGroupIter};
use crate::app::decompiler::token_iterator::TokenIterator;
use crate::program::model::address::Address;
use crate::program::model::pcode::{Decoder, DecoderException, HighFunction, PcodeFactory};

/// A grouping of source code tokens representing an entire function. Port of
/// `ghidra.app.decompiler.ClangFunction`.
pub struct ClangFunction {
    token_group: ClangTokenGroup,
    hfunc: Arc<dyn HighFunction>,
}

impl ClangFunction {
    /// Port of `ClangFunction(ClangNode, HighFunction)`.
    pub fn new(parent: Option<Arc<dyn ClangNode>>, hfunc: Arc<dyn HighFunction>) -> Self {
        Self {
            token_group: ClangTokenGroup::new(parent),
            hfunc,
        }
    }

    /// Port of `ClangFunction.getClangFunction()`. See the module docs for why this, not
    /// [`ClangNode::get_clang_function`], is the faithful counterpart of Java's `return this`.
    pub fn get_clang_function(&self) -> &ClangFunction {
        self
    }

    /// Port of `ClangFunction.getHighFunction()`.
    pub fn get_high_function(&self) -> Arc<dyn HighFunction> {
        self.hfunc.clone()
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

/// Zero-sized handle satisfying [`crate::app::seam_stubs::ClangFunction`]. See the module docs'
/// "`getClangFunction()`: two answers for two callers" section for why
/// [`ClangNode::get_clang_function`] returns this instead of a literal `self`.
struct ClangFunctionHandle;

impl crate::app::seam_stubs::ClangFunction for ClangFunctionHandle {}

impl ClangNode for ClangFunction {
    fn parent(&self) -> Option<&dyn ClangNode> {
        ClangFunction::parent(self)
    }

    fn get_min_address(&self) -> Option<Address> {
        ClangFunction::get_min_address(self)
    }

    fn get_max_address(&self) -> Option<Address> {
        ClangFunction::get_max_address(self)
    }

    fn num_children(&self) -> usize {
        ClangFunction::num_children(self)
    }

    fn child(&self, i: usize) -> &dyn ClangNode {
        ClangFunction::child(self, i)
    }

    fn get_clang_function(&self) -> Box<dyn crate::app::seam_stubs::ClangFunction> {
        Box::new(ClangFunctionHandle)
    }

    fn flatten<'a>(&'a self, list: &mut Vec<&'a dyn ClangNode>) {
        ClangFunction::flatten(self, list)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl std::fmt::Display for ClangFunction {
    /// Port of `ClangTokenGroup.toString()` (inherited).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.token_group)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::decompiler::clang_token::ClangTokenBase;
    use crate::program::model::listing::Function;
    use crate::program::model::lang::{CompilerSpec, Language};
    use crate::program::model::pcode::global_symbol_map::GlobalSymbolMap;
    use crate::program::model::pcode::{HighVariable, Varnode};
    use crate::program::seam_stubs::LocalSymbolMap;

    struct MockHighFunction {
        id: i64,
    }

    impl HighFunction for MockHighFunction {
        fn get_function(&self) -> Box<dyn Function> {
            unimplemented!("not exercised by these tests")
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }
        fn get_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by these tests")
        }
        fn get_local_symbol_map(&self) -> Box<dyn LocalSymbolMap> {
            unimplemented!("not exercised by these tests")
        }
        fn get_global_symbol_map(&self) -> Arc<dyn GlobalSymbolMap> {
            unimplemented!("not exercised by these tests")
        }
        fn grab_from_function(&mut self, _override_extrapop: i32, _include_default_names: bool, _do_override: bool) {
            unimplemented!("not exercised by these tests")
        }
        fn decode(
            &mut self,
            _decoder: &dyn Decoder,
        ) -> Result<(), DecoderException> {
            unimplemented!("not exercised by these tests")
        }
        fn split_out_merge_group(
            &mut self,
            _high: Box<dyn HighVariable>,
            _vn: &Varnode,
        ) -> Result<Box<dyn HighVariable>, crate::program::model::pcode::PcodeException> {
            unimplemented!("not exercised by these tests")
        }
        fn encode(
            &self,
            _encoder: &mut dyn crate::program::model::pcode::Encoder,
            _id: i64,
            _namespace: &dyn crate::program::model::symbol::Namespace,
            _entry_point: Option<Address>,
            _size: i32,
        ) -> std::io::Result<()> {
            unimplemented!("not exercised by these tests")
        }
        fn set_volatile(&mut self, _vn: &Varnode, _val: bool) {
            unimplemented!("not exercised by these tests")
        }
    }

    #[test]
    fn get_high_function_returns_the_constructed_function() {
        let hfunc: Arc<dyn HighFunction> = Arc::new(MockHighFunction { id: 42 });
        let func = ClangFunction::new(None, hfunc);
        assert_eq!(func.get_high_function().get_id(), 42);
    }

    #[test]
    fn inherent_get_clang_function_returns_self_by_identity() {
        let hfunc: Arc<dyn HighFunction> = Arc::new(MockHighFunction { id: 1 });
        let func = ClangFunction::new(None, hfunc);
        let back = func.get_clang_function();
        assert!(std::ptr::eq(back, &func));
    }

    #[test]
    fn delegates_add_token_group_and_address_tracking_to_the_inner_group() {
        let space = crate::program::model::address::AddressSpace::new(
            "ram",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            1,
        );
        let addr = |off: i64| Address::new(space.clone(), off);

        struct AddressedLeaf {
            min: Address,
            max: Address,
        }
        impl std::fmt::Display for AddressedLeaf {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "x")
            }
        }
        impl ClangNode for AddressedLeaf {
            fn parent(&self) -> Option<&dyn ClangNode> {
                None
            }
            fn get_min_address(&self) -> Option<Address> {
                Some(self.min.clone())
            }
            fn get_max_address(&self) -> Option<Address> {
                Some(self.max.clone())
            }
            fn num_children(&self) -> usize {
                0
            }
            fn child(&self, i: usize) -> &dyn ClangNode {
                panic!("no children, requested {i}")
            }
            fn get_clang_function(&self) -> Box<dyn crate::app::seam_stubs::ClangFunction> {
                unimplemented!("not exercised by this test")
            }
            fn flatten<'a>(&'a self, list: &mut Vec<&'a dyn ClangNode>) {
                list.push(self);
            }
            fn is_clang_token(&self) -> bool {
                true
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let hfunc: Arc<dyn HighFunction> = Arc::new(MockHighFunction { id: 7 });
        let mut func = ClangFunction::new(None, hfunc);
        func.add_token_group(Box::new(AddressedLeaf {
            min: addr(100),
            max: addr(200),
        }));
        func.add_token_group(Box::new(AddressedLeaf {
            min: addr(50),
            max: addr(150),
        }));

        assert_eq!(func.get_min_address(), Some(addr(50)));
        assert_eq!(func.get_max_address(), Some(addr(200)));
        assert_eq!(func.num_children(), 2);
    }

    #[test]
    fn token_iterator_and_display_delegate_to_the_inner_group() {
        let hfunc: Arc<dyn HighFunction> = Arc::new(MockHighFunction { id: 0 });
        let mut func = ClangFunction::new(None, hfunc);
        func.add_token_group(Box::new(ClangTokenBase::with_text(None, "int")));
        func.add_token_group(Box::new(ClangTokenBase::with_text(None, "x")));

        assert_eq!(func.to_string(), "int x");

        let forward: Vec<String> = func
            .token_iterator(true)
            .map(|n| n.to_string())
            .collect();
        assert_eq!(forward, vec!["int", "x"]);
    }

    /// Reached through `&dyn ClangNode` (e.g. as a `Parent()` link elsewhere in a tree), the
    /// trait method can't literally return `this` -- see the module docs. It still must return
    /// *something* satisfying the marker trait, and must not panic.
    #[test]
    fn trait_get_clang_function_returns_a_value_without_panicking() {
        let hfunc: Arc<dyn HighFunction> = Arc::new(MockHighFunction { id: 9 });
        let func = ClangFunction::new(None, hfunc);
        let node: &dyn ClangNode = &func;
        let _handle = node.get_clang_function();
    }
}
