use crate::program::model::address::factory::AddressFactory;
use crate::program::seam_stubs::{
    pcode_block_name_to_type, PcodeBlock, PCODE_BLOCK_BASIC, PCODE_BLOCK_COPY, PCODE_BLOCK_PLAIN,
};
use std::sync::Arc;

/// Resolves block-name/index bookkeeping while a [`BlockGraph`](crate::program::model::pcode::block_graph::BlockGraph)
/// tree is decoded, and defers goto-target resolution until an entire level (or the whole graph)
/// has been read.
///
/// Port of `ghidra.program.model.pcode.BlockMap`, promoted straight to a trait because it was
/// selected as a dependency-cycle cut-point (it and `BlockGraph`/`PcodeBlock` reference each
/// other through `decodeBody`/`decode`/`createBlock`).
///
/// The Java class holds four private fields: `factory` (shared, immutable after construction),
/// `sortlist` (the current decode level's blocks, fresh per instance), and `leaflist`/`gotoreflist`
/// (shared by reference with every level, via the `BlockMap(BlockMap op2)` copy constructor). That
/// aliasing can't be expressed through a single Rust field layout without dictating a concrete
/// implementation, so this trait instead exposes the same distinction through abstract list
/// accessors: `level_list_*` for the always-fresh `sortlist`, and `leaf_list_*`/`goto_ref_*` for
/// the lists a concrete `new_child` implementation must share (e.g. via a cloned `Rc<RefCell<_>>`
/// or `Arc<Mutex<_>>`) with every resolver descended from it. [`resolve_block`](BlockMap::resolve_block)
/// stands in for the private static `resolveBlock(int)`, which switches on the block type tag to
/// construct one of fifteen concrete `PcodeBlock` subclasses -- none of which are ported yet, so
/// building the actual instance is left to the implementation.
///
/// The algorithmic methods (`create_block`, `find_level_block`, `sort_level_list`, `add_goto_ref`,
/// `resolve_goto_references`) are default methods reproducing the Java bodies in terms of those
/// accessors and the [`PcodeBlock`] placeholder's `get_index`/`get_parent` and the new
/// `as_block_goto`/`as_block_if_goto`/`as_block_multi_goto` downcast helpers grown onto it for
/// this port (see `crate::program::seam_stubs`).
pub trait BlockMap {
    /// Stands in for `BlockMap.getAddressFactory()`.
    fn get_address_factory(&self) -> Arc<dyn AddressFactory>;

    /// Stands in for the private static `BlockMap.resolveBlock(int)`: construct a fresh, empty
    /// `PcodeBlock` instance matching the given type tag (one of the `PCODE_BLOCK_*` constants in
    /// `crate::program::seam_stubs`).
    fn resolve_block(&self, block_type: i32) -> Arc<dyn PcodeBlock>;

    /// Stands in for `new BlockMap(BlockMap parent)`: build a child resolver nested under this
    /// one. The implementation must share this resolver's leaf list and goto-reference list (not
    /// copy them) with the child, matching Java's by-reference field copy, while giving the child
    /// its own empty level list.
    fn new_child(&self) -> Box<dyn BlockMap>;

    /// Number of blocks currently in this level's list (the private `sortlist`).
    fn level_list_len(&self) -> usize;
    /// Stands in for `sortlist.get(i)`.
    fn level_list_get(&self, i: usize) -> Arc<dyn PcodeBlock>;
    /// Stands in for `sortlist.add(block)`.
    fn level_list_push(&self, block: Arc<dyn PcodeBlock>);
    /// Replaces the level list's contents/order, used to commit a sort back to storage.
    fn level_list_set(&self, blocks: Vec<Arc<dyn PcodeBlock>>);

    /// Number of blocks in the (possibly shared) leaf list.
    fn leaf_list_len(&self) -> usize;
    /// Stands in for `leaflist.get(i)`.
    fn leaf_list_get(&self, i: usize) -> Arc<dyn PcodeBlock>;
    /// Stands in for `leaflist.add(block)`.
    fn leaf_list_push(&self, block: Arc<dyn PcodeBlock>);
    /// Replaces the leaf list's contents/order, used to commit a sort back to storage.
    fn leaf_list_set(&self, blocks: Vec<Arc<dyn PcodeBlock>>);

    /// Number of pending goto references (the private `gotoreflist`).
    fn goto_ref_len(&self) -> usize;
    /// Stands in for `gotoreflist.get(i)`, returning `(gotoblock, rootindex, depth)`.
    fn goto_ref_get(&self, i: usize) -> (Arc<dyn PcodeBlock>, i32, i32);
    /// Stands in for `gotoreflist.add(new GotoReference(gblock, root, depth))`.
    fn goto_ref_push(&self, gotoblock: Arc<dyn PcodeBlock>, root_index: i32, depth: i32);

    /// Assume blocks are in index order, find the block with index `ind`.
    ///
    /// Port of `BlockMap.findLevelBlock(int)`.
    fn find_level_block(&self, ind: i32) -> Option<Arc<dyn PcodeBlock>> {
        let len = self.level_list_len();
        let snapshot: Vec<Arc<dyn PcodeBlock>> = (0..len).map(|i| self.level_list_get(i)).collect();
        find_block(&snapshot, ind)
    }

    /// Port of `BlockMap.sortLevelList()`.
    fn sort_level_list(&self) {
        let len = self.level_list_len();
        let mut snapshot: Vec<Arc<dyn PcodeBlock>> = (0..len).map(|i| self.level_list_get(i)).collect();
        snapshot.sort_by_key(|b| b.get_index());
        self.level_list_set(snapshot);
    }

    /// Port of `BlockMap.createBlock(String, int)`.
    fn create_block(&self, name: &str, index: i32) -> Arc<dyn PcodeBlock> {
        let btype = pcode_block_name_to_type(name);
        let res = self.resolve_block(btype);
        res.set_index(index);
        self.level_list_push(res.clone());
        if btype == PCODE_BLOCK_PLAIN || btype == PCODE_BLOCK_COPY || btype == PCODE_BLOCK_BASIC {
            self.leaf_list_push(res.clone());
        }
        res
    }

    /// Port of `BlockMap.addGotoRef(PcodeBlock, int, int)`.
    fn add_goto_ref(&self, gotoblock: Arc<dyn PcodeBlock>, root: i32, depth: i32) {
        self.goto_ref_push(gotoblock, root, depth);
    }

    /// Resolve every pending goto reference against the (now complete) leaf list.
    ///
    /// Port of `BlockMap.resolveGotoReferences()`.
    fn resolve_goto_references(&self) {
        let leaf_len = self.leaf_list_len();
        let mut leaves: Vec<Arc<dyn PcodeBlock>> =
            (0..leaf_len).map(|i| self.leaf_list_get(i)).collect();
        leaves.sort_by_key(|b| b.get_index());
        self.leaf_list_set(leaves.clone());

        for i in 0..self.goto_ref_len() {
            let (gotoblock, root_index, depth) = self.goto_ref_get(i);
            let mut bl = find_block(&leaves, root_index);
            let mut remaining = depth;
            while remaining > 0 {
                remaining -= 1;
                bl = bl.and_then(|b| b.get_parent());
            }
            let Some(bl) = bl else {
                continue;
            };
            if let Some(g) = gotoblock.as_block_goto() {
                g.set_goto_target(bl);
            } else if let Some(g) = gotoblock.as_block_if_goto() {
                g.set_goto_target(bl);
            } else if let Some(g) = gotoblock.as_block_multi_goto() {
                g.add_goto_target(bl);
            }
        }
    }
}

/// Stands in for the private static `BlockMap.findBlock(ArrayList<PcodeBlock>, int)`: binary
/// search a list assumed to be sorted in index order for the block with index `ind`.
fn find_block(list: &[Arc<dyn PcodeBlock>], ind: i32) -> Option<Arc<dyn PcodeBlock>> {
    let mut min: i64 = 0;
    let mut max: i64 = list.len() as i64 - 1;
    while min <= max {
        let mid = ((min + max) / 2) as usize;
        let block = &list[mid];
        let block_index = block.get_index();
        if block_index == ind {
            return Some(block.clone());
        }
        if block_index < ind {
            min = mid as i64 + 1;
        } else {
            max = mid as i64 - 1;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use crate::program::seam_stubs::{
        BlockGoto, PCODE_BLOCK_BASIC, PCODE_BLOCK_GOTO, PCODE_BLOCK_IFGOTO, PCODE_BLOCK_MULTIGOTO,
    };
    use std::cell::{Cell, RefCell};

    struct MockLeaf {
        index: Cell<i32>,
        block_type: i32,
        parent: RefCell<Option<Arc<dyn PcodeBlock>>>,
    }

    impl MockLeaf {
        fn new(index: i32, block_type: i32) -> Arc<MockLeaf> {
            Arc::new(MockLeaf {
                index: Cell::new(index),
                block_type,
                parent: RefCell::new(None),
            })
        }
    }

    impl PcodeBlock for MockLeaf {
        fn get_index(&self) -> i32 {
            self.index.get()
        }
        fn set_index(&self, index: i32) {
            self.index.set(index);
        }
        fn get_block_type(&self) -> i32 {
            self.block_type
        }
        fn add_in_edge(&self, _begin: Arc<dyn PcodeBlock>, _label: i32) {}
        fn encode(&self, _encoder: &mut dyn crate::program::model::pcode::encoder::Encoder) -> std::io::Result<()> {
            Ok(())
        }
        fn decode(
            &self,
            _decoder: &dyn crate::program::model::pcode::decoder::Decoder,
            _resolver: &dyn BlockMap,
        ) -> Result<(), crate::program::model::pcode::decoder_exception::DecoderException> {
            Ok(())
        }
        fn get_parent(&self) -> Option<Arc<dyn PcodeBlock>> {
            self.parent.borrow().clone()
        }
    }

    struct MockGotoLeaf {
        index: Cell<i32>,
        target: RefCell<Option<Arc<dyn PcodeBlock>>>,
    }

    impl MockGotoLeaf {
        fn new(index: i32) -> Arc<MockGotoLeaf> {
            Arc::new(MockGotoLeaf {
                index: Cell::new(index),
                target: RefCell::new(None),
            })
        }
    }

    impl PcodeBlock for MockGotoLeaf {
        fn get_index(&self) -> i32 {
            self.index.get()
        }
        fn set_index(&self, index: i32) {
            self.index.set(index);
        }
        fn get_block_type(&self) -> i32 {
            PCODE_BLOCK_GOTO
        }
        fn add_in_edge(&self, _begin: Arc<dyn PcodeBlock>, _label: i32) {}
        fn encode(&self, _encoder: &mut dyn crate::program::model::pcode::encoder::Encoder) -> std::io::Result<()> {
            Ok(())
        }
        fn decode(
            &self,
            _decoder: &dyn crate::program::model::pcode::decoder::Decoder,
            _resolver: &dyn BlockMap,
        ) -> Result<(), crate::program::model::pcode::decoder_exception::DecoderException> {
            Ok(())
        }
        fn as_block_goto(&self) -> Option<&dyn BlockGoto> {
            Some(self)
        }
    }

    impl BlockGoto for MockGotoLeaf {
        fn set_goto_target(&self, target: Arc<dyn PcodeBlock>) {
            *self.target.borrow_mut() = Some(target);
        }
    }

    struct MockBlockMap {
        factory: Arc<dyn AddressFactory>,
        level_list: RefCell<Vec<Arc<dyn PcodeBlock>>>,
        leaf_list: Arc<RefCell<Vec<Arc<dyn PcodeBlock>>>>,
        goto_refs: Arc<RefCell<Vec<(Arc<dyn PcodeBlock>, i32, i32)>>>,
    }

    impl MockBlockMap {
        fn new(factory: Arc<dyn AddressFactory>) -> Self {
            Self {
                factory,
                level_list: RefCell::new(Vec::new()),
                leaf_list: Arc::new(RefCell::new(Vec::new())),
                goto_refs: Arc::new(RefCell::new(Vec::new())),
            }
        }
    }

    impl BlockMap for MockBlockMap {
        fn get_address_factory(&self) -> Arc<dyn AddressFactory> {
            self.factory.clone()
        }

        fn resolve_block(&self, block_type: i32) -> Arc<dyn PcodeBlock> {
            match block_type {
                PCODE_BLOCK_GOTO | PCODE_BLOCK_IFGOTO | PCODE_BLOCK_MULTIGOTO => {
                    MockGotoLeaf::new(0)
                }
                _ => MockLeaf::new(0, block_type),
            }
        }

        fn new_child(&self) -> Box<dyn BlockMap> {
            Box::new(MockBlockMap {
                factory: self.factory.clone(),
                level_list: RefCell::new(Vec::new()),
                leaf_list: self.leaf_list.clone(),
                goto_refs: self.goto_refs.clone(),
            })
        }

        fn level_list_len(&self) -> usize {
            self.level_list.borrow().len()
        }
        fn level_list_get(&self, i: usize) -> Arc<dyn PcodeBlock> {
            self.level_list.borrow()[i].clone()
        }
        fn level_list_push(&self, block: Arc<dyn PcodeBlock>) {
            self.level_list.borrow_mut().push(block);
        }
        fn level_list_set(&self, blocks: Vec<Arc<dyn PcodeBlock>>) {
            *self.level_list.borrow_mut() = blocks;
        }

        fn leaf_list_len(&self) -> usize {
            self.leaf_list.borrow().len()
        }
        fn leaf_list_get(&self, i: usize) -> Arc<dyn PcodeBlock> {
            self.leaf_list.borrow()[i].clone()
        }
        fn leaf_list_push(&self, block: Arc<dyn PcodeBlock>) {
            self.leaf_list.borrow_mut().push(block);
        }
        fn leaf_list_set(&self, blocks: Vec<Arc<dyn PcodeBlock>>) {
            *self.leaf_list.borrow_mut() = blocks;
        }

        fn goto_ref_len(&self) -> usize {
            self.goto_refs.borrow().len()
        }
        fn goto_ref_get(&self, i: usize) -> (Arc<dyn PcodeBlock>, i32, i32) {
            self.goto_refs.borrow()[i].clone()
        }
        fn goto_ref_push(&self, gotoblock: Arc<dyn PcodeBlock>, root_index: i32, depth: i32) {
            self.goto_refs.borrow_mut().push((gotoblock, root_index, depth));
        }
    }

    fn address_factory() -> Arc<dyn AddressFactory> {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        Arc::new(DefaultAddressFactory::new(vec![ram]))
    }

    #[test]
    fn usable_as_trait_object() {
        let map = MockBlockMap::new(address_factory());
        let dyn_map: &dyn BlockMap = &map;
        assert_eq!(dyn_map.level_list_len(), 0);
    }

    #[test]
    fn create_block_resolves_type_and_tracks_leaves() {
        let map = MockBlockMap::new(address_factory());
        let basic = map.create_block("basic", 7);
        // "basic" is unreachable via nameToType (matches the real Java gap: PcodeBlock.nameToType
        // has no 'b' case and returns -1), so resolve_block falls through to the unresolved
        // sentinel type -1 rather than PCODE_BLOCK_BASIC.
        assert_eq!(basic.get_block_type(), -1);
        assert_eq!(basic.get_index(), 7);
        // Because "basic" did not resolve, it should NOT be added to the leaf list; only
        // "plain"/"copy" round-trip through createBlock as leaves.
        assert_eq!(map.leaf_list_len(), 0);

        let plain = map.create_block("plain", 9);
        assert_eq!(plain.get_block_type(), crate::program::seam_stubs::PCODE_BLOCK_PLAIN);
        assert_eq!(map.leaf_list_len(), 1);
        assert_eq!(map.level_list_len(), 2);
    }

    #[test]
    fn find_level_block_binary_searches_sorted_list() {
        let map = MockBlockMap::new(address_factory());
        map.level_list_push(MockLeaf::new(30, PCODE_BLOCK_BASIC));
        map.level_list_push(MockLeaf::new(10, PCODE_BLOCK_BASIC));
        map.level_list_push(MockLeaf::new(20, PCODE_BLOCK_BASIC));

        map.sort_level_list();
        assert_eq!(map.level_list_get(0).get_index(), 10);
        assert_eq!(map.level_list_get(1).get_index(), 20);
        assert_eq!(map.level_list_get(2).get_index(), 30);

        assert_eq!(map.find_level_block(20).unwrap().get_index(), 20);
        assert!(map.find_level_block(99).is_none());
    }

    #[test]
    fn new_child_shares_leaf_and_goto_lists_but_not_level_list() {
        let parent = MockBlockMap::new(address_factory());
        parent.level_list_push(MockLeaf::new(1, PCODE_BLOCK_BASIC));
        parent.leaf_list_push(MockLeaf::new(1, PCODE_BLOCK_BASIC));

        let child = parent.new_child();
        assert_eq!(child.level_list_len(), 0);
        assert_eq!(child.leaf_list_len(), 1);

        child.leaf_list_push(MockLeaf::new(2, PCODE_BLOCK_BASIC));
        // Leaf list is shared by reference, like Java's `leaflist = op2.leaflist`.
        assert_eq!(parent.leaf_list_len(), 2);
    }

    #[test]
    fn resolve_goto_references_walks_parent_chain_by_depth() {
        let map = MockBlockMap::new(address_factory());
        let root = MockLeaf::new(0, PCODE_BLOCK_BASIC);
        let mid = MockLeaf::new(1, PCODE_BLOCK_BASIC);
        *mid.parent.borrow_mut() = Some(root.clone() as Arc<dyn PcodeBlock>);
        let leaf = MockLeaf::new(2, PCODE_BLOCK_BASIC);
        *leaf.parent.borrow_mut() = Some(mid.clone() as Arc<dyn PcodeBlock>);

        map.leaf_list_push(leaf.clone());

        let goto_block = MockGotoLeaf::new(99);
        map.add_goto_ref(goto_block.clone(), 2, 2);

        map.resolve_goto_references();

        let target = goto_block.target.borrow().clone().expect("target resolved");
        assert_eq!(target.get_index(), root.get_index());
    }
}
