use crate::program::model::address::Address;
use crate::program::model::pcode::block_map::BlockMap;
use crate::program::model::pcode::decoder::{Decoder, DecoderError};
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{
    ATTRIB_FIRST, ATTRIB_LAST, ATTRIB_SPACE, ELEM_RANGE, ELEM_RANGELIST,
};
use crate::program::model::pcode::list_linked::LinkedIter;
use crate::program::seam_stubs::{PcodeBlock, PcodeOpAst};
use std::io;
use std::sync::Arc;

/// A basic block constructed from PcodeOps.
///
/// Port of `ghidra.program.model.pcode.PcodeBlockBasic`, promoted straight to a trait because it
/// was selected as a dependency-cycle cut-point.
///
/// The Java class `extends PcodeBlock`, which is not yet ported; see the
/// [`PcodeBlock`](crate::program::seam_stubs::PcodeBlock) placeholder (declared as this trait's
/// supertrait bound) for what is stubbed out and why. Each stored `PcodeOp` is actually a
/// `PcodeOpAST` at runtime (Java downcasts on every insert/remove to set/read the op's parent
/// block and its position within this block's op list); `PcodeOpAST` is not yet ported either, so
/// it is likewise stubbed as [`PcodeOpAst`](crate::program::seam_stubs::PcodeOpAst) in
/// `crate::program::seam_stubs`.
///
/// Private field state is exposed as abstract accessor methods that a concrete implementation
/// supplies, mirroring this crate's existing convention for the same issue (see
/// [`BlockGraph`](crate::program::model::pcode::block_graph::BlockGraph)'s module docs):
/// [`get_address_ranges`](PcodeBlockBasic::get_address_ranges) and
/// [`add_range`](PcodeBlockBasic::add_range) stand in for the private `cover` field (an
/// `AddressSet`, not yet ported), so that [`basic_encode_body`](PcodeBlockBasic::basic_encode_body)
/// and [`basic_decode_body`](PcodeBlockBasic::basic_decode_body) can reproduce the real
/// `encodeBody`/`decodeBody` algorithms as default methods. The private `oplist` field (a
/// `ListLinked`, already ported at [`crate::program::model::pcode::list_linked`]) is not a
/// placeholder, so it is instead threaded through the API directly via [`LinkedIter`] cursors.
///
/// [`basic_encode_body`](PcodeBlockBasic::basic_encode_body)/
/// [`basic_decode_body`](PcodeBlockBasic::basic_decode_body) are exposed under `basic_`-prefixed
/// names instead of `encode_body`/`decode_body` since [`PcodeBlock`] already declares those names
/// (Rust does not allow a subtrait to re-declare a supertrait method under the same name),
/// matching this crate's existing convention for the same issue (see `BlockGraph`'s module docs).
///
/// `basic_encode_body` never closes the `ELEM_RANGE` element it opens for each range -- it only
/// closes `ELEM_RANGELIST` at the end -- matching `PcodeBlockBasic.encodeBody`'s Java source
/// exactly; that asymmetry is preserved as-is rather than "fixed", since this is a straight
/// behavioral port.
///
/// The write-only self-parent assignment (`opast.setParent(this)` in `insertBefore`/`insertAfter`/
/// `insertEnd`) is not modeled here for the same reason `BlockGraph`'s parent back-pointer isn't:
/// producing an `Arc<dyn PcodeBlockBasic>` that refers to `self` from a `&self` method needs the
/// concrete implementation's own ownership model (e.g. a `Weak`/self-referential handle set up at
/// construction time), not something this trait can supply generically.
pub trait PcodeBlockBasic: PcodeBlock {
    /// The starting address of this basic block, i.e. the address of the first instruction
    /// covered by the block.
    ///
    /// Port of the `PcodeBlock.getStart()` override.
    fn get_start(&self) -> Address;

    /// The ending address of this basic block, i.e. the address of the last instruction covered
    /// by the block.
    ///
    /// Port of the `PcodeBlock.getStop()` override.
    fn get_stop(&self) -> Address;

    /// Is the given address in the range of instructions represented by this basic block.
    ///
    /// Port of `PcodeBlockBasic.contains(Address)`.
    fn contains(&self, addr: &Address) -> bool;

    /// Stands in for the private `cover` field's range enumeration
    /// (`cover.getAddressRanges(true)`), returning each covered range as an inclusive
    /// `(start, stop)` address pair. See this trait's module docs for why this accessor exists.
    fn get_address_ranges(&self) -> Vec<(Address, Address)>;

    /// Stands in for the private `cover` field's range insertion (`cover.addRange(Address,
    /// Address)`). See this trait's module docs for why this accessor exists.
    fn add_range(&self, start: Address, stop: Address);

    /// Insert a new PcodeOp before a specific point in the list of PcodeOps.
    ///
    /// Port of the protected `PcodeBlockBasic.insertBefore(Iterator<PcodeOp>, PcodeOp)`.
    fn insert_before(&self, iter: &LinkedIter, op: Arc<dyn PcodeOpAst>);

    /// Insert a new PcodeOp after a specific point in the list of PcodeOps.
    ///
    /// Port of the protected `PcodeBlockBasic.insertAfter(Iterator<PcodeOp>, PcodeOp)`.
    fn insert_after(&self, iter: &LinkedIter, op: Arc<dyn PcodeOpAst>);

    /// Insert a PcodeOp at the end of the block.
    ///
    /// Port of the protected `PcodeBlockBasic.insertEnd(PcodeOp)`.
    fn insert_end(&self, op: Arc<dyn PcodeOpAst>);

    /// Remove a PcodeOp from the block.
    ///
    /// Port of the protected `PcodeBlockBasic.remove(PcodeOp)`.
    fn remove(&self, op: Arc<dyn PcodeOpAst>);

    /// An iterator, positioned before the first element, over the PcodeOps in this basic block.
    ///
    /// Port of `PcodeBlockBasic.getIterator()`.
    fn get_iterator(&self) -> LinkedIter;

    /// The first PcodeOp in this block, or `None` if the block is empty.
    ///
    /// Port of `PcodeBlockBasic.getFirstOp()`.
    fn get_first_op(&self) -> Option<Arc<dyn PcodeOpAst>>;

    /// The last PcodeOp in this block, or `None` if the block is empty.
    ///
    /// Port of `PcodeBlockBasic.getLastOp()`.
    fn get_last_op(&self) -> Option<Arc<dyn PcodeOpAst>>;

    /// Encode this basic block's address coverage.
    ///
    /// Port of the protected `PcodeBlockBasic.encodeBody(Encoder)` override. See this trait's
    /// module docs for the naming and the deliberately-unclosed `ELEM_RANGE` element.
    fn basic_encode_body(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_RANGELIST)?;
        for (start, stop) in self.get_address_ranges() {
            encoder.open_element(ELEM_RANGE)?;
            encoder.write_space(ATTRIB_SPACE, start.space())?;
            encoder.write_unsigned_integer(ATTRIB_FIRST, start.offset() as u64)?;
            encoder.write_unsigned_integer(ATTRIB_LAST, stop.offset() as u64)?;
        }
        encoder.close_element(ELEM_RANGELIST)
    }

    /// Decode this basic block's address coverage.
    ///
    /// Port of the protected `PcodeBlockBasic.decodeBody(Decoder, BlockMap)` override. The
    /// `resolver` parameter is unused, matching the Java source (it is present only because the
    /// signature must match the abstract `PcodeBlock.decodeBody` it overrides).
    fn basic_decode_body(
        &self,
        decoder: &dyn Decoder,
        _resolver: &dyn BlockMap,
    ) -> Result<(), DecoderException> {
        let rangelistel = decoder
            .open_element_with_id(ELEM_RANGELIST)
            .map_err(decode_err)?;
        loop {
            let rangeel = decoder.peek_element().map_err(decode_err)?;
            if rangeel != ELEM_RANGE.id {
                break;
            }
            decoder.open_element().map_err(decode_err)?;
            let address_space = decoder
                .read_space_with_id(ATTRIB_SPACE)
                .map_err(decode_err)?;
            let offset = decoder
                .read_unsigned_integer_with_id(ATTRIB_FIRST)
                .map_err(decode_err)?;
            let start = address_space.address(offset as i64);
            let offset = decoder
                .read_unsigned_integer_with_id(ATTRIB_LAST)
                .map_err(decode_err)?;
            let stop = address_space.address(offset as i64);
            self.add_range(start, stop);
            decoder.close_element(rangeel).map_err(decode_err)?;
        }
        decoder.close_element(rangelistel).map_err(decode_err)
    }
}

fn decode_err(e: DecoderError) -> DecoderException {
    DecoderException::with_cause("failed to decode PcodeBlockBasic", e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::factory::AddressFactory;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::ids::AttributeId;
    use crate::program::model::pcode::ids::ElementId;
    use crate::program::model::pcode::list_linked::ListLinked;
    use crate::program::seam_stubs::PCODE_BLOCK_BASIC;
    use std::cell::{Cell, RefCell};

    struct MockOp {
        label: &'static str,
        parent: RefCell<Option<Arc<dyn PcodeBlockBasic>>>,
        basic_iter: RefCell<Option<LinkedIter>>,
    }

    impl MockOp {
        fn new(label: &'static str) -> Arc<MockOp> {
            Arc::new(MockOp {
                label,
                parent: RefCell::new(None),
                basic_iter: RefCell::new(None),
            })
        }
    }

    impl PcodeOpAst for MockOp {
        fn set_parent(&self, parent: Option<Arc<dyn PcodeBlockBasic>>) {
            *self.parent.borrow_mut() = parent;
        }
        fn set_basic_iter(&self, iter: LinkedIter) {
            *self.basic_iter.borrow_mut() = Some(iter);
        }
        fn get_basic_iter(&self) -> LinkedIter {
            self.basic_iter.borrow().expect("basic iter not set")
        }
    }

    struct MockBlock {
        index: Cell<i32>,
        ranges: RefCell<Vec<(Address, Address)>>,
        oplist: ListLinked<Arc<dyn PcodeOpAst>>,
        self_ref: RefCell<Option<Arc<dyn PcodeBlockBasic>>>,
    }

    impl MockBlock {
        fn new() -> Arc<MockBlock> {
            let block = Arc::new(MockBlock {
                index: Cell::new(0),
                ranges: RefCell::new(Vec::new()),
                oplist: ListLinked::new(),
                self_ref: RefCell::new(None),
            });
            *block.self_ref.borrow_mut() = Some(block.clone() as Arc<dyn PcodeBlockBasic>);
            block
        }
    }

    impl PcodeBlock for MockBlock {
        fn get_index(&self) -> i32 {
            self.index.get()
        }
        fn set_index(&self, index: i32) {
            self.index.set(index);
        }
        fn get_block_type(&self) -> i32 {
            PCODE_BLOCK_BASIC
        }
        fn add_in_edge(&self, _begin: Arc<dyn PcodeBlock>, _label: i32) {}
        fn encode(&self, _encoder: &mut dyn Encoder) -> io::Result<()> {
            Ok(())
        }
        fn decode(
            &self,
            _decoder: &dyn Decoder,
            _resolver: &dyn BlockMap,
        ) -> Result<(), DecoderException> {
            Ok(())
        }
    }

    impl PcodeBlockBasic for MockBlock {
        fn get_start(&self) -> Address {
            self.ranges
                .borrow()
                .iter()
                .map(|(start, _)| start.clone())
                .min()
                .expect("block has no ranges")
        }

        fn get_stop(&self) -> Address {
            self.ranges
                .borrow()
                .iter()
                .map(|(_, stop)| stop.clone())
                .max()
                .expect("block has no ranges")
        }

        fn contains(&self, addr: &Address) -> bool {
            self.ranges.borrow().iter().any(|(start, stop)| {
                start.space().space_id() == addr.space().space_id()
                    && addr.offset() >= start.offset()
                    && addr.offset() <= stop.offset()
            })
        }

        fn get_address_ranges(&self) -> Vec<(Address, Address)> {
            self.ranges.borrow().clone()
        }

        fn add_range(&self, start: Address, stop: Address) {
            self.ranges.borrow_mut().push((start, stop));
        }

        fn insert_before(&self, iter: &LinkedIter, op: Arc<dyn PcodeOpAst>) {
            op.set_parent(self.self_ref.borrow().clone());
            let newiter = self.oplist.insert_before(iter, op.clone());
            op.set_basic_iter(newiter);
        }

        fn insert_after(&self, iter: &LinkedIter, op: Arc<dyn PcodeOpAst>) {
            op.set_parent(self.self_ref.borrow().clone());
            let newiter = self.oplist.insert_after(iter, op.clone());
            op.set_basic_iter(newiter);
        }

        fn insert_end(&self, op: Arc<dyn PcodeOpAst>) {
            op.set_parent(self.self_ref.borrow().clone());
            let newiter = self.oplist.add(op.clone());
            op.set_basic_iter(newiter);
        }

        fn remove(&self, op: Arc<dyn PcodeOpAst>) {
            op.set_parent(None);
            self.oplist.remove(&op.get_basic_iter());
        }

        fn get_iterator(&self) -> LinkedIter {
            self.oplist.iterator()
        }

        fn get_first_op(&self) -> Option<Arc<dyn PcodeOpAst>> {
            self.oplist.first().map(|op| op.clone())
        }

        fn get_last_op(&self) -> Option<Arc<dyn PcodeOpAst>> {
            self.oplist.last().map(|op| op.clone())
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    /// Identity comparison against a known [`MockOp`], since [`PcodeOpAst`] doesn't (and
    /// shouldn't) expose `Any` downcasting.
    fn same_op(a: &Arc<dyn PcodeOpAst>, expected: &Arc<MockOp>) -> bool {
        Arc::ptr_eq(a, &(expected.clone() as Arc<dyn PcodeOpAst>))
    }

    fn is_op(candidate: &Option<Arc<dyn PcodeOpAst>>, expected: &Arc<MockOp>) -> bool {
        match candidate {
            Some(op) => same_op(op, expected),
            None => false,
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let block = MockBlock::new();
        let dyn_block: &dyn PcodeBlockBasic = &*block;
        assert_eq!(dyn_block.get_index(), 0);
        assert_eq!(dyn_block.get_block_type(), PCODE_BLOCK_BASIC);
    }

    #[test]
    fn insert_end_and_iteration_match_java_list_order() {
        let block = MockBlock::new();
        let op1 = MockOp::new("op1");
        let op2 = MockOp::new("op2");

        block.insert_end(op1.clone());
        block.insert_end(op2.clone());

        assert!(is_op(&block.get_first_op(), &op1));
        assert!(is_op(&block.get_last_op(), &op2));

        // op.setParent(this) should have been recorded for each inserted op.
        assert!(op1.parent.borrow().is_some());
        assert!(op2.parent.borrow().is_some());

        let mut cursor = block.get_iterator();
        let mut seen = Vec::new();
        while block.oplist.has_next(&cursor) {
            let val = block.oplist.next_val(&mut cursor).unwrap();
            seen.push(val.clone());
        }
        assert_eq!(seen.len(), 2);
        assert!(same_op(&seen[0], &op1));
        assert!(same_op(&seen[1], &op2));
    }

    #[test]
    fn insert_before_places_op_ahead_of_cursor_target() {
        let block = MockBlock::new();
        let op1 = MockOp::new("op1");
        let op3 = MockOp::new("op3");
        block.insert_end(op1.clone());
        block.insert_end(op3.clone());

        let op2 = MockOp::new("op2");
        // op3's own basic-iter cursor now points at its node; inserting "before" it should land
        // op2 between op1 and op3.
        block.insert_before(&op3.get_basic_iter(), op2.clone());

        let mut cursor = block.get_iterator();
        let mut seen = Vec::new();
        while block.oplist.has_next(&cursor) {
            let val = block.oplist.next_val(&mut cursor).unwrap();
            seen.push(val.clone());
        }
        assert_eq!(seen.len(), 3);
        assert!(same_op(&seen[0], &op1));
        assert!(same_op(&seen[1], &op2));
        assert!(same_op(&seen[2], &op3));
    }

    #[test]
    fn remove_detaches_parent_and_updates_first_op() {
        let block = MockBlock::new();
        let op1 = MockOp::new("op1");
        let op2 = MockOp::new("op2");
        block.insert_end(op1.clone());
        block.insert_end(op2.clone());

        block.remove(op1.clone());

        assert!(op1.parent.borrow().is_none());
        assert!(is_op(&block.get_first_op(), &op2));
        assert!(is_op(&block.get_last_op(), &op2));
    }

    #[test]
    fn contains_and_start_stop_reflect_added_ranges_like_java_cover() {
        let ram = ram_space();
        let block = MockBlock::new();
        block.add_range(Address::new(ram.clone(), 0x1000), Address::new(ram.clone(), 0x100f));
        block.add_range(Address::new(ram.clone(), 0x2000), Address::new(ram.clone(), 0x200f));

        assert_eq!(block.get_start(), Address::new(ram.clone(), 0x1000));
        assert_eq!(block.get_stop(), Address::new(ram.clone(), 0x200f));
        assert!(block.contains(&Address::new(ram.clone(), 0x1008)));
        assert!(block.contains(&Address::new(ram.clone(), 0x2000)));
        assert!(!block.contains(&Address::new(ram.clone(), 0x1500)));
    }

    #[derive(Default)]
    struct MockEncoder {
        writes: Vec<String>,
    }

    impl Encoder for MockEncoder {
        fn open_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.writes.push(format!("open:{}", elem_id.name));
            Ok(())
        }
        fn close_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.writes.push(format!("close:{}", elem_id.name));
            Ok(())
        }
        fn write_bool(&mut self, _attrib_id: AttributeId, _val: bool) -> io::Result<()> {
            Ok(())
        }
        fn write_signed_integer(&mut self, _attrib_id: AttributeId, _val: i64) -> io::Result<()> {
            Ok(())
        }
        fn write_unsigned_integer(&mut self, attrib_id: AttributeId, val: u64) -> io::Result<()> {
            self.writes.push(format!("uint:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_string(&mut self, _attrib_id: AttributeId, _val: &str) -> io::Result<()> {
            Ok(())
        }
        fn write_string_indexed(
            &mut self,
            _attrib_id: AttributeId,
            _index: i32,
            _val: &str,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_space(&mut self, attrib_id: AttributeId, spc: &AddressSpace) -> io::Result<()> {
            self.writes
                .push(format!("space:{}={}", attrib_id.name, spc.name()));
            Ok(())
        }
        fn write_space_indexed(
            &mut self,
            _attrib_id: AttributeId,
            _index: i32,
            _name: &str,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_opcode(
            &mut self,
            _attrib_id: AttributeId,
            _opcode: crate::decompiler::opcodes::op_code::OpCode,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_opcode_ordinal(&mut self, _attrib_id: AttributeId, _opcode: i32) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn basic_encode_body_never_closes_range_matching_java_source() {
        let ram = ram_space();
        let block = MockBlock::new();
        block.add_range(Address::new(ram.clone(), 0x1000), Address::new(ram.clone(), 0x100f));
        block.add_range(Address::new(ram.clone(), 0x2000), Address::new(ram.clone(), 0x200f));

        let mut encoder = MockEncoder::default();
        block.basic_encode_body(&mut encoder).unwrap();

        assert_eq!(
            encoder.writes,
            vec![
                "open:rangelist".to_string(),
                "open:range".to_string(),
                "space:space=ram".to_string(),
                "uint:first=4096".to_string(),
                "uint:last=4111".to_string(),
                "open:range".to_string(),
                "space:space=ram".to_string(),
                "uint:first=8192".to_string(),
                "uint:last=8207".to_string(),
                "close:rangelist".to_string(),
            ]
        );
    }

    /// Feeds `basic_decode_body` a canned sequence of `(first, last)` offsets on a single address
    /// space, mirroring the `<rangelist><range .../><range .../></rangelist>` structure
    /// `basic_encode_body` (and the real `PcodeBlockBasic.encodeBody`) would have written.
    struct MockRangeDecoder {
        space: Arc<AddressSpace>,
        ranges: Vec<(u64, u64)>,
        pos: std::sync::atomic::AtomicUsize,
    }

    impl Decoder for MockRangeDecoder {
        fn get_address_factory(&self) -> Arc<dyn AddressFactory> {
            unimplemented!()
        }
        fn set_address_factory(&self, _factory: Arc<dyn AddressFactory>) {}
        fn peek_element(&self) -> Result<i32, DecoderError> {
            if self.pos.load(std::sync::atomic::Ordering::SeqCst) < self.ranges.len() {
                Ok(ELEM_RANGE.id)
            } else {
                Ok(ELEM_RANGELIST.id)
            }
        }
        fn open_element(&self) -> Result<i32, DecoderError> {
            Ok(ELEM_RANGE.id)
        }
        fn open_element_with_id(&self, _elem_id: ElementId) -> Result<i32, DecoderError> {
            Ok(ELEM_RANGELIST.id)
        }
        fn close_element(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }
        fn close_element_skipping(&self, _id: i32) -> Result<(), DecoderError> {
            unimplemented!()
        }
        fn get_next_attribute_id(&self) -> Result<i32, DecoderError> {
            unimplemented!()
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
        fn read_signed_integer_with_id(&self, _attrib_id: AttributeId) -> Result<i64, DecoderError> {
            unimplemented!()
        }
        fn read_unsigned_integer(&self) -> Result<u64, DecoderError> {
            unimplemented!()
        }
        fn read_unsigned_integer_with_id(
            &self,
            attrib_id: AttributeId,
        ) -> Result<u64, DecoderError> {
            let (first, last) = self.ranges[self.pos.load(std::sync::atomic::Ordering::SeqCst)];
            if attrib_id.name == ATTRIB_FIRST.name {
                Ok(first)
            } else {
                self.pos.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(last)
            }
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
            Ok(self.space.clone())
        }
    }

    struct UnusedBlockMap;
    impl BlockMap for UnusedBlockMap {
        fn get_address_factory(&self) -> Arc<dyn AddressFactory> {
            unimplemented!()
        }
        fn resolve_block(&self, _block_type: i32) -> Arc<dyn PcodeBlock> {
            unimplemented!()
        }
        fn new_child(&self) -> Box<dyn BlockMap> {
            unimplemented!()
        }
        fn level_list_len(&self) -> usize {
            unimplemented!()
        }
        fn level_list_get(&self, _i: usize) -> Arc<dyn PcodeBlock> {
            unimplemented!()
        }
        fn level_list_push(&self, _block: Arc<dyn PcodeBlock>) {
            unimplemented!()
        }
        fn level_list_set(&self, _blocks: Vec<Arc<dyn PcodeBlock>>) {
            unimplemented!()
        }
        fn leaf_list_len(&self) -> usize {
            unimplemented!()
        }
        fn leaf_list_get(&self, _i: usize) -> Arc<dyn PcodeBlock> {
            unimplemented!()
        }
        fn leaf_list_push(&self, _block: Arc<dyn PcodeBlock>) {
            unimplemented!()
        }
        fn leaf_list_set(&self, _blocks: Vec<Arc<dyn PcodeBlock>>) {
            unimplemented!()
        }
        fn goto_ref_len(&self) -> usize {
            unimplemented!()
        }
        fn goto_ref_get(&self, _i: usize) -> (Arc<dyn PcodeBlock>, i32, i32) {
            unimplemented!()
        }
        fn goto_ref_push(&self, _gotoblock: Arc<dyn PcodeBlock>, _root_index: i32, _depth: i32) {
            unimplemented!()
        }
    }

    #[test]
    fn basic_decode_body_round_trips_encoded_ranges() {
        let ram = ram_space();
        let block = MockBlock::new();
        let decoder = MockRangeDecoder {
            space: ram.clone(),
            ranges: vec![(0x1000, 0x100f), (0x2000, 0x200f)],
            pos: std::sync::atomic::AtomicUsize::new(0),
        };

        block
            .basic_decode_body(&decoder, &UnusedBlockMap)
            .unwrap();

        assert_eq!(
            block.get_address_ranges(),
            vec![
                (Address::new(ram.clone(), 0x1000), Address::new(ram.clone(), 0x100f)),
                (Address::new(ram.clone(), 0x2000), Address::new(ram.clone(), 0x200f)),
            ]
        );
        assert_eq!(decoder.pos.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
}
