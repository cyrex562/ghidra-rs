//! Real port of `ghidra.program.model.pcode.BlockCopy`.
//!
//! Previously a placeholder trait lived at `crate::program::seam_stubs::BlockCopy`, exposing only
//! the handful of members
//! [`BlockGraph::transfer_object_ref`](crate::program::model::pcode::block_graph::BlockGraph::transfer_object_ref)
//! needed before this class was ported for real. This file graduates that placeholder in place,
//! following the same precedent `PcodeBlock` itself used (see its module doc at
//! `crate::program::model::pcode::pcode_block`): `seam_stubs.rs` re-exports [`BlockCopy`] under
//! its old path, so `BlockGraph`'s existing call sites (and its test mocks) keep compiling
//! unchanged.
//!
//! Java's `BlockCopy extends PcodeBlock` directly (not `BlockGraph`) and is described as "a
//! placeholder for a basic block (BlockBasic) within a structured control-flow graph": it wraps a
//! reference to the real (pre-structuring) basic block object, an entry address, and an alternate
//! index used to correlate this copy with the original flow graph's corresponding `BlockCopy`
//! during [`BlockGraph::transfer_object_ref`](crate::program::model::pcode::block_graph::BlockGraph::transfer_object_ref).
//!
//! The private `ref`/`address`/`altindex` fields are exposed as abstract accessor methods a
//! concrete implementation supplies, matching this crate's established convention for the same
//! issue (see `BlockGraph`'s and `PcodeBlockBasic`'s module docs). The private `Object ref` field
//! is modeled as an opaque `Arc<dyn Any + Send + Sync>` handle, mirroring
//! [`crate::program::seam_stubs::PcodeOpAst`]'s treatment of a similarly-typed field elsewhere.
//!
//! `getStart()`/`getStop()` are **not** declared on the [`PcodeBlock`] supertrait (see that
//! trait's module docs for why), so they're added here as new, non-conflicting methods, matching
//! the naming [`PcodeBlockBasic`](crate::program::model::pcode::pcode_block_basic::PcodeBlockBasic)
//! already established for the same situation. [`get_stop`](BlockCopy::get_stop) is given a
//! default body delegating to [`get_start`](BlockCopy::get_start): Java's real
//! `BlockCopy.getStop()` body is `return address;`, byte-for-byte identical to `getStart()`'s
//! `return address;` -- both getters read the exact same field, so the default is a faithful
//! single-source-of-truth port, not an approximation.
//!
//! `encodeHeader`/`decodeHeader` are exposed under `block_copy_`-prefixed names instead of
//! `encode_header`/`decode_header`, since [`PcodeBlock`] already declares those names (Rust does
//! not allow a subtrait to re-declare a supertrait method under the same name), matching this
//! crate's existing convention (see `PcodeBlockBasic`'s `basic_encode_body`/`basic_decode_body`).

use crate::program::model::address::Address;
use crate::program::model::pcode::decoder::{Decoder, DecoderError};
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::ATTRIB_ALTINDEX;
use crate::program::model::pcode::pcode_block::PcodeBlock;
use std::any::Any;
use std::io;
use std::sync::Arc;

/// Placeholder for a basic block (`BlockBasic`) within a structured control-flow graph. It
/// originally mirrors the in and out edges of the basic block, but edges may be modified during
/// the structuring process. This copy holds a reference to the actual basic block.
///
/// Port of `ghidra.program.model.pcode.BlockCopy`. See this module's docs for what's real vs.
/// left as an abstract accessor.
pub trait BlockCopy: PcodeBlock {
    /// Stands in for the private `ref` field getter (`BlockCopy.getRef()`). Modeled as an opaque
    /// `Any` handle, mirroring the Java field's `Object` type.
    fn get_ref(&self) -> Option<Arc<dyn Any + Send + Sync>>;

    /// The starting address of this basic block copy (the entry address of the underlying basic
    /// block).
    ///
    /// Port of the `PcodeBlock.getStart()` override.
    fn get_start(&self) -> Address;

    /// The ending address of this basic block copy.
    ///
    /// Port of the `PcodeBlock.getStop()` override. See this module's docs for why the default
    /// body is a faithful port, not an approximation.
    fn get_stop(&self) -> Address {
        self.get_start()
    }

    /// Stands in for the private `altindex` field getter (`BlockCopy.getAltIndex()`).
    fn get_alt_index(&self) -> i32;

    /// Stands in for the private `altindex` field setter, used by
    /// [`block_copy_decode_header`](BlockCopy::block_copy_decode_header) to restore the field
    /// from a stream (Java's field assignment inside `decodeHeader` plays the same role; there is
    /// no public Java setter for `altindex` since only `decodeHeader` itself ever mutates it
    /// after construction).
    fn set_alt_index(&self, altindex: i32);

    /// Used (by `BlockGraph.transferObjectRef`) to reset the internal Object and Address.
    ///
    /// Port of the protected `BlockCopy.set(Object, Address)`.
    fn set(&self, r: Option<Arc<dyn Any + Send + Sync>>, addr: Address);

    /// Port of the protected `BlockCopy.encodeHeader(Encoder)` override. See this module's docs
    /// for the naming.
    fn block_copy_encode_header(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        self.encode_header(encoder)?;
        encoder.write_signed_integer(ATTRIB_ALTINDEX, self.get_alt_index() as i64)
    }

    /// Port of the protected `BlockCopy.decodeHeader(Decoder)` override. See this module's docs
    /// for the naming.
    fn block_copy_decode_header(&self, decoder: &dyn Decoder) -> Result<(), DecoderException> {
        self.decode_header(decoder)?;
        let altindex = decoder
            .read_signed_integer_with_id(ATTRIB_ALTINDEX)
            .map_err(decode_err)?;
        self.set_alt_index(altindex as i32);
        Ok(())
    }
}

fn decode_err(e: DecoderError) -> DecoderException {
    DecoderException::with_cause("failed to decode BlockCopy", e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::block_map::BlockMap;
    use crate::program::model::pcode::pcode_block::PCODE_BLOCK_COPY;
    use std::cell::{Cell, RefCell};

    struct MockCopyBlock {
        index: Cell<i32>,
        alt_index: Cell<i32>,
        ref_val: RefCell<Option<Arc<dyn Any + Send + Sync>>>,
        address: RefCell<Address>,
    }

    impl MockCopyBlock {
        fn new(address: Address) -> Arc<MockCopyBlock> {
            Arc::new(MockCopyBlock {
                index: Cell::new(0),
                alt_index: Cell::new(0),
                ref_val: RefCell::new(None),
                address: RefCell::new(address),
            })
        }
    }

    impl PcodeBlock for MockCopyBlock {
        fn get_index(&self) -> i32 {
            self.index.get()
        }
        fn set_index(&self, index: i32) {
            self.index.set(index);
        }
        fn get_block_type(&self) -> i32 {
            PCODE_BLOCK_COPY
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

    impl BlockCopy for MockCopyBlock {
        fn get_ref(&self) -> Option<Arc<dyn Any + Send + Sync>> {
            self.ref_val.borrow().clone()
        }
        fn get_start(&self) -> Address {
            self.address.borrow().clone()
        }
        fn get_alt_index(&self) -> i32 {
            self.alt_index.get()
        }
        fn set_alt_index(&self, altindex: i32) {
            self.alt_index.set(altindex);
        }
        fn set(&self, r: Option<Arc<dyn Any + Send + Sync>>, addr: Address) {
            *self.ref_val.borrow_mut() = r;
            *self.address.borrow_mut() = addr;
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn usable_as_trait_object() {
        let block = MockCopyBlock::new(Address::new(ram_space(), 0x1000));
        let dyn_block: &dyn BlockCopy = &*block;
        assert_eq!(dyn_block.get_block_type(), PCODE_BLOCK_COPY);
    }

    #[test]
    fn get_stop_defaults_to_get_start_like_java() {
        let addr = Address::new(ram_space(), 0x4000);
        let block = MockCopyBlock::new(addr.clone());
        assert_eq!(block.get_start(), addr.clone());
        // BlockCopy.getStop() is byte-for-byte identical to getStart() in Java -- both return the
        // same `address` field.
        assert_eq!(block.get_stop(), addr);
    }

    #[test]
    fn set_replaces_ref_and_address() {
        #[derive(Debug, PartialEq)]
        struct Handle(u32);

        let block = MockCopyBlock::new(Address::new(ram_space(), 0));
        assert!(block.get_ref().is_none());

        let new_addr = Address::new(ram_space(), 0x2000);
        let handle: Arc<dyn Any + Send + Sync> = Arc::new(Handle(7));
        block.set(Some(handle), new_addr.clone());

        assert_eq!(
            block.get_ref().unwrap().downcast_ref::<Handle>(),
            Some(&Handle(7))
        );
        assert_eq!(block.get_start(), new_addr);
    }

    struct MockEncoder {
        writes: RefCell<Vec<String>>,
    }
    impl Encoder for MockEncoder {
        fn open_element(
            &mut self,
            elem_id: crate::program::model::pcode::ids::ElementId,
        ) -> io::Result<()> {
            self.writes.borrow_mut().push(format!("open:{}", elem_id.name));
            Ok(())
        }
        fn close_element(
            &mut self,
            elem_id: crate::program::model::pcode::ids::ElementId,
        ) -> io::Result<()> {
            self.writes.borrow_mut().push(format!("close:{}", elem_id.name));
            Ok(())
        }
        fn write_bool(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _val: bool,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_signed_integer(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            val: i64,
        ) -> io::Result<()> {
            self.writes.borrow_mut().push(format!("int:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_unsigned_integer(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _val: u64,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_string(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _val: &str,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_string_indexed(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _index: i32,
            _val: &str,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_space(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _spc: &crate::program::model::address::AddressSpace,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_space_indexed(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _index: i32,
            _name: &str,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_opcode(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _opcode: crate::decompiler::opcodes::op_code::OpCode,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_opcode_ordinal(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _opcode: i32,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn block_copy_encode_header_writes_index_then_altindex() {
        let block = MockCopyBlock::new(Address::new(ram_space(), 0));
        block.set_index(3);
        block.set_alt_index(42);

        let mut encoder = MockEncoder {
            writes: RefCell::new(Vec::new()),
        };
        block.block_copy_encode_header(&mut encoder).unwrap();

        assert_eq!(
            *encoder.writes.borrow(),
            vec!["int:index=3".to_string(), "int:altindex=42".to_string()]
        );
    }
}
