//! Real port of `ghidra.program.model.pcode.PcodeBlock`.
//!
//! Previously a placeholder trait lived at `crate::program::seam_stubs::PcodeBlock`, standing in
//! for this class before both `BlockGraph`
//! ([`crate::program::model::pcode::block_graph::BlockGraph`]) and `PcodeBlockBasic`
//! ([`crate::program::model::pcode::pcode_block_basic::PcodeBlockBasic`]) needed a supertrait to
//! extend. This file graduates that placeholder to a real, faithful port, following this crate's
//! established precedent for graduating a seam-stub type in place (see `PrototypePieces`'s module
//! doc at `crate::program::model::lang::prototype_pieces` for a clean example of the same move).
//! `seam_stubs.rs` re-exports [`PcodeBlock`] (and the `PCODE_BLOCK_*` constants and the
//! `pcode_block_type_to_name`/`pcode_block_name_to_type` helpers that used to live alongside it)
//! under their old paths, so none of `BlockGraph`'s, `BlockMap`'s, or `PcodeBlockBasic`'s existing
//! call sites -- including their test mocks -- need to change.
//!
//! ## What's real vs. still a gap
//!
//! - The `index`/`blocktype` field accessors, `encodeHeader`/`decodeHeader`,
//!   `encodeBody`/`decodeBody` (no-op defaults, overridden by real subclasses),
//!   `getFalseOut`/`getTrueOut`/`getIn`/`getOut`/`getInRevIndex`/`getOutRevIndex`/`getInSize`/
//!   `getOutSize`, `typeToName`/`nameToType`, and `calcDepth` are all ported as real default
//!   methods (or, for the two static helpers, free functions), reproducing the Java bodies.
//! - **In/out-edge storage** (the private `intothis`/`outofthis` fields, each an
//!   `ArrayList<BlockEdge>`) is exposed the same way `BlockGraph`'s block list and
//!   `PcodeBlockBasic`'s address-range cover are: as abstract accessor methods a concrete
//!   implementation supplies ([`PcodeBlock::in_edge_count`]/[`get_in_edge`](PcodeBlock::get_in_edge)/
//!   [`push_in_edge`](PcodeBlock::push_in_edge) and their `out_edge`/`out_edge_count` counterparts
//!   below). Unlike `BlockGraph`'s/`PcodeBlockBasic`'s accessors, though, these are given
//!   **default bodies that report zero edges** rather than being left required: `PcodeBlock`
//!   already has seven existing implementors spread across three files (`block_graph.rs`,
//!   `block_map.rs`, `pcode_block_basic.rs`), all test mocks that predate edge bookkeeping and
//!   have no need for it; making the new accessors required would force every one of them to grow
//!   a stub implementation for no behavioral benefit. A concrete implementation that wants real
//!   edge tracking overrides all of these together (they must stay mutually consistent -- the
//!   same requirement `BlockGraph`'s `get_size`/`get_block`/`push_block` triple already carries).
//! - [`PcodeBlock::add_in_edge`] stays a required method, unchanged from the placeholder: its real
//!   body needs `this` as an owned `Arc<dyn PcodeBlock>` (to install the reciprocal edge on the
//!   *other* endpoint), which a `&self` method cannot produce generically. This is the same
//!   limitation already documented on
//!   [`PcodeBlockBasic::insert_before`](crate::program::model::pcode::pcode_block_basic::PcodeBlockBasic::insert_before)
//!   et al., resolved the same way there: a concrete implementation's own self-referential `Arc`,
//!   set up at construction time.
//! - [`decode_next_in_edge`] and [`decode_edges`] have the identical self-`Arc` need (Java's
//!   `decodeNextInEdge` builds `new BlockEdge(this, 0, ...)` to register on the far endpoint), so
//!   both are exposed as **free functions** taking the owning block's `&Arc<dyn PcodeBlock>`
//!   explicitly, rather than trait methods -- matching [`get_front_leaf`] below, and matching this
//!   crate's `PcodeBlockBasic::insert_before`/`insert_after`/`insert_end` precedent for the same
//!   shape of problem, without adding new required trait methods that would force every existing
//!   mock to implement them.
//! - `PcodeBlock.decodeNextInEdge(Decoder, ArrayList<? extends PcodeBlock>)` -- the alternate
//!   overload used only by `PcodeSyntaxTree.decode`, which is not yet ported -- is not ported
//!   here; only the `BlockMap`-resolver overload that `BlockGraph`/`PcodeBlockBasic` actually need
//!   is. // TODO(port): add the `ArrayList` overload if/when `PcodeSyntaxTree` is ported.
//! - `getStart()`/`getStop()` are **not** added to this trait, even though Java declares them
//!   (returning the `Address.NO_ADDRESS` sentinel by default): `PcodeBlockBasic` already declares
//!   its own non-overriding `get_start`/`get_stop` methods of the same name (added when it was
//!   written against the placeholder, which had none), and Rust does not allow a subtrait to
//!   redeclare a supertrait method under the same name. Since every real block type overrides
//!   these anyway (the base implementation is only ever a sentinel), and adding them here would
//!   force renaming `PcodeBlockBasic`'s existing, already-tested `get_start`/`get_stop` (and every
//!   call site), they are left off `PcodeBlock` itself. // TODO(port): if a future `Block*`
//!   subclass needs the *base* `PcodeBlock.getStart()`/`getStop()` sentinel behavior specifically
//!   (as opposed to `PcodeBlockBasic`'s real override), it isn't available here.
//! - `toString()` is not ported for the same reason: it composes `typeToName(blocktype) + "@" +
//!   getStart()`, and `getStart` isn't on this trait.
//!
//! `BlockEdge` (Java's `public static class PcodeBlock.BlockEdge`) is ported as a plain struct
//! with its own `encode`/associated `decode`.

use crate::program::model::pcode::block_graph::BlockGraph;
use crate::program::model::pcode::block_map::BlockMap;
use crate::program::model::pcode::decoder::{Decoder, DecoderError};
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{ATTRIB_END, ATTRIB_INDEX, ATTRIB_REV, ELEM_EDGE};
use crate::program::seam_stubs::{BlockCopy, BlockGoto, BlockIfGoto, BlockMultiGoto};
use std::io;
use std::sync::Arc;

pub const PCODE_BLOCK_PLAIN: i32 = 0;
pub const PCODE_BLOCK_BASIC: i32 = 1;
pub const PCODE_BLOCK_GRAPH: i32 = 2;
pub const PCODE_BLOCK_COPY: i32 = 3;
pub const PCODE_BLOCK_GOTO: i32 = 4;
pub const PCODE_BLOCK_MULTIGOTO: i32 = 5;
pub const PCODE_BLOCK_LIST: i32 = 6;
pub const PCODE_BLOCK_CONDITION: i32 = 7;
pub const PCODE_BLOCK_PROPERIF: i32 = 8;
pub const PCODE_BLOCK_IFELSE: i32 = 9;
pub const PCODE_BLOCK_IFGOTO: i32 = 10;
pub const PCODE_BLOCK_WHILEDO: i32 = 11;
pub const PCODE_BLOCK_DOWHILE: i32 = 12;
pub const PCODE_BLOCK_SWITCH: i32 = 13;
pub const PCODE_BLOCK_INFLOOP: i32 = 14;

/// Port of `PcodeBlock.typeToName(int)`. Returns `None` for an unrecognized type tag, mirroring
/// the Java method's `return null` fallthrough.
pub fn pcode_block_type_to_name(block_type: i32) -> Option<&'static str> {
    match block_type {
        PCODE_BLOCK_PLAIN => Some("plain"),
        PCODE_BLOCK_BASIC => Some("basic"),
        PCODE_BLOCK_GRAPH => Some("graph"),
        // "this a trick for the decompiler c-side"
        PCODE_BLOCK_COPY => Some("plain"),
        PCODE_BLOCK_GOTO => Some("goto"),
        PCODE_BLOCK_MULTIGOTO => Some("multigoto"),
        PCODE_BLOCK_LIST => Some("list"),
        PCODE_BLOCK_CONDITION => Some("condition"),
        PCODE_BLOCK_PROPERIF => Some("properif"),
        PCODE_BLOCK_IFELSE => Some("ifelse"),
        PCODE_BLOCK_IFGOTO => Some("ifgoto"),
        PCODE_BLOCK_WHILEDO => Some("whiledo"),
        PCODE_BLOCK_DOWHILE => Some("dowhile"),
        PCODE_BLOCK_SWITCH => Some("switch"),
        PCODE_BLOCK_INFLOOP => Some("infloop"),
        _ => None,
    }
}

/// Port of `PcodeBlock.nameToType(String)`, used by
/// [`BlockMap::create_block`](crate::program::model::pcode::block_map::BlockMap::create_block) to
/// resolve an XML element name back to a block type tag. Returns `-1` for an unrecognized name,
/// mirroring the Java method's fallthrough (including its "basic" gap: `nameToType` never
/// recognizes the name `typeToName` produces for [`PCODE_BLOCK_BASIC`]).
pub fn pcode_block_name_to_type(name: &str) -> i32 {
    match name.chars().next() {
        Some('c') => PCODE_BLOCK_COPY,
        Some('d') => PCODE_BLOCK_DOWHILE,
        Some('g') => {
            if name == "goto" {
                PCODE_BLOCK_GOTO
            } else {
                PCODE_BLOCK_GRAPH
            }
        }
        Some('i') => {
            if name == "ifelse" {
                PCODE_BLOCK_IFELSE
            } else if name == "infloop" {
                PCODE_BLOCK_INFLOOP
            } else {
                PCODE_BLOCK_IFGOTO
            }
        }
        Some('l') => PCODE_BLOCK_LIST,
        Some('m') => PCODE_BLOCK_MULTIGOTO,
        Some('p') => {
            if name == "properif" {
                PCODE_BLOCK_PROPERIF
            } else {
                PCODE_BLOCK_PLAIN
            }
        }
        Some('s') => PCODE_BLOCK_SWITCH,
        Some('w') => PCODE_BLOCK_WHILEDO,
        _ => -1,
    }
}

/// Port of the nested `PcodeBlock.BlockEdge` class: one directed edge between two blocks, from
/// the perspective of one endpoint's edge list.
#[derive(Clone)]
pub struct BlockEdge {
    /// Label of this edge. Not currently encoded/decoded (matches the Java comment "We are not
    /// encoding label currently" / "Tag does not currently contain info about label").
    pub label: i32,
    /// The other end of the edge.
    pub point: Arc<dyn PcodeBlock>,
    /// Index of the reciprocal edge in `point`'s own edge list, i.e.
    /// `this.get_out(i).get_in(reverse_index) == this` (or the `getIn`/`getOut` mirror image,
    /// depending which list this edge lives in).
    pub reverse_index: i32,
}

impl BlockEdge {
    pub fn new(point: Arc<dyn PcodeBlock>, label: i32, reverse_index: i32) -> Self {
        Self {
            label,
            point,
            reverse_index,
        }
    }

    /// Encode edge to stream assuming we already know what block we are in.
    ///
    /// Port of `BlockEdge.encode(Encoder)`.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_EDGE)?;
        // We are not encoding label currently.
        encoder.write_signed_integer(ATTRIB_END, self.point.get_index() as i64)?;
        encoder.write_signed_integer(ATTRIB_REV, self.reverse_index as i64)?;
        encoder.close_element(ELEM_EDGE)
    }

    /// Decode a single edge.
    ///
    /// Port of `BlockEdge.decode(Decoder, BlockMap)`.
    pub fn decode(decoder: &dyn Decoder, resolver: &dyn BlockMap) -> Result<Self, DecoderException> {
        let el = decoder
            .open_element_with_id(ELEM_EDGE)
            .map_err(decode_err)?;
        let end_index = decoder
            .read_signed_integer_with_id(ATTRIB_END)
            .map_err(decode_err)? as i32;
        let point = resolver
            .find_level_block(end_index)
            .ok_or_else(|| DecoderException::new("Bad serialized edge in block graph"))?;
        let reverse_index = decoder
            .read_signed_integer_with_id(ATTRIB_REV)
            .map_err(decode_err)? as i32;
        decoder.close_element(el).map_err(decode_err)?;
        Ok(BlockEdge {
            label: 0,
            point,
            reverse_index,
        })
    }
}

/// Blocks of PcodeOps.
///
/// Port of `ghidra.program.model.pcode.PcodeBlock`. See this module's docs for what's a faithful
/// default method, what's a required (implementor-supplied) method, and what's deliberately not
/// ported.
pub trait PcodeBlock {
    /// Stands in for the inherited `index` field getter (`PcodeBlock.getIndex()`).
    fn get_index(&self) -> i32;

    /// Stands in for the inherited `index` field setter (`PcodeBlock.setIndex(int)`).
    fn set_index(&self, index: i32);

    /// Stands in for the inherited `blocktype` field getter (`PcodeBlock.getType()`).
    fn get_block_type(&self) -> i32;

    /// Add a directed edge coming from `begin` into this block.
    ///
    /// Port of the protected `PcodeBlock.addInEdge(PcodeBlock, int)`. Left as a required method:
    /// the real algorithm needs `this` as an owned `Arc<dyn PcodeBlock>` to install the reciprocal
    /// out-edge on `begin`, which a `&self` method cannot produce generically. See this module's
    /// docs for the established resolution (a concrete implementation's own self-referential
    /// `Arc`).
    ///
    /// A conforming implementation should mirror:
    /// ```text
    /// let ourrev = begin.out_edge_count() as i32;
    /// let brev = self.in_edge_count() as i32;
    /// self.push_in_edge(BlockEdge::new(begin.clone(), label, ourrev));
    /// begin.push_out_edge(Some(BlockEdge::new(self_arc, label, brev)));
    /// ```
    fn add_in_edge(&self, begin: Arc<dyn PcodeBlock>, label: i32);

    /// Stands in for the protected `PcodeBlock.encodeBody(Encoder)`. Defaults to a no-op,
    /// matching `PcodeBlock`'s own default ("no body by default").
    fn encode_body(&self, _encoder: &mut dyn Encoder) -> io::Result<()> {
        Ok(())
    }

    /// Stands in for the protected `PcodeBlock.decodeBody(Decoder, BlockMap)`. Defaults to a
    /// no-op, matching `PcodeBlock`'s own default ("no body to restore by default").
    fn decode_body(
        &self,
        _decoder: &dyn Decoder,
        _resolver: &dyn BlockMap,
    ) -> Result<(), DecoderException> {
        Ok(())
    }

    /// Encode this block to a stream.
    ///
    /// Port of the public `PcodeBlock.encode(Encoder)`. Left as a required method: the real body
    /// (`openElement(ELEM_BLOCK); encodeHeader(...); encodeBody(...); encodeEdges(...);
    /// closeElement(...)`) composes several methods that concrete `Block*` subclasses override
    /// under distinct names (matching this crate's convention for a subtrait re-declaring a
    /// supertrait method, e.g. `PcodeBlockBasic::basic_encode_body`), so there is no single
    /// generic default that would correctly dispatch to the right override for every subclass.
    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()>;

    /// Decode this block from a stream.
    ///
    /// Port of the public `PcodeBlock.decode(Decoder, BlockMap)`. Left as a required method for
    /// the same reason as [`encode`](PcodeBlock::encode).
    fn decode(&self, decoder: &dyn Decoder, resolver: &dyn BlockMap) -> Result<(), DecoderException>;

    /// Encode basic attributes to stream. Assumes this block's element is already started.
    ///
    /// Port of the protected `PcodeBlock.encodeHeader(Encoder)`.
    fn encode_header(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.write_signed_integer(ATTRIB_INDEX, self.get_index() as i64)
    }

    /// Port of the protected `PcodeBlock.decodeHeader(Decoder)`.
    fn decode_header(&self, decoder: &dyn Decoder) -> Result<(), DecoderException> {
        let index = decoder
            .read_signed_integer_with_id(ATTRIB_INDEX)
            .map_err(decode_err)?;
        self.set_index(index as i32);
        Ok(())
    }

    /// Number of blocks flowing into this block (the private `intothis` field's length).
    ///
    /// Defaults to `0`. See this module's docs for why the in/out-edge accessors default to
    /// reporting no edges rather than being required.
    fn in_edge_count(&self) -> usize {
        0
    }

    /// Stands in for `intothis.get(i)`. Defaults to panicking (there are never any in-edges to
    /// return by default), matching the spirit of Java's `ArrayList.get` throwing
    /// `IndexOutOfBoundsException` for any invalid index.
    fn get_in_edge(&self, i: usize) -> BlockEdge {
        panic!("PcodeBlock::get_in_edge({i}): no in-edges tracked (default edge storage)")
    }

    /// Stands in for `intothis.add(edge)`. Defaults to a no-op.
    fn push_in_edge(&self, _edge: BlockEdge) {}

    /// Number of blocks this block flows into (the private `outofthis` field's length).
    ///
    /// Defaults to `0`. See this module's docs for why the in/out-edge accessors default to
    /// reporting no edges rather than being required.
    fn out_edge_count(&self) -> usize {
        0
    }

    /// Stands in for `outofthis.get(i)`, which may be `null` in Java while
    /// [`decode_next_in_edge`] is still padding out a not-yet-fully-decoded block's out-edge
    /// list; modeled as `Option` for that reason. Defaults to panicking for any index, matching
    /// the spirit of Java's `ArrayList.get` throwing `IndexOutOfBoundsException`.
    fn get_out_edge(&self, i: usize) -> Option<BlockEdge> {
        panic!("PcodeBlock::get_out_edge({i}): no out-edges tracked (default edge storage)")
    }

    /// Stands in for `outofthis.add(edge)` (including `outofthis.add(null)`, used by
    /// [`decode_next_in_edge`] to pad the list out). Defaults to a no-op.
    fn push_out_edge(&self, _edge: Option<BlockEdge>) {}

    /// Stands in for `outofthis.set(i, edge)`. Defaults to panicking for any index (there is
    /// nothing to overwrite in the default empty storage).
    fn set_out_edge(&self, i: usize, _edge: Option<BlockEdge>) {
        panic!("PcodeBlock::set_out_edge({i}): no out-edges tracked (default edge storage)")
    }

    /// Port of `PcodeBlock.getIn(int)`.
    fn get_in(&self, i: usize) -> Arc<dyn PcodeBlock> {
        self.get_in_edge(i).point.clone()
    }

    /// Port of `PcodeBlock.getOut(int)`.
    fn get_out(&self, i: usize) -> Arc<dyn PcodeBlock> {
        self.get_out_edge(i)
            .expect("PcodeBlock::get_out: out-edge slot not yet resolved")
            .point
            .clone()
    }

    /// Get reverse index of the i-th outgoing block, i.e.
    /// `this.getOut(i).getIn(reverse_index) == this`.
    ///
    /// Port of `PcodeBlock.getOutRevIndex(int)`.
    fn get_out_rev_index(&self, i: usize) -> i32 {
        self.get_out_edge(i)
            .expect("PcodeBlock::get_out_rev_index: out-edge slot not yet resolved")
            .reverse_index
    }

    /// Get reverse index of the i-th incoming block, i.e.
    /// `this.getIn(i).getOut(reverse_index) == this`.
    ///
    /// Port of `PcodeBlock.getInRevIndex(int)`.
    fn get_in_rev_index(&self, i: usize) -> i32 {
        self.get_in_edge(i).reverse_index
    }

    /// Assuming paths out of this block depend on a boolean condition, the block coming out of
    /// this one if the condition is false.
    ///
    /// Port of `PcodeBlock.getFalseOut()`.
    fn get_false_out(&self) -> Arc<dyn PcodeBlock> {
        self.get_out(0)
    }

    /// Assuming paths out of this block depend on a boolean condition, the block coming out of
    /// this one if the condition is true.
    ///
    /// Port of `PcodeBlock.getTrueOut()`.
    fn get_true_out(&self) -> Arc<dyn PcodeBlock> {
        self.get_out(1)
    }

    /// Port of `PcodeBlock.getInSize()`.
    fn get_in_size(&self) -> i32 {
        self.in_edge_count() as i32
    }

    /// Port of `PcodeBlock.getOutSize()`.
    fn get_out_size(&self) -> i32 {
        self.out_edge_count() as i32
    }

    /// Encode information about this block's edges to stream.
    ///
    /// Port of the protected `PcodeBlock.encodeEdges(Encoder)`.
    fn encode_edges(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        for i in 0..self.in_edge_count() {
            self.get_in_edge(i).encode(encoder)?;
        }
        Ok(())
    }

    /// Distance (in `getParent()` hops) from `leaf` up to `self`, or `-1` if `self` is not an
    /// ancestor of `leaf`.
    ///
    /// Port of `PcodeBlock.calcDepth(PcodeBlock)`. Takes `Option` (rather than a bare
    /// `Arc<dyn PcodeBlock>`) so a `null` starting `leaf` -- which Java allows, immediately
    /// returning `-1` -- has a direct representation.
    fn calc_depth(&self, leaf: Option<Arc<dyn PcodeBlock>>) -> i32 {
        let self_ptr = self as *const Self as *const ();
        let mut cur = leaf;
        let mut depth = 0;
        loop {
            let is_self = match &cur {
                Some(c) => (c.as_ref() as *const dyn PcodeBlock).cast::<()>() == self_ptr,
                None => false,
            };
            if is_self {
                return depth;
            }
            match cur {
                None => return -1,
                Some(c) => {
                    cur = c.get_parent();
                    depth += 1;
                }
            }
        }
    }

    /// Returns this block viewed as a
    /// [`BlockGraph`](crate::program::model::pcode::block_graph::BlockGraph) when it is one.
    /// Mirrors the `instanceof BlockGraph` checks in `BlockGraph.addBlock` and
    /// `BlockGraph.transferObjectRef`. Defaults to `None`; `BlockGraph` implementations override
    /// it to return `Some(self)`.
    fn as_block_graph(&self) -> Option<&dyn BlockGraph> {
        None
    }

    /// Returns this block viewed as a [`BlockCopy`] when it is one. Mirrors the `instanceof
    /// BlockCopy` check in `BlockGraph.transferObjectRef`. Defaults to `None`.
    fn as_block_copy(&self) -> Option<&dyn BlockCopy> {
        None
    }

    /// Stands in for the inherited `parent` field getter (`PcodeBlock.getParent()`), used by
    /// [`BlockMap::resolve_goto_references`](crate::program::model::pcode::block_map::BlockMap::resolve_goto_references)
    /// to walk up from a goto's root block by the recorded depth, and by
    /// [`calc_depth`](PcodeBlock::calc_depth) above. Defaults to `None`, matching an unparented
    /// (e.g. top-level) block.
    fn get_parent(&self) -> Option<Arc<dyn PcodeBlock>> {
        None
    }

    /// Returns this block viewed as a [`BlockGoto`] when it is one. Mirrors the `instanceof
    /// BlockGoto` check in `BlockMap.resolveGotoReferences`. Defaults to `None`.
    fn as_block_goto(&self) -> Option<&dyn BlockGoto> {
        None
    }

    /// Returns this block viewed as a [`BlockIfGoto`] when it is one. Mirrors the `instanceof
    /// BlockIfGoto` check in `BlockMap.resolveGotoReferences`. Defaults to `None`.
    fn as_block_if_goto(&self) -> Option<&dyn BlockIfGoto> {
        None
    }

    /// Returns this block viewed as a [`BlockMultiGoto`] when it is one. Mirrors the `instanceof
    /// BlockMultiGoto` check in `BlockMap.resolveGotoReferences`. Defaults to `None`.
    fn as_block_multi_goto(&self) -> Option<&dyn BlockMultiGoto> {
        None
    }
}

/// Follow `BlockGraph` containers down to the first non-`BlockGraph` leaf.
///
/// Port of `PcodeBlock.getFrontLeaf()`. Exposed as a free function taking the starting block as
/// an owned `Arc` (rather than a trait method taking `&self`), sidestepping the need for
/// implementors to hand back a self-referential `Arc<dyn PcodeBlock>` from a `&self` method. See
/// this module's docs for the same limitation elsewhere.
///
/// Faithfully does *not* guard against an empty `BlockGraph` (`get_size() == 0`): like Java's
/// `((BlockGraph) bl).getBlock(0)`, this will panic via the concrete implementation's own
/// `get_block` if a `BlockGraph` in the chain has no children, matching the real
/// `IndexOutOfBoundsException` Java would throw.
pub fn get_front_leaf(bl: Arc<dyn PcodeBlock>) -> Arc<dyn PcodeBlock> {
    let mut cur = bl;
    loop {
        let next = match cur.as_block_graph() {
            Some(g) => g.get_block(0),
            None => break,
        };
        cur = next;
    }
    cur
}

/// Decode the next input edge from the stream, resolving the far endpoint through `resolver`.
///
/// Port of the protected `PcodeBlock.decodeNextInEdge(Decoder, BlockMap)`. Exposed as a free
/// function taking the owning block as an explicit `&Arc<dyn PcodeBlock>` (`self_block`); see
/// this module's docs for why.
pub fn decode_next_in_edge(
    self_block: &Arc<dyn PcodeBlock>,
    decoder: &dyn Decoder,
    resolver: &dyn BlockMap,
) -> Result<(), DecoderException> {
    let edge = BlockEdge::decode(decoder, resolver)?;
    let this_index = self_block.in_edge_count() as i32;
    let far = edge.point.clone();
    let far_slot = edge.reverse_index as usize;
    self_block.push_in_edge(edge);
    while far.out_edge_count() <= far_slot {
        far.push_out_edge(None);
    }
    far.set_out_edge(
        far_slot,
        Some(BlockEdge::new(self_block.clone(), 0, this_index)),
    );
    Ok(())
}

/// Decode all of `self_block`'s incoming edges from the stream.
///
/// Port of the protected `PcodeBlock.decodeEdges(Decoder, BlockMap)`. Exposed as a free function
/// for the same self-`Arc` reason as [`decode_next_in_edge`] (which it calls in a loop).
pub fn decode_edges(
    self_block: &Arc<dyn PcodeBlock>,
    decoder: &dyn Decoder,
    resolver: &dyn BlockMap,
) -> Result<(), DecoderException> {
    loop {
        let el = decoder.peek_element().map_err(decode_err)?;
        if el != ELEM_EDGE.id {
            break;
        }
        decode_next_in_edge(self_block, decoder, resolver)?;
    }
    Ok(())
}

fn decode_err(e: DecoderError) -> DecoderException {
    DecoderException::with_cause("failed to decode PcodeBlock", e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::pcode::block_map::BlockMap as BlockMapTrait;
    use std::cell::{Cell, RefCell};

    /// A block with real (`RefCell`-backed) in/out-edge storage, overriding all seven edge
    /// accessors together as this module's docs require. Keeps a self-referential `Arc` (set up
    /// after construction, matching the established convention) so `add_in_edge` can hand back
    /// `self` as an `Arc<dyn PcodeBlock>`.
    struct EdgeBlock {
        index: Cell<i32>,
        block_type: i32,
        into: RefCell<Vec<BlockEdge>>,
        outof: RefCell<Vec<Option<BlockEdge>>>,
        self_ref: RefCell<Option<Arc<dyn PcodeBlock>>>,
    }

    impl EdgeBlock {
        fn new(index: i32, block_type: i32) -> Arc<EdgeBlock> {
            let block = Arc::new(EdgeBlock {
                index: Cell::new(index),
                block_type,
                into: RefCell::new(Vec::new()),
                outof: RefCell::new(Vec::new()),
                self_ref: RefCell::new(None),
            });
            *block.self_ref.borrow_mut() = Some(block.clone() as Arc<dyn PcodeBlock>);
            block
        }
    }

    impl PcodeBlock for EdgeBlock {
        fn get_index(&self) -> i32 {
            self.index.get()
        }
        fn set_index(&self, index: i32) {
            self.index.set(index);
        }
        fn get_block_type(&self) -> i32 {
            self.block_type
        }
        fn add_in_edge(&self, begin: Arc<dyn PcodeBlock>, label: i32) {
            let ourrev = begin.out_edge_count() as i32;
            let brev = self.in_edge_count() as i32;
            self.push_in_edge(BlockEdge::new(begin.clone(), label, ourrev));
            let self_arc = self.self_ref.borrow().clone().unwrap();
            begin.push_out_edge(Some(BlockEdge::new(self_arc, label, brev)));
        }
        fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
            self.encode_header(encoder)?;
            self.encode_body(encoder)?;
            self.encode_edges(encoder)
        }
        fn decode(&self, decoder: &dyn Decoder, resolver: &dyn BlockMap) -> Result<(), DecoderException> {
            self.decode_header(decoder)?;
            self.decode_body(decoder, resolver)?;
            let self_arc = self.self_ref.borrow().clone().unwrap();
            decode_edges(&self_arc, decoder, resolver)
        }

        fn in_edge_count(&self) -> usize {
            self.into.borrow().len()
        }
        fn get_in_edge(&self, i: usize) -> BlockEdge {
            self.into.borrow()[i].clone()
        }
        fn push_in_edge(&self, edge: BlockEdge) {
            self.into.borrow_mut().push(edge);
        }
        fn out_edge_count(&self) -> usize {
            self.outof.borrow().len()
        }
        fn get_out_edge(&self, i: usize) -> Option<BlockEdge> {
            self.outof.borrow()[i].clone()
        }
        fn push_out_edge(&self, edge: Option<BlockEdge>) {
            self.outof.borrow_mut().push(edge);
        }
        fn set_out_edge(&self, i: usize, edge: Option<BlockEdge>) {
            self.outof.borrow_mut()[i] = edge;
        }

        fn get_parent(&self) -> Option<Arc<dyn PcodeBlock>> {
            None
        }
    }

    /// A bare-minimum block using only the seam's original required methods, proving the
    /// existing (pre-graduation) implementor shape still compiles unchanged and inherits sane
    /// "no edges" defaults.
    struct MinimalBlock {
        index: Cell<i32>,
    }

    impl PcodeBlock for MinimalBlock {
        fn get_index(&self) -> i32 {
            self.index.get()
        }
        fn set_index(&self, index: i32) {
            self.index.set(index);
        }
        fn get_block_type(&self) -> i32 {
            PCODE_BLOCK_PLAIN
        }
        fn add_in_edge(&self, _begin: Arc<dyn PcodeBlock>, _label: i32) {}
        fn encode(&self, _encoder: &mut dyn Encoder) -> io::Result<()> {
            Ok(())
        }
        fn decode(&self, _decoder: &dyn Decoder, _resolver: &dyn BlockMap) -> Result<(), DecoderException> {
            Ok(())
        }
    }

    #[test]
    fn type_to_name_and_name_to_type_round_trip() {
        assert_eq!(pcode_block_type_to_name(PCODE_BLOCK_IFELSE), Some("ifelse"));
        assert_eq!(pcode_block_type_to_name(999), None);
        assert_eq!(pcode_block_name_to_type("ifelse"), PCODE_BLOCK_IFELSE);
        assert_eq!(pcode_block_name_to_type("unknownzzz"), -1);
        // Real Java gap: nameToType never recognizes "basic".
        assert_eq!(pcode_block_name_to_type("basic"), -1);
    }

    #[test]
    fn minimal_block_inherits_no_edge_defaults() {
        let block = MinimalBlock { index: Cell::new(0) };
        assert_eq!(block.get_in_size(), 0);
        assert_eq!(block.get_out_size(), 0);
    }

    #[test]
    #[should_panic(expected = "no in-edges tracked")]
    fn minimal_block_get_in_panics_like_java_index_out_of_bounds() {
        let block = MinimalBlock { index: Cell::new(0) };
        block.get_in(0);
    }

    #[test]
    fn add_in_edge_wires_both_endpoints_like_java() {
        let a = EdgeBlock::new(0, PCODE_BLOCK_BASIC);
        let b = EdgeBlock::new(1, PCODE_BLOCK_BASIC);

        // b.addInEdge(a, 7): an edge from a into b.
        b.add_in_edge(a.clone() as Arc<dyn PcodeBlock>, 7);

        assert_eq!(b.get_in_size(), 1);
        assert_eq!(a.get_out_size(), 1);
        assert!(Arc::ptr_eq(&b.get_in(0), &(a.clone() as Arc<dyn PcodeBlock>)));
        assert!(Arc::ptr_eq(&a.get_out(0), &(b.clone() as Arc<dyn PcodeBlock>)));
        // Reverse indices point back at each other.
        assert_eq!(b.get_in_rev_index(0), 0);
        assert_eq!(a.get_out_rev_index(0), 0);
    }

    #[test]
    fn get_false_out_and_true_out_read_slots_0_and_1() {
        let block = EdgeBlock::new(0, PCODE_BLOCK_IFELSE);
        let false_target = EdgeBlock::new(1, PCODE_BLOCK_BASIC);
        let true_target = EdgeBlock::new(2, PCODE_BLOCK_BASIC);
        block.push_out_edge(Some(BlockEdge::new(false_target.clone() as Arc<dyn PcodeBlock>, 0, 0)));
        block.push_out_edge(Some(BlockEdge::new(true_target.clone() as Arc<dyn PcodeBlock>, 0, 0)));

        assert!(Arc::ptr_eq(&block.get_false_out(), &(false_target as Arc<dyn PcodeBlock>)));
        assert!(Arc::ptr_eq(&block.get_true_out(), &(true_target as Arc<dyn PcodeBlock>)));
    }

    #[test]
    fn calc_depth_walks_parent_chain() {
        struct Parented {
            index: Cell<i32>,
            parent: RefCell<Option<Arc<dyn PcodeBlock>>>,
        }
        impl PcodeBlock for Parented {
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
            fn decode(&self, _decoder: &dyn Decoder, _resolver: &dyn BlockMap) -> Result<(), DecoderException> {
                Ok(())
            }
            fn get_parent(&self) -> Option<Arc<dyn PcodeBlock>> {
                self.parent.borrow().clone()
            }
        }

        let root: Arc<dyn PcodeBlock> = Arc::new(Parented {
            index: Cell::new(0),
            parent: RefCell::new(None),
        });
        let mid_impl = Arc::new(Parented {
            index: Cell::new(1),
            parent: RefCell::new(Some(root.clone())),
        });
        let mid: Arc<dyn PcodeBlock> = mid_impl.clone();
        let leaf_impl = Arc::new(Parented {
            index: Cell::new(2),
            parent: RefCell::new(Some(mid.clone())),
        });
        let leaf: Arc<dyn PcodeBlock> = leaf_impl;

        assert_eq!(root.calc_depth(Some(leaf.clone())), 2);
        assert_eq!(mid.calc_depth(Some(leaf.clone())), 1);
        assert_eq!(leaf.calc_depth(Some(leaf.clone())), 0);
        assert_eq!(root.calc_depth(None), -1);

        let unrelated: Arc<dyn PcodeBlock> = Arc::new(Parented {
            index: Cell::new(9),
            parent: RefCell::new(None),
        });
        assert_eq!(unrelated.calc_depth(Some(leaf)), -1);
    }

    #[test]
    fn get_front_leaf_stops_at_non_block_graph() {
        // MinimalBlock never overrides as_block_graph, so it is its own front leaf.
        let leaf: Arc<dyn PcodeBlock> = Arc::new(MinimalBlock { index: Cell::new(5) });
        let result = get_front_leaf(leaf.clone());
        assert!(Arc::ptr_eq(&result, &leaf));
    }

    struct MockEncoder {
        writes: RefCell<Vec<String>>,
    }
    impl MockEncoder {
        fn new() -> Self {
            Self {
                writes: RefCell::new(Vec::new()),
            }
        }
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
    fn encode_edges_emits_one_edge_element_per_in_edge() {
        let a = EdgeBlock::new(3, PCODE_BLOCK_BASIC);
        let b = EdgeBlock::new(4, PCODE_BLOCK_BASIC);
        b.add_in_edge(a.clone() as Arc<dyn PcodeBlock>, 0);

        let mut encoder = MockEncoder::new();
        b.encode_edges(&mut encoder).unwrap();

        assert_eq!(
            *encoder.writes.borrow(),
            vec![
                "open:edge".to_string(),
                "int:end=3".to_string(),
                "int:rev=0".to_string(),
                "close:edge".to_string(),
            ]
        );
    }

    /// Feeds `decode_next_in_edge` a canned `<edge end=".." rev=".."/>` and confirms it both
    /// records the in-edge on `self_block` *and* installs the reciprocal out-edge on the
    /// resolved far endpoint -- including the null-padding growth Java's
    /// `while (inEdge.point.outofthis.size() <= inEdge.reverse_index) outofthis.add(null);`
    /// performs when the far endpoint's out-edge list isn't long enough yet.
    struct MockEdgeDecoder {
        end_index: i32,
        reverse_index: i32,
        pos: std::sync::atomic::AtomicUsize,
    }
    impl Decoder for MockEdgeDecoder {
        fn get_address_factory(&self) -> Arc<dyn crate::program::model::address::factory::AddressFactory> {
            unimplemented!()
        }
        fn set_address_factory(&self, _factory: Arc<dyn crate::program::model::address::factory::AddressFactory>) {}
        fn peek_element(&self) -> Result<i32, DecoderError> {
            Ok(ELEM_EDGE.id)
        }
        fn open_element(&self) -> Result<i32, DecoderError> {
            Ok(ELEM_EDGE.id)
        }
        fn open_element_with_id(
            &self,
            _elem_id: crate::program::model::pcode::ids::ElementId,
        ) -> Result<i32, DecoderError> {
            Ok(ELEM_EDGE.id)
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
        fn read_bool_with_id(
            &self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
        ) -> Result<bool, DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer(&self) -> Result<i64, DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer_with_id(
            &self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
        ) -> Result<i64, DecoderError> {
            if attrib_id.name == ATTRIB_END.name {
                Ok(self.end_index as i64)
            } else {
                self.pos.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(self.reverse_index as i64)
            }
        }
        fn read_unsigned_integer(&self) -> Result<u64, DecoderError> {
            unimplemented!()
        }
        fn read_unsigned_integer_with_id(
            &self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
        ) -> Result<u64, DecoderError> {
            unimplemented!()
        }
        fn read_string(&self) -> Result<String, DecoderError> {
            unimplemented!()
        }
        fn read_string_with_id(
            &self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
        ) -> Result<String, DecoderError> {
            unimplemented!()
        }
        fn read_space(&self) -> Result<Arc<crate::program::model::address::AddressSpace>, DecoderError> {
            unimplemented!()
        }
        fn read_space_with_id(
            &self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
        ) -> Result<Arc<crate::program::model::address::AddressSpace>, DecoderError> {
            unimplemented!()
        }
    }

    struct MockLevelListMap {
        blocks: Vec<Arc<dyn PcodeBlock>>,
    }
    impl BlockMapTrait for MockLevelListMap {
        fn get_address_factory(&self) -> Arc<dyn crate::program::model::address::factory::AddressFactory> {
            unimplemented!()
        }
        fn resolve_block(&self, _block_type: i32) -> Arc<dyn PcodeBlock> {
            unimplemented!()
        }
        fn new_child(&self) -> Box<dyn BlockMapTrait> {
            unimplemented!()
        }
        fn level_list_len(&self) -> usize {
            self.blocks.len()
        }
        fn level_list_get(&self, i: usize) -> Arc<dyn PcodeBlock> {
            self.blocks[i].clone()
        }
        fn level_list_push(&self, _block: Arc<dyn PcodeBlock>) {
            unimplemented!()
        }
        fn level_list_set(&self, _blocks: Vec<Arc<dyn PcodeBlock>>) {
            unimplemented!()
        }
        fn leaf_list_len(&self) -> usize {
            0
        }
        fn leaf_list_get(&self, _i: usize) -> Arc<dyn PcodeBlock> {
            unimplemented!()
        }
        fn leaf_list_push(&self, _block: Arc<dyn PcodeBlock>) {}
        fn leaf_list_set(&self, _blocks: Vec<Arc<dyn PcodeBlock>>) {}
        fn goto_ref_len(&self) -> usize {
            0
        }
        fn goto_ref_get(&self, _i: usize) -> (Arc<dyn PcodeBlock>, i32, i32) {
            unimplemented!()
        }
        fn goto_ref_push(&self, _gotoblock: Arc<dyn PcodeBlock>, _root_index: i32, _depth: i32) {}
    }

    #[test]
    fn decode_next_in_edge_installs_reciprocal_out_edge_with_null_padding() {
        let far = EdgeBlock::new(5, PCODE_BLOCK_BASIC);
        let self_block: Arc<dyn PcodeBlock> = EdgeBlock::new(9, PCODE_BLOCK_BASIC);
        let resolver = MockLevelListMap {
            blocks: vec![far.clone() as Arc<dyn PcodeBlock>],
        };
        // end="5" resolves (via find_level_block's binary search) to `far` (index 5); rev="2"
        // means far's out-edge list must be padded to length 3 before slot 2 is set.
        let decoder = MockEdgeDecoder {
            end_index: 5,
            reverse_index: 2,
            pos: std::sync::atomic::AtomicUsize::new(0),
        };

        decode_next_in_edge(&self_block, &decoder, &resolver).unwrap();

        assert_eq!(self_block.get_in_size(), 1);
        assert!(Arc::ptr_eq(&self_block.get_in(0), &(far.clone() as Arc<dyn PcodeBlock>)));

        assert_eq!(far.get_out_size(), 3);
        assert!(far.get_out_edge(0).is_none());
        assert!(far.get_out_edge(1).is_none());
        let installed = far.get_out_edge(2).expect("slot 2 installed");
        assert!(Arc::ptr_eq(&installed.point, &self_block));
        assert_eq!(installed.reverse_index, 0);
    }
}
