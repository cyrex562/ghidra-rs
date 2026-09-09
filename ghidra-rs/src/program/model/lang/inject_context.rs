//! Port of `ghidra.program.model.lang.InjectContext`.
//!
//! A plain value type (not an [`InjectPayload`](crate::program::model::lang::inject_payload::InjectPayload)
//! implementor itself) carrying the addressing context and input/output storage locations an
//! injection needs: the call/userop site, the following instruction, and the varnodes that stand
//! in for the payload's declared parameters.
//!
//! `InjectPayload::inject`/`InjectPayload::get_pcode` previously took
//! `&dyn seam_stubs::InjectContext`, an empty marker trait with no accessors -- unusable for a
//! real implementation, since the payload's `checkParameterRestrictions`/`setupParameters` logic
//! needs the actual `base_addr`/`input_list`/`output` fields, not just an opaque trait object.
//! Porting this type for real meant fixing that: the marker trait is gone, and every call site
//! (the `InjectPayload`/`InjectPayloadSleigh`/`InjectPayloadCallfixup` trait definitions, their
//! tests, and the few other consumers of the marker trait) now takes this concrete
//! [`InjectContext`] by reference instead.

use std::sync::Arc;

use crate::program::model::address::special_address::SpecialAddress;
use crate::program::model::address::Address;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::pcode::address_xml;
use crate::program::model::pcode::decoder::{Decoder, DecoderError};
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::ids::{ATTRIB_SIZE, ELEM_CONTEXT, ELEM_INPUT, ELEM_OUTPUT};
use crate::program::model::pcode::Varnode;

/// Carries the addressing context and input/output parameter storage for a single injection.
///
/// Port of `ghidra.program.model.lang.InjectContext`. Java's fields are public and nullable; the
/// nullable `ArrayList<Varnode>` fields become `Option<Vec<Varnode>>` here, and the nullable
/// `Address` fields default to [`SpecialAddress::no_address`] (this crate's `Address` has no null
/// value, matching the convention used elsewhere for "unset" Java `Address` fields, e.g.
/// [`address_xml::decode_from_attributes`]).
#[derive(Clone)]
pub struct InjectContext {
    /// The language of the injecting instruction.
    pub language: Option<Arc<SleighLanguage>>,
    /// Base address of the op (call, userop) causing the inject.
    pub base_addr: Address,
    /// Address of the next instruction following the injecting instruction.
    pub next_addr: Address,
    /// For a call inject, the address of the function being called.
    pub call_addr: Address,
    pub ref_addr: Address,
    /// Input parameters for the injection.
    pub input_list: Option<Vec<Varnode>>,
    /// Output parameters for the injection.
    pub output: Option<Vec<Varnode>>,
}

impl InjectContext {
    /// Construct an empty context, matching Java's no-arg constructor (all fields left at their
    /// default/null value).
    pub fn new() -> Self {
        InjectContext {
            language: None,
            base_addr: SpecialAddress::no_address(),
            next_addr: SpecialAddress::no_address(),
            call_addr: SpecialAddress::no_address(),
            ref_addr: SpecialAddress::no_address(),
            input_list: None,
            output: None,
        }
    }

    /// Decode `this` context from a `<context>` element, restoring [`Self::base_addr`],
    /// [`Self::call_addr`], and the optional `<input>`/`<output>` varnode lists.
    ///
    /// Port of `InjectContext.decode(Decoder)`.
    ///
    /// # Errors
    /// Returns an error for any problems decoding the stream.
    pub fn decode(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderException> {
        let el = decoder.open_element_with_id(ELEM_CONTEXT).map_err(decode_err)?;
        self.base_addr = address_xml::decode(decoder)?;
        self.call_addr = address_xml::decode(decoder)?;
        let mut subel = decoder.peek_element().map_err(decode_err)?;
        if subel == ELEM_INPUT.id {
            decoder.open_element().map_err(decode_err)?;
            self.input_list = Some(decode_varnode_list(decoder)?);
            decoder.close_element(subel).map_err(decode_err)?;
            subel = decoder.peek_element().map_err(decode_err)?;
        }
        if subel == ELEM_OUTPUT.id {
            decoder.open_element().map_err(decode_err)?;
            self.output = Some(decode_varnode_list(decoder)?);
            decoder.close_element(subel).map_err(decode_err)?;
        }
        decoder.close_element(el).map_err(decode_err)?;
        Ok(())
    }
}

impl Default for InjectContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Decode a sequence of `<addr size=".."/>`-style elements (as found inside an `<input>` or
/// `<output>` element) into a list of [`Varnode`]s. Extracted from the (identical, duplicated in
/// Java) loop bodies of `InjectContext.decode`'s `<input>` and `<output>` handling.
fn decode_varnode_list(decoder: &dyn Decoder) -> Result<Vec<Varnode>, DecoderException> {
    let mut list = Vec::new();
    loop {
        let addrel = decoder.peek_element().map_err(decode_err)?;
        if addrel == 0 {
            break;
        }
        decoder.open_element().map_err(decode_err)?;
        let addr = address_xml::decode_from_attributes(decoder)?;
        let size = decoder.read_signed_integer_with_id(ATTRIB_SIZE).map_err(decode_err)? as i32;
        decoder.close_element(addrel).map_err(decode_err)?;
        list.push(Varnode::new(addr, size));
    }
    Ok(list)
}

fn decode_err(e: DecoderError) -> DecoderException {
    DecoderException::with_cause("failed to decode InjectContext", e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressFactory, AddressSpace, AddressSpaceType};
    use crate::program::model::address::factory::DefaultAddressFactory;
    use crate::program::model::pcode::decoder::DecoderError;
    use crate::program::model::pcode::ids::{
        AttributeId, ElementId, ATTRIB_OFFSET, ATTRIB_SPACE, ELEM_ADDR,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn new_defaults_to_no_address_and_none_lists() {
        let ctx = InjectContext::new();
        assert!(ctx.language.is_none());
        assert_eq!(ctx.base_addr, SpecialAddress::no_address());
        assert_eq!(ctx.next_addr, SpecialAddress::no_address());
        assert_eq!(ctx.call_addr, SpecialAddress::no_address());
        assert_eq!(ctx.ref_addr, SpecialAddress::no_address());
        assert!(ctx.input_list.is_none());
        assert!(ctx.output.is_none());
    }

    #[test]
    fn default_matches_new() {
        let ctx = InjectContext::default();
        assert_eq!(ctx.base_addr, SpecialAddress::no_address());
    }

    // --- decode() ---

    /// A scripted decoder driving a fixed sequence of element opens/closes/attributes,
    /// simulating: `<context><addr space=ram off=0x10/><addr space=ram off=0x20/>
    /// <input><addr space=ram off=0x100 size=4/><addr space=ram off=0x104 size=8/></input>
    /// <output><addr space=ram off=0x200 size=2/></output></context>`
    struct ScriptedDecoder {
        factory: Arc<dyn AddressFactory>,
        space: Arc<AddressSpace>,
        // Sequence of (peek_element result, open_element result) pairs consumed in order by
        // peek_element/open_element calls; a real decoder tracks a cursor internally, this test
        // double just replays a script.
        elem_script: Vec<i32>,
        elem_pos: AtomicUsize,
        // Attribute script per open <addr> element: (space_offset_pairs, size)
        addr_attrs: Vec<(u64, Option<i64>)>,
        addr_pos: AtomicUsize,
        attr_step: AtomicUsize,
    }

    impl Decoder for ScriptedDecoder {
        fn get_address_factory(&self) -> Arc<dyn AddressFactory> {
            self.factory.clone()
        }
        fn set_address_factory(&self, _factory: Arc<dyn AddressFactory>) {}

        fn peek_element(&self) -> Result<i32, DecoderError> {
            let pos = self.elem_pos.load(Ordering::SeqCst);
            Ok(*self.elem_script.get(pos).unwrap_or(&0))
        }
        fn open_element(&self) -> Result<i32, DecoderError> {
            let pos = self.elem_pos.fetch_add(1, Ordering::SeqCst);
            self.attr_step.store(0, Ordering::SeqCst);
            Ok(self.elem_script[pos])
        }
        fn open_element_with_id(&self, elem_id: ElementId) -> Result<i32, DecoderError> {
            self.open_element()?;
            Ok(elem_id.id)
        }
        fn close_element(&self, _id: i32) -> Result<(), DecoderError> {
            // Closing an element consumes its end tag, revealing whatever comes next (the next
            // sibling's start tag, or a "0" no-more-children marker) at the next `elem_script`
            // position -- mirroring how a real decoder's cursor advances past an end tag.
            self.elem_pos.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn close_element_skipping(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }

        fn get_next_attribute_id(&self) -> Result<i32, DecoderError> {
            let step = self.attr_step.load(Ordering::SeqCst);
            let (_, size) = &self.addr_attrs[self.addr_pos.load(Ordering::SeqCst)];
            let ids = if size.is_some() {
                vec![ATTRIB_SPACE.id, ATTRIB_OFFSET.id, ATTRIB_SIZE.id]
            } else {
                vec![ATTRIB_SPACE.id, ATTRIB_OFFSET.id]
            };
            if step >= ids.len() {
                return Ok(0);
            }
            self.attr_step.store(step + 1, Ordering::SeqCst);
            Ok(ids[step])
        }
        fn rewind_attributes(&self) {
            self.attr_step.store(0, Ordering::SeqCst);
        }

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
            let (_, size) = &self.addr_attrs[self.addr_pos.load(Ordering::SeqCst)];
            let v = size.expect("read_signed_integer_with_id called on an addr without a size");
            // The size attribute is the last one read for this <addr>; advance to the next one.
            self.addr_pos.fetch_add(1, Ordering::SeqCst);
            Ok(v)
        }

        fn read_unsigned_integer(&self) -> Result<u64, DecoderError> {
            let (off, size) = &self.addr_attrs[self.addr_pos.load(Ordering::SeqCst)];
            if size.is_none() {
                self.addr_pos.fetch_add(1, Ordering::SeqCst);
            }
            Ok(*off)
        }
        fn read_unsigned_integer_with_id(&self, _attrib_id: AttributeId) -> Result<u64, DecoderError> {
            self.read_unsigned_integer()
        }

        fn read_string(&self) -> Result<String, DecoderError> {
            unimplemented!()
        }
        fn read_string_with_id(&self, _attrib_id: AttributeId) -> Result<String, DecoderError> {
            unimplemented!()
        }

        fn read_space(&self) -> Result<Arc<AddressSpace>, DecoderError> {
            Ok(self.space.clone())
        }
        fn read_space_with_id(&self, _attrib_id: AttributeId) -> Result<Arc<AddressSpace>, DecoderError> {
            self.read_space()
        }
    }

    #[test]
    fn decode_restores_base_call_input_and_output() {
        let space = ram_space();
        let factory: Arc<dyn AddressFactory> = Arc::new(DefaultAddressFactory::new(vec![space.clone()]));

        // `elem_pos` is a flat cursor over every element boundary `decode()` crosses: each
        // `open_element`/`open_element_with_id` call consumes the slot at the current position
        // (advancing it by one), and each `close_element` call *also* advances by one (consuming
        // the matching end tag, revealing whatever's peeked next). `peek_element` only reads the
        // current slot without advancing. Slots that are only ever crossed by a `close_element`
        // (never separately peeked/opened) are "don't care" and left as `ELEM_ADDR.id`.
        //
        //   pos  0: <context> start tag (consumed by open_element_with_id; value unread)
        //   pos  1: <addr> start tag for base_addr (consumed by AddressXML::decode's open)
        //   pos  2: (base_addr's <addr> end tag; consumed by AddressXML::decode's close)
        //   pos  3: <addr> start tag for call_addr
        //   pos  4: (call_addr's <addr> end tag)
        //   pos  5: <input> start tag -- peeked, then opened
        //   pos  6: first input <addr> start tag -- peeked, then opened
        //   pos  7: (first input addr's end tag)
        //   pos  8: second input <addr> start tag -- peeked, then opened
        //   pos  9: (second input addr's end tag)
        //   pos 10: 0 -- peek: no more input addrs
        //   pos 11: <output> start tag -- peeked, then opened (also consumes </input>'s end tag)
        //   pos 12: output <addr> start tag -- peeked, then opened
        //   pos 13: (output addr's end tag)
        //   pos 14: 0 -- peek: no more output addrs
        let elem_script = vec![
            ELEM_ADDR.id,   // 0: <context> (unread)
            ELEM_ADDR.id,   // 1: base_addr
            ELEM_ADDR.id,   // 2: (don't care)
            ELEM_ADDR.id,   // 3: call_addr
            ELEM_ADDR.id,   // 4: (don't care)
            ELEM_INPUT.id,  // 5: <input>
            ELEM_ADDR.id,   // 6: first input addr
            ELEM_ADDR.id,   // 7: (don't care)
            ELEM_ADDR.id,   // 8: second input addr
            ELEM_ADDR.id,   // 9: (don't care)
            0,              // 10: no more input addrs
            ELEM_OUTPUT.id, // 11: <output>
            ELEM_ADDR.id,   // 12: output addr
            ELEM_ADDR.id,   // 13: (don't care)
            0,              // 14: no more output addrs
        ];

        let addr_attrs = vec![
            (0x10, None),        // base_addr
            (0x20, None),        // call_addr
            (0x100, Some(4)),    // input[0]
            (0x104, Some(8)),    // input[1]
            (0x200, Some(2)),    // output[0]
        ];

        let decoder = ScriptedDecoder {
            factory,
            space: space.clone(),
            elem_script,
            elem_pos: AtomicUsize::new(0),
            addr_attrs,
            addr_pos: AtomicUsize::new(0),
            attr_step: AtomicUsize::new(0),
        };

        let mut ctx = InjectContext::new();
        ctx.decode(&decoder).expect("decode should succeed");

        assert_eq!(ctx.base_addr, space.address(0x10));
        assert_eq!(ctx.call_addr, space.address(0x20));

        let input = ctx.input_list.expect("input_list should be populated");
        assert_eq!(input.len(), 2);
        assert_eq!(input[0].get_offset(), 0x100);
        assert_eq!(input[0].get_size(), 4);
        assert_eq!(input[1].get_offset(), 0x104);
        assert_eq!(input[1].get_size(), 8);

        let output = ctx.output.expect("output should be populated");
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].get_offset(), 0x200);
        assert_eq!(output[0].get_size(), 2);
    }
}
