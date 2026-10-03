pub mod const_tpl;
pub mod handle_tpl;
pub mod op_tpl;
pub mod varnode_tpl;

use crate::decompiler::opcodes::op_code::OpCode;
use crate::program::model::pcode::{
    Decoder, DecoderError, Encoder, ATTRIB_LABELS, ATTRIB_SECTION, ELEM_CONSTRUCT_TPL, ELEM_NULL,
};
use std::io;

pub use const_tpl::{ConstTpl, ConstTplSelect, ConstTplType};
pub use handle_tpl::HandleTpl;
pub use op_tpl::OpTpl;
pub use varnode_tpl::VarnodeTpl;

/// Models `ghidra.pcodeCPort.semantics.ConstructTpl`. Java's `delayslot` field isn't ported: it's
/// marked `// FIXME: Seems to be unused` in the Java source itself, is never written by
/// `decode()`, and `encode()` only writes it when non-zero -- since nothing ever sets it, that
/// branch never fires in practice.
#[derive(Debug, Clone)]
pub struct ConstructTpl {
    pub num_labels: i32,
    pub vec: Vec<OpTpl>,
    pub result: Option<HandleTpl>,
}

impl ConstructTpl {
    pub fn new() -> Self {
        Self {
            num_labels: 0,
            vec: Vec::new(),
            result: None,
        }
    }

    pub fn decode(&mut self, decoder: &dyn Decoder) -> Result<i32, DecoderError> {
        let mut section_id = -1;
        self.num_labels = 0;
        let el = decoder.open_element_with_id(ELEM_CONSTRUCT_TPL)?;

        loop {
            let attr = decoder.get_next_attribute_id()?;
            if attr == 0 {
                break;
            }
            if attr == ATTRIB_LABELS.id {
                self.num_labels = decoder.read_signed_integer()? as i32;
            } else if attr == ATTRIB_SECTION.id {
                section_id = decoder.read_signed_integer()? as i32;
            }
        }

        let hand_el = decoder.peek_element()?;
        if hand_el == ELEM_NULL.id {
            let null_el = decoder.open_element()?;
            decoder.close_element(null_el)?;
            self.result = None;
        } else {
            let mut hand = HandleTpl::new();
            hand.decode(decoder)?;
            self.result = Some(hand);
        }

        self.vec.clear();
        while decoder.peek_element()? != 0 {
            let mut op = OpTpl::new();
            op.decode(decoder)?;
            self.vec.push(op);
        }
        decoder.close_element(el)?;
        Ok(section_id)
    }

    /// Remaps handle-typed constants across every op and the result, matching Java's special
    /// case for `CPUI_MULTIEQUAL` build-directive ops (Java's `changeHandleIndex`): a
    /// MULTIEQUAL's single input encodes a raw operand index as a real constant offset rather
    /// than a normal varnode reference, so it's remapped directly instead of going through
    /// `OpTpl::change_handle_index`'s usual per-varnode handle remapping.
    pub fn change_handle_index(&mut self, handmap: &[i32]) {
        for op in &mut self.vec {
            if op.get_opcode() == OpCode::CpuiMultiequal {
                let index = op.get_in(0).offset.value_real as usize;
                let mut new_in = op.get_in(0).clone();
                new_in.offset = ConstTpl {
                    tp: ConstTplType::Real,
                    value_real: handmap[index] as u64,
                    value_spaceid: None,
                    handle_index: 0,
                    select: None,
                };
                op.set_input(new_in, 0);
            } else {
                op.change_handle_index(handmap);
            }
        }
        if let Some(result) = &mut self.result {
            result.change_handle_index(handmap);
        }
    }

    pub fn encode(&self, encoder: &mut dyn Encoder, section_id: i32) -> io::Result<()> {
        encoder.open_element(ELEM_CONSTRUCT_TPL)?;
        if section_id >= 0 {
            encoder.write_signed_integer(ATTRIB_SECTION, section_id as i64)?;
        }
        if self.num_labels != 0 {
            encoder.write_signed_integer(ATTRIB_LABELS, self.num_labels as i64)?;
        }
        match &self.result {
            Some(result) => result.encode(encoder)?,
            None => {
                encoder.open_element(ELEM_NULL)?;
                encoder.close_element(ELEM_NULL)?;
            }
        }
        for op in &self.vec {
            op.encode(encoder)?;
        }
        encoder.close_element(ELEM_CONSTRUCT_TPL)
    }
}

impl Default for ConstructTpl {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingEncoder {
        opened: Vec<&'static str>,
        closed: Vec<&'static str>,
        ints: Vec<i64>,
    }

    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: crate::program::model::pcode::ElementId) -> io::Result<()> {
            self.opened.push(elem_id.name);
            Ok(())
        }
        fn close_element(&mut self, elem_id: crate::program::model::pcode::ElementId) -> io::Result<()> {
            self.closed.push(elem_id.name);
            Ok(())
        }
        fn write_bool(&mut self, _a: crate::program::model::pcode::AttributeId, _v: bool) -> io::Result<()> { Ok(()) }
        fn write_signed_integer(&mut self, _a: crate::program::model::pcode::AttributeId, v: i64) -> io::Result<()> {
            self.ints.push(v);
            Ok(())
        }
        fn write_unsigned_integer(&mut self, _a: crate::program::model::pcode::AttributeId, _v: u64) -> io::Result<()> { Ok(()) }
        fn write_string(&mut self, _a: crate::program::model::pcode::AttributeId, _v: &str) -> io::Result<()> { Ok(()) }
        fn write_string_indexed(&mut self, _a: crate::program::model::pcode::AttributeId, _i: i32, _v: &str) -> io::Result<()> { Ok(()) }
        fn write_space(&mut self, _a: crate::program::model::pcode::AttributeId, _s: &crate::program::model::address::AddressSpace) -> io::Result<()> { Ok(()) }
        fn write_space_indexed(&mut self, _a: crate::program::model::pcode::AttributeId, _i: i32, _n: &str) -> io::Result<()> { Ok(()) }
        fn write_opcode(&mut self, _a: crate::program::model::pcode::AttributeId, _o: OpCode) -> io::Result<()> { Ok(()) }
        fn write_opcode_ordinal(&mut self, _a: crate::program::model::pcode::AttributeId, _o: i32) -> io::Result<()> { Ok(()) }
    }

    #[test]
    fn new_is_empty() {
        let tpl = ConstructTpl::new();
        assert_eq!(tpl.num_labels, 0);
        assert!(tpl.vec.is_empty());
        assert!(tpl.result.is_none());
    }

    #[test]
    fn encode_with_no_result_writes_null_element() {
        let tpl = ConstructTpl::new();
        let mut encoder = RecordingEncoder::default();
        tpl.encode(&mut encoder, -1).unwrap();
        assert_eq!(encoder.opened, vec!["construct_tpl", "null"]);
        assert_eq!(encoder.closed, vec!["null", "construct_tpl"]);
    }

    #[test]
    fn encode_writes_section_id_when_non_negative() {
        let tpl = ConstructTpl::new();
        let mut encoder = RecordingEncoder::default();
        tpl.encode(&mut encoder, 3).unwrap();
        assert_eq!(encoder.ints, vec![3]);
    }

    #[test]
    fn encode_omits_section_id_when_negative() {
        let tpl = ConstructTpl::new();
        let mut encoder = RecordingEncoder::default();
        tpl.encode(&mut encoder, -1).unwrap();
        assert!(encoder.ints.is_empty());
    }

    #[test]
    fn encode_writes_result_when_present() {
        let mut tpl = ConstructTpl::new();
        tpl.result = Some(HandleTpl::new());
        let mut encoder = RecordingEncoder::default();
        tpl.encode(&mut encoder, -1).unwrap();
        assert_eq!(encoder.opened[0], "construct_tpl");
        assert_eq!(encoder.opened[1], "handle_tpl");
        assert!(!encoder.opened.contains(&"null"));
    }

    #[test]
    fn change_handle_index_remaps_multiequal_input_as_a_raw_index() {
        let mut tpl = ConstructTpl::new();
        let mut op = OpTpl::with_opcode(OpCode::CpuiMultiequal);
        op.add_input(VarnodeTpl {
            space: ConstTpl::new(),
            offset: ConstTpl {
                tp: ConstTplType::Real,
                value_real: 2,
                value_spaceid: None,
                handle_index: 0,
                select: None,
            },
            size: ConstTpl::new(),
        });
        tpl.vec.push(op);

        tpl.change_handle_index(&[10, 11, 12]);

        assert_eq!(tpl.vec[0].get_in(0).offset.value_real, 12);
    }

    #[test]
    fn change_handle_index_remaps_ordinary_op_via_handle_remapping() {
        let mut tpl = ConstructTpl::new();
        let mut op = OpTpl::with_opcode(OpCode::CpuiCopy);
        op.add_input(VarnodeTpl::with_handle(0, false));
        tpl.vec.push(op);

        tpl.change_handle_index(&[7]);

        assert_eq!(tpl.vec[0].get_in(0).space.handle_index, 7);
    }
}
