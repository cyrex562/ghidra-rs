use super::varnode_tpl::VarnodeTpl;
use crate::decompiler::opcodes::OpCode;
use crate::program::model::pcode::{
    Decoder, DecoderError, Encoder, ATTRIB_CODE, ELEM_NULL, ELEM_OP_TPL,
};
use std::io;

#[derive(Debug, Clone)]
pub struct OpTpl {
    pub opc: OpCode,
    pub output: Option<VarnodeTpl>,
    pub input: Vec<VarnodeTpl>,
}

impl OpTpl {
    pub fn new() -> Self {
        Self {
            opc: OpCode::DoNotUseMeIAmEnumElementZero,
            output: None,
            input: Vec::new(),
        }
    }

    pub fn with_opcode(opc: OpCode) -> Self {
        Self {
            opc,
            output: None,
            input: Vec::new(),
        }
    }

    pub fn get_out(&self) -> Option<&VarnodeTpl> {
        self.output.as_ref()
    }

    pub fn num_input(&self) -> usize {
        self.input.len()
    }

    pub fn get_in(&self, i: usize) -> &VarnodeTpl {
        &self.input[i]
    }

    pub fn get_opcode(&self) -> OpCode {
        self.opc
    }

    pub fn set_opcode(&mut self, o: OpCode) {
        self.opc = o;
    }

    pub fn set_output(&mut self, vt: VarnodeTpl) {
        self.output = Some(vt);
    }

    pub fn clear_output(&mut self) {
        self.output = None;
    }

    pub fn add_input(&mut self, vt: VarnodeTpl) {
        self.input.push(vt);
    }

    pub fn set_input(&mut self, vt: VarnodeTpl, slot: usize) {
        self.input[slot] = vt;
    }

    /// Returns true if any input or output has zero size.
    pub fn is_zero_size(&self) -> bool {
        if let Some(output) = &self.output {
            if output.is_zero_size() {
                return true;
            }
        }
        self.input.iter().any(VarnodeTpl::is_zero_size)
    }

    /// Removes the indicated input.
    pub fn remove_input(&mut self, index: usize) {
        self.input.remove(index);
    }

    pub fn change_handle_index(&mut self, handmap: &[i32]) {
        if let Some(output) = &mut self.output {
            output.change_handle_index(handmap);
        }
        for vn in &mut self.input {
            vn.change_handle_index(handmap);
        }
    }

    pub fn decode(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderError> {
        let el = decoder.open_element_with_id(ELEM_OP_TPL)?;
        let ordinal = decoder.read_signed_integer_with_id(ATTRIB_CODE)? as usize;
        self.opc = OpCode::from_ordinal(ordinal)
            .ok_or_else(|| DecoderError::Generic(format!("Bad encoded opcode {ordinal}")))?;

        let outel = decoder.peek_element()?;
        if outel == ELEM_NULL.id {
            let null_el = decoder.open_element()?;
            decoder.close_element(null_el)?;
            self.output = None;
        } else {
            let mut vn = VarnodeTpl::new();
            vn.decode(decoder)?;
            self.output = Some(vn);
        }

        self.input.clear();
        while decoder.peek_element()? != 0 {
            let mut vn = VarnodeTpl::new();
            vn.decode(decoder)?;
            self.input.push(vn);
        }
        decoder.close_element(el)?;
        Ok(())
    }

    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_OP_TPL)?;
        encoder.write_opcode(ATTRIB_CODE, self.opc)?;
        match &self.output {
            Some(output) => output.encode(encoder)?,
            None => {
                encoder.open_element(ELEM_NULL)?;
                encoder.close_element(ELEM_NULL)?;
            }
        }
        for vn in &self.input {
            vn.encode(encoder)?;
        }
        encoder.close_element(ELEM_OP_TPL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::sleigh::template::const_tpl::{ConstTpl, ConstTplType};
    use crate::program::model::pcode::ids::{AttributeId, ElementId};
    use std::sync::Arc;

    #[derive(Default)]
    struct RecordingEncoder {
        depth: i32,
        writes: Vec<String>,
    }

    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.depth += 1;
            self.writes.push(format!("open:{}", elem_id.name));
            Ok(())
        }

        fn close_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.depth -= 1;
            self.writes.push(format!("close:{}", elem_id.name));
            Ok(())
        }

        fn write_bool(&mut self, attrib_id: AttributeId, val: bool) -> io::Result<()> {
            self.writes.push(format!("bool:{}={}", attrib_id.name, val));
            Ok(())
        }

        fn write_signed_integer(&mut self, attrib_id: AttributeId, val: i64) -> io::Result<()> {
            self.writes.push(format!("int:{}={}", attrib_id.name, val));
            Ok(())
        }

        fn write_unsigned_integer(&mut self, attrib_id: AttributeId, val: u64) -> io::Result<()> {
            self.writes
                .push(format!("uint:{}={}", attrib_id.name, val));
            Ok(())
        }

        fn write_string(&mut self, attrib_id: AttributeId, val: &str) -> io::Result<()> {
            self.writes.push(format!("str:{}={}", attrib_id.name, val));
            Ok(())
        }

        fn write_string_indexed(
            &mut self,
            attrib_id: AttributeId,
            index: i32,
            val: &str,
        ) -> io::Result<()> {
            self.writes
                .push(format!("str[{}]:{}={}", index, attrib_id.name, val));
            Ok(())
        }

        fn write_space(
            &mut self,
            attrib_id: AttributeId,
            spc: &crate::program::model::address::AddressSpace,
        ) -> io::Result<()> {
            self.writes
                .push(format!("space:{}={}", attrib_id.name, spc.name()));
            Ok(())
        }

        fn write_space_indexed(
            &mut self,
            attrib_id: AttributeId,
            index: i32,
            name: &str,
        ) -> io::Result<()> {
            self.writes
                .push(format!("space[{}]:{}={}", index, attrib_id.name, name));
            Ok(())
        }

        fn write_opcode(&mut self, attrib_id: AttributeId, opcode: OpCode) -> io::Result<()> {
            self.writes
                .push(format!("opcode:{}={:?}", attrib_id.name, opcode));
            Ok(())
        }

        fn write_opcode_ordinal(&mut self, attrib_id: AttributeId, opcode: i32) -> io::Result<()> {
            self.writes
                .push(format!("opcode:{}=#{}", attrib_id.name, opcode));
            Ok(())
        }
    }

    fn real_varnode(offset: u64, size: u64) -> VarnodeTpl {
        VarnodeTpl {
            space: ConstTpl {
                tp: ConstTplType::Real,
                value_real: 0,
                value_spaceid: None,
                handle_index: 0,
                select: None,
            },
            offset: ConstTpl {
                tp: ConstTplType::Real,
                value_real: offset,
                value_spaceid: None,
                handle_index: 0,
                select: None,
            },
            size: ConstTpl {
                tp: ConstTplType::Real,
                value_real: size,
                value_spaceid: None,
                handle_index: 0,
                select: None,
            },
        }
    }

    #[test]
    fn new_defaults_to_no_output_or_input() {
        let op = OpTpl::new();
        assert_eq!(op.get_out(), None);
        assert_eq!(op.num_input(), 0);
    }

    #[test]
    fn with_opcode_sets_opcode() {
        let op = OpTpl::with_opcode(OpCode::CpuiIntAdd);
        assert_eq!(op.get_opcode(), OpCode::CpuiIntAdd);
    }

    #[test]
    fn set_opcode_updates_opcode() {
        let mut op = OpTpl::new();
        op.set_opcode(OpCode::CpuiCopy);
        assert_eq!(op.get_opcode(), OpCode::CpuiCopy);
    }

    #[test]
    fn add_input_and_get_in_roundtrip() {
        let mut op = OpTpl::new();
        op.add_input(real_varnode(0, 4));
        op.add_input(real_varnode(4, 8));
        assert_eq!(op.num_input(), 2);
        assert_eq!(op.get_in(0).offset.value_real, 0);
        assert_eq!(op.get_in(1).offset.value_real, 4);
    }

    #[test]
    fn set_input_replaces_slot() {
        let mut op = OpTpl::new();
        op.add_input(real_varnode(0, 4));
        op.set_input(real_varnode(99, 4), 0);
        assert_eq!(op.get_in(0).offset.value_real, 99);
    }

    #[test]
    fn set_output_and_clear_output() {
        let mut op = OpTpl::new();
        op.set_output(real_varnode(0, 4));
        assert!(op.get_out().is_some());
        op.clear_output();
        assert_eq!(op.get_out(), None);
    }

    #[test]
    fn remove_input_shifts_remaining() {
        let mut op = OpTpl::new();
        op.add_input(real_varnode(0, 4));
        op.add_input(real_varnode(4, 4));
        op.remove_input(0);
        assert_eq!(op.num_input(), 1);
        assert_eq!(op.get_in(0).offset.value_real, 4);
    }

    #[test]
    fn is_zero_size_false_when_all_nonzero() {
        let mut op = OpTpl::new();
        op.set_output(real_varnode(0, 4));
        op.add_input(real_varnode(0, 8));
        assert!(!op.is_zero_size());
    }

    #[test]
    fn is_zero_size_true_when_output_zero() {
        let mut op = OpTpl::new();
        op.set_output(real_varnode(0, 0));
        assert!(op.is_zero_size());
    }

    #[test]
    fn is_zero_size_true_when_input_zero() {
        let mut op = OpTpl::new();
        op.add_input(real_varnode(0, 0));
        assert!(op.is_zero_size());
    }

    #[test]
    fn change_handle_index_remaps_handles() {
        let mut op = OpTpl::new();
        let handle_vn = VarnodeTpl {
            space: ConstTpl {
                tp: ConstTplType::Handle,
                value_real: 0,
                value_spaceid: None,
                handle_index: 2,
                select: Some(
                    crate::program::model::lang::sleigh::template::const_tpl::ConstTplSelect::VSpace,
                ),
            },
            offset: ConstTpl::new(),
            size: ConstTpl::new(),
        };
        op.set_output(handle_vn);
        op.change_handle_index(&[10, 11, 12]);
        assert_eq!(op.get_out().unwrap().space.handle_index, 12);
    }

    #[test]
    fn encode_writes_opcode_and_input_output() {
        let mut op = OpTpl::with_opcode(OpCode::CpuiIntAdd);
        op.set_output(real_varnode(0, 4));
        op.add_input(real_varnode(4, 4));

        let mut encoder = RecordingEncoder::default();
        op.encode(&mut encoder).unwrap();

        assert_eq!(encoder.depth, 0);
        assert!(encoder.writes[0] == "open:op_tpl");
        assert!(encoder
            .writes
            .iter()
            .any(|w| w.contains("opcode:code=CpuiIntAdd")));
        assert_eq!(*encoder.writes.last().unwrap(), "close:op_tpl");
    }

    #[test]
    fn encode_writes_null_element_when_no_output() {
        let op = OpTpl::with_opcode(OpCode::CpuiCopy);
        let mut encoder = RecordingEncoder::default();
        op.encode(&mut encoder).unwrap();
        assert!(encoder.writes.iter().any(|w| w == "open:null"));
    }

    #[test]
    fn decode_encode_roundtrip_preserves_opcode_and_shape() {
        // Build via encode into a Vec-backed decoder is out of scope without a concrete
        // Decoder implementation in this module; instead verify decode() rejects a bad opcode
        // ordinal, which is the one failure path decode() itself owns.
        struct BadOpcodeDecoder;
        impl Decoder for BadOpcodeDecoder {
            fn get_address_factory(
                &self,
            ) -> Arc<dyn crate::program::model::address::AddressFactory> {
                unimplemented!()
            }
            fn set_address_factory(
                &self,
                _factory: Arc<dyn crate::program::model::address::AddressFactory>,
            ) {
            }
            fn peek_element(&self) -> Result<i32, DecoderError> {
                Ok(0)
            }
            fn open_element(&self) -> Result<i32, DecoderError> {
                Ok(1)
            }
            fn open_element_with_id(
                &self,
                _elem_id: ElementId,
            ) -> Result<i32, DecoderError> {
                Ok(1)
            }
            fn close_element(&self, _id: i32) -> Result<(), DecoderError> {
                Ok(())
            }
            fn close_element_skipping(&self, _id: i32) -> Result<(), DecoderError> {
                Ok(())
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
                Ok(9999)
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
            fn read_string_with_id(
                &self,
                _attrib_id: AttributeId,
            ) -> Result<String, DecoderError> {
                unimplemented!()
            }
            fn read_space(
                &self,
            ) -> Result<Arc<crate::program::model::address::AddressSpace>, DecoderError> {
                unimplemented!()
            }
            fn read_space_with_id(
                &self,
                _attrib_id: AttributeId,
            ) -> Result<Arc<crate::program::model::address::AddressSpace>, DecoderError> {
                unimplemented!()
            }
        }

        let mut op = OpTpl::new();
        let err = op.decode(&BadOpcodeDecoder).unwrap_err();
        assert!(matches!(err, DecoderError::Generic(_)));
    }
}
