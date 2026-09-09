use std::any::Any;
use std::sync::Arc;

use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::protorules::assign_action::{
    AssignAction, HIDDENRET_PTRPARAM, HIDDENRET_SPECIALREG, HIDDENRET_SPECIALREG_VOID,
};
use crate::program::model::pcode::{
    Encoder, ATTRIB_STRATEGY, ATTRIB_VOIDLOCK, ELEM_HIDDEN_RETURN,
};
use crate::program::seam_stubs::{ParamListStandardLike, ParameterPieces, PrototypePieces};
use crate::util::exception::InvalidInputException;
use crate::util::xml::spec_xml_utils::decode_boolean;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Allocate the return value as an input parameter.
///
/// A pointer to where the return value is to be stored is passed in as an input parameter. This
/// action signals this by returning one of [`HIDDENRET_PTRPARAM`] (the pointer is allocated as a
/// normal input parameter), [`HIDDENRET_SPECIALREG`] (the pointer is passed in a dedicated
/// register), or [`HIDDENRET_SPECIALREG_VOID`].
///
/// Usually, if a hidden return input is present, the normal register used for return will also
/// hold the pointer at the point(s) where the function returns. A signal of
/// [`HIDDENRET_SPECIALREG_VOID`] indicates the normal return register is not used to pass back
/// the pointer.
///
/// Port of `ghidra.program.model.lang.protorules.HiddenReturnAssign`.
pub struct HiddenReturnAssign {
    /// The resource list this action was configured against (`AssignAction.resource`). Not read
    /// by [`assign_address`](Self::assign_address) -- this action's whole behavior is just
    /// signaling `ret_code` back to the caller -- but retained so
    /// [`clone_box`](Self::clone_box) can carry it forward to the clone, mirroring the Java
    /// constructor's `super(res)` call.
    resource: Arc<dyn ParamListStandardLike>,
    /// The specific signal to pass back (`HiddenReturnAssign.retCode`).
    ret_code: i32,
}

impl HiddenReturnAssign {
    /// Strategy attribute value for a hidden-return pointer passed as a dedicated register
    /// (`HiddenReturnAssign.STRATEGY_SPECIAL`).
    pub const STRATEGY_SPECIAL: &'static str = "special";
    /// Strategy attribute value for a hidden-return pointer passed as a normal parameter
    /// (`HiddenReturnAssign.STRATEGY_NORMAL`).
    pub const STRATEGY_NORMAL: &'static str = "normalparam";

    /// Port of the public constructor.
    pub fn new(res: Arc<dyn ParamListStandardLike>, code: i32) -> Self {
        HiddenReturnAssign {
            resource: res,
            ret_code: code,
        }
    }
}

impl AssignAction for HiddenReturnAssign {
    fn clone_box(
        &self,
        new_resource: Arc<dyn ParamListStandardLike>,
    ) -> Result<Box<dyn AssignAction>, InvalidInputException> {
        Ok(Box::new(HiddenReturnAssign::new(new_resource, self.ret_code)))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn is_equivalent(&self, op: &dyn AssignAction) -> bool {
        let Some(other) = op.as_any().downcast_ref::<HiddenReturnAssign>() else {
            return false;
        };
        self.ret_code == other.ret_code
    }

    fn assign_address(
        &self,
        dt: &Arc<dyn DataType>,
        proto: &PrototypePieces,
        pos: i32,
        dt_manager: &dyn DataTypeManager,
        status: &mut [i32],
        res: &mut ParameterPieces,
    ) -> i32 {
        let _ = (dt, proto, pos, dt_manager, status, res, &self.resource);
        self.ret_code // Signal to assignMap to use TYPECLASS_HIDDENRET
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        encoder.open_element(ELEM_HIDDEN_RETURN)?;
        if self.ret_code == HIDDENRET_PTRPARAM {
            encoder.write_string(ATTRIB_STRATEGY, Self::STRATEGY_NORMAL)?;
        } else if self.ret_code == HIDDENRET_SPECIALREG_VOID {
            encoder.write_bool(ATTRIB_VOIDLOCK, true)?;
        }
        encoder.close_element(ELEM_HIDDEN_RETURN)?;
        Ok(())
    }

    fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), XmlParseException>
    where
        Self: Sized,
    {
        self.ret_code = HIDDENRET_SPECIALREG;
        let elem = parser
            .start(&[ELEM_HIDDEN_RETURN.name])
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        if let Some(strategy_string) = elem.get_attribute(ATTRIB_STRATEGY.name) {
            if strategy_string == Self::STRATEGY_NORMAL {
                self.ret_code = HIDDENRET_PTRPARAM;
            } else if strategy_string == Self::STRATEGY_SPECIAL {
                self.ret_code = HIDDENRET_SPECIALREG;
            } else {
                return Err(XmlParseException::new(format!(
                    "Bad <hidden_return> strategy: {strategy_string}"
                )));
            }
        }
        let void_lock_string = elem.get_attribute(ATTRIB_VOIDLOCK.name).unwrap_or_default();
        if decode_boolean(&void_lock_string) {
            self.ret_code = HIDDENRET_SPECIALREG_VOID;
        }
        parser
            .end()
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::protorules::assign_action::{FAIL, SUCCESS};
    use crate::program::model::lang::protorules::xml_test_support::{MockElement, QueueParser};
    use crate::program::model::pcode::{AttributeId, ElementId};

    struct MockResource;
    impl ParamListStandardLike for MockResource {}

    struct MockDataType;
    impl DataType for MockDataType {}

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    fn resource() -> Arc<dyn ParamListStandardLike> {
        Arc::new(MockResource)
    }

    #[test]
    fn assign_address_always_returns_the_configured_ret_code_and_ignores_dt() {
        let action = HiddenReturnAssign::new(resource(), HIDDENRET_SPECIALREG);
        let dt: Arc<dyn DataType> = Arc::new(MockDataType);
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut res = ParameterPieces::default();
        let mut status = [0i32; 1];

        let code = action.assign_address(&dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, HIDDENRET_SPECIALREG);
        // No resource consumed, no address assigned -- this action is a pure signal.
        assert_eq!(status[0], 0);
        assert!(res.address.is_none());
        // Sanity: the signal codes are distinct from ordinary SUCCESS/FAIL.
        assert_ne!(code, SUCCESS);
        assert_ne!(code, FAIL);
    }

    #[test]
    fn is_equivalent_compares_ret_code_only() {
        let a = HiddenReturnAssign::new(resource(), HIDDENRET_PTRPARAM);
        let b = HiddenReturnAssign::new(resource(), HIDDENRET_PTRPARAM);
        let c = HiddenReturnAssign::new(resource(), HIDDENRET_SPECIALREG);
        assert!(a.is_equivalent(&b));
        assert!(!a.is_equivalent(&c));
    }

    #[test]
    fn clone_box_carries_ret_code_and_new_resource() {
        let action = HiddenReturnAssign::new(resource(), HIDDENRET_SPECIALREG_VOID);
        let cloned = action
            .clone_box(resource())
            .expect("clone should succeed");
        assert!(action.is_equivalent(cloned.as_ref()));
        let cloned_concrete = cloned
            .as_any()
            .downcast_ref::<HiddenReturnAssign>()
            .unwrap();
        assert_eq!(cloned_concrete.ret_code, HIDDENRET_SPECIALREG_VOID);
    }

    struct RecordingEncoder {
        elements: Vec<&'static str>,
        strings: Vec<(&'static str, String)>,
        bools: Vec<(&'static str, bool)>,
    }
    impl RecordingEncoder {
        fn new() -> Self {
            RecordingEncoder {
                elements: Vec::new(),
                strings: Vec::new(),
                bools: Vec::new(),
            }
        }
    }
    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: ElementId) -> std::io::Result<()> {
            self.elements.push(elem_id.name);
            Ok(())
        }
        fn close_element(&mut self, _elem_id: ElementId) -> std::io::Result<()> {
            Ok(())
        }
        fn write_bool(&mut self, attrib_id: AttributeId, val: bool) -> std::io::Result<()> {
            self.bools.push((attrib_id.name, val));
            Ok(())
        }
        fn write_signed_integer(&mut self, _attrib_id: AttributeId, _val: i64) -> std::io::Result<()> {
            Ok(())
        }
        fn write_unsigned_integer(&mut self, _attrib_id: AttributeId, _val: u64) -> std::io::Result<()> {
            Ok(())
        }
        fn write_string(&mut self, attrib_id: AttributeId, val: &str) -> std::io::Result<()> {
            self.strings.push((attrib_id.name, val.to_string()));
            Ok(())
        }
        fn write_string_indexed(&mut self, _attrib_id: AttributeId, _index: i32, _val: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn write_space(&mut self, _attrib_id: AttributeId, _spc: &AddressSpace) -> std::io::Result<()> {
            Ok(())
        }
        fn write_space_indexed(&mut self, _attrib_id: AttributeId, _index: i32, _name: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn write_opcode(&mut self, _attrib_id: AttributeId, _opcode: crate::decompiler::opcodes::op_code::OpCode) -> std::io::Result<()> {
            Ok(())
        }
        fn write_opcode_ordinal(&mut self, _attrib_id: AttributeId, _opcode: i32) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn encode_writes_normal_strategy_for_ptrparam() {
        let action = HiddenReturnAssign::new(resource(), HIDDENRET_PTRPARAM);
        let mut enc = RecordingEncoder::new();
        action.encode(&mut enc).unwrap();
        assert_eq!(enc.elements, vec!["hidden_return"]);
        assert_eq!(enc.strings, vec![("strategy", "normalparam".to_string())]);
        assert!(enc.bools.is_empty());
    }

    #[test]
    fn encode_writes_voidlock_for_specialreg_void() {
        let action = HiddenReturnAssign::new(resource(), HIDDENRET_SPECIALREG_VOID);
        let mut enc = RecordingEncoder::new();
        action.encode(&mut enc).unwrap();
        assert!(enc.strings.is_empty());
        assert_eq!(enc.bools, vec![("voidlock", true)]);
    }

    #[test]
    fn encode_writes_nothing_extra_for_plain_specialreg() {
        // Matches the real Java quirk: HIDDENRET_SPECIALREG (the default produced by
        // restore_xml when no attributes are present) writes neither a "strategy" nor a
        // "voidlock" attribute -- round-tripping relies on restore_xml's own default.
        let action = HiddenReturnAssign::new(resource(), HIDDENRET_SPECIALREG);
        let mut enc = RecordingEncoder::new();
        action.encode(&mut enc).unwrap();
        assert!(enc.strings.is_empty());
        assert!(enc.bools.is_empty());
    }

    #[test]
    fn restore_xml_defaults_to_specialreg_with_no_attributes() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("hidden_return", 0, &[]),
            MockElement::end("hidden_return", 0),
        ]);
        let mut action = HiddenReturnAssign::new(resource(), 0);
        action.restore_xml(&mut parser).unwrap();
        assert_eq!(action.ret_code, HIDDENRET_SPECIALREG);
    }

    #[test]
    fn restore_xml_reads_normalparam_strategy() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("hidden_return", 0, &[("strategy", "normalparam")]),
            MockElement::end("hidden_return", 0),
        ]);
        let mut action = HiddenReturnAssign::new(resource(), 0);
        action.restore_xml(&mut parser).unwrap();
        assert_eq!(action.ret_code, HIDDENRET_PTRPARAM);
    }

    #[test]
    fn restore_xml_rejects_unknown_strategy() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("hidden_return", 0, &[("strategy", "bogus")]),
            MockElement::end("hidden_return", 0),
        ]);
        let mut action = HiddenReturnAssign::new(resource(), 0);
        assert!(action.restore_xml(&mut parser).is_err());
    }

    #[test]
    fn restore_xml_voidlock_overrides_strategy_to_specialreg_void() {
        // Matches the real Java quirk: `voidlock` is checked *after* `strategy`, so even a
        // "normalparam" strategy is overridden to HIDDENRET_SPECIALREG_VOID if voidlock="true"
        // is also present.
        let mut parser = QueueParser::new(vec![
            MockElement::start(
                "hidden_return",
                0,
                &[("strategy", "normalparam"), ("voidlock", "true")],
            ),
            MockElement::end("hidden_return", 0),
        ]);
        let mut action = HiddenReturnAssign::new(resource(), 0);
        action.restore_xml(&mut parser).unwrap();
        assert_eq!(action.ret_code, HIDDENRET_SPECIALREG_VOID);
    }

    #[test]
    fn usable_as_trait_object() {
        let action: Box<dyn AssignAction> =
            Box::new(HiddenReturnAssign::new(resource(), HIDDENRET_PTRPARAM));
        let dt: Arc<dyn DataType> = Arc::new(MockDataType);
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut res = ParameterPieces::default();
        let mut status = [0i32; 1];
        let code = action.assign_address(&dt, &proto, -1, &dt_manager, &mut status, &mut res);
        assert_eq!(code, HIDDENRET_PTRPARAM);
        let _ = Address::new(AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0), 0);
    }
}
