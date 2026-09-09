use std::any::Any;
use std::sync::Arc;

use crate::program::model::address::AddressSpace;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::pointer::Pointer;
use crate::program::model::lang::protorules::assign_action::AssignAction;
use crate::program::model::pcode::{Encoder, ELEM_CONVERT_TO_PTR};
use crate::program::seam_stubs::{ParamListStandardLike, ParameterPieces, PrototypePieces};
use crate::util::exception::InvalidInputException;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Adapts a `Box<dyn Pointer>` so it can be stored/passed as `Arc<dyn DataType>`.
///
/// `Pointer: DataType` in the Java sense (`Pointer` is an interface extending `DataType`), but
/// `Pointer` itself declares no `DataType` overrides, so wrapping and using the default
/// `DataType` behavior here is equivalent to what a real upcast would observe. Mirrors the
/// identically-motivated `PointerAsDataType` in
/// [`param_list_standard_out`](crate::program::model::lang::param_list_standard_out).
struct PointerAsDataType(Box<dyn Pointer>);

impl DataType for PointerAsDataType {
    fn is_pointer(&self) -> bool {
        true
    }
}

/// Action converting the parameter's data-type to a pointer, and assigning storage for the
/// pointer. This assumes the data-type is stored elsewhere and only the pointer is passed as a
/// parameter.
///
/// Port of `ghidra.program.model.lang.protorules.ConvertToPointer`.
pub struct ConvertToPointer {
    /// The resource list this action allocates from (`AssignAction.resource`).
    resource: Arc<dyn ParamListStandardLike>,
    /// Address space used for pointer size (`ConvertToPointer.space`).
    space: Option<Arc<AddressSpace>>,
}

impl ConvertToPointer {
    /// Port of the public constructor.
    pub fn new(res: Arc<dyn ParamListStandardLike>) -> Self {
        let space = res.spacebase();
        ConvertToPointer { resource: res, space }
    }
}

impl AssignAction for ConvertToPointer {
    fn clone_box(
        &self,
        new_resource: Arc<dyn ParamListStandardLike>,
    ) -> Result<Box<dyn AssignAction>, InvalidInputException> {
        Ok(Box::new(ConvertToPointer::new(new_resource)))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn is_equivalent(&self, op: &dyn AssignAction) -> bool {
        let Some(other) = op.as_any().downcast_ref::<ConvertToPointer>() else {
            return false;
        };
        match (&self.space, &other.space) {
            (None, None) => true,
            (Some(a), Some(b)) => a.as_ref() == b.as_ref(),
            _ => false,
        }
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
        let pointer_size = self.space.as_ref().map_or(-1, |space| space.pointer_size());
        // Convert the data-type to a pointer
        let pointer = dt_manager.get_pointer_with_size(dt.as_ref(), pointer_size);
        let pointer_type: Arc<dyn DataType> = Arc::new(PointerAsDataType(pointer));
        // (Recursively) assign storage
        let response_code = self
            .resource
            .assign_address(&pointer_type, proto, pos, dt_manager, status, res);
        res.is_indirect = true;
        response_code
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        encoder.open_element(ELEM_CONVERT_TO_PTR)?;
        encoder.close_element(ELEM_CONVERT_TO_PTR)?;
        Ok(())
    }

    fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), XmlParseException>
    where
        Self: Sized,
    {
        parser
            .start(&[ELEM_CONVERT_TO_PTR.name])
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        parser
            .end()
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;
    use crate::program::model::lang::protorules::assign_action::{FAIL, SUCCESS};
    use crate::program::model::lang::protorules::xml_test_support::{MockElement, QueueParser};
    use crate::program::model::pcode::{AttributeId, ElementId};

    struct MockDataType {
        length: i32,
    }
    impl DataType for MockDataType {
        fn get_length(&self) -> i32 {
            self.length
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    /// A resource list that succeeds only when handed a pointer-typed data-type -- used to
    /// verify `ConvertToPointer` actually recurses through `resource.assign_address` with the
    /// *converted* pointer type, rather than the original (non-pointer) data-type.
    struct PointerOnlyResource {
        spacebase: Arc<AddressSpace>,
    }
    impl ParamListStandardLike for PointerOnlyResource {
        fn spacebase(&self) -> Option<Arc<AddressSpace>> {
            Some(self.spacebase.clone())
        }
        fn assign_address(
            &self,
            dt: &Arc<dyn DataType>,
            _proto: &PrototypePieces,
            _pos: i32,
            _dt_manager: &dyn DataTypeManager,
            status: &mut [i32],
            res: &mut ParameterPieces,
        ) -> i32 {
            if !dt.is_pointer() {
                return FAIL;
            }
            status[0] += 1;
            res.data_type = Some(dt.clone());
            SUCCESS
        }
    }

    fn resource() -> Arc<dyn ParamListStandardLike> {
        Arc::new(PointerOnlyResource { spacebase: ram_space() })
    }

    #[test]
    fn assign_address_converts_to_pointer_and_marks_indirect() {
        let action = ConvertToPointer::new(resource());
        let dt: Arc<dyn DataType> = Arc::new(MockDataType { length: 32 }); // large struct-like type
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut res = ParameterPieces::default();
        let mut status = [0i32; 1];

        let code = action.assign_address(&dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, SUCCESS);
        assert!(res.is_indirect);
        assert!(res.data_type.as_ref().is_some_and(|d| d.is_pointer()));
        assert_eq!(status[0], 1);
    }

    #[test]
    fn assign_address_still_marks_indirect_on_failure() {
        // Matches the real Java quirk: `res.isIndirect = true` runs unconditionally after the
        // recursive assignAddress call, even if that call failed.
        struct AlwaysFail;
        impl ParamListStandardLike for AlwaysFail {}
        let action = ConvertToPointer::new(Arc::new(AlwaysFail));
        let dt: Arc<dyn DataType> = Arc::new(MockDataType { length: 8 });
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut res = ParameterPieces::default();
        let mut status = [0i32; 1];

        let code = action.assign_address(&dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, FAIL);
        assert!(res.is_indirect);
    }

    #[test]
    fn is_equivalent_compares_space() {
        let a = ConvertToPointer::new(resource());
        let b = ConvertToPointer::new(resource());
        assert!(a.is_equivalent(&b));

        struct NoSpace;
        impl ParamListStandardLike for NoSpace {}
        let c = ConvertToPointer::new(Arc::new(NoSpace));
        assert!(!a.is_equivalent(&c));
    }

    #[test]
    fn clone_box_recomputes_space_from_new_resource() {
        let action = ConvertToPointer::new(resource());
        let cloned = action.clone_box(resource()).expect("clone should succeed");
        assert!(action.is_equivalent(cloned.as_ref()));
    }

    struct RecordingEncoder {
        elements: Vec<&'static str>,
    }
    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: ElementId) -> std::io::Result<()> {
            self.elements.push(elem_id.name);
            Ok(())
        }
        fn close_element(&mut self, _elem_id: ElementId) -> std::io::Result<()> {
            Ok(())
        }
        fn write_bool(&mut self, _attrib_id: AttributeId, _val: bool) -> std::io::Result<()> {
            Ok(())
        }
        fn write_signed_integer(&mut self, _attrib_id: AttributeId, _val: i64) -> std::io::Result<()> {
            Ok(())
        }
        fn write_unsigned_integer(&mut self, _attrib_id: AttributeId, _val: u64) -> std::io::Result<()> {
            Ok(())
        }
        fn write_string(&mut self, _attrib_id: AttributeId, _val: &str) -> std::io::Result<()> {
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
    fn encode_writes_bare_convert_to_ptr_element() {
        let action = ConvertToPointer::new(resource());
        let mut enc = RecordingEncoder { elements: Vec::new() };
        action.encode(&mut enc).unwrap();
        assert_eq!(enc.elements, vec!["convert_to_ptr"]);
    }

    #[test]
    fn restore_xml_accepts_bare_element() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("convert_to_ptr", 0, &[]),
            MockElement::end("convert_to_ptr", 0),
        ]);
        let mut action = ConvertToPointer::new(resource());
        assert!(action.restore_xml(&mut parser).is_ok());
    }

    #[test]
    fn usable_as_trait_object() {
        let action: Box<dyn AssignAction> = Box::new(ConvertToPointer::new(resource()));
        let dt: Arc<dyn DataType> = Arc::new(MockDataType { length: 16 });
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut res = ParameterPieces::default();
        let mut status = [0i32; 1];
        let code = action.assign_address(&dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, SUCCESS);
    }
}
