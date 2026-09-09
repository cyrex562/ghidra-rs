use std::any::Any;
use std::sync::Arc;

use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::protorules::assign_action::AssignAction;
use crate::program::model::lang::storage_class::StorageClass;
use crate::program::model::pcode::{Encoder, ATTRIB_STORAGE, ELEM_CONSUME};
use crate::program::seam_stubs::{ParamListStandardLike, ParameterPieces, PrototypePieces};
use crate::util::exception::InvalidInputException;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Consume a parameter from a specific resource list.
///
/// Normally the resource list is determined by the parameter data-type, but this action
/// specifies an overriding resource list.
///
/// Port of `ghidra.program.model.lang.protorules.ConsumeAs`.
pub struct ConsumeAs {
    /// The resource list this action allocates from (`AssignAction.resource`).
    resource: Arc<dyn ParamListStandardLike>,
    /// The resource list the parameter is consumed from (`ConsumeAs.resourceType`).
    resource_type: StorageClass,
}

impl ConsumeAs {
    /// Port of the public constructor.
    pub fn new(store: StorageClass, res: Arc<dyn ParamListStandardLike>) -> Self {
        ConsumeAs {
            resource: res,
            resource_type: store,
        }
    }
}

impl AssignAction for ConsumeAs {
    fn clone_box(
        &self,
        new_resource: Arc<dyn ParamListStandardLike>,
    ) -> Result<Box<dyn AssignAction>, InvalidInputException> {
        Ok(Box::new(ConsumeAs::new(self.resource_type, new_resource)))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn is_equivalent(&self, op: &dyn AssignAction) -> bool {
        let Some(other) = op.as_any().downcast_ref::<ConsumeAs>() else {
            return false;
        };
        self.resource_type == other.resource_type
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
        self.resource
            .assign_address_fallback(self.resource_type, dt, true, status, res)
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        encoder.open_element(ELEM_CONSUME)?;
        encoder.write_string(ATTRIB_STORAGE, &self.resource_type.to_string())?;
        encoder.close_element(ELEM_CONSUME)?;
        Ok(())
    }

    fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), XmlParseException>
    where
        Self: Sized,
    {
        let elem = parser
            .start(&[ELEM_CONSUME.name])
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        let storage_string = elem.get_attribute(ATTRIB_STORAGE.name).unwrap_or_default();
        self.resource_type = StorageClass::from_str(&storage_string)?;
        parser
            .end()
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::protorules::assign_action::{FAIL, SUCCESS};
    use crate::program::model::lang::protorules::param_test_support::{ram_space, TestEntry, TestResource};
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

    fn float_register_resource() -> Arc<dyn ParamListStandardLike> {
        Arc::new(TestResource {
            // align: 0 makes this a single "exclusion" slot (a single dedicated register),
            // which is the typical shape of a per-storage-class ParamEntry in a real .cspec.
            entries: vec![Arc::new(TestEntry {
                ty: StorageClass::Float,
                group: 0,
                addressbase: 0x100,
                align: 0,
                ..TestEntry::default()
            })],
            num_group: 1,
            spacebase: Some(ram_space()),
        })
    }

    #[test]
    fn assign_address_delegates_to_resource_fallback_with_match_exact() {
        let action = ConsumeAs::new(StorageClass::Float, float_register_resource());
        let dt: Arc<dyn DataType> = Arc::new(MockDataType { length: 4 });
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut res = ParameterPieces::default();
        let mut status = [0i32; 1];

        let code = action.assign_address(&dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, SUCCESS);
        assert_eq!(res.address.unwrap().offset(), 0x100);
        assert_eq!(status[0], -1); // Exclusion entry: fully consumed after one use
    }

    #[test]
    fn assign_address_fails_when_no_entry_of_the_requested_class_exists() {
        // match_exact=true means a StorageClass::General entry does NOT satisfy a request for
        // StorageClass::Float (unlike the plain resource.assignAddress fallback, which would
        // accept a general entry).
        let general_only = Arc::new(TestResource {
            entries: vec![Arc::new(TestEntry { ty: StorageClass::General, ..TestEntry::default() })],
            num_group: 1,
            spacebase: None,
        });
        let action = ConsumeAs::new(StorageClass::Float, general_only);
        let dt: Arc<dyn DataType> = Arc::new(MockDataType { length: 4 });
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut res = ParameterPieces::default();
        let mut status = [0i32; 1];

        let code = action.assign_address(&dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, FAIL);
    }

    #[test]
    fn is_equivalent_compares_resource_type_only() {
        let a = ConsumeAs::new(StorageClass::Float, float_register_resource());
        let b = ConsumeAs::new(StorageClass::Float, float_register_resource());
        let c = ConsumeAs::new(StorageClass::Vector, float_register_resource());
        assert!(a.is_equivalent(&b));
        assert!(!a.is_equivalent(&c));
    }

    #[test]
    fn clone_box_carries_resource_type_and_new_resource() {
        let action = ConsumeAs::new(StorageClass::Ptr, float_register_resource());
        let cloned = action
            .clone_box(float_register_resource())
            .expect("clone should succeed");
        assert!(action.is_equivalent(cloned.as_ref()));
    }

    struct RecordingEncoder {
        elements: Vec<&'static str>,
        strings: Vec<(&'static str, String)>,
    }
    impl RecordingEncoder {
        fn new() -> Self {
            RecordingEncoder { elements: Vec::new(), strings: Vec::new() }
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
        fn write_bool(&mut self, _attrib_id: AttributeId, _val: bool) -> std::io::Result<()> {
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
        fn write_space(&mut self, _attrib_id: AttributeId, _spc: &crate::program::model::address::AddressSpace) -> std::io::Result<()> {
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
    fn encode_writes_consume_element_with_storage_attribute() {
        let action = ConsumeAs::new(StorageClass::Vector, float_register_resource());
        let mut enc = RecordingEncoder::new();
        action.encode(&mut enc).unwrap();
        assert_eq!(enc.elements, vec!["consume"]);
        assert_eq!(enc.strings, vec![("storage", "vector".to_string())]);
    }

    #[test]
    fn restore_xml_reads_storage_class() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("consume", 0, &[("storage", "ptr")]),
            MockElement::end("consume", 0),
        ]);
        let mut action = ConsumeAs::new(StorageClass::General, float_register_resource());
        action.restore_xml(&mut parser).unwrap();
        assert_eq!(action.resource_type, StorageClass::Ptr);
    }

    #[test]
    fn restore_xml_rejects_unknown_storage_class() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("consume", 0, &[("storage", "bogus")]),
            MockElement::end("consume", 0),
        ]);
        let mut action = ConsumeAs::new(StorageClass::General, float_register_resource());
        assert!(action.restore_xml(&mut parser).is_err());
    }

    #[test]
    fn usable_as_trait_object() {
        let action: Box<dyn AssignAction> =
            Box::new(ConsumeAs::new(StorageClass::Float, float_register_resource()));
        let dt: Arc<dyn DataType> = Arc::new(MockDataType { length: 4 });
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut res = ParameterPieces::default();
        let mut status = [0i32; 1];
        let code = action.assign_address(&dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, SUCCESS);
    }
}
