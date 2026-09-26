use std::any::Any;
use std::sync::Arc;

use crate::program::model::address::AddressSpaceType;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::param_entry::ParamEntry;
use crate::program::model::lang::protorules::assign_action::{AssignAction, SUCCESS};
use crate::program::model::pcode::{Encoder, ELEM_GOTO_STACK};
use crate::program::model::lang::param_list_standard::ParamListStandard;
use crate::program::seam_stubs::{ParameterPieces, PrototypePieces};
use crate::util::exception::InvalidInputException;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Find the first non-exclusion `ParamEntry` in `resource` whose space is a stack space.
///
/// Port of the private `initializeEntry` shared (identically, in Java) by `GotoStack` and
/// `ExtraStack`; duplicated here and in
/// [`extra_stack`](crate::program::model::lang::protorules::extra_stack) rather than factored
/// into one shared helper, mirroring the Java source's own duplication.
///
/// # Errors
/// Returns an error if no matching `<pentry>` exists.
fn find_stack_entry(resource: &ParamListStandard) -> Result<Arc<ParamEntry>, InvalidInputException> {
    for entry in resource.entries() {
        if !entry.is_exclusion() && entry.get_space().space_type() == AddressSpaceType::Stack {
            return Ok(entry.clone());
        }
    }
    Err(InvalidInputException::with_message(
        "Cannot find matching <pentry> for action: goto_stack",
    ))
}

/// Action assigning a parameter Address from the next available stack location.
///
/// Port of `ghidra.program.model.lang.protorules.GotoStack`.
pub struct GotoStack {
    /// Parameter Entry corresponding to the stack (`GotoStack.stackEntry`), shared with the
    /// resource list it was found in.
    stack_entry: Arc<ParamEntry>,
}

impl GotoStack {
    /// Port of the public constructor.
    ///
    /// # Errors
    /// Returns an error if `res` has no stack `ParamEntry`.
    pub fn new(res: &ParamListStandard) -> Result<Self, InvalidInputException> {
        let stack_entry = find_stack_entry(res)?;
        Ok(GotoStack { stack_entry })
    }
}

impl AssignAction for GotoStack {
    fn clone_box(
        &self,
        new_resource: &ParamListStandard,
    ) -> Result<Box<dyn AssignAction>, InvalidInputException> {
        Ok(Box::new(GotoStack::new(new_resource)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn is_equivalent(&self, op: &dyn AssignAction) -> bool {
        let Some(other) = op.as_any().downcast_ref::<GotoStack>() else {
            return false;
        };
        self.stack_entry.is_equivalent(&other.stack_entry)
    }

    fn assign_address(
        &self,
        _resource: &ParamListStandard,
        dt: &Arc<dyn DataType>,
        _proto: &PrototypePieces,
        _pos: i32,
        _dt_manager: &dyn DataTypeManager,
        status: &mut [i32],
        res: &mut ParameterPieces,
    ) -> i32 {
        let grp = self.stack_entry.get_group() as usize;
        res.data_type = Some(dt.clone());
        status[grp] = self.stack_entry.get_addr_by_slot(
            status[grp],
            dt.get_length(),
            dt.get_alignment(),
            res,
        );
        SUCCESS
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        encoder.open_element(ELEM_GOTO_STACK)?;
        encoder.close_element(ELEM_GOTO_STACK)?;
        Ok(())
    }

    fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        resource: &ParamListStandard,
    ) -> Result<(), XmlParseException>
    where
        Self: Sized,
    {
        parser
            .start(&[ELEM_GOTO_STACK.name])
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        parser
            .end()
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        self.stack_entry =
            find_stack_entry(resource).map_err(|e| XmlParseException::new(e.0))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::protorules::param_test_support::{
        ram_space, stack_space, TestEntry, TestResource,
    };
    use crate::program::model::lang::protorules::xml_test_support::{MockElement, QueueParser};
    use crate::program::model::lang::storage_class::StorageClass;
    use crate::program::model::pcode::{AttributeId, ElementId};

    struct MockDataType {
        length: i32,
        alignment: i32,
    }
    impl DataType for MockDataType {
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_alignment(&self) -> i32 {
            self.alignment
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    fn stack_resource() -> ParamListStandard {
        TestResource {
            entries: vec![
                TestEntry { ty: StorageClass::General, space: ram_space(), ..TestEntry::default() },
                TestEntry {
                    space: stack_space(),
                    group: 3,
                    align: 4,
                    numslots: 8,
                    addressbase: 0,
                    ..TestEntry::default()
                },
            ],
            num_group: 4,
            spacebase: None,
        }.build()
    }

    #[test]
    fn new_finds_the_stack_entry_skipping_non_stack_entries() {
        let action = GotoStack::new(&stack_resource()).expect("stack entry should be found");
        assert_eq!(action.stack_entry.get_group(), 3);
    }

    #[test]
    fn new_fails_when_no_stack_entry_exists() {
        let no_stack = TestResource {
            entries: vec![TestEntry::default()],
            num_group: 1,
            spacebase: None,
        }.build();
        assert!(GotoStack::new(&no_stack).is_err());
    }

    #[test]
    fn assign_address_allocates_sequential_stack_slots() {
        let action = GotoStack::new(&stack_resource()).unwrap();
        let dt: Arc<dyn DataType> = Arc::new(MockDataType { length: 4, alignment: 4 });
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut status = [0i32; 4];
        let mut res = ParameterPieces::default();

        let code = action.assign_address(&stack_resource(), &dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, SUCCESS);
        assert_eq!(res.address.unwrap().offset(), 0);
        assert_eq!(status[3], 1);
        assert!(res.data_type.as_ref().is_some());

        let mut res2 = ParameterPieces::default();
        let code2 = action.assign_address(&stack_resource(), &dt, &proto, 1, &dt_manager, &mut status, &mut res2);
        assert_eq!(code2, SUCCESS);
        assert_eq!(res2.address.unwrap().offset(), 4);
        assert_eq!(status[3], 2);
    }

    #[test]
    fn is_equivalent_compares_stack_entry() {
        let a = GotoStack::new(&stack_resource()).unwrap();
        let b = GotoStack::new(&stack_resource()).unwrap();
        assert!(a.is_equivalent(&b));

        let different = TestResource {
            entries: vec![TestEntry {
                space: stack_space(),
                group: 5, // different group -> not equivalent
                align: 4,
                numslots: 8,
                ..TestEntry::default()
            }],
            num_group: 6,
            spacebase: None,
        }.build();
        let c = GotoStack::new(&different).unwrap();
        assert!(!a.is_equivalent(&c));
    }

    #[test]
    fn clone_box_recomputes_stack_entry_from_new_resource() {
        let action = GotoStack::new(&stack_resource()).unwrap();
        let cloned = action.clone_box(&stack_resource()).expect("clone should succeed");
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
    fn encode_writes_bare_goto_stack_element() {
        let action = GotoStack::new(&stack_resource()).unwrap();
        let mut enc = RecordingEncoder { elements: Vec::new() };
        action.encode(&mut enc).unwrap();
        assert_eq!(enc.elements, vec!["goto_stack"]);
    }

    #[test]
    fn restore_xml_reinitializes_the_stack_entry() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("goto_stack", 0, &[]),
            MockElement::end("goto_stack", 0),
        ]);
        let resource = stack_resource();
        let mut action = GotoStack { stack_entry: find_stack_entry(&resource).unwrap() };
        action.restore_xml(&mut parser, &resource).unwrap();
        assert_eq!(action.stack_entry.get_group(), 3);
    }

    #[test]
    fn restore_xml_fails_when_resource_has_no_stack_entry() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("goto_stack", 0, &[]),
            MockElement::end("goto_stack", 0),
        ]);
        let no_stack = TestResource {
            entries: vec![TestEntry::default()],
            num_group: 1,
            spacebase: None,
        }.build();
        // Built against a resource that DOES have a stack entry, then restored against one that
        // doesn't, to exercise restore_xml's own error path.
        let mut action = GotoStack::new(&stack_resource()).unwrap();
        assert!(action.restore_xml(&mut parser, &no_stack).is_err());
    }

    #[test]
    fn usable_as_trait_object() {
        let action: Box<dyn AssignAction> = Box::new(GotoStack::new(&stack_resource()).unwrap());
        let dt: Arc<dyn DataType> = Arc::new(MockDataType { length: 4, alignment: 4 });
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut status = [0i32; 4];
        let mut res = ParameterPieces::default();
        let code = action.assign_address(&stack_resource(), &dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, SUCCESS);
    }
}
