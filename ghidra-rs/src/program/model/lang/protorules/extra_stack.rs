use std::any::Any;
use std::sync::Arc;

use crate::program::model::address::AddressSpaceType;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::param_entry::ParamEntry;
use crate::program::model::lang::protorules::assign_action::{AssignAction, SUCCESS};
use crate::program::model::lang::storage_class::StorageClass;
use crate::program::model::pcode::{
    Encoder, ATTRIB_AFTER_BYTES, ATTRIB_AFTER_STORAGE, ATTRIB_STORAGE, ELEM_EXTRA_STACK,
};
use crate::program::model::lang::param_list_standard::ParamListStandard;
use crate::program::seam_stubs::{ParameterPieces, PrototypePieces};
use crate::util::exception::InvalidInputException;
use crate::util::xml::spec_xml_utils::decode_int;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Find the first non-exclusion `ParamEntry` in `resource` whose space is a stack space.
///
/// Port of the private `initializeEntry` shared (identically, in Java) by `GotoStack` and
/// `ExtraStack`; see
/// [`goto_stack::find_stack_entry`](crate::program::model::lang::protorules::goto_stack) for the
/// sibling copy and why this is duplicated rather than shared.
///
/// # Errors
/// Returns an error if no matching `<pentry>` exists.
fn find_stack_entry(
    resource: &ParamListStandard,
) -> Result<Arc<ParamEntry>, InvalidInputException> {
    for entry in resource.entries() {
        if !entry.is_exclusion() && entry.get_space().space_type() == AddressSpaceType::Stack {
            return Ok(entry.clone());
        }
    }
    Err(InvalidInputException::with_message(
        "Cannot find matching <pentry> for action: extra_stack",
    ))
}

/// Consume stack resources as a side-effect.
///
/// This action is a side-effect and doesn't assign an address for the current parameter. If the
/// current parameter has been assigned an address that is not on the stack, this action consumes
/// stack resources as if the parameter were allocated to the stack. If the current parameter was
/// already assigned a stack address, no additional action is taken.
///
/// Port of `ghidra.program.model.lang.protorules.ExtraStack`.
pub struct ExtraStack {
    /// Parameter entry corresponding to the stack (`ExtraStack.stackEntry`).
    stack_entry: Arc<ParamEntry>,
    /// Activate the side effect after the given number of bytes have been consumed
    /// (`ExtraStack.afterBytes`).
    after_bytes: i32,
    /// Activate the side effect after the given amount of this storage class has been consumed
    /// (`ExtraStack.afterStorage`).
    after_storage: StorageClass,
}

impl ExtraStack {
    /// Port of the public constructor.
    ///
    /// # Errors
    /// Returns an error if `res` has no stack `ParamEntry`.
    pub fn new(
        storage: StorageClass,
        offset: i32,
        res: &ParamListStandard,
    ) -> Result<Self, InvalidInputException> {
        let stack_entry = find_stack_entry(res)?;
        Ok(ExtraStack {
            stack_entry,
            after_bytes: offset,
            after_storage: storage,
        })
    }
}

impl AssignAction for ExtraStack {
    fn clone_box(
        &self,
        new_resource: &ParamListStandard,
    ) -> Result<Box<dyn AssignAction>, InvalidInputException> {
        Ok(Box::new(ExtraStack::new(self.after_storage, self.after_bytes, new_resource)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn is_equivalent(&self, op: &dyn AssignAction) -> bool {
        let Some(other) = op.as_any().downcast_ref::<ExtraStack>() else {
            return false;
        };
        if self.after_bytes != other.after_bytes || self.after_storage != other.after_storage {
            return false;
        }
        self.stack_entry.is_equivalent(&other.stack_entry)
    }

    fn assign_address(
        &self,
        resource: &ParamListStandard,
        dt: &Arc<dyn DataType>,
        _proto: &PrototypePieces,
        _pos: i32,
        _dt_manager: &dyn DataTypeManager,
        status: &mut [i32],
        res: &mut ParameterPieces,
    ) -> i32 {
        // Precondition (mirrors the Java `res.address.getAddressSpace()` null-dereference risk):
        // ExtraStack is only ever meaningful as a side-effect that runs *after* a primary action
        // has already assigned `res.address` for the current parameter.
        let addr = res
            .address
            .as_ref()
            .expect("ExtraStack::assign_address requires res.address to already be assigned");
        if addr.space().as_ref() == self.stack_entry.get_space().as_ref() {
            return SUCCESS; // Parameter was already assigned to the stack
        }
        let grp = self.stack_entry.get_group() as usize;
        // Check whether we have consumed enough storage to need to adjust the stack yet
        if self.after_bytes > 0 {
            let mut bytes_consumed = 0;
            for i in 0..resource.get_num_param_entry() {
                if i as usize == grp {
                    continue;
                }
                let Some(entry) = resource.get_entry(i) else {
                    continue;
                };
                if entry.get_type() != self.after_storage {
                    continue;
                }
                if status[i as usize] != 0 {
                    bytes_consumed += entry.get_size();
                }
            }
            if bytes_consumed < self.after_bytes {
                return SUCCESS; // Don't yet need to consume extra stack space
            }
        }
        // We assign the stack address (but ignore the actual address) updating the status for
        // the stack, which consumes the stack resources.
        let mut unused = ParameterPieces::default();
        status[grp] =
            self.stack_entry
                .get_addr_by_slot(status[grp], dt.get_length(), dt.get_alignment(), &mut unused);
        SUCCESS
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        encoder.open_element(ELEM_EXTRA_STACK)?;
        if self.after_bytes >= 0 {
            encoder.write_unsigned_integer(ATTRIB_AFTER_BYTES, self.after_bytes as u64)?;
        }
        if self.after_storage != StorageClass::General {
            // Real Java quirk (`ExtraStack.encode`/`restoreAttributesXml` in
            // ExtraStack.java): encode writes the storage class under the `storage` attribute
            // (ATTRIB_STORAGE), but restoreAttributesXml only recognizes it back under the
            // *different* `afterstorage` attribute (ATTRIB_AFTER_STORAGE) -- see
            // `restore_attributes_xml` below. A round-trip through XML therefore silently drops
            // `after_storage` back to `StorageClass::General`. Faithfully reproduced rather than
            // silently fixed; see the `restore_xml_round_trip_loses_after_storage` test.
            encoder.write_string(ATTRIB_STORAGE, &self.after_storage.to_string())?;
        }
        encoder.close_element(ELEM_EXTRA_STACK)?;
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
        let elem = parser
            .start(&[ELEM_EXTRA_STACK.name])
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        for (name, value) in elem.get_attribute_iter() {
            if name == ATTRIB_AFTER_BYTES.name {
                self.after_bytes = decode_int(Some(&value));
            } else if name == ATTRIB_AFTER_STORAGE.name {
                self.after_storage = StorageClass::from_str(&value)?;
            }
        }
        parser
            .end()
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        self.stack_entry = find_stack_entry(resource).map_err(|e| XmlParseException::new(e.0))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::Address;
    use crate::program::model::lang::protorules::param_test_support::{
        ram_space, stack_space, TestEntry, TestResource,
    };
    use crate::program::model::lang::protorules::xml_test_support::{MockElement, QueueParser};
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

    /// Resource with one general register (group 0), one float register (group 1), and a stack
    /// entry (group 2).
    fn resource() -> ParamListStandard {
        TestResource {
            entries: vec![
                TestEntry { ty: StorageClass::General, group: 0, align: 0, size: 4, space: ram_space(), ..TestEntry::default() },
                TestEntry { ty: StorageClass::Float, group: 1, align: 0, size: 4, space: ram_space(), ..TestEntry::default() },
                TestEntry { space: stack_space(), group: 2, align: 4, numslots: 8, addressbase: 0, ..TestEntry::default() },
            ],
            num_group: 3,
            spacebase: None,
        }.build()
    }

    fn dt() -> Arc<dyn DataType> {
        Arc::new(MockDataType { length: 4, alignment: 4 })
    }

    #[test]
    #[should_panic(expected = "res.address to already be assigned")]
    fn assign_address_panics_if_res_address_not_yet_set() {
        // Mirrors the real Java NPE-on-null-dereference precondition: ExtraStack is only ever
        // invoked as a side-effect after a primary action has already assigned res.address.
        let action = ExtraStack::new(StorageClass::General, -1, &resource()).unwrap();
        let mut res = ParameterPieces::default();
        let mut status = [0i32; 3];
        action.assign_address(&resource(), &dt(), &PrototypePieces::default(), 0, &MockDataTypeManager, &mut status, &mut res);
    }

    #[test]
    fn assign_address_is_a_noop_when_already_on_the_stack() {
        let action = ExtraStack::new(StorageClass::General, -1, &resource()).unwrap();
        let mut res = ParameterPieces {
            address: Some(Address::new(stack_space(), 0)),
            ..ParameterPieces::default()
        };
        let mut status = [0i32; 3];
        let code = action.assign_address(&resource(), &dt(), &PrototypePieces::default(), 0, &MockDataTypeManager, &mut status, &mut res);
        assert_eq!(code, SUCCESS);
        assert_eq!(status, [0, 0, 0]); // no stack resources consumed
    }

    #[test]
    fn assign_address_consumes_stack_when_not_on_stack_and_no_threshold() {
        let action = ExtraStack::new(StorageClass::General, -1, &resource()).unwrap();
        let mut res = ParameterPieces {
            address: Some(Address::new(ram_space(), 0x10)), // assigned to a register, not the stack
            ..ParameterPieces::default()
        };
        let mut status = [0i32; 3];
        let code = action.assign_address(&resource(), &dt(), &PrototypePieces::default(), 0, &MockDataTypeManager, &mut status, &mut res);
        assert_eq!(code, SUCCESS);
        assert_eq!(status[2], 1); // stack group advanced by one slot
    }

    #[test]
    fn assign_address_waits_until_the_byte_threshold_is_reached() {
        // after_storage=General, after_bytes=4: only consume stack once >=4 bytes of General
        // storage have been used elsewhere.
        let action = ExtraStack::new(StorageClass::General, 4, &resource()).unwrap();
        let mut res = ParameterPieces {
            address: Some(Address::new(ram_space(), 0x10)),
            ..ParameterPieces::default()
        };
        let mut status = [0i32; 3]; // group 0 (General) not yet consumed
        let code = action.assign_address(&resource(), &dt(), &PrototypePieces::default(), 0, &MockDataTypeManager, &mut status, &mut res);
        assert_eq!(code, SUCCESS);
        assert_eq!(status[2], 0); // threshold not met -> no stack consumption yet

        let mut status2 = [1i32, 0, 0]; // group 0 (General, size 4) now consumed
        let mut res2 = ParameterPieces {
            address: Some(Address::new(ram_space(), 0x10)),
            ..ParameterPieces::default()
        };
        let code2 = action.assign_address(&resource(), &dt(), &PrototypePieces::default(), 0, &MockDataTypeManager, &mut status2, &mut res2);
        assert_eq!(code2, SUCCESS);
        assert_eq!(status2[2], 1); // threshold met (4 >= 4) -> stack now consumed
    }

    #[test]
    fn is_equivalent_compares_after_bytes_after_storage_and_stack_entry() {
        let a = ExtraStack::new(StorageClass::General, 4, &resource()).unwrap();
        let b = ExtraStack::new(StorageClass::General, 4, &resource()).unwrap();
        assert!(a.is_equivalent(&b));

        let diff_bytes = ExtraStack::new(StorageClass::General, 8, &resource()).unwrap();
        assert!(!a.is_equivalent(&diff_bytes));

        let diff_storage = ExtraStack::new(StorageClass::Float, 4, &resource()).unwrap();
        assert!(!a.is_equivalent(&diff_storage));
    }

    #[test]
    fn clone_box_recomputes_stack_entry_from_new_resource() {
        let action = ExtraStack::new(StorageClass::General, 4, &resource()).unwrap();
        let cloned = action.clone_box(&resource()).expect("clone should succeed");
        assert!(action.is_equivalent(cloned.as_ref()));
    }

    struct RecordingEncoder {
        elements: Vec<&'static str>,
        strings: Vec<(&'static str, String)>,
        unsigned: Vec<(&'static str, u64)>,
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
        fn write_unsigned_integer(&mut self, attrib_id: AttributeId, val: u64) -> std::io::Result<()> {
            self.unsigned.push((attrib_id.name, val));
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
    fn encode_writes_after_bytes_and_storage() {
        let action = ExtraStack::new(StorageClass::Float, 4, &resource()).unwrap();
        let mut enc = RecordingEncoder { elements: Vec::new(), strings: Vec::new(), unsigned: Vec::new() };
        action.encode(&mut enc).unwrap();
        assert_eq!(enc.elements, vec!["extra_stack"]);
        assert_eq!(enc.unsigned, vec![("afterbytes", 4)]);
        assert_eq!(enc.strings, vec![("storage", "float".to_string())]);
    }

    #[test]
    fn encode_omits_after_bytes_when_negative() {
        let action = ExtraStack::new(StorageClass::General, -1, &resource()).unwrap();
        let mut enc = RecordingEncoder { elements: Vec::new(), strings: Vec::new(), unsigned: Vec::new() };
        action.encode(&mut enc).unwrap();
        assert!(enc.unsigned.is_empty());
        assert!(enc.strings.is_empty());
    }

    #[test]
    fn restore_xml_reads_after_bytes_and_after_storage_attribute_names() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("extra_stack", 0, &[("afterbytes", "8"), ("afterstorage", "float")]),
            MockElement::end("extra_stack", 0),
        ]);
        let mut action = ExtraStack::new(StorageClass::General, -1, &resource()).unwrap();
        action.restore_xml(&mut parser, &resource()).unwrap();
        assert_eq!(action.after_bytes, 8);
        assert_eq!(action.after_storage, StorageClass::Float);
    }

    #[test]
    fn restore_xml_round_trip_loses_after_storage() {
        // Faithfully reproduces the real Java bug documented on `encode` above: encode() writes
        // the storage class under the "storage" attribute name, but restoreAttributesXml() only
        // recognizes "afterstorage". So an encode -> restore_xml round trip silently drops
        // after_storage back to General, even though after_bytes round-trips fine.
        let original = ExtraStack::new(StorageClass::Float, 4, &resource()).unwrap();
        let mut enc = RecordingEncoder { elements: Vec::new(), strings: Vec::new(), unsigned: Vec::new() };
        original.encode(&mut enc).unwrap();
        // What encode wrote uses "storage", NOT "afterstorage":
        assert_eq!(enc.strings, vec![("storage", "float".to_string())]);

        // Simulate parsing that same "storage"-named attribute back in: restore_xml doesn't
        // recognize it, so after_storage reverts to General.
        let mut parser = QueueParser::new(vec![
            MockElement::start("extra_stack", 0, &[("afterbytes", "4"), ("storage", "float")]),
            MockElement::end("extra_stack", 0),
        ]);
        let mut restored = ExtraStack::new(StorageClass::General, -1, &resource()).unwrap();
        restored.restore_xml(&mut parser, &resource()).unwrap();
        assert_eq!(restored.after_bytes, 4); // this one round-trips fine
        assert_eq!(restored.after_storage, StorageClass::General); // but this one is lost
        assert_ne!(restored.after_storage, original.after_storage);
    }

    #[test]
    fn usable_as_trait_object() {
        let action: Box<dyn AssignAction> = Box::new(ExtraStack::new(StorageClass::General, -1, &resource()).unwrap());
        let mut res = ParameterPieces {
            address: Some(Address::new(ram_space(), 0x10)),
            ..ParameterPieces::default()
        };
        let mut status = [0i32; 3];
        let code = action.assign_address(&resource(), &dt(), &PrototypePieces::default(), 0, &MockDataTypeManager, &mut status, &mut res);
        assert_eq!(code, SUCCESS);
    }
}
