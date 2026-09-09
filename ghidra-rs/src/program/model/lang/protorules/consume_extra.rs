use std::any::Any;
use std::sync::Arc;

use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::param_entry::ParamEntry;
use crate::program::model::lang::protorules::assign_action::{AssignAction, SUCCESS};
use crate::program::model::lang::storage_class::StorageClass;
use crate::program::model::pcode::{Encoder, ATTRIB_MATCHSIZE, ATTRIB_STORAGE, ELEM_CONSUME_EXTRA};
use crate::program::seam_stubs::{ParamListStandardLike, ParameterPieces, PrototypePieces};
use crate::util::exception::InvalidInputException;
use crate::util::xml::spec_xml_utils::decode_boolean;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Consume additional registers from an alternate resource list.
///
/// This action is a side-effect and doesn't assign an address for the current parameter. The
/// resource list, `resource_type`, is specified. If the side-effect is triggered, register
/// resources from this list are consumed. If `match_size` is true (the default), registers are
/// consumed until the number of bytes in the data-type is reached. Otherwise, only a single
/// register is consumed. If all registers are already consumed, no action is taken.
///
/// Port of `ghidra.program.model.lang.protorules.ConsumeExtra`.
pub struct ConsumeExtra {
    /// The resource list this action allocates from (`AssignAction.resource`).
    resource: Arc<dyn ParamListStandardLike>,
    /// The other resource list to consume from (`ConsumeExtra.resourceType`).
    resource_type: StorageClass,
    /// False if the side-effect only consumes a single register (`ConsumeExtra.matchSize`).
    match_size: bool,
    /// Registers that can be consumed (`ConsumeExtra.tiles`).
    tiles: Vec<Arc<dyn ParamEntry>>,
}

/// Port of the private `initializeEntries` (identical logic to
/// [`consume_remaining`](super::consume_remaining)'s free function of the same shape; duplicated
/// per-class since Java itself defines this method separately on each class).
///
/// # Errors
/// Returns an error if `resource` has no matching entries.
fn initialize_entries(
    resource: &Arc<dyn ParamListStandardLike>,
    resource_type: StorageClass,
) -> Result<Vec<Arc<dyn ParamEntry>>, InvalidInputException> {
    let tiles = resource.extract_tiles(resource_type);
    if tiles.is_empty() {
        return Err(InvalidInputException::with_message(
            "Could not find matching resources for action: consume_extra",
        ));
    }
    Ok(tiles)
}

impl ConsumeExtra {
    /// Port of the public constructor.
    ///
    /// # Errors
    /// Returns an error if `res` has no `ParamEntry` matching `store`.
    pub fn new(
        store: StorageClass,
        matched: bool,
        res: Arc<dyn ParamListStandardLike>,
    ) -> Result<Self, InvalidInputException> {
        let tiles = initialize_entries(&res, store)?;
        Ok(ConsumeExtra { resource: res, resource_type: store, match_size: matched, tiles })
    }
}

impl AssignAction for ConsumeExtra {
    fn clone_box(
        &self,
        new_resource: Arc<dyn ParamListStandardLike>,
    ) -> Result<Box<dyn AssignAction>, InvalidInputException> {
        Ok(Box::new(ConsumeExtra::new(self.resource_type, self.match_size, new_resource)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn is_equivalent(&self, op: &dyn AssignAction) -> bool {
        let Some(other) = op.as_any().downcast_ref::<ConsumeExtra>() else {
            return false;
        };
        if self.match_size != other.match_size || self.resource_type != other.resource_type {
            return false;
        }
        if self.tiles.len() != other.tiles.len() {
            return false;
        }
        self.tiles
            .iter()
            .zip(other.tiles.iter())
            .all(|(a, b)| a.is_equivalent(b.as_ref()))
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
        let _ = (res, &self.resource);
        let mut size_left = dt.get_length();
        let mut iter = 0usize;
        while size_left > 0 && iter != self.tiles.len() {
            let entry = &self.tiles[iter];
            iter += 1;
            let grp = entry.get_group() as usize;
            if status[grp] != 0 {
                continue; // Already consumed
            }
            status[grp] = -1; // Consume the slot/register
            size_left -= entry.get_size();
            if !self.match_size {
                break; // Only consume a single register
            }
        }
        SUCCESS
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        encoder.open_element(ELEM_CONSUME_EXTRA)?;
        encoder.write_string(ATTRIB_STORAGE, &self.resource_type.to_string())?;
        encoder.write_bool(ATTRIB_MATCHSIZE, self.match_size)?;
        encoder.close_element(ELEM_CONSUME_EXTRA)?;
        Ok(())
    }

    fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), XmlParseException>
    where
        Self: Sized,
    {
        let elem = parser
            .start(&[ELEM_CONSUME_EXTRA.name])
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        for (name, value) in elem.get_attribute_iter() {
            if name == ATTRIB_STORAGE.name {
                self.resource_type = StorageClass::from_str(&value)?;
            } else if name == ATTRIB_MATCHSIZE.name {
                self.match_size = decode_boolean(&value);
            }
        }
        parser
            .end()
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        self.tiles = initialize_entries(&self.resource, self.resource_type)
            .map_err(|e| XmlParseException::new(e.0))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn two_general_registers() -> Arc<dyn ParamListStandardLike> {
        Arc::new(TestResource {
            entries: vec![
                Arc::new(TestEntry { ty: StorageClass::General, group: 0, align: 0, size: 4, space: ram_space(), ..TestEntry::default() }),
                Arc::new(TestEntry { ty: StorageClass::General, group: 1, align: 0, size: 4, space: ram_space(), ..TestEntry::default() }),
            ],
            num_group: 2,
            spacebase: None,
        })
    }

    #[test]
    fn assign_address_consumes_until_size_is_covered_when_match_size() {
        let action = ConsumeExtra::new(StorageClass::General, true, two_general_registers()).unwrap();
        let dt: Arc<dyn DataType> = Arc::new(MockDataType { length: 8 }); // needs both 4-byte regs
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut res = ParameterPieces::default();
        let mut status = [0i32; 2];

        let code = action.assign_address(&dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, SUCCESS);
        assert_eq!(status, [-1, -1]);
    }

    #[test]
    fn assign_address_stops_once_size_is_covered() {
        let action = ConsumeExtra::new(StorageClass::General, true, two_general_registers()).unwrap();
        let dt: Arc<dyn DataType> = Arc::new(MockDataType { length: 4 }); // one 4-byte reg covers it
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut res = ParameterPieces::default();
        let mut status = [0i32; 2];

        let code = action.assign_address(&dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, SUCCESS);
        assert_eq!(status, [-1, 0]); // second register left untouched
    }

    #[test]
    fn assign_address_consumes_only_one_register_when_not_match_size() {
        let action = ConsumeExtra::new(StorageClass::General, false, two_general_registers()).unwrap();
        let dt: Arc<dyn DataType> = Arc::new(MockDataType { length: 100 }); // would need many regs if matchSize
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut res = ParameterPieces::default();
        let mut status = [0i32; 2];

        let code = action.assign_address(&dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, SUCCESS);
        assert_eq!(status, [-1, 0]); // only the first register consumed
    }

    #[test]
    fn assign_address_skips_already_consumed_registers() {
        let action = ConsumeExtra::new(StorageClass::General, true, two_general_registers()).unwrap();
        let dt: Arc<dyn DataType> = Arc::new(MockDataType { length: 4 });
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut res = ParameterPieces::default();
        let mut status = [5i32, 0]; // first register already consumed

        let code = action.assign_address(&dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, SUCCESS);
        assert_eq!(status, [5, -1]); // falls through to the second register
    }

    #[test]
    fn is_equivalent_compares_match_size_resource_type_and_tiles() {
        let a = ConsumeExtra::new(StorageClass::General, true, two_general_registers()).unwrap();
        let b = ConsumeExtra::new(StorageClass::General, true, two_general_registers()).unwrap();
        assert!(a.is_equivalent(&b));

        let diff_match = ConsumeExtra::new(StorageClass::General, false, two_general_registers()).unwrap();
        assert!(!a.is_equivalent(&diff_match));
    }

    #[test]
    fn clone_box_recomputes_tiles_from_new_resource() {
        let action = ConsumeExtra::new(StorageClass::General, true, two_general_registers()).unwrap();
        let cloned = action.clone_box(two_general_registers()).expect("clone should succeed");
        assert!(action.is_equivalent(cloned.as_ref()));
    }

    struct RecordingEncoder {
        elements: Vec<&'static str>,
        strings: Vec<(&'static str, String)>,
        bools: Vec<(&'static str, bool)>,
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
    fn encode_writes_storage_and_matchsize() {
        let action = ConsumeExtra::new(StorageClass::Float, false, {
            Arc::new(TestResource {
                entries: vec![Arc::new(TestEntry { ty: StorageClass::Float, align: 0, ..TestEntry::default() })],
                num_group: 1,
                spacebase: None,
            })
        }).unwrap();
        let mut enc = RecordingEncoder { elements: Vec::new(), strings: Vec::new(), bools: Vec::new() };
        action.encode(&mut enc).unwrap();
        assert_eq!(enc.elements, vec!["consume_extra"]);
        assert_eq!(enc.strings, vec![("storage", "float".to_string())]);
        assert_eq!(enc.bools, vec![("matchsize", false)]);
    }

    #[test]
    fn restore_xml_reads_storage_and_matchsize() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("consume_extra", 0, &[("storage", "general"), ("matchsize", "false")]),
            MockElement::end("consume_extra", 0),
        ]);
        let mut action = ConsumeExtra::new(StorageClass::General, true, two_general_registers()).unwrap();
        action.restore_xml(&mut parser).unwrap();
        assert!(!action.match_size);
        assert_eq!(action.resource_type, StorageClass::General);
    }
}
