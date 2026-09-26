use std::any::Any;
use std::sync::Arc;

use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::param_entry::ParamEntry;
use crate::program::model::lang::protorules::assign_action::{AssignAction, SUCCESS};
use crate::program::model::lang::storage_class::StorageClass;
use crate::program::model::pcode::{Encoder, ATTRIB_STORAGE, ELEM_CONSUME_REMAINING};
use crate::program::model::lang::param_list_standard::ParamListStandard;
use crate::program::seam_stubs::{ParameterPieces, PrototypePieces};
use crate::util::exception::InvalidInputException;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Consume all the remaining registers from a given resource list.
///
/// This action is a side-effect and doesn't assign an address for the current parameter. The
/// resource list, `resource_type`, is specified. If the side-effect is triggered, all register
/// resources from this list are consumed, until no registers remain. If all registers are
/// already consumed, no action is taken.
///
/// Port of `ghidra.program.model.lang.protorules.ConsumeRemaining`.
pub struct ConsumeRemaining {
    /// The resource list to consume from (`ConsumeRemaining.resourceType`).
    resource_type: StorageClass,
    /// Registers that can be consumed (`ConsumeRemaining.tiles`).
    tiles: Vec<Arc<ParamEntry>>,
}

/// Cache the specific `ParamEntry`s needed by the action: every single-register, exclusion entry
/// matching `resource_type`.
///
/// Port of the private `initializeEntries`.
///
/// # Errors
/// Returns an error if `resource` has no matching entries.
fn initialize_entries(
    resource: &ParamListStandard,
    resource_type: StorageClass,
) -> Result<Vec<Arc<ParamEntry>>, InvalidInputException> {
    let tiles = resource.extract_tiles(resource_type);
    if tiles.is_empty() {
        return Err(InvalidInputException::with_message(
            "Could not find matching resources for action: consume_remaining",
        ));
    }
    Ok(tiles)
}

impl ConsumeRemaining {
    /// Port of the public constructor.
    ///
    /// # Errors
    /// Returns an error if `res` has no `ParamEntry` matching `store`.
    pub fn new(
        store: StorageClass,
        res: &ParamListStandard,
    ) -> Result<Self, InvalidInputException> {
        let tiles = initialize_entries(res, store)?;
        Ok(ConsumeRemaining { resource_type: store, tiles })
    }

    /// Port of the "protected" constructor; see
    /// [`ConsumeExtra::for_decode`](super::consume_extra::ConsumeExtra::for_decode)'s doc for the
    /// full rationale. `resource_type` here is just a placeholder default -- `restore_xml`
    /// unconditionally overwrites it from the stream's `storage` attribute and re-derives `tiles`
    /// via `initialize_entries` at the end, exactly as Java's `restoreXml` does.
    pub fn for_decode() -> Self {
        ConsumeRemaining { resource_type: StorageClass::General, tiles: Vec::new() }
    }
}

impl AssignAction for ConsumeRemaining {
    fn clone_box(
        &self,
        new_resource: &ParamListStandard,
    ) -> Result<Box<dyn AssignAction>, InvalidInputException> {
        Ok(Box::new(ConsumeRemaining::new(self.resource_type, new_resource)?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn is_equivalent(&self, op: &dyn AssignAction) -> bool {
        let Some(other) = op.as_any().downcast_ref::<ConsumeRemaining>() else {
            return false;
        };
        if self.resource_type != other.resource_type {
            return false;
        }
        if self.tiles.len() != other.tiles.len() {
            return false;
        }
        self.tiles
            .iter()
            .zip(other.tiles.iter())
            .all(|(a, b)| a.is_equivalent(b))
    }

    fn assign_address(
        &self,
        _resource: &ParamListStandard,
        _dt: &Arc<dyn DataType>,
        _proto: &PrototypePieces,
        _pos: i32,
        _dt_manager: &dyn DataTypeManager,
        status: &mut [i32],
        _res: &mut ParameterPieces,
    ) -> i32 {
        for entry in &self.tiles {
            let grp = entry.get_group() as usize;
            if status[grp] != 0 {
                continue; // Already consumed
            }
            status[grp] = -1;
        }
        SUCCESS
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        encoder.open_element(ELEM_CONSUME_REMAINING)?;
        encoder.write_string(ATTRIB_STORAGE, &self.resource_type.to_string())?;
        encoder.close_element(ELEM_CONSUME_REMAINING)?;
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
            .start(&[ELEM_CONSUME_REMAINING.name])
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        let storage_string = elem.get_attribute(ATTRIB_STORAGE.name).unwrap_or_default();
        self.resource_type = StorageClass::from_str(&storage_string)?;
        parser
            .end()
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        self.tiles = initialize_entries(resource, self.resource_type)
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

    struct MockDataType;
    impl DataType for MockDataType {}

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    fn two_general_registers() -> ParamListStandard {
        TestResource {
            entries: vec![
                TestEntry { ty: StorageClass::General, group: 0, align: 0, space: ram_space(), ..TestEntry::default() },
                TestEntry { ty: StorageClass::General, group: 1, align: 0, space: ram_space(), ..TestEntry::default() },
            ],
            num_group: 2,
            spacebase: None,
        }.build()
    }

    #[test]
    fn new_fails_when_no_matching_entries_exist() {
        let empty = TestResource::default().build();
        assert!(ConsumeRemaining::new(StorageClass::General, &empty).is_err());
    }

    #[test]
    fn assign_address_marks_all_unconsumed_tiles_as_consumed() {
        let action = ConsumeRemaining::new(StorageClass::General, &two_general_registers()).unwrap();
        let dt: Arc<dyn DataType> = Arc::new(MockDataType);
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut res = ParameterPieces::default();
        let mut status = [0i32, 3]; // group 1 already partially consumed (status != 0)

        let code = action.assign_address(&two_general_registers(), &dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, SUCCESS);
        assert_eq!(status[0], -1); // was 0 (unconsumed) -> now fully consumed
        assert_eq!(status[1], 3); // already nonzero -> left untouched
    }

    #[test]
    fn is_equivalent_compares_resource_type_and_tiles() {
        let a = ConsumeRemaining::new(StorageClass::General, &two_general_registers()).unwrap();
        let b = ConsumeRemaining::new(StorageClass::General, &two_general_registers()).unwrap();
        assert!(a.is_equivalent(&b));

        let c = ConsumeRemaining::new(StorageClass::Float, &{
            TestResource {
                entries: vec![TestEntry { ty: StorageClass::Float, align: 0, ..TestEntry::default() }],
                num_group: 1,
                spacebase: None,
            }.build()
        }).unwrap();
        assert!(!a.is_equivalent(&c));
    }

    #[test]
    fn clone_box_recomputes_tiles_from_new_resource() {
        let action = ConsumeRemaining::new(StorageClass::General, &two_general_registers()).unwrap();
        let cloned = action.clone_box(&two_general_registers()).expect("clone should succeed");
        assert!(action.is_equivalent(cloned.as_ref()));
    }

    struct RecordingEncoder {
        elements: Vec<&'static str>,
        strings: Vec<(&'static str, String)>,
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
    fn encode_writes_storage_attribute() {
        let action = ConsumeRemaining::new(StorageClass::Vector, &{
            TestResource {
                entries: vec![TestEntry { ty: StorageClass::Vector, align: 0, ..TestEntry::default() }],
                num_group: 1,
                spacebase: None,
            }.build()
        }).unwrap();
        let mut enc = RecordingEncoder { elements: Vec::new(), strings: Vec::new() };
        action.encode(&mut enc).unwrap();
        assert_eq!(enc.elements, vec!["consume_remaining"]);
        assert_eq!(enc.strings, vec![("storage", "vector".to_string())]);
    }

    #[test]
    fn restore_xml_reinitializes_tiles() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("consume_remaining", 0, &[("storage", "general")]),
            MockElement::end("consume_remaining", 0),
        ]);
        let mut action = ConsumeRemaining::new(StorageClass::General, &two_general_registers()).unwrap();
        action.restore_xml(&mut parser, &two_general_registers()).unwrap();
        assert_eq!(action.tiles.len(), 2);
    }

    #[test]
    fn restore_xml_fails_when_no_matching_entries_after_reparse() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("consume_remaining", 0, &[("storage", "float")]),
            MockElement::end("consume_remaining", 0),
        ]);
        let mut action = ConsumeRemaining::new(StorageClass::General, &two_general_registers()).unwrap();
        assert!(action.restore_xml(&mut parser, &two_general_registers()).is_err());
    }

    #[test]
    fn for_decode_then_restore_xml_picks_up_a_non_default_storage_class() {
        let float_only_resource = TestResource {
            entries: vec![TestEntry {
                ty: StorageClass::Float,
                align: 0,
                space: ram_space(),
                ..TestEntry::default()
            }],
            num_group: 1,
            spacebase: None,
        }.build();
        let mut parser = QueueParser::new(vec![
            MockElement::start("consume_remaining", 0, &[("storage", "float")]),
            MockElement::end("consume_remaining", 0),
        ]);
        let mut action = ConsumeRemaining::for_decode();
        action.restore_xml(&mut parser, &float_only_resource).unwrap();
        assert_eq!(action.resource_type, StorageClass::Float);
        assert_eq!(action.tiles.len(), 1);
    }
}
