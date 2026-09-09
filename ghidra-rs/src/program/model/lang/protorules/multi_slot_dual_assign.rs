use std::any::Any;
use std::sync::Arc;

use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::param_entry::ParamEntry;
use crate::program::model::lang::param_list_standard::get_basic_type_class;
use crate::program::model::lang::protorules::assign_action::{
    justify_pieces, AssignAction, FAIL, SUCCESS,
};
use crate::program::model::lang::protorules::primitive_extractor::PrimitiveExtractor;
use crate::program::model::lang::storage_class::StorageClass;
use crate::program::model::pcode::{
    Encoder, Varnode, ATTRIB_A, ATTRIB_B, ATTRIB_FILL_ALTERNATE, ATTRIB_REVERSEJUSTIFY,
    ATTRIB_REVERSESIGNIF, ATTRIB_STACKSPILL, ATTRIB_STORAGE, ELEM_JOIN, ELEM_JOIN_DUAL_CLASS,
};
use crate::program::seam_stubs::{ParamListStandardLike, ParameterPieces, PrototypePieces};
use crate::util::exception::InvalidInputException;
use crate::util::xml::spec_xml_utils::decode_boolean;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Consume multiple registers from different storage classes to pass a data-type.
///
/// This action is for calling conventions that can use both floating-point and general purpose
/// registers when assigning storage for a single composite data-type, such as the x86-64 System V
/// ABI.
///
/// Port of `ghidra.program.model.lang.protorules.MultiSlotDualAssign`.
pub struct MultiSlotDualAssign {
    /// The resource list this action allocates from (`AssignAction.resource`).
    resource: Arc<dyn ParamListStandardLike>,
    /// Resource list from which to consume general tiles (`MultiSlotDualAssign.baseType`).
    base_type: StorageClass,
    /// Resource list from which to consume alternate tiles (`MultiSlotDualAssign.altType`).
    alt_type: StorageClass,
    /// True for big endian architectures (`MultiSlotDualAssign.isBigEndian`).
    is_big_endian: bool,
    /// True if resources can be consumed from the stack (`MultiSlotDualAssign.consumeFromStack`).
    consume_from_stack: bool,
    /// True if resources are consumed starting with most significant bytes
    /// (`MultiSlotDualAssign.consumeMostSig`).
    consume_most_sig: bool,
    /// True if initial bytes are padding for odd data-type sizes
    /// (`MultiSlotDualAssign.justifyRight`).
    justify_right: bool,
    /// True if a single primitive needs to fill an alternate tile
    /// (`MultiSlotDualAssign.fillAlternate`).
    fill_alternate: bool,
    /// Number of bytes in a tile (`MultiSlotDualAssign.tileSize`).
    tile_size: i32,
    /// General registers for joining (`MultiSlotDualAssign.baseTiles`).
    base_tiles: Vec<Arc<dyn ParamEntry>>,
    /// Alternate registers for joining (`MultiSlotDualAssign.altTiles`).
    alt_tiles: Vec<Arc<dyn ParamEntry>>,
    /// The stack resource (`MultiSlotDualAssign.stackEntry`).
    stack_entry: Option<Arc<dyn ParamEntry>>,
}

impl MultiSlotDualAssign {
    /// Find the tiles matching `base_type`/`alt_type`, and the stack entry if needed.
    ///
    /// Port of the private `initializeEntries`.
    ///
    /// # Errors
    /// Returns an error if the required elements are not available in the resource list, or if
    /// the base and alternate tile sizes don't match.
    fn initialize_entries(&mut self) -> Result<(), InvalidInputException> {
        self.base_tiles = self.resource.extract_tiles(self.base_type);
        self.alt_tiles = self.resource.extract_tiles(self.alt_type);
        self.stack_entry = self.resource.extract_stack();
        if self.base_tiles.is_empty() || self.alt_tiles.is_empty() {
            return Err(InvalidInputException::with_message(
                "Could not find matching resources for action: join_dual_class",
            ));
        }
        self.tile_size = self.base_tiles[0].get_size();
        if self.tile_size != self.alt_tiles[0].get_size() {
            return Err(InvalidInputException::with_message(
                "Storage class register sizes do not match for action: join_dual_class",
            ));
        }
        if self.consume_from_stack && self.stack_entry.is_none() {
            return Err(InvalidInputException::with_message(
                "Cannot find matching stack resource for action: join_dual_class",
            ));
        }
        Ok(())
    }

    /// Get the index of the first unused [`ParamEntry`] within a given tileset, starting the
    /// search at `iter`.
    ///
    /// Port of the private `getFirstUnused`. Returns `tiles.len()` if none is found (matching
    /// Java's `tiles.length` sentinel).
    fn get_first_unused(mut iter: usize, tiles: &[Arc<dyn ParamEntry>], status: &[i32]) -> usize {
        while iter != tiles.len() {
            let entry = &tiles[iter];
            if status[entry.get_group() as usize] != 0 {
                iter += 1;
                continue; // Already consumed
            }
            return iter;
        }
        tiles.len()
    }

    /// Get the storage class to use for the specific section of the data-type starting at `off`
    /// and extending through `tile_size` bytes.
    ///
    /// If any primitive overlaps the boundary of the section, returns `-1`. Otherwise, if all
    /// the primitive data-types in the section match the alternate storage class, returns `1`,
    /// or if one or more does not match, returns `0`. `*index`, the index of the first primitive
    /// after the start of the section, is updated in place to the first primitive after the end
    /// of the section.
    ///
    /// Port of the private `getTileClass`.
    fn get_tile_class(&self, primitives: &PrimitiveExtractor, off: i32, index: &mut usize) -> i32 {
        let mut res = 1;
        let mut count = 0;
        let end_boundary = off + self.tile_size;
        if *index >= primitives.size() {
            return -1;
        }
        let first_primitive_len = primitives.get(*index).dt.get_length();
        while *index < primitives.size() {
            let element = primitives.get(*index);
            if element.offset < off {
                return -1;
            }
            if element.offset >= end_boundary {
                break;
            }
            if element.offset + element.dt.get_length() > end_boundary {
                return -1;
            }
            count += 1;
            *index += 1;
            let storage = get_basic_type_class(element.dt.as_ref());
            if storage != self.alt_type {
                res = 0;
            }
        }
        if count == 0 {
            return -1; // Must be at least one primitive in section
        }
        if self.fill_alternate {
            // Only use altType if the tile contains one primitive of exactly the tile size.
            if count > 1 {
                res = 0;
            }
            if first_primitive_len != self.tile_size {
                res = 0;
            }
        }
        res
    }

    /// Port of the "protected" constructor, used to build a default-configured instance before
    /// [`restore_xml`](AssignAction::restore_xml) overrides its attributes (mirroring
    /// `AssignAction.restoreActionXml`'s `new MultiSlotDualAssign(res)`, not itself ported into
    /// this crate yet -- see [`AssignAction`](super::assign_action::AssignAction)'s module doc).
    pub fn for_decode(res: Arc<dyn ParamListStandardLike>) -> Self {
        let is_big_endian = res.is_big_endian();
        MultiSlotDualAssign {
            resource: res,
            base_type: StorageClass::General,
            alt_type: StorageClass::Float,
            is_big_endian,
            consume_from_stack: false,
            consume_most_sig: is_big_endian,
            justify_right: is_big_endian,
            fill_alternate: false,
            tile_size: 0,
            base_tiles: Vec::new(),
            alt_tiles: Vec::new(),
            stack_entry: None,
        }
    }

    /// Port of the public constructor.
    ///
    /// # Errors
    /// Returns an error if the required elements are not available in `res`.
    pub fn new(
        base_store: StorageClass,
        alt_store: StorageClass,
        stack: bool,
        most_sig: bool,
        just_right: bool,
        fill_alt: bool,
        res: Arc<dyn ParamListStandardLike>,
    ) -> Result<Self, InvalidInputException> {
        let is_big_endian = res.is_big_endian();
        let mut action = MultiSlotDualAssign {
            resource: res,
            base_type: base_store,
            alt_type: alt_store,
            is_big_endian,
            consume_from_stack: stack,
            consume_most_sig: most_sig,
            justify_right: just_right,
            fill_alternate: fill_alt,
            tile_size: 0,
            base_tiles: Vec::new(),
            alt_tiles: Vec::new(),
            stack_entry: None,
        };
        action.initialize_entries()?;
        Ok(action)
    }
}

impl AssignAction for MultiSlotDualAssign {
    fn clone_box(
        &self,
        new_resource: Arc<dyn ParamListStandardLike>,
    ) -> Result<Box<dyn AssignAction>, InvalidInputException> {
        Ok(Box::new(MultiSlotDualAssign::new(
            self.base_type,
            self.alt_type,
            self.consume_from_stack,
            self.consume_most_sig,
            self.justify_right,
            self.fill_alternate,
            new_resource,
        )?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn is_equivalent(&self, op: &dyn AssignAction) -> bool {
        let Some(other) = op.as_any().downcast_ref::<MultiSlotDualAssign>() else {
            return false;
        };
        if self.consume_from_stack != other.consume_from_stack
            || self.consume_most_sig != other.consume_most_sig
            || self.justify_right != other.justify_right
            || self.fill_alternate != other.fill_alternate
        {
            return false;
        }
        if self.base_type != other.base_type || self.alt_type != other.alt_type {
            return false;
        }
        if self.base_tiles.len() != other.base_tiles.len() {
            return false;
        }
        for (a, b) in self.base_tiles.iter().zip(other.base_tiles.iter()) {
            if !a.is_equivalent(b.as_ref()) {
                return false;
            }
        }
        if self.alt_tiles.len() != other.alt_tiles.len() {
            return false;
        }
        for (a, b) in self.alt_tiles.iter().zip(other.alt_tiles.iter()) {
            if !a.is_equivalent(b.as_ref()) {
                return false;
            }
        }
        // Note: Java's isEquivalent does NOT compare stackEntry (unlike MultiSlotAssign's own
        // isEquivalent, which does); faithfully not compared here either.
        true
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
        let primitives = PrimitiveExtractor::new(dt.as_ref(), false, 0, 1024);
        if !primitives.is_valid() || primitives.size() == 0 || primitives.contains_holes() {
            return FAIL;
        }
        let mut primitive_index = 0usize;
        let mut tmp_status = status.to_vec();
        let mut pieces: Vec<Varnode> = Vec::new();
        let type_size = dt.get_length();
        let align = dt.get_alignment();
        let mut size_left = type_size;
        let mut iter_base = 0usize;
        let mut iter_alt = 0usize;
        while size_left > 0 {
            let iter_type = self.get_tile_class(&primitives, type_size - size_left, &mut primitive_index);
            if iter_type < 0 {
                return FAIL;
            }
            let entry: Arc<dyn ParamEntry>;
            if iter_type == 0 {
                iter_base = Self::get_first_unused(iter_base, &self.base_tiles, &tmp_status);
                if iter_base == self.base_tiles.len() {
                    if !self.consume_from_stack {
                        return FAIL; // Out of general registers
                    }
                    break;
                }
                entry = self.base_tiles[iter_base].clone();
            } else {
                iter_alt = Self::get_first_unused(iter_alt, &self.alt_tiles, &tmp_status);
                if iter_alt == self.alt_tiles.len() {
                    if !self.consume_from_stack {
                        return FAIL; // Out of alternate registers
                    }
                    break;
                }
                entry = self.alt_tiles[iter_alt].clone();
            }
            let trial_size = entry.get_size();
            let grp = entry.get_group() as usize;
            let mut param = ParameterPieces::default();
            entry.get_addr_by_slot(tmp_status[grp], trial_size, 1, &mut param);
            tmp_status[grp] = -1; // Consume the register
            let Some(addr) = param.address else {
                // Defensive: a freshly-consumed, single-slot exclusion tile requesting exactly
                // its own size should never fail to produce an address; guards against an
                // unsound unwrap if a future ParamEntry impl disagrees.
                return FAIL;
            };
            pieces.push(Varnode::new(addr, trial_size));
            size_left -= trial_size;
        }
        if size_left > 0 {
            // Have to use the stack to get enough bytes.
            if !self.consume_from_stack {
                return FAIL;
            }
            let Some(stack_entry) = &self.stack_entry else {
                return FAIL;
            };
            let grp = stack_entry.get_group() as usize;
            let mut param = ParameterPieces::default();
            tmp_status[grp] = stack_entry.get_addr_by_slot_justified(
                tmp_status[grp],
                size_left,
                align,
                &mut param,
                self.justify_right,
            );
            let Some(addr) = param.address else {
                return FAIL;
            };
            pieces.push(Varnode::new(addr, size_left));
        }
        if size_left < 0 {
            // Have odd data-type size.
            justify_pieces(&mut pieces, -size_left, self.is_big_endian, self.consume_most_sig, self.justify_right);
        }
        // Commit resource usage for all the pieces.
        status.copy_from_slice(&tmp_status);
        res.data_type = Some(dt.clone());
        let Some(language) = self.resource.get_language() else {
            return FAIL;
        };
        res.assign_address_from_pieces(pieces, self.consume_most_sig, false, language.as_ref());
        SUCCESS
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        encoder.open_element(ELEM_JOIN_DUAL_CLASS)?;
        if self.resource.is_big_endian() != self.justify_right {
            encoder.write_bool(ATTRIB_REVERSEJUSTIFY, true)?;
        }
        if self.resource.is_big_endian() != self.consume_most_sig {
            encoder.write_bool(ATTRIB_REVERSESIGNIF, true)?;
        }
        if self.base_type != StorageClass::General {
            encoder.write_string(ATTRIB_STORAGE, &self.base_type.to_string())?;
        }
        if self.alt_type != StorageClass::Float {
            encoder.write_string(ATTRIB_B, &self.alt_type.to_string())?;
        }
        encoder.write_bool(ATTRIB_STACKSPILL, self.consume_from_stack)?;
        encoder.write_bool(ATTRIB_FILL_ALTERNATE, self.fill_alternate)?;
        // Real Java quirk (`MultiSlotDualAssign.encode`): opens `ELEM_JOIN_DUAL_CLASS` but closes
        // with the *different* `ELEM_JOIN` element id. Most `Encoder` implementations (including
        // this crate's, and Ghidra's own stream writers) don't actually validate that
        // openElement/closeElement tag names match, so this mismatch is silently harmless in
        // practice -- but it's a real bug in the Java source, faithfully reproduced rather than
        // silently fixed. See `encode_closes_with_the_wrong_element_id_bug` below.
        encoder.close_element(ELEM_JOIN)?;
        Ok(())
    }

    fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), XmlParseException>
    where
        Self: Sized,
    {
        let elem = parser
            .start(&[ELEM_JOIN_DUAL_CLASS.name])
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        for (name, value) in elem.get_attribute_iter() {
            if name == ATTRIB_REVERSEJUSTIFY.name {
                if decode_boolean(&value) {
                    self.justify_right = !self.justify_right;
                }
            } else if name == ATTRIB_REVERSESIGNIF.name {
                if decode_boolean(&value) {
                    self.consume_most_sig = !self.consume_most_sig;
                }
            } else if name == ATTRIB_STORAGE.name || name == ATTRIB_A.name {
                self.base_type = StorageClass::from_str(&value)?;
            } else if name == ATTRIB_B.name {
                self.alt_type = StorageClass::from_str(&value)?;
            } else if name == ATTRIB_STACKSPILL.name {
                self.consume_from_stack = decode_boolean(&value);
            } else if name == ATTRIB_FILL_ALTERNATE.name {
                self.fill_alternate = decode_boolean(&value);
            }
        }
        parser
            .end()
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        self.initialize_entries()
            .map_err(|e| XmlParseException::new(e.0))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::composite::Composite;
    use crate::program::model::data::data_type_component::DataTypeComponent;
    use crate::program::model::data::structure::Structure;
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::protorules::param_test_support::{
        ram_space, stack_space, TestEntry, TestLanguage, TestResource,
    };
    use crate::program::model::lang::protorules::xml_test_support::{MockElement, QueueParser};
    use crate::program::model::pcode::{AttributeId, ElementId};

    #[derive(Clone)]
    struct MockPrimitive {
        length: i32,
        floating_point: bool,
    }
    impl DataType for MockPrimitive {
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_alignment(&self) -> i32 {
            self.length
        }
        fn is_floating_point(&self) -> bool {
            self.floating_point
        }
        fn is_integer_type(&self) -> bool {
            !self.floating_point
        }
        fn is_signed_integer_type(&self) -> bool {
            true
        }
    }

    #[derive(Clone)]
    struct MockComponent {
        offset: i32,
        field: MockPrimitive,
    }
    impl DataTypeComponent for MockComponent {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(self.field.clone())
        }
        fn get_offset(&self) -> i32 {
            self.offset
        }
    }

    struct MockStruct {
        components: Vec<MockComponent>,
        length: i32,
    }
    impl DataType for MockStruct {
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_alignment(&self) -> i32 {
            4
        }
        fn is_structure(&self) -> bool {
            true
        }
        fn as_structure(&self) -> Option<&dyn Structure> {
            Some(self)
        }
    }
    impl Composite for MockStruct {
        fn get_defined_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
            self.components.iter().cloned().map(|c| Box::new(c) as Box<dyn DataTypeComponent>).collect()
        }
        fn is_packing_enabled(&self) -> bool {
            true // Avoid the extra-space/hole checks entirely; not what these tests exercise.
        }
    }
    impl Structure for MockStruct {}

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    struct DualResource {
        entries: Vec<Arc<dyn ParamEntry>>,
        big_endian: bool,
    }
    impl ParamListStandardLike for DualResource {
        fn get_num_param_entry(&self) -> i32 {
            self.entries.len() as i32
        }
        fn get_entry(&self, index: i32) -> Option<Arc<dyn ParamEntry>> {
            self.entries.get(index as usize).cloned()
        }
        fn get_language(&self) -> Option<Arc<dyn Language>> {
            Some(Arc::new(TestLanguage { big_endian: self.big_endian }))
        }
    }

    /// One 4-byte general (base) exclusion tile (group 0), one 4-byte float (alt) exclusion tile
    /// (group 1), and a stack entry (group 2).
    fn dual_resource() -> Arc<dyn ParamListStandardLike> {
        Arc::new(DualResource {
            entries: vec![
                Arc::new(TestEntry {
                    ty: StorageClass::General,
                    group: 0,
                    align: 0,
                    size: 4,
                    addressbase: 0x1000,
                    space: ram_space(),
                    ..TestEntry::default()
                }),
                Arc::new(TestEntry {
                    ty: StorageClass::Float,
                    group: 1,
                    align: 0,
                    size: 4,
                    addressbase: 0x2000,
                    space: ram_space(),
                    ..TestEntry::default()
                }),
                Arc::new(TestEntry {
                    space: stack_space(),
                    group: 2,
                    align: 4,
                    numslots: 8,
                    addressbase: 0,
                    ..TestEntry::default()
                }),
            ],
            big_endian: false,
        })
    }

    fn dt_manager() -> MockDataTypeManager {
        MockDataTypeManager
    }

    #[test]
    fn new_fails_when_alt_tiles_are_missing() {
        let no_float = Arc::new(DualResource {
            entries: vec![Arc::new(TestEntry {
                ty: StorageClass::General,
                group: 0,
                align: 0,
                space: ram_space(),
                ..TestEntry::default()
            })],
            big_endian: false,
        });
        let err =
            MultiSlotDualAssign::new(StorageClass::General, StorageClass::Float, true, false, false, false, no_float)
                .map(|_| ()) // MultiSlotDualAssign isn't Debug; unwrap_err needs the Ok side to be.
                .unwrap_err();
        assert!(err.0.contains("join_dual_class"));
    }

    #[test]
    fn new_fails_when_tile_sizes_disagree() {
        let mismatched = Arc::new(DualResource {
            entries: vec![
                Arc::new(TestEntry {
                    ty: StorageClass::General,
                    group: 0,
                    align: 0,
                    size: 4,
                    space: ram_space(),
                    ..TestEntry::default()
                }),
                Arc::new(TestEntry {
                    ty: StorageClass::Float,
                    group: 1,
                    align: 0,
                    size: 8, // different tile size than the general tile
                    space: ram_space(),
                    ..TestEntry::default()
                }),
            ],
            big_endian: false,
        });
        let err =
            MultiSlotDualAssign::new(StorageClass::General, StorageClass::Float, false, false, false, false, mismatched)
                .map(|_| ())
                .unwrap_err();
        assert!(err.0.contains("do not match"));
    }

    #[test]
    fn assign_address_places_int_member_in_base_and_float_member_in_alt_register() {
        let action = MultiSlotDualAssign::new(
            StorageClass::General,
            StorageClass::Float,
            false,
            true, // most_sig = true: no piece reversal, keeps this test's ordering simple
            false,
            false,
            dual_resource(),
        )
        .unwrap();
        // { int a; float b; } -- two 4-byte members, one classified General, one Float.
        let dt: Arc<dyn DataType> = Arc::new(MockStruct {
            components: vec![
                MockComponent { offset: 0, field: MockPrimitive { length: 4, floating_point: false } },
                MockComponent { offset: 4, field: MockPrimitive { length: 4, floating_point: true } },
            ],
            length: 8,
        });
        let dtm = dt_manager();
        let proto = PrototypePieces::default();
        let mut status = [0i32; 3];
        let mut res = ParameterPieces::default();

        let code = action.assign_address(&dt, &proto, 0, &dtm, &mut status, &mut res);
        assert_eq!(code, SUCCESS);
        assert_eq!(status[0], -1); // base (general) tile consumed
        assert_eq!(status[1], -1); // alt (float) tile consumed
        assert_eq!(status[2], 0); // stack untouched
        let pieces = res.join_pieces.expect("two distinct-class pieces must produce join pieces");
        assert_eq!(pieces.len(), 2);
        assert_eq!(pieces[0].get_address().offset(), 0x1000); // general tile
        assert_eq!(pieces[1].get_address().offset(), 0x2000); // float tile
    }

    #[test]
    fn assign_address_spills_onto_the_stack_when_a_needed_class_is_exhausted() {
        let action = MultiSlotDualAssign::new(
            StorageClass::General,
            StorageClass::Float,
            true,
            true,
            false,
            false,
            dual_resource(),
        )
        .unwrap();
        // Three 4-byte int members: only one General tile is available, so the remaining two
        // members (8 bytes) must spill to the stack once getFirstUnused runs out of base tiles.
        let dt: Arc<dyn DataType> = Arc::new(MockStruct {
            components: vec![
                MockComponent { offset: 0, field: MockPrimitive { length: 4, floating_point: false } },
                MockComponent { offset: 4, field: MockPrimitive { length: 4, floating_point: false } },
                MockComponent { offset: 8, field: MockPrimitive { length: 4, floating_point: false } },
            ],
            length: 12,
        });
        let dtm = dt_manager();
        let proto = PrototypePieces::default();
        let mut status = [0i32; 3];
        let mut res = ParameterPieces::default();

        let code = action.assign_address(&dt, &proto, 0, &dtm, &mut status, &mut res);
        assert_eq!(code, SUCCESS);
        assert_eq!(status[0], -1); // the one general tile consumed
        // The remaining 8 bytes spill to the stack as one `getAddrBySlot` request (not further
        // split by tile boundaries); at align 4 that's 2 slots.
        assert_eq!(status[2], 2);
    }

    #[test]
    fn assign_address_fails_when_a_needed_class_is_exhausted_and_stack_spill_is_disabled() {
        let action = MultiSlotDualAssign::new(
            StorageClass::General,
            StorageClass::Float,
            false,
            true,
            false,
            false,
            dual_resource(),
        )
        .unwrap();
        let dt: Arc<dyn DataType> = Arc::new(MockStruct {
            components: vec![
                MockComponent { offset: 0, field: MockPrimitive { length: 4, floating_point: false } },
                MockComponent { offset: 4, field: MockPrimitive { length: 4, floating_point: false } },
            ],
            length: 8,
        });
        let dtm = dt_manager();
        let proto = PrototypePieces::default();
        let mut status = [0i32; 3];
        let mut res = ParameterPieces::default();

        let code = action.assign_address(&dt, &proto, 0, &dtm, &mut status, &mut res);
        assert_eq!(code, FAIL);
    }

    #[test]
    fn assign_address_fails_when_a_primitive_straddles_a_tile_boundary() {
        let action = MultiSlotDualAssign::new(
            StorageClass::General,
            StorageClass::Float,
            true,
            true,
            false,
            false,
            dual_resource(),
        )
        .unwrap();
        // A single 6-byte primitive with a 4-byte tile size straddles the tile-0/tile-1 boundary.
        let dt: Arc<dyn DataType> = Arc::new(MockStruct {
            components: vec![MockComponent {
                offset: 0,
                field: MockPrimitive { length: 6, floating_point: false },
            }],
            length: 6,
        });
        let dtm = dt_manager();
        let proto = PrototypePieces::default();
        let mut status = [0i32; 3];
        let mut res = ParameterPieces::default();

        let code = action.assign_address(&dt, &proto, 0, &dtm, &mut status, &mut res);
        assert_eq!(code, FAIL);
    }

    #[test]
    fn assign_address_fails_when_primitive_extraction_is_invalid() {
        let action = MultiSlotDualAssign::new(
            StorageClass::General,
            StorageClass::Float,
            true,
            true,
            false,
            false,
            dual_resource(),
        )
        .unwrap();
        // A bare (non-array, non-struct, non-union) data-type is not something PrimitiveExtractor
        // can decompose into members at all.
        let dt: Arc<dyn DataType> = Arc::new(MockPrimitive { length: 4, floating_point: false });
        let dtm = dt_manager();
        let proto = PrototypePieces::default();
        let mut status = [0i32; 3];
        let mut res = ParameterPieces::default();

        let code = action.assign_address(&dt, &proto, 0, &dtm, &mut status, &mut res);
        assert_eq!(code, FAIL);
    }

    #[test]
    fn is_equivalent_compares_configuration_and_tiles_but_not_stack_entry() {
        let a = MultiSlotDualAssign::new(
            StorageClass::General,
            StorageClass::Float,
            true,
            false,
            false,
            false,
            dual_resource(),
        )
        .unwrap();
        let b = MultiSlotDualAssign::new(
            StorageClass::General,
            StorageClass::Float,
            true,
            false,
            false,
            false,
            dual_resource(),
        )
        .unwrap();
        assert!(a.is_equivalent(&b));

        let diff_fill = MultiSlotDualAssign::new(
            StorageClass::General,
            StorageClass::Float,
            true,
            false,
            false,
            true,
            dual_resource(),
        )
        .unwrap();
        assert!(!a.is_equivalent(&diff_fill));

        let diff_alt = MultiSlotDualAssign::new(
            StorageClass::General,
            StorageClass::Vector,
            false, // no stack entry in this resource
            false,
            false,
            false,
            Arc::new(DualResource {
                entries: vec![
                    Arc::new(TestEntry { ty: StorageClass::General, group: 0, align: 0, size: 4, space: ram_space(), ..TestEntry::default() }),
                    Arc::new(TestEntry { ty: StorageClass::Vector, group: 1, align: 0, size: 4, space: ram_space(), ..TestEntry::default() }),
                ],
                big_endian: false,
            }),
        )
        .unwrap();
        assert!(!a.is_equivalent(&diff_alt));
    }

    #[test]
    fn clone_box_carries_configuration_and_new_resource() {
        let action = MultiSlotDualAssign::new(
            StorageClass::General,
            StorageClass::Float,
            true,
            true,
            true,
            true,
            dual_resource(),
        )
        .unwrap();
        let cloned = action.clone_box(dual_resource()).expect("clone should succeed");
        assert!(action.is_equivalent(cloned.as_ref()));
    }

    #[test]
    fn for_decode_derives_big_endian_defaults() {
        let big_endian_resource = Arc::new(DualResource {
            entries: vec![
                Arc::new(TestEntry { ty: StorageClass::General, group: 0, align: 0, space: ram_space(), big_endian: true, ..TestEntry::default() }),
            ],
            big_endian: true,
        });
        let action = MultiSlotDualAssign::for_decode(big_endian_resource);
        assert!(action.consume_most_sig);
        assert!(action.justify_right);
        assert!(!action.consume_from_stack); // always false by default, unlike MultiSlotAssign
    }

    struct RecordingEncoder {
        elements: Vec<&'static str>,
        bools: Vec<(&'static str, bool)>,
        strings: Vec<(&'static str, String)>,
    }
    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: ElementId) -> std::io::Result<()> {
            self.elements.push(elem_id.name);
            Ok(())
        }
        fn close_element(&mut self, elem_id: ElementId) -> std::io::Result<()> {
            self.elements.push(elem_id.name);
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
    fn encode_closes_with_the_wrong_element_id_bug() {
        // Faithfully reproduces the real Java bug documented on `encode`: it opens
        // ELEM_JOIN_DUAL_CLASS but closes with ELEM_JOIN.
        let action = MultiSlotDualAssign::new(
            StorageClass::General,
            StorageClass::Float,
            false,
            false,
            false,
            false,
            dual_resource(),
        )
        .unwrap();
        let mut enc = RecordingEncoder { elements: Vec::new(), bools: Vec::new(), strings: Vec::new() };
        action.encode(&mut enc).unwrap();
        assert_eq!(enc.elements, vec!["join_dual_class", "join"]);
    }

    #[test]
    fn encode_writes_b_attribute_for_non_default_alt_type() {
        let action = MultiSlotDualAssign::new(
            StorageClass::General,
            StorageClass::Vector,
            false,
            false,
            false,
            false,
            Arc::new(DualResource {
                entries: vec![
                    Arc::new(TestEntry { ty: StorageClass::General, group: 0, align: 0, size: 4, space: ram_space(), ..TestEntry::default() }),
                    Arc::new(TestEntry { ty: StorageClass::Vector, group: 1, align: 0, size: 4, space: ram_space(), ..TestEntry::default() }),
                ],
                big_endian: false,
            }),
        )
        .unwrap();
        let mut enc = RecordingEncoder { elements: Vec::new(), bools: Vec::new(), strings: Vec::new() };
        action.encode(&mut enc).unwrap();
        assert_eq!(enc.strings, vec![("b", "vector".to_string())]);
    }

    #[test]
    fn restore_xml_accepts_both_storage_and_a_attribute_names_for_base_type() {
        let mut parser_storage = QueueParser::new(vec![
            MockElement::start("join_dual_class", 0, &[("storage", "vector")]),
            MockElement::end("join_dual_class", 0),
        ]);
        let mut action1 = MultiSlotDualAssign::for_decode(Arc::new(DualResource {
            entries: vec![
                Arc::new(TestEntry { ty: StorageClass::Vector, group: 0, align: 0, size: 4, space: ram_space(), ..TestEntry::default() }),
                Arc::new(TestEntry { ty: StorageClass::Float, group: 1, align: 0, size: 4, space: ram_space(), ..TestEntry::default() }),
            ],
            big_endian: false,
        }));
        action1.restore_xml(&mut parser_storage).unwrap();
        assert_eq!(action1.base_type, StorageClass::Vector);

        let mut parser_a = QueueParser::new(vec![
            MockElement::start("join_dual_class", 0, &[("a", "vector")]),
            MockElement::end("join_dual_class", 0),
        ]);
        let mut action2 = MultiSlotDualAssign::for_decode(Arc::new(DualResource {
            entries: vec![
                Arc::new(TestEntry { ty: StorageClass::Vector, group: 0, align: 0, size: 4, space: ram_space(), ..TestEntry::default() }),
                Arc::new(TestEntry { ty: StorageClass::Float, group: 1, align: 0, size: 4, space: ram_space(), ..TestEntry::default() }),
            ],
            big_endian: false,
        }));
        action2.restore_xml(&mut parser_a).unwrap();
        assert_eq!(action2.base_type, StorageClass::Vector);
    }

    #[test]
    fn restore_xml_reads_b_attribute_and_reinitializes_tiles() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("join_dual_class", 0, &[("b", "vector")]),
            MockElement::end("join_dual_class", 0),
        ]);
        let mut action = MultiSlotDualAssign::for_decode(Arc::new(DualResource {
            entries: vec![
                Arc::new(TestEntry { ty: StorageClass::General, group: 0, align: 0, size: 4, space: ram_space(), ..TestEntry::default() }),
                Arc::new(TestEntry { ty: StorageClass::Vector, group: 1, align: 0, size: 4, space: ram_space(), ..TestEntry::default() }),
            ],
            big_endian: false,
        }));
        action.restore_xml(&mut parser).unwrap();
        assert_eq!(action.alt_type, StorageClass::Vector);
        assert_eq!(action.alt_tiles.len(), 1);
    }

    #[test]
    fn usable_as_trait_object() {
        let action: Box<dyn AssignAction> = Box::new(
            MultiSlotDualAssign::new(StorageClass::General, StorageClass::Float, false, true, false, false, dual_resource())
                .unwrap(),
        );
        let dt: Arc<dyn DataType> = Arc::new(MockStruct {
            components: vec![MockComponent { offset: 0, field: MockPrimitive { length: 4, floating_point: false } }],
            length: 4,
        });
        let dtm = dt_manager();
        let proto = PrototypePieces::default();
        let mut status = [0i32; 3];
        let mut res = ParameterPieces::default();
        let code = action.assign_address(&dt, &proto, 0, &dtm, &mut status, &mut res);
        assert_eq!(code, SUCCESS);
    }
}
