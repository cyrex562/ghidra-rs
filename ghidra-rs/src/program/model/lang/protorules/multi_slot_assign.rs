use std::any::Any;
use std::sync::Arc;

use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::param_entry::ParamEntry;
use crate::program::model::lang::protorules::assign_action::{
    justify_pieces, AssignAction, FAIL, SUCCESS,
};
use crate::program::model::lang::storage_class::StorageClass;
use crate::program::model::pcode::{
    Encoder, ATTRIB_ALIGN, ATTRIB_BACKFILL, ATTRIB_REVERSEJUSTIFY, ATTRIB_REVERSESIGNIF,
    ATTRIB_STACKSPILL, ATTRIB_STORAGE, ELEM_JOIN,
};
use crate::program::model::lang::param_list_standard::ParamListStandard;
use crate::program::seam_stubs::{ParameterPieces, PrototypePieces};
use crate::util::exception::InvalidInputException;
use crate::util::xml::spec_xml_utils::decode_boolean;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Consume multiple registers to pass a data-type.
///
/// Available registers are consumed until the data-type is covered, and an appropriate join-space
/// address is assigned. Registers can be consumed from a specific resource list. Consumption can
/// spill over onto the stack if desired.
///
/// Port of `ghidra.program.model.lang.protorules.MultiSlotAssign`.
pub struct MultiSlotAssign {
    /// Resource list from which to consume (`MultiSlotAssign.resourceType`).
    resource_type: StorageClass,
    /// True for big endian architectures (`MultiSlotAssign.isBigEndian`).
    is_big_endian: bool,
    /// True if resources should be consumed from the stack (`MultiSlotAssign.consumeFromStack`).
    consume_from_stack: bool,
    /// True if resources are consumed starting with most significant bytes
    /// (`MultiSlotAssign.consumeMostSig`).
    consume_most_sig: bool,
    /// True if register resources are discarded to match alignment
    /// (`MultiSlotAssign.enforceAlignment`).
    enforce_alignment: bool,
    /// True if initial bytes are padding for odd data-type sizes (`MultiSlotAssign.justifyRight`).
    justify_right: bool,
    /// True if an assignment should only consume adjacent entries in the list
    /// (`MultiSlotAssign.adjacentEntries`). Both Java constructors always set this `true`; there
    /// is no way to configure it otherwise, and `restoreXml` never touches it either. Kept as a
    /// field (rather than a hardcoded literal at each use site) purely to mirror the Java class
    /// shape and so [`is_equivalent`](AssignAction::is_equivalent) can compare it faithfully.
    adjacent_entries: bool,
    /// True if entries skipped for alignment can be reused for later params
    /// (`MultiSlotAssign.allowBackfill`).
    allow_backfill: bool,
    /// Registers that can be joined (`MultiSlotAssign.tiles`).
    tiles: Vec<Arc<ParamEntry>>,
    /// The stack resource (`MultiSlotAssign.stackEntry`).
    stack_entry: Option<Arc<ParamEntry>>,
}

impl MultiSlotAssign {
    /// Cache specific [`ParamEntry`]s needed by the action.
    ///
    /// Find the tiles matching `resource_type`, and the entry corresponding to the stack if
    /// `consume_from_stack` is set.
    ///
    /// Port of the private `initializeEntries`.
    ///
    /// # Errors
    /// Returns an error if the required elements are not available in the resource list.
    fn initialize_entries(&mut self, resource: &ParamListStandard) -> Result<(), InvalidInputException> {
        self.tiles = resource.extract_tiles(self.resource_type);
        self.stack_entry = resource.extract_stack();
        if self.tiles.is_empty() {
            return Err(InvalidInputException::with_message(
                "Could not find matching resources for action: join",
            ));
        }
        if self.consume_from_stack && self.stack_entry.is_none() {
            return Err(InvalidInputException::with_message(
                "Cannot find matching <pentry> for action: join",
            ));
        }
        Ok(())
    }

    /// Port of the "protected" constructor, used to build a default-configured instance before
    /// [`restore_xml`](AssignAction::restore_xml) overrides its attributes (mirroring
    /// `AssignAction.restoreActionXml`'s `new MultiSlotAssign(res)`, not itself ported into this
    /// crate yet -- see [`AssignAction`]'s module doc).
    ///
    /// Unlike [`new`](Self::new), this does **not** call [`initialize_entries`](Self::initialize_entries);
    /// Java defers that to the end of `restoreXml`, since the resource-list lookups depend on
    /// `resourceType`, which an XML attribute may still override.
    pub fn for_decode(res: &ParamListStandard) -> Self {
        let is_big_endian = res.is_big_endian();
        // Port of `consumeFromStack = !(res instanceof ParamListStandardOut)`; see
        // `ParamListStandard::is_standard_out`'s doc for how this stands in for Java's
        // `instanceof` runtime type test.
        let consume_from_stack = !res.is_standard_out();
        MultiSlotAssign {
            resource_type: StorageClass::General,
            is_big_endian,
            consume_from_stack,
            consume_most_sig: is_big_endian,
            enforce_alignment: false,
            justify_right: is_big_endian,
            adjacent_entries: true,
            allow_backfill: false,
            tiles: Vec::new(),
            stack_entry: None,
        }
    }

    /// Port of the public constructor.
    ///
    /// # Errors
    /// Returns an error if the required elements are not available in `res`.
    pub fn new(
        store: StorageClass,
        stack: bool,
        most_sig: bool,
        align: bool,
        just_right: bool,
        backfill: bool,
        res: &ParamListStandard,
    ) -> Result<Self, InvalidInputException> {
        let is_big_endian = res.is_big_endian();
        let mut action = MultiSlotAssign {
            resource_type: store,
            is_big_endian,
            consume_from_stack: stack,
            consume_most_sig: most_sig,
            enforce_alignment: align,
            justify_right: just_right,
            adjacent_entries: true,
            allow_backfill: backfill,
            tiles: Vec::new(),
            stack_entry: None,
        };
        action.initialize_entries(res)?;
        Ok(action)
    }

    /// Test if a data-type of the given size will fit starting at a particular entry within the
    /// resource list.
    ///
    /// Port of the private `checkFit`.
    ///
    /// # Quirk (faithfully reproduced)
    /// Java's `checkFit` (`MultiSlotAssign.checkFit`) has a real bug: its trailing
    /// `while (iter != tiles.length && sizeLeft > 0)` loop -- meant to walk forward confirming
    /// enough *adjacent* tiles remain available to cover the data-type -- never advances `iter`.
    /// It therefore always re-examines the exact same `tiles[iter]` entry (whose group
    /// availability was already confirmed by the check above the loop) `ceil(sizeLeft /
    /// entry.getSize())` times, decrementing `sizeLeft` by the same amount each time, and always
    /// returns `true` once that single entry's group/alignment checks pass -- regardless of
    /// whether later adjacent tiles are actually available. This means `adjacentEntries` (always
    /// `true` in practice; see the field doc) has essentially no real effect: `checkFit` never
    /// rejects a position for lack of adjacent room. See
    /// `check_fit_never_rejects_for_insufficient_adjacent_tiles` for a test proving this.
    fn check_fit(
        &self,
        iter: usize,
        mut size_left: i32,
        align: i32,
        resources_consumed: i32,
        tmp_status: &[i32],
    ) -> bool {
        let entry = &self.tiles[iter];
        if tmp_status[entry.get_group() as usize] != 0 {
            return false;
        }
        if self.enforce_alignment {
            let reg_size = entry.get_size();
            if align > reg_size && (resources_consumed % align) != 0 {
                return false;
            }
        }
        if !self.adjacent_entries {
            return true;
        }
        while iter != self.tiles.len() && size_left > 0 {
            let entry = &self.tiles[iter];
            if tmp_status[entry.get_group() as usize] != 0 {
                return false;
            }
            size_left -= entry.get_size();
        }
        true
    }
}

impl AssignAction for MultiSlotAssign {
    fn clone_box(
        &self,
        new_resource: &ParamListStandard,
    ) -> Result<Box<dyn AssignAction>, InvalidInputException> {
        Ok(Box::new(MultiSlotAssign::new(
            self.resource_type,
            self.consume_from_stack,
            self.consume_most_sig,
            self.enforce_alignment,
            self.justify_right,
            self.allow_backfill,
            new_resource,
        )?))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn is_equivalent(&self, op: &dyn AssignAction) -> bool {
        let Some(other) = op.as_any().downcast_ref::<MultiSlotAssign>() else {
            return false;
        };
        if self.consume_from_stack != other.consume_from_stack
            || self.consume_most_sig != other.consume_most_sig
            || self.enforce_alignment != other.enforce_alignment
            || self.justify_right != other.justify_right
            || self.adjacent_entries != other.adjacent_entries
            || self.allow_backfill != other.allow_backfill
        {
            return false;
        }
        if self.resource_type != other.resource_type {
            return false;
        }
        if self.tiles.len() != other.tiles.len() {
            return false;
        }
        for (a, b) in self.tiles.iter().zip(other.tiles.iter()) {
            if !a.is_equivalent(b) {
                return false;
            }
        }
        match (&self.stack_entry, &other.stack_entry) {
            (None, None) => {}
            (Some(a), Some(b)) => {
                if !a.is_equivalent(b) {
                    return false;
                }
            }
            _ => return false,
        }
        true
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
        let mut tmp_status = status.to_vec();
        let mut pieces: Vec<crate::program::model::pcode::Varnode> = Vec::new();
        let mut size_left = dt.get_length();
        let mut align = dt.get_alignment();
        let mut iter = 0usize;
        let mut resources_consumed = 0i32;
        while iter != self.tiles.len() {
            if self.check_fit(iter, size_left, align, resources_consumed, &tmp_status) {
                break;
            }
            let entry = &self.tiles[iter];
            if !self.allow_backfill {
                tmp_status[entry.get_group() as usize] = -1; // Consume unaligned register
            }
            resources_consumed += entry.get_size();
            iter += 1;
        }
        while size_left > 0 && iter != self.tiles.len() {
            let entry = self.tiles[iter].clone();
            iter += 1;
            let grp = entry.get_group() as usize;
            if tmp_status[grp] != 0 {
                continue; // Already consumed
            }
            let trial_size = entry.get_size();
            let mut param = ParameterPieces::default();
            entry.get_addr_by_slot(tmp_status[grp], trial_size, align, &mut param);
            tmp_status[grp] = -1; // Consume the register
            let Some(addr) = param.address else {
                // Defensive: a freshly-consumed, single-slot exclusion tile requesting exactly
                // its own size should never fail to produce an address; guards against an
                // unsound unwrap if a future ParamEntry impl disagrees.
                return FAIL;
            };
            pieces.push(crate::program::model::pcode::Varnode::new(addr, trial_size));
            size_left -= trial_size;
            align = 1; // Treat remaining partial pieces as having no alignment requirement
        }
        let mut one_piece_join = false;
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
            pieces.push(crate::program::model::pcode::Varnode::new(addr, size_left));
        } else if size_left < 0 {
            // Have odd data-type size.
            if self.resource_type == StorageClass::Float && pieces.len() == 1 {
                // Floating-point register holding extended lower precision value: treat as
                // "join" of full size register.
                one_piece_join = true;
            } else {
                justify_pieces(&mut pieces, -size_left, self.is_big_endian, self.consume_most_sig, self.justify_right);
            }
        }
        // Commit resource usage for all the pieces.
        status.copy_from_slice(&tmp_status);
        res.data_type = Some(dt.clone());
        let Some(language) = resource.get_language() else {
            // A restored ParamListStandard always has its Language; only one assembled with
            // `from_parts` and no language lacks it.
            return FAIL;
        };
        res.assign_address_from_pieces(pieces, self.consume_most_sig, one_piece_join, language.as_ref());
        SUCCESS
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        encoder.open_element(ELEM_JOIN)?;
        // Java re-queries `resource.isBigEndian()` here; the resource list is not held by this
        // action, so the value cached from the same resource at construction is used (entries are
        // immutable once restored, so the two agree).
        if self.is_big_endian != self.justify_right {
            encoder.write_bool(ATTRIB_REVERSEJUSTIFY, true)?;
        }
        if self.is_big_endian != self.consume_most_sig {
            encoder.write_bool(ATTRIB_REVERSESIGNIF, true)?;
        }
        if self.resource_type != StorageClass::General {
            encoder.write_string(ATTRIB_STORAGE, &self.resource_type.to_string())?;
        }
        encoder.write_bool(ATTRIB_ALIGN, self.enforce_alignment)?;
        encoder.write_bool(ATTRIB_STACKSPILL, self.consume_from_stack)?;
        encoder.write_bool(ATTRIB_BACKFILL, self.allow_backfill)?;
        encoder.close_element(ELEM_JOIN)?;
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
            .start(&[ELEM_JOIN.name])
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
            } else if name == ATTRIB_STORAGE.name {
                self.resource_type = StorageClass::from_str(&value)?;
            } else if name == ATTRIB_ALIGN.name {
                self.enforce_alignment = decode_boolean(&value);
            } else if name == ATTRIB_STACKSPILL.name {
                self.consume_from_stack = decode_boolean(&value);
            } else if name == ATTRIB_BACKFILL.name {
                self.allow_backfill = decode_boolean(&value);
            }
        }
        parser
            .end()
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        self.initialize_entries(resource)
            .map_err(|e| XmlParseException::new(e.0))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::protorules::param_test_support::{
        ram_space, stack_space, TestEntry, TestLanguage, TestResource,
    };
    use crate::program::model::lang::protorules::xml_test_support::{MockElement, QueueParser};
    use crate::program::model::lang::language::Language;
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

    /// Two 4-byte general-purpose exclusion tiles (groups 0/1) plus a stack entry (group 2), on
    /// a little-endian language.
    /// A real resource list over `entries` on a language of the given endianness, optionally
    /// marked as the base of an output list.
    fn tile_list(entries: Vec<TestEntry>, big_endian: bool, standard_out: bool) -> ParamListStandard {
        let num_group = entries.len() as i32;
        let mut list = TestResource { entries, num_group, spacebase: None }
            .build_with_language(Some(Arc::new(TestLanguage { big_endian }) as Arc<dyn Language>));
        list.set_standard_out(standard_out);
        list
    }

    fn two_tile_resource() -> ParamListStandard {
        tile_list(vec![
                TestEntry {
                    ty: StorageClass::General,
                    group: 0,
                    addressbase: 0x1000,
                    align: 0,
                    size: 4,
                    space: ram_space(),
                    ..TestEntry::default()
                },
                TestEntry {
                    ty: StorageClass::General,
                    group: 1,
                    addressbase: 0x2000,
                    align: 0,
                    size: 4,
                    space: ram_space(),
                    ..TestEntry::default()
                },
                TestEntry {
                    space: stack_space(),
                    group: 2,
                    align: 4,
                    numslots: 8,
                    addressbase: 0,
                    ..TestEntry::default()
                },
            ], false, false)
    }

    fn no_tile_resource() -> ParamListStandard {
        TestResource {
            entries: vec![TestEntry {
                space: stack_space(),
                group: 0,
                align: 4,
                numslots: 8,
                ..TestEntry::default()
            }],
            num_group: 1,
            spacebase: None,
        }.build()
    }

    #[test]
    fn new_fails_when_no_matching_tiles_are_present() {
        let err = MultiSlotAssign::new(
            StorageClass::General,
            true,
            false,
            false,
            false,
            false,
            &no_tile_resource(),
        )
        .map(|_| ()) // MultiSlotAssign isn't Debug; unwrap_err needs the Ok side to be.
        .unwrap_err();
        assert!(err.0.contains("join"));
    }

    #[test]
    fn new_fails_when_stack_requested_but_absent() {
        let no_stack = TestResource {
            entries: vec![TestEntry {
                ty: StorageClass::General,
                group: 0,
                align: 0,
                space: ram_space(),
                ..TestEntry::default()
            }],
            num_group: 1,
            spacebase: None,
        }.build();
        let err = MultiSlotAssign::new(StorageClass::General, true, false, false, false, false, &no_stack)
            .map(|_| ())
            .unwrap_err();
        assert!(err.0.contains("<pentry>"));
    }

    #[test]
    fn assign_address_splits_a_data_type_across_two_general_registers() {
        // most_sig = true so ParameterPieces::assign_address_from_pieces does not reverse the
        // piece order, keeping this test's address assertions independent of that unrelated
        // detail.
        let action =
            MultiSlotAssign::new(StorageClass::General, false, true, false, false, false, &two_tile_resource())
                .unwrap();
        let dt: Arc<dyn DataType> = Arc::new(MockDataType { length: 8, alignment: 4 });
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut status = [0i32; 3];
        let mut res = ParameterPieces::default();

        let code = action.assign_address(&two_tile_resource(), &dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, SUCCESS);
        assert_eq!(status[0], -1);
        assert_eq!(status[1], -1);
        assert_eq!(status[2], 0); // stack untouched
        let pieces = res.join_pieces.expect("two disjoint tiles must produce join pieces");
        assert_eq!(pieces.len(), 2);
        assert_eq!(pieces[0].get_address().offset(), 0x1000);
        assert_eq!(pieces[1].get_address().offset(), 0x2000);
    }

    #[test]
    fn assign_address_spills_onto_the_stack_when_tiles_are_insufficient() {
        let action =
            MultiSlotAssign::new(StorageClass::General, true, false, false, false, false, &two_tile_resource())
                .unwrap();
        // 12 bytes: fills both 4-byte tiles (8 bytes), spills the remaining 4 onto the stack.
        let dt: Arc<dyn DataType> = Arc::new(MockDataType { length: 12, alignment: 4 });
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut status = [0i32; 3];
        let mut res = ParameterPieces::default();

        let code = action.assign_address(&two_tile_resource(), &dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, SUCCESS);
        assert_eq!(status[0], -1);
        assert_eq!(status[1], -1);
        assert_eq!(status[2], 1); // one stack slot consumed
        let pieces = res.join_pieces.expect("three pieces expected");
        assert_eq!(pieces.len(), 3);
    }

    #[test]
    fn assign_address_fails_when_tiles_are_insufficient_and_stack_spill_is_disabled() {
        let action =
            MultiSlotAssign::new(StorageClass::General, false, false, false, false, false, &two_tile_resource())
                .unwrap();
        let dt: Arc<dyn DataType> = Arc::new(MockDataType { length: 12, alignment: 4 });
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut status = [0i32; 3];
        let mut res = ParameterPieces::default();

        let code = action.assign_address(&two_tile_resource(), &dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, FAIL);
    }

    #[test]
    fn check_fit_never_rejects_for_insufficient_adjacent_tiles() {
        // Faithfully reproduces the real Java bug documented on `check_fit`: tile 0 is free, but
        // tile 1 (needed to cover the full requested size) is already consumed. A *correct*
        // adjacency check would reject this position; the real (buggy) Java implementation
        // returns `true` regardless, since `iter` never advances past tile 0.
        let action =
            MultiSlotAssign::new(StorageClass::General, false, false, false, false, false, &two_tile_resource())
                .unwrap();
        let tmp_status = [0i32, -1, 0]; // tile 1 (group 1) already consumed
        let fits = action.check_fit(0, /* sizeLeft = tile0.size + tile1.size */ 8, 4, 0, &tmp_status);
        assert!(fits, "real Java checkFit bug: never rejects for insufficient adjacent tiles");
    }

    #[test]
    fn check_fit_still_rejects_when_the_starting_tile_itself_is_consumed() {
        let action =
            MultiSlotAssign::new(StorageClass::General, false, false, false, false, false, &two_tile_resource())
                .unwrap();
        let tmp_status = [-1i32, 0, 0]; // tile 0 (the one checkFit is asked about) is consumed
        let fits = action.check_fit(0, 4, 4, 0, &tmp_status);
        assert!(!fits);
    }

    #[test]
    fn is_equivalent_compares_configuration_tiles_and_stack_entry() {
        let a =
            MultiSlotAssign::new(StorageClass::General, true, false, false, false, false, &two_tile_resource())
                .unwrap();
        let b =
            MultiSlotAssign::new(StorageClass::General, true, false, false, false, false, &two_tile_resource())
                .unwrap();
        assert!(a.is_equivalent(&b));

        let diff_align =
            MultiSlotAssign::new(StorageClass::General, true, false, true, false, false, &two_tile_resource())
                .unwrap();
        assert!(!a.is_equivalent(&diff_align));

        let diff_backfill =
            MultiSlotAssign::new(StorageClass::General, true, false, false, false, true, &two_tile_resource())
                .unwrap();
        assert!(!a.is_equivalent(&diff_backfill));
    }

    #[test]
    fn clone_box_carries_configuration_and_new_resource() {
        let action =
            MultiSlotAssign::new(StorageClass::General, true, true, false, true, false, &two_tile_resource())
                .unwrap();
        let cloned = action.clone_box(&two_tile_resource()).expect("clone should succeed");
        assert!(action.is_equivalent(cloned.as_ref()));
    }

    #[test]
    fn for_decode_defaults_consume_from_stack_from_standard_out_marker() {
        let out_resource = tile_list(vec![TestEntry {
                ty: StorageClass::General,
                group: 0,
                align: 0,
                space: ram_space(),
                ..TestEntry::default()
            }], false, true);
        let action = MultiSlotAssign::for_decode(&out_resource);
        assert!(!action.consume_from_stack);

        let action2 = MultiSlotAssign::for_decode(&two_tile_resource());
        assert!(action2.consume_from_stack);
    }

    #[test]
    fn for_decode_derives_big_endian_defaults() {
        let big_endian_resource = tile_list(vec![TestEntry {
                ty: StorageClass::General,
                group: 0,
                align: 0,
                space: ram_space(),
                big_endian: true,
                ..TestEntry::default()
            }], true, false);
        let action = MultiSlotAssign::for_decode(&big_endian_resource);
        assert!(action.consume_most_sig);
        assert!(action.justify_right);
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
    fn encode_writes_join_element_with_expected_attributes() {
        let action =
            MultiSlotAssign::new(StorageClass::Float, true, false, true, false, false, &resource_with_float_tile())
                .unwrap();
        let mut enc = RecordingEncoder { elements: Vec::new(), bools: Vec::new(), strings: Vec::new() };
        action.encode(&mut enc).unwrap();
        assert_eq!(enc.elements, vec!["join"]);
        assert_eq!(enc.strings, vec![("storage", "float".to_string())]);
        assert!(enc.bools.contains(&("align", true)));
        assert!(enc.bools.contains(&("stackspill", true)));
        assert!(enc.bools.contains(&("backfill", false)));
    }

    #[test]
    fn encode_omits_storage_attribute_for_general() {
        let action = MultiSlotAssign::new(StorageClass::General, false, false, false, false, false, &two_tile_resource())
            .unwrap();
        let mut enc = RecordingEncoder { elements: Vec::new(), bools: Vec::new(), strings: Vec::new() };
        action.encode(&mut enc).unwrap();
        assert!(enc.strings.is_empty());
    }

    #[test]
    fn restore_xml_toggles_justify_and_signif_and_reinitializes_entries() {
        let mut parser = QueueParser::new(vec![
            MockElement::start(
                "join",
                0,
                &[
                    ("reversejustify", "true"),
                    ("reversesignif", "true"),
                    ("align", "true"),
                    ("stackspill", "true"),
                    ("backfill", "true"),
                ],
            ),
            MockElement::end("join", 0),
        ]);
        let mut action =
            MultiSlotAssign::new(StorageClass::General, false, false, false, false, false, &two_tile_resource())
                .unwrap();
        assert!(!action.justify_right);
        assert!(!action.consume_most_sig);
        action.restore_xml(&mut parser, &two_tile_resource()).unwrap();
        assert!(action.justify_right); // toggled
        assert!(action.consume_most_sig); // toggled
        assert!(action.enforce_alignment);
        assert!(action.consume_from_stack);
        assert!(action.allow_backfill);
        assert_eq!(action.tiles.len(), 2);
    }

    fn resource_with_float_tile() -> ParamListStandard {
        tile_list(vec![
                TestEntry {
                    ty: StorageClass::General,
                    group: 0,
                    align: 0,
                    size: 4,
                    space: ram_space(),
                    ..TestEntry::default()
                },
                TestEntry {
                    ty: StorageClass::Float,
                    group: 1,
                    align: 0,
                    size: 8,
                    space: ram_space(),
                    ..TestEntry::default()
                },
                TestEntry {
                    space: stack_space(),
                    group: 2,
                    align: 4,
                    numslots: 8,
                    ..TestEntry::default()
                },
            ], false, false)
    }

    #[test]
    fn restore_xml_reads_storage_class_and_reinitializes_tiles_for_the_new_class() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("join", 0, &[("storage", "float")]),
            MockElement::end("join", 0),
        ]);
        // for_decode intentionally skips populating tiles (Java only calls initializeEntries() at
        // the very end of restoreXml, after resourceType is finalized from the XML attributes).
        let resource = resource_with_float_tile();
        let mut action = MultiSlotAssign::for_decode(&resource);
        action.restore_xml(&mut parser, &resource).unwrap();
        assert_eq!(action.resource_type, StorageClass::Float);
        assert_eq!(action.tiles.len(), 1);
        assert_eq!(action.tiles[0].get_type(), StorageClass::Float);
    }

    #[test]
    fn usable_as_trait_object() {
        let action: Box<dyn AssignAction> = Box::new(
            MultiSlotAssign::new(StorageClass::General, false, false, false, false, false, &two_tile_resource())
                .unwrap(),
        );
        let dt: Arc<dyn DataType> = Arc::new(MockDataType { length: 4, alignment: 4 });
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut status = [0i32; 3];
        let mut res = ParameterPieces::default();
        let code = action.assign_address(&two_tile_resource(), &dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, SUCCESS);
    }
}
