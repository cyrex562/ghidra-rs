use std::sync::Arc;

use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::param_entry::ParamEntry;
use crate::program::model::lang::param_list::{ParamList, WithSlotRec};
use crate::program::model::lang::protorules::assign_action;
use crate::program::model::lang::storage_class::StorageClass;
use crate::program::model::pcode::{
    Encoder, ATTRIB_KILLEDBYCALL, ATTRIB_SEPARATEFLOAT, ATTRIB_THISBEFORERETPOINTER, ELEM_GROUP,
    ELEM_INPUT, ELEM_OUTPUT,
};
use crate::program::seam_stubs::{ModelRuleLike, ParameterPieces, PrototypePieces};

/// Classify a data-type for the purpose of picking a storage resource.
///
/// Port of the static helper `ghidra.program.model.lang.ParamEntry.getBasicTypeClass`. Lives
/// here rather than on [`ParamEntry`] since it only inspects the data-type, not any
/// particular parameter-entry instance.
pub fn get_basic_type_class(tp: &dyn DataType) -> StorageClass {
    if tp.is_typedef() {
        if let Some(base) = tp.typedef_base_data_type() {
            return get_basic_type_class(base.as_ref());
        }
    }
    if tp.is_floating_point() {
        return StorageClass::Float;
    }
    if tp.is_pointer() {
        return StorageClass::Ptr;
    }
    StorageClass::General
}

/// Standard analysis for parameter lists.
///
/// A list of resources ([`ParamEntry`] entries) describing possible storage locations for a
/// function's parameters (or return value), plus [`ModelRuleLike`] rules controlling how
/// addresses get assigned to a given parameter's data-type.
///
/// In Java, `ParamListStandard implements ParamList` directly. Several of its methods (
/// `assignMap`, `encode`, `getStackParameterAlignment`, `getStackParameterOffset`,
/// `possibleParamWithSlot`, `isEquivalent`) override `ParamList` methods of the same name; since
/// Rust doesn't let a subtrait retroactively supply a supertrait's required method, those are
/// exposed here as distinctly-named provided methods (suffixed `_std`) that a concrete type's
/// `ParamList` impl is expected to delegate to. The remaining methods (`assignAddressFallback`,
/// `assignAddress`, `getNumParamEntry`, `getEntry`, `isBigEndian`, `extractTiles`,
/// `extractStack`) are unique to this class, so they keep their original names.
///
/// `encode` is provided (`encode_std`) since it only depends on the already-ported `Encoder`,
/// the real [`ParamEntry`] port, and the [`ModelRuleLike`] placeholder. `restoreXml` is NOT
/// provided: it constructs new `ParamEntry`/`ModelRule` instances from an XML stream (including
/// `SizeRestrictedFilter`/`ConvertToPointer` for the `pointermax` attribute), which needs those
/// classes' real constructors, not just accessors on an opaque placeholder trait object. It
/// remains an abstract, required method inherited from [`ParamList`], to be implemented once
/// `ModelRule` (and the `AddressXML` join-parsing it also needs) are ported. Likewise
/// `getPotentialRegisterStorage` is not provided:
/// the real method constructs `VariableStorage` instances, and the
/// [`VariableStorage`](crate::program::seam_stubs::VariableStorage) placeholder is an empty
/// marker trait with no constructor.
///
/// Port of `ghidra.program.model.lang.ParamListStandard`.
pub trait ParamListStandard: ParamList {
    /// The resource list, in order (`ParamListStandard.entry`).
    fn entries(&self) -> &[Box<dyn ParamEntry>];

    /// Rules to apply when assigning addresses (`ParamListStandard.modelRules`).
    fn model_rules(&self) -> &[Box<dyn ModelRuleLike>];

    /// Number of "groups" in this parameter convention (`ParamListStandard.numgroup`).
    fn num_group(&self) -> i32;

    /// Space containing relative offset parameters (`ParamListStandard.spacebase`), or `None`.
    fn spacebase(&self) -> Option<Arc<AddressSpace>>;

    /// Do hidden return pointers usurp the storage of the `this` pointer
    /// (`ParamListStandard.thisbeforeret`).
    fn this_before_ret(&self) -> bool;

    /// Is storage in this list automatically "killed by call"
    /// (`ParamListStandard.autoKilledByCall`).
    fn auto_killed_by_call(&self) -> bool;

    /// Are metatyped entries in separate resource sections (`ParamListStandard.splitMetatype`).
    fn split_metatype(&self) -> bool;

    /// Find the (first) entry containing the given range.
    ///
    /// Port of the private `ParamListStandard.findEntry`.
    fn find_entry(&self, loc: &Address, size: i32) -> Option<usize> {
        self.entries()
            .iter()
            .position(|e| e.get_min_size() <= size && e.justified_contain(loc, size) == 0)
    }

    /// Assign storage for the given parameter class, using the fallback assignment algorithm.
    ///
    /// Port of `ParamListStandard.assignAddressFallback`.
    fn assign_address_fallback(
        &self,
        resource: StorageClass,
        tp: &Arc<dyn DataType>,
        match_exact: bool,
        status: &mut [i32],
        param: &mut ParameterPieces,
    ) -> i32 {
        for element in self.entries() {
            let grp = element.get_group() as usize;
            if status[grp] < 0 {
                continue;
            }
            if resource != element.get_type()
                && (match_exact || element.get_type() != StorageClass::General)
            {
                continue;
            }

            status[grp] = element.get_addr_by_slot(
                status[grp],
                tp.get_aligned_length(),
                tp.get_alignment(),
                param,
            );
            if param.address.is_none() {
                continue; // -tp- does not fit in this entry
            }
            if element.is_exclusion() {
                for group in element.get_all_groups() {
                    status[group as usize] = -1; // some number of groups are taken up
                }
            }
            param.data_type = Some(tp.clone());
            return assign_action::SUCCESS;
        }
        param.address = None;
        assign_action::FAIL
    }

    /// Fill in the address and other details for the given parameter.
    ///
    /// Attempts to apply a [`ModelRuleLike`] first; if none succeed, falls back to
    /// [`assign_address_fallback`](Self::assign_address_fallback).
    ///
    /// Port of `ParamListStandard.assignAddress`. The Java method also bails out early when `dt`
    /// is (or is a typedef wrapping) the `DataType.DEFAULT` singleton; that check is folded into
    /// [`DataType::is_default_data_type`].
    fn assign_address(
        &self,
        dt: &Arc<dyn DataType>,
        proto: &PrototypePieces,
        pos: i32,
        dt_manager: &dyn DataTypeManager,
        status: &mut [i32],
        res: &mut ParameterPieces,
    ) -> i32 {
        if dt.is_zero_length() {
            return assign_action::NO_ASSIGNMENT;
        }
        if dt.is_default_data_type() {
            return assign_action::NO_ASSIGNMENT;
        }
        if dt.is_typedef() {
            if let Some(base) = dt.typedef_base_data_type() {
                if base.is_default_data_type() {
                    return assign_action::NO_ASSIGNMENT;
                }
            }
        }
        for rule in self.model_rules() {
            let response_code = rule.assign_address(dt, proto, pos, dt_manager, status, res);
            if response_code != assign_action::FAIL {
                return response_code;
            }
        }
        let store = get_basic_type_class(dt.as_ref());
        self.assign_address_fallback(store, dt, false, status, res)
    }

    /// The number of [`ParamEntry`] entries in this list.
    ///
    /// Port of `ParamListStandard.getNumParamEntry`.
    fn get_num_param_entry(&self) -> usize {
        self.entries().len()
    }

    /// Within this list, get the entry at the given index.
    ///
    /// Port of `ParamListStandard.getEntry`.
    fn get_entry(&self, index: usize) -> &dyn ParamEntry {
        self.entries()[index].as_ref()
    }

    /// True if resources are from a big endian address space.
    ///
    /// Port of `ParamListStandard.isBigEndian`.
    fn is_big_endian(&self) -> bool {
        self.entries()[0].is_big_endian()
    }

    /// Port of `ParamListStandard.assignMap`, overriding [`ParamList::assign_map`]. See the
    /// trait-level docs for why this is not named `assign_map`.
    fn assign_map_std(
        &self,
        proto: &PrototypePieces,
        dt_manager: &dyn DataTypeManager,
        res: &mut Vec<ParameterPieces>,
        add_auto_params: bool,
    ) {
        let mut status = vec![0i32; self.num_group().max(0) as usize];

        if add_auto_params && res.len() == 2 {
            // Check for hidden parameters defined by the output list.
            let last_idx = res.len() - 1;
            if res[last_idx].hidden_return_ptr {
                // Need to pull from registers marked as hiddenret.
                if let Some(dt) = res[last_idx].data_type.clone() {
                    self.assign_address_fallback(
                        StorageClass::HiddenRet,
                        &dt,
                        false,
                        &mut status,
                        &mut res[last_idx],
                    );
                }
            } else if let Some(dt) = res[last_idx].data_type.clone() {
                // Assign as a regular first input pointer parameter.
                self.assign_address(&dt, proto, 0, dt_manager, &mut status, &mut res[last_idx]);
            }
            res[last_idx].hidden_return_ptr = true;
        }

        for i in 0..proto.intypes.len() {
            res.push(ParameterPieces::default());
            let idx = res.len() - 1;
            let response_code = self.assign_address(
                &proto.intypes[i],
                proto,
                i as i32,
                dt_manager,
                &mut status,
                &mut res[idx],
            );
            if response_code == assign_action::FAIL || response_code == assign_action::NO_ASSIGNMENT
            {
                // Do not continue to assign after first failure; fill out with unassigned
                // pieces.
                for _ in (i + 1)..proto.intypes.len() {
                    res.push(ParameterPieces::default());
                }
                return;
            }
        }
    }

    /// Port of `ParamListStandard.getStackParameterAlignment`, overriding
    /// [`ParamList::get_stack_parameter_alignment`].
    fn get_stack_parameter_alignment_std(&self) -> i32 {
        for pentry in self.entries() {
            if pentry.get_space().space_type() == AddressSpaceType::Stack {
                return pentry.get_align();
            }
        }
        -1
    }

    /// Port of `ParamListStandard.getStackParameterOffset`, overriding
    /// [`ParamList::get_stack_parameter_offset`].
    fn get_stack_parameter_offset_std(&self) -> Option<i64> {
        for element in self.entries() {
            if element.is_exclusion() {
                continue;
            }
            let space = element.get_space();
            if space.space_type() != AddressSpaceType::Stack {
                continue;
            }
            let mut res = element.get_address_base();
            if element.is_reverse_stack() {
                res += element.get_size() as i64;
            }
            return Some(space.truncate_offset(res));
        }
        None
    }

    /// Port of `ParamListStandard.possibleParamWithSlot`, overriding
    /// [`ParamList::possible_param_with_slot`].
    fn possible_param_with_slot_std(&self, loc: &Address, size: i32, res: &mut WithSlotRec) -> bool {
        let Some(num) = self.find_entry(loc, size) else {
            return false;
        };
        let curentry = self.entries()[num].as_ref();
        res.slot = curentry.get_slot(loc, 0);
        if curentry.is_exclusion() {
            res.slotsize = curentry.get_all_groups().len() as i32;
        } else {
            res.slotsize = ((size - 1) / curentry.get_align()) + 1;
        }
        true
    }

    /// Port of `ParamListStandard.isEquivalent`, overriding [`ParamList::is_equivalent`]. Omits
    /// the Java method's leading `getClass() != obj.getClass()` check, since trait objects have
    /// no equivalent notion here; callers comparing across genuinely different concrete types
    /// are expected to fail one of the field comparisons below instead.
    fn is_equivalent_std(&self, other: &dyn ParamListStandard) -> bool {
        if self.entries().len() != other.entries().len() {
            return false;
        }
        for (a, b) in self.entries().iter().zip(other.entries().iter()) {
            if !a.is_equivalent(b.as_ref()) {
                return false;
            }
        }
        if self.model_rules().len() != other.model_rules().len() {
            return false;
        }
        for (a, b) in self.model_rules().iter().zip(other.model_rules().iter()) {
            if !a.is_equivalent(b.as_ref()) {
                return false;
            }
        }
        if self.num_group() != other.num_group() {
            return false;
        }
        if self.spacebase() != other.spacebase() {
            return false;
        }
        if self.this_before_ret() != other.this_before_ret() {
            return false;
        }
        if self.auto_killed_by_call() != other.auto_killed_by_call() {
            return false;
        }
        true
    }

    /// Extract all entries that have the given storage class and are single registers.
    ///
    /// Port of `ParamListStandard.extractTiles`.
    fn extract_tiles(&self, res_type: StorageClass) -> Vec<&dyn ParamEntry> {
        self.entries()
            .iter()
            .filter(|e| e.is_exclusion() && e.get_all_groups().len() == 1 && e.get_type() == res_type)
            .map(|e| e.as_ref())
            .collect()
    }

    /// If there is an entry corresponding to the stack resource in this list, return it.
    ///
    /// Port of `ParamListStandard.extractStack`.
    fn extract_stack(&self) -> Option<&dyn ParamEntry> {
        self.entries()
            .iter()
            .rev()
            .find(|e| !e.is_exclusion() && e.get_space().space_type() == AddressSpaceType::Stack)
            .map(|e| e.as_ref())
    }

    /// Port of `ParamListStandard.encode`, overriding [`ParamList::encode`].
    fn encode_std(&self, encoder: &mut dyn Encoder, is_input: bool) -> std::io::Result<()> {
        encoder.open_element(if is_input { ELEM_INPUT } else { ELEM_OUTPUT })?;
        if self.this_before_ret() {
            encoder.write_bool(ATTRIB_THISBEFORERETPOINTER, true)?;
        }
        encoder.write_bool(ATTRIB_KILLEDBYCALL, self.auto_killed_by_call())?;
        if is_input && !self.split_metatype() {
            encoder.write_bool(ATTRIB_SEPARATEFLOAT, false)?;
        }
        let mut curgroup: i32 = -1;
        for el in self.entries() {
            if curgroup >= 0 && (!el.is_grouped() || el.get_group() != curgroup) {
                encoder.close_element(ELEM_GROUP)?;
                curgroup = -1;
            }
            if el.is_grouped() && curgroup < 0 {
                encoder.open_element(ELEM_GROUP)?;
                curgroup = el.get_group();
            }
            el.encode(encoder)?;
        }
        if curgroup >= 0 {
            encoder.close_element(ELEM_GROUP)?;
        }
        for rule in self.model_rules() {
            rule.encode(encoder)?;
        }
        encoder.close_element(if is_input { ELEM_INPUT } else { ELEM_OUTPUT })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpace;
    use crate::program::model::lang::compiler_spec::CompilerSpec;
    use crate::program::model::lang::language::Language;
    use crate::program::model::listing::program::Program;
    use crate::program::seam_stubs::VariableStorage;
    use crate::util::xml::xml_parse_exception::XmlParseException;
    use crate::util::xml::xml_pull_parser::XmlPullParser;

    #[derive(Clone)]
    struct MockEntry {
        space: Arc<AddressSpace>,
        group: i32,
        min_size: i32,
        size: i32,
        align: i32,
        ty: StorageClass,
        exclusion: bool,
        grouped: bool,
        capacity: i32,
    }

    impl ParamEntry for MockEntry {
        fn get_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }
        fn get_group(&self) -> i32 {
            self.group
        }
        fn get_min_size(&self) -> i32 {
            self.min_size
        }
        fn get_size(&self) -> i32 {
            self.size
        }
        fn get_align(&self) -> i32 {
            self.align
        }
        fn get_address_base(&self) -> i64 {
            0
        }
        fn get_type(&self) -> StorageClass {
            self.ty
        }
        fn is_exclusion(&self) -> bool {
            self.exclusion
        }
        fn is_grouped(&self) -> bool {
            self.grouped
        }
        fn justified_contain(&self, loc: &Address, size: i32) -> i32 {
            if loc.space() == &self.space && size <= self.size {
                0
            } else {
                -1
            }
        }
        fn get_slot(&self, _loc: &Address, _skip: i32) -> i32 {
            self.group
        }
        fn get_addr_by_slot(
            &self,
            slot_num: i32,
            _size: i32,
            _align: i32,
            param: &mut ParameterPieces,
        ) -> i32 {
            if slot_num >= self.capacity {
                param.address = None;
                return slot_num;
            }
            let offset = (self.group * 100 + slot_num) as i64 * 8;
            param.address = Some(Address::new(self.space.clone(), offset));
            slot_num + 1
        }
        fn is_equivalent(&self, other: &dyn ParamEntry) -> bool {
            self.get_group() == other.get_group() && self.get_type() == other.get_type()
        }
    }

    struct MockModelRule;
    impl ModelRuleLike for MockModelRule {}

    struct MockDataType {
        length: i32,
        is_ptr: bool,
    }
    impl DataType for MockDataType {
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_pointer(&self) -> bool {
            self.is_ptr
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    fn register_space() -> Arc<AddressSpace> {
        AddressSpace::new(
            "register",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Register,
            0,
        )
    }

    fn stack_space() -> Arc<AddressSpace> {
        AddressSpace::new(
            "stack",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Stack,
            0,
        )
    }

    struct MockParamListStandard {
        entries: Vec<Box<dyn ParamEntry>>,
        model_rules: Vec<Box<dyn ModelRuleLike>>,
    }

    impl ParamListStandard for MockParamListStandard {
        fn entries(&self) -> &[Box<dyn ParamEntry>] {
            &self.entries
        }
        fn model_rules(&self) -> &[Box<dyn ModelRuleLike>] {
            &self.model_rules
        }
        fn num_group(&self) -> i32 {
            2
        }
        fn spacebase(&self) -> Option<Arc<AddressSpace>> {
            Some(stack_space())
        }
        fn this_before_ret(&self) -> bool {
            false
        }
        fn auto_killed_by_call(&self) -> bool {
            true
        }
        fn split_metatype(&self) -> bool {
            true
        }
    }

    impl ParamList for MockParamListStandard {
        fn assign_map(
            &self,
            proto: &PrototypePieces,
            dt_manage: &dyn DataTypeManager,
            res: &mut Vec<ParameterPieces>,
            add_auto_params: bool,
        ) {
            self.assign_map_std(proto, dt_manage, res, add_auto_params);
        }

        fn encode(&self, encoder: &mut dyn Encoder, is_input: bool) -> std::io::Result<()> {
            self.encode_std(encoder, is_input)
        }

        fn restore_xml<P: XmlPullParser>(
            &mut self,
            _parser: &mut P,
            _cspec: &dyn CompilerSpec,
        ) -> Result<(), XmlParseException>
        where
            Self: Sized,
        {
            unimplemented!("XML restore needs a ported ModelRule constructor and AddressXML")
        }

        fn get_potential_register_storage(&self, _prog: &dyn Program) -> Vec<Box<dyn VariableStorage>> {
            Vec::new()
        }

        fn get_stack_parameter_alignment(&self) -> i32 {
            self.get_stack_parameter_alignment_std()
        }

        fn get_stack_parameter_offset(&self) -> Option<i64> {
            self.get_stack_parameter_offset_std()
        }

        fn possible_param_with_slot(&self, loc: &Address, size: i32, res: &mut WithSlotRec) -> bool {
            self.possible_param_with_slot_std(loc, size, res)
        }

        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!()
        }

        fn get_spacebase(&self) -> Option<Arc<AddressSpace>> {
            self.spacebase()
        }

        fn is_this_before_ret_pointer(&self) -> bool {
            self.this_before_ret()
        }

        fn is_equivalent(&self, other: &dyn ParamList) -> bool {
            let _ = other;
            false
        }
    }

    fn two_register_list() -> MockParamListStandard {
        let reg = register_space();
        MockParamListStandard {
            entries: vec![
                Box::new(MockEntry {
                    space: reg.clone(),
                    group: 0,
                    min_size: 1,
                    size: 4,
                    align: 4,
                    ty: StorageClass::General,
                    exclusion: true,
                    grouped: false,
                    capacity: 1,
                }),
                Box::new(MockEntry {
                    space: reg.clone(),
                    group: 1,
                    min_size: 1,
                    size: 4,
                    align: 4,
                    ty: StorageClass::General,
                    exclusion: true,
                    grouped: false,
                    capacity: 1,
                }),
            ],
            model_rules: Vec::new(),
        }
    }

    #[test]
    fn assign_address_fallback_finds_free_slot_and_marks_it_consumed() {
        let list = two_register_list();
        let mut status = vec![0i32; 2];
        let mut param = ParameterPieces::default();
        let dt: Arc<dyn DataType> = Arc::new(MockDataType {
            length: 4,
            is_ptr: false,
        });

        let code =
            list.assign_address_fallback(StorageClass::General, &dt, false, &mut status, &mut param);

        assert_eq!(code, assign_action::SUCCESS);
        assert!(param.address.is_some());
        assert_eq!(status[0], -1); // exclusion entry marks its group fully consumed

        // Second call finds the next entry since group 0 is now marked consumed.
        let mut param2 = ParameterPieces::default();
        let code2 =
            list.assign_address_fallback(StorageClass::General, &dt, false, &mut status, &mut param2);
        assert_eq!(code2, assign_action::SUCCESS);
        assert_eq!(status[1], -1);

        // Third call fails: both groups are consumed.
        let mut param3 = ParameterPieces::default();
        let code3 =
            list.assign_address_fallback(StorageClass::General, &dt, false, &mut status, &mut param3);
        assert_eq!(code3, assign_action::FAIL);
        assert!(param3.address.is_none());
    }

    #[test]
    fn assign_address_classifies_pointer_and_falls_back_when_rules_fail() {
        let list = two_register_list();
        let mut status = vec![0i32; 2];
        let mut param = ParameterPieces::default();
        let dt: Arc<dyn DataType> = Arc::new(MockDataType {
            length: 4,
            is_ptr: true,
        });

        let code = list.assign_address(&dt, &PrototypePieces::default(), 0, &MockDataTypeManager, &mut status, &mut param);

        assert_eq!(code, assign_action::SUCCESS);
        assert!(param.address.is_some());
    }

    #[test]
    fn assign_map_std_assigns_each_input_type_in_order() {
        let list = two_register_list();
        let a: Arc<dyn DataType> = Arc::new(MockDataType {
            length: 4,
            is_ptr: false,
        });
        let b: Arc<dyn DataType> = Arc::new(MockDataType {
            length: 4,
            is_ptr: false,
        });
        let proto = PrototypePieces {
            outtype: None,
            intypes: vec![a, b],
        };
        let mut res = Vec::new();

        list.assign_map_std(&proto, &MockDataTypeManager, &mut res, false);

        assert_eq!(res.len(), 2);
        assert!(res[0].address.is_some());
        assert!(res[1].address.is_some());
        // Each parameter lands in a different group's register.
        assert_ne!(res[0].address.as_ref().unwrap().offset(), res[1].address.as_ref().unwrap().offset());
    }

    #[test]
    fn assign_map_std_stops_and_fills_unassigned_after_first_failure() {
        let list = two_register_list();
        let big: Arc<dyn DataType> = Arc::new(MockDataType {
            length: 4,
            is_ptr: false,
        });
        // Three inputs but only two registers: the third should fail and the loop should not
        // just silently drop it -- it gets appended as an unassigned placeholder.
        let proto = PrototypePieces {
            outtype: None,
            intypes: vec![big.clone(), big.clone(), big],
        };
        let mut res = Vec::new();

        list.assign_map_std(&proto, &MockDataTypeManager, &mut res, false);

        assert_eq!(res.len(), 3);
        assert!(res[0].address.is_some());
        assert!(res[1].address.is_some());
        assert!(res[2].address.is_none());
    }

    #[test]
    fn get_num_param_entry_get_entry_and_is_big_endian() {
        let list = two_register_list();
        assert_eq!(list.get_num_param_entry(), 2);
        assert_eq!(list.get_entry(0).get_group(), 0);
        assert!(!list.is_big_endian());
    }

    #[test]
    fn extract_tiles_and_extract_stack() {
        let reg = register_space();
        let stack = stack_space();
        let list = MockParamListStandard {
            entries: vec![
                Box::new(MockEntry {
                    space: reg.clone(),
                    group: 0,
                    min_size: 1,
                    size: 4,
                    align: 4,
                    ty: StorageClass::General,
                    exclusion: true,
                    grouped: false,
                    capacity: 1,
                }),
                Box::new(MockEntry {
                    space: stack.clone(),
                    group: 1,
                    min_size: 1,
                    size: 4,
                    align: 4,
                    ty: StorageClass::General,
                    exclusion: false,
                    grouped: false,
                    capacity: 100,
                }),
            ],
            model_rules: Vec::new(),
        };

        let tiles = list.extract_tiles(StorageClass::General);
        assert_eq!(tiles.len(), 1);
        assert_eq!(tiles[0].get_group(), 0);

        let stack_entry = list.extract_stack();
        assert!(stack_entry.is_some());
        assert_eq!(stack_entry.unwrap().get_group(), 1);
    }

    #[test]
    fn get_stack_parameter_alignment_and_offset() {
        let stack = stack_space();
        let list = MockParamListStandard {
            entries: vec![Box::new(MockEntry {
                space: stack.clone(),
                group: 0,
                min_size: 1,
                size: 4,
                align: 8,
                ty: StorageClass::General,
                exclusion: false,
                grouped: false,
                capacity: 100,
            })],
            model_rules: Vec::new(),
        };

        assert_eq!(list.get_stack_parameter_alignment_std(), 8);
        assert_eq!(list.get_stack_parameter_offset_std(), Some(0));
    }

    #[test]
    fn possible_param_with_slot_reports_slot_and_size() {
        let list = two_register_list();
        let reg = register_space();
        let loc = Address::new(reg, 0);
        let mut slot_rec = WithSlotRec::default();

        assert!(list.possible_param_with_slot_std(&loc, 4, &mut slot_rec));
        assert_eq!(slot_rec.slotsize, 1); // exclusion entry -> one group

        let other_space = AddressSpace::new(
            "otherspace",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        );
        let miss_loc = Address::new(other_space, 0);
        assert!(!list.possible_param_with_slot_std(&miss_loc, 4, &mut slot_rec));
    }

    #[test]
    fn is_equivalent_std_compares_entries_and_flags() {
        let a = two_register_list();
        let b = two_register_list();
        assert!(a.is_equivalent_std(&b));

        let mut c = two_register_list();
        c.entries.pop();
        assert!(!a.is_equivalent_std(&c));
    }

    #[test]
    fn get_basic_type_class_classifies_pointers_and_general() {
        let ptr: Arc<dyn DataType> = Arc::new(MockDataType {
            length: 4,
            is_ptr: true,
        });
        let general: Arc<dyn DataType> = Arc::new(MockDataType {
            length: 4,
            is_ptr: false,
        });
        assert_eq!(get_basic_type_class(ptr.as_ref()), StorageClass::Ptr);
        assert_eq!(get_basic_type_class(general.as_ref()), StorageClass::General);
    }

    #[test]
    fn usable_as_trait_object() {
        let list: Box<dyn ParamListStandard> = Box::new(two_register_list());
        assert_eq!(list.get_num_param_entry(), 2);
        assert_eq!(list.num_group(), 2);
        assert!(list.auto_killed_by_call());
    }

    #[test]
    fn usable_as_param_list_trait_object_via_delegation() {
        let list: Box<dyn ParamList> = Box::new(two_register_list());
        assert_eq!(list.get_stack_parameter_offset(), None); // no stack entries in this fixture
        assert!(!list.is_this_before_ret_pointer());
    }
}
