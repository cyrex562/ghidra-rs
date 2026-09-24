//! Port of `ghidra.program.model.lang.ParamListStandard`.

use std::sync::Arc;

use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::param_entry::{order_within_group, ParamEntry};
use crate::program::model::lang::param_list::WithSlotRec;
use crate::program::model::lang::program_architecture::ProgramArchitecture;
use crate::program::model::lang::protorules::assign_action;
use crate::program::model::lang::protorules::convert_to_pointer::ConvertToPointer;
use crate::program::model::lang::protorules::model_rule::ModelRule;
use crate::program::model::lang::protorules::size_restricted_filter::SizeRestrictedFilter;
use crate::program::model::lang::storage_class::StorageClass;
use crate::program::model::listing::variable_storage::{VariableStorage, VariableStorageImpl};
use crate::program::model::pcode::{
    Encoder, ATTRIB_KILLEDBYCALL, ATTRIB_POINTERMAX, ATTRIB_SEPARATEFLOAT,
    ATTRIB_THISBEFORERETPOINTER, ELEM_GROUP, ELEM_INPUT, ELEM_OUTPUT, ELEM_PENTRY, ELEM_RULE,
};
use crate::program::seam_stubs::{ParameterPieces, PrototypePieces};
use crate::util::xml::spec_xml_utils::{decode_boolean, decode_int};
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Classify a data-type for the purpose of picking a storage resource.
///
/// Port of the static helper `ghidra.program.model.lang.ParamEntry.getBasicTypeClass`.
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

/// Standard analysis for parameter lists: a resource list of [`ParamEntry`]s describing where
/// parameters (or a return value) can be stored, plus [`ModelRule`]s controlling how a storage
/// location is chosen for a given data-type.
///
/// The subclasses `ParamListStandardOut` and `ParamListRegisterOut` override only `assignMap`;
/// they are ported as structs embedding this one (see
/// [`ParamListStandardOut`](super::param_list_standard_out::ParamListStandardOut)), and the
/// `ParamList` interface over all three is the [`ParamList`](super::param_list::ParamList) enum.
///
/// # Rules and their resource list
/// Java's `AssignAction`s hold a back-reference to the `ParamListStandard` they allocate from.
/// Here that reference is a call-time argument instead: [`ModelRule::assign_address`] and every
/// `AssignAction` receive `&ParamListStandard` when they run, so the list can own its rules
/// without a reference cycle (the crate's recorded convention for back-references).
///
/// Port of `ghidra.program.model.lang.ParamListStandard`.
#[derive(Default)]
pub struct ParamListStandard {
    /// The language associated with this convention (`ParamListStandard.language`).
    language: Option<Arc<dyn Language>>,
    /// Number of "groups" in this parameter convention (`ParamListStandard.numgroup`).
    numgroup: i32,
    /// Do hidden return pointers usurp the storage of the this pointer
    /// (`ParamListStandard.thisbeforeret`).
    thisbeforeret: bool,
    /// Is storage in this list automatically "killed by call"
    /// (`ParamListStandard.autoKilledByCall`).
    auto_killed_by_call: bool,
    /// Are metatyped entries in separate resource sections (`ParamListStandard.splitMetatype`).
    split_metatype: bool,
    /// The resource list, in order (`ParamListStandard.entry`).
    entry: Vec<Arc<ParamEntry>>,
    /// Rules to apply when assigning addresses (`ParamListStandard.modelRules`).
    model_rules: Vec<ModelRule>,
    /// Space containing relative offset parameters (`ParamListStandard.spacebase`).
    spacebase: Option<Arc<AddressSpace>>,
    /// True when this list is the base of a `ParamListStandardOut` (or `ParamListRegisterOut`).
    /// Stands in for Java's `res instanceof ParamListStandardOut`, which `MultiSlotAssign` tests
    /// on the resource list it is built against.
    standard_out: bool,
}

impl ParamListStandard {
    /// An empty, unconfigured list, ready for [`restore_xml`](Self::restore_xml).
    ///
    /// Port of the implicit no-arg constructor.
    pub fn new() -> Self {
        ParamListStandard { split_metatype: true, ..Default::default() }
    }

    /// Build a list from already-constructed components, for code that synthesizes a calling
    /// convention rather than reading one from a compiler specification. Rules that need the list
    /// itself to be built (as `restoreXml` builds them after the entries) can be added afterwards
    /// with [`add_model_rule`](Self::add_model_rule).
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        entry: Vec<Arc<ParamEntry>>,
        numgroup: i32,
        spacebase: Option<Arc<AddressSpace>>,
        thisbeforeret: bool,
        auto_killed_by_call: bool,
        split_metatype: bool,
        language: Option<Arc<dyn Language>>,
    ) -> Self {
        ParamListStandard {
            language,
            numgroup,
            thisbeforeret,
            auto_killed_by_call,
            split_metatype,
            entry,
            model_rules: Vec::new(),
            spacebase,
            standard_out: false,
        }
    }

    /// Append a rule to this list's rule set (applied after all existing rules).
    pub fn add_model_rule(&mut self, rule: ModelRule) {
        self.model_rules.push(rule);
    }

    /// Mark this list as the base of an output list; see the `standard_out` field.
    pub(crate) fn set_standard_out(&mut self, standard_out: bool) {
        self.standard_out = standard_out;
    }

    /// True if this list is the base of a `ParamListStandardOut`/`ParamListRegisterOut`: the
    /// stand-in for Java's `instanceof ParamListStandardOut`.
    pub fn is_standard_out(&self) -> bool {
        self.standard_out
    }

    /// The resource list, in order.
    pub fn entries(&self) -> &[Arc<ParamEntry>] {
        &self.entry
    }

    /// The rules applied, in order, when assigning addresses.
    pub fn model_rules(&self) -> &[ModelRule] {
        &self.model_rules
    }

    /// Number of resource groups in this convention (`ParamListStandard.numgroup`).
    pub fn num_group(&self) -> i32 {
        self.numgroup
    }

    /// True if storage in this list is automatically "killed by call".
    pub fn auto_killed_by_call(&self) -> bool {
        self.auto_killed_by_call
    }

    /// True if metatyped entries are in separate resource sections.
    pub fn split_metatype(&self) -> bool {
        self.split_metatype
    }

    /// Find the (first) entry containing the given memory range.
    ///
    /// Port of the private `ParamListStandard.findEntry`.
    fn find_entry(&self, loc: &Address, size: i32) -> Option<usize> {
        self.entry
            .iter()
            .position(|e| e.get_min_size() <= size && e.justified_contain(loc, size) == 0)
    }

    /// Assign storage for the given parameter class, using the fallback assignment algorithm:
    /// the first entry of the right class with room left.
    ///
    /// Port of `ParamListStandard.assignAddressFallback`.
    pub fn assign_address_fallback(
        &self,
        resource: StorageClass,
        tp: &Arc<dyn DataType>,
        match_exact: bool,
        status: &mut [i32],
        param: &mut ParameterPieces,
    ) -> i32 {
        for element in &self.entry {
            let grp = element.get_group() as usize;
            if status[grp] < 0 {
                continue;
            }
            if resource != element.get_type()
                && (match_exact || element.get_type() != StorageClass::General)
            {
                continue;
            }
            status[grp] =
                element.get_addr_by_slot(status[grp], tp.get_aligned_length(), tp.get_alignment(), param);
            if param.address.is_none() {
                continue; // -tp- does not fit in this entry
            }
            if element.is_exclusion() {
                for &group in element.get_all_groups() {
                    // For an exclusion entry some number of groups are taken up
                    status[group as usize] = -1;
                }
            }
            param.data_type = Some(tp.clone());
            return assign_action::SUCCESS;
        }
        param.address = None;
        assign_action::FAIL
    }

    /// Fill in the address and other details for the given parameter: apply the first model rule
    /// that does not fail, else fall back to [`assign_address_fallback`](Self::assign_address_fallback).
    /// Returns an `AssignAction` response code.
    ///
    /// Port of `ParamListStandard.assignAddress`.
    pub fn assign_address(
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
        for model_rule in &self.model_rules {
            let response_code = model_rule.assign_address(self, dt, proto, pos, dt_manager, status, res);
            if response_code != assign_action::FAIL {
                return response_code;
            }
        }
        let store = get_basic_type_class(dt.as_ref());
        self.assign_address_fallback(store, dt, false, status, res)
    }

    /// The number of entries in this list.
    ///
    /// Port of `ParamListStandard.getNumParamEntry`.
    pub fn get_num_param_entry(&self) -> i32 {
        self.entry.len() as i32
    }

    /// The entry at `index`, or `None` if out of range (Java throws
    /// `ArrayIndexOutOfBoundsException`).
    ///
    /// Port of `ParamListStandard.getEntry`.
    pub fn get_entry(&self, index: i32) -> Option<&Arc<ParamEntry>> {
        usize::try_from(index).ok().and_then(|i| self.entry.get(i))
    }

    /// True if resources in this list are from a big endian address space. An empty list (where
    /// Java would throw) reports little endian.
    ///
    /// Port of `ParamListStandard.isBigEndian`.
    pub fn is_big_endian(&self) -> bool {
        self.entry.first().is_some_and(|e| e.is_big_endian())
    }

    /// Given the data-types of a prototype, compute the storage for each input parameter and
    /// append it to `res`. If `add_auto_params` and `res` already holds a hidden return pointer
    /// placeholder (from the output list), that is assigned first.
    ///
    /// Port of `ParamListStandard.assignMap`.
    pub fn assign_map(
        &self,
        proto: &PrototypePieces,
        dt_manager: &dyn DataTypeManager,
        res: &mut Vec<ParameterPieces>,
        add_auto_params: bool,
    ) {
        let mut status = vec![0i32; self.numgroup.max(0) as usize];

        if add_auto_params && res.len() == 2 {
            // Check for hidden parameters defined by the output list
            let last_idx = res.len() - 1;
            let last_type = res[last_idx].data_type.clone();
            if let Some(dt) = last_type {
                if res[last_idx].hidden_return_ptr {
                    // Need to pull from registers marked as hiddenret
                    self.assign_address_fallback(StorageClass::HiddenRet, &dt, false, &mut status, &mut res[last_idx]);
                } else {
                    // Assign as a regular first input pointer parameter
                    self.assign_address(&dt, proto, 0, dt_manager, &mut status, &mut res[last_idx]);
                }
            }
            res[last_idx].hidden_return_ptr = true;
        }
        for i in 0..proto.intypes.len() {
            res.push(ParameterPieces::default());
            let idx = res.len() - 1;
            let res_code = self.assign_address(&proto.intypes[i], proto, i as i32, dt_manager, &mut status, &mut res[idx]);
            if res_code == assign_action::FAIL || res_code == assign_action::NO_ASSIGNMENT {
                // Do not continue to assign after first failure; fill out with UNASSIGNED pieces
                for _ in (i + 1)..proto.intypes.len() {
                    res.push(ParameterPieces::default());
                }
                return;
            }
        }
    }

    /// All parameter storage locations consisting of a single register.
    ///
    /// Port of `ParamListStandard.getPotentialRegisterStorage(Program)`. Takes the program as the
    /// [`ProgramArchitecture`] it is in Java (`Program extends ProgramArchitecture`), which is
    /// what `VariableStorage`'s constructor needs.
    pub fn get_potential_register_storage(
        &self,
        prog: Arc<dyn ProgramArchitecture>,
    ) -> Vec<Box<dyn VariableStorage>> {
        let mut res: Vec<Box<dyn VariableStorage>> = Vec::new();
        for pe in &self.entry {
            if !pe.is_exclusion() {
                continue;
            }
            if pe.get_space().space_type() == AddressSpaceType::Register {
                let addr = pe.get_space().address(pe.get_address_base());
                // Skip this particular storage location if it is invalid (Java's
                // `catch (InvalidInputException)`)
                if let Ok(var) = VariableStorageImpl::from_address(prog.clone(), addr, pe.get_size()) {
                    res.push(Box::new(var));
                }
            }
        }
        res
    }

    /// Encode this list as an `<input>` or `<output>` element.
    ///
    /// Port of `ParamListStandard.encode`.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    pub fn encode(&self, encoder: &mut dyn Encoder, is_input: bool) -> std::io::Result<()> {
        encoder.open_element(if is_input { ELEM_INPUT } else { ELEM_OUTPUT })?;
        if self.thisbeforeret {
            encoder.write_bool(ATTRIB_THISBEFORERETPOINTER, true)?;
        }
        encoder.write_bool(ATTRIB_KILLEDBYCALL, self.auto_killed_by_call)?;
        if is_input && !self.split_metatype {
            encoder.write_bool(ATTRIB_SEPARATEFLOAT, false)?;
        }
        let mut curgroup: i32 = -1;
        for el in &self.entry {
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
        for model_rule in &self.model_rules {
            model_rule.encode(encoder)?;
        }
        encoder.close_element(if is_input { ELEM_INPUT } else { ELEM_OUTPUT })?;
        Ok(())
    }

    /// Parse a `<pentry>` tag and append the entry to `pe`.
    ///
    /// Port of the private `ParamListStandard.parsePentry`.
    fn parse_pentry<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        cspec: &dyn CompilerSpec,
        pe: &mut Vec<Arc<ParamEntry>>,
        groupid: i32,
        split_float: bool,
        grouped: bool,
    ) -> Result<(), XmlParseException> {
        let mut last_class = StorageClass::Class4;
        if let Some(last_entry) = pe.last() {
            last_class = if last_entry.is_grouped() { StorageClass::General } else { last_entry.get_type() };
        }
        let pentry = ParamEntry::restore_xml(parser, cspec, pe, grouped, groupid)?;
        if split_float {
            let current_class = if grouped { StorageClass::General } else { pentry.get_type() };
            if last_class != current_class && last_class.value() < current_class.value() {
                return Err(XmlParseException::new("parameter list entries must be ordered by storage class"));
            }
        }
        if pentry.get_space().space_type() == AddressSpaceType::Stack {
            self.spacebase = Some(pentry.get_space());
        }
        let group_set = pentry.get_all_groups();
        let maxgroup = group_set[group_set.len() - 1] + 1;
        if maxgroup > self.numgroup {
            self.numgroup = maxgroup;
        }
        pe.push(Arc::new(pentry));
        Ok(())
    }

    /// Parse a sequence of `<pentry>`s that are allocated as a group (all from the same group).
    ///
    /// Port of the private `ParamListStandard.parseGroup`.
    fn parse_group<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        cspec: &dyn CompilerSpec,
        pe: &mut Vec<Arc<ParamEntry>>,
        split_float: bool,
    ) -> Result<(), XmlParseException> {
        let el = parser.start(&[ELEM_GROUP.name])?;
        let basegroup = self.numgroup;
        let mut count = 0usize;
        while parser.peek().is_start() {
            self.parse_pentry(parser, cspec, pe, basegroup, split_float, true)?;
            count += 1;
            let last_entry = pe.last().expect("parse_pentry just pushed an entry");
            if last_entry.get_space().space_type() == AddressSpaceType::Join {
                return Err(XmlParseException::new("<pentry> in the join space not allowed in <group> tag"));
            }
        }
        // Check that all entries in the group are distinguishable
        for i in 1..count {
            let cur_entry = &pe[pe.len() - 1 - i];
            for j in 0..i {
                order_within_group(cur_entry, &pe[pe.len() - 1 - j])?;
            }
        }
        parser.end_matching(&el)?;
        Ok(())
    }

    /// Restore this list from an `<input>` or `<output>` element.
    ///
    /// Port of `ParamListStandard.restoreXml`.
    ///
    /// # Errors
    /// Returns an error for badly formed or inconsistent XML.
    pub(crate) fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        cspec: &dyn CompilerSpec,
    ) -> Result<(), XmlParseException> {
        let mut pe: Vec<Arc<ParamEntry>> = Vec::new();
        self.numgroup = 0;
        self.language = Some(Arc::from(cspec.get_language()));
        self.spacebase = None;
        let mut pointermax = 0;
        self.thisbeforeret = false;
        self.auto_killed_by_call = false;
        self.split_metatype = true;
        self.entry.clear();
        self.model_rules.clear();
        let mainel = parser.start(&[])?;
        if let Some(attribute) = mainel.get_attribute(ATTRIB_POINTERMAX.name) {
            pointermax = decode_int(Some(&attribute));
        }
        if let Some(attribute) = mainel.get_attribute(ATTRIB_THISBEFORERETPOINTER.name) {
            self.thisbeforeret = decode_boolean(&attribute);
        }
        if let Some(attribute) = mainel.get_attribute(ATTRIB_KILLEDBYCALL.name) {
            self.auto_killed_by_call = decode_boolean(&attribute);
        }
        if let Some(attribute) = mainel.get_attribute(ATTRIB_SEPARATEFLOAT.name) {
            self.split_metatype = decode_boolean(&attribute);
        }
        let split_metatype = self.split_metatype;
        loop {
            let el = parser.peek();
            if !el.is_start() {
                break;
            }
            let name = el.get_name();
            if name == ELEM_PENTRY.name {
                let groupid = self.numgroup;
                self.parse_pentry(parser, cspec, &mut pe, groupid, split_metatype, false)?;
            } else if name == ELEM_GROUP.name {
                self.parse_group(parser, cspec, &mut pe, split_metatype)?;
            } else if name == ELEM_RULE.name {
                break;
            } else {
                // Java loops forever on an unrecognized child here (the element is never
                // consumed); reject it instead.
                return Err(XmlParseException::new(format!("Unexpected element in parameter list: {name}")));
            }
        }
        self.entry = pe;
        let mut rules = Vec::new();
        loop {
            let sub_id = parser.peek();
            if !sub_id.is_start() {
                break;
            }
            if sub_id.get_name() == ELEM_RULE.name {
                let mut rule = ModelRule::new();
                rule.restore_xml(parser, self)?;
                rules.push(rule);
            } else {
                return Err(XmlParseException::new(
                    "<pentry> and <group> elements must come before any <modelrule>",
                ));
            }
        }
        parser.end_matching(&mainel)?;
        if pointermax > 0 {
            // Add a ModelRule at the end that converts too big data-types to pointers
            let type_filter = SizeRestrictedFilter::with_min_max(pointermax + 1, 0);
            let action = ConvertToPointer::new(self);
            let rule = ModelRule::from_components(&type_filter, &action, self)
                .map_err(|e| XmlParseException::new(e.to_string()))?;
            rules.push(rule);
        }
        self.model_rules = rules;
        Ok(())
    }

    /// The byte alignment of parameters passed on the stack, or -1 if there are none.
    ///
    /// Port of `ParamListStandard.getStackParameterAlignment`.
    pub fn get_stack_parameter_alignment(&self) -> i32 {
        for pentry in &self.entry {
            if pentry.get_space().space_type() == AddressSpaceType::Stack {
                return pentry.get_align();
            }
        }
        -1
    }

    /// The boundary offset separating stack parameters from other local variables, or `None` if
    /// there are no stack parameters.
    ///
    /// Port of `ParamListStandard.getStackParameterOffset`.
    pub fn get_stack_parameter_offset(&self) -> Option<i64> {
        for pentry in &self.entry {
            if pentry.is_exclusion() {
                continue;
            }
            let space = pentry.get_space();
            if space.space_type() != AddressSpaceType::Stack {
                continue;
            }
            let mut res = pentry.get_address_base();
            if pentry.is_reverse_stack() {
                res += pentry.get_size() as i64;
            }
            return Some(space.truncate_offset(res));
        }
        None
    }

    /// Determine if the given memory range is a possible parameter and, if so, which slot(s) it
    /// occupies.
    ///
    /// Port of `ParamListStandard.possibleParamWithSlot`.
    pub fn possible_param_with_slot(&self, loc: &Address, size: i32, res: &mut WithSlotRec) -> bool {
        let Some(num) = self.find_entry(loc, size) else {
            return false;
        };
        let curentry = &self.entry[num];
        res.slot = curentry.get_slot(loc, 0);
        if curentry.is_exclusion() {
            res.slotsize = curentry.get_all_groups().len() as i32;
        } else {
            res.slotsize = ((size - 1) / curentry.get_align()) + 1;
        }
        true
    }

    /// The language associated with this convention.
    ///
    /// Port of `ParamListStandard.getLanguage`.
    pub fn get_language(&self) -> Option<Arc<dyn Language>> {
        self.language.clone()
    }

    /// The address space of stack-based parameters in this list, if any.
    ///
    /// Port of `ParamListStandard.getSpacebase`.
    pub fn get_spacebase(&self) -> Option<Arc<AddressSpace>> {
        self.spacebase.clone()
    }

    /// Determine if this list is configured identically to another. The Java `getClass()`
    /// check is made by the [`ParamList`](super::param_list::ParamList) enum.
    ///
    /// Port of `ParamListStandard.isEquivalent`.
    pub fn is_equivalent(&self, op2: &ParamListStandard) -> bool {
        if self.entry.len() != op2.entry.len() {
            return false;
        }
        if !self.entry.iter().zip(&op2.entry).all(|(a, b)| a.is_equivalent(b)) {
            return false;
        }
        if self.model_rules.len() != op2.model_rules.len() {
            return false;
        }
        if !self.model_rules.iter().zip(&op2.model_rules).all(|(a, b)| a.is_equivalent(b)) {
            return false;
        }
        if self.numgroup != op2.numgroup {
            return false;
        }
        let same_space = match (&self.spacebase, &op2.spacebase) {
            (None, None) => true,
            (Some(a), Some(b)) => a.as_ref() == b.as_ref(),
            _ => false,
        };
        if !same_space {
            return false;
        }
        self.thisbeforeret == op2.thisbeforeret && self.auto_killed_by_call == op2.auto_killed_by_call
    }

    /// True if the `this` pointer is allocated before a hidden return pointer.
    ///
    /// Port of `ParamListStandard.isThisBeforeRetPointer`.
    pub fn is_this_before_ret_pointer(&self) -> bool {
        self.thisbeforeret
    }

    /// All entries of the given storage class that are single, exclusive registers.
    ///
    /// Port of `ParamListStandard.extractTiles`.
    pub fn extract_tiles(&self, res_type: StorageClass) -> Vec<Arc<ParamEntry>> {
        self.entry
            .iter()
            .filter(|e| e.is_exclusion() && e.get_all_groups().len() == 1 && e.get_type() == res_type)
            .cloned()
            .collect()
    }

    /// The stack resource of this list, if any. Note that this scans backward and returns the
    /// last matching entry.
    ///
    /// Port of `ParamListStandard.extractStack`.
    pub fn extract_stack(&self) -> Option<Arc<ParamEntry>> {
        self.entry
            .iter()
            .rev()
            .find(|e| !e.is_exclusion() && e.get_space().space_type() == AddressSpaceType::Stack)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::cspec_test_support::{
        float_type, int_type, parser, register_space, stack_space, TestCompilerSpec,
        TestDataTypeManager, SYSV_INPUT,
    };

    fn sysv_input() -> ParamListStandard {
        let mut list = ParamListStandard::new();
        list.restore_xml(&mut parser(SYSV_INPUT), &TestCompilerSpec::x86_64()).unwrap();
        list
    }

    fn restore(xml: &str) -> Result<ParamListStandard, XmlParseException> {
        let mut list = ParamListStandard::new();
        list.restore_xml(&mut parser(xml), &TestCompilerSpec::x86_64())?;
        Ok(list)
    }

    #[test]
    fn restore_sysv_input_list() {
        let list = sysv_input();
        assert_eq!(list.get_num_param_entry(), 9);
        assert_eq!(list.num_group(), 9);
        assert!(list.split_metatype());
        assert!(!list.auto_killed_by_call());
        assert!(!list.is_this_before_ret_pointer());
        assert_eq!(list.get_spacebase().unwrap().space_type(), AddressSpaceType::Stack);
        assert_eq!(list.get_entry(0).unwrap().get_type(), StorageClass::Float);
        assert_eq!(list.get_entry(2).unwrap().get_address_base(), 0x38); // RDI
        assert_eq!(list.get_entry(8).unwrap().get_group(), 8);
        assert!(list.get_entry(9).is_none());
        assert!(list.model_rules().is_empty());
        assert!(!list.is_big_endian());
        assert!(list.get_language().is_some());
    }

    #[test]
    fn assign_map_sysv_ints_floats_and_stack_overflow() {
        let list = sysv_input();
        let mut intypes = vec![int_type(4), float_type(8), int_type(8)];
        intypes.extend((0..5).map(|_| int_type(8)));
        let proto = PrototypePieces { outtype: None, intypes, ..Default::default() };
        let mut res = Vec::new();
        list.assign_map(&proto, &TestDataTypeManager, &mut res, false);
        let offs: Vec<(AddressSpaceType, i64)> = res
            .iter()
            .map(|p| {
                let a = p.address.as_ref().unwrap();
                (a.space().space_type(), a.offset())
            })
            .collect();
        use AddressSpaceType::{Register as R, Stack as S};
        assert_eq!(
            offs,
            vec![(R, 0x38), (R, 0x1200), (R, 0x30), (R, 0x10), (R, 0x8), (R, 0x80), (R, 0x88), (S, 8)]
        );
    }

    #[test]
    fn assign_address_fallback_consumes_exclusive_groups() {
        let list = sysv_input();
        let mut status = vec![0i32; 9];
        let dt = int_type(8);
        let mut p = ParameterPieces::default();
        assert_eq!(list.assign_address_fallback(StorageClass::General, &dt, false, &mut status, &mut p), assign_action::SUCCESS);
        assert_eq!(status[2], -1);
        // match_exact: a pointer class matches no entry exactly
        let mut p = ParameterPieces::default();
        assert_eq!(list.assign_address_fallback(StorageClass::Ptr, &dt, true, &mut status, &mut p), assign_action::FAIL);
        assert!(p.address.is_none());
    }

    #[test]
    fn stack_parameter_alignment_offset_and_slots() {
        let list = sysv_input();
        assert_eq!(list.get_stack_parameter_alignment(), 8);
        assert_eq!(list.get_stack_parameter_offset(), Some(8));
        let mut rec = WithSlotRec::default();
        assert!(list.possible_param_with_slot(&Address::new(register_space(), 0x30), 8, &mut rec));
        assert_eq!(rec, WithSlotRec { slot: 3, slotsize: 1 });
        assert!(list.possible_param_with_slot(&Address::new(stack_space(), 0x18), 12, &mut rec));
        assert_eq!(rec, WithSlotRec { slot: 8 + 2, slotsize: 2 });
        assert!(!list.possible_param_with_slot(&Address::new(register_space(), 0x0), 8, &mut rec));
    }

    #[test]
    fn extract_tiles_and_stack() {
        let list = sysv_input();
        assert_eq!(list.extract_tiles(StorageClass::General).len(), 6);
        assert_eq!(list.extract_tiles(StorageClass::Float).len(), 2);
        assert_eq!(list.extract_stack().unwrap().get_address_base(), 8);
    }

    #[test]
    fn restore_attributes_group_and_pointermax() {
        let list = restore(
            r#"<input pointermax="8" thisbeforeretpointer="true" killedbycall="true" separatefloat="false">
                 <group>
                   <pentry minsize="1" maxsize="8" metatype="float"><register name="XMM0_Qa"/></pentry>
                   <pentry minsize="1" maxsize="8"><register name="RCX"/></pentry>
                 </group>
                 <pentry minsize="1" maxsize="500" align="8"><addr offset="40" space="stack"/></pentry>
               </input>"#,
        )
        .unwrap();
        assert!(list.is_this_before_ret_pointer());
        assert!(list.auto_killed_by_call());
        assert!(!list.split_metatype());
        assert_eq!(list.num_group(), 2);
        assert!(list.get_entry(0).unwrap().is_grouped());
        assert_eq!(list.get_entry(1).unwrap().get_group(), 0);
        assert_eq!(list.get_entry(2).unwrap().get_group(), 1);
        // pointermax adds a ConvertToPointer rule: a 16-byte struct goes by pointer in RCX.
        assert_eq!(list.model_rules().len(), 1);
        let mut status = vec![0i32; 2];
        let mut p = ParameterPieces::default();
        let code = list.assign_address(&int_type(16), &PrototypePieces::default(), 0, &TestDataTypeManager, &mut status, &mut p);
        assert_eq!(code, assign_action::SUCCESS);
        assert_eq!(p.address.as_ref().unwrap().offset(), 0x8);
        assert!(p.is_indirect);
    }

    #[test]
    fn restore_rejects_misordered_classes_and_group_conflicts() {
        let err = restore(
            r#"<input>
                 <pentry minsize="1" maxsize="8"><register name="RDI"/></pentry>
                 <pentry minsize="4" maxsize="8" metatype="float"><register name="XMM0_Qa"/></pentry>
               </input>"#,
        );
        assert!(err.err().unwrap().message().contains("ordered by storage class"));
        let err = restore(
            r#"<input><group>
                 <pentry minsize="1" maxsize="8"><register name="RDI"/></pentry>
                 <pentry minsize="1" maxsize="8"><register name="RSI"/></pentry>
               </group></input>"#,
        );
        assert!(err.err().unwrap().message().contains("distinguished by size or type"));
    }

    #[test]
    fn is_equivalent_compares_entries_rules_and_flags() {
        assert!(sysv_input().is_equivalent(&sysv_input()));
        let other = restore(r#"<input><pentry minsize="1" maxsize="8"><register name="RDI"/></pentry></input>"#).unwrap();
        assert!(!sysv_input().is_equivalent(&other));
    }

    #[test]
    fn get_basic_type_class_classifies() {
        assert_eq!(get_basic_type_class(float_type(8).as_ref()), StorageClass::Float);
        assert_eq!(get_basic_type_class(int_type(8).as_ref()), StorageClass::General);
    }
}
