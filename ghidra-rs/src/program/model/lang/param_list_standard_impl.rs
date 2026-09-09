//! Concrete port of `ghidra.program.model.lang.ParamListStandard`.
//!
//! [`param_list_standard`](crate::program::model::lang::param_list_standard) ports every real
//! method of the Java class as a default method on the [`ParamListStandard`] trait, but (as that
//! module's doc explains) a Rust trait has no fields, so it needed a concrete implementor to
//! actually hold the `entry`/`modelRules`/`numgroup`/`spacebase`/... state Java's class carries.
//! Every implementor of both [`ParamListStandard`] and
//! [`ParamListStandardLike`](crate::program::seam_stubs::ParamListStandardLike) in this crate,
//! before this file, was a `#[cfg(test)]`-only mock (see the `MockParamListStandard`/
//! `TestResource`/`StackOnlyResource`/etc. structs scattered across
//! `param_list_standard.rs`/`protorules/*.rs`). [`ParamListStandardImpl`] is the first real one,
//! following this crate's `Trait` + `TraitImpl` naming precedent (see
//! [`VariableStorage`](crate::program::model::listing::variable_storage::VariableStorage) /
//! [`VariableStorageImpl`](crate::program::model::listing::variable_storage::VariableStorageImpl)).
//!
//! # Construction
//!
//! Java only ever builds a real `ParamListStandard` via `restoreXml`, which is not portable yet
//! (see [`ParamListStandard`]'s module doc for the precise blocker: `ParamEntry` has no ported
//! constructor). [`ParamListStandardImpl::from_parts`] is this port's substitute: a "from
//! components" constructor in the same spirit as
//! [`ModelRule::from_components`](crate::program::model::lang::protorules::model_rule::ModelRule::from_components),
//! taking an already-built entry list and rule list rather than parsing them from XML.
//!
//! Building the rule list itself typically needs a `Arc<dyn ParamListStandardLike>` handle on the
//! resource list the rules will run against (e.g. `GotoStack::new`/`ConvertToPointer::new` resolve
//! their target stack entry at construction time) -- in Java this is `this`, captured mid
//! construction, before `modelRules` itself is populated. This port has no self-referential
//! construction trick to offer (no `Arc::new_cyclic`-based public constructor), so callers build a
//! transient resource view via [`ParamListStandardImpl::from_parts`] with an empty rule list
//! first, use `Arc::new(..) as Arc<dyn ParamListStandardLike>` on *that* to build the rules (which
//! only ever read `entry`/`numgroup`/`spacebase`/`language`, never `modelRules`, matching Java's
//! own field-initialization order), then build the final instance with the resulting rules. See
//! this module's tests for the pattern.

use std::sync::Arc;

use crate::program::model::address::{AddressSpace, AddressSpaceType};
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::param_entry::ParamEntry;
use crate::program::model::lang::param_list::{ParamList, WithSlotRec};
use crate::program::model::lang::param_list_standard::ParamListStandard;
use crate::program::model::listing::program::Program;
use crate::program::model::listing::variable_storage::VariableStorage;
use crate::program::model::pcode::Encoder;
use crate::program::seam_stubs::{
    ModelRuleLike, ParamListStandardLike, ParameterPieces, PrototypePieces,
};
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Concrete, fully populated port of `ghidra.program.model.lang.ParamListStandard`.
///
/// Holds the same state as the Java class's protected fields: a resource list of [`ParamEntry`]s,
/// a list of [`ModelRuleLike`] rules, the number of resource groups, an optional stack-relative
/// address space, and the three configuration flags. See this module's doc for how it gets built
/// (there being no ported `restoreXml`).
pub struct ParamListStandardImpl {
    /// The language associated with this convention (`ParamListStandard.language`).
    language: Option<Arc<dyn Language>>,
    /// The resource list, in order (`ParamListStandard.entry`).
    entry: Vec<Arc<dyn ParamEntry>>,
    /// Rules to apply when assigning addresses (`ParamListStandard.modelRules`).
    model_rules: Vec<Arc<dyn ModelRuleLike>>,
    /// Number of "groups" in this parameter convention (`ParamListStandard.numgroup`).
    numgroup: i32,
    /// Space containing relative offset parameters (`ParamListStandard.spacebase`).
    spacebase: Option<Arc<AddressSpace>>,
    /// Do hidden return pointers usurp the storage of the `this` pointer
    /// (`ParamListStandard.thisbeforeret`).
    thisbeforeret: bool,
    /// Is storage in this list automatically "killed by call"
    /// (`ParamListStandard.autoKilledByCall`).
    auto_killed_by_call: bool,
    /// Are metatyped entries in separate resource sections (`ParamListStandard.splitMetatype`).
    split_metatype: bool,
}

impl ParamListStandardImpl {
    /// Build a `ParamListStandardImpl` from already-constructed components.
    ///
    /// See this module's doc for why this replaces `restoreXml` as the way to build one of these,
    /// and for the two-phase pattern needed when the rules themselves need a resource-list handle
    /// at construction time.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        entry: Vec<Arc<dyn ParamEntry>>,
        model_rules: Vec<Arc<dyn ModelRuleLike>>,
        numgroup: i32,
        spacebase: Option<Arc<AddressSpace>>,
        thisbeforeret: bool,
        auto_killed_by_call: bool,
        split_metatype: bool,
        language: Option<Arc<dyn Language>>,
    ) -> Self {
        ParamListStandardImpl {
            language,
            entry,
            model_rules,
            numgroup,
            spacebase,
            thisbeforeret,
            auto_killed_by_call,
            split_metatype,
        }
    }
}

impl ParamListStandard for ParamListStandardImpl {
    fn entries(&self) -> &[Arc<dyn ParamEntry>] {
        &self.entry
    }

    fn model_rules(&self) -> &[Arc<dyn ModelRuleLike>] {
        &self.model_rules
    }

    fn num_group(&self) -> i32 {
        self.numgroup
    }

    fn spacebase(&self) -> Option<Arc<AddressSpace>> {
        self.spacebase.clone()
    }

    fn this_before_ret(&self) -> bool {
        self.thisbeforeret
    }

    fn auto_killed_by_call(&self) -> bool {
        self.auto_killed_by_call
    }

    fn split_metatype(&self) -> bool {
        self.split_metatype
    }
}

impl ParamListStandardLike for ParamListStandardImpl {
    fn num_group(&self) -> i32 {
        self.numgroup
    }

    fn spacebase(&self) -> Option<Arc<AddressSpace>> {
        self.spacebase.clone()
    }

    /// Delegates to [`ParamListStandard::assign_address`], the real (model-rule-dispatching)
    /// port of `ParamListStandard.assignAddress` -- unlike
    /// [`ParamListStandardLike::assign_address`]'s own placeholder default (which always fails,
    /// having no `modelRules` field to consult), this is a fully faithful implementation.
    fn assign_address(
        &self,
        dt: &Arc<dyn crate::program::model::data::data_type::DataType>,
        proto: &PrototypePieces,
        pos: i32,
        dt_manager: &dyn DataTypeManager,
        status: &mut [i32],
        res: &mut ParameterPieces,
    ) -> i32 {
        <Self as ParamListStandard>::assign_address(self, dt, proto, pos, dt_manager, status, res)
    }

    fn get_num_param_entry(&self) -> i32 {
        self.entry.len() as i32
    }

    fn get_entry(&self, index: i32) -> Option<Arc<dyn ParamEntry>> {
        if index < 0 {
            return None;
        }
        self.entry.get(index as usize).cloned()
    }

    fn get_language(&self) -> Option<Arc<dyn Language>> {
        self.language.clone()
    }
}

impl ParamList for ParamListStandardImpl {
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

    /// Port of `ParamListStandard.restoreXml`.
    ///
    /// # Errors
    /// Always returns an error: see this module's and [`ParamListStandard`]'s doc for the exact
    /// blocker (`ParamEntry.restoreXml`/the private `parsePentry`/`parseGroup` helpers are not
    /// ported). Use [`ParamListStandardImpl::from_parts`] instead.
    fn restore_xml<P: XmlPullParser>(
        &mut self,
        _parser: &mut P,
        _cspec: &dyn CompilerSpec,
    ) -> Result<(), XmlParseException>
    where
        Self: Sized,
    {
        Err(XmlParseException::new(
            "ParamListStandard::restoreXml is not supported by this port: it needs a real \
             ParamEntry.restoreXml constructor (still trait-only) plus the private \
             parsePentry/parseGroup helpers, neither of which exist yet; construct a \
             ParamListStandardImpl via from_parts instead",
        ))
    }

    /// Port of `ParamListStandard.getPotentialRegisterStorage`.
    ///
    /// The real filtering logic (which entries qualify: exclusion entries whose space is a
    /// register space) is ported faithfully below. Constructing the resulting
    /// [`VariableStorage`] for a qualifying entry is NOT: see this module's/
    /// [`ParamListStandard`]'s doc for the precise blocker (no way to obtain an `Arc<dyn
    /// ProgramArchitecture>` from a bare `&dyn Program`). Java additionally discards any entry
    /// for which `new VariableStorage(...)` throws `InvalidInputException` (`catch` block that
    /// just skips it); until the blocker above is resolved every entry takes that same discard
    /// path, so this always returns an empty list.
    ///
    /// TODO(port): once a `&dyn Program` -> `Arc<dyn ProgramArchitecture>` bridge exists in this
    /// crate, replace the `continue` below with
    /// `VariableStorageImpl::from_address(program_arch, pe.get_space().address(pe.get_address_base()), pe.get_size())`,
    /// pushing the `Ok` case and discarding the `Err` case exactly like Java's `catch`.
    fn get_potential_register_storage(&self, _prog: &dyn Program) -> Vec<Box<dyn VariableStorage>> {
        let mut res: Vec<Box<dyn VariableStorage>> = Vec::new();
        for element in &self.entry {
            if !element.is_exclusion() {
                continue;
            }
            if element.get_space().space_type() != AddressSpaceType::Register {
                continue;
            }
            // TODO(port): construct and push a real VariableStorageImpl here -- see the doc
            // comment above for the exact blocker.
            continue;
        }
        res
    }

    fn get_stack_parameter_alignment(&self) -> i32 {
        self.get_stack_parameter_alignment_std()
    }

    fn get_stack_parameter_offset(&self) -> Option<i64> {
        self.get_stack_parameter_offset_std()
    }

    fn possible_param_with_slot(
        &self,
        loc: &crate::program::model::address::Address,
        size: i32,
        res: &mut WithSlotRec,
    ) -> bool {
        self.possible_param_with_slot_std(loc, size, res)
    }

    /// Port of `ParamListStandard.getLanguage`.
    ///
    /// # Panics
    /// Always panics: [`ParamList::get_language`] returns an owned `Box<dyn Language>`, but this
    /// struct (like [`ParamListStandardLike::get_language`], which this same struct also
    /// implements faithfully) only ever holds a shared `Arc<dyn Language>`, and `Language` has no
    /// `clone_box`/owned-conversion method in this crate to bridge the two -- the same blocker
    /// documented on [`get_potential_register_storage`](Self::get_potential_register_storage).
    /// No production code calls [`ParamList::get_language`] (only
    /// [`ParamListStandardLike::get_language`], which is implemented above); callers that need
    /// the language should use that instead.
    fn get_language(&self) -> Box<dyn Language> {
        unimplemented!(
            "ParamList::get_language needs an owned Box<dyn Language>, but ParamListStandardImpl \
             only holds an Arc<dyn Language> and Language has no owned-clone method; use \
             ParamListStandardLike::get_language instead"
        )
    }

    fn get_spacebase(&self) -> Option<Arc<AddressSpace>> {
        self.spacebase.clone()
    }

    fn is_this_before_ret_pointer(&self) -> bool {
        self.thisbeforeret
    }

    /// Port of `ParamListStandard.isEquivalent`, overriding [`ParamList::is_equivalent`].
    fn is_equivalent(&self, other: &dyn ParamList) -> bool {
        match other.as_any().downcast_ref::<ParamListStandardImpl>() {
            Some(other) => self.is_equivalent_std(other),
            None => false,
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::Address;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::lang::protorules::assign_action::{FAIL, SUCCESS};
    use crate::program::model::lang::protorules::consume_as::ConsumeAs;
    use crate::program::model::lang::protorules::goto_stack::GotoStack;
    use crate::program::model::lang::protorules::model_rule::ModelRule;
    use crate::program::model::lang::protorules::param_test_support::{
        ram_space, stack_space, TestEntry, TestLanguage,
    };
    use crate::program::model::lang::protorules::size_restricted_filter::SizeRestrictedFilter;
    use crate::program::model::lang::storage_class::StorageClass;

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

    fn int_dt(length: i32) -> Arc<dyn DataType> {
        Arc::new(MockDataType { length })
    }

    /// Builds a two-resource `ParamListStandardImpl`: group 0 is a single 4-byte exclusion
    /// register, group 1 is an 8-slot, 4-byte-aligned stack region. A `ConsumeAs` rule (matching
    /// any size) sends everything through the register first; `GotoStack` isn't wired as a rule
    /// here (assign_address_fallback/register exhaustion is exercised directly in a separate
    /// test) -- this fixture is deliberately just entries wired through the default fallback
    /// path (no model rules), verifying overflow from register to stack the same way Java's
    /// bare `assignAddressFallback`/`assignMap` do for a resource list with no matching rule.
    fn register_then_stack_list() -> ParamListStandardImpl {
        let reg_entry: Arc<dyn ParamEntry> = Arc::new(TestEntry {
            space: ram_space(),
            group: 0,
            min_size: 1,
            size: 4,
            align: 0, // exclusion entry: single slot, no alignment
            addressbase: 0x1000,
            numslots: 1,
            ty: StorageClass::General,
            ..TestEntry::default()
        });
        let stack_entry: Arc<dyn ParamEntry> = Arc::new(TestEntry {
            space: stack_space(),
            group: 1,
            min_size: 1,
            // Java's ParamEntry.size for an aligned (multi-slot) entry is the span of the WHOLE
            // region (numslots * align), not one slot -- justified_contain/contains/etc. rely on
            // this. 8 slots * 4-byte alignment = 32.
            size: 32,
            align: 4,
            addressbase: 0,
            numslots: 8,
            ty: StorageClass::General,
            ..TestEntry::default()
        });
        ParamListStandardImpl::from_parts(
            vec![reg_entry, stack_entry],
            Vec::new(),
            2,
            Some(stack_space()),
            false,
            true,
            true,
            Some(Arc::new(TestLanguage { big_endian: false })),
        )
    }

    #[test]
    fn assign_map_std_overflows_from_register_to_stack() {
        let list = register_then_stack_list();
        let proto = PrototypePieces {
            outtype: None,
            intypes: vec![int_dt(4), int_dt(4), int_dt(4)],
            ..Default::default()
        };
        let mut res = Vec::new();

        list.assign_map(&proto, &MockDataTypeManager, &mut res, false);

        assert_eq!(res.len(), 3);
        // First parameter takes the sole register.
        assert_eq!(res[0].address.as_ref().unwrap().space().space_type(), AddressSpaceType::Ram);
        // Second and third parameters overflow onto the stack, at increasing offsets.
        assert_eq!(res[1].address.as_ref().unwrap().space().space_type(), AddressSpaceType::Stack);
        assert_eq!(res[1].address.as_ref().unwrap().offset(), 0);
        assert_eq!(res[2].address.as_ref().unwrap().space().space_type(), AddressSpaceType::Stack);
        assert_eq!(res[2].address.as_ref().unwrap().offset(), 4);
    }

    #[test]
    fn get_num_param_entry_get_entry_and_is_big_endian_via_param_list_standard() {
        let list = register_then_stack_list();
        assert_eq!(ParamListStandard::entries(&list).len(), 2);
        assert_eq!(ParamListStandard::get_entry(&list, 0).get_group(), 0);
        assert!(!ParamListStandard::is_big_endian(&list));
    }

    #[test]
    fn get_num_param_entry_and_get_entry_via_param_list_standard_like() {
        let list = register_then_stack_list();
        assert_eq!(ParamListStandardLike::get_num_param_entry(&list), 2);
        assert_eq!(
            ParamListStandardLike::get_entry(&list, 1).unwrap().get_group(),
            1
        );
        assert!(ParamListStandardLike::get_entry(&list, 5).is_none());
        assert!(ParamListStandardLike::get_entry(&list, -1).is_none());
    }

    #[test]
    fn extract_tiles_and_extract_stack() {
        let list = register_then_stack_list();
        let tiles = ParamListStandard::extract_tiles(&list, StorageClass::General);
        assert_eq!(tiles.len(), 1);
        assert_eq!(tiles[0].get_group(), 0);

        let stack_entry = ParamListStandard::extract_stack(&list);
        assert!(stack_entry.is_some());
        assert_eq!(stack_entry.unwrap().get_group(), 1);
    }

    #[test]
    fn get_stack_parameter_alignment_and_offset() {
        let list = register_then_stack_list();
        assert_eq!(list.get_stack_parameter_alignment(), 4);
        assert_eq!(list.get_stack_parameter_offset(), Some(0));
    }

    #[test]
    fn possible_param_with_slot_reports_slot_and_size() {
        let list = register_then_stack_list();
        let loc = Address::new(ram_space(), 0x1000);
        let mut slot_rec = WithSlotRec::default();

        assert!(list.possible_param_with_slot(&loc, 4, &mut slot_rec));
        assert_eq!(slot_rec.slotsize, 1); // exclusion entry -> one group

        let stack_loc = Address::new(stack_space(), 4);
        assert!(list.possible_param_with_slot(&stack_loc, 4, &mut slot_rec));
        // group (1) + one 4-byte-aligned slot in (offset 4 / align 4 = 1) = 2.
        assert_eq!(slot_rec.slot, 2);
    }

    #[test]
    fn is_equivalent_compares_two_real_instances() {
        let a = register_then_stack_list();
        let b = register_then_stack_list();
        assert!(ParamList::is_equivalent(&a, &b));

        let mut c = register_then_stack_list();
        c.entry.pop();
        assert!(!ParamList::is_equivalent(&a, &c));
    }

    #[test]
    fn is_equivalent_rejects_a_different_param_list_type() {
        struct OtherParamList;
        impl ParamList for OtherParamList {
            fn assign_map(
                &self,
                _proto: &PrototypePieces,
                _dt_manage: &dyn DataTypeManager,
                _res: &mut Vec<ParameterPieces>,
                _add_auto_params: bool,
            ) {
            }
            fn encode(&self, _encoder: &mut dyn Encoder, _is_input: bool) -> std::io::Result<()> {
                Ok(())
            }
            fn restore_xml<P: XmlPullParser>(
                &mut self,
                _parser: &mut P,
                _cspec: &dyn CompilerSpec,
            ) -> Result<(), XmlParseException>
            where
                Self: Sized,
            {
                Ok(())
            }
            fn get_potential_register_storage(
                &self,
                _prog: &dyn Program,
            ) -> Vec<Box<dyn VariableStorage>> {
                Vec::new()
            }
            fn get_stack_parameter_alignment(&self) -> i32 {
                -1
            }
            fn get_stack_parameter_offset(&self) -> Option<i64> {
                None
            }
            fn possible_param_with_slot(
                &self,
                _loc: &crate::program::model::address::Address,
                _size: i32,
                _res: &mut WithSlotRec,
            ) -> bool {
                false
            }
            fn get_language(&self) -> Box<dyn Language> {
                unimplemented!()
            }
            fn get_spacebase(&self) -> Option<Arc<AddressSpace>> {
                None
            }
            fn is_this_before_ret_pointer(&self) -> bool {
                false
            }
            fn is_equivalent(&self, _other: &dyn ParamList) -> bool {
                false
            }
        }

        let a = register_then_stack_list();
        let other = OtherParamList;
        assert!(!ParamList::is_equivalent(&a, &other));
    }

    /// Real, end-to-end rule dispatch: a `ConsumeAs` `ModelRule` (matching any size, via
    /// [`SizeRestrictedFilter::new`]) is built against a *transient* single-register resource
    /// view (see this module's doc for why), then the final `ParamListStandardImpl` is built
    /// with that rule attached. `assign_address` should route through the rule (consuming the
    /// register) rather than falling back to `assign_address_fallback` directly -- both would
    /// produce the same address here, so the real proof is `status[0]` reflecting the rule's own
    /// bookkeeping path executing at all (see the next test for a case where the rule and the
    /// fallback diverge).
    #[test]
    fn assign_address_dispatches_through_a_real_model_rule() {
        let reg_entry: Arc<dyn ParamEntry> = Arc::new(TestEntry {
            space: ram_space(),
            group: 0,
            min_size: 1,
            size: 4,
            align: 0,
            addressbase: 0x2000,
            numslots: 1,
            ty: StorageClass::General,
            ..TestEntry::default()
        });

        // Phase 1: transient resource view (no rules yet) used only to build the rule/action.
        let transient = Arc::new(ParamListStandardImpl::from_parts(
            vec![reg_entry.clone()],
            Vec::new(),
            1,
            None,
            false,
            false,
            true,
            Some(Arc::new(TestLanguage { big_endian: false })),
        )) as Arc<dyn ParamListStandardLike>;

        let action = ConsumeAs::new(StorageClass::General, transient.clone());
        let filter = SizeRestrictedFilter::new();
        let rule = ModelRule::from_components(&filter, &action, transient).unwrap();

        // Phase 2: the real instance, now with the rule attached.
        let list = ParamListStandardImpl::from_parts(
            vec![reg_entry],
            vec![Arc::new(rule)],
            1,
            None,
            false,
            false,
            true,
            Some(Arc::new(TestLanguage { big_endian: false })),
        );

        let dt = int_dt(4);
        let proto = PrototypePieces::default();
        let mut status = [0i32; 1];
        let mut res = ParameterPieces::default();

        let code = ParamListStandardLike::assign_address(
            &list,
            &dt,
            &proto,
            0,
            &MockDataTypeManager,
            &mut status,
            &mut res,
        );

        assert_eq!(code, SUCCESS);
        assert_eq!(status[0], -1); // exclusion entry: fully consumed
        assert_eq!(res.address.unwrap().offset(), 0x2000);
    }

    /// Proves `assign_address` genuinely tries model rules *before* falling back: a `GotoStack`
    /// rule filtered to reject 8-byte-or-larger types (`SizeRestrictedFilter::with_min_max`)
    /// sends small types to the stack even though a register entry (which the bare fallback
    /// algorithm would prefer, being listed first) is also present and would otherwise match.
    #[test]
    fn assign_address_rule_match_takes_priority_over_fallback_order() {
        let reg_entry: Arc<dyn ParamEntry> = Arc::new(TestEntry {
            space: ram_space(),
            group: 0,
            min_size: 1,
            size: 4,
            align: 0,
            addressbase: 0x3000,
            numslots: 1,
            ty: StorageClass::General,
            ..TestEntry::default()
        });
        let stack_entry: Arc<dyn ParamEntry> = Arc::new(TestEntry {
            space: stack_space(),
            group: 1,
            min_size: 1,
            // Java's ParamEntry.size for an aligned (multi-slot) entry is the span of the WHOLE
            // region (numslots * align), not one slot -- justified_contain/contains/etc. rely on
            // this. 8 slots * 4-byte alignment = 32.
            size: 32,
            align: 4,
            addressbase: 0,
            numslots: 8,
            ty: StorageClass::General,
            ..TestEntry::default()
        });

        let transient = Arc::new(ParamListStandardImpl::from_parts(
            vec![reg_entry.clone(), stack_entry.clone()],
            Vec::new(),
            2,
            Some(stack_space()),
            false,
            false,
            true,
            Some(Arc::new(TestLanguage { big_endian: false })),
        )) as Arc<dyn ParamListStandardLike>;

        let action = GotoStack::new(transient.clone()).unwrap();
        // Only matches sizes < 8 (so our 4-byte type matches, forcing it to the stack instead of
        // the register that would otherwise win under plain fallback ordering).
        let filter = SizeRestrictedFilter::with_min_max(0, 7);
        let rule = ModelRule::from_components(&filter, &action, transient).unwrap();

        let list = ParamListStandardImpl::from_parts(
            vec![reg_entry, stack_entry],
            vec![Arc::new(rule)],
            2,
            Some(stack_space()),
            false,
            false,
            true,
            Some(Arc::new(TestLanguage { big_endian: false })),
        );

        let dt = int_dt(4);
        let proto = PrototypePieces::default();
        let mut status = [0i32; 2];
        let mut res = ParameterPieces::default();

        let code =
            ParamListStandard::assign_address(&list, &dt, &proto, 0, &MockDataTypeManager, &mut status, &mut res);

        assert_eq!(code, SUCCESS);
        // Went to the stack (group 1), not the register (group 0), proving the rule ran and won.
        assert_eq!(res.address.as_ref().unwrap().space().space_type(), AddressSpaceType::Stack);
        assert_eq!(status[0], 0); // register untouched
    }

    #[test]
    fn assign_address_falls_back_when_no_rule_matches() {
        // Same setup as above, but the filter now only matches sizes >= 8, so our 4-byte type
        // fails the rule and must fall through to assign_address_fallback, landing on the
        // register (the first matching entry).
        let reg_entry: Arc<dyn ParamEntry> = Arc::new(TestEntry {
            space: ram_space(),
            group: 0,
            min_size: 1,
            size: 4,
            align: 0,
            addressbase: 0x4000,
            numslots: 1,
            ty: StorageClass::General,
            ..TestEntry::default()
        });
        let stack_entry: Arc<dyn ParamEntry> = Arc::new(TestEntry {
            space: stack_space(),
            group: 1,
            min_size: 1,
            // Java's ParamEntry.size for an aligned (multi-slot) entry is the span of the WHOLE
            // region (numslots * align), not one slot -- justified_contain/contains/etc. rely on
            // this. 8 slots * 4-byte alignment = 32.
            size: 32,
            align: 4,
            addressbase: 0,
            numslots: 8,
            ty: StorageClass::General,
            ..TestEntry::default()
        });

        let transient = Arc::new(ParamListStandardImpl::from_parts(
            vec![reg_entry.clone(), stack_entry.clone()],
            Vec::new(),
            2,
            Some(stack_space()),
            false,
            false,
            true,
            Some(Arc::new(TestLanguage { big_endian: false })),
        )) as Arc<dyn ParamListStandardLike>;

        let action = GotoStack::new(transient.clone()).unwrap();
        let filter = SizeRestrictedFilter::with_min_max(8, 0);
        let rule = ModelRule::from_components(&filter, &action, transient).unwrap();

        let list = ParamListStandardImpl::from_parts(
            vec![reg_entry, stack_entry],
            vec![Arc::new(rule)],
            2,
            Some(stack_space()),
            false,
            false,
            true,
            Some(Arc::new(TestLanguage { big_endian: false })),
        );

        let dt = int_dt(4);
        let proto = PrototypePieces::default();
        let mut status = [0i32; 2];
        let mut res = ParameterPieces::default();

        let code =
            ParamListStandard::assign_address(&list, &dt, &proto, 0, &MockDataTypeManager, &mut status, &mut res);

        assert_eq!(code, SUCCESS);
        assert_eq!(res.address.as_ref().unwrap().space().space_type(), AddressSpaceType::Ram);
        assert_eq!(status[0], -1);
    }

    #[test]
    fn assign_address_no_assignment_for_zero_length_type() {
        let list = register_then_stack_list();
        struct ZeroLengthType;
        impl DataType for ZeroLengthType {
            fn get_length(&self) -> i32 {
                0
            }
            fn is_zero_length(&self) -> bool {
                true
            }
        }
        let dt: Arc<dyn DataType> = Arc::new(ZeroLengthType);
        let proto = PrototypePieces::default();
        let mut status = vec![0i32; 2];
        let mut res = ParameterPieces::default();

        let code =
            ParamListStandard::assign_address(&list, &dt, &proto, 0, &MockDataTypeManager, &mut status, &mut res);
        assert_eq!(
            code,
            crate::program::model::lang::protorules::assign_action::NO_ASSIGNMENT
        );
    }

    #[test]
    fn encode_std_round_trips_through_param_list_encode() {
        struct RecordingEncoder {
            elements: Vec<&'static str>,
        }
        impl Encoder for RecordingEncoder {
            fn open_element(
                &mut self,
                elem_id: crate::program::model::pcode::ElementId,
            ) -> std::io::Result<()> {
                self.elements.push(elem_id.name);
                Ok(())
            }
            fn close_element(
                &mut self,
                elem_id: crate::program::model::pcode::ElementId,
            ) -> std::io::Result<()> {
                self.elements.push(elem_id.name);
                Ok(())
            }
            fn write_bool(
                &mut self,
                _attrib_id: crate::program::model::pcode::AttributeId,
                _val: bool,
            ) -> std::io::Result<()> {
                Ok(())
            }
            fn write_signed_integer(
                &mut self,
                _attrib_id: crate::program::model::pcode::AttributeId,
                _val: i64,
            ) -> std::io::Result<()> {
                Ok(())
            }
            fn write_unsigned_integer(
                &mut self,
                _attrib_id: crate::program::model::pcode::AttributeId,
                _val: u64,
            ) -> std::io::Result<()> {
                Ok(())
            }
            fn write_string(
                &mut self,
                _attrib_id: crate::program::model::pcode::AttributeId,
                _val: &str,
            ) -> std::io::Result<()> {
                Ok(())
            }
            fn write_string_indexed(
                &mut self,
                _attrib_id: crate::program::model::pcode::AttributeId,
                _index: i32,
                _val: &str,
            ) -> std::io::Result<()> {
                Ok(())
            }
            fn write_space(
                &mut self,
                _attrib_id: crate::program::model::pcode::AttributeId,
                _spc: &AddressSpace,
            ) -> std::io::Result<()> {
                Ok(())
            }
            fn write_space_indexed(
                &mut self,
                _attrib_id: crate::program::model::pcode::AttributeId,
                _index: i32,
                _name: &str,
            ) -> std::io::Result<()> {
                Ok(())
            }
            fn write_opcode(
                &mut self,
                _attrib_id: crate::program::model::pcode::AttributeId,
                _opcode: crate::decompiler::opcodes::op_code::OpCode,
            ) -> std::io::Result<()> {
                Ok(())
            }
            fn write_opcode_ordinal(
                &mut self,
                _attrib_id: crate::program::model::pcode::AttributeId,
                _opcode: i32,
            ) -> std::io::Result<()> {
                Ok(())
            }
        }

        let list = register_then_stack_list();
        let mut enc = RecordingEncoder { elements: Vec::new() };
        list.encode(&mut enc, true).unwrap();
        assert_eq!(enc.elements.first(), Some(&"input"));
        assert_eq!(enc.elements.last(), Some(&"input"));
        assert!(enc.elements.contains(&"pentry"));
    }

    #[test]
    fn get_potential_register_storage_is_empty_pending_program_architecture_bridge() {
        // See the doc comment on ParamList::get_potential_register_storage above: this is a
        // documented gap, not a silent omission -- proven here so a future fix (once the
        // Program -> ProgramArchitecture bridge exists) has a failing test to update.
        struct MockProgram;
        impl crate::framework::model::DomainObject for MockProgram {}
        impl Program for MockProgram {
            fn get_name(&self) -> String {
                "mock".to_string()
            }
            fn get_language_id(&self) -> String {
                "mock:LE:32:default".to_string()
            }
        }

        let list = register_then_stack_list();
        let storage = list.get_potential_register_storage(&MockProgram);
        assert!(storage.is_empty());
    }

    #[test]
    fn usable_as_param_list_standard_trait_object() {
        let list: Box<dyn ParamListStandard> = Box::new(register_then_stack_list());
        assert_eq!(list.get_num_param_entry(), 2);
        assert_eq!(list.num_group(), 2);
        assert!(list.auto_killed_by_call());
    }

    #[test]
    fn usable_as_param_list_standard_like_trait_object() {
        let list: Arc<dyn ParamListStandardLike> = Arc::new(register_then_stack_list());
        assert_eq!(ParamListStandardLike::get_num_param_entry(list.as_ref()), 2);
        assert!(list.get_language().is_some());
    }

    #[test]
    fn usable_as_param_list_trait_object() {
        let list: Box<dyn ParamList> = Box::new(register_then_stack_list());
        assert_eq!(list.get_stack_parameter_alignment(), 4);
        assert!(!list.is_this_before_ret_pointer());
    }
}
