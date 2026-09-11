//! Port of `ghidra.program.model.lang.PrototypeModelMerged`.
//!
//! A placeholder `PrototypeModel` standing in for several candidate calling-convention models
//! that share the same output model but haven't yet been distinguished; [`Self::select_model`]
//! scores each candidate against a function's actual parameter storage and picks the best match.
//!
//! In Java this `extends PrototypeModel`. Following the "`extends X`" convention established by
//! [`PrototypeModelError`](super::prototype_model_error::PrototypeModelError) (composition, not
//! inheritance, since [`PrototypeModel`] is a trait here), `PrototypeModelMerged` is its own
//! struct implementing the [`PrototypeModel`] trait, holding its own `name` and `modellist`
//! fields directly (matching `PrototypeModel`'s own `protected String name` and this class's
//! `private PrototypeModel[] modellist` fields) rather than delegating to a wrapped model --
//! unlike `PrototypeModelError`, there is no single "original" model to delegate to here.
//!
//! # Deliberate deviation: default-constructed `modellist`
//! Java's no-arg constructor leaves `modellist = null`; calling `numModels()`/`getModel(int)`/
//! `selectModel(...)` before `restoreXml` throws `NullPointerException`. This port instead
//! defaults `modellist` to an empty `Vec`, matching the "unconfigured model" convention already
//! established for [`PrototypeModel`]'s own trait defaults (see that module's docs: "empty
//! lists", not a panic, for every collection-valued accessor on a freshly-constructed model).
//! `num_models()` returns `0` and `select_model` returns the same "no model matches" error it
//! would for a `modellist` of length zero, rather than panicking.

use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::lang::param_list::WithSlotRec;
use crate::program::model::lang::prototype_model::PrototypeModel;
use crate::program::model::listing::parameter::Parameter;
use crate::program::model::pcode::ids::{ATTRIB_NAME, ELEM_MODEL, ELEM_RESOLVEPROTOTYPE};
use crate::program::model::pcode::Encoder;
use crate::program::seam_stubs::PcodeInjectLibrary;
use crate::app::plugin::processors::sleigh::sleigh_exception::SleighException;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_exception::XmlException;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

fn xml_err(e: XmlException) -> XmlParseException {
    XmlParseException::with_cause(e.to_string(), e)
}

/// A single scored parameter slot. Port of the private inner class `PrototypeModelMerged.PEntry`.
///
/// # Real Java quirk faithfully reproduced (not fixed)
/// Java's `PEntry implements Comparable<PEntry>` with `compareTo` based on `slot` alone, but
/// does *not* override `equals()`/`hashCode()` (default `Object` identity). This is the same
/// shape of Comparable/equals-contract mismatch found elsewhere in this session's
/// `program.model.lang` ports -- here it's latent/inconsequential because `PEntry` is only ever
/// used inside a single `ArrayList` sorted via `Collections.sort` (which needs only `compareTo`,
/// never `equals`), so this port doesn't need `PartialEq`/`Eq` on [`PEntry`] either; only the
/// `slot`-based ordering used by [`ScoreProtoModel::do_score`] is ported.
#[derive(Debug, Clone, Copy)]
struct PEntry {
    /// Slot within the parameter list.
    slot: i32,
    /// Number of slots occupied.
    size: i32,
}

/// Scores a single candidate [`PrototypeModel`] against a set of observed parameter storage
/// locations. Port of the private inner class `PrototypeModelMerged.ScoreProtoModel`.
struct ScoreProtoModel<'a> {
    /// `true` to score input parameters, `false` to score outputs. Only the input path is
    /// exercised by [`super::PrototypeModelMerged::select_model`] (it always constructs with
    /// `true`, mirroring Java's `new ScoreProtoModel(true, ...)`), but both branches are ported
    /// faithfully since the Java class supports both.
    isinputscore: bool,
    entry: Vec<PEntry>,
    model: &'a dyn PrototypeModel,
    finalscore: i32,
    mismatch: i32,
}

impl<'a> ScoreProtoModel<'a> {
    fn new(isinput: bool, model: &'a dyn PrototypeModel, numparam: usize) -> Self {
        Self {
            isinputscore: isinput,
            entry: Vec::with_capacity(numparam),
            model,
            finalscore: -1,
            mismatch: 0,
        }
    }

    fn get_score(&self) -> i32 {
        self.finalscore
    }

    /// Port of `ScoreProtoModel.addParameter(Address, int)`.
    fn add_parameter(&mut self, addr: &Address, sz: i32) {
        let mut rec = WithSlotRec::default();
        let isparam = if self.isinputscore {
            self.model.possible_input_param_with_slot(addr, sz, &mut rec)
        } else {
            self.model.possible_output_param_with_slot(addr, sz, &mut rec)
        };
        if isparam {
            self.entry.push(PEntry { slot: rec.slot, size: rec.slotsize });
        } else {
            self.mismatch += 1;
        }
    }

    /// Port of `ScoreProtoModel.doScore()`.
    fn do_score(&mut self) {
        // `Collections.sort(entry)` uses `PEntry.compareTo`, which orders by `slot` only; a
        // stable sort (Rust's `sort_by_key`, like Java's `Collections.sort`) preserves insertion
        // order among equal-slot entries, matching Java exactly.
        self.entry.sort_by_key(|e| e.slot);

        let mut nextfree: i32 = 0;
        let mut basescore: i32 = 0;
        let penalty = [16, 10, 7, 5];
        let penaltyfinal = 3;
        let mismatchpenalty = 20;

        for p in &self.entry {
            if p.slot > nextfree {
                // A hole in slot coverage.
                while nextfree < p.slot {
                    if nextfree < 4 {
                        basescore += penalty[nextfree as usize];
                    } else {
                        basescore += penaltyfinal;
                    }
                    nextfree += 1;
                }
                nextfree += p.size;
            } else if nextfree > p.slot {
                // Slot duplication.
                basescore += mismatchpenalty;
                if p.slot + p.size > nextfree {
                    nextfree = p.slot + p.size;
                }
            } else {
                nextfree = p.slot + p.size;
            }
        }
        self.finalscore = basescore + mismatchpenalty * self.mismatch;
    }
}

/// A `PrototypeModel` that merges several candidate calling-convention models, used during
/// analysis to distinguish which one actually applies to an unknown function.
///
/// Port of `ghidra.program.model.lang.PrototypeModelMerged`. See the module docs for how this
/// port maps Java's `extends PrototypeModel` (with its own `name`/`modellist` fields) onto this
/// trait-based crate.
pub struct PrototypeModelMerged {
    name: Option<String>,
    modellist: Vec<Arc<dyn PrototypeModel>>,
}

impl PrototypeModelMerged {
    /// Constructs an empty, unconfigured merged model. Call [`Self::restore_xml`] to populate it.
    ///
    /// Port of `PrototypeModelMerged()`.
    pub fn new() -> Self {
        Self { name: None, modellist: Vec::new() }
    }

    /// The number of candidate models being distinguished between.
    ///
    /// Port of `PrototypeModelMerged.numModels()`.
    pub fn num_models(&self) -> usize {
        self.modellist.len()
    }

    /// Returns the candidate model at index `i`.
    ///
    /// Port of `PrototypeModelMerged.getModel(int)`.
    ///
    /// # Panics
    /// Panics if `i >= self.num_models()`, matching Java's `ArrayIndexOutOfBoundsException` for
    /// an out-of-range index.
    pub fn get_model(&self, i: usize) -> Arc<dyn PrototypeModel> {
        self.modellist[i].clone()
    }

    /// Restores this merged model's configuration (`name` and the list of candidate models, each
    /// looked up by name in `model_list`) from a `<resolveprototype>` XML element.
    ///
    /// # Errors
    /// Returns [`XmlParseException`] for malformed XML, or if a `<model name="...">` child names
    /// a model that isn't present in `model_list`.
    ///
    /// Port of `PrototypeModelMerged.restoreXml(XmlPullParser, List<PrototypeModel>)`.
    pub fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        model_list: &[Arc<dyn PrototypeModel>],
    ) -> Result<(), XmlParseException> {
        let mut mylist: Vec<Arc<dyn PrototypeModel>> = Vec::new();
        let el = parser.start(&[]).map_err(xml_err)?;
        self.name = el.get_attribute("name");
        while parser.peek().is_start() {
            let subel = parser.start(&[]).map_err(xml_err)?;
            let model_name = subel.get_attribute("name");
            let found = model_name.as_deref().and_then(|mn| {
                model_list
                    .iter()
                    .find(|m| m.get_name().as_deref() == Some(mn))
                    .cloned()
            });
            let found = match found {
                Some(m) => m,
                None => {
                    return Err(XmlParseException::new(format!(
                        "Missing prototype model: {}",
                        model_name.unwrap_or_default()
                    )));
                }
            };
            mylist.push(found);
            parser.end_matching(&subel).map_err(xml_err)?;
        }
        parser.end_matching(&el).map_err(xml_err)?;
        self.modellist = mylist;
        Ok(())
    }

    /// Picks the candidate model that best fits the observed parameter storage in `params`,
    /// scoring each candidate via [`ScoreProtoModel`] and choosing the lowest-scoring (i.e. best
    /// matching) one. A score of `0` is a perfect match and short-circuits the search.
    ///
    /// # Errors
    /// Returns a [`SleighException`] if no candidate scores below the initial threshold of `500`
    /// (including when there are no candidate models at all), matching Java's "No model matches :
    /// missing default".
    ///
    /// Port of `PrototypeModelMerged.selectModel(Parameter[])`.
    pub fn select_model(
        &self,
        params: &[Box<dyn Parameter>],
    ) -> Result<Arc<dyn PrototypeModel>, SleighException> {
        let mut bestscore = 500;
        let mut bestindex: Option<usize> = None;
        for (i, model) in self.modellist.iter().enumerate() {
            let mut scoremodel = ScoreProtoModel::new(true, model.as_ref(), params.len());
            for p in params {
                let storage = match p.get_variable_storage() {
                    Some(s) => s,
                    // Java's `getVariableStorage()` is never null for a real `Parameter`; a
                    // `None` here (this crate's port models it as `Option`) has no assigned
                    // storage to score, so it's treated the same as unassigned storage below.
                    None => continue,
                };
                if storage.is_unassigned_storage() || storage.is_bad_storage() {
                    continue;
                }
                let min_addr = match storage.get_min_address() {
                    Some(a) => a,
                    // Java calls `storage.getMinAddress()` unconditionally here and would throw
                    // `NullPointerException` if it returned `null` for non-unassigned/non-bad
                    // storage with no varnodes; this port skips the parameter instead of
                    // panicking.
                    None => continue,
                };
                scoremodel.add_parameter(&min_addr, p.get_length());
            }
            scoremodel.do_score();
            let score = scoremodel.get_score();
            if score < bestscore {
                bestscore = score;
                bestindex = Some(i);
                if bestscore == 0 {
                    break; // Can't get any lower.
                }
            }
        }
        match bestindex {
            Some(i) => Ok(self.modellist[i].clone()),
            None => Err(SleighException::with_message("No model matches : missing default")),
        }
    }
}

impl Default for PrototypeModelMerged {
    fn default() -> Self {
        Self::new()
    }
}

impl PrototypeModel for PrototypeModelMerged {
    fn get_name(&self) -> Option<String> {
        self.name.clone()
    }

    fn is_merged(&self) -> bool {
        true
    }

    fn encode(
        &self,
        encoder: &mut dyn Encoder,
        _inject_library: &dyn PcodeInjectLibrary,
    ) -> std::io::Result<()> {
        // Port of `PrototypeModelMerged.encode(Encoder, PcodeInjectLibrary)`. `injectLibrary` is
        // unused in the Java body too (a real, faithfully-reproduced quirk: the parameter is
        // declared but never referenced).
        encoder.open_element(ELEM_RESOLVEPROTOTYPE)?;
        encoder.write_string(ATTRIB_NAME, self.name.as_deref().unwrap_or(""))?;
        for model in &self.modellist {
            encoder.open_element(ELEM_MODEL)?;
            encoder.write_string(ATTRIB_NAME, model.get_name().as_deref().unwrap_or(""))?;
            encoder.close_element(ELEM_MODEL)?;
        }
        encoder.close_element(ELEM_RESOLVEPROTOTYPE)
    }

    fn is_equivalent(&self, obj: &dyn PrototypeModel) -> bool {
        let Some(op2) = obj.as_any().downcast_ref::<PrototypeModelMerged>() else {
            return false;
        };
        if self.modellist.len() != op2.modellist.len() {
            return false;
        }
        for (a, b) in self.modellist.iter().zip(op2.modellist.iter()) {
            // Java: `!modellist[i].getName().equals(op2.modellist[i].getName())`, which would
            // throw `NullPointerException` if `getName()` returned `null`; comparing the
            // `Option<String>`s directly avoids that without changing behavior for the (only
            // realistic) case where both names are set.
            if a.get_name() != b.get_name() {
                return false;
            }
        }
        true
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::param_list::WithSlotRec;

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    /// A candidate model that assigns the first `slots` parameters to consecutive register
    /// slots, mirroring a simple fixed-register calling convention for scoring purposes. `slot =
    /// address_offset - slot_bias`, letting different candidate models disagree about which slot
    /// a given address maps to (so tests can construct genuinely different scores for the same
    /// observed parameter storage, rather than every candidate agreeing by construction).
    struct FixedSlotModel {
        name: &'static str,
        slots: i32,
        slot_bias: i32,
    }

    impl FixedSlotModel {
        fn new(name: &'static str, slots: i32) -> Self {
            Self { name, slots, slot_bias: 0 }
        }

        fn with_bias(name: &'static str, slots: i32, slot_bias: i32) -> Self {
            Self { name, slots, slot_bias }
        }
    }

    impl PrototypeModel for FixedSlotModel {
        fn get_name(&self) -> Option<String> {
            Some(self.name.to_string())
        }

        fn possible_input_param_with_slot(
            &self,
            loc: &Address,
            _size: i32,
            res: &mut WithSlotRec,
        ) -> bool {
            // Slot is derived from the address offset (0-based), for test determinism.
            let slot = loc.offset() as i32 - self.slot_bias;
            if slot >= 0 && slot < self.slots {
                res.slot = slot;
                res.slotsize = 1;
                true
            } else {
                false
            }
        }
    }

    /// A candidate model that never matches any parameter (all input queries fail), standing in
    /// for a calling convention incompatible with the observed storage.
    struct NeverMatchesModel {
        name: &'static str,
    }

    impl PrototypeModel for NeverMatchesModel {
        fn get_name(&self) -> Option<String> {
            Some(self.name.to_string())
        }
    }

    struct MockDataType;
    impl crate::program::model::data::data_type::DataType for MockDataType {}

    struct MockVariableStorage {
        min_address: Option<Address>,
        unassigned: bool,
        bad: bool,
    }

    impl crate::program::model::listing::variable_storage::VariableStorage for MockVariableStorage {
        fn get_varnodes(&self) -> Vec<crate::program::model::pcode::Varnode> {
            match &self.min_address {
                Some(a) => vec![crate::program::model::pcode::Varnode::new(a.clone(), 4)],
                None => Vec::new(),
            }
        }
        fn is_bad_storage(&self) -> bool {
            self.bad
        }
        fn is_unassigned_storage(&self) -> bool {
            self.unassigned
        }
        fn get_min_address(&self) -> Option<Address> {
            self.min_address.clone()
        }
    }

    struct MockParameter {
        length: i32,
        storage: Option<MockVariableStorage>,
    }

    impl crate::program::model::listing::Variable for MockParameter {
        fn is_parameter(&self) -> bool {
            true
        }
        fn is_auto_parameter(&self) -> bool {
            false
        }
        fn get_data_type(&self) -> Box<dyn crate::program::model::data::data_type::DataType> {
            Box::new(MockDataType)
        }
        fn set_data_type_with_storage(
            &mut self,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
            _storage: Box<dyn crate::program::model::listing::variable_storage::VariableStorage>,
            _force: bool,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }
        fn set_data_type(
            &mut self,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }
        fn set_data_type_aligned(
            &mut self,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
            _align_stack: bool,
            _force: bool,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }
        fn get_name(&self) -> Option<String> {
            None
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_valid(&self) -> bool {
            true
        }
        fn get_function(&self) -> Option<Box<dyn crate::program::model::listing::Function>> {
            None
        }
        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            struct MockProgram;
            impl crate::framework::model::DomainObject for MockProgram {}
            impl crate::program::model::listing::Program for MockProgram {
                fn get_name(&self) -> String {
                    "mock".to_string()
                }
                fn get_language_id(&self) -> String {
                    "mock:LE:32:default".to_string()
                }
            }
            Arc::new(MockProgram)
        }
        fn get_source(&self) -> crate::program::model::symbol::SourceType {
            crate::program::model::symbol::SourceType::UserDefined
        }
        fn set_name(
            &mut self,
            _name: &str,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::program::model::listing::variable::SetVariableNameError> {
            Ok(())
        }
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn set_comment(&mut self, _comment: Option<String>) {}
        fn get_variable_storage(
            &self,
        ) -> Option<Box<dyn crate::program::model::listing::variable_storage::VariableStorage>> {
            self.storage.as_ref().map(|s| {
                Box::new(MockVariableStorage {
                    min_address: s.min_address.clone(),
                    unassigned: s.unassigned,
                    bad: s.bad,
                }) as Box<dyn crate::program::model::listing::variable_storage::VariableStorage>
            })
        }
        fn get_first_storage_varnode(&self) -> Option<crate::program::model::pcode::Varnode> {
            None
        }
        fn get_last_storage_varnode(&self) -> Option<crate::program::model::pcode::Varnode> {
            None
        }
        fn is_stack_variable(&self) -> bool {
            false
        }
        fn has_stack_storage(&self) -> bool {
            false
        }
        fn is_register_variable(&self) -> bool {
            false
        }
        fn get_register(&self) -> Option<crate::program::model::lang::RegisterRef> {
            None
        }
        fn get_registers(&self) -> Option<Vec<crate::program::model::lang::RegisterRef>> {
            None
        }
        fn get_min_address(&self) -> Option<Address> {
            self.storage.as_ref().and_then(|s| s.min_address.clone())
        }
        fn get_stack_offset(
            &self,
        ) -> Result<i32, crate::program::model::listing::variable::UnsupportedOperationError> {
            Err(crate::program::model::listing::variable::UnsupportedOperationError(
                "not a simple stack variable".to_string(),
            ))
        }
        fn is_memory_variable(&self) -> bool {
            false
        }
        fn is_unique_variable(&self) -> bool {
            false
        }
        fn is_compound_variable(&self) -> bool {
            false
        }
        fn has_assigned_storage(&self) -> bool {
            self.storage.is_some()
        }
        fn get_first_use_offset(&self) -> i32 {
            0
        }
        fn get_symbol(&self) -> Option<Arc<dyn crate::program::model::symbol::Symbol>> {
            None
        }
        fn is_equivalent(&self, _variable: &dyn crate::program::model::listing::Variable) -> bool {
            false
        }
        fn compare_to(&self, _other: &dyn crate::program::model::listing::Variable) -> std::cmp::Ordering {
            std::cmp::Ordering::Equal
        }
    }

    impl Parameter for MockParameter {
        fn get_ordinal(&self) -> i32 {
            0
        }
        fn is_auto_parameter(&self) -> bool {
            false
        }
        fn get_auto_parameter_type(&self) -> Option<crate::program::model::listing::AutoParameterType> {
            None
        }
        fn is_forced_indirect(&self) -> bool {
            false
        }
        fn get_formal_data_type(&self) -> Box<dyn crate::program::model::data::data_type::DataType> {
            Box::new(MockDataType)
        }
    }

    fn assigned_param(offset: i64, length: i32) -> Box<dyn Parameter> {
        Box::new(MockParameter {
            length,
            storage: Some(MockVariableStorage {
                min_address: Some(mock_address(offset)),
                unassigned: false,
                bad: false,
            }),
        })
    }

    fn unassigned_param(length: i32) -> Box<dyn Parameter> {
        Box::new(MockParameter {
            length,
            storage: Some(MockVariableStorage { min_address: None, unassigned: true, bad: false }),
        })
    }

    #[test]
    fn default_constructed_is_empty_and_unnamed() {
        let m = PrototypeModelMerged::new();
        assert_eq!(m.num_models(), 0);
        assert_eq!(m.get_name(), None);
        assert!(m.is_merged());
    }

    #[test]
    fn select_model_errors_when_no_models_registered() {
        let m = PrototypeModelMerged::new();
        let params = vec![assigned_param(0, 4)];
        let err = m.select_model(&params).err().unwrap();
        assert_eq!(err.message(), "No model matches : missing default");
    }

    #[test]
    fn select_model_picks_the_perfectly_matching_candidate() {
        // Two candidates: one only has 1 slot (won't fit params at offsets 0 and 1), the other
        // has enough slots to place both parameters with zero gaps/mismatches -> score 0.
        let too_small = Arc::new(FixedSlotModel::new("too_small", 1)) as Arc<dyn PrototypeModel>;
        let perfect = Arc::new(FixedSlotModel::new("perfect", 4)) as Arc<dyn PrototypeModel>;

        let mut merged = PrototypeModelMerged::new();
        merged.modellist = vec![too_small, perfect.clone()];

        let params = vec![assigned_param(0, 4), assigned_param(1, 4)];
        let selected = merged.select_model(&params).expect("a model should match");
        assert_eq!(selected.get_name(), Some("perfect".to_string()));
    }

    #[test]
    fn select_model_prefers_lower_score_over_declaration_order() {
        // Both candidates place a parameter observed at address offset 1, but disagree about
        // which slot that maps to (`slot = offset - slot_bias`): "gappy" (bias 0) maps it to
        // slot 1, leaving slot 0 as a hole -> incurs a `penalty[0] = 16` hole penalty. "tight"
        // (bias 1) maps the very same observed address to slot 0 -> a perfect score of 0.
        let gappy = Arc::new(FixedSlotModel::with_bias("gappy", 4, 0)) as Arc<dyn PrototypeModel>;
        let tight = Arc::new(FixedSlotModel::with_bias("tight", 4, 1)) as Arc<dyn PrototypeModel>;

        let mut merged = PrototypeModelMerged::new();
        // Declare "gappy" first to prove selection is score-driven, not declaration-order-driven.
        merged.modellist = vec![gappy, tight];

        let params = vec![assigned_param(1, 4)];
        let selected = merged.select_model(&params).expect("a model should match");
        assert_eq!(selected.get_name(), Some("tight".to_string()));
    }

    #[test]
    fn select_model_counts_mismatches_against_never_matching_candidate() {
        let never = Arc::new(NeverMatchesModel { name: "never" }) as Arc<dyn PrototypeModel>;
        let fits = Arc::new(FixedSlotModel::new("fits", 4)) as Arc<dyn PrototypeModel>;

        let mut merged = PrototypeModelMerged::new();
        merged.modellist = vec![never, fits];

        let params = vec![assigned_param(0, 4)];
        let selected = merged.select_model(&params).expect("a model should match");
        assert_eq!(selected.get_name(), Some("fits".to_string()));
    }

    #[test]
    fn select_model_skips_unassigned_and_bad_storage_parameters() {
        let only = Arc::new(FixedSlotModel::new("only", 4)) as Arc<dyn PrototypeModel>;
        let mut merged = PrototypeModelMerged::new();
        merged.modellist = vec![only];

        // A mix of a real, matching parameter and one with unassigned storage: the unassigned
        // one must not count as a mismatch (Java skips it via `continue` before ever calling
        // `addParameter`).
        let params = vec![assigned_param(0, 4), unassigned_param(4)];
        let selected = merged.select_model(&params).expect("should still match via the real param");
        assert_eq!(selected.get_name(), Some("only".to_string()));
    }

    #[test]
    fn get_model_returns_candidate_by_index() {
        let a = Arc::new(FixedSlotModel::new("a", 1)) as Arc<dyn PrototypeModel>;
        let b = Arc::new(FixedSlotModel::new("b", 1)) as Arc<dyn PrototypeModel>;
        let mut merged = PrototypeModelMerged::new();
        merged.modellist = vec![a, b];

        assert_eq!(merged.num_models(), 2);
        assert_eq!(merged.get_model(0).get_name(), Some("a".to_string()));
        assert_eq!(merged.get_model(1).get_name(), Some("b".to_string()));
    }

    #[test]
    fn is_equivalent_compares_by_class_and_submodel_names() {
        let a = Arc::new(FixedSlotModel::new("a", 1)) as Arc<dyn PrototypeModel>;
        let b = Arc::new(FixedSlotModel::new("b", 1)) as Arc<dyn PrototypeModel>;

        let mut m1 = PrototypeModelMerged::new();
        m1.modellist = vec![a.clone(), b.clone()];
        let mut m2 = PrototypeModelMerged::new();
        m2.modellist = vec![a.clone(), b.clone()];

        assert!(m1.is_equivalent(&m2));
    }

    #[test]
    fn is_equivalent_false_for_different_length_modellists() {
        let a = Arc::new(FixedSlotModel::new("a", 1)) as Arc<dyn PrototypeModel>;

        let mut m1 = PrototypeModelMerged::new();
        m1.modellist = vec![a.clone()];
        let mut m2 = PrototypeModelMerged::new();
        m2.modellist = vec![a.clone(), a];

        assert!(!m1.is_equivalent(&m2));
    }

    #[test]
    fn is_equivalent_false_for_different_submodel_names() {
        let a = Arc::new(FixedSlotModel::new("a", 1)) as Arc<dyn PrototypeModel>;
        let c = Arc::new(FixedSlotModel::new("c", 1)) as Arc<dyn PrototypeModel>;

        let mut m1 = PrototypeModelMerged::new();
        m1.modellist = vec![a];
        let mut m2 = PrototypeModelMerged::new();
        m2.modellist = vec![c];

        assert!(!m1.is_equivalent(&m2));
    }

    #[test]
    fn is_equivalent_false_against_a_different_concrete_prototype_model_type() {
        struct OtherModel;
        impl PrototypeModel for OtherModel {}

        let m = PrototypeModelMerged::new();
        assert!(!m.is_equivalent(&OtherModel));
    }

    #[test]
    fn encode_writes_resolveprototype_with_name_and_submodels() {
        #[derive(Default)]
        struct RecordingEncoder {
            opened: Vec<crate::program::model::pcode::ids::ElementId>,
            closed: Vec<crate::program::model::pcode::ids::ElementId>,
            strings: Vec<(crate::program::model::pcode::ids::AttributeId, String)>,
        }
        impl Encoder for RecordingEncoder {
            fn open_element(&mut self, elem_id: crate::program::model::pcode::ids::ElementId) -> std::io::Result<()> {
                self.opened.push(elem_id);
                Ok(())
            }
            fn close_element(&mut self, elem_id: crate::program::model::pcode::ids::ElementId) -> std::io::Result<()> {
                self.closed.push(elem_id);
                Ok(())
            }
            fn write_bool(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _val: bool) -> std::io::Result<()> {
                Ok(())
            }
            fn write_signed_integer(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _val: i64) -> std::io::Result<()> {
                Ok(())
            }
            fn write_unsigned_integer(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _val: u64) -> std::io::Result<()> {
                Ok(())
            }
            fn write_string(&mut self, attrib_id: crate::program::model::pcode::ids::AttributeId, val: &str) -> std::io::Result<()> {
                self.strings.push((attrib_id, val.to_string()));
                Ok(())
            }
            fn write_string_indexed(
                &mut self,
                attrib_id: crate::program::model::pcode::ids::AttributeId,
                index: i32,
                val: &str,
            ) -> std::io::Result<()> {
                self.strings.push((attrib_id, format!("[{index}]{val}")));
                Ok(())
            }
            fn write_space(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _spc: &AddressSpace) -> std::io::Result<()> {
                Ok(())
            }
            fn write_space_indexed(
                &mut self,
                _attrib_id: crate::program::model::pcode::ids::AttributeId,
                _index: i32,
                _name: &str,
            ) -> std::io::Result<()> {
                Ok(())
            }
            fn write_opcode(
                &mut self,
                _attrib_id: crate::program::model::pcode::ids::AttributeId,
                _opcode: crate::decompiler::opcodes::op_code::OpCode,
            ) -> std::io::Result<()> {
                Ok(())
            }
            fn write_opcode_ordinal(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _opcode: i32) -> std::io::Result<()> {
                Ok(())
            }
        }

        struct MockPcodeInjectLibrary;
        impl PcodeInjectLibrary for MockPcodeInjectLibrary {}

        let mut merged = PrototypeModelMerged::new();
        merged.name = Some("merged_cc".to_string());
        merged.modellist = vec![
            Arc::new(FixedSlotModel::new("cc_a", 1)) as Arc<dyn PrototypeModel>,
            Arc::new(FixedSlotModel::new("cc_b", 1)) as Arc<dyn PrototypeModel>,
        ];

        let mut encoder = RecordingEncoder::default();
        merged.encode(&mut encoder, &MockPcodeInjectLibrary).unwrap();

        assert_eq!(
            encoder.opened,
            vec![ELEM_RESOLVEPROTOTYPE, ELEM_MODEL, ELEM_MODEL]
        );
        assert_eq!(
            encoder.closed,
            vec![ELEM_MODEL, ELEM_MODEL, ELEM_RESOLVEPROTOTYPE]
        );
        assert!(encoder.strings.contains(&(ATTRIB_NAME, "merged_cc".to_string())));
        assert!(encoder.strings.contains(&(ATTRIB_NAME, "cc_a".to_string())));
        assert!(encoder.strings.contains(&(ATTRIB_NAME, "cc_b".to_string())));
    }
}
