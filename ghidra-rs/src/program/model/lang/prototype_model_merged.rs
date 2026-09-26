//! Port of `ghidra.program.model.lang.PrototypeModelMerged`.
//!
//! A placeholder `PrototypeModel` standing in for several candidate calling-convention models
//! that share the same output model but haven't yet been distinguished; [`Self::select_model`]
//! scores each candidate against a function's actual parameter storage and picks the best match.
//!
//! In Java this `extends PrototypeModel`, and a merged model is handed out wherever a
//! `PrototypeModel` is (e.g. `CompilerSpec.getAllModels()`), so it is a [`PrototypeModel`] value
//! whose kind is `Merged` (see that module's docs); this module holds its constructor, its
//! methods and the scoring helper.
//!
//! # Deliberate deviation: default-constructed `modellist`
//! Java's no-arg constructor leaves `modellist = null`; calling `numModels()`/`getModel(int)`/
//! `selectModel(...)` before `restoreXml` throws `NullPointerException`. This port instead
//! starts with an empty list: `num_models()` returns `0` and `select_model` returns the same "no
//! model matches" error it would for a `modellist` of length zero.

use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::lang::param_list::WithSlotRec;
use crate::program::model::lang::prototype_model::{ModelKind, PrototypeModel};
use crate::program::model::listing::parameter::Parameter;
use crate::program::model::pcode::ids::{ATTRIB_NAME, ELEM_MODEL, ELEM_RESOLVEPROTOTYPE};
use crate::program::model::pcode::Encoder;
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
    /// exercised by [`PrototypeModel::select_model`] (it always constructs with
    /// `true`, mirroring Java's `new ScoreProtoModel(true, ...)`), but both branches are ported
    /// faithfully since the Java class supports both.
    isinputscore: bool,
    entry: Vec<PEntry>,
    model: &'a PrototypeModel,
    finalscore: i32,
    mismatch: i32,
}

impl<'a> ScoreProtoModel<'a> {
    fn new(isinput: bool, model: &'a PrototypeModel, numparam: usize) -> Self {
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

impl PrototypeModel {
    /// An empty, unconfigured merged model. Call [`restore_merged_xml`](Self::restore_merged_xml)
    /// to populate it.
    ///
    /// Port of `PrototypeModelMerged()`.
    pub fn new_merged() -> Self {
        let mut model = PrototypeModel::new();
        model.kind = ModelKind::Merged(Vec::new());
        model
    }

    /// The candidate models of a merged model (empty for any other model).
    fn merged_models(&self) -> &[Arc<PrototypeModel>] {
        match &self.kind {
            ModelKind::Merged(list) => list,
            _ => &[],
        }
    }

    /// The number of candidate models being distinguished between.
    ///
    /// Port of `PrototypeModelMerged.numModels()`.
    pub fn num_models(&self) -> usize {
        self.merged_models().len()
    }

    /// The candidate model at index `i`.
    ///
    /// Port of `PrototypeModelMerged.getModel(int)`.
    ///
    /// # Panics
    /// Panics if `i >= self.num_models()`, matching Java's `ArrayIndexOutOfBoundsException`.
    pub fn get_model(&self, i: usize) -> Arc<PrototypeModel> {
        self.merged_models()[i].clone()
    }

    /// Restore a merged model (its `name` and candidate models, each looked up by name in
    /// `model_list`) from a `<resolveprototype>` element.
    ///
    /// Port of `PrototypeModelMerged.restoreXml(XmlPullParser, List<PrototypeModel>)`.
    ///
    /// # Errors
    /// Returns an error for malformed XML, or if a `<model name="...">` child names a model not
    /// present in `model_list`.
    pub(crate) fn restore_merged_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        model_list: &[Arc<PrototypeModel>],
    ) -> Result<(), XmlParseException> {
        let mut mylist: Vec<Arc<PrototypeModel>> = Vec::new();
        let el = parser.start(&[]).map_err(xml_err)?;
        self.name = el.get_attribute("name");
        while parser.peek().is_start() {
            let subel = parser.start(&[]).map_err(xml_err)?;
            let model_name = subel.get_attribute("name");
            let found = model_name
                .as_deref()
                .and_then(|mn| model_list.iter().find(|m| m.name.as_deref() == Some(mn)).cloned());
            let Some(found) = found else {
                return Err(XmlParseException::new(format!(
                    "Missing prototype model: {}",
                    model_name.unwrap_or_default()
                )));
            };
            mylist.push(found);
            parser.end_matching(&subel).map_err(xml_err)?;
        }
        parser.end_matching(&el).map_err(xml_err)?;
        self.kind = ModelKind::Merged(mylist);
        Ok(())
    }

    /// Pick the candidate model that best fits the observed parameter storage in `params`: each
    /// candidate is scored via [`ScoreProtoModel`] and the lowest score wins; `0` is a perfect
    /// match and ends the search.
    ///
    /// Port of `PrototypeModelMerged.selectModel(Parameter[])`.
    ///
    /// # Errors
    /// Returns a [`SleighException`] if no candidate scores below the initial threshold of `500`
    /// (including when there are no candidates), matching Java's "No model matches : missing
    /// default".
    pub fn select_model(&self, params: &[&dyn Parameter]) -> Result<Arc<PrototypeModel>, SleighException> {
        let modellist = self.merged_models();
        let mut bestscore = 500;
        let mut bestindex: Option<usize> = None;
        for (i, model) in modellist.iter().enumerate() {
            let mut scoremodel = ScoreProtoModel::new(true, model.as_ref(), params.len());
            for p in params {
                let Some(storage) = p.get_variable_storage() else {
                    // Java's `getVariableStorage()` is never null for a real `Parameter`; with
                    // no storage there is nothing to score, as for unassigned storage.
                    continue;
                };
                if storage.is_unassigned_storage() || storage.is_bad_storage() {
                    continue;
                }
                let Some(min_addr) = storage.get_min_address() else {
                    // Java would throw `NullPointerException`; skip the parameter instead.
                    continue;
                };
                scoremodel.add_parameter(&min_addr, p.get_length());
            }
            scoremodel.do_score();
            let score = scoremodel.get_score();
            if score < bestscore {
                bestscore = score;
                bestindex = Some(i);
                if bestscore == 0 {
                    break; // Can't get any lower
                }
            }
        }
        match bestindex {
            Some(i) => Ok(modellist[i].clone()),
            None => Err(SleighException::with_message("No model matches : missing default")),
        }
    }
}

/// Port of `PrototypeModelMerged.encode(Encoder, PcodeInjectLibrary)` (the library is unused in
/// Java too): a `<resolveprototype>` naming each candidate model.
pub(crate) fn encode_merged(
    model: &PrototypeModel,
    modellist: &[Arc<PrototypeModel>],
    encoder: &mut dyn Encoder,
) -> std::io::Result<()> {
    encoder.open_element(ELEM_RESOLVEPROTOTYPE)?;
    encoder.write_string(ATTRIB_NAME, model.name.as_deref().unwrap_or(""))?;
    for sub in modellist {
        encoder.open_element(ELEM_MODEL)?;
        encoder.write_string(ATTRIB_NAME, sub.name.as_deref().unwrap_or(""))?;
        encoder.close_element(ELEM_MODEL)?;
    }
    encoder.close_element(ELEM_RESOLVEPROTOTYPE)
}

/// Port of `PrototypeModelMerged.isEquivalent`'s comparison once both sides are merged models:
/// same number of candidates with the same names, in order.
pub(crate) fn merged_lists_equivalent(a: &[Arc<PrototypeModel>], b: &[Arc<PrototypeModel>]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.name == y.name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpace;
    use crate::program::model::lang::cspec_test_support::{parser, register_space, TestCompilerSpec};

    /// x86-64 System V: integer arguments in RDI, RSI, RDX, RCX, R8, R9.
    const SYSV: &str = r#"<prototype name="__stdcall" extrapop="8" stackshift="8">
      <input>
        <pentry minsize="1" maxsize="8"><register name="RDI"/></pentry>
        <pentry minsize="1" maxsize="8"><register name="RSI"/></pentry>
        <pentry minsize="1" maxsize="8"><register name="RDX"/></pentry>
        <pentry minsize="1" maxsize="8"><register name="RCX"/></pentry>
        <pentry minsize="1" maxsize="8"><register name="R8"/></pentry>
        <pentry minsize="1" maxsize="8"><register name="R9"/></pentry>
      </input>
      <output><pentry minsize="1" maxsize="8"><register name="RAX"/></pentry></output>
    </prototype>"#;

    /// x86-64 Microsoft: integer arguments in RCX, RDX, R8, R9.
    const MS: &str = r#"<prototype name="__fastcall" extrapop="8" stackshift="8">
      <input>
        <pentry minsize="1" maxsize="8"><register name="RCX"/></pentry>
        <pentry minsize="1" maxsize="8"><register name="RDX"/></pentry>
        <pentry minsize="1" maxsize="8"><register name="R8"/></pentry>
        <pentry minsize="1" maxsize="8"><register name="R9"/></pentry>
      </input>
      <output><pentry minsize="1" maxsize="8"><register name="RAX"/></pentry></output>
    </prototype>"#;

    fn model(xml: &str) -> Arc<PrototypeModel> {
        let mut m = PrototypeModel::new();
        m.restore_xml(&mut parser(xml), &TestCompilerSpec::x86_64(), None).unwrap();
        Arc::new(m)
    }

    fn merged(models: &[Arc<PrototypeModel>]) -> PrototypeModel {
        let mut xml = String::from(r#"<resolveprototype name="merged">"#);
        for m in models {
            xml.push_str(&format!(r#"<model name="{}"/>"#, m.get_name().unwrap()));
        }
        xml.push_str("</resolveprototype>");
        let mut merged = PrototypeModel::new_merged();
        merged.restore_merged_xml(&mut parser(&xml), models).unwrap();
        merged
    }

    fn reg(offset: i64) -> Address {
        Address::new(register_space(), offset)
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

    fn assigned_param(addr: Address, length: i32) -> Box<dyn Parameter> {
        Box::new(MockParameter {
            length,
            storage: Some(MockVariableStorage { min_address: Some(addr), unassigned: false, bad: false }),
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
        let m = PrototypeModel::new_merged();
        assert_eq!(m.num_models(), 0);
        assert_eq!(m.get_name(), None);
        assert!(m.is_merged());
        assert!(!PrototypeModel::new().is_merged());
    }

    #[test]
    fn restore_merged_xml_resolves_models_by_name() {
        let (sysv, ms) = (model(SYSV), model(MS));
        let m = merged(&[sysv.clone(), ms.clone()]);
        assert_eq!(m.get_name().as_deref(), Some("merged"));
        assert_eq!(m.num_models(), 2);
        assert_eq!(m.get_model(1).get_name().as_deref(), Some("__fastcall"));

        let mut bad = PrototypeModel::new_merged();
        let err = bad
            .restore_merged_xml(&mut parser(r#"<resolveprototype name="x"><model name="nope"/></resolveprototype>"#), &[sysv])
            .err()
            .unwrap();
        assert_eq!(err.message(), "Missing prototype model: nope");
    }

    #[test]
    fn select_model_errors_when_no_models_registered() {
        let m = PrototypeModel::new_merged();
        let err = m.select_model(&[assigned_param(reg(0x38), 8).as_ref()]).err().unwrap();
        assert_eq!(err.message(), "No model matches : missing default");
    }

    #[test]
    fn select_model_picks_sysv_for_rdi_rsi_arguments() {
        let m = merged(&[model(MS), model(SYSV)]);
        let params = vec![assigned_param(reg(0x38), 8), assigned_param(reg(0x30), 8)];
        assert_eq!(m.select_model(&params.iter().map(|p| p.as_ref()).collect::<Vec<_>>()).unwrap().get_name().as_deref(), Some("__stdcall"));
    }

    #[test]
    fn select_model_prefers_lower_score_over_declaration_order() {
        // RCX/RDX are slots 0/1 of the Microsoft model (score 0) but slots 3/2 of System V, which
        // leaves holes at slots 0 and 1 (penalty 16 + 10). System V is declared first.
        let m = merged(&[model(SYSV), model(MS)]);
        let params = vec![assigned_param(reg(0x8), 8), assigned_param(reg(0x10), 8)];
        assert_eq!(m.select_model(&params.iter().map(|p| p.as_ref()).collect::<Vec<_>>()).unwrap().get_name().as_deref(), Some("__fastcall"));
    }

    #[test]
    fn select_model_counts_mismatches() {
        // RDI is not a Microsoft parameter register: one mismatch (20) for __fastcall.
        let m = merged(&[model(MS), model(SYSV)]);
        let params = vec![assigned_param(reg(0x38), 8)];
        assert_eq!(m.select_model(&params.iter().map(|p| p.as_ref()).collect::<Vec<_>>()).unwrap().get_name().as_deref(), Some("__stdcall"));
    }

    #[test]
    fn select_model_skips_unassigned_storage() {
        let m = merged(&[model(MS)]);
        let params = vec![assigned_param(reg(0x8), 8), unassigned_param(4)];
        assert_eq!(m.select_model(&params.iter().map(|p| p.as_ref()).collect::<Vec<_>>()).unwrap().get_name().as_deref(), Some("__fastcall"));
    }

    #[test]
    fn is_equivalent_compares_by_kind_and_submodel_names() {
        let (sysv, ms) = (model(SYSV), model(MS));
        assert!(merged(&[sysv.clone(), ms.clone()]).is_equivalent(&merged(&[sysv.clone(), ms.clone()])));
        assert!(!merged(&[sysv.clone()]).is_equivalent(&merged(&[sysv.clone(), ms.clone()])));
        assert!(!merged(&[sysv.clone()]).is_equivalent(&merged(&[ms.clone()])));
        assert!(!merged(&[sysv.clone()]).is_equivalent(&sysv));
        assert!(!sysv.is_equivalent(&merged(&[sysv.clone()])));
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

        let m = merged(&[model(SYSV), model(MS)]);
        let mut encoder = RecordingEncoder::default();
        m.encode(&mut encoder, None).unwrap();
        assert_eq!(encoder.opened, vec![ELEM_RESOLVEPROTOTYPE, ELEM_MODEL, ELEM_MODEL]);
        assert_eq!(encoder.closed, vec![ELEM_MODEL, ELEM_MODEL, ELEM_RESOLVEPROTOTYPE]);
        assert!(encoder.strings.contains(&(ATTRIB_NAME, "merged".to_string())));
        assert!(encoder.strings.contains(&(ATTRIB_NAME, "__stdcall".to_string())));
        assert!(encoder.strings.contains(&(ATTRIB_NAME, "__fastcall".to_string())));
    }
}
