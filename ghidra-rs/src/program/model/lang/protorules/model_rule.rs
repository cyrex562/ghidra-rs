use std::sync::Arc;

use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::protorules::and_filter::AndFilter;
use crate::program::model::lang::protorules::assign_action::{
    restore_action_xml, restore_precondition_xml, restore_sideeffect_xml, AssignAction, FAIL,
};
use crate::program::model::lang::protorules::datatype_filter::{self, DatatypeFilter};
use crate::program::model::lang::protorules::qualifier_filter::{self, QualifierFilter};
use crate::program::model::pcode::{Encoder, ELEM_RULE};
use crate::program::model::lang::param_list_standard::ParamListStandard;
use crate::program::seam_stubs::{ParameterPieces, PrototypePieces};
use crate::util::exception::InvalidInputException;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// A rule controlling how parameters are assigned addresses.
///
/// Rules are applied to a parameter in the context of a full function prototype. A rule applies
/// only for a specific class of data-type associated with the parameter, as determined by its
/// [`DatatypeFilter`], and may have other criteria limiting when it applies (via
/// [`QualifierFilter`]).
///
/// Port of `ghidra.program.model.lang.protorules.ModelRule`.
///
/// # `Option`/empty-`Vec` vs. Java `null`
///
/// Java's no-arg constructor leaves `filter`/`qualifier`/`assign` `null` and never initializes
/// `preconditions`/`sideeffects` at all (they'd only become valid arrays once `restoreXml`
/// populates them) -- every other real code path (the two other constructors, or `restoreXml`
/// itself) fully populates all five fields. This port represents that same "not configured yet"
/// state with `Option::None` for the singular fields and an empty `Vec` for the two lists (rather
/// than an uninitialized/nullable array), which is unconditionally safe to read from -- no
/// behavior change for any real, fully-constructed `ModelRule`, just no null-pointer risk for one
/// that (mirroring the Java class) was never fully configured.
pub struct ModelRule {
    /// Which data-types this rule applies to (`ModelRule.filter`).
    filter: Option<Box<dyn DatatypeFilter>>,
    /// Additional qualifiers for when the rule should apply, if any (`ModelRule.qualifier`).
    qualifier: Option<Box<dyn QualifierFilter>>,
    /// How the Address should be assigned (`ModelRule.assign`).
    assign: Option<Box<dyn AssignAction>>,
    /// Extra actions that happen before assignment, discarded on failure
    /// (`ModelRule.preconditions`).
    preconditions: Vec<Box<dyn AssignAction>>,
    /// Extra actions that happen on success (`ModelRule.sideeffects`).
    sideeffects: Vec<Box<dyn AssignAction>>,
}

impl ModelRule {
    /// Port of the no-arg constructor.
    pub fn new() -> Self {
        ModelRule {
            filter: None,
            qualifier: None,
            assign: None,
            preconditions: Vec::new(),
            sideeffects: Vec::new(),
        }
    }

    /// Port of the copy constructor.
    ///
    /// # Errors
    /// Returns an error if necessary resources are not present in `res`.
    pub fn from_copy(
        op2: &ModelRule,
        res: &ParamListStandard,
    ) -> Result<Self, InvalidInputException> {
        let filter = op2.filter.as_ref().map(|f| f.clone_box());
        let qualifier = op2.qualifier.as_ref().map(|q| q.clone_box());
        let assign = match &op2.assign {
            Some(a) => Some(a.clone_box(res)?),
            None => None,
        };
        let mut preconditions = Vec::with_capacity(op2.preconditions.len());
        for p in &op2.preconditions {
            preconditions.push(p.clone_box(res)?);
        }
        let mut sideeffects = Vec::with_capacity(op2.sideeffects.len());
        for s in &op2.sideeffects {
            sideeffects.push(s.clone_box(res)?);
        }
        Ok(ModelRule { filter, qualifier, assign, preconditions, sideeffects })
    }

    /// Construct from components.
    ///
    /// The provided components are cloned into the new object.
    ///
    /// # Errors
    /// Returns an error if necessary resources are missing from `res`.
    pub fn from_components(
        type_filter: &dyn DatatypeFilter,
        action: &dyn AssignAction,
        res: &ParamListStandard,
    ) -> Result<Self, InvalidInputException> {
        Ok(ModelRule {
            filter: Some(type_filter.clone_box()),
            qualifier: None,
            assign: Some(action.clone_box(res)?),
            preconditions: Vec::new(),
            sideeffects: Vec::new(),
        })
    }

    /// Decode this rule from a stream.
    ///
    /// Port of `ModelRule.restoreXml`.
    ///
    /// # Errors
    /// Returns an error for problems decoding the stream, or if resources are missing.
    pub fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        res: &ParamListStandard,
    ) -> Result<(), XmlParseException> {
        parser
            .start(&[ELEM_RULE.name])
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        self.filter = Some(datatype_filter::restore_filter_xml(parser)?);

        let mut qualifier_list: Vec<Box<dyn QualifierFilter>> = Vec::new();
        while let Some(tmp_filter) = qualifier_filter::restore_filter_xml(parser)? {
            qualifier_list.push(tmp_filter);
        }
        self.qualifier = match qualifier_list.len() {
            0 => None,
            1 => qualifier_list.into_iter().next(),
            _ => Some(Box::new(AndFilter::new(qualifier_list)) as Box<dyn QualifierFilter>),
        };

        let mut preconditions = Vec::new();
        while let Some(pre_action) = restore_precondition_xml(parser, res)? {
            preconditions.push(pre_action);
        }
        self.preconditions = preconditions;

        self.assign = Some(restore_action_xml(parser, res)?);

        let mut sideeffects = Vec::new();
        loop {
            let peeked = parser.peek();
            if !peeked.is_start() {
                break;
            }
            sideeffects.push(restore_sideeffect_xml(parser, res)?);
        }
        self.sideeffects = sideeffects;

        parser
            .end()
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        Ok(())
    }
}

impl Default for ModelRule {
    fn default() -> Self {
        Self::new()
    }
}

impl ModelRule {
    /// Assign an address and other details for a specific parameter or for return storage in
    /// context, allocating from `resource`. Returns an `AssignAction` response code; [`FAIL`] if
    /// the rule's filters don't match.
    ///
    /// Port of `ModelRule.assignAddress`. `resource` is the owning `ParamListStandard` (Java's
    /// actions hold it as a field; see [`ParamListStandard`]'s doc).
    #[allow(clippy::too_many_arguments)]
    pub fn assign_address(
        &self,
        resource: &ParamListStandard,
        dt: &Arc<dyn DataType>,
        proto: &PrototypePieces,
        pos: i32,
        dt_manager: &dyn DataTypeManager,
        status: &mut [i32],
        res: &mut ParameterPieces,
    ) -> i32 {
        // Java doesn't null-check `filter` here at all (a fully-constructed ModelRule always has
        // one); this port fails defensively instead of the equivalent unchecked-null-deref risk.
        let Some(filter) = &self.filter else {
            return FAIL;
        };
        if !filter.filter(dt.as_ref()) {
            return FAIL;
        }
        if let Some(qualifier) = &self.qualifier {
            if !qualifier.filter(proto, pos) {
                return FAIL;
            }
        }

        let mut tmp_status = status.to_vec();
        // Precondition response codes are discarded, matching Java exactly -- a failing
        // precondition doesn't abort the rule.
        for precondition in &self.preconditions {
            precondition.assign_address(resource, dt, proto, pos, dt_manager, &mut tmp_status, res);
        }

        let Some(assign) = &self.assign else {
            return FAIL;
        };
        let response = assign.assign_address(resource, dt, proto, pos, dt_manager, &mut tmp_status, res);
        if response != FAIL {
            status.copy_from_slice(&tmp_status);
            // Side-effect response codes are discarded too, matching Java exactly.
            for sideeffect in &self.sideeffects {
                sideeffect.assign_address(resource, dt, proto, pos, dt_manager, status, res);
            }
        }
        response
    }

    /// Encode this rule to a stream.
    ///
    /// Port of `ModelRule.encode`.
    ///
    /// # Errors
    /// Returns an error for problems writing to the stream.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        encoder.open_element(ELEM_RULE)?;
        if let Some(filter) = &self.filter {
            filter.encode(encoder)?;
        }
        if let Some(qualifier) = &self.qualifier {
            qualifier.encode(encoder)?;
        }
        for precondition in &self.preconditions {
            precondition.encode(encoder)?;
        }
        if let Some(assign) = &self.assign {
            assign.encode(encoder)?;
        }
        for sideeffect in &self.sideeffects {
            sideeffect.encode(encoder)?;
        }
        encoder.close_element(ELEM_RULE)?;
        Ok(())
    }

    /// Determine if this rule has the same encoding as another.
    ///
    /// Port of `ModelRule.isEquivalent`.
    pub fn is_equivalent(&self, other: &ModelRule) -> bool {
        match (&self.assign, &other.assign) {
            (None, None) => {}
            (Some(a), Some(b)) => {
                if !a.is_equivalent(b.as_ref()) {
                    return false;
                }
            }
            _ => return false,
        }
        match (&self.filter, &other.filter) {
            (None, None) => {}
            (Some(a), Some(b)) => {
                if !a.is_equivalent(b.as_ref()) {
                    return false;
                }
            }
            _ => return false,
        }
        match (&self.qualifier, &other.qualifier) {
            (None, None) => {}
            (Some(a), Some(b)) => {
                if !a.is_equivalent(b.as_ref()) {
                    return false;
                }
            }
            _ => return false,
        }
        if self.preconditions.len() != other.preconditions.len() {
            return false;
        }
        for (a, b) in self.preconditions.iter().zip(other.preconditions.iter()) {
            if !a.is_equivalent(b.as_ref()) {
                return false;
            }
        }
        if self.sideeffects.len() != other.sideeffects.len() {
            return false;
        }
        for (a, b) in self.sideeffects.iter().zip(other.sideeffects.iter()) {
            if !a.is_equivalent(b.as_ref()) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::protorules::assign_action::SUCCESS;
    use crate::program::model::lang::protorules::goto_stack::GotoStack;
    use crate::program::model::lang::protorules::homogeneous_aggregate::HomogeneousAggregate;
    use crate::program::model::lang::protorules::meta_type_filter::MetaTypeFilter;
    use crate::program::model::lang::protorules::param_test_support::{
        ram_space, stack_space, TestEntry, TestLanguage, TestResource,
    };
    use crate::program::model::lang::protorules::position_match_filter::PositionMatchFilter;
    use crate::program::model::lang::protorules::size_restricted_filter::SizeRestrictedFilter;
    use crate::program::model::lang::protorules::varargs_filter::VarargsFilter;
    use crate::program::model::lang::protorules::xml_test_support::{MockElement, QueueParser};
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::storage_class::StorageClass;
    use crate::program::model::pcode::pcode_data_type_manager::TYPE_INT;
    use crate::program::model::pcode::{AttributeId, ElementId};

    struct MockDataType {
        length: i32,
    }
    impl DataType for MockDataType {
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_alignment(&self) -> i32 {
            self.length
        }
        fn is_integer_type(&self) -> bool {
            true
        }
        fn is_signed_integer_type(&self) -> bool {
            true
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    fn with_language(entries: Vec<TestEntry>) -> ParamListStandard {
        let num_group = entries.len() as i32;
        TestResource { entries, num_group, spacebase: None }
            .build_with_language(Some(Arc::new(TestLanguage { big_endian: false }) as Arc<dyn Language>))
    }

    fn stack_resource() -> ParamListStandard {
        with_language(vec![TestEntry {
            space: stack_space(),
            group: 0,
            align: 4,
            numslots: 8,
            addressbase: 0,
            ..TestEntry::default()
        }])
    }

    fn int_dt() -> Arc<dyn DataType> {
        Arc::new(MockDataType { length: 4 })
    }

    #[test]
    fn new_is_not_equivalent_to_a_fully_built_rule() {
        // Bare `new()` (filter/qualifier/assign all None) is a distinct state from any
        // fully-configured rule.
        let bare = ModelRule::new();
        let action = GotoStack::new(&stack_resource()).unwrap();
        let filter = SizeRestrictedFilter::new();
        let built = ModelRule::from_components(&filter, &action, &stack_resource()).unwrap();
        assert!(!bare.is_equivalent(&built));
    }

    #[test]
    fn assign_address_composes_filter_and_action() {
        let action = GotoStack::new(&stack_resource()).unwrap();
        let filter = SizeRestrictedFilter::new(); // "any" filter: matches everything
        let rule = ModelRule::from_components(&filter, &action, &stack_resource()).unwrap();

        let dt = int_dt();
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut status = [0i32; 1];
        let mut res = ParameterPieces::default();

        let code = rule.assign_address(&stack_resource(), &dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, SUCCESS);
        assert_eq!(status[0], 1); // one stack slot consumed
    }

    #[test]
    fn assign_address_fails_when_the_datatype_filter_rejects() {
        // HomogeneousAggregate(TYPE_INT) only matches aggregates whose primitives are all
        // TYPE_INT; a bare, non-aggregate MockDataType is rejected outright by `filter`, well
        // before the underlying GotoStack action ever runs.
        let action = GotoStack::new(&stack_resource()).unwrap();
        let filter = HomogeneousAggregate::with_bounds("int-aggregate", TYPE_INT, 4, 0, 0);
        let rule = ModelRule::from_components(&filter, &action, &stack_resource()).unwrap();

        let dt = int_dt();
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut status = [0i32; 1];
        let mut res = ParameterPieces::default();

        let code = rule.assign_address(&stack_resource(), &dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, FAIL);
        assert_eq!(status[0], 0); // no resources consumed on a filter rejection
    }

    #[test]
    fn assign_address_fails_when_the_qualifier_rejects() {
        let action = GotoStack::new(&stack_resource()).unwrap();
        let filter = SizeRestrictedFilter::new();
        let mut rule = ModelRule::from_components(&filter, &action, &stack_resource()).unwrap();
        rule.qualifier = Some(Box::new(PositionMatchFilter::new(3))); // only matches pos == 3

        let dt = int_dt();
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut status = [0i32; 1];
        let mut res = ParameterPieces::default();

        let code = rule.assign_address(&stack_resource(), &dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, FAIL);
    }

    #[test]
    fn assign_address_commits_side_effects_only_on_success() {
        // Two-entry resource: group 0 is a stack entry the primary GotoStack action consumes,
        // group 1 is a second stack-space entry (a distinct ParamEntry, so ExtraStack's `already
        // on the stack` short-circuit doesn't apply) that a ConsumeExtra side-effect consumes.
        use crate::program::model::lang::protorules::consume_extra::ConsumeExtra;

        let resource = with_language(vec![
                TestEntry {
                    ty: StorageClass::General,
                    space: ram_space(),
                    group: 0,
                    align: 0,
                    size: 4,
                    addressbase: 0x1000,
                    ..TestEntry::default()
                },
                TestEntry {
                    ty: StorageClass::General,
                    space: ram_space(),
                    group: 1,
                    align: 0,
                    size: 4,
                    addressbase: 0x2000,
                    ..TestEntry::default()
                },
            ]);

        let action = crate::program::model::lang::protorules::consume_as::ConsumeAs::new(StorageClass::General);
        let filter = SizeRestrictedFilter::new();
        let mut rule = ModelRule::from_components(&filter, &action, &resource).unwrap();
        let sideeffect = ConsumeExtra::new(StorageClass::General, true, &resource).unwrap();
        rule.sideeffects.push(Box::new(sideeffect));

        let dt = int_dt();
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut status = [0i32; 2];
        let mut res = ParameterPieces::default();

        let code = rule.assign_address(&resource, &dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, SUCCESS);
        // ConsumeAs alone would only ever touch group 0; group 1 being consumed too proves the
        // side-effect ran.
        assert_eq!(status, [-1, -1]);
    }

    #[test]
    fn from_copy_produces_an_equivalent_independent_rule() {
        let action = GotoStack::new(&stack_resource()).unwrap();
        let filter = SizeRestrictedFilter::new();
        let original = ModelRule::from_components(&filter, &action, &stack_resource()).unwrap();
        let copy = ModelRule::from_copy(&original, &stack_resource()).unwrap();
        assert!(original.is_equivalent(&copy));
    }

    #[test]
    fn is_equivalent_detects_a_different_filter() {
        let action = GotoStack::new(&stack_resource()).unwrap();
        let filter_a = SizeRestrictedFilter::with_min_max(0, 4);
        let filter_b = SizeRestrictedFilter::with_min_max(0, 8);
        let rule_a = ModelRule::from_components(&filter_a, &action, &stack_resource()).unwrap();
        let rule_b = ModelRule::from_components(&filter_b, &action, &stack_resource()).unwrap();
        assert!(!rule_a.is_equivalent(&rule_b));
    }

    #[test]
    fn is_equivalent_detects_a_different_action() {
        let filter = SizeRestrictedFilter::new();
        let action_a = GotoStack::new(&stack_resource()).unwrap();
        let action_b = crate::program::model::lang::protorules::consume_as::ConsumeAs::new(StorageClass::General);
        let rule_a = ModelRule::from_components(&filter, &action_a, &stack_resource()).unwrap();
        let rule_b = ModelRule::from_components(&filter, &action_b, &stack_resource()).unwrap();
        assert!(!rule_a.is_equivalent(&rule_b));
    }

    struct RecordingEncoder {
        elements: Vec<&'static str>,
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
        fn write_bool(&mut self, _attrib_id: AttributeId, _val: bool) -> std::io::Result<()> {
            Ok(())
        }
        fn write_signed_integer(&mut self, _attrib_id: AttributeId, _val: i64) -> std::io::Result<()> {
            Ok(())
        }
        fn write_unsigned_integer(&mut self, _attrib_id: AttributeId, _val: u64) -> std::io::Result<()> {
            Ok(())
        }
        fn write_string(&mut self, _attrib_id: AttributeId, _val: &str) -> std::io::Result<()> {
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
    fn encode_wraps_filter_and_action_in_a_rule_element() {
        let action = GotoStack::new(&stack_resource()).unwrap();
        let filter = SizeRestrictedFilter::new();
        let rule = ModelRule::from_components(&filter, &action, &stack_resource()).unwrap();
        let mut enc = RecordingEncoder { elements: Vec::new() };
        rule.encode(&mut enc).unwrap();
        assert_eq!(enc.elements.first(), Some(&"rule"));
        assert_eq!(enc.elements.last(), Some(&"rule"));
        assert!(enc.elements.contains(&"datatype")); // SizeRestrictedFilter's element
        assert!(enc.elements.contains(&"goto_stack")); // GotoStack's element
    }

    #[test]
    fn restore_xml_round_trips_filter_qualifier_and_action() {
        // <rule><datatype name="any"/><varargs/><goto_stack/></rule>
        let mut parser = QueueParser::new(vec![
            MockElement::start("rule", 0, &[]),
            MockElement::start("datatype", 1, &[("name", "any")]),
            MockElement::end("datatype", 1),
            MockElement::start("varargs", 1, &[]),
            MockElement::end("varargs", 1),
            MockElement::start("goto_stack", 1, &[]),
            MockElement::end("goto_stack", 1),
            MockElement::end("rule", 0),
        ]);
        let mut rule = ModelRule::new();
        rule.restore_xml(&mut parser, &stack_resource()).unwrap();

        assert!(rule.filter.as_ref().unwrap().as_any().downcast_ref::<SizeRestrictedFilter>().is_some());
        assert!(rule.qualifier.as_ref().unwrap().as_any().downcast_ref::<VarargsFilter>().is_some());
        assert!(rule.assign.as_ref().unwrap().as_any().downcast_ref::<GotoStack>().is_some());
        assert!(rule.preconditions.is_empty());
        assert!(rule.sideeffects.is_empty());
    }

    #[test]
    fn restore_xml_combines_multiple_qualifiers_into_an_and_filter() {
        // <rule><datatype name="any"/><varargs/><position index="0"/><goto_stack/></rule>
        let mut parser = QueueParser::new(vec![
            MockElement::start("rule", 0, &[]),
            MockElement::start("datatype", 1, &[("name", "any")]),
            MockElement::end("datatype", 1),
            MockElement::start("varargs", 1, &[]),
            MockElement::end("varargs", 1),
            MockElement::start("position", 1, &[("index", "0")]),
            MockElement::end("position", 1),
            MockElement::start("goto_stack", 1, &[]),
            MockElement::end("goto_stack", 1),
            MockElement::end("rule", 0),
        ]);
        let mut rule = ModelRule::new();
        rule.restore_xml(&mut parser, &stack_resource()).unwrap();
        assert!(rule.qualifier.as_ref().unwrap().as_any().downcast_ref::<AndFilter>().is_some());
    }

    #[test]
    fn restore_xml_falls_back_to_a_metatype_filter_name() {
        // <rule><datatype name="int"/><goto_stack/></rule> -- "int" isn't a recognized filter
        // name, so DatatypeFilter::restore_filter_xml resolves it as a decompiler metatype.
        let mut parser = QueueParser::new(vec![
            MockElement::start("rule", 0, &[]),
            MockElement::start("datatype", 1, &[("name", "int")]),
            MockElement::end("datatype", 1),
            MockElement::start("goto_stack", 1, &[]),
            MockElement::end("goto_stack", 1),
            MockElement::end("rule", 0),
        ]);
        let mut rule = ModelRule::new();
        rule.restore_xml(&mut parser, &stack_resource()).unwrap();
        let meta_filter = rule.filter.as_ref().unwrap().as_any().downcast_ref::<MetaTypeFilter>();
        assert!(meta_filter.is_some());
    }

    #[test]
    fn restore_xml_reads_no_qualifiers() {
        // <rule><datatype name="any"/><goto_stack/></rule>
        let mut parser = QueueParser::new(vec![
            MockElement::start("rule", 0, &[]),
            MockElement::start("datatype", 1, &[("name", "any")]),
            MockElement::end("datatype", 1),
            MockElement::start("goto_stack", 1, &[]),
            MockElement::end("goto_stack", 1),
            MockElement::end("rule", 0),
        ]);
        let mut rule = ModelRule::new();
        rule.restore_xml(&mut parser, &stack_resource()).unwrap();
        assert!(rule.qualifier.is_none());
    }

    #[test]
    fn restore_xml_reads_preconditions_and_sideeffects() {
        // <rule><datatype name="any"/><consume_extra storage="general" matchsize="true"/>
        //   <goto_stack/><consume_extra storage="general" matchsize="true"/></rule>
        let resource = with_language(vec![
                TestEntry {
                    ty: StorageClass::General,
                    space: ram_space(),
                    group: 0,
                    align: 0,
                    size: 4,
                    ..TestEntry::default()
                },
                TestEntry {
                    space: stack_space(),
                    group: 1,
                    align: 4,
                    numslots: 8,
                    ..TestEntry::default()
                },
            ]);
        let mut parser = QueueParser::new(vec![
            MockElement::start("rule", 0, &[]),
            MockElement::start("datatype", 1, &[("name", "any")]),
            MockElement::end("datatype", 1),
            MockElement::start("consume_extra", 1, &[("storage", "general"), ("matchsize", "true")]),
            MockElement::end("consume_extra", 1),
            MockElement::start("goto_stack", 1, &[]),
            MockElement::end("goto_stack", 1),
            MockElement::start("consume_extra", 1, &[("storage", "general"), ("matchsize", "true")]),
            MockElement::end("consume_extra", 1),
            MockElement::end("rule", 0),
        ]);
        let mut rule = ModelRule::new();
        rule.restore_xml(&mut parser, &resource).unwrap();
        assert_eq!(rule.preconditions.len(), 1);
        assert_eq!(rule.sideeffects.len(), 1);
    }

    #[test]
    fn restore_xml_errors_on_unknown_action_name() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("rule", 0, &[]),
            MockElement::start("datatype", 1, &[("name", "any")]),
            MockElement::end("datatype", 1),
            MockElement::start("not_a_real_action", 1, &[]),
            MockElement::end("not_a_real_action", 1),
        ]);
        let mut rule = ModelRule::new();
        assert!(rule.restore_xml(&mut parser, &stack_resource()).is_err());
    }
}
