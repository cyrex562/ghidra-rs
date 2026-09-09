use std::any::Any;
use std::sync::Arc;

use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::pcode::{Encoder, Varnode};
use crate::program::seam_stubs::{ParamListStandardLike, ParameterPieces, PrototypePieces};
use crate::util::exception::InvalidInputException;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Response code: the data-type is fully assigned.
pub const SUCCESS: i32 = 0;
/// Response code: the action could not be applied.
pub const FAIL: i32 = 1;
/// Response code: do not assign a storage location.
pub const NO_ASSIGNMENT: i32 = 2;
/// Response code: a hidden return pointer is needed as the first input parameter.
pub const HIDDENRET_PTRPARAM: i32 = 3;
/// Response code: a hidden return pointer is needed in a special register.
pub const HIDDENRET_SPECIALREG: i32 = 4;
/// Response code: a hidden return pointer is needed, but there is no normal return.
pub const HIDDENRET_SPECIALREG_VOID: i32 = 5;

/// An action that assigns an Address to a function prototype parameter.
///
/// A request for the address of either return storage or an input parameter is made through
/// [`assign_address`](AssignAction::assign_address), which is given full information about the
/// function prototype. Details about how the action performs are configured through
/// [`restore_xml`](AssignAction::restore_xml).
///
/// Port of `ghidra.program.model.lang.protorules.AssignAction`.
///
/// The Java class also declares static factory methods `restoreActionXml`,
/// `restoreSideeffectXml`, and `restorePreconditionXml` that inspect the root element of an XML
/// stream and dispatch to one of `GotoStack`, `MultiSlotAssign`, `ConsumeAs`,
/// `ConvertToPointer`, `HiddenReturnAssign`, `MultiMemberAssign`, `MultiSlotDualAssign`,
/// `ConsumeExtra`, `ExtraStack`, or `ConsumeRemaining`. Now that every one of those sibling
/// actions is ported, these are ported too as free functions below --
/// [`restore_action_xml`], [`restore_sideeffect_xml`], [`restore_precondition_xml`] -- needed by
/// [`ModelRule::restore_xml`](super::model_rule::ModelRule::restore_xml).
pub trait AssignAction {
    /// Make a copy of this action, to be owned by `new_resource`.
    ///
    /// Port of the Java `clone(ParamListStandard)` method; renamed because `clone` returning
    /// `Self` is not object-safe.
    ///
    /// # Errors
    /// Returns an error if required configuration is not present in the new resource object.
    fn clone_box(
        &self,
        new_resource: Arc<dyn ParamListStandardLike>,
    ) -> Result<Box<dyn AssignAction>, InvalidInputException>;

    /// Returns this action as [`std::any::Any`], so that [`is_equivalent`](Self::is_equivalent)
    /// implementations can downcast `op` to a concrete type.
    ///
    /// Every Java implementer of `isEquivalent` starts with a `getClass() != op.getClass()`
    /// check and then casts `op` to its own concrete type; `downcast_ref` on the value returned
    /// here is the Rust equivalent of that pattern.
    fn as_any(&self) -> &dyn Any;

    /// Test if the given action is configured and performs identically to this one.
    fn is_equivalent(&self, op: &dyn AssignAction) -> bool;

    /// Assign an address and other meta-data for a specific parameter or for return storage in
    /// context.
    ///
    /// The Address is assigned based on the data-type of the parameter, available register
    /// resources, and other details of the function prototype. Consumed resources are marked in
    /// `status`.
    ///
    /// `pos` is the position of the parameter (`pos >= 0`) or return storage (`pos == -1`).
    ///
    /// Returns a response code: [`SUCCESS`] if the Address was successfully assigned, [`FAIL`]
    /// if the Address could not be assigned, or [`HIDDENRET_PTRPARAM`] (among other
    /// `HIDDENRET_*` codes) if an additional hidden return parameter is required.
    ///
    /// Takes `dt` as `&Arc<dyn DataType>` rather than `&dyn DataType` (unlike, e.g.,
    /// [`DatatypeFilter::filter`](super::datatype_filter::DatatypeFilter::filter), which only
    /// *inspects* a data-type): several real implementors (`ConsumeAs`, `ConvertToPointer`,
    /// `MultiMemberAssign`) need to either store `dt` into
    /// [`ParameterPieces::data_type`](crate::program::seam_stubs::ParameterPieces::data_type)
    /// (an `Option<Arc<dyn DataType>>`) or hand it on to
    /// [`ParamListStandardLike::assign_address`](crate::program::seam_stubs::ParamListStandardLike::assign_address)/
    /// `assign_address_fallback` (which are already `Arc`-based, matching how
    /// [`PrototypePieces::intypes`](crate::program::seam_stubs::PrototypePieces::intypes) stores
    /// its data-types). `DataType` has no generic `clone()` to mint an owned/`Arc`'d copy from a
    /// bare `&dyn DataType`, so a borrowed signature here would make those real call sites
    /// impossible to implement without an unsound workaround. Changed from `&dyn DataType` when
    /// this package's `AssignAction` implementors were ported (2026-09-09); at that point this
    /// trait had exactly one implementor in the whole crate (the test-only `GotoStackMockAction`
    /// below), so the change carried no blast radius beyond this file.
    fn assign_address(
        &self,
        dt: &Arc<dyn DataType>,
        proto: &PrototypePieces,
        pos: i32,
        dt_manager: &dyn DataTypeManager,
        status: &mut [i32],
        res: &mut ParameterPieces,
    ) -> i32;

    /// Save this action and its configuration to a stream.
    ///
    /// # Errors
    /// Returns an error for problems writing to the stream.
    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()>;

    /// Configure any details of how this action should behave from the stream.
    ///
    /// Generic over the parser implementation (rather than a trait object) because
    /// [`XmlPullParser`] is not object-safe; this keeps [`AssignAction`] itself dyn-compatible
    /// for every other method.
    ///
    /// # Errors
    /// Returns an error if there are problems decoding the stream.
    fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), XmlParseException>
    where
        Self: Sized;
}

/// Adjust the final (or first) `Varnode` of a piece sequence so that a data-type smaller than
/// the full sequence is read from the correctly justified sub-range.
///
/// Port of the Java `AssignAction.justifyPieces` static method.
pub fn justify_pieces(
    pieces: &mut [Varnode],
    offset: i32,
    is_big_endian: bool,
    consume_most_sig: bool,
    justify_right: bool,
) {
    let add_offset = is_big_endian ^ consume_most_sig ^ justify_right;
    let pos = if justify_right { 0 } else { pieces.len() - 1 };

    let vn = &pieces[pos];
    let mut addr = vn.get_address().clone();
    if add_offset {
        addr = addr
            .add(offset as i64)
            .expect("address overflow while justifying pieces");
    }
    let sz = vn.get_size() - offset;
    pieces[pos] = Varnode::new(addr, sz);
}

/// Read the next action element from the stream and return the new configured, boxed action. If
/// the next element is not a recognized action, returns an error.
///
/// Port of the static `AssignAction.restoreActionXml`. A free function, not a trait method,
/// since [`restore_xml`](AssignAction::restore_xml) is generic (hence not part of the trait's
/// object-safe surface) -- each branch below therefore calls `restore_xml` on the concrete,
/// `Sized` action type *before* erasing it to `Box<dyn AssignAction>`, the same pattern as
/// [`DatatypeFilter::restore_filter_xml`](super::datatype_filter::restore_filter_xml).
///
/// # Errors
/// Returns an error if the resource list is missing configuration the chosen action needs, if
/// there are problems decoding the stream, or if the next element's name isn't a recognized
/// action.
pub fn restore_action_xml<P: XmlPullParser>(
    parser: &mut P,
    res: Arc<dyn ParamListStandardLike>,
) -> Result<Box<dyn AssignAction>, XmlParseException> {
    use crate::program::model::lang::protorules::consume_as::ConsumeAs;
    use crate::program::model::lang::protorules::convert_to_pointer::ConvertToPointer;
    use crate::program::model::lang::protorules::goto_stack::GotoStack;
    use crate::program::model::lang::protorules::hidden_return_assign::HiddenReturnAssign;
    use crate::program::model::lang::protorules::multi_member_assign::MultiMemberAssign;
    use crate::program::model::lang::protorules::multi_slot_assign::MultiSlotAssign;
    use crate::program::model::lang::protorules::multi_slot_dual_assign::MultiSlotDualAssign;
    use crate::program::model::lang::storage_class::StorageClass;
    use crate::program::model::pcode::{
        ELEM_CONSUME, ELEM_CONVERT_TO_PTR, ELEM_GOTO_STACK, ELEM_HIDDEN_RETURN, ELEM_JOIN,
        ELEM_JOIN_DUAL_CLASS, ELEM_JOIN_PER_PRIMITIVE,
    };

    let elem = parser.peek();
    let nm = elem.get_name().to_string();
    if nm == ELEM_GOTO_STACK.name {
        // GotoStack::new is eager (unlike Java's deferred `new GotoStack(res, 0)`), but
        // behaviorally equivalent here: GotoStack's stack-entry lookup depends on nothing an XML
        // attribute could override (goto_stack has no attributes at all), and restore_xml
        // re-runs the identical lookup unconditionally regardless.
        let mut action = GotoStack::new(res).map_err(|e| XmlParseException::new(e.0))?;
        action.restore_xml(parser)?;
        return Ok(Box::new(action));
    }
    if nm == ELEM_JOIN.name {
        let mut action = MultiSlotAssign::for_decode(res);
        action.restore_xml(parser)?;
        return Ok(Box::new(action));
    }
    if nm == ELEM_CONSUME.name {
        let mut action = ConsumeAs::new(StorageClass::General, res);
        action.restore_xml(parser)?;
        return Ok(Box::new(action));
    }
    if nm == ELEM_CONVERT_TO_PTR.name {
        let mut action = ConvertToPointer::new(res);
        action.restore_xml(parser)?;
        return Ok(Box::new(action));
    }
    if nm == ELEM_HIDDEN_RETURN.name {
        let mut action = HiddenReturnAssign::new(res, HIDDENRET_SPECIALREG);
        action.restore_xml(parser)?;
        return Ok(Box::new(action));
    }
    if nm == ELEM_JOIN_PER_PRIMITIVE.name {
        let most_sig = res.is_big_endian();
        let mut action = MultiMemberAssign::new(StorageClass::General, false, most_sig, res);
        action.restore_xml(parser)?;
        return Ok(Box::new(action));
    }
    if nm == ELEM_JOIN_DUAL_CLASS.name {
        let mut action = MultiSlotDualAssign::for_decode(res);
        action.restore_xml(parser)?;
        return Ok(Box::new(action));
    }
    Err(XmlParseException::new(format!("Unknown model rule action: {nm}")))
}

/// Read the next sideeffect element from the stream and return the new configured, boxed action.
/// If the next element is not a recognized sideeffect, returns an error.
///
/// Port of the static `AssignAction.restoreSideeffectXml`. See [`restore_action_xml`] for why
/// this is a free function.
///
/// # Errors
/// Returns an error if the resource list is missing configuration the chosen action needs, if
/// there are problems decoding the stream, or if the next element's name isn't a recognized
/// sideeffect.
pub fn restore_sideeffect_xml<P: XmlPullParser>(
    parser: &mut P,
    res: Arc<dyn ParamListStandardLike>,
) -> Result<Box<dyn AssignAction>, XmlParseException> {
    use crate::program::model::lang::protorules::consume_extra::ConsumeExtra;
    use crate::program::model::lang::protorules::consume_remaining::ConsumeRemaining;
    use crate::program::model::lang::protorules::extra_stack::ExtraStack;
    use crate::program::model::lang::storage_class::StorageClass;
    use crate::program::model::pcode::{ELEM_CONSUME_EXTRA, ELEM_CONSUME_REMAINING, ELEM_EXTRA_STACK};

    let elem = parser.peek();
    let nm = elem.get_name().to_string();
    if nm == ELEM_CONSUME_EXTRA.name {
        let mut action = ConsumeExtra::for_decode(res);
        action.restore_xml(parser)?;
        return Ok(Box::new(action));
    }
    if nm == ELEM_EXTRA_STACK.name {
        // ExtraStack::new is eager, but safe here: its stack-entry lookup is independent of
        // `afterStorage`/`afterBytes` (the only fields an XML attribute can override), matching
        // GotoStack's reasoning above.
        let mut action = ExtraStack::new(StorageClass::General, -1, res)
            .map_err(|e| XmlParseException::new(e.0))?;
        action.restore_xml(parser)?;
        return Ok(Box::new(action));
    }
    if nm == ELEM_CONSUME_REMAINING.name {
        let mut action = ConsumeRemaining::for_decode(res);
        action.restore_xml(parser)?;
        return Ok(Box::new(action));
    }
    Err(XmlParseException::new(format!("Unknown model rule sideeffect: {nm}")))
}

/// Read the next precondition element from the stream, if it exists, and return the new
/// configured, boxed action. If the next element is not a precondition, returns `Ok(None)`
/// without consuming it.
///
/// Port of the static `AssignAction.restorePreconditionXml`. See [`restore_action_xml`] for why
/// this is a free function.
///
/// # Errors
/// Returns an error if the resource list is missing configuration `ConsumeExtra` needs, or if
/// there are problems decoding the stream.
pub fn restore_precondition_xml<P: XmlPullParser>(
    parser: &mut P,
    res: Arc<dyn ParamListStandardLike>,
) -> Result<Option<Box<dyn AssignAction>>, XmlParseException> {
    use crate::program::model::lang::protorules::consume_extra::ConsumeExtra;
    use crate::program::model::pcode::ELEM_CONSUME_EXTRA;

    let elem = parser.peek();
    let nm = elem.get_name().to_string();
    if nm != ELEM_CONSUME_EXTRA.name {
        return Ok(None);
    }
    let mut action = ConsumeExtra::for_decode(res);
    action.restore_xml(parser)?;
    Ok(Some(Box::new(action)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::{AttributeId, ElementId};

    #[test]
    fn justify_pieces_adjusts_last_element_when_offset_and_flags_agree() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let mut pieces = vec![
            Varnode::new(Address::new(ram.clone(), 0x1000), 4),
            Varnode::new(Address::new(ram.clone(), 0x2000), 4),
        ];

        // is_big_endian ^ consume_most_sig ^ justify_right == true ^ false ^ false == true
        justify_pieces(&mut pieces, 1, true, false, false);

        let last = &pieces[1];
        assert_eq!(last.get_address().offset(), 0x2001);
        assert_eq!(last.get_size(), 3);
        // Untouched sibling piece is left alone.
        assert_eq!(pieces[0].get_address().offset(), 0x1000);
    }

    #[test]
    fn justify_pieces_leaves_address_unchanged_when_flags_cancel_out() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let mut pieces = vec![Varnode::new(Address::new(ram.clone(), 0x3000), 4)];

        // is_big_endian ^ consume_most_sig ^ justify_right == true ^ true ^ false == false
        justify_pieces(&mut pieces, 2, true, true, false);

        let piece = &pieces[0];
        assert_eq!(piece.get_address().offset(), 0x3000);
        assert_eq!(piece.get_size(), 2);
    }

    #[derive(Clone)]
    struct MockParamListStandard {
        big_endian: bool,
    }
    impl ParamListStandardLike for MockParamListStandard {}

    #[derive(Clone)]
    struct GotoStackMockAction {
        resource: Arc<dyn ParamListStandardLike>,
        stack_offset: i32,
    }

    impl AssignAction for GotoStackMockAction {
        fn clone_box(
            &self,
            new_resource: Arc<dyn ParamListStandardLike>,
        ) -> Result<Box<dyn AssignAction>, InvalidInputException> {
            Ok(Box::new(GotoStackMockAction {
                resource: new_resource,
                stack_offset: self.stack_offset,
            }))
        }

        fn as_any(&self) -> &dyn Any {
            self
        }

        fn is_equivalent(&self, op: &dyn AssignAction) -> bool {
            let Some(other) = op.as_any().downcast_ref::<GotoStackMockAction>() else {
                return false;
            };
            self.stack_offset == other.stack_offset
        }

        fn assign_address(
            &self,
            dt: &Arc<dyn DataType>,
            _proto: &PrototypePieces,
            pos: i32,
            _dt_manager: &dyn DataTypeManager,
            status: &mut [i32],
            _res: &mut ParameterPieces,
        ) -> i32 {
            let _ = dt;
            if pos < 0 {
                return FAIL;
            }
            status[0] += 1;
            SUCCESS
        }

        fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
            encoder.write_signed_integer(
                crate::program::model::pcode::ATTRIB_SIZE,
                self.stack_offset as i64,
            )
        }

        fn restore_xml<P: XmlPullParser>(
            &mut self,
            _parser: &mut P,
        ) -> Result<(), XmlParseException>
        where
            Self: Sized,
        {
            Ok(())
        }
    }

    struct MockDataType;
    impl DataType for MockDataType {}

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    struct NoopEncoder;
    impl Encoder for NoopEncoder {
        fn open_element(&mut self, _elem_id: ElementId) -> std::io::Result<()> {
            Ok(())
        }
        fn close_element(&mut self, _elem_id: ElementId) -> std::io::Result<()> {
            Ok(())
        }
        fn write_bool(&mut self, _attrib_id: AttributeId, _val: bool) -> std::io::Result<()> {
            Ok(())
        }
        fn write_signed_integer(
            &mut self,
            _attrib_id: AttributeId,
            _val: i64,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn write_unsigned_integer(
            &mut self,
            _attrib_id: AttributeId,
            _val: u64,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn write_string(&mut self, _attrib_id: AttributeId, _val: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn write_string_indexed(
            &mut self,
            _attrib_id: AttributeId,
            _index: i32,
            _val: &str,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn write_space(
            &mut self,
            _attrib_id: AttributeId,
            _spc: &crate::program::model::address::AddressSpace,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn write_space_indexed(
            &mut self,
            _attrib_id: AttributeId,
            _index: i32,
            _name: &str,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn write_opcode(
            &mut self,
            _attrib_id: AttributeId,
            _opcode: crate::decompiler::opcodes::op_code::OpCode,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn write_opcode_ordinal(
            &mut self,
            _attrib_id: AttributeId,
            _opcode: i32,
        ) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn usable_as_trait_object_and_assigns_address() {
        let resource: Arc<dyn ParamListStandardLike> =
            Arc::new(MockParamListStandard { big_endian: false });
        let action: Box<dyn AssignAction> = Box::new(GotoStackMockAction {
            resource,
            stack_offset: 8,
        });

        let dt: Arc<dyn DataType> = Arc::new(MockDataType);
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut res = ParameterPieces::default();
        let mut status = [0i32; 1];

        let code = action.assign_address(&dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, SUCCESS);
        assert_eq!(status[0], 1);

        let fail_code = action.assign_address(&dt, &proto, -1, &dt_manager, &mut status, &mut res);
        assert_eq!(fail_code, FAIL);
    }

    #[test]
    fn clone_box_produces_equivalent_independent_copy() {
        let resource: Arc<dyn ParamListStandardLike> =
            Arc::new(MockParamListStandard { big_endian: true });
        let action = GotoStackMockAction {
            resource: resource.clone(),
            stack_offset: 4,
        };

        let cloned = action.clone_box(resource).expect("clone should succeed");
        assert!(action.is_equivalent(cloned.as_ref()));

        let different = GotoStackMockAction {
            resource: Arc::new(MockParamListStandard { big_endian: true }),
            stack_offset: 5,
        };
        assert!(!action.is_equivalent(&different));
    }

    #[test]
    fn encode_reaches_the_stream() {
        let resource: Arc<dyn ParamListStandardLike> =
            Arc::new(MockParamListStandard { big_endian: false });
        let action = GotoStackMockAction {
            resource,
            stack_offset: 12,
        };
        let mut encoder = NoopEncoder;
        assert!(action.encode(&mut encoder).is_ok());
    }

    #[test]
    fn restore_action_xml_dispatches_goto_stack_and_join() {
        use crate::program::model::lang::protorules::param_test_support::{
            ram_space, stack_space, TestEntry, TestResource,
        };
        use crate::program::model::lang::protorules::xml_test_support::{MockElement, QueueParser};
        use crate::program::model::lang::protorules::goto_stack::GotoStack;
        use crate::program::model::lang::protorules::multi_slot_assign::MultiSlotAssign;
        use crate::program::model::lang::storage_class::StorageClass;

        let resource: Arc<dyn ParamListStandardLike> = Arc::new(TestResource {
            entries: vec![
                Arc::new(TestEntry {
                    ty: StorageClass::General,
                    group: 0,
                    align: 0,
                    space: ram_space(),
                    ..TestEntry::default()
                }),
                Arc::new(TestEntry {
                    space: stack_space(),
                    group: 1,
                    align: 4,
                    numslots: 8,
                    ..TestEntry::default()
                }),
            ],
            num_group: 2,
            spacebase: None,
        });

        let mut goto_parser = QueueParser::new(vec![
            MockElement::start("goto_stack", 0, &[]),
            MockElement::end("goto_stack", 0),
        ]);
        let goto_action = restore_action_xml(&mut goto_parser, resource.clone()).unwrap();
        assert!(goto_action.as_any().downcast_ref::<GotoStack>().is_some());

        let mut join_parser = QueueParser::new(vec![
            MockElement::start("join", 0, &[]),
            MockElement::end("join", 0),
        ]);
        let join_action = restore_action_xml(&mut join_parser, resource).unwrap();
        assert!(join_action.as_any().downcast_ref::<MultiSlotAssign>().is_some());
    }

    #[test]
    fn restore_action_xml_errors_on_unknown_action_name() {
        use crate::program::model::lang::protorules::xml_test_support::{MockElement, QueueParser};

        let resource: Arc<dyn ParamListStandardLike> =
            Arc::new(MockParamListStandard { big_endian: false });
        let mut parser = QueueParser::new(vec![
            MockElement::start("not_a_real_action", 0, &[]),
            MockElement::end("not_a_real_action", 0),
        ]);
        assert!(restore_action_xml(&mut parser, resource).is_err());
    }

    #[test]
    fn restore_sideeffect_xml_dispatches_consume_extra() {
        use crate::program::model::lang::protorules::param_test_support::{ram_space, TestEntry, TestResource};
        use crate::program::model::lang::protorules::xml_test_support::{MockElement, QueueParser};
        use crate::program::model::lang::protorules::consume_extra::ConsumeExtra;
        use crate::program::model::lang::storage_class::StorageClass;

        let resource: Arc<dyn ParamListStandardLike> = Arc::new(TestResource {
            entries: vec![Arc::new(TestEntry {
                ty: StorageClass::General,
                group: 0,
                align: 0,
                space: ram_space(),
                ..TestEntry::default()
            })],
            num_group: 1,
            spacebase: None,
        });
        let mut parser = QueueParser::new(vec![
            MockElement::start("consume_extra", 0, &[("storage", "general"), ("matchsize", "true")]),
            MockElement::end("consume_extra", 0),
        ]);
        let action = restore_sideeffect_xml(&mut parser, resource).unwrap();
        assert!(action.as_any().downcast_ref::<ConsumeExtra>().is_some());
    }

    #[test]
    fn restore_precondition_xml_returns_none_for_a_non_precondition_element() {
        use crate::program::model::lang::protorules::xml_test_support::{MockElement, QueueParser};

        let resource: Arc<dyn ParamListStandardLike> =
            Arc::new(MockParamListStandard { big_endian: false });
        let mut parser = QueueParser::new(vec![
            MockElement::start("goto_stack", 0, &[]),
            MockElement::end("goto_stack", 0),
        ]);
        assert!(restore_precondition_xml(&mut parser, resource).unwrap().is_none());
    }
}
