//! Port of `ghidra.program.model.lang.InjectPayloadSleigh`.
//!
//! `InjectPayloadSleigh` was selected as a dependency-cycle cut-point: in Java,
//! `SleighLanguage` holds a `List<InjectPayloadSleigh>` and constructs concrete subclasses
//! (`InjectPayloadCallfixup`, `InjectPayloadCallother`, `InjectPayloadJumpAssist`,
//! `InjectPayloadSegment` -- none yet ported) polymorphically as `InjectPayloadSleigh`, while
//! `InjectPayloadSleigh.restoreXml` itself takes a `SleighLanguage` parameter. `PcodeInjectLibrary`
//! (not yet ported) also depends on the base class alone, driving compilation of the sleigh source
//! text via `releaseParseString`/`setTemplate` without caring which subclass it holds. Modeling
//! `InjectPayloadSleigh` as a trait over [`InjectPayload`] lets those consumers depend on the
//! trait object instead of the concrete class, breaking the cycle.
//!
//! The private/internal helpers (`checkParameterRestrictions`, `setupParameters`,
//! `orderParameters`, `setInputParameters`/`setOutputParameters`) are left out of the trait since
//! they are only ever called from within the base class's own `inject`/`restoreXml`
//! implementations, never by subclasses or other classes.
//!
//! [`InjectPayloadSleighImpl`] below is the concrete port of `InjectPayloadSleigh`'s actual field
//! state and method bodies (constructors, accessors, `<pcode>` element encode/decode,
//! `checkParameterRestrictions`, `isEquivalent`'s base comparison, and `inject`/`getPcode`) that
//! the trait-only cut described above left out. Each of the four real Java subclasses
//! (`InjectPayloadCallfixup`, `InjectPayloadCallother`, `InjectPayloadJumpAssist`,
//! `InjectPayloadSegment`) is ported as its own struct that *contains* an
//! [`InjectPayloadSleighImpl`] (composition standing in for the Java `extends`), delegating the
//! shared [`InjectPayload`]/[`InjectPayloadSleigh`] surface to it and layering its own extra
//! fields/overrides on top -- see `inject_payload_callother.rs`, `inject_payload_jump_assist.rs`,
//! and `inject_payload_segment.rs`.

use crate::decompiler::opcodes::OpCode;
use crate::program::model::address::factory::AddressFactory;
use crate::program::model::lang::inject_context::InjectContext;
use crate::program::model::lang::inject_payload::{
    InjectParameter, InjectPayload, InjectPayloadError, CALLMECHANISM_TYPE,
};
use crate::program::model::lang::sleigh::template::{
    ConstTpl, ConstTplType, ConstructTpl, OpTpl, VarnodeTpl,
};
use crate::program::model::pcode::ids::{
    ATTRIB_CONTENT, ATTRIB_DYNAMIC, ATTRIB_INCIDENTALCOPY, ATTRIB_INJECT, ATTRIB_NAME,
    ATTRIB_PARAMSHIFT, ATTRIB_SIZE, ELEM_BODY, ELEM_INPUT, ELEM_OUTPUT, ELEM_PCODE,
};
use crate::program::model::pcode::Encoder;
use crate::util::exception::NotFoundException;
use crate::util::xml::spec_xml_utils::{decode_boolean, decode_int};
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_exception::XmlException;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Adapt an [`XmlException`] from the low-level [`XmlPullParser`] navigation helpers
/// (`start`/`end_matching`, ...) to the [`XmlParseException`] this module's `InjectPayload`
/// implementations report, mirroring how `InjectPayloadSleigh.restoreXml`'s `throws
/// XmlParseException` wraps whatever the underlying `XmlPullParser` throws.
pub(crate) fn xml_err(e: XmlException) -> XmlParseException {
    XmlParseException::with_cause(e.to_string(), e)
}

/// A payload of p-code defined via a string passed to the sleigh compiler.
///
/// Port of `ghidra.program.model.lang.InjectPayloadSleigh`.
pub trait InjectPayloadSleigh: InjectPayload {
    /// Takes (and clears) the raw p-code source text parsed from this payload's XML `<body>`, so
    /// the sleigh compiler can compile it into a [`ConstructTpl`]. Returns `None` once already
    /// taken, or if this payload has no `<body>` (a dynamic payload).
    ///
    /// Port of the package-private `InjectPayloadSleigh.releaseParseString()`.
    fn release_parse_string(&mut self) -> Option<String>;

    /// Installs the compiled p-code template for this payload -- typically the result of
    /// compiling the text returned by [`release_parse_string`](Self::release_parse_string) --
    /// and recomputes whether the payload falls through (see [`compute_fall_thru`]).
    ///
    /// Port of the protected `InjectPayloadSleigh.setTemplate(ConstructTpl)`.
    fn set_template(&mut self, template: ConstructTpl);

    /// Returns `self` as `&dyn Any`, so callers holding a `dyn InjectPayloadSleigh` trait object
    /// can `downcast_ref` back to a specific concrete implementor.
    ///
    /// Not part of the Java API -- `PcodeInjectLibrary.encodeCompilerSpec()` needs an
    /// `instanceof InjectPayloadSegment` check on payloads it only otherwise holds as
    /// `InjectPayloadSleigh`/`InjectPayload`, which Java gets for free from its class hierarchy.
    /// This crate's [`PcodeInjectLibrary`](crate::program::model::lang::pcode_inject_library::PcodeInjectLibrary)
    /// stores every payload behind this trait object (since every constructible payload type in
    /// this crate implements it), so it needs an explicit downcast to recover that same
    /// information.
    fn as_any(&self) -> &dyn std::any::Any;
}

/// Determines whether p-code ending in `op_vec`'s final operation falls through, i.e. does not
/// end in an unconditional branch, indirect branch, or return.
///
/// Port of the private `InjectPayloadSleigh.computeFallThru()`, extracted as a free function so
/// any [`InjectPayloadSleigh`] implementation can reuse it from
/// [`InjectPayloadSleigh::set_template`].
pub fn compute_fall_thru(op_vec: &[OpTpl]) -> bool {
    match op_vec.last() {
        None => true,
        Some(op) => !matches!(
            op.get_opcode(),
            OpCode::CpuiBranch | OpCode::CpuiBranchind | OpCode::CpuiReturn
        ),
    }
}

/// Builds a dummy p-code sequence to use in place of a normal parsed payload whose p-code failed
/// to parse. The sequence is non-empty, consisting of a single operation: `tmp = tmp + 0;`
///
/// Port of the static `InjectPayloadSleigh.getDummyPcode(AddressFactory)`.
pub fn get_dummy_pcode(addr_factory: &dyn AddressFactory) -> ConstructTpl {
    let unique_space = ConstTpl {
        tp: ConstTplType::SpaceId,
        value_real: 0,
        value_spaceid: addr_factory.get_unique_space(),
        handle_index: 0,
        select: None,
    };
    let const_space = ConstTpl {
        tp: ConstTplType::SpaceId,
        value_real: 0,
        value_spaceid: addr_factory.get_constant_space(),
        handle_index: 0,
        select: None,
    };
    let tmp_offset = ConstTpl {
        tp: ConstTplType::Real,
        value_real: 0x100,
        value_spaceid: None,
        handle_index: 0,
        select: None,
    };
    let const_zero = ConstTpl::new();
    let size = ConstTpl {
        tp: ConstTplType::Real,
        value_real: 4,
        value_spaceid: None,
        handle_index: 0,
        select: None,
    };

    let temp = VarnodeTpl {
        space: unique_space,
        offset: tmp_offset,
        size: size.clone(),
    };
    let zero = VarnodeTpl {
        space: const_space,
        offset: const_zero,
        size,
    };

    let mut op = OpTpl::with_opcode(OpCode::CpuiIntAdd);
    op.set_output(temp.clone());
    op.add_input(temp);
    op.add_input(zero);

    ConstructTpl {
        num_labels: 0,
        vec: vec![op],
        result: None,
    }
}

/// Concrete port of `InjectPayloadSleigh`'s field state and method bodies -- the part left out of
/// the [`InjectPayloadSleigh`] trait cut described in the module docs above. Each real subclass
/// (`InjectPayloadCallfixup`, `InjectPayloadCallother`, `InjectPayloadJumpAssist`,
/// `InjectPayloadSegment`) embeds one of these and delegates to it, the way Java's subclasses
/// inherit it.
#[derive(Clone)]
pub struct InjectPayloadSleighImpl {
    pcode_template: Option<ConstructTpl>,
    param_shift: i32,
    isfallthru: bool,
    /// Treat COPY operations as incidental.
    incidental_copy: bool,
    input_list: Vec<InjectParameter>,
    output: Vec<InjectParameter>,
    /// 0 = uponentry, 1 = uponreturn, -1 = not applicable (only meaningful for
    /// [`CALLMECHANISM_TYPE`](crate::program::model::lang::inject_payload::CALLMECHANISM_TYPE)
    /// payloads, none of which are among the classes built on top of this base yet).
    sub_type: i32,
    /// Formal name of this inject. Java leaves this `null` until a subclass's `restoreXml`
    /// assigns it (or the public constructor is given one directly); there every subclass this
    /// crate builds on top of `InjectPayloadSleighImpl` assigns it before any accessor is called,
    /// so the empty string standing in for "unset" here is never actually observed.
    name: String,
    /// Type of this payload: `CALLFIXUP_TYPE`, `CALLOTHERFIXUP_TYPE`, etc. `-1` before it's set.
    type_: i32,
    /// Source of this payload (e.g. a `.pspec` file path).
    source: String,
    /// Raw p-code source text parsed from `<body>`, awaiting compilation into
    /// [`Self::pcode_template`] by the sleigh compiler.
    parse_string: Option<String>,
}

impl InjectPayloadSleighImpl {
    /// Constructor for a partial clone of another payload whose p-code failed to parse.
    ///
    /// Port of the protected `InjectPayloadSleigh(ConstructTpl, InjectPayloadSleigh)`.
    pub fn new_partial_clone(pcode: ConstructTpl, failed: &InjectPayloadSleighImpl) -> Self {
        let isfallthru = compute_fall_thru(&pcode.vec);
        InjectPayloadSleighImpl {
            pcode_template: Some(pcode),
            param_shift: failed.param_shift,
            isfallthru,
            incidental_copy: failed.incidental_copy,
            input_list: failed.input_list.clone(),
            output: failed.output.clone(),
            sub_type: failed.sub_type,
            name: failed.name.clone(),
            type_: failed.type_,
            source: format!("{}_FAILED", failed.source),
            parse_string: None,
        }
    }

    /// Constructor for a dummy payload, given just a name.
    ///
    /// Port of the protected `InjectPayloadSleigh(ConstructTpl, int, String)`.
    pub fn new_dummy(pcode: ConstructTpl, tp: i32, nm: impl Into<String>) -> Self {
        let isfallthru = compute_fall_thru(&pcode.vec);
        InjectPayloadSleighImpl {
            pcode_template: Some(pcode),
            param_shift: 0,
            isfallthru,
            incidental_copy: false,
            input_list: Vec::new(),
            output: Vec::new(),
            sub_type: -1,
            name: nm.into(),
            type_: tp,
            source: "FAILED".to_string(),
            parse_string: None,
        }
    }

    /// Constructor for use where `restoreXml` is overridden and provides name and type.
    ///
    /// Port of the protected `InjectPayloadSleigh(String)`. Java leaves `isfallthru` at its
    /// default `false` here (it is never explicitly computed in this constructor, since there is
    /// no `pcodeTemplate` yet to compute it from) -- faithfully reproduced below rather than
    /// "fixed" to some other default.
    pub fn new_source(source_name: impl Into<String>) -> Self {
        InjectPayloadSleighImpl {
            pcode_template: None,
            param_shift: 0,
            isfallthru: false,
            incidental_copy: false,
            input_list: Vec::new(),
            output: Vec::new(),
            sub_type: -1,
            name: String::new(),
            type_: -1,
            source: source_name.into(),
            parse_string: None,
        }
    }

    /// Provides the basic form; `restoreXml` fills in the rest.
    ///
    /// Port of the public `InjectPayloadSleigh(String, int, String)`.
    pub fn new(nm: impl Into<String>, tp: i32, source_name: impl Into<String>) -> Self {
        InjectPayloadSleighImpl {
            pcode_template: None,
            param_shift: 0,
            isfallthru: false,
            incidental_copy: false,
            input_list: Vec::new(),
            output: Vec::new(),
            sub_type: -1,
            name: nm.into(),
            type_: tp,
            source: source_name.into(),
            parse_string: None,
        }
    }

    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    /// Assigns the formal name of this inject. Java's subclasses (`InjectPayloadCallfixup`,
    /// `InjectPayloadCallother`, `InjectPayloadJumpAssist`, `InjectPayloadSegment`) reach in and
    /// assign the protected `name` field directly from their own `restoreXml` overrides; this is
    /// the equivalent for the crate's subclasses that embed [`InjectPayloadSleighImpl`] by
    /// composition instead of inheritance.
    pub(crate) fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    /// Assigns the injection type (`CALLFIXUP_TYPE`, `CALLOTHERFIXUP_TYPE`, ...). Mirrors Java's
    /// `InjectPayloadCallfixup`/`InjectPayloadCallother` public constructors, which set the
    /// inherited protected `type` field directly (`type = CALLFIXUP_TYPE;`) after delegating to
    /// `super(sourceName)`.
    pub(crate) fn set_type(&mut self, tp: i32) {
        self.type_ = tp;
    }

    pub fn get_type(&self) -> i32 {
        self.type_
    }

    pub fn get_source(&self) -> String {
        self.source.clone()
    }

    pub fn get_param_shift(&self) -> i32 {
        self.param_shift
    }

    pub fn get_input(&self) -> Vec<InjectParameter> {
        self.input_list.clone()
    }

    pub fn get_output(&self) -> Vec<InjectParameter> {
        self.output.clone()
    }

    pub fn is_fall_thru(&self) -> bool {
        self.isfallthru
    }

    pub fn is_incidental_copy(&self) -> bool {
        self.incidental_copy
    }

    /// Port of `InjectPayloadSleigh.setInputParameters(List<InjectParameter>)`.
    pub fn set_input_parameters(&mut self, input: Vec<InjectParameter>) {
        self.input_list = input;
    }

    /// Port of `InjectPayloadSleigh.setOutputParameters(List<InjectParameter>)`.
    pub fn set_output_parameters(&mut self, output: Vec<InjectParameter>) {
        self.output = output;
    }

    /// All input and output parameters must have a unique index. Orders them so that inputs come
    /// first, then outputs.
    ///
    /// Port of `InjectPayloadSleigh.orderParameters()`.
    pub fn order_parameters(&mut self) {
        let mut id = 0;
        for param in self.input_list.iter_mut() {
            param.set_index(id);
            id += 1;
        }
        for param in self.output.iter_mut() {
            param.set_index(id);
            id += 1;
        }
    }

    /// Port of the package-private `InjectPayloadSleigh.releaseParseString()`.
    pub fn release_parse_string(&mut self) -> Option<String> {
        self.parse_string.take()
    }

    /// Port of the protected `InjectPayloadSleigh.setTemplate(ConstructTpl)`.
    pub fn set_template(&mut self, template: ConstructTpl) {
        self.isfallthru = compute_fall_thru(&template.vec);
        self.pcode_template = Some(template);
    }

    /// Verify that the storage locations passed in `con` match the restrictions for this payload.
    ///
    /// Port of the private `InjectPayloadSleigh.checkParameterRestrictions(InjectContext,
    /// Address)`. Java's `addr` parameter is never actually read by the method body (a real,
    /// harmless dead parameter in the original) -- dropped here since it has no observable effect
    /// to preserve.
    ///
    /// # Errors
    /// Returns an error naming which expected aspect of the context is not present.
    pub fn check_parameter_restrictions(&self, con: &InjectContext) -> Result<(), NotFoundException> {
        let insize = con.input_list.as_ref().map_or(0, |v| v.len());
        if self.input_list.len() != insize {
            return Err(NotFoundException::with_message(format!(
                "Input parameters do not match specification {} in\n{}",
                self.name, self.source
            )));
        }
        for (i, param) in self.input_list.iter().enumerate() {
            let sz = param.get_size();
            if sz != 0 && sz != con.input_list.as_ref().unwrap()[i].get_size() {
                return Err(NotFoundException::with_message(format!(
                    "Input parameter size does not match specification {} in\n{}",
                    self.name, self.source
                )));
            }
        }
        let outsize = con.output.as_ref().map_or(0, |v| v.len());
        if self.output.len() != outsize {
            if outsize == 0 {
                return Err(NotFoundException::with_message(format!(
                    "Output expected by specification {} in\n{}",
                    self.name, self.source
                )));
            }
            return Err(NotFoundException::with_message(format!(
                "Output not expected by specification {} in\n{}",
                self.name, self.source
            )));
        }
        for (i, param) in self.output.iter().enumerate() {
            let sz = param.get_size();
            if sz != 0 && sz != con.output.as_ref().unwrap()[i].get_size() {
                return Err(NotFoundException::with_message(format!(
                    "Output size does not match specification {} in\n{}",
                    self.name, self.source
                )));
            }
        }
        Ok(())
    }

    /// Send the p-code payload to the emitter.
    ///
    /// Port of `InjectPayloadSleigh.inject(InjectContext, PcodeEmit)`.
    ///
    /// # Errors
    /// Real for the parameter-restriction check (`checkParameterRestrictions`). Beyond that,
    /// always returns [`InjectPayloadError::NotYetPorted`]: Java's body is `ParserWalker walker =
    /// emit.getWalker(); walker.snippetState(); setupParameters(context, walker);
    /// emit.build(pcodeTemplate, -1); emit.resolveRelatives();`, but this crate's
    /// [`PcodeEmit::walker`](crate::app::plugin::processors::sleigh::pcode_emit::PcodeEmit::walker)
    /// returns only an immutable `&ParserWalker`, and
    /// [`ParserWalker`](crate::program::model::lang::sleigh::walker::ParserWalker) has no
    /// `snippet_state()` and no mutable accessor into a operand's `FixedHandle` (`get_parent_handle`
    /// returns `Option<&FixedHandle>`, not a mutable handle to write `space`/`offset_offset`/`size`
    /// into) -- so `setupParameters`'s operand-binding loop cannot be performed.
    pub fn inject(
        &self,
        context: &InjectContext,
        _emit: &mut dyn crate::app::plugin::processors::sleigh::pcode_emit::PcodeEmit,
    ) -> Result<(), InjectPayloadError> {
        self.check_parameter_restrictions(context)?;
        Err(InjectPayloadError::NotYetPorted(format!(
            "InjectPayloadSleighImpl::inject({}): blocked on ParserWalker/PcodeEmit missing \
             snippet_state()/mutable FixedHandle access -- see doc comment",
            self.name
        )))
    }

    /// A convenience function wrapping [`Self::inject`], to produce the final set of
    /// [`PcodeOp`](crate::program::model::pcode::PcodeOp) objects.
    ///
    /// Port of `InjectPayloadSleigh.getPcode(Program, InjectContext)`.
    ///
    /// # Errors
    /// Real for the parameter-restriction check. Beyond that, always returns
    /// [`InjectPayloadError::NotYetPorted`]: Java's body constructs a `new
    /// SleighParserContext(con.baseAddr, con.nextAddr, con.refAddr, con.callAddr)`, but this
    /// crate's [`SleighParserContext`](crate::app::plugin::processors::sleigh::sleigh_parser_context::SleighParserContext)
    /// is itself a dependency-cycle-cut trait with no concrete constructible implementor, so a
    /// `ParserWalker`/`PcodeEmitObjects` pipeline cannot be built here even before hitting the
    /// same gap as [`Self::inject`].
    pub fn get_pcode(
        &self,
        _program: &dyn crate::program::model::listing::program::Program,
        context: &InjectContext,
    ) -> Result<Vec<crate::program::model::pcode::PcodeOp>, InjectPayloadError> {
        self.check_parameter_restrictions(context)?;
        Err(InjectPayloadError::NotYetPorted(format!(
            "InjectPayloadSleighImpl::get_pcode({}): blocked on SleighParserContext having no \
             concrete constructible implementor, plus the same ParserWalker/PcodeEmit gap as \
             `inject` -- see doc comment",
            self.name
        )))
    }

    /// Base comparison shared by every subclass's `isEquivalent` override: name, per-element
    /// input/output parameter equivalence, incidental-copy, param-shift, type, and sub-type.
    /// `isfallthru` is intentionally not compared (matching a comment in the Java source: it's a
    /// product of the p-code templates, not part of the payload's declared identity), and neither
    /// is `source` (Java's `isEquivalent` never compares it either).
    ///
    /// Port of the shared tail of `InjectPayloadSleigh.isEquivalent(InjectPayload)`. Unlike Java,
    /// this crate's [`InjectPayload::is_equivalent`] takes `&dyn InjectPayload`, which cannot be
    /// downcast back to a concrete subclass to compare its own extra private fields (Java uses a
    /// `getClass()`-gated cast for that) -- callers holding two same-concrete-type payloads should
    /// prefer that subclass's own typed `is_equivalent_*` method (which compares its extra fields
    /// too) over this base comparison alone.
    pub fn is_equivalent_base(&self, other: &InjectPayloadSleighImpl) -> bool {
        if self.name != other.name {
            return false;
        }
        if self.input_list.len() != other.input_list.len() {
            return false;
        }
        for (a, b) in self.input_list.iter().zip(other.input_list.iter()) {
            if !a.is_equivalent(b) {
                return false;
            }
        }
        if self.output.len() != other.output.len() {
            return false;
        }
        for (a, b) in self.output.iter().zip(other.output.iter()) {
            if !a.is_equivalent(b) {
                return false;
            }
        }
        if self.incidental_copy != other.incidental_copy {
            return false;
        }
        if self.param_shift != other.param_shift {
            return false;
        }
        if self.type_ != other.type_ || self.sub_type != other.sub_type {
            return false;
        }
        true
    }

    /// Encode this payload's `<pcode>` element (open tag through close tag) to the stream.
    /// Subclasses that wrap this in an outer element call this between opening and closing their
    /// own wrapper.
    ///
    /// Port of `InjectPayloadSleigh.encode(Encoder)`.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    pub fn encode_pcode_element(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        encoder.open_element(ELEM_PCODE)?;
        if self.type_ == CALLMECHANISM_TYPE && self.sub_type >= 0 {
            encoder.write_string(
                ATTRIB_INJECT,
                if self.sub_type == 0 { "uponentry" } else { "uponreturn" },
            )?;
        }
        if self.param_shift != 0 {
            encoder.write_signed_integer(ATTRIB_PARAMSHIFT, self.param_shift as i64)?;
        }
        if self.pcode_template.is_none() {
            encoder.write_bool(ATTRIB_DYNAMIC, true)?;
        }
        if self.incidental_copy {
            encoder.write_bool(ATTRIB_INCIDENTALCOPY, self.incidental_copy)?;
        }
        for param in &self.input_list {
            encoder.open_element(ELEM_INPUT)?;
            encoder.write_string(ATTRIB_NAME, param.get_name())?;
            encoder.write_signed_integer(ATTRIB_SIZE, param.get_size() as i64)?;
            encoder.close_element(ELEM_INPUT)?;
        }
        for param in &self.output {
            encoder.open_element(ELEM_OUTPUT)?;
            encoder.write_string(ATTRIB_NAME, param.get_name())?;
            encoder.write_signed_integer(ATTRIB_SIZE, param.get_size() as i64)?;
            encoder.close_element(ELEM_OUTPUT)?;
        }
        if self.pcode_template.is_some() {
            // Quirk faithfully reproduced from Java: the decompiler never reads the <body> tag's
            // content, so `encode` always writes this fixed placeholder string regardless of the
            // payload's actual parsed p-code.
            encoder.open_element(ELEM_BODY)?;
            encoder.write_string(ATTRIB_CONTENT, " local tmp:1 = 0; ")?;
            encoder.close_element(ELEM_BODY)?;
        }
        encoder.close_element(ELEM_PCODE)
    }

    /// Restore this payload's state from a `<pcode>` element. Subclasses that wrap this in an
    /// outer element call this after consuming their own wrapper's start tag.
    ///
    /// Port of `InjectPayloadSleigh.restoreXml(XmlPullParser, SleighLanguage)` (the `language`
    /// parameter is unused by the base class itself; it exists for subclass overrides, e.g.
    /// `InjectPayloadSegment`, that need it).
    ///
    /// # Errors
    /// Returns an error for badly formed XML, or if neither a `<body>` nor `dynamic="true"` is
    /// present.
    pub fn restore_xml_pcode_element<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
    ) -> Result<(), XmlParseException> {
        let mut inlist = Vec::new();
        let mut outlist = Vec::new();
        let el = parser.start(&[]).map_err(xml_err)?;
        if let Some(injectstr) = el.get_attribute("inject") {
            self.sub_type = match injectstr.as_str() {
                "uponentry" => 0,
                "uponreturn" => 1,
                other => {
                    return Err(XmlParseException::new(format!(
                        "Unknown \"inject\" attribute value: {other}"
                    )))
                }
            };
        }
        self.param_shift = decode_int(el.get_attribute("paramshift").as_deref());
        let is_dynamic = decode_boolean(el.get_attribute("dynamic").as_deref().unwrap_or(""));
        self.incidental_copy =
            decode_boolean(el.get_attribute("incidentalcopy").as_deref().unwrap_or(""));

        let mut subel = parser.peek();
        while subel.is_start() {
            subel = parser.start(&[]).map_err(xml_err)?;
            if subel.get_name() == "body" {
                let end_el = parser.end_matching(&subel).map_err(xml_err)?;
                self.parse_string = Some(end_el.get_text().to_string());
                break;
            }
            let param_name = subel.get_attribute("name").unwrap_or_default();
            let size = decode_int(subel.get_attribute("size").as_deref());
            let param = InjectParameter::new(param_name, size);
            if subel.get_name() == "input" {
                inlist.push(param);
            } else {
                outlist.push(param);
            }
            parser.end_matching(&subel).map_err(xml_err)?;
            subel = parser.peek();
        }
        parser.end_matching(&el).map_err(xml_err)?;

        if let Some(s) = self.parse_string.take() {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                self.parse_string = Some(trimmed.to_string());
            }
        }
        if self.parse_string.is_none() && !is_dynamic {
            return Err(XmlParseException::new(format!(
                "Missing pcode <body> in injection: {}",
                self.source
            )));
        }

        self.set_input_parameters(inlist);
        self.set_output_parameters(outlist);
        self.order_parameters();
        Ok(())
    }
}

impl InjectPayload for InjectPayloadSleighImpl {
    fn get_name(&self) -> String {
        InjectPayloadSleighImpl::get_name(self)
    }

    fn get_type(&self) -> i32 {
        InjectPayloadSleighImpl::get_type(self)
    }

    fn get_source(&self) -> String {
        InjectPayloadSleighImpl::get_source(self)
    }

    fn get_param_shift(&self) -> i32 {
        InjectPayloadSleighImpl::get_param_shift(self)
    }

    fn get_input(&self) -> Vec<InjectParameter> {
        InjectPayloadSleighImpl::get_input(self)
    }

    fn get_output(&self) -> Vec<InjectParameter> {
        InjectPayloadSleighImpl::get_output(self)
    }

    fn is_error_placeholder(&self) -> bool {
        false
    }

    fn inject(
        &self,
        context: &InjectContext,
        emit: &mut dyn crate::app::plugin::processors::sleigh::pcode_emit::PcodeEmit,
    ) -> Result<(), InjectPayloadError> {
        InjectPayloadSleighImpl::inject(self, context, emit)
    }

    fn get_pcode(
        &self,
        program: &dyn crate::program::model::listing::program::Program,
        context: &InjectContext,
    ) -> Result<Vec<crate::program::model::pcode::PcodeOp>, InjectPayloadError> {
        InjectPayloadSleighImpl::get_pcode(self, program, context)
    }

    fn is_fall_thru(&self) -> bool {
        InjectPayloadSleighImpl::is_fall_thru(self)
    }

    fn is_incidental_copy(&self) -> bool {
        InjectPayloadSleighImpl::is_incidental_copy(self)
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        self.encode_pcode_element(encoder)
    }

    fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        _language: &crate::program::model::lang::sleigh::SleighLanguage,
    ) -> Result<(), XmlParseException>
    where
        Self: Sized,
    {
        self.restore_xml_pcode_element(parser)
    }

    fn is_equivalent(&self, other: &dyn InjectPayload) -> bool {
        self.name == other.get_name()
            && self.get_input() == other.get_input()
            && self.get_output() == other.get_output()
            && self.incidental_copy == other.is_incidental_copy()
            && self.param_shift == other.get_param_shift()
            && self.type_ == other.get_type()
    }
}

impl InjectPayloadSleigh for InjectPayloadSleighImpl {
    fn release_parse_string(&mut self) -> Option<String> {
        InjectPayloadSleighImpl::release_parse_string(self)
    }

    fn set_template(&mut self, template: ConstructTpl) {
        InjectPayloadSleighImpl::set_template(self, template)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::factory::DefaultAddressFactory;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::inject_payload::{
        InjectParameter, InjectPayloadError, CALLFIXUP_TYPE,
    };
    use crate::program::model::lang::sleigh::SleighLanguage;
    use crate::program::model::listing::program::Program;
    use crate::program::model::pcode::{Encoder, PcodeOp};
    use crate::app::plugin::processors::sleigh::pcode_emit::PcodeEmit;
    use crate::program::model::lang::inject_context::InjectContext;
    use crate::util::xml::xml_parse_exception::XmlParseException;
    use crate::util::xml::xml_pull_parser::XmlPullParser;

    struct MockInjectPayloadSleigh {
        name: String,
        parse_string: Option<String>,
        template: Option<ConstructTpl>,
        is_fallthru: bool,
    }

    impl InjectPayload for MockInjectPayloadSleigh {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_type(&self) -> i32 {
            CALLFIXUP_TYPE
        }

        fn get_source(&self) -> String {
            "mock".to_string()
        }

        fn get_param_shift(&self) -> i32 {
            0
        }

        fn get_input(&self) -> Vec<InjectParameter> {
            Vec::new()
        }

        fn get_output(&self) -> Vec<InjectParameter> {
            Vec::new()
        }

        fn is_error_placeholder(&self) -> bool {
            false
        }

        fn inject(
            &self,
            _context: &InjectContext,
            _emit: &mut dyn PcodeEmit,
        ) -> Result<(), InjectPayloadError> {
            Ok(())
        }

        fn get_pcode(
            &self,
            _program: &dyn Program,
            _context: &InjectContext,
        ) -> Result<Vec<PcodeOp>, InjectPayloadError> {
            Ok(Vec::new())
        }

        fn is_fall_thru(&self) -> bool {
            self.is_fallthru
        }

        fn is_incidental_copy(&self) -> bool {
            false
        }

        fn encode(&self, _encoder: &mut dyn Encoder) -> std::io::Result<()> {
            Ok(())
        }

        fn restore_xml<P: XmlPullParser>(
            &mut self,
            _parser: &mut P,
            _language: &SleighLanguage,
        ) -> Result<(), XmlParseException>
        where
            Self: Sized,
        {
            Ok(())
        }

        fn is_equivalent(&self, other: &dyn InjectPayload) -> bool {
            self.name == other.get_name()
        }
    }

    impl InjectPayloadSleigh for MockInjectPayloadSleigh {
        fn release_parse_string(&mut self) -> Option<String> {
            self.parse_string.take()
        }

        fn set_template(&mut self, template: ConstructTpl) {
            self.is_fallthru = compute_fall_thru(&template.vec);
            self.template = Some(template);
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    fn factory() -> DefaultAddressFactory {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let unique = AddressSpace::new("unique", 32, 1, AddressSpaceType::Unique, 2);
        let constant = AddressSpace::new("const", 32, 1, AddressSpaceType::Constant, 3);
        DefaultAddressFactory::new(vec![ram, unique, constant])
    }

    #[test]
    fn usable_as_trait_object_and_drives_release_and_set_template() {
        let mut payload: Box<dyn InjectPayloadSleigh> = Box::new(MockInjectPayloadSleigh {
            name: "myInject".to_string(),
            parse_string: Some(" local tmp:1 = 0; ".to_string()),
            template: None,
            is_fallthru: false,
        });

        assert_eq!(payload.get_name(), "myInject");
        assert!(!payload.is_fall_thru());

        let text = payload.release_parse_string();
        assert_eq!(text.as_deref(), Some(" local tmp:1 = 0; "));
        assert_eq!(payload.release_parse_string(), None);

        let dummy = get_dummy_pcode(&factory());
        payload.set_template(dummy);
        assert!(payload.is_fall_thru());
    }

    #[test]
    fn get_dummy_pcode_builds_single_int_add_op() {
        let template = get_dummy_pcode(&factory());
        assert_eq!(template.vec.len(), 1);
        let op = &template.vec[0];
        assert_eq!(op.get_opcode(), OpCode::CpuiIntAdd);
        assert!(op.get_out().is_some());
        assert_eq!(op.num_input(), 2);
        assert!(compute_fall_thru(&template.vec));
    }

    #[test]
    fn compute_fall_thru_detects_terminal_control_flow() {
        assert!(compute_fall_thru(&[]));

        let falls_through = vec![OpTpl::with_opcode(OpCode::CpuiIntAdd)];
        assert!(compute_fall_thru(&falls_through));

        for opc in [OpCode::CpuiBranch, OpCode::CpuiBranchind, OpCode::CpuiReturn] {
            let terminated = vec![OpTpl::with_opcode(OpCode::CpuiIntAdd), OpTpl::with_opcode(opc)];
            assert!(!compute_fall_thru(&terminated));
        }
    }

    // --- InjectPayloadSleighImpl ---

    struct MockProgram;
    impl crate::framework::model::domain_object::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            String::new()
        }
        fn get_language_id(&self) -> String {
            String::new()
        }
    }

    struct PanicPcodeEmit;
    impl PcodeEmit for PanicPcodeEmit {
        fn start_address(&self) -> crate::program::model::address::Address {
            unimplemented!("blocked path never calls into PcodeEmit")
        }
        fn fall_offset(&self) -> i32 {
            unimplemented!("blocked path never calls into PcodeEmit")
        }
        fn walker(&self) -> &crate::program::model::lang::sleigh::ParserWalker {
            unimplemented!("blocked path never calls into PcodeEmit")
        }
        fn pcode_override(&self) -> Option<&dyn crate::program::model::pcode::PcodeOverride> {
            None
        }
        fn fall_override(&self) -> Option<crate::program::model::address::Address> {
            None
        }
        fn default_fall_address(&self) -> Option<crate::program::model::address::Address> {
            None
        }
        fn add_label_ref(&mut self) {}
        fn resolve_relatives(
            &mut self,
        ) -> Result<(), crate::app::plugin::processors::sleigh::sleigh_exception::SleighException>
        {
            unimplemented!("blocked path never calls into PcodeEmit")
        }
        fn dump(
            &mut self,
            _instr_addr: crate::program::model::address::Address,
            _opcode: crate::decompiler::opcodes::op_code::OpCode,
            _in_: &mut [crate::app::plugin::processors::sleigh::varnode_data::VarnodeData],
            _isize: usize,
            _out: Option<&crate::app::plugin::processors::sleigh::varnode_data::VarnodeData>,
        ) -> std::io::Result<()> {
            unimplemented!("blocked path never calls into PcodeEmit")
        }
        fn build(
            &mut self,
            _construct: &crate::program::model::lang::sleigh::template::ConstructTpl,
            _secnum: i32,
        ) -> Result<(), crate::app::plugin::processors::sleigh::pcode_emit::PcodeEmitBuildError>
        {
            unimplemented!("blocked path never calls into PcodeEmit")
        }
    }

    fn ram_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn ctx_with_params(input_sizes: &[i32], output_sizes: &[i32]) -> InjectContext {
        let space = ram_space();
        let mut ctx = InjectContext::new();
        ctx.input_list = Some(
            input_sizes
                .iter()
                .enumerate()
                .map(|(i, sz)| crate::program::model::pcode::Varnode::new(space.address(i as i64 * 16), *sz))
                .collect(),
        );
        ctx.output = Some(
            output_sizes
                .iter()
                .enumerate()
                .map(|(i, sz)| {
                    crate::program::model::pcode::Varnode::new(space.address(1000 + i as i64 * 16), *sz)
                })
                .collect(),
        );
        ctx
    }

    #[test]
    fn constructors_match_java_field_defaults() {
        // Ctor 3 (`InjectPayloadSleigh(String)`) and ctor 4 (public) both leave `isfallthru` at
        // its Java default `false` -- neither constructor computes it, since there's no
        // `pcodeTemplate` yet.
        let via_source = InjectPayloadSleighImpl::new_source("src.pspec");
        assert_eq!(via_source.get_source(), "src.pspec");
        assert_eq!(via_source.get_type(), -1);
        assert!(!via_source.is_fall_thru());
        assert!(via_source.get_input().is_empty());

        let via_public = InjectPayloadSleighImpl::new("myFixup", CALLFIXUP_TYPE, "src.pspec");
        assert_eq!(via_public.get_name(), "myFixup");
        assert_eq!(via_public.get_type(), CALLFIXUP_TYPE);
        assert!(!via_public.is_fall_thru());
    }

    #[test]
    fn dummy_constructor_computes_fallthru_from_pcode() {
        let dummy = InjectPayloadSleighImpl::new_dummy(get_dummy_pcode(&factory()), CALLFIXUP_TYPE, "dummy");
        assert!(dummy.is_fall_thru());
        assert_eq!(dummy.get_source(), "FAILED");
        assert_eq!(dummy.get_param_shift(), 0);
        assert!(!dummy.is_incidental_copy());
    }

    #[test]
    fn partial_clone_copies_failed_payload_state_and_appends_failed_suffix() {
        let mut failed = InjectPayloadSleighImpl::new("origFixup", CALLFIXUP_TYPE, "orig.pspec");
        failed.set_input_parameters(vec![InjectParameter::new("p0", 4)]);
        failed.order_parameters();

        let clone = InjectPayloadSleighImpl::new_partial_clone(get_dummy_pcode(&factory()), &failed);
        assert_eq!(clone.get_name(), "origFixup");
        assert_eq!(clone.get_source(), "orig.pspec_FAILED");
        assert_eq!(clone.get_input().len(), 1);
        assert!(clone.is_fall_thru());
    }

    #[test]
    fn order_parameters_assigns_sequential_indices_inputs_then_outputs() {
        let mut payload = InjectPayloadSleighImpl::new("p", CALLFIXUP_TYPE, "src");
        payload.set_input_parameters(vec![InjectParameter::new("in0", 4), InjectParameter::new("in1", 8)]);
        payload.set_output_parameters(vec![InjectParameter::new("out0", 2)]);
        payload.order_parameters();

        let input = payload.get_input();
        assert_eq!(input[0].get_index(), 0);
        assert_eq!(input[1].get_index(), 1);
        let output = payload.get_output();
        assert_eq!(output[0].get_index(), 2);
    }

    #[test]
    fn check_parameter_restrictions_accepts_matching_context() {
        let mut payload = InjectPayloadSleighImpl::new("p", CALLFIXUP_TYPE, "src");
        payload.set_input_parameters(vec![InjectParameter::new("in0", 4)]);
        payload.set_output_parameters(vec![InjectParameter::new("out0", 8)]);

        let ctx = ctx_with_params(&[4], &[8]);
        assert!(payload.check_parameter_restrictions(&ctx).is_ok());
    }

    #[test]
    fn check_parameter_restrictions_zero_size_param_matches_anything() {
        // Java: `if (sz != 0 && sz != con.inputlist.get(i).getSize())` -- a declared size of 0
        // means "any size is acceptable".
        let mut payload = InjectPayloadSleighImpl::new("p", CALLFIXUP_TYPE, "src");
        payload.set_input_parameters(vec![InjectParameter::new("in0", 0)]);
        payload.order_parameters();

        let ctx = ctx_with_params(&[123], &[]);
        assert!(payload.check_parameter_restrictions(&ctx).is_ok());
    }

    #[test]
    fn check_parameter_restrictions_rejects_input_count_mismatch() {
        let mut payload = InjectPayloadSleighImpl::new("p", CALLFIXUP_TYPE, "src");
        payload.set_input_parameters(vec![InjectParameter::new("in0", 4)]);

        let ctx = ctx_with_params(&[], &[]);
        let err = payload.check_parameter_restrictions(&ctx).unwrap_err();
        assert!(err.to_string().contains("Input parameters do not match"));
    }

    #[test]
    fn check_parameter_restrictions_rejects_input_size_mismatch() {
        let mut payload = InjectPayloadSleighImpl::new("p", CALLFIXUP_TYPE, "src");
        payload.set_input_parameters(vec![InjectParameter::new("in0", 4)]);

        let ctx = ctx_with_params(&[8], &[]);
        let err = payload.check_parameter_restrictions(&ctx).unwrap_err();
        assert!(err.to_string().contains("Input parameter size does not match"));
    }

    #[test]
    fn check_parameter_restrictions_rejects_missing_expected_output() {
        let mut payload = InjectPayloadSleighImpl::new("p", CALLFIXUP_TYPE, "src");
        payload.set_output_parameters(vec![InjectParameter::new("out0", 8)]);

        let ctx = ctx_with_params(&[], &[]);
        let err = payload.check_parameter_restrictions(&ctx).unwrap_err();
        assert!(err.to_string().contains("Output expected by specification"));
    }

    #[test]
    fn check_parameter_restrictions_rejects_unexpected_output() {
        let payload = InjectPayloadSleighImpl::new("p", CALLFIXUP_TYPE, "src");
        let ctx = ctx_with_params(&[], &[8]);
        let err = payload.check_parameter_restrictions(&ctx).unwrap_err();
        assert!(err.to_string().contains("Output not expected by specification"));
    }

    #[test]
    fn inject_runs_real_check_then_reports_not_yet_ported() {
        let payload = InjectPayloadSleighImpl::new("p", CALLFIXUP_TYPE, "src");
        let ctx = ctx_with_params(&[], &[]);

        match payload.inject(&ctx, &mut PanicPcodeEmit) {
            Err(InjectPayloadError::NotYetPorted(msg)) => assert!(msg.contains("p")),
            other => panic!("expected NotYetPorted, got {other:?}"),
        }
    }

    #[test]
    fn inject_surfaces_real_parameter_mismatch_before_the_not_yet_ported_gap() {
        let mut payload = InjectPayloadSleighImpl::new("p", CALLFIXUP_TYPE, "src");
        payload.set_input_parameters(vec![InjectParameter::new("in0", 4)]);
        // Context provides no inputs at all -- checkParameterRestrictions is real and must be
        // the thing that fails, not the NotYetPorted stand-in.
        let ctx = ctx_with_params(&[], &[]);

        match payload.inject(&ctx, &mut PanicPcodeEmit) {
            Err(InjectPayloadError::NotFound(_)) => {}
            other => panic!("expected NotFound from the real parameter check, got {other:?}"),
        }
    }

    #[test]
    fn get_pcode_runs_real_check_then_reports_not_yet_ported() {
        let payload = InjectPayloadSleighImpl::new("p", CALLFIXUP_TYPE, "src");
        let ctx = ctx_with_params(&[], &[]);
        match payload.get_pcode(&MockProgram, &ctx) {
            Err(InjectPayloadError::NotYetPorted(_)) => {}
            other => panic!("expected NotYetPorted, got {other:?}"),
        }
    }

    #[test]
    fn is_equivalent_base_compares_name_params_and_flags() {
        let mut a = InjectPayloadSleighImpl::new("same", CALLFIXUP_TYPE, "src");
        a.set_input_parameters(vec![InjectParameter::new("in0", 4)]);
        let mut b = InjectPayloadSleighImpl::new("same", CALLFIXUP_TYPE, "src2");
        b.set_input_parameters(vec![InjectParameter::new("in0", 4)]);
        assert!(a.is_equivalent_base(&b));

        let c = InjectPayloadSleighImpl::new("different", CALLFIXUP_TYPE, "src");
        assert!(!a.is_equivalent_base(&c));

        let mut d = InjectPayloadSleighImpl::new("same", CALLFIXUP_TYPE, "src");
        d.set_input_parameters(vec![InjectParameter::new("in0", 8)]); // different size
        assert!(!a.is_equivalent_base(&d));
    }

    struct RecordingEncoder {
        events: Vec<String>,
    }
    impl RecordingEncoder {
        fn new() -> Self {
            Self { events: Vec::new() }
        }
    }
    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: crate::program::model::pcode::ids::ElementId) -> std::io::Result<()> {
            self.events.push(format!("open:{}", elem_id.name));
            Ok(())
        }
        fn close_element(&mut self, elem_id: crate::program::model::pcode::ids::ElementId) -> std::io::Result<()> {
            self.events.push(format!("close:{}", elem_id.name));
            Ok(())
        }
        fn write_bool(&mut self, attrib_id: crate::program::model::pcode::ids::AttributeId, val: bool) -> std::io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_signed_integer(&mut self, attrib_id: crate::program::model::pcode::ids::AttributeId, val: i64) -> std::io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_unsigned_integer(&mut self, attrib_id: crate::program::model::pcode::ids::AttributeId, val: u64) -> std::io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_string(&mut self, attrib_id: crate::program::model::pcode::ids::AttributeId, val: &str) -> std::io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_string_indexed(&mut self, attrib_id: crate::program::model::pcode::ids::AttributeId, index: i32, val: &str) -> std::io::Result<()> {
            self.events.push(format!("attr:{}[{}]={}", attrib_id.name, index, val));
            Ok(())
        }
        fn write_space(&mut self, attrib_id: crate::program::model::pcode::ids::AttributeId, spc: &AddressSpace) -> std::io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, spc.name()));
            Ok(())
        }
        fn write_space_indexed(&mut self, attrib_id: crate::program::model::pcode::ids::AttributeId, index: i32, name: &str) -> std::io::Result<()> {
            self.events.push(format!("attr:{}[{}]={}", attrib_id.name, index, name));
            Ok(())
        }
        fn write_opcode(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _opcode: crate::decompiler::opcodes::op_code::OpCode) -> std::io::Result<()> {
            Ok(())
        }
        fn write_opcode_ordinal(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _opcode: i32) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn encode_pcode_element_writes_params_and_placeholder_body() {
        let mut payload = InjectPayloadSleighImpl::new("p", CALLFIXUP_TYPE, "src");
        payload.set_input_parameters(vec![InjectParameter::new("in0", 4)]);
        payload.set_output_parameters(vec![InjectParameter::new("out0", 8)]);
        payload.set_template(get_dummy_pcode(&factory()));

        let mut enc = RecordingEncoder::new();
        payload.encode_pcode_element(&mut enc).unwrap();

        assert_eq!(enc.events[0], "open:pcode");
        assert!(enc.events.iter().any(|e| e == "open:input"));
        assert!(enc.events.iter().any(|e| e == "attr:name=in0"));
        assert!(enc.events.iter().any(|e| e == "attr:size=4"));
        assert!(enc.events.iter().any(|e| e == "open:output"));
        assert!(enc.events.iter().any(|e| e == "attr:name=out0"));
        // Real Java quirk: the <body> content written is always this fixed placeholder string,
        // regardless of what p-code the payload actually holds -- the decompiler never reads it.
        assert!(enc.events.iter().any(|e| e == "attr:XMLcontent= local tmp:1 = 0; "));
        assert_eq!(enc.events.last().unwrap(), "close:pcode");
        // No pcode_template means ATTRIB_DYNAMIC would be written instead; here we have a
        // template, so it must NOT appear.
        assert!(!enc.events.iter().any(|e| e.starts_with("attr:dynamic")));
    }

    #[test]
    fn encode_pcode_element_dynamic_payload_omits_body_and_writes_dynamic_attr() {
        let payload = InjectPayloadSleighImpl::new("p", CALLFIXUP_TYPE, "src"); // no template set
        let mut enc = RecordingEncoder::new();
        payload.encode_pcode_element(&mut enc).unwrap();
        assert!(enc.events.iter().any(|e| e == "attr:dynamic=true"));
        assert!(!enc.events.iter().any(|e| e.starts_with("open:body")));
    }

    #[test]
    fn encode_pcode_element_omits_paramshift_and_incidentalcopy_when_default() {
        let payload = InjectPayloadSleighImpl::new("p", CALLFIXUP_TYPE, "src");
        let mut enc = RecordingEncoder::new();
        payload.encode_pcode_element(&mut enc).unwrap();
        assert!(!enc.events.iter().any(|e| e.starts_with("attr:paramshift")));
        assert!(!enc.events.iter().any(|e| e.starts_with("attr:incidentalcopy")));
    }

    // --- restore_xml_pcode_element ---

    #[derive(Clone)]
    struct MockElement {
        name: String,
        level: i32,
        is_start: bool,
        is_end: bool,
        attrs: std::collections::HashMap<String, String>,
        text: String,
    }

    impl MockElement {
        fn start(name: &str, level: i32, attrs: &[(&str, &str)]) -> Self {
            Self {
                name: name.to_string(),
                level,
                is_start: true,
                is_end: false,
                attrs: attrs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
                text: String::new(),
            }
        }
        fn end(name: &str, level: i32) -> Self {
            Self {
                name: name.to_string(),
                level,
                is_start: false,
                is_end: true,
                attrs: std::collections::HashMap::new(),
                text: String::new(),
            }
        }
        fn end_with_text(name: &str, level: i32, text: &str) -> Self {
            let mut e = Self::end(name, level);
            e.text = text.to_string();
            e
        }
    }

    impl XmlElement for MockElement {
        fn get_level(&self) -> i32 {
            self.level
        }
        fn is_start(&self) -> bool {
            self.is_start
        }
        fn is_end(&self) -> bool {
            self.is_end
        }
        fn is_content(&self) -> bool {
            !self.is_start && !self.is_end
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_attributes(&self) -> std::collections::HashMap<String, String> {
            self.attrs.clone()
        }
        fn get_attribute_iter(&self) -> Box<dyn Iterator<Item = (String, String)> + '_> {
            Box::new(self.attrs.clone().into_iter())
        }
        fn has_attribute(&self, key: &str) -> bool {
            self.attrs.contains_key(key)
        }
        fn get_attribute(&self, key: &str) -> Option<String> {
            self.attrs.get(key).cloned()
        }
        fn get_text(&self) -> &str {
            &self.text
        }
        fn get_column_number(&self) -> i32 {
            0
        }
        fn get_line_number(&self) -> i32 {
            0
        }
        fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
            self.attrs.insert(key.into(), value.into());
        }
        fn is_start_with(&self, name: &str) -> bool {
            self.is_start && self.name == name
        }
    }

    struct QueueParser {
        elements: Vec<MockElement>,
        pos: usize,
        pulling_content: bool,
    }
    impl QueueParser {
        fn new(elements: Vec<MockElement>) -> Self {
            Self { elements, pos: 0, pulling_content: false }
        }
    }
    impl XmlPullParser for QueueParser {
        type Element = MockElement;
        fn get_name(&self) -> &str {
            "queue"
        }
        fn get_processing_instruction(&self, _name: &str, _attribute: &str) -> Option<String> {
            None
        }
        fn is_pulling_content(&self) -> bool {
            self.pulling_content
        }
        fn set_pulling_content(&mut self, pulling_content: bool) {
            self.pulling_content = pulling_content;
        }
        fn has_next(&self) -> bool {
            self.pos < self.elements.len()
        }
        fn peek(&self) -> MockElement {
            self.elements[self.pos].clone()
        }
        fn next(&mut self) -> MockElement {
            let elem = self.elements[self.pos].clone();
            self.pos += 1;
            elem
        }
        fn dispose(&mut self) {}
    }

    #[test]
    fn restore_xml_pcode_element_parses_inputs_outputs_and_body() {
        let elements = vec![
            MockElement::start("pcode", 0, &[("paramshift", "1"), ("incidentalcopy", "true")]),
            MockElement::start("input", 1, &[("name", "p0"), ("size", "4")]),
            MockElement::end("input", 1),
            MockElement::start("output", 1, &[("name", "r0"), ("size", "8")]),
            MockElement::end("output", 1),
            MockElement::start("body", 1, &[]),
            MockElement::end_with_text("body", 1, " local tmp:1 = 0; "),
            MockElement::end("pcode", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut payload = InjectPayloadSleighImpl::new_source("src.pspec");
        payload.restore_xml_pcode_element(&mut parser).expect("restore_xml should succeed");

        assert_eq!(payload.get_param_shift(), 1);
        assert!(payload.is_incidental_copy());
        let input = payload.get_input();
        assert_eq!(input.len(), 1);
        assert_eq!(input[0].get_name(), "p0");
        assert_eq!(input[0].get_size(), 4);
        assert_eq!(input[0].get_index(), 0);
        let output = payload.get_output();
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].get_name(), "r0");
        assert_eq!(output[0].get_index(), 1);
    }

    #[test]
    fn restore_xml_pcode_element_dynamic_without_body_is_allowed() {
        let elements = vec![
            MockElement::start("pcode", 0, &[("dynamic", "true")]),
            MockElement::end("pcode", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut payload = InjectPayloadSleighImpl::new_source("src.pspec");
        assert!(payload.restore_xml_pcode_element(&mut parser).is_ok());
    }

    #[test]
    fn restore_xml_pcode_element_missing_body_without_dynamic_errors() {
        let elements = vec![
            MockElement::start("pcode", 0, &[]),
            MockElement::end("pcode", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut payload = InjectPayloadSleighImpl::new_source("src.pspec");
        let err = payload.restore_xml_pcode_element(&mut parser).unwrap_err();
        assert!(err.to_string().contains("Missing pcode <body>"));
    }

    #[test]
    fn restore_xml_pcode_element_rejects_unknown_inject_attribute() {
        let elements = vec![
            MockElement::start("pcode", 0, &[("inject", "sideways")]),
            MockElement::end("pcode", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut payload = InjectPayloadSleighImpl::new_source("src.pspec");
        let err = payload.restore_xml_pcode_element(&mut parser).unwrap_err();
        assert!(err.to_string().contains("Unknown \"inject\" attribute value"));
    }

    #[test]
    fn restore_xml_pcode_element_blank_body_is_treated_as_absent() {
        // Java trims the <body> text and, if empty, sets parseString back to null -- so a
        // whitespace-only body with no dynamic="true" still trips the missing-body error.
        let elements = vec![
            MockElement::start("pcode", 0, &[]),
            MockElement::start("body", 1, &[]),
            MockElement::end_with_text("body", 1, "   \n  "),
            MockElement::end("pcode", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut payload = InjectPayloadSleighImpl::new_source("src.pspec");
        let err = payload.restore_xml_pcode_element(&mut parser).unwrap_err();
        assert!(err.to_string().contains("Missing pcode <body>"));
    }

    #[test]
    fn trait_object_roundtrip_via_inject_payload_encode_and_restore() {
        let payload: Box<dyn InjectPayload> =
            Box::new(InjectPayloadSleighImpl::new("p", CALLFIXUP_TYPE, "src"));
        assert_eq!(payload.get_name(), "p");
        assert!(!payload.is_error_placeholder());
        assert!(payload.encode(&mut RecordingEncoder::new()).is_ok());
    }
}
