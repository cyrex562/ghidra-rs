//! Port of `ghidra.program.model.lang.PcodeInjectLibrary`.
//!
//! The manager that owns and dispatches every p-code-injection payload (call-fixups, call-other
//! overrides, jump-assist tables, segment handling) ported alongside it in this session:
//! [`InjectPayload`], [`InjectPayloadSleigh`]/[`InjectPayloadSleighImpl`], [`InjectContext`],
//! [`InjectPayloadCallfixupImpl`], [`InjectPayloadCallother`], [`InjectPayloadJumpAssist`],
//! [`InjectPayloadSegment`], and the two `*Error` payload types.
//!
//! # Storage: `Arc<dyn InjectPayloadSleigh>` instead of Java's `InjectPayload`
//!
//! Java's five maps/arrays (`callFixupMap`, `callOtherFixupMap`, `callOtherOverride`,
//! `callMechFixupMap`, `exePcodeMap`, `programPayload`) are all typed `InjectPayload` --
//! `allocateInject` can be overridden by a derived library to return arbitrary `InjectPayload`
//! implementors that aren't `InjectPayloadSleigh` at all. In this crate every constructible
//! payload type (the base [`InjectPayloadSleighImpl`] and all four real subclasses, plus both
//! `*Error` placeholders) implements [`InjectPayloadSleigh`], and `allocate_inject` below only
//! ever produces one of those, so the maps are typed `Arc<dyn InjectPayloadSleigh>` rather than
//! `Arc<dyn InjectPayload>` (calling [`InjectPayload`]'s own methods on a value works fine through
//! a `dyn InjectPayloadSleigh` reference or an upcast to `&dyn InjectPayload`, since
//! `InjectPayloadSleigh: InjectPayload`). `Arc` (rather than `Box`) matches this class's own
//! javadoc on its copy constructor: "InjectPayloads can be considered immutable and don't need to
//! be cloned" -- Java's `clone()`/copy-constructor builds fresh `TreeMap`s that still reference
//! the *same* payload objects, and `#[derive(Clone)]` on [`PcodeInjectLibrary`] reproduces that
//! exactly (fresh `BTreeMap`s, shared `Arc`-counted payloads) rather than deep-cloning them.
//!
//! # Gaps
//!
//! - **`parseInject` failures**: Java's `PcodeParser.compilePcode` returns `null` (after logging)
//!   when the snippet had reported errors, and `parseInject` installs that `null` template.
//!   [`PcodeParser::compile_pcode`] returns an error instead, so
//!   [`PcodeInjectLibrary::parse_inject`] (and thus registration) fails for such a payload.
//! - **`allocateInject`/`restoreXmlInject`'s polymorphic dispatch**: Java calls
//!   `payload.restoreXml(parser, language)` on whatever concrete subclass `allocateInject`
//!   returned. [`InjectPayload::restore_xml`] is generic over the parser type (`where Self:
//!   Sized`) -- the same thing that keeps `InjectPayload` itself dyn-compatible for every other
//!   method (see that trait's module docs) -- so it can never be called through a trait object.
//!   [`AllocatedInjectPayload`] stands in for the concrete return type so
//!   [`PcodeInjectLibrary::restore_xml_inject`] can call each variant's own (non-dyn) `restore_xml`
//!   method before boxing the result as `Arc<dyn InjectPayloadSleigh>` for storage.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Weak};

use crate::app::plugin::processors::sleigh::sleigh_exception::SleighException;
use crate::app::plugin::processors::sleigh::unique_layout::UniqueLayout;
use crate::program::model::lang::constant_pool::ConstantPool;
use crate::program::model::lang::inject_context::InjectContext;
use crate::program::model::lang::inject_payload::{
    InjectPayload, CALLFIXUP_TYPE, CALLMECHANISM_TYPE, CALLOTHERFIXUP_TYPE, EXECUTABLEPCODE_TYPE,
};
use crate::program::model::lang::inject_payload_callfixup::InjectPayloadCallfixupImpl;
use crate::program::model::lang::inject_payload_callother::InjectPayloadCallother;
use crate::program::model::lang::inject_payload_segment::InjectPayloadSegment;
use crate::program::model::lang::inject_payload_sleigh::{InjectPayloadSleigh, InjectPayloadSleighImpl};
use crate::program::model::lang::pcode_parser::PcodeParser;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::sleigh::grammar::Location;
use crate::program::model::listing::program::Program;
use crate::program::model::pcode::Encoder;
use crate::util::msg::Msg;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Error produced by [`PcodeInjectLibrary::restore_xml_inject`], which can fail either while
/// parsing the payload's XML or (via [`PcodeInjectLibrary::register_inject`]) while registering it.
///
/// Java declares only `throws XmlParseException` on `restoreXmlInject` -- `registerInject`'s
/// `SleighException` is an unchecked `RuntimeException` there, so Java doesn't need a combined
/// checked-exception type. This crate models both `SleighException` and `XmlParseException` as
/// ordinary `Result` errors throughout, so a function that can hit either needs a type that can
/// represent both.
#[derive(Debug)]
pub enum PcodeInjectLibraryError {
    /// The payload's XML failed to parse.
    Xml(XmlParseException),
    /// The payload was well-formed but could not be registered.
    Sleigh(SleighException),
}

impl From<XmlParseException> for PcodeInjectLibraryError {
    fn from(e: XmlParseException) -> Self {
        PcodeInjectLibraryError::Xml(e)
    }
}

impl From<SleighException> for PcodeInjectLibraryError {
    fn from(e: SleighException) -> Self {
        PcodeInjectLibraryError::Sleigh(e)
    }
}

impl fmt::Display for PcodeInjectLibraryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PcodeInjectLibraryError::Xml(e) => write!(f, "{e}"),
            PcodeInjectLibraryError::Sleigh(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for PcodeInjectLibraryError {}

/// The concrete type of a payload freshly produced by [`PcodeInjectLibrary::allocate_inject`].
///
/// See the module docs above for why this enum exists instead of a `Box<dyn InjectPayload>`.
pub enum AllocatedInjectPayload {
    Callfixup(InjectPayloadCallfixupImpl),
    Callother(InjectPayloadCallother),
    Sleigh(InjectPayloadSleighImpl),
}

impl AllocatedInjectPayload {
    /// Consumes this value, boxing the concrete payload it holds as `Arc<dyn InjectPayloadSleigh>`
    /// for storage in a [`PcodeInjectLibrary`] map.
    fn into_arc(self) -> Arc<dyn InjectPayloadSleigh> {
        match self {
            AllocatedInjectPayload::Callfixup(p) => Arc::new(p),
            AllocatedInjectPayload::Callother(p) => Arc::new(p),
            AllocatedInjectPayload::Sleigh(p) => Arc::new(p),
        }
    }
}

/// The manager that owns and dispatches p-code-injection payloads for a [`SleighLanguage`] (and,
/// via [`PcodeInjectLibrary::register_program_inject`], per-`Program` extensions layered on top).
///
/// Port of `ghidra.program.model.lang.PcodeInjectLibrary`.
#[derive(Clone)]
pub struct PcodeInjectLibrary {
    /// The language. Weak because the language owns (caches) the compiler spec that owns this
    /// library; the language must outlive every use of the library (see
    /// [`WeakLanguage`](crate::program::model::lang::language::WeakLanguage)).
    language: Weak<SleighLanguage>,
    /// Current base address for new temporary registers.
    unique_base: u64,
    /// Map of names to registered call-fixups.
    call_fixup_map: BTreeMap<String, Arc<dyn InjectPayloadSleigh>>,
    /// Map of registered call-other-fixup names to their injection payload. A `None` value means
    /// the name is a known user-defined op with no fixup installed (including a name whose fixup
    /// was pulled out into [`Self::call_other_override`]).
    call_other_fixup_map: BTreeMap<String, Option<Arc<dyn InjectPayloadSleigh>>>,
    /// List of call-other-fixups overridden by a program extension.
    call_other_override: Option<Vec<Arc<dyn InjectPayloadSleigh>>>,
    /// Map of registered injectUponEntry/Return ids.
    call_mech_fixup_map: BTreeMap<String, Arc<dyn InjectPayloadSleigh>>,
    /// Map of registered p-code scripts.
    exe_pcode_map: BTreeMap<String, Arc<dyn InjectPayloadSleigh>>,
    /// List of Program-specific payloads.
    program_payload: Option<Vec<Arc<dyn InjectPayloadSleigh>>>,
}

impl PcodeInjectLibrary {
    /// Constructs a library for the given language.
    ///
    /// Port of `PcodeInjectLibrary(SleighLanguage)`. The library does not keep `language` alive;
    /// the caller must.
    pub fn new(language: &Arc<SleighLanguage>) -> Self {
        let unique_base = UniqueLayout::Inject.get_offset(Some(language));
        PcodeInjectLibrary {
            language: Arc::downgrade(language),
            unique_base,
            call_fixup_map: BTreeMap::new(),
            call_other_fixup_map: BTreeMap::new(),
            call_other_override: None,
            call_mech_fixup_map: BTreeMap::new(),
            exe_pcode_map: BTreeMap::new(),
            program_payload: None,
        }
    }

    /// Returns an array of all the program specific payloads (or `None`).
    ///
    /// Port of `getProgramPayloads()`.
    pub fn get_program_payloads(&self) -> Option<&[Arc<dyn InjectPayloadSleigh>]> {
        self.program_payload.as_deref()
    }

    /// Determine if the given payload name and type exists and is an extension of the program.
    ///
    /// Port of `hasProgramPayload(String, int)`.
    pub fn has_program_payload(&self, nm: &str, tp: i32) -> bool {
        let Some(program_payload) = &self.program_payload else {
            return false;
        };
        program_payload
            .iter()
            .any(|payload| payload.get_type() == tp && payload.get_name() == nm)
    }

    /// Check if a specific payload has been overridden by a user extension.
    ///
    /// Port of `isOverride(String, int)`.
    pub fn is_override(&self, nm: &str, tp: i32) -> bool {
        if tp != CALLOTHERFIXUP_TYPE {
            return false;
        }
        let Some(overrides) = &self.call_other_override else {
            return false;
        };
        overrides.iter().any(|payload| payload.get_name() == nm)
    }

    /// Looks up a registered payload by type and name.
    ///
    /// Port of `getPayload(int, String)`. `name` is `Option` to mirror Java's explicit `if (name
    /// == null) return null;` guard.
    pub fn get_payload(&self, tp: i32, name: Option<&str>) -> Option<&dyn InjectPayload> {
        let name = name?;
        match tp {
            CALLFIXUP_TYPE => self
                .call_fixup_map
                .get(name)
                .map(|p| p.as_ref() as &dyn InjectPayload),
            CALLOTHERFIXUP_TYPE => self
                .call_other_fixup_map
                .get(name)
                .and_then(|p| p.as_ref())
                .map(|p| p.as_ref() as &dyn InjectPayload),
            CALLMECHANISM_TYPE => self
                .call_mech_fixup_map
                .get(name)
                .map(|p| p.as_ref() as &dyn InjectPayload),
            EXECUTABLEPCODE_TYPE => self
                .exe_pcode_map
                .get(name)
                .map(|p| p.as_ref() as &dyn InjectPayload),
            _ => None,
        }
    }

    /// Convert the raw p-code source text of the given payload into a `ConstructTpl`. The payload
    /// should be unattached (not already installed in the library).
    ///
    /// Port of `parseInject(InjectPayload)`: the payload's input and output parameters become
    /// operand symbols of a [`PcodeParser`] built on this library's language, the text is
    /// compiled, the parser's next free temporary becomes this library's unique base, and the
    /// template is installed with `set_template`. A payload without text (`dynamic="true"`, or
    /// already parsed) is left alone. Unlike Java (whose `InjectPayload payload` parameter can be
    /// any implementor, guarded by an `instanceof InjectPayloadSleigh` check that returns early
    /// for anything else), this takes `&mut dyn InjectPayloadSleigh` directly: every payload type
    /// this crate can construct already implements that trait.
    ///
    /// # Errors
    /// Returns an error if the p-code text does not compile (see [`PcodeParser::compile_pcode`]).
    pub fn parse_inject(&mut self, payload: &mut dyn InjectPayloadSleigh) -> Result<(), SleighException> {
        let source_name = payload.get_source();
        let source_name = if source_name.is_empty() { "unknown".to_string() } else { source_name };

        let pcode_text = match payload.release_parse_string() {
            None => return Ok(()), // Dynamic p-code generation, or already parsed.
            Some(text) => text,
        };

        let language = self.language();
        let mut parser = PcodeParser::new(&language, self.unique_base)?;
        let loc = Location::new(source_name.clone(), 1);
        for element in payload.get_input().iter().chain(payload.get_output().iter()) {
            parser
                .add_operand(&loc, element.get_name(), element.get_index())
                .map_err(|e| SleighException::with_message(format!("{}: {}", e.location, e.message())))?;
        }
        let construct_tpl = parser.compile_pcode(&pcode_text, &source_name, 1)?;

        self.unique_base = parser.get_next_temp_offset();

        payload.set_template(construct_tpl);
        Ok(())
    }

    /// Returns a list of names for all installed call-fixups.
    ///
    /// Port of `getCallFixupNames()`.
    pub fn get_call_fixup_names(&self) -> Vec<String> {
        self.call_fixup_map.keys().cloned().collect()
    }

    /// Returns a list of names for all installed callother-fixups.
    ///
    /// Port of `getCallotherFixupNames()`.
    pub fn get_callother_fixup_names(&self) -> Vec<String> {
        self.call_other_fixup_map
            .iter()
            .filter(|(_, v)| v.is_some())
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// The language.
    ///
    /// # Panics
    /// If the language has been dropped while this library is still in use.
    fn language(&self) -> Arc<SleighLanguage> {
        self.language
            .upgrade()
            .expect("language dropped while its p-code inject library is still in use")
    }

    /// Builds a fresh [`InjectContext`] carrying this library's language.
    ///
    /// Port of `buildInjectContext()`.
    pub fn build_inject_context(&self) -> InjectContext {
        let mut res = InjectContext::new();
        res.language = Some(self.language());
        res
    }

    /// Determine if the language has a given user-defined op, lazily populating
    /// [`Self::call_other_fixup_map`] with every known user-defined op name (mapped to `None`)
    /// the first time it's called. In which case, a `CALLOTHERFIXUP_TYPE` payload can be
    /// installed for it.
    ///
    /// Port of `hasUserDefinedOp(String)`.
    pub fn has_user_defined_op(&mut self, name: &str) -> bool {
        if self.call_other_fixup_map.is_empty() {
            let language = self.language();
            let max = language.get_number_of_user_defined_op_names();
            for i in 0..max {
                if let Some(opname) = language.get_user_defined_op_name(i) {
                    self.call_other_fixup_map.insert(opname, None);
                }
            }
        }
        self.call_other_fixup_map.contains_key(name)
    }

    /// Registers `payload` -- calling [`Self::parse_inject`] on it first -- into the map matching
    /// its [`InjectPayload::get_type`], returning the now-shared `payload` back to the caller (a
    /// second handle to the same `Arc`, alongside the one now stored in the library) for
    /// convenience -- e.g. so [`Self::restore_xml_inject`] can hand the freshly registered payload
    /// back to its own caller, and [`Self::register_program_inject`] can collect it into
    /// `program_payload`, without either needing a separate lookup.
    ///
    /// Port of the protected `registerInject(InjectPayload)`. Takes `payload` by value (moved in,
    /// not cloned by the caller first) specifically so the mutation [`Self::parse_inject`] performs
    /// can happen while `payload` is still uniquely owned (`Arc::get_mut` requires a strong count
    /// of 1) -- every clone this method itself produces happens only after that mutation step.
    ///
    /// # Errors
    /// Returns an error if [`Self::parse_inject`] fails, if a payload with the same name is
    /// already registered under the same type, if the payload's type is `CALLOTHERFIXUP_TYPE` but
    /// names an unknown user-defined op, or if the payload's type is not recognized.
    pub fn register_inject(
        &mut self,
        mut payload: Arc<dyn InjectPayloadSleigh>,
    ) -> Result<Arc<dyn InjectPayloadSleigh>, SleighException> {
        {
            let Some(p) = Arc::get_mut(&mut payload) else {
                return Err(SleighException::with_message(
                    "register_inject: payload is unexpectedly shared before registration",
                ));
            };
            self.parse_inject(p)?;
        }
        match payload.get_type() {
            CALLFIXUP_TYPE => {
                let name = payload.get_name();
                if self.call_fixup_map.contains_key(&name) {
                    return Err(SleighException::with_message(format!(
                        "CallFixup registered multiple times: {name}"
                    )));
                }
                self.call_fixup_map.insert(name, payload.clone());
            }
            CALLOTHERFIXUP_TYPE => {
                let name = payload.get_name();
                if !self.has_user_defined_op(&name) {
                    return Err(SleighException::with_message(format!(
                        "Unknown callother name in <callotherfixup>: {name}"
                    )));
                }
                if self.call_other_fixup_map.get(&name).is_some_and(Option::is_some) {
                    return Err(SleighException::with_message(format!(
                        "Duplicate <callotherfixup> tag: {name}"
                    )));
                }
                self.call_other_fixup_map.insert(name, Some(payload.clone()));
            }
            CALLMECHANISM_TYPE => {
                let name = payload.get_name();
                if self.call_mech_fixup_map.contains_key(&name) {
                    return Err(SleighException::with_message(format!(
                        "CallMechanism registered multiple times: {name}"
                    )));
                }
                self.call_mech_fixup_map.insert(name, payload.clone());
            }
            EXECUTABLEPCODE_TYPE => {
                let name = payload.get_name();
                if self.exe_pcode_map.contains_key(&name) {
                    return Err(SleighException::with_message(format!(
                        "Executable p-code registered multiple times: {name}"
                    )));
                }
                self.exe_pcode_map.insert(name, payload.clone());
            }
            _ => return Err(SleighException::with_message("Unknown p-code inject type")),
        }
        Ok(payload)
    }

    /// Remove a specific call mechanism payload.
    ///
    /// Port of the protected `removeMechanismPayload(String)`.
    pub fn remove_mechanism_payload(&mut self, nm: &str) -> bool {
        self.call_mech_fixup_map.remove(nm).is_some()
    }

    /// Undo any previously-installed program-specific payloads and call-other overrides.
    ///
    /// Port of the protected `uninstallProgramPayloads()`.
    pub fn uninstall_program_payloads(&mut self) {
        let Some(program_payload) = self.program_payload.take() else {
            return;
        };
        for payload in &program_payload {
            match payload.get_type() {
                CALLFIXUP_TYPE => {
                    self.call_fixup_map.remove(&payload.get_name());
                }
                CALLOTHERFIXUP_TYPE => {
                    self.call_other_fixup_map.insert(payload.get_name(), None);
                }
                _ => {}
            }
        }
        if let Some(overrides) = self.call_other_override.take() {
            for payload in overrides {
                self.call_other_fixup_map.insert(payload.get_name(), Some(payload));
            }
        }
    }

    /// Look for user callother payloads that override an existing core fixup. Move these out of
    /// [`Self::call_other_fixup_map`] into [`Self::call_other_override`]. Doesn't install the user
    /// payload yet.
    ///
    /// Port of the private `setupOverrides(List<InjectPayloadSleigh>)`. Java runs this as two
    /// passes over `userPayloads` (count matching overrides, allocate an array, then re-scan and
    /// fill it) sharing the *same* `callOtherFixupMap` read across both passes -- a `userPayloads`
    /// list with more than one entry for the same overridden name would (in Java) leave a `null`
    /// hole in the resulting array, since the second pass's re-check of the map sees the first
    /// duplicate's `null` write. This single-pass port instead pulls the override out (leaving a
    /// tombstone behind) the moment it's found, which never produces such a hole -- a deliberate
    /// simplification rather than a literal reproduction of that (never-exercised in practice: no
    /// real `.pspec`/`.cspec` registers two `<callotherfixup>`s under the same target op in one
    /// batch) double-counting edge case.
    fn setup_overrides(&mut self, user_payloads: &[Arc<dyn InjectPayloadSleigh>]) {
        let mut overrides = Vec::new();
        for payload in user_payloads {
            if payload.get_type() != CALLOTHERFIXUP_TYPE {
                continue;
            }
            if let Some(slot) = self.call_other_fixup_map.get_mut(&payload.get_name()) {
                if let Some(orig) = slot.take() {
                    overrides.push(orig);
                }
            }
        }
        if !overrides.is_empty() {
            self.call_other_override = Some(overrides);
        }
    }

    /// Registers a batch of program-specific payloads, replacing any previously installed via a
    /// prior call. Payloads that fail to register are logged and skipped rather than aborting the
    /// whole batch.
    ///
    /// Port of the protected `registerProgramInject(List<InjectPayloadSleigh>)`.
    pub fn register_program_inject(&mut self, user_payloads: Vec<Arc<dyn InjectPayloadSleigh>>) {
        self.uninstall_program_payloads();
        if user_payloads.is_empty() {
            return; // Leave program_payload None if there are no program payloads.
        }
        self.setup_overrides(&user_payloads);
        let mut installed = Vec::with_capacity(user_payloads.len());
        for payload in user_payloads {
            let name = payload.get_name();
            match self.register_inject(payload) {
                Ok(registered) => installed.push(registered),
                Err(err) => {
                    Msg::warn(
                        "PcodeInjectLibrary",
                        &format!("Error installing fixup extension: {name}: {err}"),
                    );
                }
            }
        }
        self.program_payload = Some(installed);
    }

    /// The main `InjectPayload` factory interface, producing a fresh, unattached payload of the
    /// given source/name/type.
    ///
    /// Port of `allocateInject(String, String, int)`. Java documents this as overloadable by
    /// derived libraries to produce custom dynamic payloads; this crate has no derived-library
    /// mechanism (no subclassing), so it is a plain method rather than a virtual one.
    pub fn allocate_inject(
        &self,
        source_name: impl Into<String>,
        name: impl Into<String>,
        tp: i32,
    ) -> AllocatedInjectPayload {
        let source_name = source_name.into();
        match tp {
            CALLFIXUP_TYPE => AllocatedInjectPayload::Callfixup(InjectPayloadCallfixupImpl::new(source_name)),
            CALLOTHERFIXUP_TYPE => {
                AllocatedInjectPayload::Callother(InjectPayloadCallother::new(source_name))
            }
            _ => AllocatedInjectPayload::Sleigh(InjectPayloadSleighImpl::new(name, tp, source_name)),
        }
    }

    /// Encode the parts of the inject library that come from the compiler spec to the output
    /// stream.
    ///
    /// Port of `encodeCompilerSpec(Encoder)`.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    pub fn encode_compiler_spec(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        for payload in self.call_fixup_map.values() {
            payload.encode(encoder)?;
        }
        for payload in self.call_other_fixup_map.values().flatten() {
            payload.encode(encoder)?;
        }
        for payload in self.exe_pcode_map.values() {
            if payload.as_any().downcast_ref::<InjectPayloadSegment>().is_some()
                && payload.get_source().starts_with("cspec")
            {
                payload.encode(encoder)?;
            }
        }
        Ok(())
    }

    /// Restores a payload from a `<pcode>`-family XML element, registering it into this library.
    ///
    /// Port of `restoreXmlInject(String, String, int, XmlPullParser)`. See the module docs' "Gaps"
    /// section for why this returns the concrete allocated payload as `Arc<dyn
    /// InjectPayloadSleigh>` rather than calling `restoreXml` polymorphically the way Java does.
    ///
    /// # Errors
    /// Returns an error if the XML is malformed or if [`Self::register_inject`] fails.
    pub fn restore_xml_inject<P: XmlPullParser>(
        &mut self,
        source: impl Into<String>,
        name: impl Into<String>,
        tp: i32,
        parser: &mut P,
    ) -> Result<Arc<dyn InjectPayloadSleigh>, PcodeInjectLibraryError> {
        let mut allocated = self.allocate_inject(source, name, tp);
        match &mut allocated {
            AllocatedInjectPayload::Callfixup(p) => p.restore_xml(parser)?,
            AllocatedInjectPayload::Callother(p) => p.restore_xml(parser)?,
            AllocatedInjectPayload::Sleigh(p) => p.restore_xml_pcode_element(parser)?,
        }
        let payload = allocated.into_arc();
        let registered = self.register_inject(payload)?;
        Ok(registered)
    }

    /// Get the constant pool associated with the given Program. The base library never has one.
    ///
    /// Port of `getConstantPool(Program)`.
    ///
    /// # Errors
    /// Never returns an error in this port; kept fallible to mirror Java's `throws IOException`
    /// for derived libraries that might.
    pub fn get_constant_pool(
        &self,
        _program: &dyn Program,
    ) -> std::io::Result<Option<Box<dyn ConstantPool>>> {
        Ok(None)
    }

    /// Returns the current base offset for new temporary registers.
    ///
    /// Port of the protected `getUniqueBase()`.
    pub fn get_unique_base(&self) -> u64 {
        self.unique_base
    }

    /// Compare that this and the other library contain all equivalent payloads.
    ///
    /// Port of `isEquivalent(PcodeInjectLibrary)`. Java's per-entry comparisons assume the two
    /// maps have identical key sets whenever their sizes match, calling `isEquivalent(null)` (an
    /// NPE risk) if that assumption is ever violated; this instead treats a key missing from
    /// `other` as non-equivalent rather than panicking, mirroring the deviation already documented
    /// on [`InjectPayloadSegment::is_equivalent_typed`] for the same class of Java NPE risk.
    pub fn is_equivalent(&self, other: &PcodeInjectLibrary) -> bool {
        // Cannot compare unique_base: one side may not have parsed p-code.
        if self.call_fixup_map.len() != other.call_fixup_map.len() {
            return false;
        }
        for (name, payload) in &self.call_fixup_map {
            let Some(other_payload) = other.call_fixup_map.get(name) else {
                return false;
            };
            if !payload.is_equivalent(other_payload.as_ref() as &dyn InjectPayload) {
                return false;
            }
        }

        if self.call_mech_fixup_map.len() != other.call_mech_fixup_map.len() {
            return false;
        }
        for (name, payload) in &self.call_mech_fixup_map {
            let Some(other_payload) = other.call_mech_fixup_map.get(name) else {
                return false;
            };
            if !payload.is_equivalent(other_payload.as_ref() as &dyn InjectPayload) {
                return false;
            }
        }

        if self.call_other_fixup_map.len() != other.call_other_fixup_map.len() {
            return false;
        }
        for (name, payload) in &self.call_other_fixup_map {
            let Some(other_payload) = other.call_other_fixup_map.get(name) else {
                return false;
            };
            match (payload, other_payload) {
                (Some(a), Some(b)) => {
                    if !a.is_equivalent(b.as_ref() as &dyn InjectPayload) {
                        return false;
                    }
                }
                (None, None) => {}
                _ => return false,
            }
        }

        match (&self.call_other_override, &other.call_other_override) {
            (Some(a), Some(b)) => {
                if a.len() != b.len() {
                    return false;
                }
                for (pa, pb) in a.iter().zip(b.iter()) {
                    if !pa.is_equivalent(pb.as_ref() as &dyn InjectPayload) {
                        return false;
                    }
                }
            }
            (None, None) => {}
            _ => return false,
        }

        if self.exe_pcode_map.len() != other.exe_pcode_map.len() {
            return false;
        }
        for (name, payload) in &self.exe_pcode_map {
            let Some(other_payload) = other.exe_pcode_map.get(name) else {
                return false;
            };
            if !payload.is_equivalent(other_payload.as_ref() as &dyn InjectPayload) {
                return false;
            }
        }

        match (&self.program_payload, &other.program_payload) {
            (Some(a), Some(b)) => {
                if a.len() != b.len() {
                    return false;
                }
                for (pa, pb) in a.iter().zip(b.iter()) {
                    if !pa.is_equivalent(pb.as_ref() as &dyn InjectPayload) {
                        return false;
                    }
                }
            }
            (None, None) => {}
            _ => return false,
        }

        true
    }
}

/// A registered payload handed out through the
/// [`seam_stubs::PcodeInjectLibrary`](crate::program::seam_stubs::PcodeInjectLibrary) view, which
/// returns owned `Box<dyn InjectPayload>`s. The payload is shared with the library (Java hands out
/// the same object); every query delegates to it.
struct SharedInjectPayload(Arc<dyn InjectPayloadSleigh>);

impl InjectPayload for SharedInjectPayload {
    fn get_name(&self) -> String {
        self.0.get_name()
    }
    fn get_type(&self) -> i32 {
        self.0.get_type()
    }
    fn get_source(&self) -> String {
        self.0.get_source()
    }
    fn get_param_shift(&self) -> i32 {
        self.0.get_param_shift()
    }
    fn get_input(&self) -> Vec<crate::program::model::lang::inject_payload::InjectParameter> {
        self.0.get_input()
    }
    fn get_output(&self) -> Vec<crate::program::model::lang::inject_payload::InjectParameter> {
        self.0.get_output()
    }
    fn is_error_placeholder(&self) -> bool {
        self.0.is_error_placeholder()
    }
    fn inject(
        &self,
        context: &InjectContext,
        emit: &mut dyn crate::app::plugin::processors::sleigh::pcode_emit::PcodeEmit,
    ) -> Result<(), crate::program::model::lang::inject_payload::InjectPayloadError> {
        self.0.inject(context, emit)
    }
    fn get_pcode(
        &self,
        program: &dyn Program,
        context: &InjectContext,
    ) -> Result<Vec<crate::program::model::pcode::PcodeOp>, crate::program::model::lang::inject_payload::InjectPayloadError> {
        self.0.get_pcode(program, context)
    }
    fn is_fall_thru(&self) -> bool {
        self.0.is_fall_thru()
    }
    fn is_incidental_copy(&self) -> bool {
        self.0.is_incidental_copy()
    }
    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        self.0.encode(encoder)
    }
    /// A registered payload is immutable (the Java library's own contract), so it cannot be
    /// restored in place.
    fn restore_xml<P: XmlPullParser>(&mut self, _parser: &mut P, _language: &SleighLanguage) -> Result<(), XmlParseException> {
        Err(XmlParseException::new(format!("payload {} is registered and cannot be restored", self.0.get_name())))
    }
    fn is_equivalent(&self, other: &dyn InjectPayload) -> bool {
        self.0.is_equivalent(other)
    }
}

/// The library as seen through the
/// [`CompilerSpec::get_pcode_inject_library`](crate::program::model::lang::compiler_spec::CompilerSpec::get_pcode_inject_library)
/// seam.
impl crate::program::seam_stubs::PcodeInjectLibrary for PcodeInjectLibrary {
    fn get_payload(&self, inject_type: i32, name: &str) -> Option<Box<dyn InjectPayload>> {
        let payload = match inject_type {
            CALLFIXUP_TYPE => self.call_fixup_map.get(name).cloned(),
            CALLOTHERFIXUP_TYPE => self.call_other_fixup_map.get(name).cloned().flatten(),
            CALLMECHANISM_TYPE => self.call_mech_fixup_map.get(name).cloned(),
            EXECUTABLEPCODE_TYPE => self.exe_pcode_map.get(name).cloned(),
            _ => None,
        }?;
        Some(Box::new(SharedInjectPayload(payload)))
    }

    fn build_inject_context(&self) -> InjectContext {
        PcodeInjectLibrary::build_inject_context(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::pcode::PackedDecode;
    use std::collections::HashMap;

    /// Builds a real [`SleighLanguage`] with a "ram" address space and, if `with_userop` is set,
    /// one user-defined op named `"myop"` (id/index 0), decoded via `SleighLanguage::decode` --
    /// its only public constructor -- from a hand-assembled packed-binary byte sequence. The
    /// prefix (everything through `</spaces>`) is the same known-good sequence used by
    /// `inject_payload_segment.rs`'s own `test_language()` helper; the `<symbol_table>` section is
    /// new, built by hand against `PackedDecode`/`SymbolTable::decode`'s documented wire format
    /// (see that module for the header-byte encoding: `0x40|id`/`0x80|id` for element open/close,
    /// `0xC0|id` for attributes, `(typecode<<4)|lengthcode` for attribute values).
    fn test_language(with_userop: bool) -> Arc<SleighLanguage> {
        let mut data = vec![];
        // <sleigh version="4" bigendian="false">
        data.extend_from_slice(&[0x60, 0xA1, 0xE0, 0xA2, 0x21, 4, 0xE0, 0xA3, 0x10]);
        // <spaces defaultspace="ram">
        data.extend_from_slice(&[0x60, 0xA2, 0xE0, 0xA9, 0x71, 3, b'r', b'a', b'm']);
        // <space_other/>
        data.extend_from_slice(&[0x60, 0xAD, 0xA0, 0xAD]);
        // <space name="ram" size="4" index="1" delay="1"/>
        data.extend_from_slice(&[
            0x60, 0xA5, 0xCC, 0x71, 3, b'r', b'a', b'm', 0xCF, 0x21, 4, 0xC9, 0x21, 1, 0xE0, 0xAA,
            0x21, 1, 0xA0, 0xA5,
        ]);
        // </spaces>
        data.extend_from_slice(&[0xA0, 0xA2]);

        let sym_size: u8 = if with_userop { 1 } else { 0 };
        // <symbol_table scopesize="1" symbolsize="{sym_size}">
        data.extend_from_slice(&[0x60, 0xA6, 0xE0, 0xAD, 0x21, 1, 0xE0, 0xAE, 0x21, sym_size]);
        // <scope id="0" parent="0"/>
        data.extend_from_slice(&[0x56, 0xC3, 0x41, 0, 0xD6, 0x41, 0, 0x96]);
        if with_userop {
            // <userop_head name="myop" id="0" scope="0"/>
            data.extend_from_slice(&[
                0x5A, 0xCC, 0x71, 4, b'm', b'y', b'o', b'p', 0xC3, 0x41, 0, 0xCD, 0x41, 0, 0x9A,
            ]);
            // <userop id="0" index="0"/>
            data.extend_from_slice(&[0x59, 0xC3, 0x41, 0, 0xC9, 0x21, 0, 0x99]);
        }
        // </symbol_table>
        data.extend_from_slice(&[0xA0, 0xA6]);
        // </sleigh>
        data.extend_from_slice(&[0xA0, 0xA1]);

        let factory = Arc::new(crate::program::model::address::DefaultAddressFactory::new(vec![]));
        let decoder = PackedDecode::new(factory, data);
        Arc::new(SleighLanguage::decode(&decoder, "test".to_string()).expect("test language should decode"))
    }

    /// A library does not keep its language alive, so the fixtures it is built on are kept for
    /// the whole test run.
    fn library() -> PcodeInjectLibrary {
        static LANGUAGE: std::sync::OnceLock<Arc<SleighLanguage>> = std::sync::OnceLock::new();
        PcodeInjectLibrary::new(LANGUAGE.get_or_init(|| test_language(false)))
    }

    fn library_with_userop() -> PcodeInjectLibrary {
        static LANGUAGE: std::sync::OnceLock<Arc<SleighLanguage>> = std::sync::OnceLock::new();
        PcodeInjectLibrary::new(LANGUAGE.get_or_init(|| test_language(true)))
    }

    /// Unwraps the `Err` side of a [`PcodeInjectLibrary::register_inject`] result. A plain
    /// `.unwrap_err()` doesn't work here since the `Ok` type, `Arc<dyn InjectPayloadSleigh>`,
    /// doesn't implement `Debug` (as `unwrap_err` requires).
    fn expect_register_err(
        result: Result<Arc<dyn InjectPayloadSleigh>, SleighException>,
    ) -> SleighException {
        match result {
            Ok(_) => panic!("expected register_inject to fail"),
            Err(e) => e,
        }
    }

    fn dynamic_callfixup(source: &str) -> Arc<dyn InjectPayloadSleigh> {
        let mut p = InjectPayloadCallfixupImpl::new(source);
        // Directly drive the base's pcode-element parsing via a minimal dynamic XML sequence.
        let elements = vec![
            MockElement::start("callfixup", 0, &[("name", "my_fixup")]),
            MockElement::start("pcode", 1, &[("dynamic", "true")]),
            MockElement::end("pcode", 1),
            MockElement::end("callfixup", 0),
        ];
        let mut parser = QueueParser::new(elements);
        p.restore_xml(&mut parser).expect("restore_xml should succeed");
        Arc::new(p)
    }

    fn dynamic_callother(source: &str, targetop: &str) -> Arc<dyn InjectPayloadSleigh> {
        let mut p = InjectPayloadCallother::new(source);
        let elements = vec![
            MockElement::start("callotherfixup", 0, &[("targetop", targetop)]),
            MockElement::start("pcode", 1, &[("dynamic", "true")]),
            MockElement::end("pcode", 1),
            MockElement::end("callotherfixup", 0),
        ];
        let mut parser = QueueParser::new(elements);
        p.restore_xml(&mut parser).expect("restore_xml should succeed");
        Arc::new(p)
    }

    fn dynamic_sleigh(name: &str, tp: i32, source: &str) -> Arc<dyn InjectPayloadSleigh> {
        let mut p = InjectPayloadSleighImpl::new(name, tp, source);
        let elements = vec![
            MockElement::start("pcode", 0, &[("dynamic", "true")]),
            MockElement::end("pcode", 0),
        ];
        let mut parser = QueueParser::new(elements);
        p.restore_xml_pcode_element(&mut parser).expect("restore_xml should succeed");
        Arc::new(p)
    }

    #[derive(Clone)]
    struct MockElement {
        name: String,
        level: i32,
        is_start: bool,
        is_end: bool,
        attrs: HashMap<String, String>,
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
                attrs: HashMap::new(),
                text: String::new(),
            }
        }
        fn end_with_text(name: &str, level: i32, text: &str) -> Self {
            let mut e = Self::end(name, level);
            e.text = text.to_string();
            e
        }
    }
    impl crate::util::xml::xml_element::XmlElement for MockElement {
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
        fn get_attributes(&self) -> HashMap<String, String> {
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

    struct RecordingEncoder {
        events: Vec<String>,
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
        fn write_space(&mut self, attrib_id: crate::program::model::pcode::ids::AttributeId, spc: &crate::program::model::address::AddressSpace) -> std::io::Result<()> {
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

    // --- construction / unique_base ---

    #[test]
    fn new_computes_unique_base_from_language() {
        let lang = test_language(false);
        assert_eq!(lang.get_unique_base(), 0); // .sla test fixture never sets uniqbase
        let lib = PcodeInjectLibrary::new(&lang);
        assert_eq!(lib.get_unique_base(), 0x200); // UniqueLayout.INJECT
    }

    // --- has_user_defined_op ---

    #[test]
    fn has_user_defined_op_finds_real_userop_and_rejects_unknown_name() {
        let mut lib = library_with_userop();
        assert!(lib.has_user_defined_op("myop"));
        assert!(!lib.has_user_defined_op("not_a_real_op"));
    }

    #[test]
    fn has_user_defined_op_false_when_language_has_no_userops() {
        let mut lib = library();
        assert!(!lib.has_user_defined_op("myop"));
    }

    // --- register_inject: callfixup ---

    #[test]
    fn register_inject_callfixup_then_lookup_by_name() {
        let mut lib = library();
        let payload = dynamic_callfixup("test.pspec");
        lib.register_inject(payload).expect("registration should succeed");

        assert_eq!(lib.get_call_fixup_names(), vec!["my_fixup".to_string()]);
        let found = lib.get_payload(CALLFIXUP_TYPE, Some("my_fixup"));
        assert!(found.is_some());
        assert_eq!(found.unwrap().get_name(), "my_fixup");
        assert!(lib.get_payload(CALLFIXUP_TYPE, Some("nonexistent")).is_none());
        assert!(lib.get_payload(CALLFIXUP_TYPE, None).is_none());
    }

    #[test]
    fn register_inject_callfixup_duplicate_name_rejected() {
        let mut lib = library();
        lib.register_inject(dynamic_callfixup("a.pspec")).unwrap();
        let err = expect_register_err(lib.register_inject(dynamic_callfixup("b.pspec")));
        assert!(err.to_string().contains("CallFixup registered multiple times"));
    }

    // --- register_inject: callotherfixup ---

    #[test]
    fn register_inject_callotherfixup_requires_known_userop() {
        let mut lib = library(); // no userops known
        let err = expect_register_err(lib.register_inject(dynamic_callother("a.pspec", "myop")));
        assert!(err.to_string().contains("Unknown callother name"));
    }

    #[test]
    fn register_inject_callotherfixup_succeeds_for_known_userop() {
        let mut lib = library_with_userop();
        lib.register_inject(dynamic_callother("a.pspec", "myop")).expect("registration should succeed");
        assert_eq!(lib.get_callother_fixup_names(), vec!["myop".to_string()]);
        assert!(lib.get_payload(CALLOTHERFIXUP_TYPE, Some("myop")).is_some());
    }

    #[test]
    fn register_inject_callotherfixup_duplicate_rejected() {
        let mut lib = library_with_userop();
        lib.register_inject(dynamic_callother("a.pspec", "myop")).unwrap();
        let err = expect_register_err(lib.register_inject(dynamic_callother("b.pspec", "myop")));
        assert!(err.to_string().contains("Duplicate <callotherfixup> tag"));
    }

    // --- register_inject: callmechanism / executablepcode ---

    #[test]
    fn register_inject_callmechanism_then_remove() {
        let mut lib = library();
        let payload = dynamic_sleigh("uponentry", CALLMECHANISM_TYPE, "cc.cspec");
        lib.register_inject(payload).unwrap();
        assert!(lib.get_payload(CALLMECHANISM_TYPE, Some("uponentry")).is_some());
        assert!(lib.remove_mechanism_payload("uponentry"));
        assert!(!lib.remove_mechanism_payload("uponentry")); // already removed
        assert!(lib.get_payload(CALLMECHANISM_TYPE, Some("uponentry")).is_none());
    }

    #[test]
    fn register_inject_executablepcode_duplicate_rejected() {
        let mut lib = library();
        lib.register_inject(dynamic_sleigh("script1", EXECUTABLEPCODE_TYPE, "s.pspec")).unwrap();
        let err = expect_register_err(
            lib.register_inject(dynamic_sleigh("script1", EXECUTABLEPCODE_TYPE, "s2.pspec")),
        );
        assert!(err.to_string().contains("Executable p-code registered multiple times"));
    }

    // --- parse_inject ---

    /// A library over a language with a register file and a unique space (x86-64 subset,
    /// unique base 0x1000, so injected temporaries start at 0x1200).
    fn x86_library() -> PcodeInjectLibrary {
        static LANGUAGE: std::sync::OnceLock<Arc<SleighLanguage>> = std::sync::OnceLock::new();
        PcodeInjectLibrary::new(LANGUAGE.get_or_init(|| {
            crate::program::model::lang::cspec_test_support::sleigh_x86_64_language(None)
        }))
    }

    fn callfixup_with_body(name: &str, body: &str) -> InjectPayloadCallfixupImpl {
        let mut payload = InjectPayloadCallfixupImpl::new("src.cspec");
        let elements = vec![
            MockElement::start("callfixup", 0, &[("name", name)]),
            MockElement::start("pcode", 1, &[]),
            MockElement::start("body", 2, &[]),
            MockElement::end_with_text("body", 2, body),
            MockElement::end("pcode", 1),
            MockElement::end("callfixup", 0),
        ];
        let mut parser = QueueParser::new(elements);
        payload.restore_xml(&mut parser).unwrap();
        payload
    }

    #[test]
    fn parse_inject_ok_for_dynamic_payload() {
        let mut lib = library();
        let mut payload = InjectPayloadCallfixupImpl::new("src.pspec");
        assert!(lib.parse_inject(&mut payload).is_ok());
    }

    #[test]
    fn parse_inject_compiles_body_text_into_the_template() {
        let mut lib = x86_library();
        assert_eq!(lib.get_unique_base(), 0x1200);
        let mut payload = InjectPayloadSleighImpl::new("p", CALLFIXUP_TYPE, "src.pspec");
        let elements = vec![
            MockElement::start("pcode", 0, &[]),
            MockElement::start("body", 1, &[]),
            MockElement::end_with_text("body", 1, " local tmp:1 = 0; RAX = zext(tmp); "),
            MockElement::end("pcode", 0),
        ];
        let mut parser = QueueParser::new(elements);
        payload.restore_xml_pcode_element(&mut parser).unwrap();
        assert!(!payload.is_fall_thru(), "no template yet");

        lib.parse_inject(&mut payload).unwrap();

        // set_template ran: the compiled template ends in a ZEXT, which falls through.
        assert!(payload.is_fall_thru());
        // Two temporaries (tmp and the zext result) were allocated from the library's base.
        assert_eq!(lib.get_unique_base(), 0x1200 + 2 * 0x100);
        // The text was consumed: a second parse is a no-op.
        assert!(lib.parse_inject(&mut payload).is_ok());
        assert_eq!(lib.get_unique_base(), 0x1400);
    }

    #[test]
    fn parse_inject_binds_input_and_output_parameters_as_operands() {
        let mut lib = x86_library();
        let mut payload = InjectPayloadSleighImpl::new("p", CALLFIXUP_TYPE, "src.pspec");
        let elements = vec![
            MockElement::start("pcode", 0, &[]),
            MockElement::start("input", 1, &[("name", "src"), ("size", "8")]),
            MockElement::end("input", 1),
            MockElement::start("output", 1, &[("name", "dst"), ("size", "8")]),
            MockElement::end("output", 1),
            MockElement::start("body", 1, &[]),
            MockElement::end_with_text("body", 1, " dst = src + RAX; "),
            MockElement::end("pcode", 0),
        ];
        let mut parser = QueueParser::new(elements);
        payload.restore_xml_pcode_element(&mut parser).unwrap();
        lib.parse_inject(&mut payload).unwrap();

        // Without the operands the names would be unknown.
        let mut unbound = InjectPayloadSleighImpl::new("q", CALLFIXUP_TYPE, "src.pspec");
        let elements = vec![
            MockElement::start("pcode", 0, &[]),
            MockElement::start("body", 1, &[]),
            MockElement::end_with_text("body", 1, " RAX = src; "),
            MockElement::end("pcode", 0),
        ];
        let mut parser = QueueParser::new(elements);
        unbound.restore_xml_pcode_element(&mut parser).unwrap();
        let err = lib.parse_inject(&mut unbound).unwrap_err();
        assert!(err.message().contains("unknown varnode or bitrange symbol 'src'"), "{}", err.message());
    }

    #[test]
    fn register_inject_compiles_and_installs_non_dynamic_payload() {
        let mut lib = x86_library();
        let payload = callfixup_with_body("real_fixup", " local tmp:1 = 0; ");
        lib.register_inject(Arc::new(payload)).unwrap();
        assert!(lib.get_payload(CALLFIXUP_TYPE, Some("real_fixup")).is_some());
    }

    #[test]
    fn register_inject_rejects_payload_whose_text_does_not_compile() {
        let mut lib = x86_library();
        let payload = callfixup_with_body("bad_fixup", " RAX = nosuchreg; ");
        let err = expect_register_err(lib.register_inject(Arc::new(payload)));
        assert!(err.to_string().contains("nosuchreg"), "{err}");
        assert!(lib.get_payload(CALLFIXUP_TYPE, Some("bad_fixup")).is_none());
    }

    // --- allocate_inject / restore_xml_inject ---

    #[test]
    fn allocate_inject_produces_the_matching_concrete_type() {
        let lib = library();
        match lib.allocate_inject("src", "unused", CALLFIXUP_TYPE) {
            AllocatedInjectPayload::Callfixup(_) => {}
            _ => panic!("expected Callfixup variant"),
        }
        match lib.allocate_inject("src", "unused", CALLOTHERFIXUP_TYPE) {
            AllocatedInjectPayload::Callother(_) => {}
            _ => panic!("expected Callother variant"),
        }
        match lib.allocate_inject("src", "genericName", CALLMECHANISM_TYPE) {
            AllocatedInjectPayload::Sleigh(p) => assert_eq!(p.get_name(), "genericName"),
            _ => panic!("expected Sleigh variant"),
        }
    }

    #[test]
    fn restore_xml_inject_registers_callfixup_and_returns_it() {
        let mut lib = library();
        let elements = vec![
            MockElement::start("callfixup", 0, &[("name", "memcpy_fixup")]),
            MockElement::start("target", 1, &[("name", "memcpy")]),
            MockElement::end("target", 1),
            MockElement::start("pcode", 1, &[("dynamic", "true")]),
            MockElement::end("pcode", 1),
            MockElement::end("callfixup", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let payload = lib
            .restore_xml_inject("src.pspec", "unused", CALLFIXUP_TYPE, &mut parser)
            .expect("restore_xml_inject should succeed");

        assert_eq!(payload.get_name(), "memcpy_fixup");
        assert_eq!(lib.get_call_fixup_names(), vec!["memcpy_fixup".to_string()]);
    }

    #[test]
    fn restore_xml_inject_propagates_xml_errors() {
        let mut lib = library();
        let elements = vec![
            MockElement::start("callotherfixup", 0, &[("targetop", "op")]),
            MockElement::end("callotherfixup", 0), // missing required <pcode> child
        ];
        let mut parser = QueueParser::new(elements);
        let result = lib.restore_xml_inject("src", "unused", CALLOTHERFIXUP_TYPE, &mut parser);
        match result {
            Ok(_) => panic!("expected an error"),
            Err(PcodeInjectLibraryError::Xml(_)) => {}
            Err(other) => panic!("expected Xml error, got {other:?}"),
        }
    }

    // --- register_program_inject / uninstall / overrides ---

    #[test]
    fn register_program_inject_adds_and_uninstall_removes() {
        let mut lib = library();
        let payload = dynamic_callfixup("prog.pspec");
        lib.register_program_inject(vec![payload]);

        assert!(lib.has_program_payload("my_fixup", CALLFIXUP_TYPE));
        assert!(!lib.has_program_payload("my_fixup", CALLOTHERFIXUP_TYPE));
        assert_eq!(lib.get_program_payloads().unwrap().len(), 1);
        assert!(lib.get_payload(CALLFIXUP_TYPE, Some("my_fixup")).is_some());

        lib.uninstall_program_payloads();
        assert!(lib.get_program_payloads().is_none());
        assert!(lib.get_payload(CALLFIXUP_TYPE, Some("my_fixup")).is_none());
    }

    #[test]
    fn register_program_inject_empty_list_leaves_program_payload_none() {
        let mut lib = library();
        lib.register_program_inject(Vec::new());
        assert!(lib.get_program_payloads().is_none());
    }

    #[test]
    fn register_program_inject_skips_failing_payload_and_logs_but_keeps_others() {
        let mut lib = x86_library();
        // A payload whose text does not compile fails; a dynamic one succeeds.
        let failing = callfixup_with_body("bad_fixup", " RAX = nosuchreg; ");

        let good = dynamic_callfixup("good.pspec");
        lib.register_program_inject(vec![Arc::new(failing), good]);

        let installed = lib.get_program_payloads().expect("Some even though one failed");
        assert_eq!(installed.len(), 1);
        assert_eq!(installed[0].get_name(), "my_fixup");
        assert!(lib.get_payload(CALLFIXUP_TYPE, Some("bad_fixup")).is_none());
        assert!(lib.get_payload(CALLFIXUP_TYPE, Some("my_fixup")).is_some());
    }

    #[test]
    fn register_program_inject_overrides_existing_callotherfixup_and_uninstall_restores_it() {
        let mut lib = library_with_userop();
        lib.register_inject(dynamic_callother("core.cspec", "myop")).unwrap();
        assert!(!lib.is_override("myop", CALLOTHERFIXUP_TYPE));

        let program_override = dynamic_callother("prog.cspec", "myop");
        lib.register_program_inject(vec![program_override]);

        assert!(lib.is_override("myop", CALLOTHERFIXUP_TYPE));
        assert!(!lib.is_override("myop", CALLFIXUP_TYPE)); // wrong type never overridden
        let active = lib.get_payload(CALLOTHERFIXUP_TYPE, Some("myop")).unwrap();
        assert_eq!(active.get_source(), "prog.cspec");

        lib.uninstall_program_payloads();
        assert!(!lib.is_override("myop", CALLOTHERFIXUP_TYPE));
        let restored = lib.get_payload(CALLOTHERFIXUP_TYPE, Some("myop")).unwrap();
        assert_eq!(restored.get_source(), "core.cspec");
    }

    // --- build_inject_context ---

    #[test]
    fn build_inject_context_carries_language() {
        let lib = library();
        let ctx = lib.build_inject_context();
        assert!(ctx.language.is_some());
    }

    // --- encode_compiler_spec ---

    #[test]
    fn encode_compiler_spec_encodes_callfixups_and_callotherfixups() {
        let mut lib = library_with_userop();
        lib.register_inject(dynamic_callfixup("a.pspec")).unwrap();
        lib.register_inject(dynamic_callother("b.pspec", "myop")).unwrap();

        let mut enc = RecordingEncoder { events: Vec::new() };
        lib.encode_compiler_spec(&mut enc).unwrap();
        assert!(enc.events.iter().any(|e| e == "open:callfixup"));
        assert!(enc.events.iter().any(|e| e == "open:callotherfixup"));
    }

    #[test]
    fn encode_compiler_spec_only_encodes_cspec_sourced_segments_from_exe_pcode_map() {
        let mut lib = library();
        // A second, independent language handle for the same fixture -- used only to drive
        // `InjectPayloadSegment::restore_xml`, which needs a `&SleighLanguage` and
        // `PcodeInjectLibrary` doesn't expose its own `language` field.
        let lang = test_language(false);

        // A generic (non-Segment) EXECUTABLEPCODE_TYPE payload sourced from "cspec" must NOT be
        // encoded (Java's `instanceof InjectPayloadSegment` guard excludes it).
        lib.register_inject(dynamic_sleigh("script1", EXECUTABLEPCODE_TYPE, "cspec:foo")).unwrap();

        let mut segment = InjectPayloadSegment::new("cspec:seg");
        let elements = vec![
            MockElement::start("segmentop", 0, &[("space", "ram")]),
            MockElement::start("pcode", 1, &[("dynamic", "true")]),
            MockElement::end("pcode", 1),
            MockElement::end("segmentop", 0),
        ];
        let mut parser = QueueParser::new(elements);
        segment.restore_xml(&mut parser, &lang).unwrap();
        lib.register_inject(Arc::new(segment)).unwrap();

        // A Segment payload NOT sourced from "cspec" must also be excluded.
        let mut other_segment = InjectPayloadSegment::new("pspec:seg");
        let elements2 = vec![
            MockElement::start("segmentop", 0, &[("userop", "otherseg"), ("space", "ram")]),
            MockElement::start("pcode", 1, &[("dynamic", "true")]),
            MockElement::end("pcode", 1),
            MockElement::end("segmentop", 0),
        ];
        let mut parser2 = QueueParser::new(elements2);
        other_segment.restore_xml(&mut parser2, &lang).unwrap();
        lib.register_inject(Arc::new(other_segment)).unwrap();

        let mut enc = RecordingEncoder { events: Vec::new() };
        lib.encode_compiler_spec(&mut enc).unwrap();
        assert_eq!(enc.events.iter().filter(|e| **e == "open:segmentop").count(), 1);
    }

    // --- get_constant_pool ---

    #[test]
    fn get_constant_pool_is_always_none() {
        let lib = library();
        let result = lib.get_constant_pool(&MockProgram).expect("never errors in this port");
        assert!(result.is_none());
    }

    // --- is_equivalent ---

    #[test]
    fn is_equivalent_true_for_matching_libraries() {
        let mut a = library();
        a.register_inject(dynamic_callfixup("x.pspec")).unwrap();
        let mut b = library();
        b.register_inject(dynamic_callfixup("x.pspec")).unwrap();
        assert!(a.is_equivalent(&b));
    }

    #[test]
    fn is_equivalent_false_for_different_payload_sets() {
        let mut a = library();
        a.register_inject(dynamic_callfixup("x.pspec")).unwrap();
        let b = library();
        assert!(!a.is_equivalent(&b));
        assert!(!b.is_equivalent(&a));
    }

    #[test]
    fn is_equivalent_reflexive_on_empty_libraries() {
        let a = library();
        let b = library();
        assert!(a.is_equivalent(&b));
    }

    // --- is_override / has_program_payload on a fresh library ---

    #[test]
    fn is_override_and_has_program_payload_false_on_fresh_library() {
        let lib = library();
        assert!(!lib.is_override("anything", CALLOTHERFIXUP_TYPE));
        assert!(!lib.has_program_payload("anything", CALLFIXUP_TYPE));
        assert!(lib.get_program_payloads().is_none());
    }

    // --- Clone shares payloads (mirrors Java's reference-sharing copy constructor) ---

    #[test]
    fn clone_shares_payloads_via_arc() {
        let mut lib = library();
        lib.register_inject(dynamic_callfixup("x.pspec")).unwrap();
        let cloned = lib.clone();

        let original_ptr = Arc::as_ptr(lib.call_fixup_map.get("my_fixup").unwrap()) as *const ();
        let cloned_ptr = Arc::as_ptr(cloned.call_fixup_map.get("my_fixup").unwrap()) as *const ();
        assert_eq!(original_ptr, cloned_ptr, "clone should share the same payload instance");
    }
}
