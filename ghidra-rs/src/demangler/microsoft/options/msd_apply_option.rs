//! Port of `ghidra.app.util.demangler.microsoft.options.MsdApplyOption`.

use std::fmt;
use std::ops::{Deref, DerefMut};

use serde::{Serialize, Serializer};

use crate::demangler::demangler_options::DemanglerOptions;
use crate::demangler::microsoft::ms_c_interpretation::MsCInterpretation;
use crate::framework::options::custom_option::CustomOption;
use crate::framework::seam_stubs::GProperties;
use crate::generic::json::Json;

const DEMANGLE_USE_KNOWN_PATTERNS: &str = "demangleOnlyKnownMangledSymbols";
const APPLY_SIGNATURE: &str = "applyFunctionSignatures";
const APPLY_CALLING_CONVENTION: &str = "applyFunctionCallingConventions";
const MS_C_INTERPRETATION: &str = "C-StyleSymbolInterpretation";

/// The "Apply" option of the Microsoft demangler analyzer, paired in Java with a custom options
/// editor panel. Together with the separate output option, its values are pushed into
/// `MicrosoftDemanglerOptions` to control the analyzer and the underlying demangler.
///
/// Port of `ghidra.app.util.demangler.microsoft.options.MsdApplyOption`. Java extends
/// [`DemanglerOptions`]; as with the crate's other demangler option types, that base is embedded
/// by composition and reached through [`Deref`]/[`DerefMut`]. The Java `CustomOption` interface is
/// implemented as [`CustomOption`].
///
/// Equality mirrors Java's `equals`: it compares the three options this type persists plus the
/// interpretation, and ignores the inherited `doDisassembly` flag.
#[derive(Debug, Clone, Serialize)]
pub struct MsdApplyOption {
    /// Java's `ReflectionToStringBuilder` lists a class's own fields before its superclass's.
    #[serde(serialize_with = "serialize_interpretation")]
    interpretation: MsCInterpretation,
    #[serde(flatten)]
    options: DemanglerOptions,
}

/// Serializes the interpretation by its Java constant name, as Java's reflective `toString`
/// renders an enum field.
fn serialize_interpretation<S: Serializer>(
    interpretation: &MsCInterpretation,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(interpretation.name())
}

impl Default for MsdApplyOption {
    /// Mirrors the no-arg constructor required for persistence: every flag `false` and
    /// [`MsCInterpretation::FunctionIfExists`], values that `read_state` is expected to overwrite.
    fn default() -> Self {
        Self::new(false, false, false, MsCInterpretation::FunctionIfExists)
    }
}

impl MsdApplyOption {
    /// Mirrors `MsdApplyOption(boolean, boolean, boolean, MsCInterpretation)`. The inherited
    /// `doDisassembly` flag keeps its [`DemanglerOptions`] default.
    pub fn new(
        demangle_only_known_patterns: bool,
        apply_signature: bool,
        apply_calling_convention: bool,
        interpretation: MsCInterpretation,
    ) -> Self {
        let mut options = DemanglerOptions::new();
        options.set_demangle_only_known_patterns(demangle_only_known_patterns);
        options.set_apply_signature(apply_signature);
        options.set_apply_calling_convention(apply_calling_convention);
        Self { interpretation, options }
    }

    /// Sets the interpretation for processing a C-style mangled symbol if there could be
    /// multiple interpretations.
    pub fn set_interpretation(&mut self, interpretation: MsCInterpretation) {
        self.interpretation = interpretation;
    }

    /// Returns the interpretation for processing a C-style mangled symbol if there could be
    /// multiple interpretations.
    pub fn interpretation(&self) -> MsCInterpretation {
        self.interpretation
    }
}

impl PartialEq for MsdApplyOption {
    fn eq(&self, other: &Self) -> bool {
        self.demangle_only_known_patterns() == other.demangle_only_known_patterns()
            && self.apply_calling_convention() == other.apply_calling_convention()
            && self.apply_signature() == other.apply_signature()
            && self.interpretation == other.interpretation
    }
}

impl Eq for MsdApplyOption {}

impl std::hash::Hash for MsdApplyOption {
    /// Hashes the same fields [`PartialEq`] compares, as Java's `hashCode` does.
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.demangle_only_known_patterns().hash(state);
        self.apply_calling_convention().hash(state);
        self.apply_signature().hash(state);
        self.interpretation.hash(state);
    }
}

impl Deref for MsdApplyOption {
    type Target = DemanglerOptions;

    fn deref(&self) -> &Self::Target {
        &self.options
    }
}

impl DerefMut for MsdApplyOption {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.options
    }
}

impl fmt::Display for MsdApplyOption {
    /// Mirrors the inherited `DemanglerOptions.toString()`, a reflective JSON rendering of every
    /// field.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Json::to_string(self))
    }
}

impl CustomOption for MsdApplyOption {
    /// Mirrors `readState(GProperties)`: each value falls back to its current setting when the
    /// properties do not hold it. An interpretation name that matches no [`MsCInterpretation`]
    /// constant also keeps the current setting, as `GProperties.getEnum` does for a value of the
    /// wrong type.
    fn read_state(&mut self, properties: &dyn GProperties) {
        let known =
            properties.get_boolean(DEMANGLE_USE_KNOWN_PATTERNS, self.demangle_only_known_patterns());
        self.set_demangle_only_known_patterns(known);
        let signature = properties.get_boolean(APPLY_SIGNATURE, self.apply_signature());
        self.set_apply_signature(signature);
        let convention =
            properties.get_boolean(APPLY_CALLING_CONVENTION, self.apply_calling_convention());
        self.set_apply_calling_convention(convention);
        let name = properties.get_enum(MS_C_INTERPRETATION, self.interpretation.name());
        if let Some(interpretation) = MsCInterpretation::value_of(&name) {
            self.interpretation = interpretation;
        }
    }

    /// Mirrors `writeState(GProperties)`.
    fn write_state(&self, properties: &mut dyn GProperties) {
        properties.put_boolean(DEMANGLE_USE_KNOWN_PATTERNS, self.demangle_only_known_patterns());
        properties.put_boolean(APPLY_SIGNATURE, self.apply_signature());
        properties.put_boolean(APPLY_CALLING_CONVENTION, self.apply_calling_convention());
        properties.put_enum(MS_C_INTERPRETATION, self.interpretation.name());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Map-backed stand-in for `GProperties`, keeping booleans and enum names apart the way
    /// Java's typed getters reject a value of the wrong type.
    #[derive(Default)]
    struct MapProperties {
        booleans: HashMap<String, bool>,
        enums: HashMap<String, String>,
    }

    impl GProperties for MapProperties {
        fn put_boolean(&mut self, name: &str, value: bool) {
            self.booleans.insert(name.to_string(), value);
        }
        fn get_boolean(&self, name: &str, default_value: bool) -> bool {
            self.booleans.get(name).copied().unwrap_or(default_value)
        }
        fn put_enum(&mut self, name: &str, value: &str) {
            self.enums.insert(name.to_string(), value.to_string());
        }
        fn get_enum(&self, name: &str, default_value: &str) -> String {
            self.enums.get(name).cloned().unwrap_or_else(|| default_value.to_string())
        }
    }

    #[test]
    fn default_constructor_values() {
        let o = MsdApplyOption::default();
        assert!(!o.demangle_only_known_patterns());
        assert!(!o.apply_signature());
        assert!(!o.apply_calling_convention());
        assert_eq!(o.interpretation(), MsCInterpretation::FunctionIfExists);
        // Not set by the constructor; keeps the DemanglerOptions default.
        assert!(o.do_disassembly());
    }

    #[test]
    fn constructor_maps_arguments_in_java_order() {
        let o = MsdApplyOption::new(true, false, true, MsCInterpretation::NonFunction);
        assert!(o.demangle_only_known_patterns());
        assert!(!o.apply_signature());
        assert!(o.apply_calling_convention());
        assert_eq!(o.interpretation(), MsCInterpretation::NonFunction);
    }

    #[test]
    fn write_state_uses_java_keys_and_enum_names() {
        let o = MsdApplyOption::new(true, false, true, MsCInterpretation::Function);
        let mut props = MapProperties::default();
        o.write_state(&mut props);
        assert_eq!(props.booleans["demangleOnlyKnownMangledSymbols"], true);
        assert_eq!(props.booleans["applyFunctionSignatures"], false);
        assert_eq!(props.booleans["applyFunctionCallingConventions"], true);
        assert_eq!(props.enums["C-StyleSymbolInterpretation"], "FUNCTION");
    }

    #[test]
    fn read_state_round_trips_write_state() {
        let original = MsdApplyOption::new(true, true, false, MsCInterpretation::NonFunction);
        let mut props = MapProperties::default();
        original.write_state(&mut props);
        let mut restored = MsdApplyOption::default();
        restored.read_state(&props);
        assert_eq!(restored, original);
        assert_eq!(restored.interpretation(), MsCInterpretation::NonFunction);
    }

    #[test]
    fn read_state_keeps_current_values_when_absent_or_unknown() {
        let mut o = MsdApplyOption::new(true, false, true, MsCInterpretation::Function);
        let mut props = MapProperties::default();
        props.put_boolean("applyFunctionSignatures", true);
        props.put_enum("C-StyleSymbolInterpretation", "NOT_A_CONSTANT");
        o.read_state(&props);
        assert!(o.demangle_only_known_patterns());
        assert!(o.apply_signature());
        assert!(o.apply_calling_convention());
        assert_eq!(o.interpretation(), MsCInterpretation::Function);
    }

    #[test]
    fn equality_ignores_do_disassembly_but_not_interpretation() {
        let a = MsdApplyOption::new(true, true, true, MsCInterpretation::Function);
        let mut b = a.clone();
        b.set_do_disassembly(false);
        assert_eq!(a, b);
        b.set_interpretation(MsCInterpretation::NonFunction);
        assert_ne!(a, b);
        let mut c = a.clone();
        c.set_apply_signature(false);
        assert_ne!(a, c);
    }

    #[test]
    fn display_lists_interpretation_by_java_name_then_base_fields() {
        let s = MsdApplyOption::default().to_string();
        let interp = s.find("\"interpretation\": \"FUNCTION_IF_EXISTS\"").expect(&s);
        let base = s.find("apply_signature").expect(&s);
        assert!(interp < base, "{s}");
    }
}
