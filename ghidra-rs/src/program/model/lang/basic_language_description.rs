//! Port of `ghidra.program.model.lang.BasicLanguageDescription`.
//!
//! In Java this is a concrete class implementing `LanguageDescription` (and extended by
//! `SleighLanguageDescription`, which in this port composes it as a field). It holds the
//! immutable description of a language: its id, processor, endianness, size, variant, version,
//! compatible compiler specs (insertion ordered, keyed by id, as Java's `LinkedHashMap`) and the
//! external tool names it is known by.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
use crate::program::model::lang::endian::Endian;
use crate::program::model::lang::language_description::LanguageDescription;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::model::lang::processor::Processor;

/// External tool name -> the names a language is known by in that tool (Java's
/// `Map<String, List<String>> externalNames`).
pub type ExternalNames = HashMap<String, Vec<String>>;

/// The basic, immutable description of a language. See the module docs.
#[derive(Clone)]
pub struct BasicLanguageDescription {
    language_id: LanguageID,
    processor: Processor,
    endian: Endian,
    instruction_endian: Endian,
    size: i32,
    variant: String,
    description: String,
    version: i32,
    minor_version: i32,
    deprecated: bool,
    /// `compatibleCompilerSpecs`: a `LinkedHashMap` in Java -- insertion ordered, and a later
    /// description with an id already present replaces the earlier one in place.
    compatible_compiler_specs: Vec<Arc<dyn CompilerSpecDescription>>,
    /// `externalNames`, which Java allows to be `null`.
    external_names: Option<ExternalNames>,
}

impl BasicLanguageDescription {
    /// Port of the `BasicLanguageDescription(LanguageID, Processor, Endian, Endian, int, String,
    /// String, int, int, boolean, List<CompilerSpecDescription>, Map<String, List<String>>)`
    /// constructor. (The single-`CompilerSpecDescription` overload is this with a one-element
    /// vector.)
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: LanguageID,
        processor: Processor,
        endian: Endian,
        instruction_endian: Endian,
        size: i32,
        variant: impl Into<String>,
        description: impl Into<String>,
        version: i32,
        minor_version: i32,
        deprecated: bool,
        compiler_specs: Vec<Arc<dyn CompilerSpecDescription>>,
        external_names: Option<ExternalNames>,
    ) -> Self {
        let mut compatible_compiler_specs: Vec<Arc<dyn CompilerSpecDescription>> = Vec::new();
        for spec in compiler_specs {
            let id = spec.get_compiler_spec_id();
            match compatible_compiler_specs
                .iter_mut()
                .find(|existing| existing.get_compiler_spec_id() == id)
            {
                Some(existing) => *existing = spec,
                None => compatible_compiler_specs.push(spec),
            }
        }
        Self {
            language_id: id,
            processor,
            endian,
            instruction_endian,
            size,
            variant: variant.into(),
            description: description.into(),
            version,
            minor_version,
            deprecated,
            compatible_compiler_specs,
            external_names,
        }
    }

    /// The processor, as the real interned [`Processor`] value (the
    /// [`LanguageDescription::get_processor`] trait method boxes the same value).
    pub fn processor(&self) -> &Processor {
        &self.processor
    }

    /// The compatible compiler spec descriptions, shared (not re-boxed), in declaration order.
    pub fn compiler_spec_descriptions(&self) -> &[Arc<dyn CompilerSpecDescription>] {
        &self.compatible_compiler_specs
    }
}

impl LanguageDescription for BasicLanguageDescription {
    fn get_language_id(&self) -> LanguageID {
        self.language_id.clone()
    }

    fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
        Box::new(self.processor.clone())
    }

    fn get_endian(&self) -> Endian {
        self.endian
    }

    fn get_instruction_endian(&self) -> Endian {
        self.instruction_endian
    }

    fn get_size(&self) -> i32 {
        self.size
    }

    fn get_variant(&self) -> String {
        self.variant.clone()
    }

    fn get_version(&self) -> i32 {
        self.version
    }

    fn get_minor_version(&self) -> i32 {
        self.minor_version
    }

    fn get_description(&self) -> String {
        self.description.clone()
    }

    fn is_deprecated(&self) -> bool {
        self.deprecated
    }

    fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
        self.compatible_compiler_specs
            .iter()
            .map(|spec| Box::new(Arc::clone(spec)) as Box<dyn CompilerSpecDescription>)
            .collect()
    }

    fn get_compiler_spec_description_by_id(
        &self,
        compiler_spec_id: &CompilerSpecID,
    ) -> Result<Box<dyn CompilerSpecDescription>, CompilerSpecNotFoundException> {
        self.compatible_compiler_specs
            .iter()
            .find(|spec| &spec.get_compiler_spec_id() == compiler_spec_id)
            .map(|spec| Box::new(Arc::clone(spec)) as Box<dyn CompilerSpecDescription>)
            .ok_or_else(|| CompilerSpecNotFoundException::new(&self.language_id, compiler_spec_id))
    }

    /// Port of `getExternalNames(String)`: a copy of the names registered for `key`, or `None`.
    fn get_external_names(&self, external_tool: &str) -> Option<Vec<String>> {
        self.external_names.as_ref()?.get(external_tool).cloned()
    }
}

/// Port of `BasicLanguageDescription.equals(Object)`: two descriptions are equal iff their
/// `LanguageID`s are equal.
impl PartialEq for BasicLanguageDescription {
    fn eq(&self, other: &Self) -> bool {
        self.language_id == other.language_id
    }
}

impl Eq for BasicLanguageDescription {}

/// Port of `BasicLanguageDescription.hashCode()` (by language id only).
impl std::hash::Hash for BasicLanguageDescription {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.language_id.hash(state);
    }
}

/// Port of `BasicLanguageDescription.toString()`: `"{processor}/{endian}/{size}/{variant}"`.
impl fmt::Display for BasicLanguageDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}/{}", self.processor, self.endian, self.size, self.variant)
    }
}

impl fmt::Debug for BasicLanguageDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BasicLanguageDescription")
            .field("language_id", &self.language_id)
            .field("processor", &self.processor)
            .field("endian", &self.endian)
            .field("size", &self.size)
            .field("variant", &self.variant)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::basic_compiler_spec_description::BasicCompilerSpecDescription;

    fn spec(id: &str, name: &str) -> Arc<dyn CompilerSpecDescription> {
        Arc::new(BasicCompilerSpecDescription::new(CompilerSpecID::new(Some(id)), name))
    }

    fn x86(id: &str, specs: Vec<Arc<dyn CompilerSpecDescription>>) -> BasicLanguageDescription {
        let mut names = ExternalNames::new();
        names.insert("IDA-PRO".to_string(), vec!["metapc".to_string()]);
        BasicLanguageDescription::new(
            LanguageID::new(id).unwrap(),
            Processor::find_or_possibly_create_processor("x86"),
            Endian::Little,
            Endian::Little,
            32,
            "default",
            "Intel/AMD 32-bit x86",
            2,
            5,
            false,
            specs,
            Some(names),
        )
    }

    #[test]
    fn accessors_report_constructor_values() {
        let d = x86("x86:LE:32:default", vec![spec("gcc", "gcc")]);
        assert_eq!(d.get_language_id().get_id_as_string(), "x86:LE:32:default");
        assert_eq!(d.get_processor().name(), "x86");
        assert_eq!(d.processor(), &Processor::find_or_possibly_create_processor("x86"));
        assert_eq!(d.get_endian(), Endian::Little);
        assert_eq!(d.get_instruction_endian(), Endian::Little);
        assert_eq!(d.get_size(), 32);
        assert_eq!(d.get_variant(), "default");
        assert_eq!(d.get_description(), "Intel/AMD 32-bit x86");
        assert_eq!((d.get_version(), d.get_minor_version()), (2, 5));
        assert!(!d.is_deprecated());
    }

    #[test]
    fn compiler_specs_keep_declaration_order_and_later_duplicates_replace_in_place() {
        let d = x86(
            "x86:LE:32:default",
            vec![spec("windows", "Visual Studio"), spec("gcc", "gcc"), spec("windows", "VS2")],
        );
        let ids: Vec<_> = d
            .get_compatible_compiler_spec_descriptions()
            .iter()
            .map(|s| (s.get_compiler_spec_id().to_string(), s.get_compiler_spec_name()))
            .collect();
        assert_eq!(
            ids,
            vec![("windows".to_string(), "VS2".to_string()), ("gcc".to_string(), "gcc".to_string())]
        );
    }

    #[test]
    fn compiler_spec_by_id_finds_or_reports_not_found() {
        let d = x86("x86:LE:32:default", vec![spec("gcc", "gcc")]);
        let found = d.get_compiler_spec_description_by_id(&CompilerSpecID::new(Some("gcc"))).unwrap();
        assert_eq!(found.get_compiler_spec_name(), "gcc");
        assert!(d
            .get_compiler_spec_description_by_id(&CompilerSpecID::new(Some("clang")))
            .is_err());
    }

    #[test]
    fn external_names_are_looked_up_by_tool() {
        let d = x86("x86:LE:32:default", vec![]);
        assert_eq!(d.get_external_names("IDA-PRO"), Some(vec!["metapc".to_string()]));
        assert_eq!(d.get_external_names("gnu"), None);
    }

    #[test]
    fn equality_and_hash_are_by_language_id_only() {
        let a = x86("x86:LE:32:default", vec![spec("gcc", "gcc")]);
        let b = x86("x86:LE:32:default", vec![]);
        let c = x86("x86:LE:32:System Management Mode", vec![]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        let set: std::collections::HashSet<_> = [a, b, c].into_iter().collect();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn display_is_processor_endian_size_variant() {
        assert_eq!(x86("x86:LE:32:default", vec![]).to_string(), "x86/little/32/default");
    }
}
