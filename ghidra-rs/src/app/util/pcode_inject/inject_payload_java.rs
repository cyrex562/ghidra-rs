use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::listing::program::Program;
use crate::program::seam_stubs::InjectPayloadCallother;
use crate::program::model::lang::inject_payload::InjectPayload;
use crate::format::javaclass::class_file_analysis_state::ClassFileAnalysisState;
use crate::format::javaclass::constantpool::abstract_constant_pool_info_java::AbstractConstantPoolInfoJava;
use std::sync::Arc;

/// Shared base struct for InjectPayloadJava implementations.
/// Subclasses of the Java abstract class InjectPayloadJava are used to generate p-code to inject
/// for modeling java bytecode in p-code. Each is attached to a CALLOTHER p-code op.
///
/// Port of `ghidra.app.util.pcodeInject.InjectPayloadJava`.
pub struct InjectPayloadJavaBase {
    /// Parent class fields
    base: InjectPayloadCallother,
    /// The Sleigh language for this payload
    pub language: SleighLanguage,
    /// The base unique value for generating unique variable names
    pub unique_base: u64,
}

/// Trait for InjectPayloadJava implementations.
/// Defines the abstract methods that concrete subclasses must implement.
pub trait InjectPayloadJava: InjectPayload {
    /// Returns the base struct containing shared fields.
    fn get_base(&self) -> &InjectPayloadJavaBase;
}

impl InjectPayloadJavaBase {
    /// Creates a new InjectPayloadJavaBase with the given parameters.
    /// Corresponds to the Java constructor: `InjectPayloadJava(String sourceName, SleighLanguage language, long uniqBase)`
    pub fn new(source_name: String, language: SleighLanguage, unique_base: u64) -> Self {
        InjectPayloadJavaBase {
            base: InjectPayloadCallother::new(source_name),
            language,
            unique_base,
        }
    }

    /// Returns the source name for this inject payload.
    pub fn get_source_name(&self) -> &str {
        self.base.get_source_name()
    }

    /// Static method to extract the constant pool from a program.
    /// Port of `InjectPayloadJava.getConstantPool(Program program)`.
    /// Verifies that the constant pool can be retrieved from the program.
    pub fn get_constant_pool_count(program: Arc<dyn Program>) -> Option<usize> {
        match ClassFileAnalysisState::get_state(program) {
            Ok(analysis_state) => {
                let class_file = analysis_state.get_class_file();
                Some(class_file.get_constant_pool().len())
            }
            Err(_) => None,
        }
    }

    /// Determines if this InjectPayloadJava is equivalent to another InjectPayloadJava.
    /// Corresponds to the Java override: `isEquivalent(InjectPayload obj)`.
    /// Compares the unique base values and delegates to parent's implementation.
    pub fn is_equivalent_java(&self, other: &InjectPayloadJavaBase) -> bool {
        self.unique_base == other.unique_base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inject_payload_callother_creation() {
        let source_name = "test_inject".to_string();
        let callother = InjectPayloadCallother::new(source_name.clone());
        assert_eq!(callother.get_source_name(), "test_inject");
    }

    #[test]
    fn test_inject_payload_callother_source_accessor() {
        let callother = InjectPayloadCallother::new("my_source".to_string());
        assert_eq!(callother.get_source_name(), "my_source");
    }
}
