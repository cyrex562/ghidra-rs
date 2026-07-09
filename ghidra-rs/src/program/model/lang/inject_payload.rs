use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException;
use crate::program::model::listing::program::Program;
use crate::program::model::mem::MemoryAccessException;
use crate::program::model::pcode::{Encoder, PcodeOp};
use crate::program::seam_stubs::{InjectContext, PcodeEmit};
use crate::util::exception::NotFoundException;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;
use std::fmt;

/// Injection type for a subroutine call fixup.
pub const CALLFIXUP_TYPE: i32 = 1;
/// Injection type for a userop (CALLOTHER) fixup.
pub const CALLOTHERFIXUP_TYPE: i32 = 2;
/// Injection type describing a call's calling-convention mechanism.
pub const CALLMECHANISM_TYPE: i32 = 3;
/// Injection type for p-code that stands in for an entire subroutine's execution.
pub const EXECUTABLEPCODE_TYPE: i32 = 4;

/// A named, sized, positional parameter (input or output) of an [`InjectPayload`].
///
/// Port of `ghidra.program.model.lang.InjectPayload.InjectParameter`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectParameter {
    name: String,
    index: i32,
    size: i32,
}

impl InjectParameter {
    /// Creates a new inject parameter with the given name and size; its index defaults to 0.
    pub fn new(name: impl Into<String>, size: i32) -> Self {
        InjectParameter {
            name: name.into(),
            index: 0,
            size,
        }
    }

    /// Returns the parameter's name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Returns the parameter's position among the payload's other input/output parameters.
    pub fn get_index(&self) -> i32 {
        self.index
    }

    /// Returns the parameter's size, in bytes.
    pub fn get_size(&self) -> i32 {
        self.size
    }

    /// Sets the parameter's position among the payload's other input/output parameters.
    pub fn set_index(&mut self, index: i32) {
        self.index = index;
    }

    /// Determine if this `InjectParameter` and another instance are equivalent.
    pub fn is_equivalent(&self, other: &InjectParameter) -> bool {
        self.name == other.name && self.index == other.index && self.size == other.size
    }
}

/// Error produced while injecting or generating p-code from an [`InjectPayload`].
#[derive(Debug)]
pub enum InjectPayloadError {
    /// A problem establishing the injection context.
    MemoryAccess(MemoryAccessException),
    /// A problem emitting the injection p-code.
    Io(std::io::Error),
    /// There is no underlying instruction being injected.
    UnknownInstruction(UnknownInstructionException),
    /// An expected aspect of the injection is not present in the context.
    NotFound(NotFoundException),
}

impl From<MemoryAccessException> for InjectPayloadError {
    fn from(err: MemoryAccessException) -> Self {
        InjectPayloadError::MemoryAccess(err)
    }
}

impl From<std::io::Error> for InjectPayloadError {
    fn from(err: std::io::Error) -> Self {
        InjectPayloadError::Io(err)
    }
}

impl From<UnknownInstructionException> for InjectPayloadError {
    fn from(err: UnknownInstructionException) -> Self {
        InjectPayloadError::UnknownInstruction(err)
    }
}

impl From<NotFoundException> for InjectPayloadError {
    fn from(err: NotFoundException) -> Self {
        InjectPayloadError::NotFound(err)
    }
}

impl fmt::Display for InjectPayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InjectPayloadError::MemoryAccess(err) => write!(f, "{}", err),
            InjectPayloadError::Io(err) => write!(f, "{}", err),
            InjectPayloadError::UnknownInstruction(err) => write!(f, "{}", err),
            InjectPayloadError::NotFound(err) => write!(f, "{}", err),
        }
    }
}

impl std::error::Error for InjectPayloadError {}

/// A semantic (p-code) override which can be injected into analyses that work with p-code
/// (Decompiler, SymbolicPropagator). The payload typically replaces either a subroutine call or
/// a userop.
///
/// Port of `ghidra.program.model.lang.InjectPayload`.
pub trait InjectPayload {
    /// Returns the formal name for this injection.
    fn get_name(&self) -> String;

    /// Returns the type of this injection: [`CALLFIXUP_TYPE`], [`CALLMECHANISM_TYPE`], etc.
    fn get_type(&self) -> i32;

    /// Returns a string describing the source of this payload.
    fn get_source(&self) -> String;

    /// Returns the number of parameters from the original call which should be truncated.
    fn get_param_shift(&self) -> i32;

    /// Returns any input parameters for this inject.
    fn get_input(&self) -> Vec<InjectParameter>;

    /// Returns any output parameters for this inject.
    fn get_output(&self) -> Vec<InjectParameter>;

    /// If parsing a payload (from XML) fails, a placeholder payload may be substituted and this
    /// method returns true for the substitute. In all other cases, this returns false.
    fn is_error_placeholder(&self) -> bool;

    /// Given a context, send the p-code payload to the emitter.
    ///
    /// # Errors
    /// Returns an error for problems establishing the injection context, problems while
    /// emitting the injection p-code, if there is no underlying instruction being injected, or
    /// if an expected aspect of the injection is not present in context.
    fn inject(
        &self,
        context: &dyn InjectContext,
        emit: &mut dyn PcodeEmit,
    ) -> Result<(), InjectPayloadError>;

    /// A convenience function wrapping [`InjectPayload::inject`], to produce the final set of
    /// [`PcodeOp`] objects.
    ///
    /// # Errors
    /// Same as [`InjectPayload::inject`].
    fn get_pcode(
        &self,
        program: &dyn Program,
        context: &dyn InjectContext,
    ) -> Result<Vec<PcodeOp>, InjectPayloadError>;

    /// Returns true if the injected p-code falls through.
    fn is_fall_thru(&self) -> bool;

    /// Returns true if this inject's COPY operations should be treated as incidental.
    fn is_incidental_copy(&self) -> bool;

    /// Encode configuration parameters as a `<pcode>` element to the stream.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()>;

    /// Restore the payload from an XML stream. The root expected document is the `<pcode>` tag,
    /// which may be wrapped with another tag by the derived class.
    ///
    /// Generic over the parser implementation (rather than a trait object) because
    /// [`XmlPullParser`] is not object-safe; this keeps [`InjectPayload`] itself dyn-compatible
    /// for every other method.
    ///
    /// # Errors
    /// Returns an error for badly formed XML.
    fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        language: &SleighLanguage,
    ) -> Result<(), XmlParseException>
    where
        Self: Sized;

    /// Determine if this `InjectPayload` and another instance are equivalent (have the same
    /// name and generate the same p-code).
    fn is_equivalent(&self, other: &dyn InjectPayload) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockInjectContext;
    impl InjectContext for MockInjectContext {}

    struct MockPcodeEmit;
    impl PcodeEmit for MockPcodeEmit {}

    struct MockEncoder;
    impl Encoder for MockEncoder {
        fn open_element(
            &mut self,
            _elem_id: crate::program::model::pcode::ElementId,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn close_element(
            &mut self,
            _elem_id: crate::program::model::pcode::ElementId,
        ) -> std::io::Result<()> {
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
            _spc: &crate::program::model::address::AddressSpace,
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

    struct MockInjectPayload {
        name: String,
        error_placeholder: bool,
    }

    impl InjectPayload for MockInjectPayload {
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
            vec![InjectParameter::new("in0", 4)]
        }

        fn get_output(&self) -> Vec<InjectParameter> {
            vec![InjectParameter::new("out0", 8)]
        }

        fn is_error_placeholder(&self) -> bool {
            self.error_placeholder
        }

        fn inject(
            &self,
            _context: &dyn InjectContext,
            _emit: &mut dyn PcodeEmit,
        ) -> Result<(), InjectPayloadError> {
            Ok(())
        }

        fn get_pcode(
            &self,
            _program: &dyn Program,
            _context: &dyn InjectContext,
        ) -> Result<Vec<PcodeOp>, InjectPayloadError> {
            Ok(Vec::new())
        }

        fn is_fall_thru(&self) -> bool {
            true
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

    #[test]
    fn inject_parameter_getters() {
        let mut param = InjectParameter::new("p0", 4);
        assert_eq!(param.get_name(), "p0");
        assert_eq!(param.get_index(), 0);
        assert_eq!(param.get_size(), 4);
        param.set_index(2);
        assert_eq!(param.get_index(), 2);
    }

    #[test]
    fn inject_parameter_is_equivalent() {
        let a = InjectParameter::new("p0", 4);
        let b = InjectParameter::new("p0", 4);
        assert!(a.is_equivalent(&b));

        let c = InjectParameter::new("p1", 4);
        assert!(!a.is_equivalent(&c));
    }

    #[test]
    fn usable_as_trait_object() {
        let payload: Box<dyn InjectPayload> = Box::new(MockInjectPayload {
            name: "myFixup".to_string(),
            error_placeholder: false,
        });

        assert_eq!(payload.get_name(), "myFixup");
        assert_eq!(payload.get_type(), CALLFIXUP_TYPE);
        assert!(!payload.is_error_placeholder());
        assert_eq!(payload.get_input().len(), 1);
        assert_eq!(payload.get_output().len(), 1);
        assert!(payload.inject(&MockInjectContext, &mut MockPcodeEmit).is_ok());
        assert!(payload.encode(&mut MockEncoder).is_ok());
    }

    #[test]
    fn is_equivalent_compares_names() {
        let a = MockInjectPayload { name: "same".to_string(), error_placeholder: false };
        let b = MockInjectPayload { name: "same".to_string(), error_placeholder: false };
        let c = MockInjectPayload { name: "different".to_string(), error_placeholder: false };

        assert!(a.is_equivalent(&b));
        assert!(!a.is_equivalent(&c));
    }

    #[test]
    fn inject_payload_error_display() {
        let err: InjectPayloadError = NotFoundException::with_message("missing").into();
        assert_eq!(err.to_string(), "missing");

        let err: InjectPayloadError = UnknownInstructionException::new().into();
        assert!(!err.to_string().is_empty());
    }
}
