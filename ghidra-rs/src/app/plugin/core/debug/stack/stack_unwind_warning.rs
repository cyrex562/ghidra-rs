//! A warning issued while unwinding a stack.
//!
//! Port of `ghidra.app.plugin.core.debug.stack.StackUnwindWarning`.

use std::any::Any;

use crate::app::seam_stubs::{PcodeOpAst, VarnodeAst};
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::function::Function;
use crate::program::model::pcode::PcodeOp;
use crate::util::msg::Msg;

/// A warning issued while unwinding a stack.
///
/// This is designed to avoid the untamed bucket of messages that a warning set usually turns
/// into. In essence, it's still a bucket of messages; however, each type is curated and has some
/// logic for how it interacts with other messages and additional instances of itself.
pub trait StackUnwindWarning: Send + Sync {
    /// Get the message for display.
    fn get_message(&self) -> String;

    /// Check if the given warning can be omitted on account of this warning.
    ///
    /// Usually, the unwinder should be careful not to emit unnecessary warnings, but at times
    /// that can be difficult, and its proper implementation may complicate the actual unwind
    /// logic. This allows the unnecessary warning to be removed afterward.
    fn moots(&self, other: &dyn StackUnwindWarning) -> bool {
        let _ = other;
        false
    }

    /// For diagnostics, report any error details indicated by this warning, usually via [`Msg`].
    fn report_details(&self) {}

    /// Enables `instanceof`-style checks (e.g. in [`Self::moots`] overrides) on a
    /// `&dyn StackUnwindWarning`.
    fn as_any(&self) -> &dyn Any;
}

/// A warning that can be combined with other instances of itself.
pub trait Combinable<T: StackUnwindWarning> {
    fn summarize(&self, all: &[T]) -> String;
}

/// The unwind analyzer could not find an exit path from the frame's program counter.
#[derive(Debug, Clone)]
pub struct NoReturnPathStackUnwindWarning {
    pub pc: Address,
}

impl StackUnwindWarning for NoReturnPathStackUnwindWarning {
    fn get_message(&self) -> String {
        format!("Could not find a path from {} to a return", self.pc)
    }

    fn moots(&self, other: &dyn StackUnwindWarning) -> bool {
        other.as_any().is::<OpaqueReturnPathStackUnwindWarning>()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// The unwind analyzer discovered at last one exit path, but none could be analyzed.
#[derive(Debug)]
pub struct OpaqueReturnPathStackUnwindWarning {
    pub pc: Address,
    pub last: Box<dyn std::error::Error + Send + Sync>,
}

impl StackUnwindWarning for OpaqueReturnPathStackUnwindWarning {
    fn get_message(&self) -> String {
        format!(
            "Could not analyze any path from {} to a return.\nLast error: {}",
            self.pc, self.last
        )
    }

    fn report_details(&self) {
        Msg::show_error_with_error(
            "OpaqueReturnPathStackUnwindWarning",
            "Details",
            &self.get_message(),
            self.last.as_ref(),
        );
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// While analyzing instructions, the unwind analyzer encountered a call to a function whose
/// effect on the stack is unknown.
///
/// The analyzer does not descend into calls or otherwise implement inter-procedural analysis.
/// Instead, it relies on analysis already performed by Ghidra's other analyzers and/or the human
/// user. The analyzer will assume a reasonable default.
pub struct UnknownPurgeStackUnwindWarning {
    pub function: Box<dyn Function>,
}

impl StackUnwindWarning for UnknownPurgeStackUnwindWarning {
    fn get_message(&self) -> String {
        format!(
            "Function {} has unknown/invalid stack purge",
            Function::get_name(self.function.as_ref())
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Combinable<UnknownPurgeStackUnwindWarning> for UnknownPurgeStackUnwindWarning {
    fn summarize(&self, all: &[UnknownPurgeStackUnwindWarning]) -> String {
        let mut names: Vec<String> =
            all.iter().map(|w| Function::get_name(w.function.as_ref())).collect();
        names.sort();
        if all.len() > 7 {
            format!(
                "Functions {}, ... have unknown/invalid stack purge.",
                names.into_iter().take(7).collect::<Vec<_>>().join(", ")
            )
        } else {
            format!("Functions {} have unknown/invalid stack purge.", names.join(", "))
        }
    }
}

/// While analyzing instructions, the unwind analyzer encountered a call to a function whose
/// convention is not known.
///
/// The analyzer will assume the default convention for the program's compiler.
pub struct UnspecifiedConventionStackUnwindWarning {
    pub function: Box<dyn Function>,
}

impl StackUnwindWarning for UnspecifiedConventionStackUnwindWarning {
    fn get_message(&self) -> String {
        format!(
            "Function {} has unspecified convention. Using default",
            Function::get_name(self.function.as_ref())
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Combinable<UnspecifiedConventionStackUnwindWarning> for UnspecifiedConventionStackUnwindWarning {
    fn summarize(&self, all: &[UnspecifiedConventionStackUnwindWarning]) -> String {
        let mut names: Vec<String> =
            all.iter().map(|w| Function::get_name(w.function.as_ref())).collect();
        names.sort();
        if all.len() > 7 {
            format!(
                "Functions {}, ... have unspecified convention.",
                names.into_iter().take(7).collect::<Vec<_>>().join(", ")
            )
        } else {
            format!("Functions {} have unspecified convention.", names.join(", "))
        }
    }
}

/// While analyzing an indirect call, using the decompiler, the unwind analyzer obtained multiple
/// high `PcodeOp::CALL` or `PcodeOp::CALLIND` p-code ops.
///
/// Perhaps this should be replaced by an assertion, but failing fast may not be a good approach
/// for this case.
#[derive(Debug, Clone)]
pub struct MultipleHighCallsStackUnwindWarning {
    pub found: Vec<PcodeOpAst>,
}

impl StackUnwindWarning for MultipleHighCallsStackUnwindWarning {
    fn get_message(&self) -> String {
        let items: Vec<String> = self.found.iter().map(|op| op.to_string()).collect();
        format!("Caller generated multiple decompiled calls. How?: [{}]", items.join(", "))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Similar to [`MultipleHighCallsStackUnwindWarning`], except no high call p-code ops.
#[derive(Debug, Clone)]
pub struct NoHighCallsStackUnwindWarning {
    pub op: PcodeOp,
}

impl StackUnwindWarning for NoHighCallsStackUnwindWarning {
    fn get_message(&self) -> String {
        format!("Caller generated no decompiled calls. How?:{}", self.op)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// While analyzing an indirect call, the target's type was not a function pointer.
pub struct UnexpectedTargetTypeStackUnwindWarning {
    pub data_type: Box<dyn DataType>,
}

impl StackUnwindWarning for UnexpectedTargetTypeStackUnwindWarning {
    fn get_message(&self) -> String {
        format!("Indirect call target has unexpected type: {}", self.data_type.get_display_name())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// While analyzing an indirect call, couldn't get the function signature because its input
/// doesn't have a high variable.
#[derive(Debug, Clone)]
pub struct NoHighVariableFromTargetPointerTypeUnwindWarning {
    pub vn: VarnodeAst,
}

impl StackUnwindWarning for NoHighVariableFromTargetPointerTypeUnwindWarning {
    fn get_message(&self) -> String {
        format!("Input of indirect call target has no high variable: {}", self.vn)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// While analyzing an indirect call, the signature could not be derived from call-site context.
#[derive(Debug, Clone)]
pub struct CouldNotRecoverSignatureStackUnwindWarning {
    pub op: PcodeOpAst,
}

impl StackUnwindWarning for CouldNotRecoverSignatureStackUnwindWarning {
    fn get_message(&self) -> String {
        format!("Could not recover signature of indirect call: {}", self.op)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A custom warning, either because a specific type is too onerous, or because the message was
/// deserialized and the specific type and info cannot be recovered.
#[derive(Debug, Clone)]
pub struct CustomStackUnwindWarning {
    pub message: String,
}

impl StackUnwindWarning for CustomStackUnwindWarning {
    fn get_message(&self) -> String {
        self.message.clone()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn test_addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    #[test]
    fn test_no_return_path_message() {
        let w = NoReturnPathStackUnwindWarning { pc: test_addr(0x1000) };
        assert_eq!(w.get_message(), format!("Could not find a path from {} to a return", test_addr(0x1000)));
    }

    #[test]
    fn test_no_return_path_moots_opaque() {
        let w = NoReturnPathStackUnwindWarning { pc: test_addr(0x1000) };
        let other = OpaqueReturnPathStackUnwindWarning {
            pc: test_addr(0x1000),
            last: Box::new(crate::app::plugin::core::debug::stack::unwind_exception::UnwindException::new("boom")),
        };
        assert!(w.moots(&other));
    }

    #[test]
    fn test_no_return_path_does_not_moot_custom() {
        let w = NoReturnPathStackUnwindWarning { pc: test_addr(0x1000) };
        let other = CustomStackUnwindWarning { message: "unrelated".to_string() };
        assert!(!w.moots(&other));
    }

    #[test]
    fn test_opaque_return_path_message_includes_cause() {
        let w = OpaqueReturnPathStackUnwindWarning {
            pc: test_addr(0x2000),
            last: Box::new(crate::app::plugin::core::debug::stack::unwind_exception::UnwindException::new(
                "underlying failure",
            )),
        };
        let msg = w.get_message();
        assert!(msg.contains("Could not analyze any path from"));
        assert!(msg.contains("underlying failure"));
    }

    #[test]
    fn test_custom_warning_message() {
        let w = CustomStackUnwindWarning { message: "a custom message".to_string() };
        assert_eq!(w.get_message(), "a custom message");
    }

    #[test]
    fn test_default_moots_is_false() {
        let a = CustomStackUnwindWarning { message: "a".to_string() };
        let b = CustomStackUnwindWarning { message: "b".to_string() };
        assert!(!a.moots(&b));
    }

    #[test]
    fn test_no_high_calls_message() {
        use crate::program::model::pcode::{OpCode, PcodeOp, SequenceNumber};
        let op = PcodeOp::new(OpCode::Copy, SequenceNumber::new(test_addr(0x10), 0), vec![], None);
        let w = NoHighCallsStackUnwindWarning { op };
        assert!(w.get_message().starts_with("Caller generated no decompiled calls. How?:"));
    }

    #[test]
    fn test_multiple_high_calls_message_empty() {
        let w = MultipleHighCallsStackUnwindWarning { found: vec![] };
        assert_eq!(w.get_message(), "Caller generated multiple decompiled calls. How?: []");
    }
}
