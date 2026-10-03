//! A simulated process (or thread group) has exited.
//!
//! Port of `ghidra.pcode.emu.sys.EmuProcessExitedException`.
//!
//! The simulator should catch this exception and terminate accordingly. Continuing execution of
//! the emulator beyond this exception will cause undefined behavior.
//!
//! Following this crate's composition-over-inheritance convention, this wraps an
//! [`EmuSystemException`] instead of extending it -- the same treatment [`EmuSystemException`]
//! itself gives [`PcodeExecutionException`](crate::pcode::exec::pcode_execution_exception::PcodeExecutionException).
//!
//! # Deviations from Java
//!
//! Java's `status` field is declared as a raw `Object`: the constructor is generically typed
//! (`<T> EmuProcessExitedException(PcodeArithmetic<T> arithmetic, T status)`), but that type
//! parameter is scoped to the constructor only, not the class, so at the field-storage level the
//! status value's concrete type `T` is erased the moment it's assigned. This port models that
//! same type erasure with `Box<dyn Any + Send + Sync>`, which -- per this crate's established
//! pitfall list -- cannot itself derive `Debug` (no such impl exists for a `dyn Any` trait
//! object), so [`EmuProcessExitedException`] has a hand-written [`std::fmt::Debug`] impl that
//! renders the erased status opaquely.

use std::any::Any;
use std::fmt;

use crate::pcode::emu::sys::emu_system_exception::EmuSystemException;
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};

/// A simulated process (or thread group) has exited.
///
/// Port of `ghidra.pcode.emu.sys.EmuProcessExitedException`.
pub struct EmuProcessExitedException {
    inner: EmuSystemException,
    status: Box<dyn Any + Send + Sync>,
}

impl EmuProcessExitedException {
    /// Attempt to concretize a value and convert it to a string.
    ///
    /// Port of the static `<T> String tryConcereteToString(PcodeArithmetic<T>, T)`. Java's
    /// `catch (Exception e)` catches broadly; this crate's [`PcodeArithmetic::to_big_integer`] is
    /// total (it returns a `Result` rather than throwing), so the equivalent here is simply
    /// falling back to `status`'s own `Display` rendering on `Err`, matching Java's fallback to
    /// `status.toString()`.
    pub fn try_concrete_to_string<T, A>(arithmetic: &A, status: &T) -> String
    where
        A: PcodeArithmetic<T>,
        T: fmt::Display,
    {
        match arithmetic.to_big_integer(status, Purpose::Inspect) {
            Ok(value) => value.to_string(),
            Err(_) => status.to_string(),
        }
    }

    /// Construct a process-exited exception with the given status code.
    ///
    /// This will attempt to concretize the status according to the given arithmetic, for display
    /// purposes. The original status remains accessible via [`Self::get_status`].
    ///
    /// Port of the generic constructor `<T> EmuProcessExitedException(PcodeArithmetic<T>, T)`.
    pub fn new<T, A>(arithmetic: &A, status: T) -> Self
    where
        A: PcodeArithmetic<T>,
        T: fmt::Display + Any + Send + Sync + 'static,
    {
        let message =
            format!("Process exited with status {}", Self::try_concrete_to_string(arithmetic, &status));
        Self { inner: EmuSystemException::new(message), status: Box::new(status) }
    }

    /// Get the status code as an erased `Any` of the throwing machine.
    ///
    /// Port of `getStatus()`. Callers that know the concrete status type `T` can recover it via
    /// `.downcast_ref::<T>()`.
    pub fn get_status(&self) -> &(dyn Any + Send + Sync) {
        &*self.status
    }

    /// The wrapped system exception, standing in for Java's `super`.
    pub fn as_system_exception(&self) -> &EmuSystemException {
        &self.inner
    }

    /// Consume this exception and return the wrapped system exception.
    pub fn into_system_exception(self) -> EmuSystemException {
        self.inner
    }

    /// Stands in for the inherited `Throwable.getMessage()`.
    pub fn message(&self) -> &str {
        self.inner.message()
    }

    /// Stands in for the inherited `PcodeExecutionException.getFrame()`.
    pub fn frame(&self) -> Option<&crate::pcode::exec::pcode_frame::PcodeFrame> {
        self.inner.frame()
    }
}

impl fmt::Debug for EmuProcessExitedException {
    /// See the module docs for why `status` (a `Box<dyn Any + Send + Sync>`) cannot participate
    /// in a derived `Debug` impl.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmuProcessExitedException")
            .field("inner", &self.inner)
            .field("status", &"<erased status>")
            .finish()
    }
}

impl fmt::Display for EmuProcessExitedException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl std::error::Error for EmuProcessExitedException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_arithmetic::Purpose;
    use crate::program::model::address::AddressSpace;
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::pcode::OpCode;

    /// A minimal `PcodeArithmetic<i64>` whose `to_big_integer` always succeeds, exercising the
    /// "concrete" branch of `tryConcereteToString`/the constructor's message. Only
    /// `get_endian`/`to_concrete` (the methods `try_concrete_to_string` actually reaches through
    /// `to_big_integer`) are meaningfully implemented; everything else this trait requires is
    /// present only to satisfy the trait and is never called.
    struct ConcreteArithmetic;

    impl PcodeArithmetic<i64> for ConcreteArithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }

        fn unary_op(&self, _opcode: OpCode, _sizeout: i32, _sizein1: i32, _in1: &i64) -> i64 {
            unimplemented!("not exercised by these tests")
        }

        fn binary_op(
            &self,
            _opcode: OpCode,
            _sizeout: i32,
            _sizein1: i32,
            _in1: &i64,
            _sizein2: i32,
            _in2: &i64,
        ) -> i64 {
            unimplemented!("not exercised by these tests")
        }

        fn mod_before_store(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &i64,
            _sizein_value: i32,
            _in_value: &i64,
        ) -> i64 {
            unimplemented!("not exercised by these tests")
        }

        fn mod_after_load(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &i64,
            _sizein_value: i32,
            _in_value: &i64,
        ) -> i64 {
            unimplemented!("not exercised by these tests")
        }

        fn from_const_bytes(&self, _value: &[u8]) -> i64 {
            unimplemented!("not exercised by these tests")
        }

        fn to_concrete(&self, value: &i64, _purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
            Ok(value.to_le_bytes().to_vec())
        }

        fn size_of(&self, _value: &i64) -> i64 {
            unimplemented!("not exercised by these tests")
        }
    }

    /// A `PcodeArithmetic<String>` whose `to_concrete` always fails, exercising the fallback
    /// branch of `tryConcereteToString` (falls back to `status.toString()` -- here, `Display`).
    struct SymbolicArithmetic;

    impl PcodeArithmetic<String> for SymbolicArithmetic {
        fn get_endian(&self) -> Option<Endian> {
            None
        }

        fn unary_op(&self, _opcode: OpCode, _sizeout: i32, _sizein1: i32, _in1: &String) -> String {
            unimplemented!("not exercised by these tests")
        }

        fn binary_op(
            &self,
            _opcode: OpCode,
            _sizeout: i32,
            _sizein1: i32,
            _in1: &String,
            _sizein2: i32,
            _in2: &String,
        ) -> String {
            unimplemented!("not exercised by these tests")
        }

        fn mod_before_store(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &String,
            _sizein_value: i32,
            _in_value: &String,
        ) -> String {
            unimplemented!("not exercised by these tests")
        }

        fn mod_after_load(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &String,
            _sizein_value: i32,
            _in_value: &String,
        ) -> String {
            unimplemented!("not exercised by these tests")
        }

        fn from_const_bytes(&self, _value: &[u8]) -> String {
            unimplemented!("not exercised by these tests")
        }

        fn to_concrete(&self, _value: &String, purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
            Err(ConcretionError::new("cannot concretize a symbolic status", purpose))
        }

        fn size_of(&self, _value: &String) -> i64 {
            unimplemented!("not exercised by these tests")
        }
    }

    #[test]
    fn try_concrete_to_string_renders_a_concretizable_status_as_its_integer_value() {
        let s = EmuProcessExitedException::try_concrete_to_string(&ConcreteArithmetic, &42i64);
        assert_eq!(s, "42");
    }

    #[test]
    fn try_concrete_to_string_falls_back_to_display_when_concretization_fails() {
        let s = EmuProcessExitedException::try_concrete_to_string(
            &SymbolicArithmetic,
            &"symbolic(RAX)".to_string(),
        );
        assert_eq!(s, "symbolic(RAX)");
    }

    #[test]
    fn new_formats_the_message_using_the_concretized_status() {
        let e = EmuProcessExitedException::new(&ConcreteArithmetic, 7i64);
        assert_eq!(e.message(), "Process exited with status 7");
        assert!(e.frame().is_none());
    }

    #[test]
    fn new_formats_the_message_using_the_fallback_display_when_not_concretizable() {
        let e = EmuProcessExitedException::new(&SymbolicArithmetic, "symbolic(RAX)".to_string());
        assert_eq!(e.message(), "Process exited with status symbolic(RAX)");
    }

    #[test]
    fn get_status_recovers_the_original_typed_value() {
        let e = EmuProcessExitedException::new(&ConcreteArithmetic, 99i64);
        assert_eq!(e.get_status().downcast_ref::<i64>(), Some(&99i64));
    }

    #[test]
    fn get_status_does_not_downcast_to_an_unrelated_type() {
        let e = EmuProcessExitedException::new(&ConcreteArithmetic, 99i64);
        assert_eq!(e.get_status().downcast_ref::<String>(), None);
    }

    #[test]
    fn display_matches_message() {
        let e = EmuProcessExitedException::new(&ConcreteArithmetic, 0i64);
        assert_eq!(e.to_string(), "Process exited with status 0");
    }

    #[test]
    fn debug_renders_without_panicking_and_hides_the_erased_status() {
        let e = EmuProcessExitedException::new(&ConcreteArithmetic, 5i64);
        let rendered = format!("{:?}", e);
        assert!(rendered.contains("EmuProcessExitedException"));
        assert!(rendered.contains("<erased status>"));
    }

    /// The wrapped exception is, in turn, a wrapper around a
    /// [`PcodeExecutionException`](crate::pcode::exec::pcode_execution_exception::PcodeExecutionException),
    /// matching the two-level Java hierarchy this composes over.
    #[test]
    fn as_system_exception_reaches_the_wrapped_execution_exception() {
        let e = EmuProcessExitedException::new(&ConcreteArithmetic, 1i64);
        let sys = e.as_system_exception();
        let exec = sys.as_execution_exception();
        assert_eq!(exec.message(), "Process exited with status 1");
    }

    #[test]
    fn into_system_exception_preserves_state() {
        let e = EmuProcessExitedException::new(&ConcreteArithmetic, 3i64);
        let inner = e.into_system_exception();
        assert_eq!(inner.message(), "Process exited with status 3");
    }
}
