use super::{EmuUnixFileStat, EmuUnixUser, MODE_R, MODE_W};
use crate::pcode::exec::pcode_arithmetic::PcodeArithmetic;
use crate::pcode::seam_stubs::EmuIOException;

/// A simulated UNIX file.
///
/// Contrast this with [`EmuUnixFileDescriptor`](super::EmuUnixFileDescriptor), which is a
/// process's handle to an open file, not the file itself.
///
/// Corresponds to `ghidra.pcode.emu.unix.EmuUnixFile`.
pub trait EmuUnixFile<T> {
    /// Get the original pathname of this file.
    ///
    /// Depending on the fidelity of the file system simulator, and the actions taken by the
    /// target program, the file may no longer actually exist at this path, but it ought to have
    /// been the pathname at some point in the file's life.
    fn pathname(&self) -> &str;

    /// Read contents from the file starting at the given offset into the given buffer.
    ///
    /// This roughly follows the semantics of the UNIX `read()`. While the offset and return
    /// value may depend on the arithmetic, the actual contents read from the file should not.
    ///
    /// Returns the number of bytes read.
    fn read(&mut self, arithmetic: &dyn PcodeArithmetic<T>, offset: T, buf: T) -> T;

    /// Write contents into the file starting at the given offset from the given buffer.
    ///
    /// This roughly follows the semantics of the UNIX `write()`. While the offset and return
    /// value may depend on the arithmetic, the actual contents written to the file should not.
    ///
    /// Returns the number of bytes written.
    fn write(&mut self, arithmetic: &dyn PcodeArithmetic<T>, offset: T, buf: T) -> T;

    /// Erase the contents of the file.
    fn truncate(&mut self);

    /// Get the file's `stat` structure, as defined by the simulator.
    fn stat(&self) -> EmuUnixFileStat;

    /// Check if the given user can read this file.
    fn is_readable(&self, user: &EmuUnixUser) -> bool {
        self.stat().has_permissions(MODE_R, user)
    }

    /// Check if the given user can write this file.
    fn is_writable(&self, user: &EmuUnixUser) -> bool {
        self.stat().has_permissions(MODE_W, user)
    }

    /// Require the user to have read permission on this file.
    ///
    /// # Errors
    ///
    /// Returns [`EmuIOException`] if the user cannot read this file.
    fn check_readable(&self, user: &EmuUnixUser) -> Result<(), EmuIOException> {
        if !self.is_readable(user) {
            return Err(EmuIOException::new(format!(
                "The file {} cannot be read.",
                self.pathname()
            )));
        }
        Ok(())
    }

    /// Require the user to have write permission on this file.
    ///
    /// # Errors
    ///
    /// Returns [`EmuIOException`] if the user cannot write this file.
    fn check_writable(&self, user: &EmuUnixUser) -> Result<(), EmuIOException> {
        if !self.is_writable(user) {
            return Err(EmuIOException::new(format!(
                "The file {} cannot be written.",
                self.pathname()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace};
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::pcode::{OpCode, PcodeOp};
    use crate::program::seam_stubs::RegisterValue;
    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_arithmetic::Purpose;
    use std::sync::Arc;

    /// A minimal in-memory file, used only to prove the trait's shape is implementable and
    /// behaves like Java's default methods (permission checks derived from `stat`).
    struct MockFile {
        pathname: String,
        data: Vec<u8>,
        stat: EmuUnixFileStat,
    }

    impl EmuUnixFile<i64> for MockFile {
        fn pathname(&self) -> &str {
            &self.pathname
        }

        fn read(&mut self, _arithmetic: &dyn PcodeArithmetic<i64>, offset: i64, buf: i64) -> i64 {
            let start = offset as usize;
            let want = buf as usize;
            let avail = self.data.len().saturating_sub(start);
            want.min(avail) as i64
        }

        fn write(&mut self, _arithmetic: &dyn PcodeArithmetic<i64>, _offset: i64, buf: i64) -> i64 {
            buf
        }

        fn truncate(&mut self) {
            self.data.clear();
        }

        fn stat(&self) -> EmuUnixFileStat {
            self.stat
        }
    }

    /// A no-op arithmetic implementation, only needed to satisfy the `read`/`write` signature
    /// in tests; none of its methods are exercised.
    struct NoopArithmetic;

    impl PcodeArithmetic<i64> for NoopArithmetic {
        fn get_domain(&self) -> &'static str {
            "test"
        }
        fn get_endian(&self) -> Option<Endian> {
            None
        }
        fn unary_op(&self, _opcode: OpCode, _sizeout: i32, _sizein1: i32, in1: &i64) -> i64 {
            *in1
        }
        fn unary_op_from_pcode_op(&self, _op: &PcodeOp, in1: &i64) -> i64 {
            *in1
        }
        fn binary_op(
            &self,
            _opcode: OpCode,
            _sizeout: i32,
            _sizein1: i32,
            in1: &i64,
            _sizein2: i32,
            _in2: &i64,
        ) -> i64 {
            *in1
        }
        fn binary_op_from_pcode_op(&self, _op: &PcodeOp, in1: &i64, _in2: &i64) -> i64 {
            *in1
        }
        fn ptr_add(
            &self,
            _sizeout: i32,
            _sizein_base: i32,
            in_base: &i64,
            _sizein_index: i32,
            _in_index: &i64,
            _in_size: i32,
        ) -> i64 {
            *in_base
        }
        fn ptr_sub(
            &self,
            _sizeout: i32,
            _sizein_base: i32,
            in_base: &i64,
            _sizein_offset: i32,
            _in_offset: &i64,
        ) -> i64 {
            *in_base
        }
        fn mod_before_store(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &i64,
            _sizein_value: i32,
            in_value: &i64,
        ) -> i64 {
            *in_value
        }
        fn mod_before_store_from_pcode_op(
            &self,
            _op: &PcodeOp,
            _space: &AddressSpace,
            _in_offset: &i64,
            in_value: &i64,
        ) -> i64 {
            *in_value
        }
        fn mod_after_load(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &i64,
            _sizein_value: i32,
            in_value: &i64,
        ) -> i64 {
            *in_value
        }
        fn mod_after_load_from_pcode_op(
            &self,
            _op: &PcodeOp,
            _space: &AddressSpace,
            _in_offset: &i64,
            in_value: &i64,
        ) -> i64 {
            *in_value
        }
        fn from_const_bytes(&self, _value: &[u8]) -> i64 {
            0
        }
        fn from_const_u64(&self, value: u64, _size: i32) -> i64 {
            value as i64
        }
        fn from_const_f32(&self, _value: f32, _size: i32) -> i64 {
            0
        }
        fn from_const_f64(&self, _value: f64, _size: i32) -> i64 {
            0
        }
        fn from_const_bool(&self, value: bool, _size: i32) -> i64 {
            value as i64
        }
        fn from_const_big_int(&self, value: i128, _size: i32, _is_contextreg: bool) -> i64 {
            value as i64
        }
        fn from_const_big_int_default(&self, value: i128, _size: i32) -> i64 {
            value as i64
        }
        fn from_const_register_value(&self, _value: &dyn RegisterValue) -> i64 {
            0
        }
        fn from_const_address(&self, _address: &Address) -> i64 {
            0
        }
        fn to_concrete(&self, value: &i64, _purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
            Ok(value.to_le_bytes().to_vec())
        }
        fn is_true(&self, value: &i64, _purpose: Purpose) -> Result<bool, ConcretionError> {
            Ok(*value != 0)
        }
        fn to_register_value(
            &self,
            register: &RegisterRef,
            value: &i64,
            _purpose: Purpose,
        ) -> Result<(RegisterRef, i128), ConcretionError> {
            Ok((register.clone(), *value as i128))
        }
        fn to_big_integer(&self, value: &i64, _purpose: Purpose) -> Result<i128, ConcretionError> {
            Ok(*value as i128)
        }
        fn to_long(&self, value: &i64, _purpose: Purpose) -> Result<i64, ConcretionError> {
            Ok(*value)
        }
        fn to_float(&self, value: &i64, _purpose: Purpose) -> Result<f32, ConcretionError> {
            Ok(*value as f32)
        }
        fn to_double(&self, value: &i64, _purpose: Purpose) -> Result<f64, ConcretionError> {
            Ok(*value as f64)
        }
        fn to_address(
            &self,
            _value: &i64,
            _space: &Arc<AddressSpace>,
            purpose: Purpose,
        ) -> Result<Address, ConcretionError> {
            Err(ConcretionError::new("not supported", purpose))
        }
        fn size_of(&self, _value: &i64) -> i64 {
            8
        }
        fn size_of_abstract(&self, value: &i64) -> i64 {
            *value
        }
    }

    fn readable_file() -> MockFile {
        MockFile {
            pathname: "/tmp/test".to_string(),
            data: vec![1, 2, 3, 4, 5],
            stat: EmuUnixFileStat {
                st_mode: MODE_R,
                ..Default::default()
            },
        }
    }

    #[test]
    fn is_readable_matches_stat_permissions() {
        let file = readable_file();
        assert!(file.is_readable(&EmuUnixUser::DEFAULT_USER));
        assert!(!file.is_writable(&EmuUnixUser::DEFAULT_USER));
    }

    #[test]
    fn check_readable_ok_when_permitted() {
        let file = readable_file();
        assert!(file.check_readable(&EmuUnixUser::DEFAULT_USER).is_ok());
    }

    #[test]
    fn check_writable_errors_with_pathname_when_not_permitted() {
        let file = readable_file();
        let err = file.check_writable(&EmuUnixUser::DEFAULT_USER).unwrap_err();
        assert_eq!(err.message(), "The file /tmp/test cannot be written.");
    }

    #[test]
    fn read_returns_bytes_available_from_offset() {
        let mut file = readable_file();
        let arithmetic = NoopArithmetic;
        let n = file.read(&arithmetic, 3, 10);
        assert_eq!(n, 2);
    }

    #[test]
    fn truncate_clears_data() {
        let mut file = readable_file();
        file.truncate();
        assert!(file.data.is_empty());
    }
}
