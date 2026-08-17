use std::collections::HashSet;
use std::sync::Arc;

use super::{EmuUnixFile, EmuUnixFileDescriptor, EmuUnixFileStat, EmuUnixUser, OpenFlag};
use crate::pcode::emu::pcode_machine::PcodeMachine;
use crate::pcode::exec::pcode_arithmetic::PcodeArithmetic;
use crate::pcode::seam_stubs::EmuIOException;
use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::model::pcode::OpCode;

/// The default file descriptor associated with a file on a simulated UNIX file system.
///
/// Corresponds to `ghidra.pcode.emu.unix.DefaultEmuUnixFileHandle`.
pub struct DefaultEmuUnixFileHandle<T: 'static> {
    arithmetic: Arc<dyn PcodeArithmetic<T>>,
    file: Box<dyn EmuUnixFile<T>>,
    flags: HashSet<OpenFlag>,
    user: EmuUnixUser,
    offset_bytes: i32,
    offset: T,
}

impl<T: Clone + 'static> DefaultEmuUnixFileHandle<T> {
    /// Construct a new handle on the given file.
    pub fn new(
        machine: &dyn PcodeMachine<T>,
        c_spec: &dyn CompilerSpec,
        file: Box<dyn EmuUnixFile<T>>,
        flags: HashSet<OpenFlag>,
        user: EmuUnixUser,
    ) -> Self {
        let arithmetic = machine.get_arithmetic();
        // off_t's fundamental type
        let offset_bytes = c_spec.get_data_organization().get_long_size();
        let offset = arithmetic.from_const_u64(0, offset_bytes);
        Self { arithmetic, file, flags, user, offset_bytes, offset }
    }

    /// Get the file opened to this handle.
    pub fn file(&self) -> &dyn EmuUnixFile<T> {
        self.file.as_ref()
    }

    /// Get the user that opened this handle.
    pub fn user(&self) -> &EmuUnixUser {
        &self.user
    }

    /// Check if the file is readable.
    ///
    /// # Errors
    ///
    /// Returns [`EmuIOException`] if this handle was not opened for reading.
    pub fn check_readable(&self) -> Result<(), EmuIOException> {
        if !OpenFlag::is_read(&self.flags) {
            return Err(EmuIOException::new("File not opened for reading"));
        }
        Ok(())
    }

    /// Check if the file is writable.
    ///
    /// # Errors
    ///
    /// Returns [`EmuIOException`] if this handle was not opened for writing.
    pub fn check_writable(&self) -> Result<(), EmuIOException> {
        if !OpenFlag::is_write(&self.flags) {
            return Err(EmuIOException::new("File not opened for writing"));
        }
        Ok(())
    }

    /// Advance the handle's offset (negative to rewind).
    fn advance_offset(&mut self, len: T) {
        let sizeof_len = self.arithmetic.size_of(&len) as i32;
        self.offset = self.arithmetic.binary_op(
            OpCode::IntAdd,
            self.offset_bytes,
            self.offset_bytes,
            &self.offset,
            sizeof_len,
            &len,
        );
    }
}

impl<T: Clone + 'static> EmuUnixFileDescriptor<T> for DefaultEmuUnixFileHandle<T> {
    fn offset(&self) -> T {
        self.offset.clone()
    }

    fn seek(&mut self, offset: T) -> Result<(), EmuIOException> {
        // TODO: Where does bounds check happen?
        self.offset = offset;
        Ok(())
    }

    fn read(&mut self, buf: T) -> Result<T, EmuIOException> {
        self.check_readable()?;
        let len = self.file.read(self.arithmetic.as_ref(), self.offset.clone(), buf);
        self.advance_offset(len.clone());
        Ok(len)
    }

    fn write(&mut self, buf: T) -> Result<T, EmuIOException> {
        self.check_writable()?;
        if self.flags.contains(&OpenFlag::OAppend) {
            let st_size = self.file.stat().st_size;
            self.offset = self.arithmetic.from_const_u64(st_size as u64, self.offset_bytes);
        }
        let len = self.file.write(self.arithmetic.as_ref(), self.offset.clone(), buf);
        self.advance_offset(len.clone());
        Ok(len)
    }

    fn stat(&self) -> EmuUnixFileStat {
        self.file.stat()
    }

    fn close(&mut self) {
        // TODO: Let the file know a handle was closed?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::pcode_machine::{AccessKind, ErasedPcodeMachine, SwiMode};
    use crate::pcode::emu::pcode_thread::ErasedPcodeThread;
    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_arithmetic::Purpose;
    use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
    use crate::pcode::exec::pcode_program::PcodeProgram;
    use crate::pcode::exec::pcode_userop_library::PcodeUseropLibrary;
    use crate::program::model::address::{Address, AddressRange, AddressSpace};
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::bit_field_packing::BitFieldPacking;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::lang::compiler_spec::{CompilerSpec, EvaluationModelType};
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::decompiler_language::DecompilerLanguage;
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::lang::sleigh::SleighLanguage;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::listing::parameter::Parameter;
    use crate::program::model::pcode::{Encoder, PcodeOp};
    use crate::program::seam_stubs::{PcodeInjectLibrary, RegisterValue};
    use std::collections::HashSet as StdHashSet;

    /// A minimal in-memory file, tracking the last write for assertions.
    struct MockFile {
        data: Vec<u8>,
        stat: EmuUnixFileStat,
        last_write_offset: Option<i64>,
    }

    impl EmuUnixFile<i64> for MockFile {
        fn pathname(&self) -> &str {
            "/tmp/test"
        }

        fn read(&mut self, _arithmetic: &dyn PcodeArithmetic<i64>, offset: i64, buf: i64) -> i64 {
            let start = offset as usize;
            let want = buf as usize;
            let avail = self.data.len().saturating_sub(start);
            want.min(avail) as i64
        }

        fn write(&mut self, _arithmetic: &dyn PcodeArithmetic<i64>, offset: i64, buf: i64) -> i64 {
            self.last_write_offset = Some(offset);
            buf
        }

        fn truncate(&mut self) {
            self.data.clear();
        }

        fn stat(&self) -> EmuUnixFileStat {
            self.stat
        }
    }

    /// Arithmetic over `i64`, sufficient to exercise offset advancement and `fromConst`.
    struct SimpleArithmetic;

    impl PcodeArithmetic<i64> for SimpleArithmetic {
        fn get_domain(&self) -> &'static str {
            "test"
        }
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }
        fn unary_op(&self, _opcode: OpCode, _sizeout: i32, _sizein1: i32, in1: &i64) -> i64 {
            *in1
        }
        fn unary_op_from_pcode_op(&self, _op: &PcodeOp, in1: &i64) -> i64 {
            *in1
        }
        fn binary_op(
            &self,
            opcode: OpCode,
            _sizeout: i32,
            _sizein1: i32,
            in1: &i64,
            _sizein2: i32,
            in2: &i64,
        ) -> i64 {
            match opcode {
                OpCode::IntAdd => in1 + in2,
                _ => *in1,
            }
        }
        fn binary_op_from_pcode_op(&self, _op: &PcodeOp, in1: &i64, in2: &i64) -> i64 {
            in1 + in2
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

    /// A machine that only ever needs to hand back [`SimpleArithmetic`].
    struct MockMachine;

    impl ErasedPcodeMachine for MockMachine {}

    impl PcodeMachine<i64> for MockMachine {
        fn get_language(&self) -> &SleighLanguage {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(SimpleArithmetic)
        }
        fn set_software_interrupt_mode(&mut self, _mode: SwiMode) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_software_interrupt_mode(&self) -> SwiMode {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_userop_library(&self) -> &dyn PcodeUseropLibrary<i64> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_stub_userop_library(&self) -> &dyn PcodeUseropLibrary<i64> {
            unimplemented!("not exercised by this smoke test")
        }
        fn new_thread(&mut self) -> Arc<dyn ErasedPcodeThread> {
            unimplemented!("not exercised by this smoke test")
        }
        fn new_thread_named(&mut self, _name: &str) -> Arc<dyn ErasedPcodeThread> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thread(
            &mut self,
            _name: &str,
            _create_if_absent: bool,
        ) -> Option<Arc<dyn ErasedPcodeThread>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_all_threads(&self) -> Vec<Arc<dyn ErasedPcodeThread>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_shared_state(&self) -> &dyn PcodeExecutorState<i64> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_shared_state_mut(&mut self) -> &mut dyn PcodeExecutorState<i64> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_suspended(&mut self, _suspended: bool) {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_suspended(&self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn compile_sleigh(&self, _source_name: &str, _source: &str) -> PcodeProgram {
            unimplemented!("not exercised by this smoke test")
        }
        fn inject(&mut self, _address: &Address, _source: &str) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_inject(&self, _address: &Address) -> Option<&PcodeProgram> {
            unimplemented!("not exercised by this smoke test")
        }
        fn clear_inject(&mut self, _address: &Address) {
            unimplemented!("not exercised by this smoke test")
        }
        fn clear_all_injects(&mut self) {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_breakpoint(&mut self, _address: &Address, _sleigh_condition: &str) {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_access_breakpoint(&mut self, _range: &AddressRange, _kind: AccessKind) {
            unimplemented!("not exercised by this smoke test")
        }
        fn clear_access_breakpoints(&mut self) {
            unimplemented!("not exercised by this smoke test")
        }
    }

    /// A data organization that only ever needs to report a `long` size.
    struct MockDataOrganization;

    impl DataOrganization for MockDataOrganization {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_pointer_size(&self) -> i32 {
            8
        }
        fn get_pointer_shift(&self) -> i32 {
            0
        }
        fn is_signed_char(&self) -> bool {
            true
        }
        fn get_char_size(&self) -> i32 {
            1
        }
        fn get_wide_char_size(&self) -> i32 {
            2
        }
        fn get_short_size(&self) -> i32 {
            2
        }
        fn get_integer_size(&self) -> i32 {
            4
        }
        fn get_long_size(&self) -> i32 {
            8
        }
        fn get_long_long_size(&self) -> i32 {
            8
        }
        fn get_float_size(&self) -> i32 {
            4
        }
        fn get_double_size(&self) -> i32 {
            8
        }
        fn get_long_double_size(&self) -> i32 {
            8
        }
        fn get_absolute_max_alignment(&self) -> i32 {
            0
        }
        fn get_machine_alignment(&self) -> i32 {
            8
        }
        fn get_default_alignment(&self) -> i32 {
            1
        }
        fn get_default_pointer_alignment(&self) -> i32 {
            8
        }
        fn get_size_alignment(&self, _size: i32) -> i32 {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_bit_field_packing(&self) -> Box<dyn BitFieldPacking> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_size_alignment_count(&self) -> i32 {
            0
        }
        fn get_sizes(&self) -> Vec<i32> {
            Vec::new()
        }
        fn get_integer_c_type_approximation(&self, _size: i32, _signed: bool) -> String {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_alignment(&self, _data_type: &dyn DataType) -> i32 {
            unimplemented!("not exercised by this smoke test")
        }
    }

    /// A compiler spec that only ever needs to hand back [`MockDataOrganization`].
    struct MockCompilerSpec;

    impl CompilerSpec for MockCompilerSpec {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_compiler_spec_description(&self) -> Box<dyn CompilerSpecDescription> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_stack_pointer(&self) -> Option<RegisterRef> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_stack_right_justified(&self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_address_space(&self, _space_name: &str) -> Option<Arc<AddressSpace>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_stack_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_stack_base_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn stack_grows_negative(&self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_calling_conventions(&self) -> Vec<Box<dyn PrototypeModel>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_calling_convention(&self, _name: &str) -> Option<Box<dyn PrototypeModel>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_all_models(&self) -> Vec<Box<dyn PrototypeModel>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_decompiler_output_language(&self) -> DecompilerLanguage {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_prototype_evaluation_model(
            &self,
            _model_type: EvaluationModelType,
        ) -> Box<dyn PrototypeModel> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_global(&self, _addr: &Address) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            Box::new(MockDataOrganization)
        }
        fn get_pcode_inject_library(&self) -> Box<dyn PcodeInjectLibrary> {
            unimplemented!("not exercised by this smoke test")
        }
        fn match_convention(&self, _convention_name: &str) -> Box<dyn PrototypeModel> {
            unimplemented!("not exercised by this smoke test")
        }
        fn find_best_calling_convention(&self, _params: &[&dyn Parameter]) -> Box<dyn PrototypeModel> {
            unimplemented!("not exercised by this smoke test")
        }
        fn has_property(&self, _key: &str) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn does_c_data_type_conversions(&self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_property_as_int(&self, _key: &str, _default_int: i32) -> i32 {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_property_as_boolean(&self, _key: &str, _default_boolean: bool) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_property_or(&self, _key: &str, _default_string: &str) -> String {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_property_keys(&self) -> StdHashSet<String> {
            unimplemented!("not exercised by this smoke test")
        }
        fn encode(&self, _encoder: &mut dyn Encoder) -> std::io::Result<()> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_equivalent(&self, _other: &dyn CompilerSpec) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
    }

    fn readable_writable_file() -> Box<dyn EmuUnixFile<i64>> {
        Box::new(MockFile {
            data: vec![1, 2, 3, 4, 5],
            stat: EmuUnixFileStat { st_size: 5, ..Default::default() },
            last_write_offset: None,
        })
    }

    fn handle_with_flags(flags: HashSet<OpenFlag>) -> DefaultEmuUnixFileHandle<i64> {
        DefaultEmuUnixFileHandle::new(
            &MockMachine,
            &MockCompilerSpec,
            readable_writable_file(),
            flags,
            EmuUnixUser::DEFAULT_USER,
        )
    }

    #[test]
    fn new_derives_offset_bytes_from_compiler_spec_and_zeroes_offset() {
        let handle = handle_with_flags(OpenFlag::set([OpenFlag::ORdwr]));
        assert_eq!(handle.offset_bytes, 8);
        assert_eq!(handle.offset(), 0);
    }

    #[test]
    fn check_readable_errors_when_not_opened_for_reading() {
        let handle = handle_with_flags(OpenFlag::set([OpenFlag::OWronly]));
        let err = handle.check_readable().unwrap_err();
        assert_eq!(err.message(), "File not opened for reading");
    }

    #[test]
    fn check_writable_errors_when_not_opened_for_writing() {
        let handle = handle_with_flags(OpenFlag::set([OpenFlag::ORdonly]));
        let err = handle.check_writable().unwrap_err();
        assert_eq!(err.message(), "File not opened for writing");
    }

    #[test]
    fn read_rejects_when_not_readable() {
        let mut handle = handle_with_flags(OpenFlag::set([OpenFlag::OWronly]));
        assert!(handle.read(10).is_err());
    }

    #[test]
    fn read_advances_offset_by_bytes_read() {
        let mut handle = handle_with_flags(OpenFlag::set([OpenFlag::ORdonly]));
        let n = handle.read(3).unwrap();
        assert_eq!(n, 3);
        assert_eq!(handle.offset(), 3);
        let n = handle.read(10).unwrap();
        assert_eq!(n, 2);
        assert_eq!(handle.offset(), 5);
    }

    #[test]
    fn write_advances_offset_by_bytes_written() {
        let mut handle = handle_with_flags(OpenFlag::set([OpenFlag::OWronly]));
        let n = handle.write(4).unwrap();
        assert_eq!(n, 4);
        assert_eq!(handle.offset(), 4);
    }

    #[test]
    fn write_with_append_flag_seeks_to_end_of_file_first() {
        let mut handle = handle_with_flags(OpenFlag::set([OpenFlag::OWronly, OpenFlag::OAppend]));
        handle.seek(1).unwrap();
        let n = handle.write(3).unwrap();
        assert_eq!(n, 3);
        // st_size (5) + bytes written (3), matching Java's re-seek-to-end-then-write semantics.
        assert_eq!(handle.offset(), 8);
    }

    #[test]
    fn seek_sets_offset_directly() {
        let mut handle = handle_with_flags(OpenFlag::set([OpenFlag::ORdwr]));
        handle.seek(42).unwrap();
        assert_eq!(handle.offset(), 42);
    }

    #[test]
    fn stat_delegates_to_file() {
        let handle = handle_with_flags(OpenFlag::set([OpenFlag::ORdonly]));
        assert_eq!(handle.stat().st_size, 5);
    }

    #[test]
    fn close_is_a_no_op() {
        let mut handle = handle_with_flags(OpenFlag::set([OpenFlag::ORdonly]));
        handle.close();
    }

    #[test]
    fn file_and_user_accessors_return_constructed_values() {
        let handle = handle_with_flags(OpenFlag::set([OpenFlag::ORdonly]));
        assert_eq!(handle.file().pathname(), "/tmp/test");
        assert_eq!(handle.user().uid, EmuUnixUser::DEFAULT_USER.uid);
    }
}
