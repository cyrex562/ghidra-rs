//! A library of system calls.
//!
//! Corresponds to `ghidra.pcode.emu.sys.EmuSyscallLibrary`.
//!
//! A system call library is a collection of p-code executable routines, invoked by a system call
//! dispatcher. That dispatcher is [`EmuSyscallLibrary::syscall`], and is exported as a Sleigh
//! userop via [`EmuSyscallLibrary::get_syscall_userop`]. If this trait is implemented alongside
//! [`AnnotatedPcodeUseropLibrary`](crate::pcode::exec::annotated_pcode_userop_library::AnnotatedPcodeUseropLibrary),
//! that userop is automatically included in the userop library.
//!
//! Java declares the map-loading helpers as `static` methods on the interface; Rust has no static
//! interface methods, so they are free functions in this module. Java's two `loadSyscallNumberMap`
//! overloads (one over a data file, one over a program) cannot share a name here, so they are
//! [`load_syscall_number_map_from_file`] and [`load_syscall_number_map`].

use std::collections::HashMap;
use std::fmt;
use std::io::{self, BufRead, BufReader};
use std::marker::PhantomData;
use std::sync::Arc;

use crate::framework::application::Application;
use crate::pcode::exec::pcode_execution_exception::PcodeExecutionException;
use crate::pcode::exec::pcode_executor::PcodeExecutor;
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_executor_state_piece::Reason;
use crate::pcode::exec::pcode_userop_library::{
    ErasedPcodeUseropLibrary, PcodeUseropDefinition, PcodeUseropLibrary,
};
use crate::pcode::seam_stubs::EmuInvalidSystemCallException;
use crate::program::model::lang::prototype_model::PrototypeModel;
use crate::program::model::listing::function::Function;
use crate::program::model::listing::program::Program;
use crate::program::model::pcode::{PcodeOp, Varnode};
use crate::program::model::symbol::SymbolType;

/// The name of the address space into which syscall "functions" are placed by analysis.
pub const SYSCALL_SPACE_NAME: &str = "syscall";

/// The name of the calling convention used by syscall "functions".
pub const SYSCALL_CONVENTION_NAME: &str = "syscall";

/// The program has no [`SYSCALL_SPACE_NAME`] address space.
///
/// Port of the `IllegalStateException` thrown by `loadSyscallFunctionMap`. This is a recoverable
/// condition from the caller's point of view -- the program simply has not been analyzed for
/// syscalls yet -- so it is reported rather than raised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoSyscallSpaceError;

impl fmt::Display for NoSyscallSpaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("No syscall address space in program. Please analyze the syscalls first.")
    }
}

impl std::error::Error for NoSyscallSpaceError {}

/// Derive a syscall number to name map from the specification in a given file.
///
/// `data_file_name` is the file name to be found in a module's data directory. Java reaches the
/// module data directories through the `Application` singleton's statics; this crate models
/// `Application` as a trait with no global instance, so the application is passed in.
///
/// Lines are stripped, `#`-prefixed lines are comments, and every remaining line must hold exactly
/// two whitespace-separated fields: the decimal syscall number and its name.
pub fn load_syscall_number_map_from_file(
    app: &(impl Application + ?Sized),
    data_file_name: &str,
) -> io::Result<HashMap<i64, String>> {
    let map_file = app.find_data_file_in_any_module(data_file_name).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("Cannot find syscall number map: {}", data_file_name),
        )
    })?;
    let mut result = HashMap::new();

    let reader = BufReader::new(map_file.get_input_stream()?);
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Badly formatted syscall number map: {}. Line: {}",
                    data_file_name, line
                ),
            ));
        }
        let number: i64 = parts[0].parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Badly formatted syscall number map: {}", data_file_name),
            )
        })?;
        result.insert(number, parts[1].to_string());
    }
    Ok(result)
}

/// Scrape functions from the given program's "syscall" space, keyed by syscall number.
pub fn load_syscall_function_map(
    program: &mut (impl Program + ?Sized),
) -> Result<HashMap<i64, Arc<dyn Function>>, NoSyscallSpaceError> {
    let space = program
        .get_address_factory()
        .and_then(|factory| factory.get_address_space_by_name(SYSCALL_SPACE_NAME))
        .ok_or(NoSyscallSpaceError)?;

    let mut result = HashMap::new();
    let Some(symbol_table) = program.get_symbol_table() else {
        return Ok(result);
    };
    let mut sit = symbol_table.get_symbol_iterator_from(&space.min_address(), true);
    while let Some(s) = sit.next_symbol() {
        let address = s.get_address();
        // Java compares the space by reference identity, stopping as soon as the iterator walks
        // out of the syscall space.
        if !Arc::ptr_eq(address.space(), &space) {
            break;
        }
        if s.get_symbol_type() != SymbolType::Function {
            continue;
        }
        // Java's `(Function) s.getObject()`, narrowed: see `Symbol::as_function`.
        if let Some(function) = s.as_function() {
            result.insert(address.offset(), function);
        }
    }
    Ok(result)
}

/// Derive a syscall number to name map by scraping functions in the program's "syscall" space.
///
/// `program` has likely been analyzed for system calls already.
pub fn load_syscall_number_map(
    program: &mut (impl Program + ?Sized),
) -> Result<HashMap<i64, String>, NoSyscallSpaceError> {
    Ok(load_syscall_function_map(program)?
        .into_iter()
        // `Function` inherits `Namespace`, which also declares `get_name`; Java resolves the
        // override, Rust needs the trait named.
        .map(|(number, function)| (number, Function::get_name(&*function)))
        .collect())
}

/// Derive a syscall number to calling convention map by scraping functions in the program's
/// "syscall" space.
///
/// A function with no calling convention is omitted. (Java's `Collectors.toMap` raises a
/// `NullPointerException` on such a function instead; there is no useful entry to record either
/// way.)
pub fn load_syscall_convention_map(
    program: &mut (impl Program + ?Sized),
) -> Result<HashMap<i64, Box<dyn PrototypeModel>>, NoSyscallSpaceError> {
    Ok(load_syscall_function_map(program)?
        .into_iter()
        .filter_map(|(number, function)| Some((number, function.get_calling_convention()?)))
        .collect())
}

/// The definition of a system call.
///
/// `T` is the type of data processed by the system call, typically `Vec<u8>`.
pub trait EmuSyscallDefinition<T: 'static> {
    /// Invoke the system call.
    ///
    /// `executor` is the executor for the system/thread invoking the call, and `library` the
    /// complete Sleigh userop library for the system. Java's `void invoke` reports failure by
    /// throwing a `PcodeExecutionException`, which [`EmuSyscallLibrary::syscall`] catches; hence
    /// the `Result`.
    fn invoke(
        &self,
        executor: &PcodeExecutor<T>,
        library: &dyn PcodeUseropLibrary<T>,
    ) -> Result<(), PcodeExecutionException>;
}

/// A library of system calls.
///
/// `T` is the type of data processed by the system calls, typically `Vec<u8>`.
pub trait EmuSyscallLibrary<T: 'static>: PcodeUseropLibrary<T> {
    /// Retrieve the desired system call number according to the emulated system's conventions.
    ///
    /// TODO: This should go away in favor of some specification stored in the emulated program
    /// database. Until then, we require system-specific implementations.
    ///
    /// `reason` is the reason for reading state, probably [`Reason::ExecuteRead`], but should be
    /// taken from the executor.
    fn read_syscall_number(&self, state: &dyn PcodeExecutorState<T>, reason: Reason) -> i64;

    /// Try to handle an error, usually by returning it to the user program.
    ///
    /// If the particular error was not expected, it is best practice to return false, causing the
    /// emulator to interrupt. Otherwise, some state is set in the machine that, by convention,
    /// communicates the error back to the user program.
    ///
    /// Returns true if execution can continue uninterrupted.
    fn handle_error(&self, executor: &PcodeExecutor<T>, err: &PcodeExecutionException) -> bool;

    /// Get the map of syscalls by number.
    ///
    /// Note this method will be invoked for every emulated syscall, so it should be a simple
    /// accessor. Any computations needed to create the map should be done ahead of time. Java
    /// returns the map; this borrows the library's own, which is that same simple accessor without
    /// the per-call rebuild an owned return type would invite.
    fn get_syscalls(&self) -> &HashMap<i64, Arc<dyn EmuSyscallDefinition<T>>>;

    /// In case this is not an annotated syscall/userop library, get the definition of the
    /// "syscall" userop for inclusion in the [`PcodeUseropLibrary`].
    ///
    /// Implementors may wish to override this to use a pre-constructed definition. That definition
    /// can be easily constructed using [`SyscallPcodeUseropDefinition`].
    ///
    /// The definition outlives the call, and Java's is backed by the very same library object, so
    /// this consumes an [`Arc`] of the library rather than a borrow.
    fn get_syscall_userop(self: Arc<Self>) -> Arc<dyn PcodeUseropDefinition<T>>
    where
        Self: Sized + 'static,
    {
        Arc::new(SyscallPcodeUseropDefinition::new(self))
    }

    /// The entry point for executing a system call on the given executor.
    ///
    /// The executor's state must already be prepared according to the relevant system calling
    /// conventions. This will determine the system call number, according to
    /// [`read_syscall_number`](Self::read_syscall_number), retrieve the relevant system call
    /// definition, and invoke it.
    fn syscall(
        &self,
        executor: &PcodeExecutor<T>,
        library: &dyn PcodeUseropLibrary<T>,
    ) -> Result<(), PcodeExecutionException> {
        let syscall_number = {
            let state = executor.get_state().lock().unwrap();
            self.read_syscall_number(&*state, executor.get_reason())
        };
        let syscall = self
            .get_syscalls()
            .get(&syscall_number)
            .ok_or_else(|| EmuInvalidSystemCallException::for_number(syscall_number))?;
        match syscall.invoke(executor, library) {
            Ok(()) => Ok(()),
            Err(err) => {
                if self.handle_error(executor, &err) {
                    Ok(())
                } else {
                    Err(err)
                }
            }
        }
    }
}

/// The [`EmuSyscallLibrary::syscall`] method wrapped as a userop definition.
///
/// `T` is the type of data processed by the userop, typically `Vec<u8>`; `L` is the library that
/// defines the syscalls.
pub struct SyscallPcodeUseropDefinition<T: 'static, L: EmuSyscallLibrary<T>> {
    syslib: Arc<L>,
    _value: PhantomData<fn() -> T>,
}

impl<T: 'static, L: EmuSyscallLibrary<T>> SyscallPcodeUseropDefinition<T, L> {
    /// Wrap the given library's syscall dispatcher as a userop definition.
    pub fn new(syslib: Arc<L>) -> Self {
        Self { syslib, _value: PhantomData }
    }

    /// The library whose dispatcher this userop invokes.
    pub fn syslib(&self) -> &Arc<L> {
        &self.syslib
    }
}

impl<T: 'static, L: EmuSyscallLibrary<T>> PcodeUseropDefinition<T>
    for SyscallPcodeUseropDefinition<T, L>
{
    fn get_name(&self) -> &str {
        "syscall"
    }

    fn get_input_count(&self) -> i32 {
        0
    }

    fn execute(
        &self,
        executor: &PcodeExecutor<T>,
        library: &dyn PcodeUseropLibrary<T>,
        _op: &PcodeOp,
        _out_var: Option<&Varnode>,
        _in_vars: &[Varnode],
    ) {
        // Java lets any `PcodeExecutionException` propagate out of this `void` method; the nearest
        // Rust equivalent is to panic, since the userop signature has no way to report the
        // failure. This matches `AbstractSleighPcodeUseropDefinitionBase::execute`.
        if let Err(err) = self.syslib.syscall(executor, library) {
            panic!("System call failed: {}", err.message());
        }
    }

    fn is_functional(&self) -> bool {
        false
    }

    fn has_side_effects(&self) -> bool {
        true
    }

    fn modifies_context(&self) -> bool {
        false
    }

    fn can_inline_pcode(&self) -> bool {
        false
    }

    fn get_output_type(&self) -> Option<std::any::TypeId> {
        // Java returns `void.class`; the unit type is its Rust counterpart. `None` is reserved for
        // Java's `null`, i.e. "not defined by a native callback."
        Some(std::any::TypeId::of::<()>())
    }

    fn get_java_method(&self) -> Option<()> {
        // Java reflects `syslib.getClass().getMethod("syscall", ...)`. Rust has no analog of
        // `java.lang.reflect.Method`; see `PcodeUseropDefinition::get_java_method`.
        None
    }

    fn get_defining_library(&self) -> Option<&dyn ErasedPcodeUseropLibrary> {
        Some(&*self.syslib)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io::Write;
    use std::sync::Mutex;

    use crate::generic::jar::resource_file::ResourceFile;
    use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_executor_state_piece::{
        ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece,
    };
    use crate::pcode::exec::pcode_userop_library::UseropMap;
    use crate::program::model::address::{
        Address, AddressFactory, AddressSpace, AddressSpaceType, DefaultAddressFactory,
    };
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::mem::MemBuffer;
    use crate::program::model::pcode::{OpCode, SequenceNumber};
    use crate::program::model::symbol::{
        SourceType, Symbol, SymbolIterator, SymbolTable,
    };

    // ---------------------------------------------------------------------------------------
    // Doubles for the syscall library itself
    // ---------------------------------------------------------------------------------------

    /// A syscall definition that records that it ran, and optionally fails.
    struct RecordingSyscall {
        name: &'static str,
        fails: bool,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl RecordingSyscall {
        fn arc(
            name: &'static str,
            fails: bool,
            log: &Arc<Mutex<Vec<String>>>,
        ) -> Arc<dyn EmuSyscallDefinition<i64>> {
            Arc::new(Self { name, fails, log: Arc::clone(log) })
        }
    }

    impl EmuSyscallDefinition<i64> for RecordingSyscall {
        fn invoke(
            &self,
            _executor: &PcodeExecutor<i64>,
            _library: &dyn PcodeUseropLibrary<i64>,
        ) -> Result<(), PcodeExecutionException> {
            self.log.lock().unwrap().push(self.name.to_string());
            if self.fails {
                Err(PcodeExecutionException::with_message("boom"))
            } else {
                Ok(())
            }
        }
    }

    /// A syscall library that reads a fixed number and reports a fixed error verdict.
    struct TestSyscallLibrary {
        number: i64,
        recover: bool,
        syscalls: HashMap<i64, Arc<dyn EmuSyscallDefinition<i64>>>,
        userops: UseropMap<i64>,
        /// Records the `Reason` the dispatcher passed to `read_syscall_number`.
        seen_reason: RefCell<Option<Reason>>,
    }

    impl TestSyscallLibrary {
        fn new(number: i64, recover: bool) -> Self {
            Self {
                number,
                recover,
                syscalls: HashMap::new(),
                userops: HashMap::new(),
                seen_reason: RefCell::new(None),
            }
        }

        fn with(mut self, number: i64, def: Arc<dyn EmuSyscallDefinition<i64>>) -> Self {
            self.syscalls.insert(number, def);
            self
        }
    }

    impl ErasedPcodeUseropLibrary for TestSyscallLibrary {}

    impl PcodeUseropLibrary<i64> for TestSyscallLibrary {
        fn get_userops(&self) -> &UseropMap<i64> {
            &self.userops
        }
    }

    impl EmuSyscallLibrary<i64> for TestSyscallLibrary {
        fn read_syscall_number(&self, _state: &dyn PcodeExecutorState<i64>, reason: Reason) -> i64 {
            *self.seen_reason.borrow_mut() = Some(reason);
            self.number
        }

        fn handle_error(
            &self,
            _executor: &PcodeExecutor<i64>,
            _err: &PcodeExecutionException,
        ) -> bool {
            self.recover
        }

        fn get_syscalls(&self) -> &HashMap<i64, Arc<dyn EmuSyscallDefinition<i64>>> {
            &self.syscalls
        }
    }

    // ---------------------------------------------------------------------------------------
    // Executor doubles: the executor is only ever passed through to the syscall definitions, and
    // asked for its state and reason. Paths are spelled out to keep the doubles local.
    // ---------------------------------------------------------------------------------------

    fn syscall_space() -> Arc<AddressSpace> {
        AddressSpace::new(SYSCALL_SPACE_NAME, 32, 1, AddressSpaceType::Ram, 1)
    }

    struct MockLanguage {
        default_space: Arc<AddressSpace>,
    }

    impl Language for MockLanguage {
        fn get_default_space(&self) -> Arc<AddressSpace> {
            Arc::clone(&self.default_space)
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            Arc::clone(&self.default_space)
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            None
        }
        fn get_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
            unimplemented!("not exercised by these tests")
        }
        fn get_language_description(
            &self,
        ) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>>
        {
            None
        }
        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            unimplemented!("not exercised by these tests")
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            Box::new(DefaultAddressFactory::new(vec![Arc::clone(&self.default_space)]))
        }
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_instruction_alignment(&self) -> i32 {
            1
        }
        fn supports_pcode(&self) -> bool {
            true
        }
        fn is_volatile(&self, _addr: &Address) -> bool {
            false
        }
        fn parse(
            &self,
            _buf: &dyn MemBuffer,
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
            crate::program::model::lang::language::ParseError,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_register_by_name(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_default_memory_blocks(
            &self,
        ) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            Box::new(crate::program::model::address::AddressSet::new())
        }
        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext,
        ) {
        }
        fn reload_language(
            &self,
            _task_monitor: &dyn crate::util::task::TaskMonitor,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>>
        {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> Result<
            Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec>,
            crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_compiler_spec(
            &self,
        ) -> Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec> {
            unimplemented!("not exercised by these tests")
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }
        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }
        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }
        fn has_manual(&self) -> bool {
            false
        }
        fn get_manual_entry(
            &self,
            _instruction_mnemonic: &str,
        ) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            Box::new(crate::program::model::address::AddressSet::new())
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    struct StubArithmetic;

    impl PcodeArithmetic<i64> for StubArithmetic {
        fn get_endian(&self) -> Option<crate::program::model::lang::endian::Endian> {
            Some(crate::program::model::lang::endian::Endian::Little)
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
        fn from_const_bytes(&self, _value: &[u8]) -> i64 {
            unimplemented!("not exercised by these tests")
        }
        fn to_concrete(&self, _value: &i64, _purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
            unimplemented!("not exercised by these tests")
        }
        fn size_of(&self, _value: &i64) -> i64 {
            8
        }
    }

    struct StubState;

    impl ErasedPcodeExecutorStatePiece for StubState {}

    impl PcodeExecutorStatePiece<i64, i64> for StubState {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }
        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(StubArithmetic)
        }
        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(StubArithmetic)
        }
        fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
            vec![self]
        }
        fn set_var_abstract(
            &mut self,
            _space: &Arc<AddressSpace>,
            _offset: &i64,
            _size: i32,
            _quantize: bool,
            _val: &i64,
        ) {
            unimplemented!("not exercised by these tests")
        }
        fn set_var_internal_abstract(
            &mut self,
            _space: &Arc<AddressSpace>,
            _offset: &i64,
            _size: i32,
            _val: &i64,
        ) {
            unimplemented!("not exercised by these tests")
        }
        fn get_var_abstract(
            &self,
            _space: &Arc<AddressSpace>,
            _offset: &i64,
            _size: i32,
            _quantize: bool,
            _reason: Reason,
        ) -> i64 {
            unimplemented!("not exercised by these tests")
        }
        fn get_var_internal_abstract(
            &self,
            _space: &Arc<AddressSpace>,
            _offset: &i64,
            _size: i32,
            _reason: Reason,
        ) -> i64 {
            unimplemented!("not exercised by these tests")
        }
        fn get_register_values(&self) -> Vec<(RegisterRef, i64)> {
            Vec::new()
        }
        fn get_concrete_buffer(&self, _address: &Address, _purpose: Purpose) -> Box<dyn MemBuffer> {
            unimplemented!("not exercised by these tests")
        }
        fn clear(&mut self) {}
    }

    impl PcodeExecutorState<i64> for StubState {}

    fn test_executor() -> PcodeExecutor<i64> {
        PcodeExecutor::new(
            Arc::new(MockLanguage { default_space: syscall_space() }),
            Arc::new(StubArithmetic),
            Arc::new(Mutex::new(StubState)),
            Reason::ExecuteRead,
        )
    }

    fn callother_op() -> PcodeOp {
        let space = syscall_space();
        PcodeOp::new(
            OpCode::CallOther,
            SequenceNumber::new(space.address(0), 0),
            Vec::new(),
            None,
        )
    }

    // ---------------------------------------------------------------------------------------
    // Dispatcher
    // ---------------------------------------------------------------------------------------

    #[test]
    fn syscall_dispatches_to_the_definition_for_the_read_number() {
        // Java: syscall() reads the number, looks it up in getSyscalls(), and invokes it.
        let log = Arc::new(Mutex::new(Vec::new()));
        let library = TestSyscallLibrary::new(4, false)
            .with(3, RecordingSyscall::arc("three", false, &log))
            .with(4, RecordingSyscall::arc("four", false, &log));
        let executor = test_executor();

        library.syscall(&executor, &library).expect("syscall should succeed");

        assert_eq!(*log.lock().unwrap(), vec!["four".to_string()]);
        // Java passes `executor.getReason()`, not a hard-coded reason.
        assert_eq!(*library.seen_reason.borrow(), Some(Reason::ExecuteRead));
    }

    #[test]
    fn unknown_syscall_number_is_an_invalid_system_call() {
        // Java: throw new EmuInvalidSystemCallException(syscallNumber)
        let log = Arc::new(Mutex::new(Vec::new()));
        let library =
            TestSyscallLibrary::new(9, false).with(3, RecordingSyscall::arc("three", false, &log));
        let executor = test_executor();

        let err = library.syscall(&executor, &library).expect_err("9 is not defined");
        assert_eq!(err.message(), "Invalid system call number: 9");
        assert!(log.lock().unwrap().is_empty());
    }

    #[test]
    fn handled_error_lets_execution_continue() {
        // Java: catch (PcodeExecutionException e) { if (!handleError(...)) throw e; }
        let log = Arc::new(Mutex::new(Vec::new()));
        let library =
            TestSyscallLibrary::new(1, true).with(1, RecordingSyscall::arc("fails", true, &log));
        let executor = test_executor();

        assert!(library.syscall(&executor, &library).is_ok());
        assert_eq!(*log.lock().unwrap(), vec!["fails".to_string()]);
    }

    #[test]
    fn unhandled_error_propagates() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let library =
            TestSyscallLibrary::new(1, false).with(1, RecordingSyscall::arc("fails", true, &log));
        let executor = test_executor();

        let err = library.syscall(&executor, &library).expect_err("handleError returned false");
        assert_eq!(err.message(), "boom");
    }

    // ---------------------------------------------------------------------------------------
    // The "syscall" userop
    // ---------------------------------------------------------------------------------------

    #[test]
    fn syscall_userop_reports_the_java_definitions_traits() {
        // Java's SyscallPcodeUseropDefinition: name "syscall", 0 inputs, not functional, has side
        // effects, does not modify context, not inlinable, void output, defined by the syslib.
        let library = Arc::new(TestSyscallLibrary::new(1, false));
        let userop = Arc::clone(&library).get_syscall_userop();

        assert_eq!(userop.get_name(), "syscall");
        assert_eq!(userop.get_input_count(), 0);
        assert!(!userop.is_functional());
        assert!(userop.has_side_effects());
        assert!(!userop.modifies_context());
        assert!(!userop.can_inline_pcode());
        assert_eq!(userop.get_output_type(), Some(std::any::TypeId::of::<()>()));
        assert!(userop.get_defining_library().is_some());
    }

    #[test]
    fn syscall_userop_execution_dispatches_the_syscall() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let library = Arc::new(
            TestSyscallLibrary::new(7, false).with(7, RecordingSyscall::arc("seven", false, &log)),
        );
        let userop = SyscallPcodeUseropDefinition::new(Arc::clone(&library));
        let executor = test_executor();

        userop.execute(&executor, &*library, &callother_op(), None, &[]);

        assert_eq!(*log.lock().unwrap(), vec!["seven".to_string()]);
    }

    #[test]
    #[should_panic(expected = "System call failed: boom")]
    fn syscall_userop_execution_surfaces_an_unhandled_error() {
        // Java lets the exception escape the `void execute`; Rust's nearest equivalent is a panic.
        let log = Arc::new(Mutex::new(Vec::new()));
        let library = Arc::new(
            TestSyscallLibrary::new(7, false).with(7, RecordingSyscall::arc("seven", true, &log)),
        );
        let userop = SyscallPcodeUseropDefinition::new(Arc::clone(&library));
        let executor = test_executor();

        userop.execute(&executor, &*library, &callother_op(), None, &[]);
    }

    // ---------------------------------------------------------------------------------------
    // loadSyscallNumberMap(String)
    // ---------------------------------------------------------------------------------------

    /// An application that resolves exactly one data file name, to a real file on disk.
    struct FileApplication {
        name: String,
        path: std::path::PathBuf,
    }

    impl Application for FileApplication {
        fn application_layout(
            &self,
        ) -> Box<dyn crate::framework::seam_stubs::ApplicationLayoutLike> {
            unimplemented!("not exercised by these tests")
        }
        fn current_platform(&self) -> Box<dyn crate::framework::platform::Platform> {
            unimplemented!("not exercised by these tests")
        }
        fn find_data_file_in_any_module(&self, relative_path: &str) -> Option<ResourceFile> {
            (relative_path == self.name).then(|| ResourceFile::new(self.path.clone()))
        }
    }

    fn app_with_map(tag: &str, contents: &str) -> FileApplication {
        let path = std::env::temp_dir().join(format!("ghidra_rs_syscall_map_{}.txt", tag));
        let mut file = std::fs::File::create(&path).expect("temp file");
        file.write_all(contents.as_bytes()).expect("write temp file");
        FileApplication { name: "syscalls.txt".to_string(), path }
    }

    #[test]
    fn syscall_number_map_skips_comments_and_parses_pairs() {
        let app = app_with_map(
            "ok",
            "# a comment\n1 read\n2 write\n   60   exit\n#trailing comment\n",
        );
        let map = load_syscall_number_map_from_file(&app, "syscalls.txt").expect("well formed");

        assert_eq!(map.len(), 3);
        assert_eq!(map[&1], "read");
        assert_eq!(map[&2], "write");
        assert_eq!(map[&60], "exit");
    }

    #[test]
    fn syscall_number_map_rejects_a_line_without_exactly_two_fields() {
        // Java: throw new IOException("Badly formatted syscall number map: ... Line: ...")
        let app = app_with_map("badfields", "1 read\n2 write extra\n");
        let err = load_syscall_number_map_from_file(&app, "syscalls.txt").expect_err("3 fields");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("Badly formatted syscall number map: syscalls.txt"),
            "unexpected message: {}",
            err
        );
        assert!(err.to_string().contains("Line: 2 write extra"), "unexpected message: {}", err);
    }

    #[test]
    fn syscall_number_map_rejects_a_non_numeric_syscall_number() {
        // Java: NumberFormatException is rewrapped as an IOException.
        let app = app_with_map("badnumber", "one read\n");
        let err = load_syscall_number_map_from_file(&app, "syscalls.txt").expect_err("not a long");
        assert_eq!(err.to_string(), "Badly formatted syscall number map: syscalls.txt");
    }

    #[test]
    fn missing_syscall_number_map_is_a_file_not_found() {
        // Java: throw new FileNotFoundException("Cannot find syscall number map: " + name)
        let app = app_with_map("missing", "");
        let err = load_syscall_number_map_from_file(&app, "elsewhere.txt").expect_err("no such");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert_eq!(err.to_string(), "Cannot find syscall number map: elsewhere.txt");
    }

    // ---------------------------------------------------------------------------------------
    // loadSyscallFunctionMap(Program)
    // ---------------------------------------------------------------------------------------

    /// A symbol carrying only what the scraper reads: its address and its type.
    struct TestSymbol {
        address: Address,
        symbol_type: SymbolType,
    }

    impl Symbol for TestSymbol {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_name(&self) -> &str {
            "sym"
        }
        fn get_symbol_type(&self) -> SymbolType {
            self.symbol_type
        }
        fn get_source(&self) -> SourceType {
            SourceType::Analysis
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            0
        }
        fn get_parent_id(&self) -> i64 {
            0
        }
    }

    /// Hands out a fixed list of symbols, counting how many were actually requested.
    struct CountingSymbolIterator {
        symbols: std::vec::IntoIter<Arc<dyn Symbol>>,
        handed_out: Arc<Mutex<usize>>,
    }

    impl SymbolIterator for CountingSymbolIterator {
        fn has_next(&self) -> bool {
            self.symbols.len() > 0
        }
        fn next_symbol(&mut self) -> Option<Arc<dyn Symbol>> {
            let next = self.symbols.next();
            if next.is_some() {
                *self.handed_out.lock().unwrap() += 1;
            }
            next
        }
    }

    struct TestSymbolTable {
        symbols: Vec<Arc<dyn Symbol>>,
        handed_out: Arc<Mutex<usize>>,
        /// The address the scraper started iterating from.
        start: Arc<Mutex<Option<Address>>>,
    }

    impl SymbolTable for TestSymbolTable {
        fn create_label(
            &mut self,
            _addr: &Address,
            _name: &str,
            _source: SourceType,
        ) -> io::Result<Arc<dyn Symbol>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_symbol(&self, _id: i64) -> io::Result<Option<Arc<dyn Symbol>>> {
            Ok(None)
        }
        fn get_symbols(&self, _addr: &Address) -> io::Result<Vec<Arc<dyn Symbol>>> {
            Ok(Vec::new())
        }
        fn get_symbol_iterator_from(
            &self,
            start_addr: &Address,
            _forward: bool,
        ) -> Box<dyn SymbolIterator> {
            *self.start.lock().unwrap() = Some(start_addr.clone());
            Box::new(CountingSymbolIterator {
                symbols: self.symbols.clone().into_iter(),
                handed_out: Arc::clone(&self.handed_out),
            })
        }
    }

    struct TestProgram {
        factory: Option<Arc<dyn AddressFactory>>,
        symbols: TestSymbolTable,
    }

    impl crate::framework::model::domain_object::DomainObject for TestProgram {}

    impl Program for TestProgram {
        fn get_name(&self) -> String {
            "test".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            self.factory.clone()
        }
        fn get_symbol_table(&mut self) -> Option<&mut dyn SymbolTable> {
            Some(&mut self.symbols)
        }
    }

    #[test]
    fn scraping_a_program_without_a_syscall_space_is_an_error() {
        // Java: throw new IllegalStateException("No syscall address space in program. ...")
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let mut program = TestProgram {
            factory: Some(Arc::new(DefaultAddressFactory::new(vec![ram]))),
            symbols: TestSymbolTable {
                symbols: Vec::new(),
                handed_out: Arc::new(Mutex::new(0)),
                start: Arc::new(Mutex::new(None)),
            },
        };

        // `Arc<dyn Function>` is not `Debug`, so the `Ok` side can't go through `assert_eq!`.
        assert!(matches!(load_syscall_function_map(&mut program), Err(NoSyscallSpaceError)));
        assert_eq!(load_syscall_number_map(&mut program), Err(NoSyscallSpaceError));
    }

    #[test]
    fn scraping_starts_at_the_syscall_space_minimum_and_stops_leaving_it() {
        // Java iterates from `space.getMinAddress()` forward, `break`s on the first symbol outside
        // the syscall space, and `continue`s past non-function symbols.
        let syscall = syscall_space();
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let handed_out = Arc::new(Mutex::new(0));
        let start = Arc::new(Mutex::new(None));
        let symbols: Vec<Arc<dyn Symbol>> = vec![
            // Skipped: in the syscall space, but not a function.
            Arc::new(TestSymbol {
                address: syscall.address(1),
                symbol_type: SymbolType::Label,
            }),
            // Ends iteration: outside the syscall space.
            Arc::new(TestSymbol { address: ram.address(2), symbol_type: SymbolType::Function }),
            // Never reached, even though it is a syscall-space function.
            Arc::new(TestSymbol {
                address: syscall.address(3),
                symbol_type: SymbolType::Function,
            }),
        ];
        let mut program = TestProgram {
            factory: Some(Arc::new(DefaultAddressFactory::new(vec![
                Arc::clone(&syscall),
                Arc::clone(&ram),
            ]))),
            symbols: TestSymbolTable {
                symbols,
                handed_out: Arc::clone(&handed_out),
                start: Arc::clone(&start),
            },
        };

        let map = load_syscall_function_map(&mut program).expect("syscall space exists");

        assert!(map.is_empty());
        assert_eq!(*start.lock().unwrap(), Some(syscall.min_address()));
        // Only the label and the out-of-space symbol were requested; the third was never reached.
        assert_eq!(*handed_out.lock().unwrap(), 2);
    }

    // ---------------------------------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------------------------------

    #[test]
    fn space_and_convention_names_match_java() {
        assert_eq!(SYSCALL_SPACE_NAME, "syscall");
        assert_eq!(SYSCALL_CONVENTION_NAME, "syscall");
    }

    #[test]
    fn no_syscall_space_message_matches_java() {
        assert_eq!(
            NoSyscallSpaceError.to_string(),
            "No syscall address space in program. Please analyze the syscalls first."
        );
    }
}
