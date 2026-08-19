//! An abstract library of UNIX system calls, suitable for use with any processor.
//!
//! Corresponds to `ghidra.pcode.emu.unix.AbstractEmuUnixSyscallUseropLibrary`.
//!
//! See the UNIX manual pages for more information about each specific system call, error numbers,
//! etc.
//!
//! Java's abstract class carries both state (the file system, the simulated user, the platform's
//! `int` size, and the process' descriptor table) and behaviour (the descriptor bookkeeping and the
//! system call bodies themselves), on top of the state its own base
//! [`AnnotatedEmuSyscallUseropLibrary`] carries. Following the same split that base already makes,
//! the state lives in [`AbstractEmuUnixSyscallUseropLibraryBase`] -- which a concrete library
//! embeds, and which in turn embeds [`AnnotatedEmuSyscallUseropLibraryBase`], so one field suffices
//! -- while the behaviour is the [`AbstractEmuUnixSyscallUseropLibrary`] trait: three required
//! methods for what Java leaves `abstract` ([`convert_flags`](AbstractEmuUnixSyscallUseropLibrary::convert_flags),
//! [`get_errno`](AbstractEmuUnixSyscallUseropLibrary::get_errno), and
//! [`return_errno`](AbstractEmuUnixSyscallUseropLibrary::return_errno)), and defaults mirroring the
//! Java bodies for everything else.
//!
//! Java's `synchronized (descriptors)` blocks have no counterpart here: every method that mutates
//! the descriptor table takes `&mut self`, which is the same mutual exclusion enforced statically.
//!
//! Two parts of the Java class are deliberately left out, both because they need machinery that is
//! not ported yet:
//! - `UnixStructuredPart`, and with it the `readv`/`writev` system calls, is written in Structured
//!   Sleigh -- `ghidra.pcode.struct.StructuredSleigh`, which is still only the minimal seam
//!   [`crate::pcode::seam_stubs::StructuredSleigh`] (no `Var`/`UseropDecl`/`_for`/`_if` surface to
//!   express `gatherScatterIovec` against). `newStructuredPart` accordingly keeps
//!   [`AnnotatedEmuSyscallUseropLibrary::new_structured_part`]'s `None` default rather than
//!   returning a part that could not do anything.
//! - The `@PcodeUserop`/`@EmuSyscall` annotations. As in [`AnnotatedEmuSyscallUseropLibrary`], a
//!   concrete library declares its userops through
//!   [`AnnotatedPcodeUseropLibrary::collect_definitions`](crate::pcode::exec::annotated_pcode_userop_library::AnnotatedPcodeUseropLibrary::collect_definitions)
//!   and its syscalls through
//!   [`AnnotatedEmuSyscallUseropLibrary::syscall_bindings`]. The bodies those definitions should
//!   call are the `unix_*` methods below, under the same names Java gives them; the
//!   [`SYSCALL_BINDINGS`] constant supplies the `@EmuSyscall` half verbatim.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::error::Error as _;

use super::default_emu_unix_file_handle::DefaultEmuUnixFileHandle;
use super::{EmuUnixFile, EmuUnixFileDescriptor, EmuUnixFileSystem, EmuUnixUser, OpenFlag};
use crate::pcode::emu::pcode_machine::PcodeMachine;
use crate::pcode::emu::sys::annotated_emu_syscall_userop_library::{
    AnnotatedEmuSyscallUseropLibrary, AnnotatedEmuSyscallUseropLibraryBase, EmuSyscallBinding,
};
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_execution_exception::PcodeExecutionException;
use crate::pcode::exec::pcode_executor::PcodeExecutor;
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_executor_state_piece::Reason;
use crate::pcode::seam_stubs::{
    EmuProcessExitedException, EmuUnixException, SettingsImpl, StringDataType,
};
use crate::program::model::data::abstract_string_data_type::AbstractStringDataType;
use crate::program::model::listing::program::Program;
use std::sync::Arc;

/// The errno values as defined by the OS simulator.
///
/// Port of the nested `AbstractEmuUnixSyscallUseropLibrary.Errno` enum. A platform-specific
/// library maps these to its own numbers through
/// [`AbstractEmuUnixSyscallUseropLibrary::get_errno`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Errno {
    /// Bad file descriptor.
    EBadF,
}

/// The `@EmuSyscall`-annotated methods of `AbstractEmuUnixSyscallUseropLibrary`, as the explicit
/// bindings this crate substitutes for Java's reflective annotation scan.
///
/// A concrete library should include these in its own
/// [`AnnotatedEmuSyscallUseropLibrary::syscall_bindings`], alongside whatever it adds itself. The
/// `readv`/`writev` bindings Java's `UnixStructuredPart` contributes are absent -- see the module
/// docs.
pub const SYSCALL_BINDINGS: &[(&str, &str)] = &[
    ("exit", "unix_exit"),
    ("read", "unix_read"),
    ("write", "unix_write"),
    ("open", "unix_open"),
    ("close", "unix_close"),
    ("group_exit", "unix_group_exit"),
];

/// [`SYSCALL_BINDINGS`] as the [`EmuSyscallBinding`] list
/// [`AnnotatedEmuSyscallUseropLibrary::syscall_bindings`] expects.
pub fn syscall_bindings() -> Vec<EmuSyscallBinding> {
    SYSCALL_BINDINGS
        .iter()
        .map(|&(syscall, userop)| EmuSyscallBinding::new(syscall, userop))
        .collect()
}

/// The shared state of a UNIX system call library.
///
/// Port of the instance fields of `AbstractEmuUnixSyscallUseropLibrary`. Java's `closedFds` and
/// `descriptors` are private to the descriptor bookkeeping (`lowestFd`, `claimFd`, `findFd`,
/// `releaseFd`, `putDescriptor`), so they stay private here too; the rest are `protected` in Java
/// and public here.
pub struct AbstractEmuUnixSyscallUseropLibraryBase<T: 'static> {
    /// The syscall/userop machinery inherited from `AnnotatedEmuSyscallUseropLibrary`.
    pub sys: AnnotatedEmuSyscallUseropLibraryBase<T>,
    /// The file system exported to the user-space program. Port of the `fs` field; a trait object
    /// because the file system is supplied by the caller and is genuinely polymorphic.
    pub fs: Box<dyn EmuUnixFileSystem<T>>,
    /// The "current user" being simulated. Port of the (non-final) `user` field.
    pub user: EmuUnixUser,
    /// The platform's `int` size, in bytes, used to size syscall return values. Port of the
    /// `intSize` field.
    pub int_size: i32,
    /// Descriptor numbers that have been released and may be reused. Port of the `closedFds`
    /// `NavigableSet`.
    closed_fds: BTreeSet<i32>,
    /// The process' open file handles, by descriptor number. Port of the `descriptors` map.
    descriptors: HashMap<i32, Box<dyn EmuUnixFileDescriptor<T>>>,
}

impl<T: 'static> AbstractEmuUnixSyscallUseropLibraryBase<T> {
    /// Construct the base for a new library, simulating
    /// [`EmuUnixUser::DEFAULT_USER`](crate::pcode::emu::unix::EmuUnixUser::DEFAULT_USER).
    ///
    /// Port of `AbstractEmuUnixSyscallUseropLibrary(PcodeMachine, EmuUnixFileSystem, Program)`.
    pub fn new(
        machine: Arc<dyn PcodeMachine<T>>,
        fs: Box<dyn EmuUnixFileSystem<T>>,
        program: Box<dyn Program>,
    ) -> Self {
        Self::with_user(machine, fs, program, EmuUnixUser::DEFAULT_USER)
    }

    /// Construct the base for a new library simulating the given user.
    ///
    /// Port of `AbstractEmuUnixSyscallUseropLibrary(PcodeMachine, EmuUnixFileSystem, Program,
    /// EmuUnixUser)`.
    ///
    /// # Panics
    ///
    /// If `program` has no compiler spec, or no "pointer" data type -- see
    /// [`AnnotatedEmuSyscallUseropLibraryBase::new`].
    pub fn with_user(
        machine: Arc<dyn PcodeMachine<T>>,
        fs: Box<dyn EmuUnixFileSystem<T>>,
        program: Box<dyn Program>,
        user: EmuUnixUser,
    ) -> Self {
        let sys = AnnotatedEmuSyscallUseropLibraryBase::new(machine, program);
        let int_size = sys.c_spec.get_data_organization().get_integer_size();
        Self {
            sys,
            fs,
            user,
            int_size,
            closed_fds: BTreeSet::new(),
            descriptors: HashMap::new(),
        }
    }

    /// The number of descriptors currently open, as Java's `descriptors.size()` reports it.
    pub fn open_descriptor_count(&self) -> usize {
        self.descriptors.len()
    }
}

/// Concretize a value as a `long`, as Java's `PcodeArithmetic.toLong(value, Purpose.OTHER)` does.
///
/// Java throws `ConcretionError`, itself a `PcodeExecutionException`; here the error becomes the
/// converted exception's cause.
fn to_long<T>(
    arithmetic: &dyn PcodeArithmetic<T>,
    value: &T,
) -> Result<i64, PcodeExecutionException> {
    arithmetic
        .to_long(value, Purpose::Other)
        .map_err(|e| PcodeExecutionException::with_cause(e.message().to_string(), e))
}

/// The descriptor bookkeeping, override points, and system call bodies of a UNIX system call
/// library.
///
/// Port of the behaviour of `AbstractEmuUnixSyscallUseropLibrary`. A concrete library implements
/// [`unix_base`](Self::unix_base)/[`unix_base_mut`](Self::unix_base_mut) (exposing its embedded
/// [`AbstractEmuUnixSyscallUseropLibraryBase`]) plus the three methods Java leaves `abstract`;
/// everything else has a default mirroring the Java body, as an override point.
pub trait AbstractEmuUnixSyscallUseropLibrary<T: Clone + 'static>:
    AnnotatedEmuSyscallUseropLibrary<T>
{
    /// The embedded shared state.
    fn unix_base(&self) -> &AbstractEmuUnixSyscallUseropLibraryBase<T>;

    /// The embedded shared state, for writing.
    fn unix_base_mut(&mut self) -> &mut AbstractEmuUnixSyscallUseropLibraryBase<T>;

    /// Convert the flags as defined for this platform to flags understood by the simulator.
    ///
    /// Port of the abstract `convertFlags(int)`.
    fn convert_flags(&self, flags: i32) -> HashSet<OpenFlag>;

    /// Get the platform-specific errno value for the given simulator-defined errno.
    ///
    /// Port of the abstract `getErrno(Errno)`.
    fn get_errno(&self, err: Errno) -> i32;

    /// Place the errno into the machine as expected by the simulated platform's ABI.
    ///
    /// Returns true if the errno was successfully placed. Port of the abstract
    /// `returnErrno(PcodeExecutor, int)`.
    fn return_errno(&self, executor: &PcodeExecutor<T>, errno: i32) -> bool;

    /// Get the first available file descriptor, i.e. the lowest available descriptor number.
    ///
    /// Port of `lowestFd()`, which -- despite the name -- consumes the reused number it returns.
    fn lowest_fd(&mut self) -> i32 {
        let base = self.unix_base_mut();
        match base.closed_fds.pop_first() {
            Some(lowest) => lowest,
            None => base.descriptors.len() as i32,
        }
    }

    /// Claim the lowest available file descriptor number for the given descriptor object, adding
    /// it to the descriptor table under that number.
    ///
    /// Port of `claimFd(EmuUnixFileDescriptor)`.
    fn claim_fd(&mut self, desc: Box<dyn EmuUnixFileDescriptor<T>>) -> i32 {
        let fd = self.lowest_fd();
        self.put_descriptor(fd, desc);
        fd
    }

    /// Get the file descriptor object for the given file descriptor number.
    ///
    /// Port of `findFd(int)`. Java hands back the descriptor for the caller to operate on; every
    /// such operation (`read`, `write`, `close`) mutates it, so this lends it mutably rather than
    /// offering a shared/exclusive accessor pair.
    ///
    /// # Errors
    ///
    /// [`EmuUnixException`] with [`Errno::EBadF`] if the file descriptor is invalid.
    fn find_fd(&mut self, fd: i32) -> Result<&mut dyn EmuUnixFileDescriptor<T>, EmuUnixException> {
        let errno = self.get_errno(Errno::EBadF);
        match self.unix_base_mut().descriptors.get_mut(&fd) {
            Some(desc) => Ok(desc.as_mut()),
            None => Err(EmuUnixException::with_errno(format!("Invalid descriptor: {}", fd), errno)),
        }
    }

    /// Release/invalidate the given file descriptor number, returning the removed descriptor.
    ///
    /// Port of `releaseFd(int)`. When `fd` is the highest number ever handed out, Java skips
    /// recording it in `closedFds`, since [`lowest_fd`](Self::lowest_fd) will offer it again
    /// anyway; this does the same. Java's fast path returns `null` for an absent descriptor
    /// (leaving its caller to raise a `NullPointerException`); this reports the same
    /// [`Errno::EBadF`] the slow path does.
    ///
    /// # Errors
    ///
    /// [`EmuUnixException`] with [`Errno::EBadF`] if the file descriptor is invalid.
    fn release_fd(
        &mut self,
        fd: i32,
    ) -> Result<Box<dyn EmuUnixFileDescriptor<T>>, EmuUnixException> {
        let errno = self.get_errno(Errno::EBadF);
        let base = self.unix_base_mut();
        let is_highest = (base.descriptors.len() + base.closed_fds.len()) as i64 - 1 == fd as i64;
        let removed = base.descriptors.remove(&fd);
        match removed {
            Some(desc) => {
                if !is_highest {
                    base.closed_fds.insert(fd);
                }
                Ok(desc)
            }
            None => Err(EmuUnixException::with_errno(format!("Invalid descriptor: {}", fd), errno)),
        }
    }

    /// Put a descriptor into the process' open file handles, returning the previous descriptor
    /// under that number, which probably ought to be `None`.
    ///
    /// Port of `putDescriptor(int, EmuUnixFileDescriptor)`.
    fn put_descriptor(
        &mut self,
        fd: i32,
        desc: Box<dyn EmuUnixFileDescriptor<T>>,
    ) -> Option<Box<dyn EmuUnixFileDescriptor<T>>> {
        self.unix_base_mut().descriptors.insert(fd, desc)
    }

    /// A factory method for creating an open file handle for `file`, opened with the
    /// platform-defined `flags`.
    ///
    /// Port of `createHandle(EmuUnixFile, int)`.
    fn create_handle(
        &self,
        file: Box<dyn EmuUnixFile<T>>,
        flags: i32,
    ) -> Box<dyn EmuUnixFileDescriptor<T>> {
        let converted = self.convert_flags(flags);
        let base = self.unix_base();
        Box::new(DefaultEmuUnixFileHandle::new(
            &*base.sys.machine,
            &*base.sys.c_spec,
            file,
            converted,
            base.user.clone(),
        ))
    }

    /// Try to handle an error by returning its errno to the user program.
    ///
    /// Port of the overridden `handleError(PcodeExecutor, PcodeExecutionException)`. Exposed under
    /// a distinct name since [`EmuSyscallLibrary::handle_error`](crate::pcode::emu::sys::emu_syscall_library::EmuSyscallLibrary::handle_error)
    /// is a supertrait method that cannot be given a second default here; a concrete library
    /// should delegate its `handle_error` to this.
    ///
    /// Java's `err instanceof EmuUnixException` becomes a downcast of the exception's cause, which
    /// is where [`From<EmuUnixException>`](EmuUnixException) files it. An exception carrying no
    /// errno returns false, i.e. lets the emulator interrupt.
    fn handle_unix_error(&self, executor: &PcodeExecutor<T>, err: &PcodeExecutionException) -> bool {
        let Some(unix_err) = err.source().and_then(|e| e.downcast_ref::<EmuUnixException>()) else {
            return false;
        };
        match unix_err.get_errno() {
            Some(errno) => self.return_errno(executor, errno),
            None => false,
        }
    }

    /// The UNIX `exit` system call, which never returns.
    ///
    /// Port of `unix_exit(T)`. Java throws; the overall simulator or script should catch it.
    ///
    /// # Errors
    ///
    /// Always [`EmuProcessExitedException`].
    fn unix_exit(&self, status: T) -> Result<T, EmuProcessExitedException<T>>
    where
        T: std::fmt::Debug,
    {
        let arithmetic = self.unix_base().sys.machine.get_arithmetic();
        Err(EmuProcessExitedException::new(arithmetic.as_ref(), status))
    }

    /// The UNIX `group_exit` system call, which never returns.
    ///
    /// Port of `unix_group_exit(T)`. Java throws; the overall simulator or script should catch it.
    ///
    /// # Errors
    ///
    /// Always [`EmuProcessExitedException`].
    fn unix_group_exit(&self, status: T) -> Result<(), EmuProcessExitedException<T>>
    where
        T: std::fmt::Debug,
    {
        let arithmetic = self.unix_base().sys.machine.get_arithmetic();
        Err(EmuProcessExitedException::new(arithmetic.as_ref(), status))
    }

    /// The UNIX `read` system call: read `count` bytes from `fd` into the buffer at `buf_ptr`,
    /// returning the number of bytes successfully read.
    ///
    /// Port of `unix_read(PcodeExecutorState, T, T, T)`.
    fn unix_read(
        &mut self,
        state: &mut dyn PcodeExecutorState<T>,
        fd: T,
        buf_ptr: T,
        count: T,
    ) -> Result<T, PcodeExecutionException> {
        let arithmetic = self.unix_base().sys.machine.get_arithmetic();
        let ifd = to_long(arithmetic.as_ref(), &fd)? as i32;
        let space = self.default_address_space();
        // TODO: Not ideal to require concrete size, but gets unwieldy to leave it abstract
        let size = to_long(arithmetic.as_ref(), &count)? as i32;
        let buf = arithmetic.from_const_u64(0, size);
        let result = self.find_fd(ifd)?.read(buf.clone())?;
        let iresult = to_long(arithmetic.as_ref(), &result)? as i32;
        state.set_var_abstract(&space, &buf_ptr, iresult, true, &buf);
        Ok(result)
    }

    /// The UNIX `write` system call: write `count` bytes from the buffer at `buf_ptr` to `fd`,
    /// returning the number of bytes successfully written.
    ///
    /// Port of `unix_write(PcodeExecutorState, T, T, T)`.
    fn unix_write(
        &mut self,
        state: &mut dyn PcodeExecutorState<T>,
        fd: T,
        buf_ptr: T,
        count: T,
    ) -> Result<T, PcodeExecutionException> {
        let arithmetic = self.unix_base().sys.machine.get_arithmetic();
        let ifd = to_long(arithmetic.as_ref(), &fd)? as i32;
        let space = self.default_address_space();
        // TODO: Not ideal to require concrete size. What are the alternatives, though?
        // TODO: size should actually be long (size_t)
        let size = to_long(arithmetic.as_ref(), &count)? as i32;
        let buf = state.get_var_abstract(&space, &buf_ptr, size, true, Reason::ExecuteRead);
        // TODO: Write back into state? "write" shouldn't touch the buffer....
        Ok(self.find_fd(ifd)?.write(buf)?)
    }

    /// The UNIX `open` system call: open the file named by the string at `pathname_ptr`, returning
    /// its file descriptor.
    ///
    /// Port of `unix_open(PcodeExecutorState, T, T, T)`.
    ///
    /// # Panics
    ///
    /// If the pathname cannot be decoded from the machine's state -- Java's
    /// `Objects.requireNonNull(sdi.getStringValue())`, whose TODO about mapping it to a UNIX error
    /// still stands.
    fn unix_open(
        &mut self,
        state: &mut dyn PcodeExecutorState<T>,
        pathname_ptr: T,
        flags: T,
        mode: T,
    ) -> Result<T, PcodeExecutionException> {
        let arithmetic = self.unix_base().sys.machine.get_arithmetic();
        let iflags = to_long(arithmetic.as_ref(), &flags)? as i32;
        let imode = to_long(arithmetic.as_ref(), &mode)? as i32;
        let pathname_off = to_long(arithmetic.as_ref(), &pathname_ptr)?;
        let space = self.default_address_space();

        let settings = SettingsImpl::new();
        let buffer = state.get_concrete_buffer(&space.address(pathname_off), Purpose::Other);
        // Java constructs the instance twice: once as a probe (length -1) to find where the string
        // ends, then again over that now-known fixed length to decode it.
        let probe = StringDataType::DATA_TYPE.get_string_data_instance(&*buffer, &settings, -1);
        let length = probe.get_string_length();
        let sdi = StringDataType::DATA_TYPE.get_string_data_instance(&*buffer, &settings, length);
        // TODO: Can NPE here be mapped to a unix error
        let pathname = sdi.get_string_value().expect("no pathname string at the given pointer");

        let converted = self.convert_flags(iflags);
        let base = self.unix_base_mut();
        let user = base.user.clone();
        let file = base.fs.open(&pathname, &converted, &user, imode)?;
        let handle = self.create_handle(file, iflags);
        let ifd = self.claim_fd(handle);
        let int_size = self.unix_base().int_size;
        Ok(arithmetic.from_const_u64(ifd as u64, int_size))
    }

    /// The UNIX `close` system call, returning 0 for success.
    ///
    /// Port of `unix_close(T)`.
    fn unix_close(&mut self, fd: T) -> Result<T, PcodeExecutionException> {
        let arithmetic = self.unix_base().sys.machine.get_arithmetic();
        let ifd = to_long(arithmetic.as_ref(), &fd)? as i32;
        // TODO: Some fs.close or file.close, when all handles have released it?
        self.release_fd(ifd)?.close();
        let int_size = self.unix_base().int_size;
        Ok(arithmetic.from_const_u64(0, int_size))
    }

    /// The machine language's default address space, in which syscall buffer pointers are
    /// interpreted. Java spells this `machine.getLanguage().getAddressFactory()
    /// .getDefaultAddressSpace()` at each of its three call sites.
    ///
    /// # Panics
    ///
    /// If the language has no default address space (Java: a `NullPointerException` at the
    /// following dereference).
    fn default_address_space(&self) -> Arc<crate::program::model::address::AddressSpace> {
        use crate::program::model::address::AddressFactory;
        self.unix_base()
            .sys
            .machine
            .get_language()
            .get_address_factory()
            .get_default_address_space()
            .expect("language has no default address space")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::pcode_machine::{AccessKind, ErasedPcodeMachine, SwiMode};
    use crate::pcode::emu::pcode_thread::ErasedPcodeThread;
    use crate::pcode::emu::sys::emu_syscall_library::{EmuSyscallDefinition, EmuSyscallLibrary};
    use crate::pcode::emu::unix::EmuUnixFileStat;
    use crate::pcode::exec::annotated_pcode_userop_library::{
        AnnotatedPcodeUseropDefinition, AnnotatedPcodeUseropLibrary, AnnotatedPcodeUseropLibraryBase,
    };
    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_executor_state_piece::PcodeExecutorStatePiece;
    use crate::pcode::exec::pcode_program::PcodeProgram;
    use crate::pcode::exec::pcode_userop_library::{
        ErasedPcodeUseropLibrary, PcodeUseropLibrary, UseropMap,
    };
    use crate::pcode::seam_stubs::EmuIOException;
    use crate::program::model::address::{
        Address, AddressRange, AddressSpace, AddressSpaceType, DefaultAddressFactory,
    };
    use crate::program::model::data::bit_field_packing::BitFieldPacking;
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::lang::compiler_spec::{CompilerSpec, EvaluationModelType};
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::lang::sleigh::SleighLanguage;
    use crate::program::model::pcode::OpCode;

    // ------------------------------------------------------------------------------------------
    // Doubles. The library's constructor pulls the machine's arithmetic, the program's compiler
    // spec (for `intSize`) and its "pointer" data type, so all three must be present.
    // ------------------------------------------------------------------------------------------

    /// Arithmetic over `i64`, enough for `fromConst`/`toLong` round trips.
    struct I64Arithmetic;

    impl PcodeArithmetic<i64> for I64Arithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }
        fn unary_op(&self, _opcode: OpCode, _sizeout: i32, _sizein1: i32, in1: &i64) -> i64 {
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
        fn from_const_bytes(&self, value: &[u8]) -> i64 {
            crate::pcode::utils::bytes_to_long(value, value.len(), false)
        }
        fn from_const_u64(&self, value: u64, _size: i32) -> i64 {
            value as i64
        }
        fn to_concrete(&self, value: &i64, _purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
            Ok(crate::pcode::utils::long_to_bytes(*value, 8, false))
        }
        fn to_long(&self, value: &i64, _purpose: Purpose) -> Result<i64, ConcretionError> {
            Ok(*value)
        }
        fn to_big_integer(&self, value: &i64, _purpose: Purpose) -> Result<i128, ConcretionError> {
            Ok(*value as i128)
        }
        fn size_of(&self, _value: &i64) -> i64 {
            8
        }
    }

    /// Builds a minimal, valid [`SleighLanguage`] with one `ram` space, which is also its default
    /// space -- all [`AbstractEmuUnixSyscallUseropLibrary::default_address_space`] needs. Mirrors
    /// `sleigh::tests::test_sleigh_decode_basic`'s hand-built packed encoding.
    fn minimal_sleigh_language() -> SleighLanguage {
        use crate::program::model::pcode::PackedDecode;

        let factory = Arc::new(DefaultAddressFactory::new(vec![]));
        let mut data = vec![];

        data.extend_from_slice(&[0x60, 0xA1]); // <sleigh
        data.extend_from_slice(&[0xE0, 0xA2, 0x21, 4]); // version=4
        data.extend_from_slice(&[0xE0, 0xA3, 0x10]); // bigendian=false

        data.extend_from_slice(&[0x60, 0xA2]); // <spaces defaultspace="ram">
        data.extend_from_slice(&[0xE0, 0xA9, 0x71, 3, b'r', b'a', b'm']);

        data.extend_from_slice(&[0x60, 0xAD, 0xA0, 0xAD]); // <space_other/>

        data.extend_from_slice(&[0x60, 0xA5]); // <space name="ram" size="4" index="1" delay="1"/>
        data.extend_from_slice(&[0xCC, 0x71, 3, b'r', b'a', b'm']);
        data.extend_from_slice(&[0xCF, 0x21, 4]);
        data.extend_from_slice(&[0xC9, 0x21, 1]);
        data.extend_from_slice(&[0xE0, 0xAA, 0x21, 1]);
        data.extend_from_slice(&[0xA0, 0xA5]);

        data.extend_from_slice(&[0xA0, 0xA2]); // </spaces>

        data.extend_from_slice(&[0x60, 0xA6]); // <symbol_table scopesize="1" symbolsize="0">
        data.extend_from_slice(&[0xE0, 0xAD, 0x21, 1]);
        data.extend_from_slice(&[0xE0, 0xAE, 0x21, 0]);
        data.extend_from_slice(&[0x56, 0xC3, 0x41, 0, 0xD6, 0x41, 0, 0x96]); // <scope id=0 parent=0/>
        data.extend_from_slice(&[0xA0, 0xA6]); // </symbol_table>

        data.extend_from_slice(&[0xA0, 0xA1]); // </sleigh>

        let decoder = PackedDecode::new(factory, data);
        SleighLanguage::decode(&decoder, "test".to_string()).unwrap()
    }

    struct MockMachine {
        language: SleighLanguage,
    }

    impl MockMachine {
        fn new() -> Self {
            Self { language: minimal_sleigh_language() }
        }
    }

    impl ErasedPcodeMachine for MockMachine {}
    impl PcodeMachine<i64> for MockMachine {
        fn get_language(&self) -> &SleighLanguage {
            &self.language
        }
        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(I64Arithmetic)
        }
        fn set_software_interrupt_mode(&mut self, _mode: SwiMode) {}
        fn get_software_interrupt_mode(&self) -> SwiMode {
            SwiMode::Active
        }
        fn get_userop_library(&self) -> &dyn PcodeUseropLibrary<i64> {
            unimplemented!("not exercised by these tests")
        }
        fn get_stub_userop_library(&self) -> &dyn PcodeUseropLibrary<i64> {
            unimplemented!("not exercised by these tests")
        }
        fn new_thread(&mut self) -> Arc<dyn ErasedPcodeThread> {
            unimplemented!("not exercised by these tests")
        }
        fn new_thread_named(&mut self, _name: &str) -> Arc<dyn ErasedPcodeThread> {
            unimplemented!("not exercised by these tests")
        }
        fn get_thread(
            &mut self,
            _name: &str,
            _create_if_absent: bool,
        ) -> Option<Arc<dyn ErasedPcodeThread>> {
            None
        }
        fn get_all_threads(&self) -> Vec<Arc<dyn ErasedPcodeThread>> {
            Vec::new()
        }
        fn get_shared_state(&self) -> &dyn PcodeExecutorState<i64> {
            unimplemented!("not exercised by these tests")
        }
        fn get_shared_state_mut(&mut self) -> &mut dyn PcodeExecutorState<i64> {
            unimplemented!("not exercised by these tests")
        }
        fn set_suspended(&mut self, _suspended: bool) {}
        fn is_suspended(&self) -> bool {
            false
        }
        fn compile_sleigh(&self, _source_name: &str, _source: &str) -> PcodeProgram {
            crate::pcode::exec::pcode_program::testing::empty_program()
        }
        fn inject(&mut self, _address: &Address, _source: &str) {}
        fn get_inject(&self, _address: &Address) -> Option<&PcodeProgram> {
            None
        }
        fn clear_inject(&mut self, _address: &Address) {}
        fn clear_all_injects(&mut self) {}
        fn add_breakpoint(&mut self, _address: &Address, _sleigh_condition: &str) {}
        fn add_access_breakpoint(&mut self, _range: &AddressRange, _kind: AccessKind) {}
        fn clear_access_breakpoints(&mut self) {}
    }

    /// The only fields of the data organization the library reads is the integer size.
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
            unimplemented!("not exercised by these tests")
        }
        fn get_bit_field_packing(&self) -> Box<dyn BitFieldPacking> {
            unimplemented!("not exercised by these tests")
        }
        fn get_size_alignment_count(&self) -> i32 {
            0
        }
        fn get_sizes(&self) -> Vec<i32> {
            Vec::new()
        }
        fn get_integer_c_type_approximation(&self, _size: i32, _signed: bool) -> String {
            unimplemented!("not exercised by these tests")
        }
        fn get_alignment(&self, _data_type: &dyn DataType) -> i32 {
            unimplemented!("not exercised by these tests")
        }
    }

    struct MockCompilerSpec;
    impl CompilerSpec for MockCompilerSpec {
        fn get_language(&self) -> Box<dyn crate::program::model::lang::language::Language> {
            unimplemented!("not exercised by these tests")
        }
        fn get_compiler_spec_description(
            &self,
        ) -> Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>
        {
            unimplemented!("not exercised by these tests")
        }
        fn get_compiler_spec_id(
            &self,
        ) -> crate::program::model::lang::compiler_spec_id::CompilerSpecID {
            unimplemented!("not exercised by these tests")
        }
        fn get_stack_pointer(&self) -> Option<RegisterRef> {
            None
        }
        fn is_stack_right_justified(&self) -> bool {
            false
        }
        fn get_address_space(&self, _space_name: &str) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_stack_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by these tests")
        }
        fn get_stack_base_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by these tests")
        }
        fn stack_grows_negative(&self) -> bool {
            true
        }
        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext,
        ) {
        }
        fn get_calling_conventions(&self) -> Vec<Box<dyn PrototypeModel>> {
            Vec::new()
        }
        fn get_calling_convention(&self, _name: &str) -> Option<Box<dyn PrototypeModel>> {
            None
        }
        fn get_all_models(&self) -> Vec<Box<dyn PrototypeModel>> {
            Vec::new()
        }
        fn get_default_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            None
        }
        fn get_decompiler_output_language(
            &self,
        ) -> crate::program::model::lang::decompiler_language::DecompilerLanguage {
            unimplemented!("not exercised by these tests")
        }
        fn get_prototype_evaluation_model(
            &self,
            _model_type: EvaluationModelType,
        ) -> Box<dyn PrototypeModel> {
            unimplemented!("not exercised by these tests")
        }
        fn is_global(&self, _addr: &Address) -> bool {
            true
        }
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            Box::new(MockDataOrganization)
        }
        fn get_pcode_inject_library(
            &self,
        ) -> Box<dyn crate::program::seam_stubs::PcodeInjectLibrary> {
            unimplemented!("not exercised by these tests")
        }
        fn match_convention(&self, _convention_name: &str) -> Box<dyn PrototypeModel> {
            unimplemented!("not exercised by these tests")
        }
        fn find_best_calling_convention(
            &self,
            _params: &[&dyn crate::program::model::listing::parameter::Parameter],
        ) -> Box<dyn PrototypeModel> {
            unimplemented!("not exercised by these tests")
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn does_c_data_type_conversions(&self) -> bool {
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
        fn get_property_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn encode(
            &self,
            _encoder: &mut dyn crate::program::model::pcode::Encoder,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn is_equivalent(&self, _other: &dyn CompilerSpec) -> bool {
            false
        }
    }

    struct PointerType;
    impl DataType for PointerType {
        fn get_name(&self) -> String {
            "pointer".to_string()
        }
    }

    struct TestDataTypeManager;
    impl DataTypeManager for TestDataTypeManager {
        fn get_data_type(&self, data_type_path: &str) -> Option<Box<dyn DataType>> {
            (data_type_path == "/pointer").then(|| Box::new(PointerType) as Box<dyn DataType>)
        }
    }

    struct TestProgram;
    impl crate::framework::model::domain_object::DomainObject for TestProgram {}
    impl Program for TestProgram {
        fn get_name(&self) -> String {
            "test".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:64:default".to_string()
        }
        fn get_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>> {
            Some(Box::new(TestDataTypeManager))
        }
        fn get_address_factory(
            &self,
        ) -> Option<Arc<dyn crate::program::model::address::AddressFactory>> {
            Some(Arc::new(DefaultAddressFactory::new(vec![AddressSpace::new(
                "ram",
                64,
                1,
                AddressSpaceType::Ram,
                0,
            )])))
        }
        fn get_compiler_spec(&self) -> Option<Box<dyn CompilerSpec>> {
            Some(Box::new(MockCompilerSpec))
        }
    }

    /// A file system that hands out one in-memory file per pathname, logging every `open`.
    #[derive(Default)]
    struct MockFileSystem {
        opened: Arc<std::sync::Mutex<Vec<(String, HashSet<OpenFlag>, i32)>>>,
    }

    struct MockFile {
        pathname: String,
    }

    impl EmuUnixFile<i64> for MockFile {
        fn pathname(&self) -> &str {
            &self.pathname
        }
        fn read(&mut self, _arithmetic: &dyn PcodeArithmetic<i64>, _offset: i64, buf: i64) -> i64 {
            buf
        }
        fn write(&mut self, _arithmetic: &dyn PcodeArithmetic<i64>, _offset: i64, buf: i64) -> i64 {
            buf
        }
        fn truncate(&mut self) {}
        fn stat(&self) -> EmuUnixFileStat {
            EmuUnixFileStat::default()
        }
    }

    impl EmuUnixFileSystem<i64> for MockFileSystem {
        fn new_file(
            &self,
            pathname: &str,
            _mode: i32,
        ) -> Result<Box<dyn EmuUnixFile<i64>>, EmuIOException> {
            Ok(Box::new(MockFile { pathname: pathname.to_string() }))
        }
        fn create_or_get_file(
            &mut self,
            pathname: &str,
            mode: i32,
        ) -> Result<Box<dyn EmuUnixFile<i64>>, EmuIOException> {
            self.new_file(pathname, mode)
        }
        fn get_file(
            &self,
            pathname: &str,
        ) -> Result<Option<Box<dyn EmuUnixFile<i64>>>, EmuIOException> {
            Ok(Some(Box::new(MockFile { pathname: pathname.to_string() })))
        }
        fn put_file(
            &mut self,
            _pathname: &str,
            _file: Box<dyn EmuUnixFile<i64>>,
        ) -> Result<(), EmuIOException> {
            Ok(())
        }
        fn unlink(&mut self, _pathname: &str, _user: &EmuUnixUser) -> Result<(), EmuIOException> {
            Ok(())
        }
        fn open(
            &mut self,
            pathname: &str,
            flags: &HashSet<OpenFlag>,
            _user: &EmuUnixUser,
            mode: i32,
        ) -> Result<Box<dyn EmuUnixFile<i64>>, EmuIOException> {
            self.opened.lock().unwrap().push((pathname.to_string(), flags.clone(), mode));
            self.new_file(pathname, mode)
        }
    }

    /// What a [`MockDescriptor`] observed, shared with the test that installed it.
    #[derive(Default)]
    struct DescriptorLog {
        reads: Vec<i64>,
        writes: Vec<i64>,
        closed: bool,
    }

    /// A descriptor that logs its traffic and returns a canned read length.
    struct MockDescriptor {
        read_result: i64,
        log: Arc<std::sync::Mutex<DescriptorLog>>,
    }

    impl EmuUnixFileDescriptor<i64> for MockDescriptor {
        fn offset(&self) -> i64 {
            0
        }
        fn seek(&mut self, _offset: i64) -> Result<(), EmuIOException> {
            Ok(())
        }
        fn read(&mut self, buf: i64) -> Result<i64, EmuIOException> {
            self.log.lock().unwrap().reads.push(buf);
            Ok(self.read_result)
        }
        fn write(&mut self, buf: i64) -> Result<i64, EmuIOException> {
            self.log.lock().unwrap().writes.push(buf);
            Ok(buf)
        }
        fn stat(&self) -> EmuUnixFileStat {
            EmuUnixFileStat::default()
        }
        fn close(&mut self) {
            self.log.lock().unwrap().closed = true;
        }
    }

    fn desc() -> Box<dyn EmuUnixFileDescriptor<i64>> {
        logged_desc(0).0
    }

    fn logged_desc(
        read_result: i64,
    ) -> (Box<dyn EmuUnixFileDescriptor<i64>>, Arc<std::sync::Mutex<DescriptorLog>>) {
        let log = Arc::new(std::sync::Mutex::new(DescriptorLog::default()));
        (Box::new(MockDescriptor { read_result, log: Arc::clone(&log) }), log)
    }

    /// A state that stores whole variables by offset and serves concrete buffers out of a flat
    /// byte image, which is all the `read`/`write`/`open` bodies touch.
    #[derive(Default)]
    struct MapState {
        /// offset -> (size, value), as written by `set_var`.
        cells: HashMap<i64, (i32, i64)>,
        /// The bytes `get_concrete_buffer` serves, indexed by address offset.
        memory: Vec<u8>,
    }

    impl crate::pcode::exec::pcode_executor_state_piece::ErasedPcodeExecutorStatePiece for MapState {}

    impl PcodeExecutorStatePiece<i64, i64> for MapState {
        fn get_language(&self) -> Box<dyn crate::program::model::lang::language::Language> {
            unimplemented!("not exercised by these tests")
        }
        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(I64Arithmetic)
        }
        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(I64Arithmetic)
        }
        fn stream_pieces(
            &self,
        ) -> Vec<&dyn crate::pcode::exec::pcode_executor_state_piece::ErasedPcodeExecutorStatePiece>
        {
            vec![self]
        }
        fn set_var_abstract(
            &mut self,
            _space: &Arc<AddressSpace>,
            offset: &i64,
            size: i32,
            _quantize: bool,
            val: &i64,
        ) {
            self.cells.insert(*offset, (size, *val));
        }
        fn set_var_internal_abstract(
            &mut self,
            space: &Arc<AddressSpace>,
            offset: &i64,
            size: i32,
            val: &i64,
        ) {
            self.set_var_abstract(space, offset, size, false, val);
        }
        fn get_var_abstract(
            &self,
            _space: &Arc<AddressSpace>,
            offset: &i64,
            _size: i32,
            _quantize: bool,
            _reason: Reason,
        ) -> i64 {
            self.cells.get(offset).map_or(0, |&(_, value)| value)
        }
        fn get_var_internal_abstract(
            &self,
            space: &Arc<AddressSpace>,
            offset: &i64,
            size: i32,
            reason: Reason,
        ) -> i64 {
            self.get_var_abstract(space, offset, size, false, reason)
        }
        fn get_register_values(&self) -> Vec<(RegisterRef, i64)> {
            Vec::new()
        }
        fn get_concrete_buffer(
            &self,
            address: &Address,
            _purpose: Purpose,
        ) -> Box<dyn crate::program::model::mem::mem_buffer::MemBuffer> {
            let start = address.offset() as usize;
            let bytes = self.memory.get(start..).unwrap_or(&[]).to_vec();
            Box::new(crate::program::model::mem::byte_mem_buffer_impl::ByteMemBufferImpl::new(
                address.clone(),
                bytes,
                false,
            ))
        }
        fn clear(&mut self) {
            self.cells.clear();
        }
    }

    impl PcodeExecutorState<i64> for MapState {}

    // ------------------------------------------------------------------------------------------
    // The library under test: the smallest concrete subclass, whose three abstract methods use
    // the Linux amd64 numbers (`EBADF` = 9, `O_WRONLY` = 1) for something checkable.
    // ------------------------------------------------------------------------------------------

    struct TestUnixLibrary {
        base: AbstractEmuUnixSyscallUseropLibraryBase<i64>,
        /// The `open` log of the file system installed in `base`.
        opened: Arc<std::sync::Mutex<Vec<(String, HashSet<OpenFlag>, i32)>>>,
    }

    impl TestUnixLibrary {
        fn new() -> Self {
            let fs = MockFileSystem::default();
            let opened = Arc::clone(&fs.opened);
            Self {
                base: AbstractEmuUnixSyscallUseropLibraryBase::new(
                    Arc::new(MockMachine::new()),
                    Box::new(fs),
                    Box::new(TestProgram),
                ),
                opened,
            }
        }
    }

    impl ErasedPcodeUseropLibrary for TestUnixLibrary {}

    impl PcodeUseropLibrary<i64> for TestUnixLibrary {
        fn get_userops(&self) -> &UseropMap<i64> {
            self.base.sys.annotated.get_userops()
        }
    }

    impl AnnotatedPcodeUseropLibrary<i64> for TestUnixLibrary {
        fn base_mut(&mut self) -> &mut AnnotatedPcodeUseropLibraryBase<i64> {
            &mut self.base.sys.annotated
        }
        fn collect_definitions(&self) -> Vec<AnnotatedPcodeUseropDefinition<i64>> {
            Vec::new()
        }
    }

    impl EmuSyscallLibrary<i64> for TestUnixLibrary {
        fn read_syscall_number(
            &self,
            _state: &dyn PcodeExecutorState<i64>,
            _reason: Reason,
        ) -> i64 {
            unimplemented!("not exercised by these tests")
        }
        fn handle_error(
            &self,
            executor: &PcodeExecutor<i64>,
            err: &PcodeExecutionException,
        ) -> bool {
            self.handle_unix_error(executor, err)
        }
        fn get_syscalls(&self) -> &HashMap<i64, Arc<dyn EmuSyscallDefinition<i64>>> {
            &self.base.sys.syscall_map
        }
    }

    impl AnnotatedEmuSyscallUseropLibrary<i64> for TestUnixLibrary {
        fn sys_base(&self) -> &AnnotatedEmuSyscallUseropLibraryBase<i64> {
            &self.base.sys
        }
        fn sys_base_mut(&mut self) -> &mut AnnotatedEmuSyscallUseropLibraryBase<i64> {
            &mut self.base.sys
        }
        fn syscall_bindings(&self) -> Vec<EmuSyscallBinding> {
            syscall_bindings()
        }
    }

    impl AbstractEmuUnixSyscallUseropLibrary<i64> for TestUnixLibrary {
        fn unix_base(&self) -> &AbstractEmuUnixSyscallUseropLibraryBase<i64> {
            &self.base
        }
        fn unix_base_mut(&mut self) -> &mut AbstractEmuUnixSyscallUseropLibraryBase<i64> {
            &mut self.base
        }
        fn convert_flags(&self, flags: i32) -> HashSet<OpenFlag> {
            // Just enough of the Linux amd64 mapping to be checkable.
            match flags & 3 {
                1 => OpenFlag::set([OpenFlag::OWronly]),
                2 => OpenFlag::set([OpenFlag::ORdwr]),
                _ => OpenFlag::set([OpenFlag::ORdonly]),
            }
        }
        fn get_errno(&self, err: Errno) -> i32 {
            match err {
                Errno::EBadF => 9,
            }
        }
        fn return_errno(&self, _executor: &PcodeExecutor<i64>, _errno: i32) -> bool {
            true
        }
    }

    // ------------------------------------------------------------------------------------------
    // Tests
    // ------------------------------------------------------------------------------------------

    #[test]
    fn int_size_comes_from_the_programs_data_organization() {
        // Java: intSize = program.getCompilerSpec().getDataOrganization().getIntegerSize()
        let lib = TestUnixLibrary::new();
        assert_eq!(lib.unix_base().int_size, 4);
        assert_eq!(lib.unix_base().user, EmuUnixUser::DEFAULT_USER);
    }

    #[test]
    fn claim_fd_hands_out_consecutive_numbers_from_zero() {
        // Java: lowestFd() falls through to descriptors.size() while closedFds is empty.
        let mut lib = TestUnixLibrary::new();
        assert_eq!(lib.claim_fd(desc()), 0);
        assert_eq!(lib.claim_fd(desc()), 1);
        assert_eq!(lib.claim_fd(desc()), 2);
        assert_eq!(lib.unix_base().open_descriptor_count(), 3);
    }

    #[test]
    fn releasing_an_interior_fd_makes_it_the_next_one_claimed() {
        // Java: releaseFd(1) is not the highest number, so 1 goes into closedFds, and the next
        // claimFd polls it back out ahead of descriptors.size().
        let mut lib = TestUnixLibrary::new();
        lib.claim_fd(desc());
        lib.claim_fd(desc());
        lib.claim_fd(desc());

        lib.release_fd(1).expect("descriptor 1 is open");
        assert_eq!(lib.unix_base().open_descriptor_count(), 2);
        assert_eq!(lib.claim_fd(desc()), 1);
        // Now that 1 is taken again, the next is fresh -- descriptors.size() == 3.
        assert_eq!(lib.claim_fd(desc()), 3);
    }

    #[test]
    fn releasing_the_highest_fd_does_not_record_it_as_closed() {
        // Java: descriptors.size() + closedFds.size() - 1 == fd, so releaseFd short-circuits
        // without touching closedFds; lowestFd() re-offers the number via descriptors.size().
        let mut lib = TestUnixLibrary::new();
        lib.claim_fd(desc());
        lib.claim_fd(desc());

        lib.release_fd(1).expect("descriptor 1 is open");
        assert_eq!(lib.claim_fd(desc()), 1);
    }

    #[test]
    fn find_fd_reports_ebadf_for_an_unknown_descriptor() {
        // Java: throw new EmuUnixException("Invalid descriptor: " + fd, getErrno(Errno.EBADF))
        let mut lib = TestUnixLibrary::new();
        let err = lib.find_fd(7).err().expect("descriptor 7 was never opened");
        assert_eq!(err.message(), "Invalid descriptor: 7");
        assert_eq!(err.get_errno(), Some(9));
    }

    #[test]
    fn release_fd_reports_ebadf_for_an_unknown_descriptor() {
        let mut lib = TestUnixLibrary::new();
        lib.claim_fd(desc());
        let err = lib.release_fd(5).err().expect("descriptor 5 was never opened");
        assert_eq!(err.message(), "Invalid descriptor: 5");
        assert_eq!(err.get_errno(), Some(9));
    }

    #[test]
    fn put_descriptor_returns_the_one_it_displaced() {
        // Java: return descriptors.put(fd, desc)
        let mut lib = TestUnixLibrary::new();
        assert!(lib.put_descriptor(0, desc()).is_none());
        let previous = lib.put_descriptor(0, desc()).expect("displaced the first");
        assert_eq!(previous.stat().st_size, 0);
        assert_eq!(lib.unix_base().open_descriptor_count(), 1);
    }

    #[test]
    fn unix_close_releases_the_descriptor_and_returns_zero() {
        // Java: releaseFd(ifd).close(); return arithmetic.fromConst(0, intSize)
        let mut lib = TestUnixLibrary::new();
        let fd = lib.claim_fd(desc()) as i64;
        assert_eq!(lib.unix_close(fd).expect("descriptor is open"), 0);
        assert_eq!(lib.unix_base().open_descriptor_count(), 0);
        // The number is now invalid.
        assert!(lib.unix_close(fd).is_err());
    }

    #[test]
    fn unix_exit_always_reports_the_process_exited_with_its_status() {
        // Java: throw new EmuProcessExitedException(machine.getArithmetic(), status)
        let lib = TestUnixLibrary::new();
        let err = lib.unix_exit(42).expect_err("exit never returns");
        assert_eq!(err.message(), "Process exited with status 42");
        assert_eq!(*err.get_status(), 42);

        let err = lib.unix_group_exit(7).expect_err("group_exit never returns");
        assert_eq!(err.message(), "Process exited with status 7");
    }

    #[test]
    fn handle_error_returns_the_errno_of_a_unix_exception_only() {
        // Java: handleError returns returnErrno(...) for an EmuUnixException carrying an errno,
        // and false for anything else -- including a EmuUnixException with a null errno.
        let lib = TestUnixLibrary::new();
        let executor = crate::pcode::exec::pcode_executor::PcodeExecutor::<i64>::new(
            Arc::new(NilLanguage),
            Arc::new(I64Arithmetic),
            Arc::new(std::sync::Mutex::new(NilState)),
            Reason::ExecuteRead,
        );

        let with_errno: PcodeExecutionException =
            EmuUnixException::with_errno("Invalid descriptor: 3", 9).into();
        assert!(lib.handle_error(&executor, &with_errno));

        let without_errno: PcodeExecutionException = EmuUnixException::new("no errno").into();
        assert!(!lib.handle_error(&executor, &without_errno));

        let unrelated = PcodeExecutionException::with_message("something else");
        assert!(!lib.handle_error(&executor, &unrelated));
    }

    /// A language with no program counter, so [`PcodeExecutor::new`] falls back to the default
    /// space's pointer size. Nothing else about it is exercised.
    struct NilLanguage;

    impl crate::program::model::lang::language::Language for NilLanguage {
        fn get_default_space(&self) -> Arc<AddressSpace> {
            AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            self.get_default_space()
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
        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            Box::new(DefaultAddressFactory::new(vec![self.get_default_space()]))
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
            _buf: &dyn crate::program::model::mem::mem_buffer::MemBuffer,
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
            Box<dyn CompilerSpec>,
            crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            Box::new(MockCompilerSpec)
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
        fn get_property_keys(&self) -> HashSet<String> {
            HashSet::new()
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
        fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
            HashSet::new()
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

    /// The executor `handle_error` is handed never touches its state.
    struct NilState;
    impl crate::pcode::exec::pcode_executor_state_piece::ErasedPcodeExecutorStatePiece for NilState {}
    impl PcodeExecutorStatePiece<i64, i64> for NilState {
        fn get_language(&self) -> Box<dyn crate::program::model::lang::language::Language> {
            unimplemented!("not exercised by these tests")
        }
        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(I64Arithmetic)
        }
        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(I64Arithmetic)
        }
        fn stream_pieces(
            &self,
        ) -> Vec<&dyn crate::pcode::exec::pcode_executor_state_piece::ErasedPcodeExecutorStatePiece>
        {
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
        }
        fn set_var_internal_abstract(
            &mut self,
            _space: &Arc<AddressSpace>,
            _offset: &i64,
            _size: i32,
            _val: &i64,
        ) {
        }
        fn get_var_abstract(
            &self,
            _space: &Arc<AddressSpace>,
            _offset: &i64,
            _size: i32,
            _quantize: bool,
            _reason: Reason,
        ) -> i64 {
            0
        }
        fn get_var_internal_abstract(
            &self,
            _space: &Arc<AddressSpace>,
            _offset: &i64,
            _size: i32,
            _reason: Reason,
        ) -> i64 {
            0
        }
        fn get_register_values(&self) -> Vec<(RegisterRef, i64)> {
            Vec::new()
        }
        fn get_concrete_buffer(
            &self,
            _address: &Address,
            _purpose: Purpose,
        ) -> Box<dyn crate::program::model::mem::mem_buffer::MemBuffer> {
            unimplemented!("not exercised by these tests")
        }
        fn clear(&mut self) {}
    }
    impl PcodeExecutorState<i64> for NilState {}

    #[test]
    fn convert_flags_reaches_the_subclass_from_create_handle() {
        // Java: createHandle passes convertFlags(flags) straight into the new handle, so a
        // read-only handle refuses writes.
        let lib = TestUnixLibrary::new();
        let file = lib.unix_base().fs.new_file("/tmp/x", 0o644).expect("file created");
        let mut handle = lib.create_handle(file, 0);
        assert!(handle.write(4).is_err());

        let file = lib.unix_base().fs.new_file("/tmp/x", 0o644).expect("file created");
        let mut handle = lib.create_handle(file, 1);
        assert_eq!(handle.write(4).expect("opened O_WRONLY"), 4);
    }

    #[test]
    fn unix_read_stores_the_bytes_read_at_the_buffer_pointer() {
        // Java: buf = arithmetic.fromConst(0, size); result = desc.read(buf);
        //       state.setVar(space, bufPtr, (int) toLong(result), true, buf); return result
        let mut lib = TestUnixLibrary::new();
        let (descriptor, log) = logged_desc(3);
        let fd = lib.claim_fd(descriptor) as i64;
        let mut state = MapState::default();

        let read = lib.unix_read(&mut state, fd, 0x100, 8).expect("descriptor is open");

        assert_eq!(read, 3, "returns what the descriptor reported reading");
        assert_eq!(log.lock().unwrap().reads, vec![0], "a zeroed buffer of the requested size");
        // The buffer is stored back at bufPtr, sized by the *actual* count read, not `count`.
        assert_eq!(state.cells.get(&0x100), Some(&(3, 0)));
    }

    #[test]
    fn unix_read_on_a_bad_descriptor_carries_ebadf_through_to_handle_error() {
        let mut lib = TestUnixLibrary::new();
        let mut state = MapState::default();

        let err = lib.unix_read(&mut state, 4, 0x100, 8).expect_err("descriptor 4 is not open");
        assert_eq!(err.message(), "Invalid descriptor: 4");
        let unix_err = err
            .source()
            .and_then(|e| e.downcast_ref::<EmuUnixException>())
            .expect("an EmuUnixException survives the conversion");
        assert_eq!(unix_err.get_errno(), Some(9));
    }

    #[test]
    fn unix_write_hands_the_descriptor_the_buffer_read_from_state() {
        // Java: buf = state.getVar(space, bufPtr, size, true, EXECUTE_READ); return desc.write(buf)
        let mut lib = TestUnixLibrary::new();
        let (descriptor, log) = logged_desc(0);
        let fd = lib.claim_fd(descriptor) as i64;
        let mut state = MapState::default();
        state.cells.insert(0x200, (8, 0xdead_beef));

        let written = lib.unix_write(&mut state, fd, 0x200, 8).expect("descriptor is open");

        assert_eq!(written, 0xdead_beef);
        assert_eq!(log.lock().unwrap().writes, vec![0xdead_beef]);
    }

    #[test]
    fn unix_open_decodes_the_pathname_from_state_and_claims_a_descriptor() {
        // Java: probes the string at pathnamePtr, opens it through the file system with the
        // converted flags, then returns claimFd(createHandle(file, flags)) as an `int`.
        let mut lib = TestUnixLibrary::new();
        let mut state = MapState::default();
        state.memory = vec![0; 0x40];
        state.memory.extend_from_slice(b"/tmp/test\0trailing garbage");

        let fd = lib.unix_open(&mut state, 0x40, 1, 0o644).expect("the file opens");

        assert_eq!(fd, 0, "the first descriptor handed out");
        assert_eq!(lib.unix_base().open_descriptor_count(), 1);
        let opened = lib.opened.lock().unwrap();
        assert_eq!(opened.len(), 1);
        let (pathname, flags, mode) = &opened[0];
        assert_eq!(pathname, "/tmp/test", "the null terminator bounds the pathname");
        assert_eq!(*flags, OpenFlag::set([OpenFlag::OWronly]), "flags go through convertFlags");
        assert_eq!(*mode, 0o644);
    }

    #[test]
    fn declared_syscall_bindings_match_the_java_annotations() {
        let bindings = syscall_bindings();
        assert_eq!(bindings.len(), 6);
        assert!(bindings.contains(&EmuSyscallBinding::new("exit", "unix_exit")));
        assert!(bindings.contains(&EmuSyscallBinding::new("group_exit", "unix_group_exit")));
        assert!(bindings.contains(&EmuSyscallBinding::new("open", "unix_open")));
    }
}
