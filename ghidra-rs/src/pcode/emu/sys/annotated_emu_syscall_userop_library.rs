//! A syscall library wherein Rust methods are exported via an explicit list of bindings.
//!
//! Corresponds to `ghidra.pcode.emu.sys.AnnotatedEmuSyscallUseropLibrary`.
//!
//! This library is both a system call library and a Sleigh userop library. To export a system
//! call, it must also be exported as a Sleigh userop -- see
//! [`AnnotatedPcodeUseropLibrary`](crate::pcode::exec::annotated_pcode_userop_library::AnnotatedPcodeUseropLibrary).
//!
//! Java discovers which userops double as syscalls by reflecting over the concrete subclass for
//! methods annotated `@EmuSyscall`. Rust has neither annotations nor reflection, so, following the
//! same substitution [`AnnotatedPcodeUseropLibrary`] makes for `@PcodeUserop`, a concrete library
//! declares its bindings explicitly through [`AnnotatedEmuSyscallUseropLibrary::syscall_bindings`]
//! as a list of [`EmuSyscallBinding`]s.
//!
//! Java's abstract class carries both state (the machine, program, compiler spec, "pointer" data
//! type, the resolved syscall map, and any additional data type archives) and concrete behavior
//! (resolving `@EmuSyscall` bindings against the program's syscall number/convention maps). The
//! state lives in [`AnnotatedEmuSyscallUseropLibraryBase`], which a concrete library embeds
//! (alongside its own [`AnnotatedPcodeUseropLibraryBase`], continuing the "each level's base wraps
//! the level below" shape already used there); the behavior is this module's
//! [`AnnotatedEmuSyscallUseropLibrary`] trait, with default bodies mirroring the Java methods'.
//!
//! Two aspects of the Java constructor are not yet reachable here:
//! - Java calls the overridable `getAdditionalArchives`/`newStructuredPart`/
//!   `disposeAdditionalArchives` from *within* the constructor, relying on virtual dispatch to
//!   reach a subclass's override before the subclass's own constructor body has run. Rust cannot
//!   dispatch to a trait override before `Self` exists, so those calls move to
//!   [`AnnotatedEmuSyscallUseropLibrary::init_syscalls`], which -- like
//!   [`AnnotatedPcodeUseropLibrary::init`](crate::pcode::exec::annotated_pcode_userop_library::AnnotatedPcodeUseropLibrary::init)
//!   -- a concrete library must call once it is fully built (and after that `init`, since
//!   binding syscalls needs the userop map `init` populates).
//! - The structured-Sleigh half of the constructor (building a `StructuredPart`, generating its
//!   userops, then re-scanning it for further `@EmuSyscall` bindings) needs
//!   `ghidra.pcode.struct.StructuredSleigh`, which is only a minimal placeholder seam
//!   ([`crate::pcode::seam_stubs::StructuredSleigh`]) until that class is ported. See
//!   [`AnnotatedEmuSyscallUseropLibrary::new_structured_part`].

use std::collections::HashMap;
use std::sync::Arc;

use crate::pcode::emu::pcode_machine::PcodeMachine;
use crate::pcode::emu::sys::emu_syscall_library::{
    load_syscall_convention_map, load_syscall_number_map, EmuSyscallDefinition, EmuSyscallLibrary,
};
use crate::pcode::exec::annotated_pcode_userop_library::{
    AnnotatedPcodeUseropLibrary, AnnotatedPcodeUseropLibraryBase,
};
use crate::pcode::exec::pcode_userop_library::{PcodeUseropDefinition, UseropMap};
use crate::pcode::seam_stubs::{StructuredSleigh, UseropEmuSyscallDefinition};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::model::lang::prototype_model::PrototypeModel;
use crate::program::model::listing::program::Program;
use crate::util::msg::Msg;

/// Port of the `@EmuSyscall` annotation: names the syscall (as resolved through the program's
/// syscall number map) exported by an already-declared userop.
///
/// Java discovers `@EmuSyscall`-annotated methods via reflection over the concrete library's
/// class; Rust has neither annotations nor reflection, so a concrete library declares its
/// bindings explicitly through [`AnnotatedEmuSyscallUseropLibrary::syscall_bindings`], mirroring
/// how `@PcodeUserop` becomes
/// [`AnnotatedPcodeUseropLibrary::collect_definitions`](crate::pcode::exec::annotated_pcode_userop_library::AnnotatedPcodeUseropLibrary::collect_definitions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmuSyscallBinding {
    /// The syscall's name, as it appears in the program's syscall number map. Port of
    /// `@EmuSyscall`'s `value`.
    pub syscall_name: String,
    /// The name of the userop (as filed in [`PcodeUseropLibrary::get_userops`]) that implements
    /// this syscall. Port of the annotated method's own name (`Method.getName()`), which Java
    /// requires to double as the `@PcodeUserop` name.
    pub userop_name: String,
}

impl EmuSyscallBinding {
    /// Bind `syscall_name` to the userop named `userop_name`.
    pub fn new(syscall_name: impl Into<String>, userop_name: impl Into<String>) -> Self {
        Self { syscall_name: syscall_name.into(), userop_name: userop_name.into() }
    }
}

/// The shared state of an annotated syscall userop library.
///
/// Port of the instance fields of `AnnotatedEmuSyscallUseropLibrary`. Embeds
/// [`AnnotatedPcodeUseropLibraryBase`] the same way that base embeds
/// [`DefaultPcodeUseropLibrary`](crate::pcode::exec::default_pcode_userop_library::DefaultPcodeUseropLibrary),
/// so a concrete library needs only this one field.
///
/// `machine` is stored as `Arc<dyn PcodeMachine<T>>` rather than a concrete type: unlike
/// `CompilerSpec`/`PrototypeModel` (whose single relevant implementer lets them collapse to a
/// concrete type), this field is populated from an arbitrary caller-supplied machine -- exactly
/// as every other machine-holding field in this crate (e.g.
/// [`DefaultPcodeThread`](crate::pcode::emu::default_pcode_thread::DefaultPcodeThread)) already
/// stores it, so genuine runtime dispatch is required here.
pub struct AnnotatedEmuSyscallUseropLibraryBase<T: 'static> {
    /// The embedded userop-collection machinery inherited from `AnnotatedPcodeUseropLibrary`.
    pub annotated: AnnotatedPcodeUseropLibraryBase<T>,
    /// The machine using this library. Port of the `machine` field.
    pub machine: Arc<dyn PcodeMachine<T>>,
    /// The program's compiler spec. Port of the `cSpec` field.
    pub c_spec: Box<dyn CompilerSpec>,
    /// The program from which syscall configuration and conventions are derived. Port of the
    /// `program` field.
    pub program: Box<dyn Program>,
    /// The program's "pointer" data type, used to size syscall parameter/return storage. Port of
    /// the `dtMachineWord` field.
    pub dt_machine_word: Arc<dyn DataType>,
    /// The resolved syscall definitions, keyed by number. Port of the `syscallMap` field.
    pub syscall_map: HashMap<i64, Arc<dyn EmuSyscallDefinition<T>>>,
    /// Additional data type archives consulted while resolving syscall types. Port of the
    /// `additionalArchives` field.
    pub additional_archives: Vec<Box<dyn DataTypeManager>>,
}

impl<T: 'static> AnnotatedEmuSyscallUseropLibraryBase<T> {
    /// Construct the base for a new library including the "syscall" userop.
    ///
    /// Port of the constructor's first three field assignments (`machine`, `program`, `cSpec`)
    /// and the `dtMachineWord` lookup. `additional_archives` starts empty and `syscall_map` starts
    /// unresolved; both are filled in by
    /// [`AnnotatedEmuSyscallUseropLibrary::init_syscalls`](crate::pcode::emu::sys::annotated_emu_syscall_userop_library::AnnotatedEmuSyscallUseropLibrary::init_syscalls),
    /// once the owning library is fully built (see the module docs for why that must happen after
    /// construction here, unlike in Java).
    ///
    /// # Panics
    ///
    /// If `program` has no compiler spec, or no "pointer" data type -- mirroring Java's behavior
    /// (a `NullPointerException` for the former, `IllegalArgumentException` for the latter).
    pub fn new(machine: Arc<dyn PcodeMachine<T>>, program: Box<dyn Program>) -> Self {
        let c_spec = program.get_compiler_spec().expect("program has no compiler spec");
        let dt_machine_word = UseropEmuSyscallDefinition::<T>::require_pointer_data_type(&*program);
        Self {
            annotated: AnnotatedPcodeUseropLibraryBase::new(),
            machine,
            c_spec,
            program,
            dt_machine_word,
            syscall_map: HashMap::new(),
            additional_archives: Vec::new(),
        }
    }
}

/// Port of `mapAndBindSyscalls(Class<?>)`'s binding step, given the program's syscall
/// number/convention maps (as produced by
/// [`load_syscall_number_map`]/[`load_syscall_convention_map`]) and the library's own userops and
/// `@EmuSyscall` bindings.
///
/// Split out from [`AnnotatedEmuSyscallUseropLibrary::init_syscalls`] as a free function so it can
/// be exercised directly, without needing a full `Program` capable of scraping a syscall address
/// space.
///
/// # Panics
///
/// If a binding names a userop that is not in `userops` (Java: `IllegalArgumentException`, "must
/// also be a p-code userop"), a syscall number with no calling convention (Java: an unguarded
/// `NullPointerException` from `convention.getStorageLocations`), or two bindings resolve to the
/// same number (Java: `IllegalArgumentException`, "Duplicate ... annotated methods").
pub fn bind_syscalls<T: 'static>(
    number_map: &HashMap<i64, String>,
    convention_map: &HashMap<i64, Box<dyn PrototypeModel>>,
    userops: &UseropMap<T>,
    bindings: &[EmuSyscallBinding],
    program: &dyn Program,
    dt_machine_word: &Arc<dyn DataType>,
) -> HashMap<i64, Arc<dyn EmuSyscallDefinition<T>>> {
    // Port of `new DualHashBidiMap<>(...)`, used only in reverse (name -> number).
    let mut name_to_number: HashMap<&str, i64> = HashMap::new();
    for (&number, name) in number_map {
        name_to_number.insert(name.as_str(), number);
    }

    let mut result = HashMap::new();
    for binding in bindings {
        let Some(&number) = name_to_number.get(binding.syscall_name.as_str()) else {
            Msg::warn(
                "AnnotatedEmuSyscallUseropLibrary",
                &format!("Syscall {} has no number", binding.syscall_name),
            );
            continue;
        };
        let opdef = userops.get(&binding.userop_name).unwrap_or_else(|| {
            panic!(
                "Method {} annotated with @EmuSyscall must also be a p-code userop",
                binding.userop_name
            )
        });
        let convention = convention_map
            .get(&number)
            .unwrap_or_else(|| panic!("No syscall calling convention for number {}", number));
        let definition: Arc<dyn EmuSyscallDefinition<T>> = Arc::new(UseropEmuSyscallDefinition::new(
            number,
            Arc::clone(opdef),
            program,
            &**convention,
            Arc::clone(dt_machine_word),
        ));
        if result.insert(number, definition).is_some() {
            panic!(
                "Duplicate @EmuSyscall annotated methods with name {}",
                binding.syscall_name
            );
        }
    }
    result
}

/// The operations and override points of an annotated syscall userop library.
///
/// Port of the concrete behavior of `AnnotatedEmuSyscallUseropLibrary`. A concrete library
/// implements [`sys_base`](Self::sys_base)/[`sys_base_mut`](Self::sys_base_mut) (exposing its
/// embedded [`AnnotatedEmuSyscallUseropLibraryBase`]) and
/// [`syscall_bindings`](Self::syscall_bindings) (its `@EmuSyscall` bindings); everything else has
/// a conventional default mirroring the Java class's bodies, as an override point.
pub trait AnnotatedEmuSyscallUseropLibrary<T: 'static>:
    AnnotatedPcodeUseropLibrary<T> + EmuSyscallLibrary<T>
{
    /// The embedded shared state.
    fn sys_base(&self) -> &AnnotatedEmuSyscallUseropLibraryBase<T>;

    /// The embedded shared state, for writing.
    fn sys_base_mut(&mut self) -> &mut AnnotatedEmuSyscallUseropLibraryBase<T>;

    /// This library's `@EmuSyscall` bindings. Port of the reflective scan
    /// `AnnotationUtilities.collectAnnotatedMethods(EmuSyscall.class, cls)` would perform over the
    /// concrete class.
    fn syscall_bindings(&self) -> Vec<EmuSyscallBinding>;

    /// Additional data type archives to consult while resolving syscall types.
    ///
    /// Port of `getAdditionalArchives`, which defaults to none.
    fn get_additional_archives(&self) -> Vec<Box<dyn DataTypeManager>> {
        Vec::new()
    }

    /// Release any archives obtained through [`get_additional_archives`](Self::get_additional_archives).
    ///
    /// Port of `disposeAdditionalArchives`, which defaults to a no-op.
    fn dispose_additional_archives(&mut self) {}

    /// Create the structured-Sleigh part of this library, if any.
    ///
    /// Port of `newStructuredPart`. Java always builds one (a `StructuredPart` wrapping this
    /// library's `program`); this defaults to `None` because `StructuredSleigh` is not yet a real
    /// port (see the module docs). A library that overrides this is responsible for filing any
    /// syscalls it exports through the structured part into its own
    /// [`syscall_bindings`](Self::syscall_bindings).
    fn new_structured_part(&self) -> Option<Box<dyn StructuredSleigh<T>>> {
        None
    }

    /// Export a userop as a system call.
    ///
    /// Port of `newBoundSyscall`.
    fn new_bound_syscall(
        &self,
        number: i64,
        opdef: Arc<dyn PcodeUseropDefinition<T>>,
        convention: &dyn PrototypeModel,
    ) -> UseropEmuSyscallDefinition<T> {
        UseropEmuSyscallDefinition::new(
            number,
            opdef,
            &*self.sys_base().program,
            convention,
            Arc::clone(&self.sys_base().dt_machine_word),
        )
    }

    /// Resolve [`syscall_bindings`](Self::syscall_bindings) against the program's syscall
    /// number/convention maps and file the result into [`AnnotatedEmuSyscallUseropLibraryBase::syscall_map`].
    ///
    /// Port of the constructor's first `mapAndBindSyscalls(this.getClass())` call.
    fn bind_syscalls(&mut self) {
        let bindings = self.syscall_bindings();
        let userops = self.get_userops().clone();
        let dt_machine_word = Arc::clone(&self.sys_base().dt_machine_word);

        let base = self.sys_base_mut();
        let number_map = load_syscall_number_map(&mut *base.program)
            .expect("program has not been analyzed for syscalls");
        let convention_map =
            load_syscall_convention_map(&mut *base.program).unwrap_or_default();
        let program: &dyn Program = &*base.program;
        let resolved =
            bind_syscalls(&number_map, &convention_map, &userops, &bindings, program, &dt_machine_word);
        base.syscall_map.extend(resolved);
    }

    /// Complete construction: resolve this library's syscalls, then release any additional
    /// archives.
    ///
    /// Port of the rest of the constructor. Must be called once by a concrete library, after
    /// [`AnnotatedPcodeUseropLibrary::init`](crate::pcode::exec::annotated_pcode_userop_library::AnnotatedPcodeUseropLibrary::init)
    /// has populated the userop map -- see the module docs for why Rust needs this as an explicit,
    /// separate step where Java does not.
    fn init_syscalls(&mut self) {
        self.bind_syscalls();
        let archives = self.get_additional_archives();
        self.sys_base_mut().additional_archives = archives;
        self.dispose_additional_archives();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use crate::pcode::emu::pcode_machine::{AccessKind, ErasedPcodeMachine, SwiMode};
    use crate::pcode::emu::pcode_thread::ErasedPcodeThread;
    use crate::pcode::exec::annotated_pcode_userop_library::{
        AnnotatedPcodeUseropDefinition, PcodeUserop, UseropContext, UseropInputs, UseropValue,
        UseropValueKind,
    };
    use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_executor::PcodeExecutor;
    use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
    use crate::pcode::exec::pcode_executor_state_piece::{
        ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece, Reason,
    };
    use crate::pcode::exec::pcode_program::PcodeProgram;
    use crate::pcode::exec::pcode_userop_library::PcodeUseropLibrary;
    use crate::program::model::address::{
        Address, AddressFactory, AddressSpace, AddressSpaceType, DefaultAddressFactory,
    };
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::listing::variable_storage::VariableStorage;
    use crate::program::model::mem::mem_buffer::MemBuffer;
    use crate::program::model::pcode::{OpCode, SequenceNumber, Varnode};

    // -----------------------------------------------------------------------------------------
    // A minimal `Program` double: only `get_data_type_manager`/`get_address_factory` are
    // exercised (`Program`'s other accessors all default already).
    // -----------------------------------------------------------------------------------------

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

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn const_space() -> Arc<AddressSpace> {
        AddressSpace::new("const", 64, 1, AddressSpaceType::Constant, 1)
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
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            Some(Arc::new(DefaultAddressFactory::new(vec![ram_space(), const_space()])))
        }
    }

    // -----------------------------------------------------------------------------------------
    // A `VariableStorage`/`PrototypeModel` pair fixing every syscall parameter and the return
    // value to one `ram` varnode apiece, in declaration order.
    // -----------------------------------------------------------------------------------------

    struct FixedStorage(Varnode);
    impl VariableStorage for FixedStorage {
        fn get_varnodes(&self) -> Vec<Varnode> {
            vec![self.0.clone()]
        }
    }

    struct TestConvention {
        varnodes: Vec<Varnode>,
    }

    impl PrototypeModel for TestConvention {
        fn get_storage_locations(
            &self,
            _program: &dyn Program,
            data_types: &[Arc<dyn DataType>],
            _add_auto_params: bool,
            _is_var_args: bool,
        ) -> Vec<Box<dyn VariableStorage>> {
            assert_eq!(data_types.len(), self.varnodes.len(), "storage requested for every slot");
            self.varnodes.iter().map(|vn| Box::new(FixedStorage(vn.clone())) as Box<dyn VariableStorage>).collect()
        }
    }

    fn ret_var() -> Varnode {
        Varnode::new(ram_space().address(0x2000), 8)
    }

    fn in_var() -> Varnode {
        Varnode::new(ram_space().address(0x1000), 8)
    }

    fn convention() -> TestConvention {
        TestConvention { varnodes: vec![ret_var(), in_var()] }
    }

    // -----------------------------------------------------------------------------------------
    // `bind_syscalls`: the reflection-free replacement for `mapAndBindSyscalls`.
    // -----------------------------------------------------------------------------------------

    fn recording_userop(log: Arc<Mutex<Vec<i64>>>) -> Arc<dyn PcodeUseropDefinition<i64>> {
        Arc::new(AnnotatedPcodeUseropDefinition::new(
            "write",
            PcodeUserop { functional: false, has_side_effects: true, ..Default::default() },
            UseropInputs::Fixed(vec![UseropValueKind::Value]),
            UseropValueKind::Void,
            Box::new(move |_ctx: &UseropContext<'_, i64>, args: &[UseropValue<i64>]| {
                log.lock().unwrap().push(*args[0].as_value().unwrap());
                None
            }),
        ))
    }

    fn userops_with(name: &str, def: Arc<dyn PcodeUseropDefinition<i64>>) -> UseropMap<i64> {
        let mut map = HashMap::new();
        map.insert(name.to_string(), def);
        map
    }

    #[test]
    fn binds_the_declared_syscall_to_its_number_and_dispatches_through_it() {
        // Java: mapAndBindSyscalls resolves "write" -> 7 via the program's number map, looks up
        // the "write" userop, and wraps it as UseropEmuSyscallDefinition(7, ...).
        let log = Arc::new(Mutex::new(Vec::new()));
        let userops = userops_with("write", recording_userop(Arc::clone(&log)));
        let bindings = vec![EmuSyscallBinding::new("write", "write")];
        let mut number_map = HashMap::new();
        number_map.insert(7, "write".to_string());
        let mut convention_map: HashMap<i64, Box<dyn PrototypeModel>> = HashMap::new();
        convention_map.insert(7, Box::new(convention()));
        let program = TestProgram;
        let dt_machine_word = UseropEmuSyscallDefinition::<i64>::require_pointer_data_type(&program);

        let resolved =
            bind_syscalls(&number_map, &convention_map, &userops, &bindings, &program, &dt_machine_word);

        assert_eq!(resolved.len(), 1);
        let definition = resolved.get(&7).expect("bound under its syscall number");

        // Dispatching it aliases the "write" userop's one input to the storage TestConvention
        // assigned, i.e. `in_var()`; poke that varnode and confirm the userop observed it.
        let executor = test_executor();
        poke(&executor, &in_var(), 0x2a);
        let library = crate::pcode::exec::pcode_userop_library::nil::<i64>();
        definition.invoke(&executor, &library).expect("dispatch succeeds");

        assert_eq!(*log.lock().unwrap(), vec![0x2a]);
    }

    #[test]
    fn a_binding_with_no_matching_number_is_skipped_not_bound() {
        // Java: Msg.warn(...); continue -- not a failure, just no entry for that binding.
        let userops = userops_with("write", recording_userop(Arc::new(Mutex::new(Vec::new()))));
        let bindings = vec![EmuSyscallBinding::new("nonexistent", "write")];
        let number_map = HashMap::new();
        let convention_map: HashMap<i64, Box<dyn PrototypeModel>> = HashMap::new();
        let program = TestProgram;
        let dt_machine_word = UseropEmuSyscallDefinition::<i64>::require_pointer_data_type(&program);

        let resolved =
            bind_syscalls(&number_map, &convention_map, &userops, &bindings, &program, &dt_machine_word);

        assert!(resolved.is_empty());
    }

    #[test]
    #[should_panic(expected = "Method write annotated with @EmuSyscall must also be a p-code userop")]
    fn a_binding_naming_an_undeclared_userop_panics() {
        let userops: UseropMap<i64> = HashMap::new();
        let bindings = vec![EmuSyscallBinding::new("write", "write")];
        let mut number_map = HashMap::new();
        number_map.insert(7, "write".to_string());
        let convention_map: HashMap<i64, Box<dyn PrototypeModel>> = HashMap::new();
        let program = TestProgram;
        let dt_machine_word = UseropEmuSyscallDefinition::<i64>::require_pointer_data_type(&program);

        bind_syscalls(&number_map, &convention_map, &userops, &bindings, &program, &dt_machine_word);
    }

    #[test]
    #[should_panic(expected = "Duplicate @EmuSyscall annotated methods with name write")]
    fn two_bindings_resolving_to_the_same_number_panic() {
        // Java: two @EmuSyscall("write")-annotated methods on the same class -- both bindings
        // resolve to the same number, and the second `syscallMap.put` collision panics.
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut userops = userops_with("write", recording_userop(Arc::clone(&log)));
        userops.insert("write2".to_string(), recording_userop(log));
        let bindings =
            vec![EmuSyscallBinding::new("write", "write"), EmuSyscallBinding::new("write", "write2")];
        let mut number_map = HashMap::new();
        number_map.insert(7, "write".to_string());
        let mut convention_map: HashMap<i64, Box<dyn PrototypeModel>> = HashMap::new();
        convention_map.insert(7, Box::new(convention()));
        let program = TestProgram;
        let dt_machine_word = UseropEmuSyscallDefinition::<i64>::require_pointer_data_type(&program);

        bind_syscalls(&number_map, &convention_map, &userops, &bindings, &program, &dt_machine_word);
    }

    // -----------------------------------------------------------------------------------------
    // `AnnotatedEmuSyscallUseropLibraryBase::new`: field setup, incl. `requirePointerDataType`.
    // -----------------------------------------------------------------------------------------

    struct NilMachine;
    impl ErasedPcodeMachine for NilMachine {}
    impl PcodeMachine<i64> for NilMachine {
        fn get_language(&self) -> &crate::program::model::lang::sleigh::SleighLanguage {
            unimplemented!("not exercised by these tests")
        }
        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            unimplemented!("not exercised by these tests")
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
        fn get_thread(&mut self, _name: &str, _create_if_absent: bool) -> Option<Arc<dyn ErasedPcodeThread>> {
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
        fn add_access_breakpoint(
            &mut self,
            _range: &crate::program::model::address::AddressRange,
            _kind: AccessKind,
        ) {
        }
        fn clear_access_breakpoints(&mut self) {}
    }

    struct MockCompilerSpec;
    impl CompilerSpec for MockCompilerSpec {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }
        fn get_compiler_spec_description(
            &self,
        ) -> Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>
        {
            unimplemented!("not exercised by these tests")
        }
        fn get_compiler_spec_id(&self) -> crate::program::model::lang::compiler_spec_id::CompilerSpecID {
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
        fn get_calling_conventions(
            &self,
        ) -> Vec<Box<dyn PrototypeModel>> {
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
            _model_type: crate::program::model::lang::compiler_spec::EvaluationModelType,
        ) -> Box<dyn PrototypeModel> {
            unimplemented!("not exercised by these tests")
        }
        fn is_global(&self, _addr: &Address) -> bool {
            true
        }
        fn get_data_organization(&self) -> Box<dyn crate::program::model::data::data_organization::DataOrganization> {
            unimplemented!("not exercised by these tests")
        }
        fn get_pcode_inject_library(&self) -> Box<dyn crate::program::seam_stubs::PcodeInjectLibrary> {
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
        fn get_property_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }
        fn encode(&self, _encoder: &mut dyn crate::program::model::pcode::Encoder) -> std::io::Result<()> {
            Ok(())
        }
        fn is_equivalent(&self, _other: &dyn CompilerSpec) -> bool {
            false
        }
    }

    struct TestProgramWithCompilerSpec;
    impl crate::framework::model::domain_object::DomainObject for TestProgramWithCompilerSpec {}
    impl Program for TestProgramWithCompilerSpec {
        fn get_name(&self) -> String {
            "test".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:64:default".to_string()
        }
        fn get_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>> {
            Some(Box::new(TestDataTypeManager))
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            Some(Arc::new(DefaultAddressFactory::new(vec![ram_space(), const_space()])))
        }
        fn get_compiler_spec(&self) -> Option<Box<dyn CompilerSpec>> {
            Some(Box::new(MockCompilerSpec))
        }
    }

    #[test]
    fn base_new_resolves_the_compiler_spec_and_pointer_data_type() {
        let machine: Arc<dyn PcodeMachine<i64>> = Arc::new(NilMachine);
        let base =
            AnnotatedEmuSyscallUseropLibraryBase::<i64>::new(machine, Box::new(TestProgramWithCompilerSpec));

        assert_eq!(base.dt_machine_word.get_name(), "pointer");
        assert!(base.syscall_map.is_empty());
        assert!(base.additional_archives.is_empty());
    }

    #[test]
    #[should_panic(expected = "No 'pointer' data type in program")]
    fn base_new_panics_without_a_pointer_data_type() {
        struct NoPointerDataTypeManager;
        impl DataTypeManager for NoPointerDataTypeManager {}

        struct NoPointerProgram;
        impl crate::framework::model::domain_object::DomainObject for NoPointerProgram {}
        impl Program for NoPointerProgram {
            fn get_name(&self) -> String {
                "test".to_string()
            }
            fn get_language_id(&self) -> String {
                "test:LE:64:default".to_string()
            }
            fn get_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>> {
                Some(Box::new(NoPointerDataTypeManager))
            }
            fn get_compiler_spec(&self) -> Option<Box<dyn CompilerSpec>> {
                Some(Box::new(MockCompilerSpec))
            }
        }

        let machine: Arc<dyn PcodeMachine<i64>> = Arc::new(NilMachine);
        AnnotatedEmuSyscallUseropLibraryBase::<i64>::new(machine, Box::new(NoPointerProgram));
    }

    // -----------------------------------------------------------------------------------------
    // Executor scaffolding, matching `emu_syscall_library`'s and
    // `annotated_pcode_userop_library`'s own test doubles.
    // -----------------------------------------------------------------------------------------

    #[derive(Debug, Clone, Copy)]
    struct I64Arithmetic;

    impl PcodeArithmetic<i64> for I64Arithmetic {
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
        fn to_concrete(&self, value: &i64, _purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
            Ok(crate::pcode::utils::long_to_bytes(*value, 8, false))
        }
        fn size_of(&self, _value: &i64) -> i64 {
            8
        }
    }

    struct MapState {
        cells: HashMap<i64, i64>,
    }

    impl ErasedPcodeExecutorStatePiece for MapState {}

    impl PcodeExecutorStatePiece<i64, i64> for MapState {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }
        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(I64Arithmetic)
        }
        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(I64Arithmetic)
        }
        fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
            vec![self]
        }
        fn set_var_abstract(
            &mut self,
            _space: &Arc<AddressSpace>,
            offset: &i64,
            _size: i32,
            _quantize: bool,
            val: &i64,
        ) {
            self.cells.insert(*offset, *val);
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
            *self.cells.get(offset).unwrap_or(&0)
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
        fn get_concrete_buffer(&self, _address: &Address, _purpose: Purpose) -> Box<dyn MemBuffer> {
            unimplemented!("not exercised by these tests")
        }
        fn clear(&mut self) {
            self.cells.clear();
        }
    }

    impl PcodeExecutorState<i64> for MapState {}

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

    fn test_executor() -> PcodeExecutor<i64> {
        PcodeExecutor::new(
            Arc::new(MockLanguage { default_space: ram_space() }),
            Arc::new(I64Arithmetic),
            Arc::new(Mutex::new(MapState { cells: HashMap::new() })),
            Reason::ExecuteRead,
        )
    }

    fn poke(executor: &PcodeExecutor<i64>, var: &Varnode, value: i64) {
        executor.get_state().lock().unwrap().set_var_varnode(var, &value);
    }
}
