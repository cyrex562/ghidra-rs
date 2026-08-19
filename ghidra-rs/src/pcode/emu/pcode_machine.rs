//! A machine which executes p-code on state of an abstract type.
//!
//! Corresponds to `ghidra.pcode.emu.PcodeMachine`.

use std::sync::Arc;

use crate::pcode::exec::pcode_arithmetic::PcodeArithmetic;
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_userop_library::PcodeUseropLibrary;
use crate::pcode::emu::pcode_thread::ErasedPcodeThread;
use crate::pcode::exec::pcode_program::PcodeProgram;
use crate::program::model::address::{Address, AddressRange};
use crate::program::model::lang::sleigh::SleighLanguage;

/// Specifies whether or not to interrupt on p-code breakpoints.
///
/// Port of `PcodeMachine.SwiMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwiMode {
    /// Heed `PcodeEmulationLibrary.emu_swi()` calls.
    Active,
    /// Ignore all `PcodeEmulationLibrary.emu_swi()` calls.
    IgnoreAll,
    /// Ignore `PcodeEmulationLibrary.emu_swi()` calls for one p-code step.
    ///
    /// The mode is reset to [`SwiMode::Active`] after one p-code step, whether or not that step
    /// causes an SWI.
    IgnoreStep,
}

/// The kind of access breakpoint.
///
/// Port of `PcodeMachine.AccessKind`. Java stores the `trapsRead`/`trapsWrite` flags in per-constant
/// fields; here they are derived from the variant, which is equivalent and needs no storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessKind {
    /// A read access breakpoint.
    R,
    /// A write access breakpoint.
    W,
    /// A read/write access breakpoint.
    Rw,
}

impl AccessKind {
    /// Check if this kind of breakpoint should trap a read, i.e.,
    /// [`OpCode::Load`](crate::program::model::pcode::OpCode).
    pub fn traps_read(self) -> bool {
        matches!(self, AccessKind::R | AccessKind::Rw)
    }

    /// Check if this kind of breakpoint should trap a write, i.e.,
    /// [`OpCode::Store`](crate::program::model::pcode::OpCode).
    pub fn traps_write(self) -> bool {
        matches!(self, AccessKind::W | AccessKind::Rw)
    }
}

/// A machine whose value type has been erased: the Rust rendering of Java's wildcard
/// `PcodeMachine<?>`.
///
/// Java's wildcard existential type (a machine over *some* unknown value domain) has no
/// generic-preserving Rust shape, so, following the convention already used for
/// [`ErasedPcodeUseropLibrary`](crate::pcode::exec::pcode_userop_library::ErasedPcodeUseropLibrary)
/// and
/// [`ErasedPcodeExecutorStatePiece`](crate::pcode::exec::pcode_executor_state_piece::ErasedPcodeExecutorStatePiece),
/// this is a bare, object-safe marker that every machine also implements. It is a supertrait of
/// [`PcodeMachine`], so a generic `impl PcodeMachine<T>` satisfies it without an explicit
/// conversion.
///
/// It also stands in for Java's *generic method* parameters over an unknown `T`, such as
/// `PcodeStateInitializer.initializeMachine(PcodeMachine<T>)`: making that method generic in Rust
/// would cost the enclosing trait its object safety, which an extension point cannot afford.
pub trait ErasedPcodeMachine {}

/// A machine which executes p-code on state of an abstract type.
///
/// `T` is the type of objects in the machine's state.
pub trait PcodeMachine<T: 'static>: ErasedPcodeMachine {
    /// Get the machine's Sleigh language (processor model).
    fn get_language(&self) -> &SleighLanguage;

    /// Get the arithmetic applied by the machine.
    ///
    /// Returns an owned handle rather than a borrow, matching
    /// [`PcodeExecutorStatePiece::get_arithmetic`](crate::pcode::exec::pcode_executor_state_piece::PcodeExecutorStatePiece::get_arithmetic):
    /// a machine's threads each need to retain the arithmetic without borrowing from the machine.
    fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<T>>;

    /// Change the efficacy of p-code breakpoints.
    ///
    /// This is used to prevent breakpoints from interrupting at inappropriate times, e.g., upon
    /// continuing from a breakpoint.
    fn set_software_interrupt_mode(&mut self, mode: SwiMode);

    /// Get the current software interrupt mode.
    fn get_software_interrupt_mode(&self) -> SwiMode;

    /// Get the userop library common to all threads in the machine.
    ///
    /// Note that threads may have larger libraries, but each contains all the userops in this
    /// library.
    fn get_userop_library(&self) -> &dyn PcodeUseropLibrary<T>;

    /// Get a userop library which at least declares all userops available in each thread userop
    /// library.
    ///
    /// Thread userop libraries may have more userops than are defined in the machine's userop
    /// library. However, to compile Sleigh programs linked to thread libraries, the thread's
    /// userops must be known to the compiler. The stub library will name all userops common among
    /// the threads, even if their definitions vary. **WARNING:** The stub library is not required
    /// to provide implementations of the userops. Often they will panic, so do not attempt to use
    /// the returned library in an executor.
    fn get_stub_userop_library(&self) -> &dyn PcodeUseropLibrary<T>;

    /// Create a new thread with a default name in this machine.
    ///
    /// The machine retains the thread as well (see [`get_all_threads`](Self::get_all_threads)),
    /// hence the shared handle. Java's return type is `PcodeThread<T>`; the handle is
    /// value-erased here until a concrete
    /// [`PcodeThread`](crate::pcode::emu::pcode_thread::PcodeThread) implementation exists to
    /// return (see [`ErasedPcodeThread`]).
    fn new_thread(&mut self) -> Arc<dyn ErasedPcodeThread>;

    /// Create a new thread with the given name in this machine.
    ///
    /// Java overloads `newThread`; Rust traits cannot overload on arity, so the named form gets a
    /// distinct name.
    fn new_thread_named(&mut self, name: &str) -> Arc<dyn ErasedPcodeThread>;

    /// Get the thread, if present, with the given name, creating it if `create_if_absent`.
    ///
    /// Returns `None` (Java's `null`) if absent and not created. Takes `&mut self` because the
    /// creating case adds to the machine.
    fn get_thread(&mut self, name: &str, create_if_absent: bool) -> Option<Arc<dyn ErasedPcodeThread>>;

    /// Collect all threads present in the machine.
    fn get_all_threads(&self) -> Vec<Arc<dyn ErasedPcodeThread>>;

    /// Get the machine's shared (memory) state.
    ///
    /// The returned state may panic if the client requests register values of it. This state is
    /// shared among all threads in this machine.
    fn get_shared_state(&self) -> &dyn PcodeExecutorState<T>;

    /// Get the machine's shared (memory) state for writing.
    ///
    /// Java has only `getSharedState()`, since a Java reference is unrestricted; writing to the
    /// state (`setVar` and friends) needs `&mut` in Rust, so the mutable view is a separate
    /// accessor rather than a getter/setter pair.
    fn get_shared_state_mut(&mut self) -> &mut dyn PcodeExecutorState<T>;

    /// Set the suspension state of the machine.
    ///
    /// This does not simply suspend all threads, but sets a machine-wide flag. A thread is
    /// suspended if either the thread's flag is set, or the machine's flag is set.
    fn set_suspended(&mut self, suspended: bool);

    /// Check the suspension state of the machine.
    fn is_suspended(&self) -> bool;

    /// Compile the given Sleigh code for execution by a thread of this machine.
    ///
    /// This links in the userop library given at construction time and those defining the
    /// emulation userops, e.g., `emu_swi`.
    fn compile_sleigh(&self, source_name: &str, source: &str) -> PcodeProgram;

    /// Override the p-code at the given address with the given Sleigh source.
    ///
    /// This will attempt to compile the given source against this machine's userop library and
    /// then inject it at the given address. The resulting p-code *replaces* that which would be
    /// executed by decoding the instruction at the given address. That means the machine will not
    /// decode, nor advance its counter, unless the Sleigh causes it. In most cases, the Sleigh
    /// will call `PcodeEmulationLibrary.emu_exec_decoded()` to cause the machine to decode and
    /// execute the overridden instruction.
    ///
    /// Each address can have at most a single inject. If there is already one present, it is
    /// replaced and the old inject completely forgotten. The injector does not support chaining or
    /// double-wrapping, etc.
    fn inject(&mut self, address: &Address, source: &str);

    /// Check for a p-code injection (override) at the given address.
    ///
    /// `address` is usually the program counter. The result is most likely `None`.
    fn get_inject(&self, address: &Address) -> Option<&PcodeProgram>;

    /// Remove the inject, if present, at the given address.
    fn clear_inject(&mut self, address: &Address);

    /// Remove all injects from this machine.
    ///
    /// This will clear execution breakpoints, but not access breakpoints. See
    /// [`clear_access_breakpoints`](Self::clear_access_breakpoints).
    fn clear_all_injects(&mut self);

    /// Add a conditional execution breakpoint at the given address.
    ///
    /// Breakpoints are implemented at the p-code level using an inject, without modification to
    /// the emulated image. As such, it cannot coexist with another inject. A client needing to
    /// break during an inject must use `PcodeEmulationLibrary.emu_swi()` in the injected Sleigh.
    ///
    /// `sleigh_condition` is a Sleigh expression which controls the breakpoint.
    fn add_breakpoint(&mut self, address: &Address, sleigh_condition: &str);

    /// Add an access breakpoint over the given range.
    ///
    /// Access breakpoints are implemented out of band, without modification to the emulated image.
    /// The breakpoints are only effective for p-code `LOAD` and `STORE` operations with concrete
    /// offsets. Thus, an operation that refers directly to a memory address, e.g., a memory-mapped
    /// register, will not be trapped. Similarly, access breakpoints on registers or unique
    /// variables will not work. Access to an abstract offset that cannot be made concrete, i.e.,
    /// via [`PcodeArithmetic::to_concrete`], cannot be trapped.
    ///
    /// A breakpoint's range cannot cross more than one page boundary. Pages are 4096 bytes each.
    /// This allows implementations to optimize checking for breakpoints. If a breakpoint does not
    /// follow this rule, the behavior is undefined. Breakpoints may overlap, but currently no
    /// indication is given as to which breakpoint interrupted emulation.
    fn add_access_breakpoint(&mut self, range: &AddressRange, kind: AccessKind);

    /// Remove all access breakpoints from this machine.
    fn clear_access_breakpoints(&mut self);
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    /// A tiny machine that records only the behavior the tests exercise: SWI mode, suspension, and
    /// the inject/breakpoint map. Everything else is out of reach without a real `SleighLanguage`.
    ///
    /// `placeholder_program` stands in for whatever `compile_sleigh` would have produced: the
    /// tests only check presence/absence of an inject, never its content, so one opaque program is
    /// shared by every entry in `injects`.
    struct RecordingMachine {
        swi_mode: Option<SwiMode>,
        suspended: bool,
        injects: HashMap<i64, String>,
        access_breakpoints: Vec<(AddressRange, AccessKind)>,
        placeholder_program: PcodeProgram,
    }

    impl Default for RecordingMachine {
        fn default() -> Self {
            RecordingMachine {
                swi_mode: None,
                suspended: false,
                injects: HashMap::new(),
                access_breakpoints: Vec::new(),
                placeholder_program: crate::pcode::exec::pcode_program::testing::empty_program(),
            }
        }
    }

    impl ErasedPcodeMachine for RecordingMachine {}

    impl PcodeMachine<Vec<u8>> for RecordingMachine {
        fn get_language(&self) -> &SleighLanguage {
            unimplemented!("test should not call this")
        }

        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
            unimplemented!("test should not call this")
        }

        fn set_software_interrupt_mode(&mut self, mode: SwiMode) {
            self.swi_mode = Some(mode);
        }

        fn get_software_interrupt_mode(&self) -> SwiMode {
            self.swi_mode.unwrap_or(SwiMode::Active)
        }

        fn get_userop_library(&self) -> &dyn PcodeUseropLibrary<Vec<u8>> {
            unimplemented!("test should not call this")
        }

        fn get_stub_userop_library(&self) -> &dyn PcodeUseropLibrary<Vec<u8>> {
            unimplemented!("test should not call this")
        }

        fn new_thread(&mut self) -> Arc<dyn ErasedPcodeThread> {
            unimplemented!("test should not call this")
        }

        fn new_thread_named(&mut self, _name: &str) -> Arc<dyn ErasedPcodeThread> {
            unimplemented!("test should not call this")
        }

        fn get_thread(
            &mut self,
            _name: &str,
            _create_if_absent: bool,
        ) -> Option<Arc<dyn ErasedPcodeThread>> {
            None
        }

        fn get_all_threads(&self) -> Vec<Arc<dyn ErasedPcodeThread>> {
            vec![]
        }

        fn get_shared_state(&self) -> &dyn PcodeExecutorState<Vec<u8>> {
            unimplemented!("test should not call this")
        }

        fn get_shared_state_mut(&mut self) -> &mut dyn PcodeExecutorState<Vec<u8>> {
            unimplemented!("test should not call this")
        }

        fn set_suspended(&mut self, suspended: bool) {
            self.suspended = suspended;
        }

        fn is_suspended(&self) -> bool {
            self.suspended
        }

        fn compile_sleigh(&self, _source_name: &str, _source: &str) -> PcodeProgram {
            crate::pcode::exec::pcode_program::testing::empty_program()
        }

        fn inject(&mut self, address: &Address, source: &str) {
            // Java: "Each address can have at most a single inject... it is replaced."
            self.injects.insert(address.offset(), source.to_string());
        }

        fn get_inject(&self, address: &Address) -> Option<&PcodeProgram> {
            self.injects
                .get(&address.offset())
                .map(|_| &self.placeholder_program)
        }

        fn clear_inject(&mut self, address: &Address) {
            self.injects.remove(&address.offset());
        }

        fn clear_all_injects(&mut self) {
            self.injects.clear();
        }

        fn add_breakpoint(&mut self, address: &Address, sleigh_condition: &str) {
            // Java implements execution breakpoints as injects.
            self.injects
                .insert(address.offset(), format!("if !({sleigh_condition}) goto <SKIP>;"));
        }

        fn add_access_breakpoint(&mut self, range: &AddressRange, kind: AccessKind) {
            self.access_breakpoints.push((range.clone(), kind));
        }

        fn clear_access_breakpoints(&mut self) {
            self.access_breakpoints.clear();
        }
    }

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn access_kind_traps_match_java_constants() {
        // Java: R(true, false), W(false, true), RW(true, true)
        assert!(AccessKind::R.traps_read());
        assert!(!AccessKind::R.traps_write());

        assert!(!AccessKind::W.traps_read());
        assert!(AccessKind::W.traps_write());

        assert!(AccessKind::Rw.traps_read());
        assert!(AccessKind::Rw.traps_write());
    }

    #[test]
    fn swi_mode_variants_are_distinct() {
        // Java's enum has exactly three constants, each distinct.
        let all = [SwiMode::Active, SwiMode::IgnoreAll, SwiMode::IgnoreStep];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                assert_eq!(i == j, a == b, "{a:?} vs {b:?}");
            }
        }
    }

    #[test]
    fn machine_tracks_swi_mode_and_suspension() {
        let mut machine = RecordingMachine::default();
        // Java's AbstractPcodeMachine starts in ACTIVE.
        assert_eq!(SwiMode::Active, machine.get_software_interrupt_mode());
        assert!(!machine.is_suspended());

        machine.set_software_interrupt_mode(SwiMode::IgnoreStep);
        assert_eq!(SwiMode::IgnoreStep, machine.get_software_interrupt_mode());

        machine.set_suspended(true);
        assert!(machine.is_suspended());
    }

    #[test]
    fn injects_are_replaced_not_chained() {
        let space = ram();
        let mut machine = RecordingMachine::default();
        let addr = space.address(0x400000);

        assert!(machine.get_inject(&addr).is_none());

        machine.inject(&addr, "emu_exec_decoded();");
        machine.inject(&addr, "emu_swi();");
        assert!(machine.get_inject(&addr).is_some());
        // "the old inject completely forgotten" -- one entry, the latest source.
        assert_eq!(1, machine.injects.len());
        assert_eq!("emu_swi();", machine.injects[&addr.offset()]);

        machine.clear_inject(&addr);
        assert!(machine.get_inject(&addr).is_none());
    }

    #[test]
    fn clear_all_injects_leaves_access_breakpoints() {
        let space = ram();
        let mut machine = RecordingMachine::default();
        machine.add_breakpoint(&space.address(0x400000), "RAX == 0");
        machine.add_access_breakpoint(
            &AddressRange::new(space.address(0x1000), space.address(0x1fff)),
            AccessKind::W,
        );

        // Java: clearAllInjects "will clear execution breakpoints, but not access breakpoints."
        machine.clear_all_injects();
        assert!(machine.injects.is_empty());
        assert_eq!(1, machine.access_breakpoints.len());
        assert!(machine.access_breakpoints[0].1.traps_write());

        machine.clear_access_breakpoints();
        assert!(machine.access_breakpoints.is_empty());
    }

    #[test]
    fn machine_is_usable_erased() {
        let machine = RecordingMachine::default();
        let erased: &dyn ErasedPcodeMachine = &machine;
        let _ = erased;
    }
}
