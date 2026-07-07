use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// ARM CPU state container for emulation.
///
/// Mirrors `ghidra.program.emulation.ArmCpuState` from Java.
pub struct ArmCpuState {
    irq_enabled: AtomicBool,
    privileged: AtomicBool,
    main_stack_pointer: AtomicU64,
    process_stack_pointer: AtomicU64,
    thread_mode_privileged: AtomicBool,
    thread_mode: AtomicBool,
    base_priority: AtomicU64,
}

impl ArmCpuState {
    /// Creates a new ARM CPU state with default values.
    ///
    /// Defaults:
    /// - irq_enabled: true
    /// - privileged: true
    /// - stack pointers: 0
    /// - thread_mode_privileged: false
    /// - thread_mode: false
    /// - base_priority: 0
    pub fn new() -> Self {
        Self {
            irq_enabled: AtomicBool::new(true),
            privileged: AtomicBool::new(true),
            main_stack_pointer: AtomicU64::new(0),
            process_stack_pointer: AtomicU64::new(0),
            thread_mode_privileged: AtomicBool::new(false),
            thread_mode: AtomicBool::new(false),
            base_priority: AtomicU64::new(0),
        }
    }

    /// Checks if interrupts are enabled.
    pub fn is_irq_enabled(&self) -> bool {
        self.irq_enabled.load(Ordering::SeqCst)
    }

    /// Sets the interrupt enable state.
    pub fn set_irq_enabled(&self, irq_enabled: bool) {
        self.irq_enabled.store(irq_enabled, Ordering::SeqCst);
    }

    /// Checks if the CPU is in privileged mode.
    pub fn is_privileged(&self) -> bool {
        self.privileged.load(Ordering::SeqCst)
    }

    /// Sets the privileged mode state.
    pub fn set_privileged(&self, privileged: bool) {
        self.privileged.store(privileged, Ordering::SeqCst);
    }

    /// Gets the main stack pointer value.
    pub fn get_main_stack_pointer(&self) -> u64 {
        self.main_stack_pointer.load(Ordering::SeqCst)
    }

    /// Sets the main stack pointer value.
    pub fn set_main_stack_pointer(&self, pointer: u64) {
        self.main_stack_pointer.store(pointer, Ordering::SeqCst);
    }

    /// Gets the process stack pointer value.
    pub fn get_process_stack_pointer(&self) -> u64 {
        self.process_stack_pointer.load(Ordering::SeqCst)
    }

    /// Sets the process stack pointer value.
    pub fn set_process_stack_pointer(&self, pointer: u64) {
        self.process_stack_pointer.store(pointer, Ordering::SeqCst);
    }

    /// Checks if thread mode has privileged access.
    pub fn is_thread_mode_privileged(&self) -> bool {
        self.thread_mode_privileged.load(Ordering::SeqCst)
    }

    /// Sets the thread mode privileged state.
    pub fn set_thread_mode_privileged(&self, thread_mode_privileged: bool) {
        self.thread_mode_privileged
            .store(thread_mode_privileged, Ordering::SeqCst);
    }

    /// Checks if the CPU is in thread mode.
    pub fn is_thread_mode(&self) -> bool {
        self.thread_mode.load(Ordering::SeqCst)
    }

    /// Sets the thread mode state.
    pub fn set_thread_mode(&self, thread_mode: bool) {
        self.thread_mode.store(thread_mode, Ordering::SeqCst);
    }

    /// Gets the base priority value.
    pub fn get_base_priority(&self) -> u64 {
        self.base_priority.load(Ordering::SeqCst)
    }

    /// Sets the base priority value.
    pub fn set_base_priority(&self, priority: u64) {
        self.base_priority.store(priority, Ordering::SeqCst);
    }
}

impl Default for ArmCpuState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_has_default_values() {
        let state = ArmCpuState::new();
        assert!(state.is_irq_enabled());
        assert!(state.is_privileged());
        assert_eq!(state.get_main_stack_pointer(), 0);
        assert_eq!(state.get_process_stack_pointer(), 0);
        assert!(!state.is_thread_mode_privileged());
        assert!(!state.is_thread_mode());
        assert_eq!(state.get_base_priority(), 0);
    }

    #[test]
    fn default_has_default_values() {
        let state = ArmCpuState::default();
        assert!(state.is_irq_enabled());
        assert!(state.is_privileged());
    }

    #[test]
    fn set_and_get_irq_enabled() {
        let state = ArmCpuState::new();
        assert!(state.is_irq_enabled());
        state.set_irq_enabled(false);
        assert!(!state.is_irq_enabled());
        state.set_irq_enabled(true);
        assert!(state.is_irq_enabled());
    }

    #[test]
    fn set_and_get_privileged() {
        let state = ArmCpuState::new();
        assert!(state.is_privileged());
        state.set_privileged(false);
        assert!(!state.is_privileged());
        state.set_privileged(true);
        assert!(state.is_privileged());
    }

    #[test]
    fn set_and_get_main_stack_pointer() {
        let state = ArmCpuState::new();
        assert_eq!(state.get_main_stack_pointer(), 0);
        state.set_main_stack_pointer(0x1000);
        assert_eq!(state.get_main_stack_pointer(), 0x1000);
        state.set_main_stack_pointer(0xFFFFFFFF);
        assert_eq!(state.get_main_stack_pointer(), 0xFFFFFFFF);
    }

    #[test]
    fn set_and_get_process_stack_pointer() {
        let state = ArmCpuState::new();
        assert_eq!(state.get_process_stack_pointer(), 0);
        state.set_process_stack_pointer(0x2000);
        assert_eq!(state.get_process_stack_pointer(), 0x2000);
        state.set_process_stack_pointer(0xFFFFFFFFFFFFFFFF);
        assert_eq!(state.get_process_stack_pointer(), 0xFFFFFFFFFFFFFFFF);
    }

    #[test]
    fn set_and_get_thread_mode_privileged() {
        let state = ArmCpuState::new();
        assert!(!state.is_thread_mode_privileged());
        state.set_thread_mode_privileged(true);
        assert!(state.is_thread_mode_privileged());
        state.set_thread_mode_privileged(false);
        assert!(!state.is_thread_mode_privileged());
    }

    #[test]
    fn set_and_get_thread_mode() {
        let state = ArmCpuState::new();
        assert!(!state.is_thread_mode());
        state.set_thread_mode(true);
        assert!(state.is_thread_mode());
        state.set_thread_mode(false);
        assert!(!state.is_thread_mode());
    }

    #[test]
    fn set_and_get_base_priority() {
        let state = ArmCpuState::new();
        assert_eq!(state.get_base_priority(), 0);
        state.set_base_priority(5);
        assert_eq!(state.get_base_priority(), 5);
        state.set_base_priority(255);
        assert_eq!(state.get_base_priority(), 255);
    }

    #[test]
    fn independent_field_mutations() {
        let state = ArmCpuState::new();
        state.set_irq_enabled(false);
        state.set_main_stack_pointer(0x1000);
        state.set_thread_mode(true);

        assert!(!state.is_irq_enabled());
        assert_eq!(state.get_main_stack_pointer(), 0x1000);
        assert!(state.is_thread_mode());
        assert!(state.is_privileged());
        assert_eq!(state.get_process_stack_pointer(), 0);
    }

    #[test]
    fn multiple_sequential_changes() {
        let state = ArmCpuState::new();

        state.set_privileged(false);
        state.set_privileged(true);
        state.set_privileged(false);
        assert!(!state.is_privileged());

        state.set_base_priority(100);
        state.set_base_priority(50);
        assert_eq!(state.get_base_priority(), 50);
    }
}
