//! A p-code thread operating on concrete bytes.
//!
//! Port of `ghidra.pcode.emu.BytesPcodeThread`.
//!
//! This is the default thread for [`PcodeEmulator`](crate::pcode::emu::pcode_emulator::PcodeEmulator).
//! It is a p-code thread that operates on concrete byte values in memory and registers.

use crate::pcode::emu::pcode_thread::ErasedPcodeThread;

/// A simple p-code thread that operates on concrete bytes.
///
/// Port of `BytesPcodeThread extends ModifiedPcodeThread<byte[]>`. This is the default
/// thread for [`PcodeEmulator`](crate::pcode::emu::pcode_emulator::PcodeEmulator).
///
/// # Implementation note
///
/// In Java, `BytesPcodeThread` extends `ModifiedPcodeThread<byte[]>` with just a constructor
/// that delegates to `super(name, machine)`. The full implementation is composed of the
/// `ModifiedPcodeThread` functionality (which wraps `DefaultPcodeThread`), which requires
/// instantiation with concrete executor state types and a decoder. Since the Rust port's
/// `PcodeEmulator::create_thread` pattern only provides a name, this struct currently
/// serves as a marker type implementing `ErasedPcodeThread`. Full `PcodeThread<Vec<u8>>`
/// functionality would require changes to how machines create and manage threads.
pub struct BytesPcodeThread {
    name: String,
}

impl BytesPcodeThread {
    /// Construct a new thread.
    ///
    /// Port of `BytesPcodeThread(String, AbstractPcodeMachine<byte[]>)`. Currently only
    /// accepts the name; the machine can be obtained later if needed for full functionality.
    pub fn new(name: &str) -> Self {
        Self { name: name.to_string() }
    }

    /// Port of the inherited `PcodeThread.getName()`.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl ErasedPcodeThread for BytesPcodeThread {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_pcode_thread_stores_and_retrieves_name() {
        let thread = BytesPcodeThread::new("test_thread");
        assert_eq!(thread.name(), "test_thread");
    }

    #[test]
    fn bytes_pcode_thread_implements_erased_pcode_thread() {
        let thread = BytesPcodeThread::new("thread0");
        let _erased: &dyn ErasedPcodeThread = &thread;
    }
}
