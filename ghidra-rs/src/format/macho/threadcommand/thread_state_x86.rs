/// x86 thread state flavor constants for Mach-O thread commands.
///
/// Mirrors the constants defined in Ghidra's abstract `ThreadStateX86` class.
pub struct ThreadStateX86;

impl ThreadStateX86 {
    #[deprecated(note = "use X86_THREAD_STATE32")]
    pub const I386_THREAD_STATE: u32 = 1;
    #[deprecated(note = "use X86_FLOAT_STATE32")]
    pub const I386_FLOAT_STATE: u32 = 2;
    #[deprecated(note = "use X86_EXCEPTION_STATE32")]
    pub const I386_EXCEPTION_STATE: u32 = 3;

    pub const X86_THREAD_STATE32: u32 = 1;
    pub const X86_FLOAT_STATE32: u32 = 2;
    pub const X86_EXCEPTION_STATE32: u32 = 3;
    pub const X86_THREAD_STATE64: u32 = 4;
    pub const X86_FLOAT_STATE64: u32 = 5;
    pub const X86_EXCEPTION_STATE64: u32 = 6;
    pub const X86_THREAD_STATE: u32 = 7;
    pub const X86_FLOAT_STATE: u32 = 8;
    pub const X86_EXCEPTION_STATE: u32 = 9;
    pub const X86_DEBUG_STATE32: u32 = 10;
    pub const X86_DEBUG_STATE64: u32 = 11;
    pub const X86_DEBUG_STATE: u32 = 12;
    pub const THREAD_STATE_NONE: u32 = 13;
}

#[cfg(test)]
mod tests {
    #[allow(deprecated)]
    use super::ThreadStateX86;

    #[test]
    #[allow(deprecated)]
    fn deprecated_aliases_match_modern_values() {
        assert_eq!(ThreadStateX86::I386_THREAD_STATE, ThreadStateX86::X86_THREAD_STATE32);
        assert_eq!(ThreadStateX86::I386_FLOAT_STATE, ThreadStateX86::X86_FLOAT_STATE32);
        assert_eq!(ThreadStateX86::I386_EXCEPTION_STATE, ThreadStateX86::X86_EXCEPTION_STATE32);
    }

    #[test]
    fn state_constants_are_sequential() {
        assert_eq!(ThreadStateX86::X86_THREAD_STATE32, 1);
        assert_eq!(ThreadStateX86::X86_FLOAT_STATE32, 2);
        assert_eq!(ThreadStateX86::X86_EXCEPTION_STATE32, 3);
        assert_eq!(ThreadStateX86::X86_THREAD_STATE64, 4);
        assert_eq!(ThreadStateX86::X86_FLOAT_STATE64, 5);
        assert_eq!(ThreadStateX86::X86_EXCEPTION_STATE64, 6);
        assert_eq!(ThreadStateX86::X86_THREAD_STATE, 7);
        assert_eq!(ThreadStateX86::X86_FLOAT_STATE, 8);
        assert_eq!(ThreadStateX86::X86_EXCEPTION_STATE, 9);
        assert_eq!(ThreadStateX86::X86_DEBUG_STATE32, 10);
        assert_eq!(ThreadStateX86::X86_DEBUG_STATE64, 11);
        assert_eq!(ThreadStateX86::X86_DEBUG_STATE, 12);
        assert_eq!(ThreadStateX86::THREAD_STATE_NONE, 13);
    }
}
