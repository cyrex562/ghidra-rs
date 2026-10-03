//! Port of `ghidra.feature.fid.hash.X86InstructionSkipper`.

use crate::program::model::lang::processor::Processor as RealProcessor;
use crate::program::seam_stubs::Processor;
use crate::util::classfinder::extension_point::ExtensionPoint;
use crate::util::search::instruction_skipper::InstructionSkipper;

// IF YOU CHANGE THIS, YOU MUST INCREMENT LibrariesTable.VERSION
// AND REBUILD ALL THE VISUAL STUDIO LIBRARIES (or anything else
// that uses the x86 32-bit processor)
#[rustfmt::skip]
const PATTERNS: &[&[u8]] = &[
    &[0x90],
    &[0x8b, 0xc0],
    &[0x8b, 0xc9],
    &[0x8b, 0xd2],
    &[0x8b, 0xdb],
    &[0x8b, 0xe4],
    &[0x8b, 0xed],
    &[0x8b, 0xf6],
    &[0x8b, 0xff],
    &[0x66, 0x90],
    &[0x0f, 0x1f, 0x00],
    &[0x0f, 0x1f, 0x40, 0x00],
    &[0x0f, 0x1f, 0x44, 0x00, 0x00],
    &[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00],
    &[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00],
    &[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
    &[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
];

/// Thin wrapper adapting the real, interned [`RealProcessor`] to the [`Processor`] placeholder
/// trait [`InstructionSkipper::get_applicable_processor`] returns. See that trait's own module
/// for why the placeholder (rather than [`RealProcessor`] directly) is still the established
/// signature across this crate.
struct GetApplicableProcessor(RealProcessor);

impl Processor for GetApplicableProcessor {
    fn name(&self) -> String {
        self.0.to_string()
    }
}

/// These are the NOP instructions laid down by Visual Studio (or potentially other compilers,
/// like gcc) as advised by Intel. They represent "do nothing" operations of various sizes which
/// are used for dynamic code patching.
///
/// Port of `ghidra.feature.fid.hash.X86InstructionSkipper`.
pub struct X86InstructionSkipper;

impl ExtensionPoint for X86InstructionSkipper {}

impl InstructionSkipper for X86InstructionSkipper {
    fn get_applicable_processor(&self) -> Box<dyn Processor> {
        Box::new(GetApplicableProcessor(RealProcessor::find_or_possibly_create_processor("x86")))
    }

    /// Port of `X86InstructionSkipper.shouldSkip(byte[], int)`. The [`InstructionSkipper`] trait
    /// (already ported) collapses Java's `(byte[] buffer, int size)` pair into a single
    /// `buffer: &[u8]` parameter, since a slice already carries its own length; Java's explicit
    /// `pat.length != size` gate plus per-byte loop is exactly slice equality (`==` on `&[u8]`
    /// checks length first, then elements), which this reduces to directly.
    fn should_skip(&self, buffer: &[u8]) -> bool {
        PATTERNS.iter().any(|pattern| *pattern == buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_applicable_processor_is_the_interned_x86_processor() {
        let skipper = X86InstructionSkipper;
        let processor = skipper.get_applicable_processor();
        assert_eq!(processor.name(), "x86");
    }

    #[test]
    fn get_applicable_processor_interns_across_calls() {
        // Mirrors Java's `Processor.findOrPossiblyCreateProcessor` interning: repeated calls
        // report the same name (the same registry entry), not merely coincidentally-equal ones.
        let skipper = X86InstructionSkipper;
        let a = skipper.get_applicable_processor();
        let b = skipper.get_applicable_processor();
        assert_eq!(a.name(), b.name());
    }

    #[test]
    fn should_skip_single_byte_nop() {
        let skipper = X86InstructionSkipper;
        assert!(skipper.should_skip(&[0x90]));
    }

    #[test]
    fn should_skip_two_byte_xchg_style_nops() {
        let skipper = X86InstructionSkipper;
        assert!(skipper.should_skip(&[0x8b, 0xc0]));
        assert!(skipper.should_skip(&[0x8b, 0xff]));
        assert!(skipper.should_skip(&[0x66, 0x90]));
    }

    #[test]
    fn should_skip_multi_byte_nop_patterns() {
        let skipper = X86InstructionSkipper;
        assert!(skipper.should_skip(&[0x0f, 0x1f, 0x00]));
        assert!(skipper.should_skip(&[0x0f, 0x1f, 0x40, 0x00]));
        assert!(skipper.should_skip(&[0x0f, 0x1f, 0x44, 0x00, 0x00]));
        assert!(skipper.should_skip(&[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00]));
        assert!(skipper.should_skip(&[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00]));
        assert!(skipper.should_skip(&[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]));
        assert!(skipper.should_skip(&[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]));
    }

    #[test]
    fn should_not_skip_unrelated_bytes() {
        let skipper = X86InstructionSkipper;
        assert!(!skipper.should_skip(&[0xc3])); // ret
        assert!(!skipper.should_skip(&[0x55])); // push ebp
    }

    #[test]
    fn should_not_skip_when_length_differs_from_every_pattern() {
        // A prefix of a real pattern, but the wrong length: Java's loop requires
        // `pat.length == size` before comparing bytes at all.
        let skipper = X86InstructionSkipper;
        assert!(!skipper.should_skip(&[0x0f, 0x1f]));
        assert!(!skipper.should_skip(&[0x0f, 0x1f, 0x00, 0x00]));
    }

    #[test]
    fn should_not_skip_when_same_length_but_bytes_differ() {
        let skipper = X86InstructionSkipper;
        // Same length as `{0x8b, 0xc0}` but different bytes.
        assert!(!skipper.should_skip(&[0x8b, 0xaa]));
    }

    #[test]
    fn should_not_skip_empty_buffer() {
        let skipper = X86InstructionSkipper;
        assert!(!skipper.should_skip(&[]));
    }

    #[test]
    fn usable_as_trait_object() {
        let skipper: Box<dyn InstructionSkipper> = Box::new(X86InstructionSkipper);
        assert!(skipper.should_skip(&[0x90]));
        assert_eq!(skipper.get_applicable_processor().name(), "x86");
    }
}
