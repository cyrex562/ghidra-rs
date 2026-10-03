//! Port of `ghidra.app.util.RepeatInstructionByteTracker`.
//!
//! Tracks runs of consecutively disassembled instructions made of one repeated byte value (e.g.
//! a run of `00 00` "instructions" through zero-filled memory), so the disassembler can stop and
//! flag a flow that exceeds a limit.

use crate::app::util::pseudo_instruction::PseudoInstruction;
use crate::program::model::address::AddressSetView;

/// Tracks the number of consecutive instructions whose bytes are all one repeated value.
///
/// Port of `ghidra.app.util.RepeatInstructionByteTracker`.
pub struct RepeatInstructionByteTracker {
    repeat_pattern_limit_ignored_region: Option<Box<dyn AddressSetView>>,
    repeat_pattern_limit: i32,
    repeat_pattern_cnt: i32,
    repeat_byte_value: u8,
}

impl RepeatInstructionByteTracker {
    /// Port of `RepeatInstructionByteTracker(int, AddressSetView)`.
    ///
    /// # Arguments
    /// * `repeat_pattern_limit` - maximum number of instructions containing the same repeated
    ///   byte values; a value less than or equal to 0 disables the check
    /// * `repeat_pattern_limit_ignored_region` - optional set of addresses where the check is
    ///   ignored
    pub fn new(
        repeat_pattern_limit: i32,
        repeat_pattern_limit_ignored_region: Option<Box<dyn AddressSetView>>,
    ) -> Self {
        RepeatInstructionByteTracker {
            repeat_pattern_limit_ignored_region,
            repeat_pattern_limit,
            repeat_pattern_cnt: 0,
            repeat_byte_value: 0,
        }
    }

    /// Resets the tracker's run count. Port of `reset()`.
    pub fn reset(&mut self) {
        self.repeat_pattern_cnt = 0;
    }

    /// Checks the next instruction of a run, returning true if it pushes the run of repeated
    /// byte instructions past the limit (the count restarts then). Port of
    /// `exceedsRepeatBytePattern(PseudoInstruction)`.
    pub fn exceeds_repeat_byte_pattern<C>(&mut self, inst: &PseudoInstruction<C>) -> bool {
        if self.repeat_pattern_limit <= 0 {
            return false;
        }
        if let Some(region) = &self.repeat_pattern_limit_ignored_region {
            if region.contains(inst.record().address()) {
                self.repeat_pattern_cnt = 0;
                return false;
            }
        }

        match inst.repeated_byte() {
            None => self.repeat_pattern_cnt = 0,
            Some(repeated_byte) if repeated_byte == self.repeat_byte_value => {
                self.repeat_pattern_cnt += 1;
                if self.repeat_pattern_cnt > self.repeat_pattern_limit {
                    self.repeat_pattern_cnt = 0;
                    return true;
                }
            }
            Some(repeated_byte) => {
                self.repeat_byte_value = repeated_byte;
                self.repeat_pattern_cnt = 1;
            }
        }
        false
    }

    /// Sets the maximum number of instructions in a single run which contain the same byte
    /// values; a value less than or equal to 0 disables the check. Port of
    /// `setRepeatPatternLimit(int)`.
    pub fn set_repeat_pattern_limit(&mut self, max_instructions: i32) {
        self.repeat_pattern_limit = max_instructions;
    }

    /// Sets the region over which the repeat pattern limit is ignored. Port of
    /// `setRepeatPatternLimitIgnored(AddressSetView)`.
    pub fn set_repeat_pattern_limit_ignored(&mut self, set: Option<Box<dyn AddressSetView>>) {
        self.repeat_pattern_limit_ignored_region = set;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::processors::sleigh::sleigh_instruction_prototype::decode_tests;
    use crate::program::model::address::{Address, AddressSet};
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::processor_context_impl::ProcessorContextImpl;
    use crate::program::model::mem::ByteMemBufferImpl;
    use std::sync::Arc;

    /// Decodes `bytes` at `offset` with the toy sleigh language: `11 11` is `mov r1, 0x11`,
    /// whose bytes repeat, and `11 2a` is `mov r1, 0x2a`, whose bytes do not.
    fn insn(offset: i64, bytes: &[u8]) -> PseudoInstruction<ProcessorContextImpl> {
        let lang = decode_tests::language();
        let addr = Address::new(lang.get_default_space(), offset);
        let proto = lang
            .parse_prototype(Arc::new(ByteMemBufferImpl::new(addr.clone(), bytes.to_vec(), true)), Vec::new(), false)
            .unwrap();
        let mem = ByteMemBufferImpl::new(addr.clone(), bytes.to_vec(), true);
        PseudoInstruction::new(addr, Arc::new(proto), &mem, ProcessorContextImpl::new(lang.clone())).unwrap()
    }

    #[test]
    fn a_run_longer_than_the_limit_is_flagged_and_restarts() {
        let mut tracker = RepeatInstructionByteTracker::new(2, None);
        let repeated = insn(0x1000, &[0x11, 0x11]);
        assert_eq!(repeated.repeated_byte(), Some(0x11));
        assert!(!tracker.exceeds_repeat_byte_pattern(&repeated)); // 1
        assert!(!tracker.exceeds_repeat_byte_pattern(&repeated)); // 2
        assert!(tracker.exceeds_repeat_byte_pattern(&repeated)); // 3 > 2
        // the count restarted at 0, and the byte value is still 0x11
        assert!(!tracker.exceeds_repeat_byte_pattern(&repeated));
        assert!(!tracker.exceeds_repeat_byte_pattern(&repeated));
        assert!(tracker.exceeds_repeat_byte_pattern(&repeated));
    }

    #[test]
    fn a_differing_instruction_or_reset_breaks_the_run() {
        let mut tracker = RepeatInstructionByteTracker::new(1, None);
        let repeated = insn(0x1000, &[0x11, 0x11]);
        let plain = insn(0x1000, &[0x11, 0x2a]);
        assert_eq!(plain.repeated_byte(), None);
        assert!(!tracker.exceeds_repeat_byte_pattern(&repeated));
        assert!(!tracker.exceeds_repeat_byte_pattern(&plain));
        assert!(!tracker.exceeds_repeat_byte_pattern(&repeated));
        tracker.reset();
        // Java keeps the byte value across a reset, so the run resumes at 1.
        assert!(!tracker.exceeds_repeat_byte_pattern(&repeated));
        assert!(tracker.exceeds_repeat_byte_pattern(&repeated));
    }

    #[test]
    fn the_check_is_off_for_a_non_positive_limit_or_in_the_ignored_region() {
        let repeated = insn(0x1000, &[0x11, 0x11]);
        let mut tracker = RepeatInstructionByteTracker::new(0, None);
        for _ in 0..5 {
            assert!(!tracker.exceeds_repeat_byte_pattern(&repeated));
        }

        tracker.set_repeat_pattern_limit(1);
        let start = repeated.record().address().clone();
        let mut ignored = AddressSet::new();
        ignored.add_range(&start, &start);
        tracker.set_repeat_pattern_limit_ignored(Some(Box::new(ignored)));
        for _ in 0..5 {
            assert!(!tracker.exceeds_repeat_byte_pattern(&repeated));
        }
        tracker.set_repeat_pattern_limit_ignored(None);
        assert!(!tracker.exceeds_repeat_byte_pattern(&repeated));
        assert!(tracker.exceeds_repeat_byte_pattern(&repeated));
    }
}
