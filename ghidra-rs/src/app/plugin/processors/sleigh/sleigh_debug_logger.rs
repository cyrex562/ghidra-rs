//! Port of `ghidra.app.plugin.processors.sleigh.SleighDebugLogger`.
//!
//! `SleighDebugLogger` was selected as a dependency-cycle cut-point, so instead of a single
//! concrete struct its public API is modeled as the [`SleighDebugLogger`] trait: a log/buffer
//! that accumulates detailed instruction parse diagnostics (mnemonic/operand bit-pattern
//! groupings, context commits, indentation-formatted text) while a [`SleighInstructionPrototype`]
//! resolves an instruction encoding.
//!
//! Both Java constructors (which drive the actual parse and populate the log) are dropped, since
//! traits cannot provide constructors -- implementers are expected to perform that parse
//! themselves and expose the results through the trait methods below. The package-private
//! (default-access) helpers `dumpConstructor`, `dumpFixedHandle`, and `dumpPattern` -- called only
//! by other classes in the same Java package during constructor resolution, not by unrelated
//! callers -- are likewise dropped as not part of the public API being cut across, matching the
//! precedent set by [`SleighInstructionPrototype`]. The private nested `DebugInstructionContext`,
//! `PatternGroup`, `InstructionBitPattern`, and `MyProcessorContextView` helper classes, along
//! with all private computation helpers (`buildMasks`, `combineOperandMask`,
//! `combinePatternMask`, `combineSymbolMask`, `buildOperandMask`, `clearBits`, `getBytes`,
//! `isSigned`, `dumpSymbolLineNumbers`, `dumpFinalGlobalSets`), are Java implementation details of
//! a single concrete logger and are not modeled here; a concrete implementer supplies its own
//! internal bookkeeping to back the trait methods.
//!
//! The public static `getFormattedBytes(byte[])` helper is fully ported as the free function
//! [`get_formatted_bytes`], since it only formats bytes and references no unported type. The
//! `getFormattedInstructionMask`/`getFormattedMaskedValue` methods and the no-op
//! `addContextPattern` are also fully ported as trait default methods, since they only delegate
//! to other [`SleighDebugLogger`] methods (or, for `addContextPattern`, do nothing at all --
//! mirroring the Java method body, which is an empty `// TODO: not implemented` stub).
//!
//! Several `IllegalStateException`/`IllegalArgumentException` throw sites in the Java source
//! (pattern not yet complete, mismatched mask length) are mirrored as documented panics rather
//! than `Result`s, consistent with how this crate treats other unchecked Java exceptions (see
//! e.g. `RangeMapAdapter`).

use crate::app::plugin::processors::sleigh::sleigh_parser_context::SleighParserContext;
use crate::app::seam_stubs::TripleSymbol;
use crate::program::model::lang::sleigh::pattern::PatternBlock;
use crate::program::model::lang::sleigh::walker::ConstructState;
use crate::program::model::mem::MemoryAccessException;

/// Port of `SleighDebugLogger.SleighDebugMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SleighDebugMode {
    /// Full parse-detail logging.
    Verbose,
    /// Only accumulate instruction/operand bit masks; no textual log is produced.
    MasksOnly,
}

/// Convenience method for formatting bytes as a bit sequence.
///
/// Port of the static `SleighDebugLogger.getFormattedBytes(byte[])`.
pub fn get_formatted_bytes(value: &[u8]) -> String {
    value
        .iter()
        .map(|b| format!("{:08b}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Provides the ability to obtain detailed instruction parse details.
///
/// Port of `ghidra.app.plugin.processors.sleigh.SleighDebugLogger`.
pub trait SleighDebugLogger {
    /// True if constructed for verbose logging.
    ///
    /// Port of `SleighDebugLogger.isVerboseEnabled()`.
    fn is_verbose_enabled(&self) -> bool;

    /// True if a parse error was detected, otherwise false is returned. [`Self::get_masked_bytes`]
    /// and [`Self::get_instruction_mask`] should only be invoked if this method returns false.
    ///
    /// Port of `SleighDebugLogger.parseFailed()`.
    fn parse_failed(&self) -> bool;

    /// Get list of constructor names with line numbers. Any debug mode may be used.
    ///
    /// Port of `SleighDebugLogger.getConstructorLineNumbers()`.
    fn get_constructor_line_numbers(&self) -> Vec<String>;

    /// Append a message string to the log buffer.
    ///
    /// NOTE: Has no effect unless constructed with [`SleighDebugMode::Verbose`].
    ///
    /// Port of `SleighDebugLogger.append(String)`.
    fn append(&mut self, str: &str);

    /// Append a binary formatted integer value with the specified range of bits bracketed to the
    /// log. A -1 value for both `startbit` and `bitcount` disables the bit range bracketing.
    ///
    /// NOTE: Has no effect unless constructed with [`SleighDebugMode::Verbose`].
    ///
    /// Port of `SleighDebugLogger.append(int, int, int)`, renamed to avoid Rust's lack of
    /// parameter-type overloading.
    fn append_int(&mut self, value: i32, startbit: i32, bitcount: i32);

    /// Append a binary formatted integer array with the specified range of bits bracketed to the
    /// log. A -1 value for both `startbit` and `bitcount` disables the bit range bracketing.
    ///
    /// NOTE: Has no effect unless constructed with [`SleighDebugMode::Verbose`].
    ///
    /// Port of `SleighDebugLogger.append(int[], int, int)`, renamed to avoid Rust's lack of
    /// parameter-type overloading.
    fn append_ints(&mut self, value: &[i32], startbit: i32, bitcount: i32);

    /// Append a binary formatted byte array with the specified range of bits bracketed to the
    /// log. A -1 value for both `startbit` and `bitcount` disables the bit range bracketing.
    ///
    /// NOTE: Has no effect unless constructed with [`SleighDebugMode::Verbose`].
    ///
    /// Port of `SleighDebugLogger.append(byte[], int, int)`, renamed to avoid Rust's lack of
    /// parameter-type overloading.
    fn append_bytes(&mut self, value: &[u8], startbit: i32, bitcount: i32);

    /// Shift log indent right by one level.
    ///
    /// Port of `SleighDebugLogger.indent()`.
    fn indent(&mut self);

    /// Shift log indent right by `levels` levels.
    ///
    /// Port of `SleighDebugLogger.indent(int)`, renamed to avoid Rust's lack of
    /// parameter-type overloading.
    fn indent_by(&mut self, levels: i32);

    /// Shift log indent left by one level.
    ///
    /// Port of `SleighDebugLogger.dropIndent()`.
    fn drop_indent(&mut self);

    /// Shift log indent left by `levels` levels.
    ///
    /// Port of `SleighDebugLogger.dropIndent(int)`, renamed to avoid Rust's lack of
    /// parameter-type overloading.
    fn drop_indent_by(&mut self, levels: i32);

    /// Return the accumulated log text.
    ///
    /// Port of `SleighDebugLogger.toString()`, renamed to avoid clashing with Rust's
    /// `Display`/`ToString`.
    fn log_text(&self) -> String;

    /// Dump context pattern details.
    ///
    /// NOTE: Has no effect unless constructed with [`SleighDebugMode::Verbose`].
    ///
    /// Port of `SleighDebugLogger.dumpContextPattern(int[], int[], int, SleighParserContext)`.
    fn dump_context_pattern(
        &mut self,
        maskvec: &[i32],
        valvec: &[i32],
        byte_offset: i32,
        pos: &dyn SleighParserContext,
    );

    /// Dump transient context setting details.
    ///
    /// NOTE: Has no effect unless constructed with [`SleighDebugMode::Verbose`].
    ///
    /// # Arguments
    /// * `pos` - instruction context
    /// * `num` - 4-byte offset within base context register for mask and value
    /// * `value` - 4-byte context value
    /// * `mask` - 4-byte context mask
    ///
    /// Port of `SleighDebugLogger.dumpContextSet(SleighParserContext, int, int, int)`.
    fn dump_context_set(&mut self, pos: &dyn SleighParserContext, num: i32, value: i32, mask: i32);

    /// Dump globalset details. The target address is currently not included in the log.
    ///
    /// NOTE: Has no effect unless constructed with [`SleighDebugMode::Verbose`].
    ///
    /// # Errors
    /// Returns [`MemoryAccessException`] if resolving the commit's fixed handle fails.
    ///
    /// Port of
    /// `SleighDebugLogger.dumpGlobalSet(SleighParserContext, ConstructState, TripleSymbol, int, int, int)`.
    fn dump_global_set(
        &mut self,
        pos: &dyn SleighParserContext,
        state: &ConstructState,
        sym: &dyn TripleSymbol,
        num: i32,
        mask: i32,
        value: i32,
    ) -> Result<(), MemoryAccessException>;

    /// Start a new pattern group for a specific sub-table. `None` corresponds to a top-level
    /// constructor or low level complex pattern (AND, OR). All committed unnamed groups with the
    /// same parent group will be combined.
    ///
    /// Port of `SleighDebugLogger.startPatternGroup(String)`.
    fn start_pattern_group(&mut self, name: Option<&str>);

    /// Terminate the current pattern group.
    ///
    /// # Arguments
    /// * `commit` - if false the group will be discarded, if true the group will be retained.
    ///
    /// Port of `SleighDebugLogger.endPatternGroup(boolean)`.
    fn end_pattern_group(&mut self, commit: bool);

    /// Add instruction bit pattern to the current pattern group.
    ///
    /// # Arguments
    /// * `offset` - base offset at which the specified `maskvalue` can be applied.
    /// * `maskvalue` - pattern mask/value
    ///
    /// Port of `SleighDebugLogger.addInstructionPattern(int, PatternBlock)`.
    fn add_instruction_pattern(&mut self, offset: i32, maskvalue: &PatternBlock);

    /// Add instruction context pattern to the current pattern group.
    ///
    /// Port of `SleighDebugLogger.addContextPattern(PatternBlock)`. The Java method body is an
    /// empty `// TODO: not implemented` stub, so this default implementation faithfully mirrors
    /// that by doing nothing.
    fn add_context_pattern(&mut self, _maskvalue: &PatternBlock) {}

    /// Returns the instruction bit mask which identifies those bits used to uniquely identify the
    /// instruction (includes addressing modes, generally excludes register selector bits
    /// associated with attaches or immediate values used for semantic values only).
    ///
    /// # Panics
    /// Implementations should panic if the prototype parse failed (mirrors
    /// `IllegalStateException`).
    ///
    /// Port of `SleighDebugLogger.getInstructionMask()`.
    fn get_instruction_mask(&mut self) -> Vec<u8>;

    /// Get the byte value mask corresponding to the specified operand.
    ///
    /// # Panics
    /// Implementations should panic if the prototype parse failed (mirrors
    /// `IllegalStateException`) or if `op_index` is not a valid operand index (mirrors
    /// `IndexOutOfBoundsException`).
    ///
    /// Port of `SleighDebugLogger.getOperandValueMask(int)`.
    fn get_operand_value_mask(&mut self, op_index: i32) -> Vec<u8>;

    /// Return the general/operand bit mask formatted as a string.
    ///
    /// # Arguments
    /// * `op_index` - operand index, or -1 for the mnemonic mask.
    ///
    /// Port of `SleighDebugLogger.getFormattedInstructionMask(int)`.
    fn get_formatted_instruction_mask(&mut self, op_index: i32) -> String {
        let mask = if op_index < 0 {
            self.get_instruction_mask()
        } else {
            self.get_operand_value_mask(op_index)
        };
        get_formatted_bytes(&mask)
    }

    /// Return the general/operand bit values formatted as a string.
    ///
    /// # Arguments
    /// * `op_index` - operand index, or -1 for the mnemonic bit values.
    ///
    /// Port of `SleighDebugLogger.getFormattedMaskedValue(int)`.
    fn get_formatted_masked_value(&mut self, op_index: i32) -> String {
        let mask = if op_index < 0 {
            self.get_instruction_mask()
        } else {
            self.get_operand_value_mask(op_index)
        };
        let value = self.get_masked_bytes(&mask);
        get_formatted_bytes(&value)
    }

    /// Get the number of operands for the resulting prototype.
    ///
    /// # Panics
    /// Implementations should panic if the prototype parse failed (mirrors
    /// `IllegalStateException`).
    ///
    /// Port of `SleighDebugLogger.getNumOperands()`.
    fn get_num_operands(&self) -> i32;

    /// Apply an appropriate mask for the resulting instruction bytes to obtain the corresponding
    /// masked bytes.
    ///
    /// # Arguments
    /// * `mask` - instruction, operand, or similarly sized mask.
    ///
    /// # Panics
    /// Implementations should panic if the prototype parse failed (mirrors
    /// `IllegalStateException`) or if `mask`'s length does not match the instruction byte length
    /// (mirrors `IllegalArgumentException`).
    ///
    /// Port of `SleighDebugLogger.getMaskedBytes(byte[])`.
    fn get_masked_bytes(&self, mask: &[u8]) -> Vec<u8>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A minimal, in-memory implementation used purely to prove the trait is object-safe and
    /// that its default methods behave sensibly -- not a full behavioral port.
    struct MockLogger {
        mode: SleighDebugMode,
        buffer: Mutex<String>,
        indent_level: i32,
        parse_ok: bool,
        instruction_bytes: Vec<u8>,
        instruction_mask: Vec<u8>,
        operand_masks: Vec<Vec<u8>>,
    }

    impl MockLogger {
        fn new(mode: SleighDebugMode) -> Self {
            Self {
                mode,
                buffer: Mutex::new(String::new()),
                indent_level: 0,
                parse_ok: true,
                instruction_bytes: vec![0xDE, 0xAD],
                instruction_mask: vec![0xF0, 0x0F],
                operand_masks: vec![vec![0x0F, 0xF0]],
            }
        }
    }

    impl SleighDebugLogger for MockLogger {
        fn is_verbose_enabled(&self) -> bool {
            self.mode == SleighDebugMode::Verbose
        }

        fn parse_failed(&self) -> bool {
            !self.parse_ok
        }

        fn get_constructor_line_numbers(&self) -> Vec<String> {
            vec!["instruction(foo.sinc:12)".to_string()]
        }

        fn append(&mut self, str: &str) {
            if !self.is_verbose_enabled() {
                return;
            }
            self.buffer.lock().unwrap().push_str(str);
        }

        fn append_int(&mut self, value: i32, _startbit: i32, _bitcount: i32) {
            self.append(&format!("{:08b}", value));
        }

        fn append_ints(&mut self, _value: &[i32], _startbit: i32, _bitcount: i32) {}

        fn append_bytes(&mut self, value: &[u8], _startbit: i32, _bitcount: i32) {
            self.append(&get_formatted_bytes(value));
        }

        fn indent(&mut self) {
            self.indent_level += 1;
        }

        fn indent_by(&mut self, levels: i32) {
            self.indent_level += levels;
        }

        fn drop_indent(&mut self) {
            if self.indent_level > 0 {
                self.indent_level -= 1;
            }
        }

        fn drop_indent_by(&mut self, levels: i32) {
            self.indent_level = (self.indent_level - levels).max(0);
        }

        fn log_text(&self) -> String {
            self.buffer.lock().unwrap().clone()
        }

        fn dump_context_pattern(
            &mut self,
            _maskvec: &[i32],
            _valvec: &[i32],
            _byte_offset: i32,
            _pos: &dyn SleighParserContext,
        ) {
        }

        fn dump_context_set(
            &mut self,
            _pos: &dyn SleighParserContext,
            _num: i32,
            _value: i32,
            _mask: i32,
        ) {
        }

        fn dump_global_set(
            &mut self,
            _pos: &dyn SleighParserContext,
            _state: &ConstructState,
            _sym: &dyn TripleSymbol,
            _num: i32,
            _mask: i32,
            _value: i32,
        ) -> Result<(), MemoryAccessException> {
            Ok(())
        }

        fn start_pattern_group(&mut self, _name: Option<&str>) {}

        fn end_pattern_group(&mut self, _commit: bool) {}

        fn add_instruction_pattern(&mut self, _offset: i32, _maskvalue: &PatternBlock) {}

        fn get_instruction_mask(&mut self) -> Vec<u8> {
            assert!(!self.parse_failed(), "Pattern is not complete");
            self.instruction_mask.clone()
        }

        fn get_operand_value_mask(&mut self, op_index: i32) -> Vec<u8> {
            self.operand_masks[op_index as usize].clone()
        }

        fn get_num_operands(&self) -> i32 {
            self.operand_masks.len() as i32
        }

        fn get_masked_bytes(&self, mask: &[u8]) -> Vec<u8> {
            assert_eq!(mask.len(), self.instruction_bytes.len(), "inappropriate mask");
            mask.iter()
                .zip(self.instruction_bytes.iter())
                .map(|(m, b)| m & b)
                .collect()
        }
    }

    #[test]
    fn get_formatted_bytes_pads_each_byte_to_eight_bits_and_joins_with_spaces() {
        assert_eq!(get_formatted_bytes(&[0xFF, 0x01, 0x00]), "11111111 00000001 00000000");
        assert_eq!(get_formatted_bytes(&[]), "");
    }

    #[test]
    fn append_is_a_noop_unless_verbose() {
        let mut quiet = MockLogger::new(SleighDebugMode::MasksOnly);
        quiet.append("hello");
        assert_eq!(quiet.log_text(), "");

        let mut verbose = MockLogger::new(SleighDebugMode::Verbose);
        verbose.append("hello");
        assert_eq!(verbose.log_text(), "hello");
    }

    #[test]
    fn indent_and_drop_indent_track_levels_and_floor_at_zero() {
        let mut logger = MockLogger::new(SleighDebugMode::Verbose);
        logger.indent_by(3);
        assert_eq!(logger.indent_level, 3);
        logger.drop_indent();
        assert_eq!(logger.indent_level, 2);
        logger.drop_indent_by(10);
        assert_eq!(logger.indent_level, 0);
    }

    #[test]
    fn get_masked_bytes_applies_mask_over_instruction_bytes() {
        let logger = MockLogger::new(SleighDebugMode::Verbose);
        let masked = logger.get_masked_bytes(&[0xF0, 0x0F]);
        assert_eq!(masked, vec![0xD0, 0x0D]);
    }

    #[test]
    fn get_formatted_instruction_mask_and_masked_value_delegate_through_default_methods() {
        let mut logger = MockLogger::new(SleighDebugMode::Verbose);
        assert_eq!(logger.get_formatted_instruction_mask(-1), "11110000 00001111");
        assert_eq!(logger.get_formatted_masked_value(-1), "11010000 00001101");
        assert_eq!(logger.get_formatted_instruction_mask(0), "00001111 11110000");
    }

    #[test]
    fn add_context_pattern_default_is_a_true_noop() {
        let mut logger = MockLogger::new(SleighDebugMode::Verbose);
        logger.append("before");
        logger.add_context_pattern(&PatternBlock::always_true());
        assert_eq!(logger.log_text(), "before");
    }

    #[test]
    fn usable_as_trait_object() {
        let mut logger: Box<dyn SleighDebugLogger> = Box::new(MockLogger::new(SleighDebugMode::Verbose));
        assert!(logger.is_verbose_enabled());
        assert!(!logger.parse_failed());
        assert_eq!(logger.get_num_operands(), 1);
        logger.append("x");
        assert_eq!(logger.log_text(), "x");
    }
}
