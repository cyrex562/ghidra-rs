//! Shared state threaded through the phases of passage translation.
//!
//! Port of `ghidra.pcode.emu.jit.analysis.JitAnalysisContext`.

use std::collections::HashSet;
use std::sync::Arc;

use crate::pcode::emu::jit::analysis::jit_control_flow_model::JitBlock;
use crate::pcode::emu::jit::jit_configuration::JitConfiguration;
use crate::pcode::seam_stubs::{AddrCtx, JitPassage};
use crate::program::model::lang::endian::Endian;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::pcode::PcodeOp;

/// A collection of state that is shared among several phases of the translation process.
///
/// Port of `ghidra.pcode.emu.jit.analysis.JitAnalysisContext`. See `JitCompiler`.
///
/// # Differences from Java
///
/// `passage` is [`JitPassage`](crate::pcode::seam_stubs::JitPassage), still a placeholder pending
/// its own port -- this type sits on the dependency cycle that placeholder exists to break (see
/// `STUBS.tsv`). Its `getLanguage()`/`getOpEntry()`/`getErrorMessage()` are grown just far enough
/// for this type to call them; the latter two panic until `JitPassage.java` lands.
///
/// `entry_blocks` and [`is_block_entry`](Self::is_block_entry) have no Java counterpart. The real
/// `getOpEntry(block.first()) != null` check
/// [`JitDataFlowBlockAnalyzer`](crate::pcode::emu::jit::analysis::jit_data_flow_block_analyzer::JitDataFlowBlockAnalyzer)
/// needs at construction time can't be answered yet (it goes through the still-panicking
/// `JitPassage::get_op_entry`), so this caches the known entry blocks directly instead.
/// [`Self::for_endian`]/[`Self::with_entry_blocks`] are the corresponding constructors for callers
/// with no [`JitConfiguration`]/[`JitPassage`] to build a Java-faithful context from; unlike
/// [`Self::new`], they carry no language.
#[derive(Clone)]
pub struct JitAnalysisContext {
    config: JitConfiguration,
    passage: JitPassage,
    language: Option<Arc<SleighLanguage>>,
    endian: Endian,
    entry_blocks: HashSet<JitBlock>,
}

impl JitAnalysisContext {
    /// Construct a new context, starting with the given configuration and source passage.
    ///
    /// Port of `new JitAnalysisContext(JitConfiguration, JitPassage)`.
    pub fn new(config: JitConfiguration, passage: JitPassage) -> Self {
        let language = passage.get_language();
        let endian = if language.is_big_endian() { Endian::Big } else { Endian::Little };
        Self { config, passage, language: Some(language), endian, entry_blocks: HashSet::new() }
    }

    /// Construct a context carrying only an endianness, for callers with no
    /// [`JitConfiguration`]/[`JitPassage`] to build one from. See the type-level doc.
    pub fn for_endian(endian: Endian) -> Self {
        Self {
            config: JitConfiguration::default(),
            passage: JitPassage::placeholder(),
            language: None,
            endian,
            entry_blocks: HashSet::new(),
        }
    }

    /// Like [`Self::for_endian`], additionally seeding the set of passage-entry blocks
    /// [`is_block_entry`](Self::is_block_entry) reports. See the type-level doc.
    pub fn with_entry_blocks(endian: Endian, entry_blocks: HashSet<JitBlock>) -> Self {
        Self {
            config: JitConfiguration::default(),
            passage: JitPassage::placeholder(),
            language: None,
            endian,
            entry_blocks,
        }
    }

    /// Get the JIT compiler configuration.
    ///
    /// Port of `JitAnalysisContext.getConfiguration()`.
    pub fn get_configuration(&self) -> &JitConfiguration {
        &self.config
    }

    /// Get the source passage.
    ///
    /// Port of `JitAnalysisContext.getPassage()`.
    pub fn get_passage(&self) -> &JitPassage {
        &self.passage
    }

    /// Get the translation source (i.e., emulation target) language.
    ///
    /// Port of `JitAnalysisContext.getLanguage()`. `None` only for a context built via
    /// [`Self::for_endian`]/[`Self::with_entry_blocks`], which carry no language -- see the
    /// type-level doc.
    pub fn get_language(&self) -> Option<&SleighLanguage> {
        self.language.as_deref()
    }

    /// Get the endianness of the translation source, i.e., emulation target.
    ///
    /// Port of `JitAnalysisContext.getEndian()`.
    pub fn get_endian(&self) -> Endian {
        self.endian
    }

    /// Check if the given p-code op is the first of an instruction.
    ///
    /// Port of `JitAnalysisContext.getOpEntry(PcodeOp)`; see `JitPassage.getOpEntry(PcodeOp)`.
    pub fn get_op_entry(&self, op: &PcodeOp) -> AddrCtx {
        self.passage.get_op_entry(op)
    }

    /// Get the error message for a given p-code op.
    ///
    /// Port of `JitAnalysisContext.getErrorMessage(PcodeOp)`; see
    /// `JitPassage.getErrorMessage(PcodeOp)`.
    pub fn get_error_message(&self, op: &PcodeOp) -> String {
        self.passage.get_error_message(op)
    }

    /// Stand-in for `getOpEntry(block.first()) != null`. See the type-level doc.
    pub fn is_block_entry(&self, block: JitBlock) -> bool {
        self.entry_blocks.contains(&block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::DefaultAddressFactory;
    use crate::program::model::pcode::PackedDecode;

    /// Builds a minimal but real little-endian `SleighLanguage`, mirroring the identical helper in
    /// [`crate::pcode::emu::jit::jit_pcode_emulator`]'s own tests.
    fn test_language() -> SleighLanguage {
        let factory = Arc::new(DefaultAddressFactory::new(vec![]));
        let mut data = vec![];
        data.extend_from_slice(&[0x60, 0xA1]); // <sleigh ...>
        data.extend_from_slice(&[0xE0, 0xA2, 0x21, 4]); // version="4"
        data.extend_from_slice(&[0xE0, 0xA3, 0x10]); // bigendian="false"
        data.extend_from_slice(&[0x60, 0xA2]); // <spaces defaultspace="ram">
        data.extend_from_slice(&[0xE0, 0xA9, 0x71, 3, b'r', b'a', b'm']);
        data.extend_from_slice(&[0x60, 0xAD, 0xA0, 0xAD]); // <space_other/>
        data.extend_from_slice(&[0x60, 0xA5]); // <space name="ram" size="4" index="1" delay="1"/>
        data.extend_from_slice(&[0xCC, 0x71, 3, b'r', b'a', b'm']);
        data.extend_from_slice(&[0xCF, 0x21, 4]);
        data.extend_from_slice(&[0xC9, 0x21, 1]);
        data.extend_from_slice(&[0xE0, 0xAA, 0x21, 1]);
        data.extend_from_slice(&[0xA0, 0xA5]); // </space>
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

    // Java: `new JitAnalysisContext(config, passage)` sets `endian = language.isBigEndian() ? BIG
    // : LITTLE` and exposes `config`/`passage`/`language` back out unchanged.
    #[test]
    fn new_derives_endian_from_language_and_exposes_ctor_args() {
        let language = Arc::new(test_language());
        let config = JitConfiguration::new(1, 2, 3, true, false, true);
        let passage = JitPassage::for_language(Arc::clone(&language));

        let context = JitAnalysisContext::new(config, passage);

        assert_eq!(context.get_endian(), Endian::Little);
        assert_eq!(*context.get_configuration(), config);
        assert_eq!(context.get_language().unwrap().get_id(), "test");
    }

    // Java has no equivalent constructor; this is the superset path existing callers use where no
    // real `JitConfiguration`/`JitPassage` is on hand. See the type-level doc.
    #[test]
    fn for_endian_and_with_entry_blocks_carry_no_language() {
        let block = JitBlock::new();
        let context = JitAnalysisContext::with_entry_blocks(Endian::Big, [block].into());

        assert_eq!(context.get_endian(), Endian::Big);
        assert!(context.get_language().is_none());
        assert!(context.is_block_entry(block));
        assert!(!context.is_block_entry(JitBlock::new()));
    }
}
