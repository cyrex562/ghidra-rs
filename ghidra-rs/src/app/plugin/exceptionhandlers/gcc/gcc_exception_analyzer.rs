//! Ported from `ghidra.app.plugin.exceptionhandlers.gcc.GccExceptionAnalyzer`.
//!
//! An analyzer for locating and marking up the GCC exception handling information.
//!
//! # Shape
//!
//! The Java class extends `AbstractAnalyzer`, which is nothing but the `Analyzer` interface plus
//! six settable fields (name, description, type, priority, default enablement, one-time support).
//! There is no `AbstractAnalyzer` in this crate and nothing polymorphic about those fields, so
//! [`GccExceptionAnalyzer`] implements [`Analyzer`] directly and answers the inherited getters
//! from its own constants -- the values the Java constructor pushes into the base class.
//!
//! # Divergences from the Java
//!
//! * **`visitedPrograms` is keyed by program name.** Java holds a `Set<Program>`, i.e. an
//!   identity set of live program objects. `added` receives `&mut dyn Program`, which has no
//!   identity a `HashSet` can key on, so the set holds [`Program::get_name`] instead. Two distinct
//!   programs with the same name would be conflated; within one analysis session, which is all
//!   this set spans, they cannot be.
//! * **The `AutoAnalysisManagerListener` is the analyzer itself.** Java builds a lambda over
//!   `visitedPrograms` and registers it with the program's `AutoAnalysisManager` so a finished
//!   session forgets the program. A closure cannot own a mutable borrow of a field of the very
//!   struct that holds it, so the callback is instead
//!   [`impl AutoAnalysisManagerListener<dyn AutoAnalysisManager>`](AutoAnalysisManagerListener)
//!   on [`GccExceptionAnalyzer`]; the manager calls it once the real
//!   [`AutoAnalysisManager`](crate::app::seam_stubs::AutoAnalysisManager) is ported. `added` skips
//!   the registration call itself, because
//!   [`auto_analysis_manager::get_analysis_manager`](crate::app::seam_stubs::auto_analysis_manager::get_analysis_manager)
//!   is an unimplemented placeholder, and panicking there would take the whole analysis pass down
//!   with it. `setProtectedLocation` in `disassembleIfNeeded` is skipped for the same reason.
//! * **`Address.NO_ADDRESS`.** `getCatchParamInfo` compares a type-info address against the
//!   `Address.NO_ADDRESS` sentinel; the ported [`Address`] has no such sentinel (the divergence
//!   [`AbstractFrameSectionBase`](crate::app::plugin::exceptionhandlers::gcc::sections::abstract_frame_section::AbstractFrameSectionBase)
//!   documents), so [`TypeInfo::type_info_address`] is `None` there instead.
//! * **`monitor.initialize(max, message)`.** The ported [`TaskMonitor`] splits that overload into
//!   `initialize` + `set_message`, so `handleStandardSections` calls both.
//! * **The commented-out ARM support is left commented out.** `hasARMSection` returns a hard
//!   `false` in the Java, with the `ARMExIdxSection`/`ARMExTabSection` checks and
//!   `handleArmSections` commented out pending review; that state is preserved rather than
//!   revived.
//! * **Sections and commands are stubs.** `EhFrameSection`, `EhFrameHeaderSection`,
//!   `DebugFrameSection`, `SetCommentCmd` and `DisassembleCommand` are not ported yet; the
//!   placeholders in [`seam_stubs`](crate::app::seam_stubs) no-op, so `added` walks its whole
//!   structure but finds no regions to mark up until they land.

use std::collections::HashSet;

use crate::app::plugin::core::analysis::AutoAnalysisManagerListener;
use crate::app::seam_stubs::{
    self, disassemble_command, AutoAnalysisManager, DebugFrameSection, EhFrameHeaderSection,
    EhFrameSection, MessageLog, RegionDescriptor, SetCommentCmd,
};
use crate::app::services::{AnalysisPriority, Analyzer, AnalyzerType};
use crate::framework::options::Options;
use crate::program::model::address::{Address, AddressRange, AddressSet, AddressSetView};
use crate::program::model::listing::{CommentType, Program};
use crate::util::exception::CancelledException;
use crate::util::msg::Msg;
use crate::util::string_utilities::StringUtilities;
use crate::util::task::TaskMonitor;

/// A type info associates the address of a type information record with the filter value that is
/// used to handle a catch action for that type.
///
/// Port of `private class GccExceptionAnalyzer.TypeInfo`. Java's getter pair is dropped in favour
/// of plain fields -- this type is private to the module, and there is nothing to encapsulate.
struct TypeInfo {
    /// The address of the type information record, or `None` for Java's `Address.NO_ADDRESS`.
    type_info_address: Option<Address>,
    /// The action filter value that selects this type.
    action_filter: i32,
}

/// An analyzer for locating and marking up the GCC exception handling information.
///
/// Port of `class GccExceptionAnalyzer extends AbstractAnalyzer`.
pub struct GccExceptionAnalyzer {
    /// Whether try/catch comments should be written into the disassembly listing.
    create_try_catch_comments_enabled: bool,
    /// The programs already marked up by this analyzer, standing in for Java's `Set<Program>`.
    visited_programs: HashSet<String>,
}

impl GccExceptionAnalyzer {
    /// Port of `GccExceptionAnalyzer.NAME`.
    pub const NAME: &'static str = "GCC Exception Handlers";

    /// Port of `GccExceptionAnalyzer.DESCRIPTION`.
    pub const DESCRIPTION: &'static str =
        "Locates and annotates exception-handling infrastructure installed by the GCC compiler";

    /// Port of `GccExceptionAnalyzer.OPTION_NAME_CREATE_TRY_CATCHS`. Java declares it `protected`;
    /// Rust has no such visibility, and the option name is part of this analyzer's public contract
    /// with the options database, so it is `pub`.
    pub const OPTION_NAME_CREATE_TRY_CATCHS: &'static str = "Create Try Catch Comments";

    /// Port of `GccExceptionAnalyzer.OPTION_DESCRIPTION_CREATE_TRY_CATCHS`.
    const OPTION_DESCRIPTION_CREATE_TRY_CATCHS: &'static str =
        "Selecting this check box causes the analyzer to create comments in the \
         disassembly listing for the try and catch code.";

    /// Port of `GccExceptionAnalyzer.OPTION_DEFAULT_CREATE_TRY_CATCHS_ENABLED`.
    const OPTION_DEFAULT_CREATE_TRY_CATCHS_ENABLED: bool = true;

    /// Creates an analyzer for marking up the GCC exception handling information.
    ///
    /// Port of `GccExceptionAnalyzer()`. The Java constructor's `super(...)` call and its
    /// `setDefaultEnablement`/`setPriority` calls are answered by [`Analyzer::get_name`],
    /// [`Analyzer::get_description`], [`Analyzer::get_analysis_type`],
    /// [`Analyzer::get_default_enablement`] and [`Analyzer::get_priority`] instead of stored
    /// fields.
    pub fn new() -> Self {
        GccExceptionAnalyzer {
            create_try_catch_comments_enabled: Self::OPTION_DEFAULT_CREATE_TRY_CATCHS_ENABLED,
            visited_programs: HashSet::new(),
        }
    }

    /// Port of `getBlock(Program, String)` folded into `hasBlock(Program, String)`: whether the
    /// program has a memory block with exactly this name.
    fn has_block(program: &dyn Program, name: &str) -> bool {
        program
            .get_memory()
            .and_then(|memory| memory.get_block_by_name(name))
            .is_some()
    }

    /// Port of `hasBlockWithPrefix(Program, String)`.
    fn has_block_with_prefix(program: &dyn Program, prefix: &str) -> bool {
        match program.get_memory() {
            Some(memory) => memory
                .get_blocks()
                .iter()
                .any(|block| block.get_name().starts_with(prefix)),
            None => false,
        }
    }

    /// Port of `hasARMSection(Program)`.
    fn has_arm_section(program: &dyn Program) -> bool {
        let _ = program;

        // ARM GCC exception handling support removed pending further review
        false

        //  let has_arm_ex_idx = Self::has_block_with_prefix(program, ARMExIdxSection::EX_IDX_BLOCK_NAME_PREFIX);
        //  let has_arm_ex_tab = Self::has_block_with_prefix(program, ARMExTabSection::EX_TAB_BLOCK_NAME_PREFIX);
        //
        //  has_arm_ex_idx || has_arm_ex_tab
    }

    /// Parses the standard GCC exception handling support sections:
    /// 1) EHFrameHeader (`.eh_frame_hdr`)
    /// 2) EHFrame (`.eh_frame`)
    ///
    /// Port of `handleStandardSections(Program, TaskMonitor, MessageLog)`.
    fn handle_standard_sections(
        &self,
        program: &mut dyn Program,
        monitor: &dyn TaskMonitor,
        log: &mut dyn MessageLog,
    ) -> Result<(), CancelledException> {
        let fde_table_count = Self::analyze_eh_frame_header_section(program, monitor, log);
        // If the EHFrameHeader doesn't exist, the fdeTableCount will be 0.

        monitor.check_cancelled()?;

        // If the .eh_frame section exists, build the structures contained within this program
        // section.
        let ehframe_section = EhFrameSection::new(monitor, program);
        let regions = match ehframe_section.analyze(fde_table_count) {
            Ok(regions) => regions,
            Err(e) => {
                log.append_msg("Error analyzing GCC exception tables");
                log.append_exception(&e);
                return Ok(());
            }
        };

        let mut eh_protected = AddressSet::new();
        monitor.initialize(Self::get_call_site_record_count(&regions) as i64);
        monitor.set_message("Marking up Call Site records");
        for region in &regions {
            if let Some(range) = region.get_range() {
                eh_protected.add_range_object(&range);
            }

            if let Some(call_site_table) = region.get_call_site_table() {
                // Process this table's call site records.
                for cs in call_site_table.get_call_site_records() {
                    monitor.increment_progress(1);
                    self.process_call_site_record(program, &mut eh_protected, region.as_ref(), cs);
                }
            }
        }

        Ok(())
    }

    /// Port of `getCallSiteRecordCount(List<RegionDescriptor>)`.
    fn get_call_site_record_count(regions: &[std::sync::Arc<dyn RegionDescriptor>]) -> usize {
        regions
            .iter()
            .filter_map(|region| region.get_call_site_table())
            .map(|table| table.get_call_site_records().len())
            .sum()
    }

    /// Port of
    /// `processCallSiteRecord(Program, AddressSet, RegionDescriptor, LSDACallSiteRecord)`.
    fn process_call_site_record(
        &self,
        program: &mut dyn Program,
        eh_protected: &mut AddressSet,
        region: &dyn RegionDescriptor,
        cs: &seam_stubs::LSDACallSiteRecord,
    ) {
        let call_site = cs.get_call_site().clone();
        eh_protected.add_range_object(&call_site);

        let cs_addr = call_site.min_address().clone();
        let lp_offset = cs.get_landing_pad_offset();

        if lp_offset == 0 {
            return;
        }

        let Some(lp_addr) = cs.get_landing_pad().cloned() else {
            return;
        };

        eh_protected.add_address(&lp_addr);

        let type_infos = Self::get_type_infos(region, cs);

        Self::disassemble_if_needed(program, &cs_addr);
        if self.create_try_catch_comments_enabled {
            Self::mark_start_of_try(program, &call_site, &lp_addr);
            Self::mark_end_of_try(program, &call_site);
        }

        Self::disassemble_if_needed(program, &lp_addr);
        if self.create_try_catch_comments_enabled {
            Self::mark_start_of_catch(program, &cs_addr, &lp_addr, &type_infos);
            Self::mark_end_of_catch(program, &call_site, &lp_addr);
        }
    }

    /// Port of `getTypeInfos(RegionDescriptor, LSDACallSiteRecord)`.
    fn get_type_infos(
        region: &dyn RegionDescriptor,
        cs: &seam_stubs::LSDACallSiteRecord,
    ) -> Vec<TypeInfo> {
        let mut type_infos = Vec::new();

        // Either table can be absent (Java: null).
        let (Some(action_table), Some(type_table)) =
            (region.get_action_table(), region.get_type_table())
        else {
            return type_infos; // No action records.
        };

        // If we have a valid offset then get that action record.
        let mut action = action_table.get_action_record_at_offset(cs.get_action_offset());

        while let Some(record) = action {
            let action_filter = record.get_action_type_filter();
            let type_info_address = type_table.get_type_info_address(action_filter);
            type_infos.push(TypeInfo { type_info_address, action_filter });

            action = record.get_next_action();
        }

        type_infos
    }

    /// Port of `shouldDisassemble()`.
    fn should_disassemble() -> bool {
        true
    }

    /// Port of `disassembleIfNeeded(Program, Address)`: `true` when this call disassembled the
    /// address, `false` when it was already code or could not be disassembled.
    fn disassemble_if_needed(program: &mut dyn Program, address: &Address) -> bool {
        if !Self::should_disassemble() {
            return false;
        }

        let already_code = program
            .get_listing()
            .and_then(|listing| listing.get_instruction_at(address))
            .is_some();

        // Java also asks the AutoAnalysisManager to protect this location from clearing; see the
        // module docs for why that call has no counterpart yet.

        if already_code {
            return false; // already disassembled
        }

        let cmd = disassemble_command::new(address.clone(), None, true);
        if !cmd.apply_to(program) || cmd.get_disassembled_address_set().is_empty() {
            let message = format!("Failed to disassemble at {address}");
            Msg::error(Self::NAME, &message);
            return false;
        }
        true
    }

    /// The `try {` comment `markStartOfTry` writes.
    fn start_of_try_comment(cs_min_addr: &Address, cs_max_addr: &Address, lp_addr: &Address) -> String {
        format!(
            "try {{ // try from {cs_min_addr} to {cs_max_addr} has its CatchHandler @ {lp_addr}"
        )
    }

    /// The `} // end try` comment `markEndOfTry` writes.
    fn end_of_try_comment(cs_min_addr: &Address, cs_max_addr: &Address) -> String {
        format!("}} // end try from {cs_min_addr} to {cs_max_addr}")
    }

    /// The `catch(...) { ... }` comment `markStartOfCatch` writes.
    fn start_of_catch_comment(type_string: &str, cs_addr: &Address, lp_addr: &Address) -> String {
        format!("catch({type_string}) {{ ... }} // from try @ {cs_addr} with catch @ {lp_addr}")
    }

    /// Port of `markStartOfTry(Program, AddressRange, Address)`.
    fn mark_start_of_try(program: &mut dyn Program, call_site: &AddressRange, lp_addr: &Address) {
        let cs_min_addr = call_site.min_address().clone();
        let cs_max_addr = call_site.max_address().clone();
        let start_try_comment = Self::start_of_try_comment(&cs_min_addr, &cs_max_addr, lp_addr);
        let existing_comment = program
            .get_listing()
            .and_then(|listing| listing.get_comment(CommentType::Pre, &cs_min_addr));
        Self::merge_comment_into(
            program,
            cs_min_addr,
            CommentType::Pre,
            existing_comment,
            &start_try_comment,
        );
    }

    /// Port of `markEndOfTry(Program, AddressRange)`.
    fn mark_end_of_try(program: &mut dyn Program, call_site: &AddressRange) {
        let cs_min_addr = call_site.min_address().clone();
        let cs_max_addr = call_site.max_address().clone();
        let comment_addr = program
            .get_listing()
            .and_then(|listing| listing.get_code_unit_containing(&cs_max_addr))
            .map(|code_unit| code_unit.get_min_address());
        let Some(comment_addr) = comment_addr else {
            return;
        };

        let end_try_comment = Self::end_of_try_comment(&cs_min_addr, &cs_max_addr);
        let existing_comment = program
            .get_listing()
            .and_then(|listing| listing.get_comment(CommentType::Post, &comment_addr));
        Self::merge_comment_into(
            program,
            comment_addr,
            CommentType::Post,
            existing_comment,
            &end_try_comment,
        );
    }

    /// Port of `markStartOfCatch(Program, Address, Address, List<TypeInfo>)`.
    fn mark_start_of_catch(
        program: &mut dyn Program,
        cs_addr: &Address,
        lp_addr: &Address,
        type_infos: &[TypeInfo],
    ) {
        let type_string = type_infos
            .iter()
            .map(Self::get_catch_param_info)
            .collect::<Vec<_>>()
            .join(", ");
        let start_catch_comment = Self::start_of_catch_comment(&type_string, cs_addr, lp_addr);
        let existing_comment = program
            .get_listing()
            .and_then(|listing| listing.get_comment(CommentType::Pre, lp_addr));
        Self::merge_comment_into(
            program,
            lp_addr.clone(),
            CommentType::Pre,
            existing_comment,
            &start_catch_comment,
        );
    }

    /// The "leave an existing comment alone if it already says this, otherwise merge" step the
    /// three `markStartOf`/`markEndOf` methods share verbatim in the Java.
    fn merge_comment_into(
        program: &mut dyn Program,
        address: Address,
        comment_type: CommentType,
        existing_comment: Option<String>,
        comment: &str,
    ) {
        let existing = existing_comment.unwrap_or_default();
        if existing.contains(comment) {
            return;
        }
        let merged_comment = existing.merge_strings(comment);
        SetCommentCmd::new(address, comment_type, merged_comment).apply_to(program);
    }

    /// Port of `getCatchParamInfo(TypeInfo)`.
    fn get_catch_param_info(a: &TypeInfo) -> String {
        let action_filter = a.action_filter;
        match &a.type_info_address {
            // Java's guard is `actionFilter == 0 || typeInfoAddress == Address.NO_ADDRESS`.
            Some(type_info_address) if action_filter != 0 => {
                format!("type#{action_filter} @ {type_info_address}")
            }
            _ => String::new(),
        }
    }

    /// Port of `markEndOfCatch(Program, AddressRange, Address)`.
    fn mark_end_of_catch(program: &mut dyn Program, call_site: &AddressRange, lp_addr: &Address) {
        let _ = (program, call_site, lp_addr);

        // TODO Need to figure out way to indicate this that won't get wiped out by other analysis.
        // *** The following is commented out until we figure out how to determine end of catch. ***
        //  // TODO If we can determine the length of the catch handler we could mark its end too.
        //  let lp_max_addr = ?;
        //  let end_catch_comment = "} // end catchHandler()";
        //  ... merge_comment_into(program, lp_max_addr, CommentType::Post, existing, end_catch_comment)
    }

    /// Port of `analyzeEhFrameHeaderSection(Program, TaskMonitor, MessageLog)`.
    fn analyze_eh_frame_header_section(
        program: &dyn Program,
        monitor: &dyn TaskMonitor,
        log: &mut dyn MessageLog,
    ) -> i32 {
        let ehframehdr_section = EhFrameHeaderSection::new(program);
        match ehframehdr_section.analyze(monitor) {
            Ok(fde_table_count) => fde_table_count,
            Err(e) => {
                log.append_msg("Error analyzing GCC EH Frame Header exception table");
                log.append_exception(&e);
                0
            }
        }
    }

    // Java's `handleArmSections(Program, TaskMonitor, MessageLog)` is commented out, along with
    // the `ARMExIdxSection`/`ARMExTabSection` analysis it ran; see `has_arm_section`.

    /// Port of `handleDebugFrameSection(Program, TaskMonitor, MessageLog)`.
    fn handle_debug_frame_section(
        program: &mut dyn Program,
        monitor: &dyn TaskMonitor,
        log: &mut dyn MessageLog,
    ) {
        let debug_frame_section = DebugFrameSection::new(monitor, program);
        if let Err(e) = debug_frame_section.analyze() {
            log.append_msg("Error analyzing GCC DebugFrame exception tables");
            log.append_exception(&e);
        }
    }
}

impl Default for GccExceptionAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for GccExceptionAnalyzer {
    fn get_name(&self) -> String {
        Self::NAME.to_string()
    }

    fn get_analysis_type(&self) -> AnalyzerType {
        AnalyzerType::ByteAnalyzer
    }

    /// `setDefaultEnablement(true)` in the Java constructor.
    fn get_default_enablement(&self, _program: &dyn Program) -> bool {
        true
    }

    /// `AbstractAnalyzer`'s default; this analyzer never calls `setSupportsOneTimeAnalysis`.
    fn supports_one_time_analysis(&self) -> bool {
        false
    }

    fn get_description(&self) -> String {
        Self::DESCRIPTION.to_string()
    }

    /// `setPriority(AnalysisPriority.FORMAT_ANALYSIS.after().after())` in the Java constructor.
    fn get_priority(&self) -> AnalysisPriority {
        AnalysisPriority::format_analysis().after().after()
    }

    fn can_analyze(&self, program: &dyn Program) -> bool {
        // Java reaches the ID through `program.getCompilerSpec().getCompilerSpecID()`; the ported
        // `Program` exposes it directly.
        let compiler_spec_id = program
            .get_compiler_spec_id()
            .map(|id| id.get_id_as_string().to_string())
            .unwrap_or_default();

        let is_gcc = compiler_spec_id.eq_ignore_ascii_case("gcc");
        let is_default = compiler_spec_id.eq_ignore_ascii_case("default");

        if !is_gcc && !is_default {
            return false;
        }

        let has_eh_frame_header =
            Self::has_block(program, EhFrameHeaderSection::EH_FRAME_HEADER_BLOCK_NAME);

        let has_eh_frame = Self::has_block(program, EhFrameSection::EH_FRAME_BLOCK_NAME);

        let has_debug_frame =
            Self::has_block_with_prefix(program, DebugFrameSection::DEBUG_FRAME_BLOCK_NAME);

        has_eh_frame || has_eh_frame_header || Self::has_arm_section(program) || has_debug_frame
    }

    fn added(
        &mut self,
        program: &mut dyn Program,
        _added_location_addresses: &dyn AddressSetView,
        monitor: &dyn TaskMonitor,
        log: &mut dyn MessageLog,
    ) -> Result<bool, CancelledException> {
        let program_key = Program::get_name(program);
        if self.visited_programs.contains(&program_key) {
            return Ok(true);
        }

        // Java registers `analysisListener` with this program's AutoAnalysisManager here; see the
        // module docs.

        monitor.set_message("Analyzing GCC exception-handling artifacts");
        monitor.set_indeterminate(true);
        monitor.set_show_progress_value(false);

        self.handle_standard_sections(program, monitor, log)?;

        Self::handle_debug_frame_section(program, monitor, log);

        // handle_arm_sections(program, monitor, log);

        self.visited_programs.insert(program_key);
        monitor.set_indeterminate(false);
        monitor.set_show_progress_value(true);

        Ok(true)
    }

    /// `AbstractAnalyzer.removed` returns false; this analyzer does not override it.
    fn removed(
        &mut self,
        _program: &mut dyn Program,
        _set: &dyn AddressSetView,
        _monitor: &dyn TaskMonitor,
        _log: &mut dyn MessageLog,
    ) -> Result<bool, CancelledException> {
        Ok(false)
    }

    fn register_options(&self, options: &mut dyn Options, _program: &dyn Program) {
        options.register_option(
            Self::OPTION_NAME_CREATE_TRY_CATCHS,
            Box::new(self.create_try_catch_comments_enabled),
            None,
            Self::OPTION_DESCRIPTION_CREATE_TRY_CATCHS,
        );
    }

    fn options_changed(&mut self, options: &dyn Options, _program: &dyn Program) {
        self.create_try_catch_comments_enabled = options.get_boolean(
            Self::OPTION_NAME_CREATE_TRY_CATCHS,
            self.create_try_catch_comments_enabled,
        );
    }

    /// `AbstractAnalyzer.analysisEnded` is a no-op; this analyzer does not override it. The
    /// per-session cleanup Java performs runs through
    /// [`AutoAnalysisManagerListener::analysis_ended`] instead.
    fn analysis_ended(&mut self, _program: &dyn Program) {}

    /// `AbstractAnalyzer`'s default; this analyzer never calls `setPrototype`.
    fn is_prototype(&self) -> bool {
        false
    }
}

/// Port of the `analysisListener` lambda
/// `(manager, isCancelled) -> visitedPrograms.remove(manager.getProgram())`, which lets a program
/// be marked up again after the analysis session that first visited it ends.
impl AutoAnalysisManagerListener<dyn AutoAnalysisManager> for GccExceptionAnalyzer {
    fn analysis_ended(&mut self, manager: &dyn AutoAnalysisManager, _is_cancelled: bool) {
        let program_key = Program::get_name(manager.get_program().as_ref());
        self.visited_programs.remove(&program_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::{
        FrameDescriptionEntry, LSDACallSiteRecord, LSDACallSiteTable, LSDATypeTable,
    };
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::CompilerSpecID;
    use crate::program::model::mem::{Memory, MemoryAccessException, MemoryBlock};
    use std::sync::Arc;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn ram_address(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    /// A memory block that only knows its own name -- all `can_analyze` ever asks of one.
    struct NamedBlock {
        name: String,
    }

    impl MemoryBlock for NamedBlock {
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_start(&self) -> Address {
            ram_address(0)
        }
        fn get_end(&self) -> Address {
            ram_address(0)
        }
        fn get_size(&self) -> u64 {
            0
        }
        fn is_initialized(&self) -> bool {
            true
        }
        fn get_byte(&self, _addr: &Address) -> Result<u8, MemoryAccessException> {
            Err(MemoryAccessException::new("no bytes"))
        }
        fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
            0
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Err(MemoryAccessException::new("read-only"))
        }
    }

    struct FakeMemory {
        blocks: Vec<Arc<dyn MemoryBlock>>,
    }

    impl Memory for FakeMemory {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_byte(&self, _addr: &Address) -> Result<u8, MemoryAccessException> {
            Err(MemoryAccessException::new("no bytes"))
        }
        fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
            0
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Err(MemoryAccessException::new("read-only"))
        }
        fn get_block_by_name(&self, name: &str) -> Option<Arc<dyn MemoryBlock>> {
            self.blocks.iter().find(|b| b.get_name() == name).cloned()
        }
        fn get_blocks(&self) -> Vec<Arc<dyn MemoryBlock>> {
            self.blocks.clone()
        }
    }

    struct MockProgram {
        compiler_spec_id: &'static str,
        memory: Arc<FakeMemory>,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "x86:LE:64:default".to_string()
        }
        fn get_compiler_spec_id(&self) -> Option<CompilerSpecID> {
            Some(CompilerSpecID::new(Some(self.compiler_spec_id)))
        }
        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            Some(self.memory.clone())
        }
    }

    fn program_with(compiler_spec_id: &'static str, block_names: &[&str]) -> MockProgram {
        let blocks = block_names
            .iter()
            .map(|name| -> Arc<dyn MemoryBlock> { Arc::new(NamedBlock { name: name.to_string() }) })
            .collect();
        MockProgram { compiler_spec_id, memory: Arc::new(FakeMemory { blocks }) }
    }

    /// A region whose LSDA tables are populated, so `get_type_infos` has something to walk.
    struct StubRegion {
        range: Option<AddressRange>,
        call_site_table: Option<Arc<LSDACallSiteTable>>,
        type_table: Option<Arc<LSDATypeTable>>,
    }

    impl RegionDescriptor for StubRegion {
        fn get_frame_descriptor_entry(&self) -> Arc<dyn FrameDescriptionEntry> {
            unimplemented!("not needed by these tests")
        }
        fn get_range(&self) -> Option<AddressRange> {
            self.range.clone()
        }
        fn get_call_site_table(&self) -> Option<Arc<LSDACallSiteTable>> {
            self.call_site_table.clone()
        }
        fn get_type_table(&self) -> Option<Arc<LSDATypeTable>> {
            self.type_table.clone()
        }
    }

    #[test]
    fn identity_matches_the_java_constants() {
        let analyzer = GccExceptionAnalyzer::new();

        assert_eq!(analyzer.get_name(), "GCC Exception Handlers");
        assert_eq!(
            analyzer.get_description(),
            "Locates and annotates exception-handling infrastructure installed by the GCC compiler"
        );
        assert_eq!(analyzer.get_analysis_type(), AnalyzerType::ByteAnalyzer);
        assert!(!analyzer.supports_one_time_analysis());
        assert!(!analyzer.is_prototype());
    }

    #[test]
    fn priority_is_two_steps_after_format_analysis() {
        // Java: AnalysisPriority.FORMAT_ANALYSIS.after().after()
        let expected = AnalysisPriority::format_analysis().priority() + 2;
        assert_eq!(GccExceptionAnalyzer::new().get_priority().priority(), expected);
    }

    #[test]
    fn can_analyze_requires_a_gcc_or_default_compiler_spec() {
        let analyzer = GccExceptionAnalyzer::new();

        // gcc / default with an exception-handling section: analyzable.
        assert!(analyzer.can_analyze(&program_with("gcc", &[".eh_frame"])));
        assert!(analyzer.can_analyze(&program_with("GCC", &[".eh_frame"])));
        assert!(analyzer.can_analyze(&program_with("default", &[".eh_frame"])));

        // Any other compiler spec: not analyzable, section or no section.
        assert!(!analyzer.can_analyze(&program_with("windows", &[".eh_frame"])));
        assert!(!analyzer.can_analyze(&program_with("borlandcpp", &[".eh_frame_hdr"])));
    }

    #[test]
    fn can_analyze_recognizes_each_exception_handling_section() {
        let analyzer = GccExceptionAnalyzer::new();

        assert!(analyzer.can_analyze(&program_with("gcc", &[".eh_frame"])));
        assert!(analyzer.can_analyze(&program_with("gcc", &[".eh_frame_hdr"])));
        // .debug_frame is matched by prefix, so a suffixed block counts too.
        assert!(analyzer.can_analyze(&program_with("gcc", &[".debug_frame"])));
        assert!(analyzer.can_analyze(&program_with("gcc", &[".debug_frame.dwo"])));

        // A gcc program with no exception-handling section at all: nothing to do.
        assert!(!analyzer.can_analyze(&program_with("gcc", &[".text", ".data"])));
        // ARM support is disabled in the Java, so its sections do not qualify a program.
        assert!(!analyzer.can_analyze(&program_with("gcc", &[".ARM.exidx", ".ARM.extab"])));
    }

    #[test]
    fn try_catch_comments_match_the_java_text() {
        let cs_min = ram_address(0x400100);
        let cs_max = ram_address(0x40011f);
        let lp = ram_address(0x400200);

        assert_eq!(
            GccExceptionAnalyzer::start_of_try_comment(&cs_min, &cs_max, &lp),
            format!("try {{ // try from {cs_min} to {cs_max} has its CatchHandler @ {lp}")
        );
        assert_eq!(
            GccExceptionAnalyzer::end_of_try_comment(&cs_min, &cs_max),
            "} // end try from ram:0x400100 to ram:0x40011f"
        );
        assert_eq!(
            GccExceptionAnalyzer::start_of_catch_comment("type#1 @ ram:0x400300", &cs_min, &lp),
            "catch(type#1 @ ram:0x400300) { ... } // from try @ ram:0x400100 with catch @ ram:0x400200"
        );
    }

    #[test]
    fn catch_param_info_is_empty_for_a_zero_filter_or_missing_type_address() {
        // A real type: "type#<filter> @ <address>".
        let typed = TypeInfo { type_info_address: Some(ram_address(0x400300)), action_filter: 2 };
        assert_eq!(
            GccExceptionAnalyzer::get_catch_param_info(&typed),
            "type#2 @ ram:0x400300"
        );

        // Filter 0 is the catch-all cleanup entry -- Java renders it as "".
        let cleanup = TypeInfo { type_info_address: Some(ram_address(0x400300)), action_filter: 0 };
        assert_eq!(GccExceptionAnalyzer::get_catch_param_info(&cleanup), "");

        // Address.NO_ADDRESS (here: None) also renders as "".
        let no_address = TypeInfo { type_info_address: None, action_filter: 2 };
        assert_eq!(GccExceptionAnalyzer::get_catch_param_info(&no_address), "");
    }

    #[test]
    fn call_site_record_count_sums_every_regions_table() {
        let call_site = AddressRange::new(ram_address(0x400100), ram_address(0x40011f));
        let record = || LSDACallSiteRecord::new(call_site.clone(), None, 0, 0);

        let two_records: Arc<dyn RegionDescriptor> = Arc::new(StubRegion {
            range: None,
            call_site_table: Some(Arc::new(LSDACallSiteTable::new(vec![record(), record()]))),
            type_table: None,
        });
        // Java's getCallSiteTable() can return null, which contributes nothing to the total.
        let no_table: Arc<dyn RegionDescriptor> =
            Arc::new(StubRegion { range: None, call_site_table: None, type_table: None });
        let one_record: Arc<dyn RegionDescriptor> = Arc::new(StubRegion {
            range: None,
            call_site_table: Some(Arc::new(LSDACallSiteTable::new(vec![record()]))),
            type_table: None,
        });

        assert_eq!(
            GccExceptionAnalyzer::get_call_site_record_count(&[two_records, no_table, one_record]),
            3
        );
    }

    #[test]
    fn type_infos_is_empty_without_both_an_action_and_a_type_table() {
        let call_site = AddressRange::new(ram_address(0x400100), ram_address(0x40011f));
        let cs = LSDACallSiteRecord::new(call_site, Some(ram_address(0x400200)), 0x100, 0);

        // Java returns an empty list when either table is null; only the type table is present
        // here, so there are no action records to walk.
        let region = StubRegion {
            range: None,
            call_site_table: None,
            type_table: Some(Arc::new(LSDATypeTable::new(vec![ram_address(0x400300)]))),
        };

        assert!(GccExceptionAnalyzer::get_type_infos(&region, &cs).is_empty());
    }

    #[test]
    fn type_table_lookup_is_one_based_with_no_address_outside_the_table() {
        // Mirrors LSDATypeTable.getTypeInfoAddress: index 0 and past-the-end are NO_ADDRESS.
        let table = LSDATypeTable::new(vec![ram_address(0x400300), ram_address(0x400308)]);

        assert_eq!(table.get_type_info_address(1), Some(ram_address(0x400300)));
        assert_eq!(table.get_type_info_address(2), Some(ram_address(0x400308)));
        assert_eq!(table.get_type_info_address(0), None);
        assert_eq!(table.get_type_info_address(3), None);
        assert_eq!(table.get_type_info_address(-1), None);
    }

    #[test]
    fn options_round_trip_the_try_catch_flag() {
        let mut analyzer = GccExceptionAnalyzer::new();
        // Java's OPTION_DEFAULT_CREATE_TRY_CATCHS_ENABLED.
        assert!(analyzer.create_try_catch_comments_enabled);

        struct OffOptions;
        impl Options for OffOptions {
            fn get_name(&self) -> String {
                "Analyzers".to_string()
            }
            fn get_boolean(&self, option_name: &str, default_value: bool) -> bool {
                if option_name == GccExceptionAnalyzer::OPTION_NAME_CREATE_TRY_CATCHS {
                    false
                } else {
                    default_value
                }
            }
        }

        let program = program_with("gcc", &[".eh_frame"]);
        analyzer.options_changed(&OffOptions, &program);
        assert!(!analyzer.create_try_catch_comments_enabled);

        // An options set that doesn't carry the option leaves the current value alone.
        struct EmptyOptions;
        impl Options for EmptyOptions {
            fn get_name(&self) -> String {
                "Analyzers".to_string()
            }
        }
        analyzer.options_changed(&EmptyOptions, &program);
        assert!(!analyzer.create_try_catch_comments_enabled);
    }
}
