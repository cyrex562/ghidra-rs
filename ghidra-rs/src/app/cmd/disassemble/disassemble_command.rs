//! Port of `ghidra.app.cmd.disassemble.DisassembleCommand`: disassemble from a start address or
//! set into a [`ProgramDB`]'s listing.
//!
//! # Deviations / not ported
//!
//! * The command applies to a [`ProgramDB`] (whose listing is a
//!   [`ListingStore`](crate::program::database::code::listing_store::ListingStore)), not any
//!   `Program`: the `Program` trait has no concrete listing to disassemble into.
//!   [`DisassembleCommand::apply`] takes `&ProgramDB` (the listing is lock-backed), and the
//!   [`BackgroundCommand`] impl delegates to it.
//! * Auto-analysis (`enableCodeAnalysis`, `AutoAnalysisManager.codeDefined` /
//!   `startAnalysis`) is not ported: `enable_code_analysis` is recorded but nothing is
//!   analyzed.
//! * The program's "Restrict Disassembly to Executable Memory" option is not stored on
//!   `ProgramDB`, so no executable-set restriction applies (Java's default when the option is
//!   off) and a non-executable start is never reported.
//! * `setSeedContext` is not ported. The disassembler's monitor is a dummy; the command's own
//!   monitor is checked for cancellation between flows (`Disassembler` takes an owned monitor
//!   handle, `applyTo` lends one).

use std::sync::Arc;

use crate::framework::cmd::background_command::{BackgroundCommand, BackgroundCommandBase};
use crate::program::database::mem::MemoryMapDB;
use crate::program::database::program_db::ProgramDB;
use crate::program::disassemble::Disassembler;
use crate::program::model::address::{Address, AddressSet, AddressSetView};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register_value::RegisterValue;
use crate::util::task::{DummyMonitor, TaskMonitor};

/// Command object for performing disassembly. Port of `DisassembleCommand`; see the module docs.
pub struct DisassembleCommand {
    base: BackgroundCommandBase,
    start_set: AddressSet,
    use_default_repeat_pattern_behavior: bool,
    restricted_set: Option<AddressSet>,
    disassembled_addrs: AddressSet,
    follow_flow: bool,
    enable_analysis: bool,
    initial_context_value: Option<RegisterValue>,
    /// Required instruction alignment for the last `do_disassembly`.
    alignment: i32,
    /// If true don't report start problems.
    disassembly_performed: bool,
    /// Non-`None` to indicate an unsupported language.
    language_error: Option<String>,
    unaligned_start: bool,
    non_executable_start: bool,
}

impl DisassembleCommand {
    /// Disassemble from `start`, restricted to `restricted_set` (`None`: no restriction),
    /// following flows if `follow_flow`. Port of `DisassembleCommand(Address, AddressSetView,
    /// boolean)`.
    pub fn new(start: Address, restricted_set: Option<AddressSet>, follow_flow: bool) -> Self {
        let mut cmd = Self::with_start_set(AddressSet::from_address(start), restricted_set, follow_flow);
        cmd.use_default_repeat_pattern_behavior = true;
        cmd
    }

    /// Disassemble from each address of `start_set`. Port of `DisassembleCommand(AddressSetView,
    /// AddressSetView, boolean)`.
    pub fn with_start_set(start_set: AddressSet, restricted_set: Option<AddressSet>, follow_flow: bool) -> Self {
        Self::named("Disassemble", start_set, restricted_set, follow_flow)
    }

    /// Port of the protected `DisassembleCommand(String, AddressSetView, AddressSetView,
    /// boolean)`.
    pub fn named(name: &str, start_set: AddressSet, restricted_set: Option<AddressSet>, follow_flow: bool) -> Self {
        DisassembleCommand {
            base: BackgroundCommandBase::new(name, true, true, false),
            start_set,
            use_default_repeat_pattern_behavior: false,
            restricted_set,
            disassembled_addrs: AddressSet::new(),
            follow_flow,
            enable_analysis: true,
            initial_context_value: None,
            alignment: 1,
            disassembly_performed: false,
            language_error: None,
            unaligned_start: false,
            non_executable_start: false,
        }
    }

    /// Sets the initial context value for the start of each flow; any sub-register value is
    /// widened to its base register. Port of `setInitialContext(RegisterValue)`.
    pub fn set_initial_context(&mut self, initial_context_value: Option<RegisterValue>) {
        self.initial_context_value = initial_context_value.map(|value| {
            let base = value.register().get_base_register();
            value.get_register_value(&base)
        });
    }

    /// Port of `enableCodeAnalysis(boolean)` (recorded only; see the module docs).
    pub fn enable_code_analysis(&mut self, enable: bool) {
        self.enable_analysis = enable;
    }

    /// The addresses disassembled by the last application. Port of `getDisassembledAddressSet()`.
    pub fn get_disassembled_address_set(&self) -> &AddressSet {
        &self.disassembled_addrs
    }

    /// Port of `applyTo(Program, TaskMonitor)` for a [`ProgramDB`].
    pub fn apply(&mut self, program: &ProgramDB, monitor: &dyn TaskMonitor) -> bool {
        let alignment = program.get_language().get_instruction_alignment();
        self.do_disassembly(monitor, program, alignment)
    }

    /// Port of the protected `doDisassembly(TaskMonitor, Program, int)`.
    fn do_disassembly(&mut self, monitor: &dyn TaskMonitor, program: &ProgramDB, instruction_alignment: i32) -> bool {
        self.alignment = instruction_alignment;
        self.disassembly_performed = false;
        self.unaligned_start = false;
        self.non_executable_start = false;
        self.disassembled_addrs = AddressSet::new();

        let mut disassembler = Disassembler::get_program_disassembler(program, Arc::new(DummyMonitor), None);

        if self.start_set.is_empty() {
            return true;
        }
        if !self.use_default_repeat_pattern_behavior {
            if self.restricted_set.as_ref() != Some(&self.start_set) {
                disassembler.set_repeat_pattern_limit_ignored(Some(Box::new(self.start_set.clone())));
            } else {
                // If disassembling an exactly specified set, don't truncate zero runs
                disassembler.set_repeat_pattern_limit(-1);
            }
        }

        let alignment = i64::from(self.alignment.max(1));
        let mut seed_set = AddressSet::new();

        // Small ranges are gathered into the seed set; a large range is disassembled flow by
        // flow (Java starts analysis between those flows).
        for range in self.start_set.to_list() {
            if monitor.is_cancelled() {
                break;
            }
            let mut sub_range_set = AddressSet::from_range(range);
            while !sub_range_set.is_empty() && !monitor.is_cancelled() {
                let Some(mut next_addr) = sub_range_set.min_address() else {
                    break;
                };

                // Check if location is already on disassembly list
                if let Some(done_range) = self.disassembled_addrs.range_containing(&next_addr) {
                    sub_range_set.delete_range_object(&done_range);
                    continue;
                }

                sub_range_set.delete_range(&next_addr, &next_addr);

                // only try disassembly on aligned boundaries
                let misalignment = next_addr.offset() % alignment;
                if misalignment != 0 {
                    next_addr = next_addr.subtract_wrap(misalignment);
                }

                // if range is small, just add it to the seed set
                if sub_range_set.num_addresses() <= 4 {
                    seed_set.add_address(&next_addr);
                    continue;
                }

                // location to disassemble is not undefined
                if !Self::is_undefined_at(program, &next_addr) {
                    let listing = program.get_listing_store();
                    let listing = listing.read().unwrap_or_else(|p| p.into_inner());
                    let memory = program.get_memory();
                    let memory = memory.read().unwrap_or_else(|p| p.into_inner());
                    sub_range_set = listing.undefined_ranges(&*memory, &sub_range_set);
                    continue;
                }

                // disassemble the seed set first, then the current start of the range
                self.do_disassembly_seeds(&mut disassembler, program, &seed_set);
                seed_set = AddressSet::new();
                let local = self.do_disassembly_seeds(&mut disassembler, program, &AddressSet::from_address(next_addr));
                sub_range_set.delete_set(&local);
            }
        }

        // If there are any small seed ranges left, disassemble them
        if !seed_set.is_empty() {
            self.do_disassembly_seeds(&mut disassembler, program, &seed_set);
        }

        self.disassembly_performed || (!self.non_executable_start && !self.unaligned_start)
    }

    /// Java's `listing.getUndefinedDataAt(addr) != null`: initialized memory no code unit covers.
    fn is_undefined_at(program: &ProgramDB, addr: &Address) -> bool {
        let listing = program.get_listing_store();
        let listing = listing.read().unwrap_or_else(|p| p.into_inner());
        let memory = program.get_memory();
        let memory = memory.read().unwrap_or_else(|p| p.into_inner());
        listing.instruction_containing(addr).is_none()
            && crate::program::model::mem::Memory::get_all_initialized_address_set(&*memory).contains(addr)
    }

    /// Port of the protected `doDisassemblySeeds(Disassembler, AddressSet, AutoAnalysisManager)`.
    fn do_disassembly_seeds(&mut self, disassembler: &mut Disassembler, program: &ProgramDB, seed_set: &AddressSet) -> AddressSet {
        let listing = program.get_listing_store();
        let mut listing = listing.write().unwrap_or_else(|p| p.into_inner());
        let memory = MemoryMapDB::as_memory(&program.get_memory());
        let result = disassembler.disassemble_set_into(
            &mut listing,
            memory,
            seed_set,
            self.restricted_set.as_ref().map(|s| s as &dyn AddressSetView),
            self.initial_context_value.as_ref(),
            self.follow_flow,
        );
        if !result.disassembled.is_empty() {
            self.disassembly_performed = true;
            self.disassembled_addrs.add_set(&result.disassembled);
        }
        result.disassembled
    }
}

impl BackgroundCommand<ProgramDB> for DisassembleCommand {
    fn base(&self) -> &BackgroundCommandBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut BackgroundCommandBase {
        &mut self.base
    }

    fn apply_to(&mut self, obj: &mut ProgramDB, monitor: &dyn TaskMonitor) -> bool {
        self.apply(obj, monitor)
    }

    /// Port of `getStatusMsg()`: why nothing was disassembled, or `None` if something was.
    fn get_status_msg(&self) -> Option<String> {
        if self.disassembly_performed {
            return None;
        }
        if let Some(error) = &self.language_error {
            return Some(format!("The program's language is not supported: {error}"));
        }
        if self.non_executable_start {
            return Some("Disassembly of non-executable memory is disabled".to_string());
        }
        if self.unaligned_start {
            return Some(format!(
                "Disassembler requires a start which is {}-byte aligned and on an undefined code unit",
                self.alignment
            ));
        }
        Some("Disassembler requires a start which is an undefined code unit".to_string())
    }
}

#[cfg(test)]
mod tests;
