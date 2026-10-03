//! The program edits the listing makes, behind a seam: the UI model speaks
//! offsets and snapshots; [`LiveProgram`] maps them onto `ProgramDB` and the
//! ported commands (`DisassembleCommand`, `CodeManager.clearCodeUnits`,
//! `RenameLabelCmd`).

use crate::code_unit_listing::InstructionSnapshot;
use crate::program_import::LiveProgram;

/// What a disassembly did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Disassembled {
    /// The disassembled ranges (inclusive), empty when nothing was.
    pub ranges: Vec<(u64, u64)>,
    /// The command's status message, if any.
    pub status: Option<String>,
}

/// A renamed symbol, as the program has it now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Renamed {
    /// Its address.
    pub address: u64,
    /// Its source, as Java displays it ("User Defined"; unchanged when the
    /// name was).
    pub source: String,
}

/// A program the listing can edit (addresses are offsets in the default space).
pub trait EditableProgram: Send + Sync {
    /// Whether an instruction contains `address`.
    fn instruction_containing(&self, address: u64) -> bool;
    /// Java `DisassembleCommand` following flows: from `start`, or from every
    /// undefined address in `ranges` when there are any.
    fn disassemble(&self, start: u64, ranges: &[(u64, u64)]) -> Disassembled;
    /// Clears the instructions intersecting each range; returns the cleared
    /// extents (widened to the instruction containing a range's start).
    fn clear_code(&self, ranges: &[(u64, u64)]) -> Vec<(u64, u64)>;
    /// The instructions starting in `lo..=hi`, as the listing shows them.
    fn instructions_in(&self, lo: u64, hi: u64) -> Vec<InstructionSnapshot>;
    /// Java `RenameLabelCmd` (USER_DEFINED) on symbol `id`.
    fn rename_symbol(&self, id: i64, name: &str) -> Result<Renamed, String>;
    /// The addresses whose references go to `address`.
    fn references_to(&self, address: u64) -> Vec<u64>;
}

impl LiveProgram {
    fn address(&self, offset: u64) -> ghidra_rs::program::model::address::Address {
        use ghidra_rs::program::model::lang::language::Language;
        ghidra_rs::program::model::address::Address::new(self.program().get_language().get_default_space(), offset as i64)
    }
}

impl EditableProgram for LiveProgram {
    fn instruction_containing(&self, address: u64) -> bool {
        let store = self.program().get_listing_store();
        let store = store.read().unwrap_or_else(std::sync::PoisonError::into_inner);
        store.instruction_containing(&self.address(address)).is_some()
    }

    fn disassemble(&self, start: u64, ranges: &[(u64, u64)]) -> Disassembled {
        use ghidra_rs::app::cmd::disassemble::disassemble_command::DisassembleCommand;
        use ghidra_rs::framework::cmd::background_command::BackgroundCommand;
        use ghidra_rs::program::model::address::AddressSet;
        use ghidra_rs::util::task::DummyMonitor;

        let mut cmd = if ranges.is_empty() {
            DisassembleCommand::new(self.address(start), None, true)
        } else {
            let mut set = AddressSet::new();
            for &(lo, hi) in ranges {
                set.add_range(&self.address(lo), &self.address(hi));
            }
            DisassembleCommand::with_start_set(set, None, true)
        };
        let applied = cmd.apply(self.program(), &DummyMonitor);
        let done: Vec<(u64, u64)> = cmd
            .get_disassembled_address_set()
            .to_list()
            .iter()
            .map(|r| (r.min_address().offset() as u64, r.max_address().offset() as u64))
            .collect();
        Disassembled { ranges: if applied { done } else { Vec::new() }, status: cmd.get_status_msg() }
    }

    fn clear_code(&self, ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
        let store = self.program().get_listing_store();
        let mut store = store.write().unwrap_or_else(std::sync::PoisonError::into_inner);
        ranges
            .iter()
            .filter_map(|&(lo, hi)| {
                let (start, end) = (self.address(lo), self.address(hi));
                // the extent actually holding instructions (the unit containing `lo` included)
                let first = store
                    .instruction_containing(&start)
                    .or_else(|| store.instruction_after(&start).filter(|&id| store.record(id).address() <= &end))?;
                let from = store.record(first).address().offset() as u64;
                store.clear_code_units(&start, &end);
                Some((from.min(lo), hi))
            })
            .collect()
    }

    fn instructions_in(&self, lo: u64, hi: u64) -> Vec<InstructionSnapshot> {
        crate::program_import::instructions_in(self.program(), &self.address(lo), &self.address(hi))
    }

    fn rename_symbol(&self, id: i64, name: &str) -> Result<Renamed, String> {
        use ghidra_rs::program::model::symbol::{SourceType, SymbolTable};
        let table = self.program().get_symbol_table();
        table
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .set_symbol_name(id, name, SourceType::UserDefined)
            .map_err(|e| e.to_string())?;
        // the program's source after the rename (an unchanged name keeps it)
        let symbol = table.read().unwrap_or_else(std::sync::PoisonError::into_inner).get_symbol(id).ok().flatten();
        let symbol = symbol.ok_or_else(|| format!("no symbol {id}"))?;
        Ok(Renamed { address: symbol.get_address().offset() as u64, source: symbol.get_source().display_string().to_owned() })
    }

    fn references_to(&self, address: u64) -> Vec<u64> {
        use ghidra_rs::program::model::symbol::reference::Reference;
        self.program().references_to(&self.address(address)).iter().map(|r| r.from_address().offset() as u64).collect()
    }
}
