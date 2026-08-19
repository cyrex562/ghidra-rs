//! Port of `ghidra.app.util.bin.format.macho.relocation.MachoRelocation`.
//!
//! A representation of a single Mach-O relocation that a `MachoRelocationHandler` (not yet
//! ported) will use to perform the relocation. In Mach-O, some relocations may be "paired," so
//! an instance of this type may carry two [`RelocationInfo`]s.
//!
//! `MachHeader`, `RelocationInfo`, `Section`, `NList`, and `SymbolTableCommand` are concrete Java
//! classes on the far side of a dependency cycle and are not ported yet; this file uses the
//! minimal placeholders in [`crate::format::seam_stubs`] (only the members this type needs).
//!
//! Java's constructor calls `program.getSymbolTable()` (a mutable accessor on the ported
//! [`Program`] trait) while resolving the initial target, then keeps `program` around for
//! [`MachoRelocation::get_program`]. This port borrows `program`/`macho_header` for the
//! relocation's lifetime (`'p`) rather than introducing shared-mutability wrappers neither the
//! Java source nor any caller in this crate needs yet.

use std::sync::Arc;

use crate::format::relocation_exception::RelocationError;
use crate::format::seam_stubs::{
    numeric_utilities, MachHeader, RelocationInfo, Section, SymbolTableCommand,
};
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::listing::program::Program;
use crate::program::model::symbol::{DefaultSymbolUtilities, Symbol, SymbolUtilities};

/// A single (optionally paired) Mach-O relocation.
///
/// Java: `MachoRelocation`.
pub struct MachoRelocation<'p> {
    program: &'p mut dyn Program,
    space: Arc<AddressSpace>,
    macho_header: &'p dyn MachHeader,

    relocation_address: Address,
    relocation_info: RelocationInfo,
    target_symbol: Option<Arc<dyn Symbol>>,
    target_section: Option<Section>,
    target_pointer: Option<Address>,

    relocation_info_extra: Option<RelocationInfo>,
    target_symbol_extra: Option<Arc<dyn Symbol>>,
    target_section_extra: Option<Section>,
    target_pointer_extra: Option<Address>,
}

impl<'p> MachoRelocation<'p> {
    /// Creates a new unpaired [`MachoRelocation`].
    ///
    /// Java: `MachoRelocation(Program, MachHeader, Address, RelocationInfo)`.
    pub fn new(
        program: &'p mut dyn Program,
        macho_header: &'p dyn MachHeader,
        relocation_address: Address,
        relocation_info: RelocationInfo,
    ) -> Self {
        let space = program
            .get_address_factory()
            .and_then(|factory| factory.get_default_address_space())
            .expect("program has no default address space");

        let (target_pointer, target_symbol, target_section) =
            Self::resolve_target(macho_header, &mut *program, &space, &relocation_info);

        MachoRelocation {
            program,
            space,
            macho_header,
            relocation_address,
            relocation_info,
            target_symbol,
            target_section,
            target_pointer,
            relocation_info_extra: None,
            target_symbol_extra: None,
            target_section_extra: None,
            target_pointer_extra: None,
        }
    }

    /// Creates a new paired [`MachoRelocation`].
    ///
    /// Java: `MachoRelocation(Program, MachHeader, Address, RelocationInfo, RelocationInfo)`.
    pub fn new_paired(
        program: &'p mut dyn Program,
        macho_header: &'p dyn MachHeader,
        relocation_address: Address,
        relocation_info: RelocationInfo,
        relocation_info_extra: RelocationInfo,
    ) -> Self {
        let mut relocation = Self::new(program, macho_header, relocation_address, relocation_info);

        let (target_pointer_extra, target_symbol_extra, target_section_extra) = Self::resolve_target(
            relocation.macho_header,
            &mut *relocation.program,
            &relocation.space,
            &relocation_info_extra,
        );

        relocation.relocation_info_extra = Some(relocation_info_extra);
        relocation.target_pointer_extra = target_pointer_extra;
        relocation.target_symbol_extra = target_symbol_extra;
        relocation.target_section_extra = target_section_extra;
        relocation
    }

    /// Gets the [`Program`] associated with this relocation.
    ///
    /// Java: `getProgram()`.
    pub fn get_program(&self) -> &dyn Program {
        &*self.program
    }

    /// Gets the [`Address`] the relocation takes place at.
    ///
    /// Java: `getRelocationAddress()`.
    pub fn get_relocation_address(&self) -> Address {
        self.relocation_address.clone()
    }

    /// Gets the lower-level [`RelocationInfo`] that describes the relocation.
    ///
    /// Java: `getRelocationInfo()`.
    pub fn get_relocation_info(&self) -> RelocationInfo {
        self.relocation_info
    }

    /// Gets the lower-level [`RelocationInfo`] that describes the second part of the paired
    /// relocation. `None` if the relocation is not paired.
    ///
    /// Java: `getRelocationInfoExtra()`.
    pub fn get_relocation_info_extra(&self) -> Option<RelocationInfo> {
        self.relocation_info_extra
    }

    /// Gets the [`Address`] of the relocation target.
    ///
    /// Java: `getTargetAddress()`.
    ///
    /// # Errors
    /// Returns [`RelocationError`] if the target address could not be found.
    pub fn get_target_address(&self) -> Result<Address, RelocationError> {
        if let Some(symbol) = &self.target_symbol {
            return Ok(symbol.get_address());
        }
        if let Some(section) = &self.target_section {
            return Ok(self.space.address(section.get_address()));
        }
        if let Some(pointer) = &self.target_pointer {
            return Ok(pointer.clone());
        }
        Err(RelocationError::new("Relocation target not found"))
    }

    /// Gets the [`Address`] of the extra relocation target.
    ///
    /// Java: `getTargetAddressExtra()`.
    ///
    /// # Errors
    /// Returns [`RelocationError`] if the extra target address could not be found (or if there
    /// wasn't an extra relocation target).
    pub fn get_target_address_extra(&self) -> Result<Address, RelocationError> {
        if let Some(symbol) = &self.target_symbol_extra {
            return Ok(symbol.get_address());
        }
        if let Some(section) = &self.target_section_extra {
            return Ok(self.space.address(section.get_address()));
        }
        if let Some(pointer) = &self.target_pointer_extra {
            return Ok(pointer.clone());
        }
        Err(RelocationError::new("Extra relocation target not found"))
    }

    /// Checks to see if this relocation requires work to be done on it. Since the Mach-O loader
    /// does not allow non-default image bases, it is unnecessary to perform relocations under
    /// certain conditions.
    ///
    /// Java: `requiresRelocation()`.
    pub fn requires_relocation(&self) -> bool {
        let mut requires = self.relocation_info.is_external() && !self.relocation_info.is_scattered();
        if let Some(extra) = &self.relocation_info_extra {
            requires = requires || (extra.is_external() && !extra.is_scattered());
        }
        requires
    }

    /// Gets a short description of the target of the relocation.
    ///
    /// Java: `getTargetDescription()`.
    pub fn get_target_description(&self) -> String {
        let mut description = Self::describe_target(
            &self.target_pointer,
            &self.target_symbol,
            &self.target_section,
            &self.relocation_info,
        );

        if let Some(extra) = &self.relocation_info_extra {
            description.push_str(" / ");
            description.push_str(&Self::describe_target(
                &self.target_pointer_extra,
                &self.target_symbol_extra,
                &self.target_section_extra,
                extra,
            ));
        }

        description
    }

    fn describe_target(
        target_pointer: &Option<Address>,
        target_symbol: &Option<Arc<dyn Symbol>>,
        target_section: &Option<Section>,
        relocation_info: &RelocationInfo,
    ) -> String {
        if let Some(pointer) = target_pointer {
            pointer.to_string()
        } else if let Some(symbol) = target_symbol {
            symbol.get_name().to_string()
        } else if let Some(section) = target_section {
            section.get_section_name().to_string()
        } else {
            numeric_utilities::to_hex_string(relocation_info.get_value() as i64)
        }
    }

    /// Attempts to resolve the relocation target for `relocation_info`: a scattered relocation
    /// resolves to a pointer address, an external relocation resolves to a target symbol,
    /// otherwise it resolves to a target section.
    ///
    /// Java: the `if (relocationInfo.isScattered()) ... else if (relocationInfo.isExternal())
    /// ... else ...` chain in both constructors.
    fn resolve_target(
        macho_header: &dyn MachHeader,
        program: &mut dyn Program,
        space: &Arc<AddressSpace>,
        relocation_info: &RelocationInfo,
    ) -> (Option<Address>, Option<Arc<dyn Symbol>>, Option<Section>) {
        if relocation_info.is_scattered() {
            (Some(space.address(relocation_info.get_value() as i64)), None, None)
        } else if relocation_info.is_external() {
            (None, Self::find_target_symbol(macho_header, program, space, relocation_info), None)
        } else {
            (None, None, Self::find_target_section(macho_header, relocation_info))
        }
    }

    /// Attempts to find the target [`Symbol`] associated with the given lower-level
    /// [`RelocationInfo`]. Only useful when `relocation_info` is marked as "external".
    ///
    /// Java: `findTargetSymbol(RelocationInfo)`.
    fn find_target_symbol(
        macho_header: &dyn MachHeader,
        program: &mut dyn Program,
        space: &Arc<AddressSpace>,
        relocation_info: &RelocationInfo,
    ) -> Option<Arc<dyn Symbol>> {
        let symbol_table_command: SymbolTableCommand = macho_header.get_symbol_table_command()?;
        let nlist = symbol_table_command.get_symbol_at(relocation_info.get_value())?.clone();
        let addr = space.address(nlist.get_value());

        let clean_name = DefaultSymbolUtilities.replace_invalid_chars(Some(nlist.get_string()), true);
        if let Some(name) = clean_name.as_deref() {
            if let Some(symbol_table) = program.get_symbol_table() {
                if let Ok(Some(symbol)) = symbol_table.get_global_symbol(name, &addr) {
                    return Some(symbol);
                }
            }
        }

        DefaultSymbolUtilities.get_label_or_function_symbol(program, nlist.get_string(), &mut |_| {
            // no logging
        })
    }

    /// Attempts to find the target [`Section`] associated with the given lower-level
    /// [`RelocationInfo`]. Only useful when `relocation_info` is NOT marked as "external".
    ///
    /// Java: `findTargetSection(RelocationInfo)`.
    fn find_target_section(macho_header: &dyn MachHeader, relocation_info: &RelocationInfo) -> Option<Section> {
        let index = relocation_info.get_value() - 1;
        if index < 0 {
            return None;
        }
        macho_header.get_all_sections().into_iter().nth(index as usize)
    }
}

impl<'p> std::fmt::Display for MachoRelocation<'p> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let symbol_name =
            self.target_symbol.as_ref().map(|s| s.get_name().to_string()).unwrap_or_else(|| "null".to_string());
        let section_name = self
            .target_section
            .as_ref()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "null".to_string());
        writeln!(f, "Symbol: {symbol_name}, Section: {section_name}")?;
        writeln!(f, "{}", self.relocation_info)?;

        if let Some(extra) = &self.relocation_info_extra {
            let symbol_name_extra = self
                .target_symbol_extra
                .as_ref()
                .map(|s| s.get_name().to_string())
                .unwrap_or_else(|| "null".to_string());
            let section_name_extra = self
                .target_section_extra
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "null".to_string());
            writeln!(f, "Symbol: {symbol_name_extra}, Section: {section_name_extra}")?;
            write!(f, "{extra}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::factory::{AddressFactory, DefaultAddressFactory};
    use crate::program::model::address::AddressSpaceType;
    use crate::program::model::listing::Listing;

    struct StubMachHeader {
        sections: Vec<Section>,
        symbol_table_command: Option<SymbolTableCommand>,
    }

    impl MachHeader for StubMachHeader {
        fn get_segment(&self, _segment_name: &str) -> Option<Box<dyn crate::format::seam_stubs::SegmentCommand>> {
            None
        }
        fn get_all_segments(&self) -> Vec<Box<dyn crate::format::seam_stubs::SegmentCommand>> {
            Vec::new()
        }
        fn get_all_sections(&self) -> Vec<Section> {
            self.sections.clone()
        }
        fn get_symbol_table_command(&self) -> Option<SymbolTableCommand> {
            self.symbol_table_command.clone()
        }
    }

    struct StubProgram {
        address_factory: Arc<DefaultAddressFactory>,
    }

    impl DomainObject for StubProgram {}

    impl Program for StubProgram {
        fn get_name(&self) -> String {
            "stub".to_string()
        }

        fn get_language_id(&self) -> String {
            "stub:LE:64:default".to_string()
        }

        fn get_listing(&mut self) -> Option<&mut dyn Listing> {
            None
        }

        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            Some(self.address_factory.clone())
        }
    }

    fn make_program() -> StubProgram {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        StubProgram { address_factory: Arc::new(DefaultAddressFactory::new(vec![space])) }
    }

    #[test]
    fn scattered_relocation_resolves_to_pointer_target() {
        let mut program = make_program();
        let header = StubMachHeader { sections: Vec::new(), symbol_table_command: None };
        let info = RelocationInfo::new(0x1000, false, true);
        let space = program.get_address_factory().unwrap().get_default_address_space().unwrap();
        let addr = space.address(0x2000);

        let relocation = MachoRelocation::new(&mut program, &header, addr, info);

        assert_eq!(relocation.get_target_address().unwrap(), space.address(0x1000));
        assert!(!relocation.requires_relocation());
    }

    #[test]
    fn non_external_relocation_resolves_to_target_section() {
        let mut program = make_program();
        let sections = vec![Section::new(0x4000, "__text"), Section::new(0x5000, "__data")];
        let header = StubMachHeader { sections, symbol_table_command: None };
        // value=2 -> index 1 -> the second section ("__data").
        let info = RelocationInfo::new(2, false, false);
        let space = program.get_address_factory().unwrap().get_default_address_space().unwrap();
        let addr = space.address(0x2000);

        let relocation = MachoRelocation::new(&mut program, &header, addr, info);

        assert_eq!(relocation.get_target_address().unwrap(), space.address(0x5000));
        assert_eq!(relocation.get_target_description(), "__data");
        assert!(!relocation.requires_relocation());
    }

    #[test]
    fn external_relocation_with_no_symbol_table_has_no_target_and_requires_relocation() {
        let mut program = make_program();
        let header = StubMachHeader { sections: Vec::new(), symbol_table_command: None };
        let info = RelocationInfo::new(7, true, false);

        let space = program.get_address_factory().unwrap().get_default_address_space().unwrap();
        let addr = space.address(0x2000);

        let relocation = MachoRelocation::new(&mut program, &header, addr, info);

        assert!(relocation.get_target_address().is_err());
        assert!(relocation.requires_relocation());
        assert_eq!(relocation.get_target_description(), "0x7");
    }

    #[test]
    fn paired_relocation_tracks_both_infos() {
        let mut program = make_program();
        let sections = vec![Section::new(0x4000, "__text")];
        let header = StubMachHeader { sections, symbol_table_command: None };
        let info = RelocationInfo::new(1, false, false);
        // value=0x99 -> index 0x98, out of range for a single-section header, so this resolves
        // to no target section (mirrors Java's findTargetSection returning null).
        let info_extra = RelocationInfo::new(0x99, false, false);
        let space = program.get_address_factory().unwrap().get_default_address_space().unwrap();
        let addr = space.address(0x2000);

        let relocation = MachoRelocation::new_paired(&mut program, &header, addr, info, info_extra);

        assert_eq!(relocation.get_relocation_info_extra(), Some(info_extra));
        assert_eq!(relocation.get_target_address().unwrap(), space.address(0x4000));
        assert!(relocation.get_target_address_extra().is_err());
        assert_eq!(relocation.get_target_description(), "__text / 0x99");
    }
}
