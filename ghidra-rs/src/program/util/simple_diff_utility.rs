//! Port of `ghidra.program.util.SimpleDiffUtility`.
//!
//! `SimpleDiffUtility` was selected as a dependency-cycle cut-point, so its public API is ported
//! as the [`SimpleDiffUtility`] trait rather than a plain struct with an `impl` block: callers can
//! depend on `Box<dyn SimpleDiffUtility>`/`Arc<dyn SimpleDiffUtility>` instead of importing a
//! concrete implementation directly.
//!
//! Unlike the Java class -- whose static methods derive their "owning" `Program` implicitly via
//! `Instruction.getProgram()`/`Symbol.getProgram()` -- every method here takes the originating
//! `Program` as an explicit leading parameter. Those Java accessors are ported here as
//! `Arc<dyn Program>`-returning getters (shared, read-only handles), which cannot yield the
//! `&mut dyn Program` these methods need to reach mutable managers (`SymbolTable`,
//! `ExternalManager`, `ReferenceManager`, `Listing`); passing `program` explicitly sidesteps that
//! seam mismatch entirely (the same adaptation `InstructionUtils` made for
//! `Instruction.getProgram().getProgramContext()`). For the same reason,
//! [`get_start_of_delay_slots`](SimpleDiffUtility::get_start_of_delay_slots),
//! [`get_end_of_delay_slots`](SimpleDiffUtility::get_end_of_delay_slots), and
//! [`expand_address_set_to_include_full_delay_slots`](SimpleDiffUtility::expand_address_set_to_include_full_delay_slots)
//! take the `Listing` directly rather than deriving it from `Instruction.getProgram().getListing()`
//! / `Program.getListing()`.
//!
//! A handful of private/protected Java helpers (`getVariableSymbol(Symbol, Program, Namespace)`,
//! `getOverlappingVariable`, `getOtherFunctionSymbol`, `getOtherCodeSymbol`,
//! `getOtherExternalLocationSymbol`) are kept as additional default-provided trait methods
//! (rather than free functions) purely so their default bodies can call back into other
//! `SimpleDiffUtility` methods through dynamic dispatch; they are not part of Java's public
//! static API. The protected `getVariableSymbol(Symbol, Function)` overload is not ported: it has
//! no caller within `SimpleDiffUtility.java` itself, so it carries no dynamic-dispatch obligation
//! for this cut-point.
//!
//! Several further adaptations, each noted at its call site below:
//! - [`get_compatible_address_space`](SimpleDiffUtility::get_compatible_address_space) drops the
//!   Java method's overlay-space check (`isOverlaySpace()`/base-space-ID comparison): this port's
//!   [`AddressSpace`] does not carry overlay membership, so only space name and
//!   [`AddressSpaceType`] are compared.
//! - `VariableStorage.isBadStorage()` has no port; `!storage.is_valid()` is used instead (see
//!   [`VariableStorage::is_valid`](crate::program::seam_stubs::VariableStorage::is_valid)).
//! - [`get_matching_external_symbol`](SimpleDiffUtility::get_matching_external_symbol) does not
//!   port the `allowInferredMatch` reference-correlation branch (which walks
//!   `ReferenceManager.getReferencesTo`/thunk addresses to infer a match when no name match is
//!   found): the flag is accepted for signature fidelity but currently has no effect, so name-based
//!   and brute-force address/name matching are always used. This is exactly the behavior Java
//!   itself falls back to when `allowInferredMatch` is `false`.
//! - Java's `ExternalReferenceCount.compareTo` breaks final ties with `Symbol.getName(true)`
//!   (fully-qualified name); this port's [`Symbol`] trait has no fully-qualified-name accessor, so
//!   [`Symbol::get_name`] is used instead.
//! - Several Java `SymbolTable` overloads (`getLibrarySymbol`, `getClassSymbol`,
//!   `getNamespaceSymbol`) are unified into
//!   [`SymbolTable::find_symbol_by_name_namespace`](crate::program::model::symbol::SymbolTable::find_symbol_by_name_namespace),
//!   since this port's `SymbolTable` does not distinguish namespace kinds at the query layer.

use std::collections::HashSet;
use std::sync::Arc;

use crate::program::model::address::{Address, AddressSet, AddressSetView, AddressSpace};
use crate::program::model::listing::{
    Instruction, Listing, Program, UNKNOWN_LIBRARY_NAME,
};
use crate::program::model::pcode::Varnode;
use crate::program::model::symbol::{ExternalLocation, Namespace, SourceType, Symbol, SymbolTable, SymbolType};
use crate::program::seam_stubs::VariableStorage;

/// Port of `ghidra.program.util.SimpleDiffUtility`. See the module docs for the adaptations made
/// while porting this static utility class to a trait.
pub trait SimpleDiffUtility: Send + Sync {
    /// Convert a variable storage object from `program` to a comparable variable storage object
    /// in `other_program`. Certain variable storage (UNIQUE/HASH-based) will always produce the
    /// same storage back unchanged.
    ///
    /// Port of `SimpleDiffUtility.getCompatibleVariableStorage(Program, VariableStorage, Program)`.
    fn get_compatible_variable_storage(
        &self,
        program: &mut dyn Program,
        storage: Option<Arc<dyn VariableStorage>>,
        other_program: &mut dyn Program,
    ) -> Option<Arc<dyn VariableStorage>> {
        let storage = storage?;
        if storage.size() == 0 || storage.is_hash_storage() {
            return Some(storage);
        }
        let mut translated = Vec::with_capacity(storage.get_varnodes().len());
        for vn in storage.get_varnodes() {
            let compatible = self.get_compatible_varnode(program, Some(&vn), other_program)?;
            translated.push(compatible);
        }
        Some(Arc::from(storage.with_varnodes(translated)))
    }

    /// Convert a varnode from `program` to a comparable varnode in `other_program`. Certain
    /// varnode address spaces (UNIQUE, HASH) will always produce the same varnode back unchanged.
    ///
    /// Port of `SimpleDiffUtility.getCompatibleVarnode(Program, Varnode, Program)`.
    fn get_compatible_varnode(
        &self,
        program: &mut dyn Program,
        varnode: Option<&Varnode>,
        other_program: &mut dyn Program,
    ) -> Option<Varnode> {
        let varnode = varnode?;
        if varnode.is_constant() {
            return Some(varnode.clone());
        }
        let addr = varnode.get_address();
        if addr.is_register_address() {
            if program.get_language_id() == other_program.get_language_id() {
                return Some(varnode.clone());
            }
            // Java looks up the register at `addr` sized to `varnode.getSize()`; this port's
            // `Program::get_register_at` has no size parameter, so the size is not matched.
            let reg = program.get_register_at(addr)?;
            let reg = reg.borrow();
            let other_reg = other_program.get_register(reg.name())?;
            let other_reg = other_reg.borrow();
            if reg.minimum_byte_size() != other_reg.minimum_byte_size() {
                return None;
            }
            let delta = addr.subtract(reg.address());
            let other_addr = if delta != 0 {
                other_reg
                    .address()
                    .add(delta)
                    .expect("register address overflow translating varnode")
            } else {
                other_reg.address().clone()
            };
            return Some(Varnode::new(other_addr, varnode.get_size()));
        }
        if addr.is_memory_address() || addr.is_stack_address() {
            if let Some(other_addr) = self.get_compatible_address(program, addr, other_program) {
                return Some(Varnode::new(other_addr, varnode.get_size()));
            }
        }
        None
    }

    /// If `instr` is contained within a delay slot the minimum address of the primary
    /// instruction will be returned. If not in a delay slot, `instr`'s minimum address is
    /// returned.
    ///
    /// Port of `SimpleDiffUtility.getStartOfDelaySlots(Instruction)`, adapted to take `listing`
    /// explicitly (see the module docs).
    fn get_start_of_delay_slots(&self, listing: &dyn Listing, instr: &dyn Instruction) -> Address {
        let mut min_addr = instr.get_min_address();
        if !instr.is_in_delay_slot() {
            return min_addr;
        }
        let lookup = match min_addr.subtract_no_wrap(1) {
            Ok(a) => a,
            Err(_) => return min_addr,
        };
        let mut prev_instr = listing.get_instruction_containing(&lookup);
        loop {
            let Some(p) = prev_instr.as_ref() else { break };
            if !p.is_in_delay_slot() {
                break;
            }
            min_addr = p.get_min_address();
            let lookup = match min_addr.subtract_no_wrap(1) {
                Ok(a) => a,
                Err(_) => return min_addr,
            };
            prev_instr = listing.get_instruction_containing(&lookup);
        }
        if let Some(p) = prev_instr {
            min_addr = p.get_min_address();
        }
        min_addr
    }

    /// If `instr` is contained within a delay slot, or has delay slots, the maximum address of
    /// the last delay slot instruction will be returned. If a normal instruction is specified,
    /// `instr`'s maximum address is returned.
    ///
    /// Port of `SimpleDiffUtility.getEndOfDelaySlots(Instruction)`, adapted to take `listing`
    /// explicitly (see the module docs).
    fn get_end_of_delay_slots(&self, listing: &dyn Listing, instr: &dyn Instruction) -> Address {
        let mut max_addr = instr.get_max_address();
        let lookup = match max_addr.add_no_wrap(1) {
            Ok(a) => a,
            Err(_) => return max_addr,
        };
        let mut next_instr = listing.get_instruction_at(&lookup);
        loop {
            let Some(next) = next_instr.as_ref() else { break };
            if !next.is_in_delay_slot() {
                break;
            }
            max_addr = next.get_max_address();
            let lookup = match max_addr.add_no_wrap(1) {
                Ok(a) => a,
                Err(_) => return max_addr,
            };
            next_instr = listing.get_instruction_at(&lookup);
        }
        max_addr
    }

    /// Expand `original_set` to include complete delay-slotted instructions which may be
    /// included at the start or end of each range within it.
    ///
    /// Port of `SimpleDiffUtility.expandAddressSetToIncludeFullDelaySlots(Program,
    /// AddressSetView)`, adapted to take `listing` directly rather than `program` (see the module
    /// docs) and to always return a fresh [`AddressSet`] (the Java method returns `originalSet`
    /// unchanged when no expansion occurs, which this port cannot do without cloning since it
    /// only borrows `original_set`).
    fn expand_address_set_to_include_full_delay_slots(
        &self,
        listing: &dyn Listing,
        original_set: &dyn AddressSetView,
    ) -> Box<dyn AddressSetView> {
        let mut expanded: Option<AddressSet> = None;
        let mut ranges = original_set.address_ranges();
        while let Some(range) = ranges.next_range() {
            if let Some(instr) = listing.get_instruction_at(range.min_address()) {
                if instr.is_in_delay_slot() {
                    let new_min = self.get_start_of_delay_slots(listing, instr.as_ref());
                    if &new_min != range.min_address() {
                        let set = expanded.get_or_insert_with(|| AddressSet::from_set(original_set));
                        set.add_range(&new_min, &instr.get_max_address());
                    }
                }
            }
            if let Some(instr) = listing.get_instruction_containing(range.max_address()) {
                if instr.is_in_delay_slot() || instr.get_delay_slot_depth() != 0 {
                    let new_max = self.get_end_of_delay_slots(listing, instr.as_ref());
                    if &new_max != range.max_address() {
                        let set = expanded.get_or_insert_with(|| AddressSet::from_set(original_set));
                        set.add_range(&instr.get_min_address(), &new_max);
                    }
                }
            }
        }
        match expanded {
            Some(set) => Box::new(set),
            None => Box::new(AddressSet::from_set(original_set)),
        }
    }

    /// Convert `addr` from `program` to a comparable address in `other_program`.
    ///
    /// Port of `SimpleDiffUtility.getCompatibleAddress(Program, Address, Program)`.
    ///
    /// # Panics
    /// Panics for variable addresses (mirrors the Java method's unconditional
    /// `IllegalArgumentException`) and for unsupported address space types (mirrors the Java
    /// method's final `IllegalArgumentException`).
    fn get_compatible_address(
        &self,
        program: &mut dyn Program,
        addr: &Address,
        other_program: &mut dyn Program,
    ) -> Option<Address> {
        use crate::program::model::address::AddressSpaceType;

        if addr.is_memory_address() {
            let other_space = self.get_compatible_address_space(addr.space(), other_program)?;
            if addr.offset() < other_space.min_offset() || addr.offset() > other_space.max_offset() {
                return None;
            }
            return Some(Address::new(other_space, addr.offset()));
        }
        if addr.space().space_type() == AddressSpaceType::Variable {
            panic!("correlation of variables by their variable address not allowed");
        }
        if addr.is_stack_address() {
            let stack_space = other_program.get_address_factory()?.get_stack_space()?;
            return Some(stack_space.address(addr.offset()));
        }
        if addr.is_register_address() {
            if program.get_language_id() == other_program.get_language_id() {
                return Some(addr.clone());
            }
            let reg = program.get_register_at(addr)?;
            let reg = reg.borrow();
            let other_reg = other_program.get_register(reg.name())?;
            let other_reg = other_reg.borrow();
            if reg.minimum_byte_size() != other_reg.minimum_byte_size() {
                return None;
            }
            let delta = addr.subtract(reg.address());
            if delta != 0 {
                return Some(
                    other_reg
                        .address()
                        .add(delta)
                        .expect("register address overflow translating address"),
                );
            }
            return Some(other_reg.address().clone());
        }
        if addr.is_external_address() {
            let s = {
                let symbol_table = program.get_symbol_table()?;
                symbol_table.get_primary_symbol(addr).ok()??
            };
            if !s.is_external() {
                return None;
            }
            let matched =
                self.get_matching_external_symbol(program, Some(s), other_program, true, None)?;
            return Some(matched.get_address());
        }
        let space_type = addr.space().space_type();
        if space_type == AddressSpaceType::None || space_type == AddressSpaceType::Unknown {
            return Some(addr.clone());
        }
        panic!("Unsupported address type");
    }

    /// Convert `addr_space` to a comparable address space in `other_program`.
    ///
    /// Port of `SimpleDiffUtility.getCompatibleAddressSpace(AddressSpace, Program)`. See the
    /// module docs for why the overlay-space check is dropped.
    fn get_compatible_address_space(
        &self,
        addr_space: &AddressSpace,
        other_program: &mut dyn Program,
    ) -> Option<Arc<AddressSpace>> {
        let other_space = other_program
            .get_address_factory()?
            .get_address_space_by_name(addr_space.name())?;
        if other_space.space_type() == addr_space.space_type() {
            Some(other_space)
        } else {
            None
        }
    }

    /// Given `symbol` (owned by `program`), get the corresponding symbol from `other_program`.
    ///
    /// Port of `SimpleDiffUtility.getSymbol(Symbol, Program)`, adapted to take `program`
    /// explicitly (see the module docs).
    ///
    /// # Panics
    /// Panics for symbol types not handled by any branch, mirroring the Java method's
    /// `AssertException` ("Got unexpected SymbolType").
    fn get_symbol(
        &self,
        program: &mut dyn Program,
        symbol: Option<Arc<dyn Symbol>>,
        other_program: &mut dyn Program,
    ) -> Option<Arc<dyn Symbol>> {
        let symbol = symbol?;
        let symbol_type = symbol.get_symbol_type();

        if symbol_type == SymbolType::Global {
            return other_program.get_global_namespace().map(|ns| ns.get_symbol());
        }

        let name = symbol.get_name().to_string();
        let other_parent = self.get_symbol(program, symbol.get_parent_symbol(), other_program)?;
        let other_namespace = other_parent.as_namespace()?;

        match symbol_type {
            SymbolType::Library | SymbolType::Class | SymbolType::Namespace => {
                let table = other_program.get_symbol_table()?;
                table
                    .find_symbol_by_name_namespace(&name, other_namespace.as_ref())
                    .ok()?
            }
            SymbolType::Parameter | SymbolType::LocalVar => {
                self.get_variable_symbol_in_namespace(program, symbol, other_program, other_namespace)
            }
            SymbolType::Function => {
                self.get_other_function_symbol(program, symbol, other_program, other_namespace)
            }
            SymbolType::Label => {
                self.get_other_code_symbol(program, symbol, other_program, other_namespace)
            }
            _ => panic!("Got unexpected SymbolType: {}", symbol_type),
        }
    }

    /// Given an external symbol owned by `program`, get the corresponding symbol -- which has
    /// the same name and path -- from `other_program`.
    ///
    /// Port of `SimpleDiffUtility.getMatchingExternalSymbol(Program, Symbol, Program, boolean,
    /// Set<Long>)`. See the module docs for why `allow_inferred_match` currently has no effect.
    fn get_matching_external_symbol(
        &self,
        program: &mut dyn Program,
        symbol: Option<Arc<dyn Symbol>>,
        other_program: &mut dyn Program,
        allow_inferred_match: bool,
        other_restricted_symbol_ids: Option<&HashSet<i64>>,
    ) -> Option<Arc<dyn Symbol>> {
        let _ = allow_inferred_match;
        let symbol = symbol?;
        let sym_type = symbol.get_symbol_type();
        if (sym_type != SymbolType::Function && sym_type != SymbolType::Label) || !symbol.is_external()
        {
            return None;
        }

        let ext_loc = program.get_external_manager()?.get_external_location(symbol.clone())?;
        let target_name =
            (symbol.get_source() != SourceType::Default).then(|| symbol.get_name().to_string());
        let target_orig_imported_name = ext_loc.get_original_imported_name();
        let target_namespace = symbol
            .get_parent_namespace()
            .map(|ns| ns.get_name_with_path(true))
            .filter(|ns| !ns.starts_with(UNKNOWN_LIBRARY_NAME));
        let target_addr = ext_loc.get_address();

        let mut matches: Vec<(Address, ExternalReferenceCount)> = Vec::new();

        if symbol.get_source() != SourceType::Default {
            let other_parent =
                self.get_symbol(program, symbol.get_parent_symbol(), other_program);
            if other_parent.is_some() {
                let candidates = {
                    let table = other_program.get_symbol_table()?;
                    table
                        .get_external_symbols_by_name(symbol.get_name())
                        .unwrap_or_default()
                };
                for other_sym in candidates {
                    let other_addr = other_sym.get_address();
                    if let Some(other_ext_loc) = other_program
                        .get_external_manager()?
                        .get_external_location(other_sym.clone())
                    {
                        let match_type = test_external_match(other_ext_loc.as_ref(), ext_loc.as_ref());
                        if match_type == ExternalMatchType::None {
                            continue;
                        }
                        let mut rc = ExternalReferenceCount::new(other_ext_loc, match_type);
                        rc.set_relative_rank(
                            target_addr.as_ref(),
                            target_namespace.as_deref(),
                            target_name.as_deref(),
                            target_orig_imported_name.as_deref(),
                        );
                        upsert_match(&mut matches, other_addr, rc);
                    }
                }
            }
        }

        if matches.is_empty() {
            let all_other_symbols = {
                let table = other_program.get_symbol_table()?;
                table.get_all_external_symbols().unwrap_or_default()
            };
            for other_sym in all_other_symbols {
                if let Some(ids) = other_restricted_symbol_ids {
                    if !ids.contains(&other_sym.get_id()) {
                        continue;
                    }
                }
                let other_addr = other_sym.get_address();
                if let Some(other_ext_loc) = other_program
                    .get_external_manager()?
                    .get_external_location(other_sym.clone())
                {
                    let match_type = test_external_match(other_ext_loc.as_ref(), ext_loc.as_ref());
                    if match_type == ExternalMatchType::None {
                        continue;
                    }
                    let mut rc = ExternalReferenceCount::new(other_ext_loc, match_type);
                    rc.set_relative_rank(
                        target_addr.as_ref(),
                        target_namespace.as_deref(),
                        target_name.as_deref(),
                        target_orig_imported_name.as_deref(),
                    );
                    upsert_match(&mut matches, other_addr, rc);
                }
            }
            if matches.is_empty() {
                return None;
            }
        }

        if matches.len() == 1 {
            let only = &matches[0].1;
            return if only.rank >= 0 { only.symbol() } else { None };
        }

        matches.sort_by(|(_, a), (_, b)| compare_matches(a, b));
        let best = &matches[0].1;
        if best.rank > 0 {
            best.symbol()
        } else {
            None
        }
    }

    /// Given an external location owned by `program`, get the corresponding external location --
    /// which has the same name and path -- from `other_program`.
    ///
    /// Port of `SimpleDiffUtility.getMatchingExternalLocation(Program, ExternalLocation, Program,
    /// boolean)`.
    fn get_matching_external_location(
        &self,
        program: &mut dyn Program,
        external_location: Option<Arc<dyn ExternalLocation>>,
        other_program: &mut dyn Program,
        allow_inferred_match: bool,
    ) -> Option<Arc<dyn ExternalLocation>> {
        let external_location = external_location?;
        let symbol = external_location.get_symbol()?;
        let matching = self.get_matching_external_symbol(
            program,
            Some(symbol),
            other_program,
            allow_inferred_match,
            None,
        )?;
        other_program.get_external_manager()?.get_external_location(matching)
    }

    /// Find the variable symbol in `other_program` which corresponds to `symbol` (owned by
    /// `program`).
    ///
    /// Port of `SimpleDiffUtility.getVariableSymbol(Symbol, Program)`, adapted to take `program`
    /// explicitly (see the module docs).
    fn get_variable_symbol(
        &self,
        program: &mut dyn Program,
        symbol: Arc<dyn Symbol>,
        other_program: &mut dyn Program,
    ) -> Option<Arc<dyn Symbol>> {
        let other_parent = self.get_symbol(program, symbol.get_parent_symbol(), other_program)?;
        let other_namespace = other_parent.as_namespace()?;
        self.get_variable_symbol_in_namespace(program, symbol, other_program, other_namespace)
    }

    /// Port of the protected `SimpleDiffUtility.getVariableSymbol(Symbol, Program, Namespace)`
    /// overload. Not part of Java's public API; see the module docs.
    fn get_variable_symbol_in_namespace(
        &self,
        program: &mut dyn Program,
        var_sym: Arc<dyn Symbol>,
        other_program: &mut dyn Program,
        other_namespace: Arc<dyn Namespace>,
    ) -> Option<Arc<dyn Symbol>> {
        let other_function_symbol = other_namespace.as_function()?.get_symbol();
        let var = var_sym.as_variable()?;
        let storage: Arc<dyn VariableStorage> = Arc::from(var.get_variable_storage()?);
        let other_storage =
            self.get_compatible_variable_storage(program, Some(storage), other_program)?;
        if !other_storage.is_valid() {
            return None;
        }
        let other_sym_table = other_program.get_symbol_table()?;
        let min_var =
            self.get_overlapping_variable(other_sym_table, var, other_storage, other_function_symbol)?;
        min_var.get_symbol()
    }

    /// Find overlapping variable which meets the following conditions:
    /// 1. First use offset matches
    /// 2. Ordinal matches (for parameters only)
    /// 3. Storage matches
    ///
    /// Port of the protected `SimpleDiffUtility.getOverlappingVariable(SymbolTable, Variable,
    /// VariableStorage, Symbol)`. Not part of Java's public API; see the module docs.
    fn get_overlapping_variable(
        &self,
        other_sym_table: &mut dyn SymbolTable,
        var: Arc<dyn crate::program::model::listing::Variable>,
        other_storage: Arc<dyn VariableStorage>,
        other_function_symbol: Arc<dyn Symbol>,
    ) -> Option<Arc<dyn crate::program::model::listing::Variable>> {
        let symbol_type = var.get_symbol()?.get_symbol_type();
        let ordinal = var.parameter_ordinal().unwrap_or(-1);
        let first_use_offset = var.get_first_use_offset();
        let symbols = other_sym_table
            .get_symbols_in_namespace(other_function_symbol.get_id())
            .ok()?;
        for s in symbols {
            if s.get_symbol_type() != symbol_type {
                continue;
            }
            let Some(v) = s.as_variable() else { continue };
            if let Some(p_ordinal) = v.parameter_ordinal() {
                if p_ordinal != ordinal {
                    continue;
                }
            }
            if v.get_first_use_offset() != first_use_offset {
                continue;
            }
            if let Some(storage) = v.get_variable_storage() {
                if storage.storage_equals(other_storage.as_ref()) {
                    return Some(v);
                }
            }
        }
        None
    }

    /// Port of the private `SimpleDiffUtility.getOtherFunctionSymbol(Symbol, Program, Namespace)`.
    /// Not part of Java's public API; see the module docs.
    fn get_other_function_symbol(
        &self,
        program: &mut dyn Program,
        symbol: Arc<dyn Symbol>,
        other_program: &mut dyn Program,
        other_namespace: Arc<dyn Namespace>,
    ) -> Option<Arc<dyn Symbol>> {
        if symbol.is_external() {
            return self.get_other_external_location_symbol(
                program,
                symbol,
                other_program,
                other_namespace,
            );
        }
        let func = symbol.as_function()?;
        let entry_point = func.get_entry_point();
        let other_entry = self.get_compatible_address(program, &entry_point, other_program)?;
        let other_func = other_program.get_function_manager()?.get_function_at(&other_entry)?;
        Some(other_func.get_symbol())
    }

    /// Port of the private `SimpleDiffUtility.getOtherCodeSymbol(Symbol, Program, Namespace)`.
    /// Not part of Java's public API; see the module docs.
    fn get_other_code_symbol(
        &self,
        program: &mut dyn Program,
        symbol: Arc<dyn Symbol>,
        other_program: &mut dyn Program,
        other_namespace: Arc<dyn Namespace>,
    ) -> Option<Arc<dyn Symbol>> {
        if symbol.is_external() {
            return self.get_other_external_location_symbol(
                program,
                symbol,
                other_program,
                other_namespace,
            );
        }
        let other_address =
            self.get_compatible_address(program, &symbol.get_address(), other_program)?;
        let other_symbol = {
            let table = other_program.get_symbol_table()?;
            table
                .find_symbol_by_name_address_namespace(
                    symbol.get_name(),
                    &other_address,
                    other_namespace.as_ref(),
                )
                .ok()?
        }?;
        if other_symbol.get_symbol_type() == symbol.get_symbol_type() {
            Some(other_symbol)
        } else {
            None
        }
    }

    /// Port of the private `SimpleDiffUtility.getOtherExternalLocationSymbol(Symbol, Program,
    /// Namespace)`. Not part of Java's public API; see the module docs.
    fn get_other_external_location_symbol(
        &self,
        program: &mut dyn Program,
        symbol: Arc<dyn Symbol>,
        other_program: &mut dyn Program,
        other_namespace: Arc<dyn Namespace>,
    ) -> Option<Arc<dyn Symbol>> {
        let external = program.get_external_manager()?.get_external_location(symbol.clone())?;
        let other_symbols = {
            let table = other_program.get_symbol_table()?;
            table
                .get_symbols_by_name_namespace(symbol.get_name(), other_namespace.as_ref())
                .ok()?
        };
        if other_symbols.len() == 1 {
            let s = other_symbols[0].clone();
            return if s.get_symbol_type() == symbol.get_symbol_type() {
                Some(s)
            } else {
                None
            };
        }
        for s in other_symbols {
            if let Some(other_external) =
                other_program.get_external_manager()?.get_external_location(s.clone())
            {
                if external.is_equivalent(other_external.as_ref()) {
                    return Some(s);
                }
            }
        }
        None
    }
}

/// A default, stateless implementation of [`SimpleDiffUtility`] using entirely the trait's
/// default method bodies. Not a port of any specific Java class -- `SimpleDiffUtility` has no
/// instance state to port, so this is the canonical implementation callers can depend on.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultSimpleDiffUtility;

impl SimpleDiffUtility for DefaultSimpleDiffUtility {}

const ADDRESS_RANK: i32 = 3;
const NAME_RANK: i32 = 2;
const NAMESPACE_RANK: i32 = 1;
const MANGLED_NAME_RANK: i32 = NAME_RANK + NAMESPACE_RANK;

/// Port of the private `SimpleDiffUtility.ExternalMatchType` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExternalMatchType {
    None,
    Name,
    MangledName,
    Address,
}

/// Port of the private static inner class `SimpleDiffUtility.ExternalReferenceCount`.
struct ExternalReferenceCount {
    ext_loc: Arc<dyn ExternalLocation>,
    match_type: ExternalMatchType,
    rank: i32,
}

impl ExternalReferenceCount {
    fn new(ext_loc: Arc<dyn ExternalLocation>, match_type: ExternalMatchType) -> Self {
        Self { ext_loc, match_type, rank: 0 }
    }

    fn symbol(&self) -> Option<Arc<dyn Symbol>> {
        self.ext_loc.get_symbol()
    }

    fn symbol_type(&self) -> Option<SymbolType> {
        self.symbol().map(|s| s.get_symbol_type())
    }

    fn full_namespace_name(&self) -> String {
        self.symbol()
            .and_then(|s| s.get_parent_namespace())
            .map(|ns| ns.get_name_with_path(true))
            .unwrap_or_default()
    }

    /// Port of `ExternalReferenceCount.setRelativeRank`. `target_name` is accepted (mirroring the
    /// Java parameter list) but -- as in the original -- unused by this method's body.
    fn set_relative_rank(
        &mut self,
        target_addr: Option<&Address>,
        target_namespace: Option<&str>,
        _target_name: Option<&str>,
        target_orig_imported_name: Option<&str>,
    ) {
        self.rank = 0;

        if self.match_type == ExternalMatchType::Address {
            self.rank = ADDRESS_RANK;
            return;
        }

        if let Some(target_addr) = target_addr {
            match self.ext_loc.get_address() {
                Some(my_addr) if &my_addr == target_addr => self.rank += ADDRESS_RANK,
                Some(_) => self.rank -= ADDRESS_RANK,
                None => {}
            }
        }

        if self.match_type == ExternalMatchType::MangledName {
            self.rank += MANGLED_NAME_RANK;
            return;
        }

        if self.match_type != ExternalMatchType::Name {
            return;
        }

        let my_orig_imported_name = self.ext_loc.get_original_imported_name();
        if target_orig_imported_name.is_some() && my_orig_imported_name.is_some() {
            self.rank -= MANGLED_NAME_RANK;
            return;
        }

        self.rank += NAME_RANK;

        if let Some(target_namespace) = target_namespace {
            if target_namespace == self.full_namespace_name() {
                self.rank += NAMESPACE_RANK;
            }
        }
    }
}

/// Port of `ExternalReferenceCount.compareTo`. See the module docs for why the final tiebreak
/// uses `Symbol::get_name` instead of `Symbol.getName(true)`.
fn compare_matches(a: &ExternalReferenceCount, b: &ExternalReferenceCount) -> std::cmp::Ordering {
    b.rank
        .cmp(&a.rank)
        .then_with(|| {
            let a_id = a.symbol_type().map(|t| t.get_id()).unwrap_or(i32::MIN);
            let b_id = b.symbol_type().map(|t| t.get_id()).unwrap_or(i32::MIN);
            b_id.cmp(&a_id)
        })
        .then_with(|| {
            let a_name = a.symbol().map(|s| s.get_name().to_string()).unwrap_or_default();
            let b_name = b.symbol().map(|s| s.get_name().to_string()).unwrap_or_default();
            a_name.cmp(&b_name)
        })
}

/// Insert-or-replace a match by address, mirroring `HashMap.put(Address, ExternalReferenceCount)`.
fn upsert_match(
    matches: &mut Vec<(Address, ExternalReferenceCount)>,
    addr: Address,
    rc: ExternalReferenceCount,
) {
    if let Some(entry) = matches.iter_mut().find(|(a, _)| *a == addr) {
        entry.1 = rc;
    } else {
        matches.push((addr, rc));
    }
}

/// Port of the private `SimpleDiffUtility.testExternalMatch(ExternalLocation, ExternalLocation)`.
fn test_external_match(ext_loc1: &dyn ExternalLocation, ext_loc2: &dyn ExternalLocation) -> ExternalMatchType {
    let match_type = test_external_name_match(ext_loc1, ext_loc2);
    if match_type == ExternalMatchType::None {
        if has_external_address_match(ext_loc1, ext_loc2) {
            ExternalMatchType::Address
        } else {
            ExternalMatchType::None
        }
    } else {
        match_type
    }
}

/// Port of the private `SimpleDiffUtility.hasExternalAddressMatch(ExternalLocation,
/// ExternalLocation)`.
fn has_external_address_match(ext_loc1: &dyn ExternalLocation, ext_loc2: &dyn ExternalLocation) -> bool {
    match ext_loc1.get_address() {
        Some(addr1) => Some(addr1) == ext_loc2.get_address(),
        None => false,
    }
}

/// Port of the private `SimpleDiffUtility.testExternalNameMatch(ExternalLocation,
/// ExternalLocation)`.
fn test_external_name_match(ext_loc1: &dyn ExternalLocation, ext_loc2: &dyn ExternalLocation) -> ExternalMatchType {
    let (Some(sym1), Some(sym2)) = (ext_loc1.get_symbol(), ext_loc2.get_symbol()) else {
        return ExternalMatchType::None;
    };
    if sym1.get_source() == SourceType::Default || sym2.get_source() == SourceType::Default {
        return ExternalMatchType::None;
    }
    if ext_loc1.get_library_name() != ext_loc2.get_library_name() {
        return ExternalMatchType::None;
    }

    let name1 = ext_loc1.get_label();
    let name2 = ext_loc2.get_label();
    let orig_name1 = ext_loc1.get_original_imported_name();
    let orig_name2 = ext_loc2.get_original_imported_name();

    if let Some(orig_name1) = &orig_name1 {
        if let Some(orig_name2) = &orig_name2 {
            return if orig_name1 == orig_name2 {
                ExternalMatchType::MangledName
            } else {
                ExternalMatchType::None
            };
        }
        let parent_is_library = sym2.get_parent_namespace().map(|ns| ns.is_library()).unwrap_or(false);
        if parent_is_library && *orig_name1 == name2 {
            return ExternalMatchType::MangledName;
        }
    } else if let Some(orig_name2) = &orig_name2 {
        let parent_is_library = sym1.get_parent_namespace().map(|ns| ns.is_library()).unwrap_or(false);
        if parent_is_library && *orig_name2 == name1 {
            return ExternalMatchType::MangledName;
        }
    }

    if name1 == name2 {
        ExternalMatchType::Name
    } else {
        ExternalMatchType::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressFactory, AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::lang::register::{Register, RegisterRef};
    use crate::program::seam_stubs::{HashVariableStorage, VarnodeListStorage};

    /// `(name, address, minimum_byte_size)` describing a single register, kept as plain
    /// `Send + Sync` data rather than a [`RegisterRef`] (`Rc<RefCell<Register>>`, which is
    /// neither) so [`MockProgram`] itself can satisfy [`Program`]'s `Send + Sync` bound. The
    /// `RegisterRef` is constructed fresh on each `get_register`/`get_register_at` call instead.
    type MockRegister = (String, Address, i32);

    struct MockProgram {
        factory: Option<Arc<dyn AddressFactory>>,
        global_namespace: Option<Arc<dyn Namespace>>,
        language_id: String,
        register: Option<MockRegister>,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn get_language_id(&self) -> String {
            self.language_id.clone()
        }

        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            self.factory.clone()
        }

        fn get_global_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.global_namespace.clone()
        }

        fn get_register(&self, name: &str) -> Option<RegisterRef> {
            let (reg_name, addr, size) = self.register.as_ref()?;
            (reg_name == name)
                .then(|| Register::new(reg_name.clone(), "", addr.clone(), *size, false, Register::TYPE_NONE))
        }

        fn get_register_at(&self, address: &Address) -> Option<RegisterRef> {
            let (reg_name, addr, size) = self.register.as_ref()?;
            (addr == address)
                .then(|| Register::new(reg_name.clone(), "", addr.clone(), *size, false, Register::TYPE_NONE))
        }
    }

    fn mock_program(
        spaces: Vec<Arc<AddressSpace>>,
        language_id: &str,
        register: Option<MockRegister>,
    ) -> MockProgram {
        MockProgram {
            factory: Some(Arc::new(DefaultAddressFactory::new(spaces))),
            global_namespace: None,
            language_id: language_id.to_string(),
            register,
        }
    }

    #[test]
    fn get_compatible_address_translates_memory_and_register_addresses() {
        let ram_a = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let ram_b = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let reg_space_a = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0);
        let reg_space_b = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0);

        let reg_addr_a = reg_space_a.address(0x0);
        let reg_addr_b = reg_space_b.address(0x0);

        let mut program = mock_program(
            vec![ram_a.clone(), reg_space_a.clone()],
            "lang-A",
            Some(("R0".to_string(), reg_addr_a.clone(), 4)),
        );
        let mut other = mock_program(
            vec![ram_b.clone(), reg_space_b.clone()],
            "lang-B",
            Some(("R0".to_string(), reg_addr_b.clone(), 4)),
        );

        let util = DefaultSimpleDiffUtility;

        let mem_addr = ram_a.address(0x401000);
        assert_eq!(
            util.get_compatible_address(&mut program, &mem_addr, &mut other),
            Some(ram_b.address(0x401000))
        );

        assert_eq!(
            util.get_compatible_address(&mut program, &reg_addr_a, &mut other),
            Some(reg_addr_b.clone())
        );

        let unmapped_space = AddressSpace::new("code", 32, 1, AddressSpaceType::Code, 5);
        let unmapped_addr = unmapped_space.address(0x10);
        assert!(util
            .get_compatible_address(&mut program, &unmapped_addr, &mut other)
            .is_none());
    }

    #[test]
    fn get_compatible_variable_storage_translates_register_backed_storage_and_passes_hash_storage_through() {
        let reg_space_a = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0);
        let reg_space_b = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0);
        let reg_addr_a = reg_space_a.address(0x0);
        let reg_addr_b = reg_space_b.address(0x0);

        let mut program = mock_program(
            vec![reg_space_a.clone()],
            "lang-A",
            Some(("R0".to_string(), reg_addr_a.clone(), 4)),
        );
        let mut other = mock_program(
            vec![reg_space_b.clone()],
            "lang-B",
            Some(("R0".to_string(), reg_addr_b.clone(), 4)),
        );

        let util = DefaultSimpleDiffUtility;
        let varnode = Varnode::new(reg_addr_a.clone(), 4);
        let storage: Arc<dyn VariableStorage> = Arc::new(VarnodeListStorage(vec![varnode]));

        let translated = util
            .get_compatible_variable_storage(&mut program, Some(storage), &mut other)
            .expect("translated storage");
        let varnodes = translated.get_varnodes();
        assert_eq!(varnodes.len(), 1);
        assert_eq!(varnodes[0].get_address(), &reg_addr_b);
        assert_eq!(varnodes[0].get_size(), 4);

        let hash_storage: Arc<dyn VariableStorage> = Arc::new(HashVariableStorage(42));
        let passthrough = util
            .get_compatible_variable_storage(&mut program, Some(hash_storage), &mut other)
            .unwrap();
        assert!(passthrough.is_hash_storage());
    }

    struct MockSymbol {
        address: Address,
        name: String,
        symbol_type: SymbolType,
        id: i64,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            self.symbol_type
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
    }

    struct MockGlobalNamespace(Arc<dyn Symbol>);

    impl Namespace for MockGlobalNamespace {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            self.0.clone()
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
    }

    #[test]
    fn get_symbol_resolves_global_symbol_via_other_programs_global_namespace() {
        fn ram_addr(offset: i64) -> Address {
            AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0).address(offset)
        }

        let other_global_symbol: Arc<dyn Symbol> = Arc::new(MockSymbol {
            address: ram_addr(0),
            name: "Global".to_string(),
            symbol_type: SymbolType::Global,
            id: 99,
        });
        let other_global_namespace: Arc<dyn Namespace> =
            Arc::new(MockGlobalNamespace(other_global_symbol.clone()));

        let mut program = mock_program(vec![], "lang-A", None);
        let mut other = MockProgram {
            factory: None,
            global_namespace: Some(other_global_namespace),
            language_id: "lang-B".to_string(),
            register: None,
        };

        let query_symbol: Arc<dyn Symbol> = Arc::new(MockSymbol {
            address: ram_addr(0),
            name: "Global".to_string(),
            symbol_type: SymbolType::Global,
            id: 1,
        });

        let util = DefaultSimpleDiffUtility;
        let resolved = util
            .get_symbol(&mut program, Some(query_symbol), &mut other)
            .expect("resolved global symbol");
        assert_eq!(resolved.get_id(), 99);
    }

    #[test]
    fn simple_diff_utility_is_object_safe_through_a_trait_object() {
        let util: Box<dyn SimpleDiffUtility> = Box::new(DefaultSimpleDiffUtility);

        let ram_a = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let ram_b = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let mut program = mock_program(vec![ram_a.clone()], "lang", None);
        let mut other = mock_program(vec![ram_b.clone()], "lang", None);

        let addr = ram_a.address(0x1000);
        assert_eq!(
            util.get_compatible_address(&mut program, &addr, &mut other),
            Some(ram_b.address(0x1000))
        );
    }
}
