//! Port of `ghidra.program.model.pcode.DataTypeSymbol`.
//!
//! **Class relationship note**: despite the naming similarity to [`EquateSymbol`](crate::program::model::pcode::equate_symbol::EquateSymbol)/
//! [`UnionFacetSymbol`](crate::program::model::pcode::union_facet_symbol::UnionFacetSymbol), the
//! Java source declares `public class DataTypeSymbol` with **no `extends` clause at all** -- it
//! does *not* extend `HighSymbol`. It is a small, standalone wrapper pairing a database `Symbol`
//! (a `LABEL` symbol whose *name* encodes a hash) with a `DataType`, used to persist an
//! association between a code address and a `FunctionSignature`/`TypeDef` datatype (e.g. for
//! call-site signature overrides) by hiding the association inside an otherwise-unused label
//! symbol's name. So this port implements the trait `high_symbol::HighSymbol` for *none* of its
//! members -- it is a plain concrete struct with its own, independent API surface, matching
//! Java's own class declaration exactly.
//!
//! # Deviations: collaborators taken as direct parameters
//! Several real methods reach their needed `Program`/`SymbolTable` through `Symbol.getProgram()`
//! (`writeSymbol`'s `HighFunction.createLabelSymbol`, `cleanupUnusedOverride`'s
//! `sym.getProgram().getSymbolTable()`/`.getDataTypeManager()`, `readSymbol`'s
//! `s.getProgram().getDataTypeManager()`). This crate's ported [`Symbol`](crate::program::model::symbol::Symbol)
//! trait has no `get_program()` method, and separately,
//! [`Program::get_symbol_table`](crate::program::model::listing::Program::get_symbol_table)
//! requires `&mut self`, which is unreachable through the shared `Arc<dyn Program>` a `Symbol`
//! would hand back even if it had one (the same architectural gap already documented on
//! [`HighSymbol::get_symbol`](crate::program::model::pcode::high_symbol::HighSymbol::get_symbol)'s
//! default). Rather than fabricate a `Program`/leave these methods unimplemented, every method
//! that would otherwise reach for `Symbol.getProgram()` instead takes the collaborator it actually
//! needs (`&dyn DataTypeManager`, `&mut dyn SymbolTable`) directly as a parameter -- the same
//! "inject the collaborator Java derives internally" deviation already established by
//! [`HighLabelSymbol`](crate::program::model::pcode::high_label_symbol::HighLabelSymbol)'s module
//! docs for `PcodeDataTypeManager`/`Program`. `write_symbol` needed no such deviation:
//! Java's own signature already takes `dtmanage: DataTypeManager` directly.
//!
//! # Deviation: `HighFunction.createLabelSymbol` inlined, not shared
//! `writeSymbol` calls the tiny static `HighFunction.createLabelSymbol(symtab, addr, symname,
//! namespace, SourceType.USER_DEFINED, false)` helper. That helper is not ported as shared API in
//! this crate (nothing else needs it yet), so its 4-line body is inlined directly into
//! [`DataTypeSymbol::write_symbol`] instead -- with `useLocalNamespace` fixed to Java's literal
//! `false` argument at this call site, [`crate::program::model::symbol::SymbolTable::create_label_in_namespace`]
//! is a direct, faithful substitute for the whole helper (its `namespace == null &&
//! useLocalNamespace` branch never fires here).
//!
//! # Blocker: `deleteSymbols`'s actual deletion step
//! `deleteSymbols`/`writeSymbol(..., clearold: true)` needs `Symbol.hasReferences()`/
//! `Symbol.delete()`, neither of which exist on this crate's ported [`Symbol`](crate::program::model::symbol::Symbol)
//! trait (expanding that trait, used by dozens of already-ported call sites, is out of scope for
//! this port). [`DataTypeSymbol::delete_symbols`] still performs the real, fully portable
//! candidate-collection/filtering logic (name-prefix, symbol-type, and namespace checks -- see the
//! `space.equals(...)` quirk noted on that method), and returns `Ok(())` unchanged for the common
//! case where nothing matches (behaviorally identical to Java there); if it *does* find candidates
//! that Java would have deleted, it returns an `Err` documenting this exact blocker rather than
//! silently doing nothing or fabricating a deletion.
//!
//! # Quirk: `deleteSymbols`'s inverted namespace check
//! `deleteSymbols` skips (i.e. does *not* delete) a same-name-prefix `LABEL` symbol when
//! `space.equals(sym.getParentNamespace())` -- that is, it only ever collects symbols whose parent
//! namespace is *different* from the given `space`. This reads backwards from what a "clear out
//! stale symbols before writing a fresh one in this namespace" cleanup would intuitively do, but
//! is reproduced exactly as written; see `delete_symbols_skips_symbols_already_in_target_namespace`
//! below.

use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_conflict_handler::KEEP_HANDLER;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::typedef_data_type::TypedefDataType;
use crate::program::model::pcode::high_function::is_override_namespace;
use crate::program::model::symbol::{Namespace, SourceType, Symbol, SymbolTable, SymbolType};
use crate::program::seam_stubs::PlaceholderDataType;
use crate::util::exception::InvalidInputException;
use crate::generic::hash::simple_crc32::SimpleCRC32;

/// A `Symbol`/`DataType` association, persisted by hiding it in a label symbol's name. Port of
/// `ghidra.program.model.pcode.DataTypeSymbol`. See the module docs -- this does **not** implement
/// [`high_symbol::HighSymbol`](crate::program::model::pcode::high_symbol::HighSymbol) despite the
/// naming similarity to its siblings in this file family.
pub struct DataTypeSymbol {
    /// Traditional symbol object. Port of the private `sym` field.
    sym: Option<Arc<dyn Symbol>>,
    /// Datatype associated with the symbol. Port of the private `datatype` field.
    datatype: Box<dyn DataType>,
    /// Root of the name. Port of the private `nmroot` field.
    nmroot: String,
    /// Datatype category. Port of the private `category` field.
    category: String,
}

impl DataTypeSymbol {
    /// Port of `DataTypeSymbol(DataType, String, String)`.
    pub fn new(dt: Box<dyn DataType>, nr: impl Into<String>, cat: impl Into<String>) -> Self {
        DataTypeSymbol { sym: None, datatype: dt, nmroot: nr.into(), category: cat.into() }
    }

    /// Port of `DataTypeSymbol.getSymbol()`.
    pub fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
        self.sym.clone()
    }

    /// Port of `DataTypeSymbol.getAddress()`.
    ///
    /// # Panics
    /// Panics if this symbol was not constructed via [`DataTypeSymbol::read_symbol`] (`sym` is
    /// still `None`), mirroring Java's uncaught `NullPointerException` from `sym.getAddress()`.
    pub fn get_address(&self) -> Address {
        self.sym
            .as_ref()
            .expect("DataTypeSymbol.getAddress() called with sym == null (mirrors Java's NPE)")
            .get_address()
    }

    /// Port of `DataTypeSymbol.getDataType()`.
    pub fn get_data_type(&self) -> &dyn DataType {
        self.datatype.as_ref()
    }

    /// Port of the private `DataTypeSymbol.buildHashedDataType(DataTypeManager)`.
    fn build_hashed_data_type(&mut self, dtmanage: &mut dyn DataTypeManager) -> Option<String> {
        if self.datatype.as_function_definition().is_some() {
            if dtmanage.contains(self.datatype.as_ref()) {
                // Signature is already in the manager, shouldn't change name
                return None;
            }
        } else {
            if !dtmanage.contains(self.datatype.as_ref()) {
                // Do not make typedef unless datatype is in our manager
                return None;
            }
            let old = std::mem::replace(&mut self.datatype, Box::new(PlaceholderDataType));
            let typedef = TypedefDataType::new_in_root("mytypedef", old).expect(
                "TypedefDataType::new_in_root failed (mirrors Java's uncaught \
                 IllegalArgumentException from the private `validate` helper)",
            );
            self.datatype = Box::new(typedef);
        }

        // Create the name and the category
        let path = CategoryPath::parse(&self.category).expect(
            "invalid category path (mirrors Java's uncaught IllegalArgumentException from `new \
             CategoryPath(String)`)",
        );
        let hash = Self::generate_hash(self.datatype.as_ref());
        for i in 0..256i32 {
            // Slot near original hash. `Integer.toHexString` treats its `int` argument as
            // unsigned 32-bit, and Java `int` addition wraps silently on overflow.
            let combined = (hash.wrapping_add(i)) as u32;
            let hash_string = format!("{combined:x}");
            let type_hashname = format!("dt_{hash_string}");
            if self.datatype.set_name_and_category(path.clone(), &type_hashname).is_err() {
                return None;
            }
            match dtmanage.get_data_type_in_category(&path, &type_hashname) {
                None => {
                    // Found empty slot, store signature here
                    let old = std::mem::replace(&mut self.datatype, Box::new(PlaceholderDataType));
                    self.datatype = dtmanage.add_data_type(old, &KEEP_HANDLER);
                    return Some(hash_string);
                }
                Some(preexists) => {
                    if preexists.is_equivalent(self.datatype.as_ref()) {
                        // If this is the right type
                        self.datatype = preexists;
                        return Some(hash_string);
                    }
                }
            }
        }
        None
    }

    /// Port of the private `DataTypeSymbol.buildSymbolName(String, Address)`.
    fn build_symbol_name(&self, hash: &str, addr: &Address) -> String {
        format!("{}_{:x}_{}", self.nmroot, addr.unsigned_offset(), hash)
    }

    /// Port of `DataTypeSymbol.writeSymbol(SymbolTable, Address, Namespace, DataTypeManager,
    /// boolean)`. See the module docs for the `HighFunction.createLabelSymbol` inlining.
    ///
    /// # Errors
    /// Returns an error if the hashed datatype could not be created (mirrors Java's
    /// `InvalidInputException("Unable to create datatype associated with symbol")`), if
    /// `clearold` triggers [`DataTypeSymbol::delete_symbols`]'s blocker (see its own docs), or if
    /// label creation itself fails.
    pub fn write_symbol(
        &mut self,
        symtab: &mut dyn SymbolTable,
        addr: &Address,
        namespace: Arc<dyn Namespace>,
        dtmanage: &mut dyn DataTypeManager,
        clearold: bool,
    ) -> Result<(), InvalidInputException> {
        if clearold {
            Self::delete_symbols(&self.nmroot, addr, symtab, namespace.as_ref())?;
        }
        let hash = self
            .build_hashed_data_type(dtmanage)
            .ok_or_else(|| InvalidInputException::with_message("Unable to create datatype associated with symbol"))?;
        let symname = self.build_symbol_name(&hash, addr);
        // Inlined `HighFunction.createLabelSymbol(symtab, addr, symname, namespace,
        // SourceType.USER_DEFINED, false)`: `useLocalNamespace` is `false` at this call site, so
        // the given `namespace` is used as-is (the `namespace == null && useLocalNamespace`
        // fallback to `symtab.getNamespace(addr)` never fires here).
        symtab
            .create_label_in_namespace(addr, &symname, namespace, SourceType::UserDefined)
            .map(|_| ())
            .map_err(|e| InvalidInputException::with_message(e.to_string()))
    }

    /// Port of the static `DataTypeSymbol.deleteSymbols(String, Address, SymbolTable,
    /// Namespace)`. See the module docs for the deliberately-preserved inverted namespace check
    /// and the `hasReferences`/`delete` blocker.
    ///
    /// # Errors
    /// Returns an error if any candidate symbol would need to be deleted (the blocker described
    /// in the module docs), or if the underlying `get_symbols` lookup fails.
    pub fn delete_symbols(
        nmroot: &str,
        addr: &Address,
        symtab: &mut dyn SymbolTable,
        space: &dyn Namespace,
    ) -> Result<(), InvalidInputException> {
        let symbols = symtab.get_symbols(addr).map_err(|e| InvalidInputException::with_message(e.to_string()))?;
        let mut dellist: Vec<Arc<dyn Symbol>> = Vec::new();
        for sym in symbols {
            if !sym.get_name().starts_with(nmroot) {
                continue;
            }
            if sym.get_symbol_type() != SymbolType::Label {
                continue;
            }
            // `space.equals(sym.getParentNamespace())` in Java: skip (don't collect) when the
            // symbol's parent namespace already matches `space`. `None` never matches (Java's
            // `Namespace.equals(null)` is always `false`), so a global-namespace symbol is never
            // skipped by this check. Namespace identity is compared by id, the closest available
            // proxy for `Namespace.equals()` in this crate (see the module docs).
            if let Some(parent) = sym.get_parent_namespace() {
                if parent.get_id() == space.get_id() {
                    continue;
                }
            }
            dellist.push(sym);
        }
        if dellist.is_empty() {
            return Ok(());
        }
        Err(InvalidInputException::with_message(format!(
            "DataTypeSymbol::delete_symbols found {} candidate symbol(s) to delete, but cannot: \
             Symbol::has_references/Symbol::delete are not present on this crate's ported Symbol \
             trait (see data_type_symbol.rs module docs)",
            dellist.len()
        )))
    }

    /// Port of `DataTypeSymbol.cleanupUnusedOverride()`. See the module docs for why
    /// `symbol_table`/`data_type_manager` are taken as direct parameters in place of
    /// `sym.getProgram()`, and for the `scanSymbolsByName` substitution.
    ///
    /// # Panics
    /// Panics if this symbol was not constructed via [`DataTypeSymbol::read_symbol`] (`sym` is
    /// still `None`), mirroring Java's `RuntimeException("not instantiated with readSymbol
    /// method")`.
    pub fn cleanup_unused_override(&self, symbol_table: &mut dyn SymbolTable, data_type_manager: &mut dyn DataTypeManager) {
        let sym = self
            .sym
            .as_ref()
            .expect("DataTypeSymbol.cleanupUnusedOverride() called before readSymbol (sym == null); mirrors Java's RuntimeException(\"not instantiated with readSymbol method\")");
        // NOTE: Although the symbol may have just been deleted its name is still accessible
        // within its retained DB record in Java; this port simply reads the name that's there.
        let override_name = sym.get_name().to_string();
        let prefix = format!("{}_", self.nmroot);
        let hash_suffix = format!("_{}", Self::extract_hash(&override_name).unwrap_or_default());

        let mut iter = symbol_table.get_symbol_iterator(&format!("{prefix}*"), true);
        while let Some(s) = iter.next_symbol() {
            let n = s.get_name();
            if !n.starts_with(&prefix) {
                break; // stop scan
            }
            let is_override = s.get_parent_namespace().map(|ns| is_override_namespace(ns.as_ref())).unwrap_or(false);
            if s.get_symbol_type() == SymbolType::Label && n.ends_with(&hash_suffix) && is_override {
                return; // do nothing if any symbol found
            }
        }

        // remove unused override signature
        data_type_manager.remove(self.get_data_type());
    }

    /// Port of the static `DataTypeSymbol.readSymbol(String, Symbol)`. See the module docs for
    /// why `dtmanage` is taken directly rather than derived from `s.getProgram()`.
    ///
    /// # Panics
    /// Panics if `s` is not a `LABEL` symbol, mirroring Java's uncaught
    /// `IllegalArgumentException("Expected CODE symbol")`.
    pub fn read_symbol(cat: &str, s: Arc<dyn Symbol>, dtmanage: &dyn DataTypeManager) -> Option<DataTypeSymbol> {
        if s.get_symbol_type() != SymbolType::Label {
            panic!("Expected CODE symbol");
        }
        let hash = Self::extract_hash(s.get_name())?;
        let nmr = Self::extract_name_root(s.get_name());
        let path = CategoryPath::parse(cat).expect(
            "invalid category path (mirrors Java's uncaught IllegalArgumentException from `new \
             CategoryPath(String)`)",
        );
        let mut dt = dtmanage.get_data_type_in_category(&path, &format!("dt_{hash}"))?;
        if let Some(td) = dt.as_typedef() {
            dt = td.get_base_data_type();
        }
        if dt.as_function_definition().is_none() {
            return None;
        }

        let mut res = DataTypeSymbol::new(dt, nmr, cat.to_string());
        res.sym = Some(s);
        Some(res)
    }

    /// Port of the static `DataTypeSymbol.generateHash(DataType)`.
    pub fn generate_hash(dt: &dyn DataType) -> i32 {
        let material: Option<String> = if let Some(fd) = dt.as_function_definition() {
            Some(fd.get_prototype_string_with_calling_convention(true))
        } else if let Some(td) = dt.as_typedef() {
            Some(td.get_data_type().get_path_name())
        } else {
            None // No hash scheme
        };

        let mut hash: u32 = 0x12cf91ab; // Initial hash
        if let Some(material) = material {
            for unit in material.encode_utf16() {
                hash = SimpleCRC32::hash_one_byte(hash, unit as u32);
            }
        }
        hash as i32
    }

    /// Port of the static `DataTypeSymbol.extractHash(String)`.
    pub fn extract_hash(symname: &str) -> Option<String> {
        symname.rfind('_').map(|last| symname[last + 1..].to_string())
    }

    /// Port of the static `DataTypeSymbol.extractNameRoot(String)`.
    pub fn extract_name_root(symname: &str) -> String {
        match symname.find('_') {
            None => String::new(),
            Some(first) => symname[..first].to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_hash_and_name_root_split_on_first_and_last_underscore() {
        assert_eq!(DataTypeSymbol::extract_hash("prt_1000_abcdef"), Some("abcdef".to_string()));
        assert_eq!(DataTypeSymbol::extract_name_root("prt_1000_abcdef"), "prt".to_string());
    }

    #[test]
    fn extract_hash_returns_none_without_underscore() {
        assert_eq!(DataTypeSymbol::extract_hash("noUnderscoreHere"), None);
    }

    #[test]
    fn extract_name_root_returns_empty_string_without_underscore() {
        assert_eq!(DataTypeSymbol::extract_name_root("noUnderscoreHere"), String::new());
    }

    #[test]
    fn generate_hash_with_no_hash_scheme_returns_initial_hash() {
        struct PlainDt;
        impl DataType for PlainDt {}
        assert_eq!(DataTypeSymbol::generate_hash(&PlainDt), 0x12cf91ab_u32 as i32);
    }

    #[test]
    fn generate_hash_is_stable_and_content_sensitive_for_function_signatures() {
        let a = DataTypeSymbol::generate_hash(&FakeFuncDefWrapper("void foo(int)"));
        let b = DataTypeSymbol::generate_hash(&FakeFuncDefWrapper("void foo(int)"));
        let c = DataTypeSymbol::generate_hash(&FakeFuncDefWrapper("void bar(int)"));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    /// Minimal [`FunctionDefinition`](crate::program::model::data::function_definition::FunctionDefinition)
    /// used only to exercise [`DataTypeSymbol::generate_hash`]'s `FunctionSignature` branch:
    /// [`FunctionSignature::get_prototype_string_with_calling_convention`] is the only method
    /// `generate_hash` actually calls, so every other required method (never reached from that
    /// call path) is `unimplemented!()`.
    struct FakeFuncDefWrapper(&'static str);
    impl DataType for FakeFuncDefWrapper {
        fn as_function_definition(&self) -> Option<&dyn crate::program::model::data::function_definition::FunctionDefinition> {
            Some(self)
        }
    }
    impl crate::program::model::listing::FunctionSignature for FakeFuncDefWrapper {
        fn get_name(&self) -> String {
            unimplemented!()
        }
        fn get_prototype_string_with_calling_convention(&self, _include_calling_convention: bool) -> String {
            self.0.to_string()
        }
        fn get_arguments(&self) -> Vec<Box<dyn crate::program::model::data::parameter_definition::ParameterDefinition>> {
            unimplemented!()
        }
        fn get_return_type(&self) -> Box<dyn DataType> {
            unimplemented!()
        }
        fn get_comment(&self) -> Option<String> {
            unimplemented!()
        }
        fn has_var_args(&self) -> bool {
            unimplemented!()
        }
        fn has_no_return(&self) -> bool {
            unimplemented!()
        }
        fn get_calling_convention(&self) -> Option<Arc<crate::program::model::lang::prototype_model::PrototypeModel>> {
            unimplemented!()
        }
        fn get_calling_convention_name(&self) -> String {
            unimplemented!()
        }
        fn is_equivalent_signature(&self, _signature: &dyn crate::program::model::listing::FunctionSignature) -> bool {
            unimplemented!()
        }
    }
    impl crate::program::model::data::function_definition::FunctionDefinition for FakeFuncDefWrapper {
        fn set_arguments(&mut self, _args: Vec<Box<dyn crate::program::model::data::parameter_definition::ParameterDefinition>>) {
            unimplemented!()
        }
        fn set_return_type(&mut self, _data_type: Box<dyn DataType>) -> Result<(), String> {
            unimplemented!()
        }
        fn set_comment(&mut self, _comment: Option<String>) {
            unimplemented!()
        }
        fn set_var_args(&mut self, _has_var_args: bool) {
            unimplemented!()
        }
        fn set_no_return(&mut self, _has_no_return: bool) {
            unimplemented!()
        }
        #[allow(deprecated)]
        fn set_generic_calling_convention(
            &mut self,
            _generic_calling_convention: &dyn crate::program::seam_stubs::GenericCallingConvention,
        ) {
            unimplemented!()
        }
        fn set_calling_convention(&mut self, _convention_name: Option<String>) -> Result<(), InvalidInputException> {
            unimplemented!()
        }
        fn replace_argument(
            &mut self,
            _ordinal: i32,
            _name: Option<String>,
            _dt: Box<dyn DataType>,
            _comment: Option<String>,
            _source: crate::program::model::symbol::SourceType,
        ) {
            unimplemented!()
        }
    }

    #[test]
    fn new_stores_fields_with_no_symbol_yet() {
        let sym = DataTypeSymbol::new(Box::new(PlaceholderDataType), "prt", "/auto_proto");
        assert!(sym.get_symbol().is_none());
    }

    #[test]
    #[should_panic(expected = "sym == null")]
    fn get_address_panics_without_a_symbol() {
        let sym = DataTypeSymbol::new(Box::new(PlaceholderDataType), "prt", "/auto_proto");
        let _ = sym.get_address();
    }

    #[test]
    #[should_panic(expected = "not instantiated with readSymbol")]
    fn cleanup_unused_override_panics_without_a_symbol() {
        struct NoopSymtab;
        impl SymbolTable for NoopSymtab {
            fn create_label(&mut self, _addr: &Address, _name: &str, _source: SourceType) -> std::io::Result<Arc<dyn Symbol>> {
                unimplemented!()
            }
            fn get_symbol(&self, _id: i64) -> std::io::Result<Option<Arc<dyn Symbol>>> {
                unimplemented!()
            }
            fn get_symbols(&self, _addr: &Address) -> std::io::Result<Vec<Arc<dyn Symbol>>> {
                unimplemented!()
            }
        }
        struct NoopDtm;
        impl DataTypeManager for NoopDtm {}

        let sym = DataTypeSymbol::new(Box::new(PlaceholderDataType), "prt", "/auto_proto");
        let mut symtab = NoopSymtab;
        let mut dtm = NoopDtm;
        sym.cleanup_unused_override(&mut symtab, &mut dtm);
    }
}
