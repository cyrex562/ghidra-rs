use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::listing::{CodeUnit, Data};
use crate::program::model::symbol::{
    DefaultSymbolUtilities, ExternalLocation, Namespace, SourceType, Symbol, SymbolType, SymbolUtilities,
};
use crate::program::util::ProgramLocation;

/// Value returned by [`CodeSymbol::get_object`], standing in for the polymorphic `Object` return
/// of `CodeSymbol.getObject()` (an `ExternalLocation`, a `CodeUnit`, or a `Data` primitive
/// component of the containing code unit).
pub enum CodeSymbolObject {
    External(Arc<dyn ExternalLocation>),
    CodeUnit(Arc<dyn CodeUnit>),
    Data(Box<dyn Data>),
}

/// Symbols that represent "labels" or external data locations.
///
/// Port of `ghidra.program.database.symbol.CodeSymbol` as a trait (cycle cut-point): the Java
/// class extends `MemorySymbol` (itself a `SymbolDB` subclass, still unported) and reaches back
/// into the owning `SymbolManager` for its `ExternalManagerDB`, `CodeManager`, and
/// `ReferenceManager`. Those construction-time wirings back into the symbol manager are what make
/// this class a cycle cut-point, so this port keeps only its overridden `Symbol`/`MemorySymbol`
/// contract as an object-safe trait extending [`Symbol`] directly (mirroring the
/// [`ClassSymbol`](crate::program::database::symbol::ClassSymbol) and
/// [`FunctionSymbol`](crate::program::database::symbol::FunctionSymbol) convention), rather than
/// modeling the `MemorySymbol`/`SymbolDB` superclass chain.
///
/// Behavior that in Java comes from calling `super.X()` (i.e. `MemorySymbol`/`SymbolDB`'s own
/// implementation) or reaches into `SymbolManager`'s collaborators is modeled as required methods
/// a concrete implementor supplies directly, rather than as a placeholder supertrait:
/// [`base_do_get_name`](Self::base_do_get_name), [`delete_with_option`](Self::delete_with_option),
/// [`check_is_primary`](Self::check_is_primary), [`code_unit_containing`](Self::code_unit_containing),
/// [`primary_symbol_at_address`](Self::primary_symbol_at_address),
/// [`demote_primary_symbol`](Self::demote_primary_symbol),
/// [`set_primary_flag`](Self::set_primary_flag),
/// [`notify_primary_symbol_set`](Self::notify_primary_symbol_set).
pub trait CodeSymbol: Symbol {
    /// Stands in for `CodeSymbol.getSymbolType()`, which always returns `SymbolType.LABEL`.
    fn get_symbol_type(&self) -> SymbolType {
        SymbolType::Label
    }

    /// Stands in for `CodeSymbol.delete()`: deletes the symbol, removing all references to its
    /// address unless it is external (in which case associated references are simply
    /// disassociated rather than removed).
    fn delete(&mut self) -> bool {
        let keep_references = !self.is_external();
        self.delete_with_option(keep_references)
    }

    /// Stands in for `CodeSymbol.delete(boolean)`. The real method conditionally calls
    /// `symbolMgr.getReferenceManager().removeAllReferencesTo(getAddress())` before delegating to
    /// `super.delete()` (`SymbolDB`'s own deletion, not modeled here); left required for the
    /// concrete implementation.
    fn delete_with_option(&mut self, keep_references: bool) -> bool;

    /// Stands in for `CodeSymbol.getObject()`: the `ExternalLocation`, containing `CodeUnit`, or
    /// primitive `Data` component this symbol represents.
    fn get_object(&self) -> Option<CodeSymbolObject> {
        if self.is_external() {
            return self.external_location().map(CodeSymbolObject::External);
        }
        let address = self.get_address();
        let cu = self.code_unit_containing(&address)?;
        if address == cu.get_min_address() {
            return Some(CodeSymbolObject::CodeUnit(cu));
        }
        let data = self.as_data(&cu)?;
        let offset = address.subtract(&data.get_min_address()) as i32;
        match data.get_primitive_at(offset) {
            Some(primitive) => Some(CodeSymbolObject::Data(primitive)),
            None => Some(CodeSymbolObject::CodeUnit(cu)),
        }
    }

    /// Accessor standing in for `symbolMgr.getExternalManager().getExternalLocation(this)`, used
    /// by [`get_object`](Self::get_object) when [`is_external`](Symbol::is_external) is `true`.
    /// Defaults to `None` so non-external implementors are unaffected.
    fn external_location(&self) -> Option<Arc<dyn ExternalLocation>> {
        None
    }

    /// Accessor standing in for `symbolMgr.getCodeManager().getCodeUnitContaining(address)`, used
    /// by [`get_object`](Self::get_object).
    fn code_unit_containing(&self, address: &Address) -> Option<Arc<dyn CodeUnit>>;

    /// Stands in for the `cu instanceof Data` downcast in `CodeSymbol.getObject()`, giving the
    /// `Data` view of `cu` when it is in fact data. Required because Rust trait objects cannot be
    /// downcast from `dyn CodeUnit` to `dyn Data` generically. Defaults to `None` (not data).
    fn as_data(&self, cu: &Arc<dyn CodeUnit>) -> Option<Box<dyn Data>> {
        let _ = cu;
        None
    }

    /// Stands in for `CodeSymbol.isPrimary()`: default-named and external symbols are always
    /// primary; otherwise defers to [`check_is_primary`](Self::check_is_primary).
    fn is_primary(&self) -> bool {
        if self.get_source() == SourceType::Default || self.is_external() {
            return true;
        }
        self.check_is_primary()
    }

    /// Accessor standing in for `SymbolDB.doCheckIsPrimary()`, used by
    /// [`is_primary`](Self::is_primary) for non-default, non-external symbols.
    fn check_is_primary(&self) -> bool;

    /// Stands in for `CodeSymbol.setPrimary()`: attempts to make this symbol the primary symbol
    /// at its address, demoting any existing primary `CodeSymbol` (but refusing if a
    /// `FunctionSymbol` already holds primacy, and refusing for external addresses or if this
    /// symbol is already primary).
    fn set_primary(&mut self) -> bool {
        if self.get_address().is_external_address() {
            return false;
        }
        if CodeSymbol::is_primary(self) {
            return false;
        }
        let old_primary = self.primary_symbol_at_address();
        if let Some(old) = &old_primary {
            if old.get_symbol_type() == SymbolType::Function {
                return false;
            }
            if old.get_symbol_type() == SymbolType::Label {
                self.demote_primary_symbol(old);
            }
        }
        self.set_primary_flag(true);
        self.notify_primary_symbol_set(old_primary);
        true
    }

    /// Accessor standing in for `symbolMgr.getPrimarySymbol(address)`, used by
    /// [`set_primary`](Self::set_primary).
    fn primary_symbol_at_address(&self) -> Option<Arc<dyn Symbol>>;

    /// Stands in for `((CodeSymbol) oldPrimarySymbol).setPrimary(false)`: demotes `old` (known to
    /// be a `SymbolType::Label` symbol) from primary status. Required because Rust trait objects
    /// cannot be downcast from `dyn Symbol` back to `dyn CodeSymbol` generically.
    fn demote_primary_symbol(&mut self, old: &Arc<dyn Symbol>);

    /// Stands in for the package-private `CodeSymbol.setPrimary(boolean)` /
    /// `SymbolDB.doSetPrimary(boolean)`, used to both promote (`true`) this symbol in
    /// [`set_primary`](Self::set_primary) and, via [`demote_primary_symbol`](Self::demote_primary_symbol),
    /// demote (`false`) another.
    fn set_primary_flag(&mut self, primary: bool);

    /// Accessor standing in for `symbolMgr.primarySymbolSet(this, oldPrimarySymbol)`, used by
    /// [`set_primary`](Self::set_primary) to notify the symbol manager of the change.
    fn notify_primary_symbol_set(&mut self, old_primary: Option<Arc<dyn Symbol>>);

    /// Stands in for `CodeSymbol.getProgramLocation()`, which builds a `LabelFieldLocation` for
    /// this symbol; not yet ported, so left required for the concrete implementation.
    fn get_program_location(&self) -> Option<Box<dyn ProgramLocation>>;

    /// Stands in for `CodeSymbol.isValidParent(Namespace)`. The real method combines
    /// `MemorySymbol.isValidParent(Namespace)` with `SymbolType.LABEL.isValidParent(Program,
    /// Namespace, Address, boolean)`, both of which depend on program/database state not
    /// available through this trait; left as a required method for the concrete implementation.
    fn is_valid_parent(&self, parent: &dyn Namespace) -> bool;

    /// Stands in for `CodeSymbol.doGetName()`: for default-named external symbols, defers to the
    /// external default-name convention; otherwise falls back to
    /// [`base_do_get_name`](Self::base_do_get_name) (`super.doGetName()`).
    fn do_get_name(&self) -> String {
        if self.get_source() == SourceType::Default && self.is_external() {
            if let Some(addr) = self.external_program_address() {
                return DefaultSymbolUtilities
                    .get_default_external_name(&addr, self.external_data_type_prefix().as_deref());
            }
        }
        self.base_do_get_name()
    }

    /// Accessor standing in for `MemorySymbol.getExternalProgramAddress()`, used by
    /// [`do_get_name`](Self::do_get_name)'s external-symbol branch. Defaults to `None`, matching
    /// non-external symbols (`is_external()` false).
    fn external_program_address(&self) -> Option<Address> {
        None
    }

    /// Accessor standing in for the data-type-name prefix resolved from `sym.getDataTypeId()` via
    /// the owning program's `DataTypeManager` in `ExternalManagerDB.getDefaultExternalName`.
    /// Defaults to `None` (no associated data type).
    fn external_data_type_prefix(&self) -> Option<String> {
        None
    }

    /// Accessor standing in for `super.doGetName()` (`SymbolDB`'s own stored-name lookup), used
    /// as the fallback in [`do_get_name`](Self::do_get_name).
    fn base_do_get_name(&self) -> String;

    /// Stands in for `CodeSymbol.validateNameSource(String, SourceType)`: non-external symbols
    /// promote a `DEFAULT` source to `ANALYSIS` and otherwise pass the source through unchanged;
    /// external symbols defer to [`validate_external_name_source`](Self::validate_external_name_source).
    fn validate_name_source(&self, new_name: Option<&str>, source: SourceType) -> SourceType {
        if !self.is_external() {
            if source == SourceType::Default {
                return SourceType::Analysis;
            }
            return source;
        }
        self.validate_external_name_source(new_name, source)
    }

    /// Accessor standing in for the external-symbol branch of `validateNameSource`:
    /// `SymbolUtilities.isReservedDynamicLabelName(newName,
    /// symbolMgr.getProgram().getAddressFactory())`, which depends on the owning program's
    /// `AddressFactory` not modeled here; left as a required method for the concrete
    /// implementation.
    fn validate_external_name_source(&self, new_name: Option<&str>, source: SourceType) -> SourceType;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn test_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn test_address(offset: i64) -> Address {
        Address::new(test_space(), offset)
    }

    struct MockSymbol {
        name: String,
        address: Address,
        source: SourceType,
        external: bool,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }
        fn get_source(&self) -> SourceType {
            self.source
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            1
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
        fn is_external(&self) -> bool {
            self.external
        }
    }

    struct MockCodeUnit {
        min: Address,
    }

    impl crate::program::seam_stubs::MemBuffer for MockCodeUnit {
        fn get_address(&self) -> Address {
            self.min.clone()
        }
    }

    impl crate::program::model::util::PropertySet for MockCodeUnit {}

    impl CodeUnit for MockCodeUnit {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            String::new()
        }
        fn get_label(&self) -> Option<String> {
            None
        }
        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            Vec::new()
        }
        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn get_min_address(&self) -> Address {
            self.min.clone()
        }
        fn get_max_address(&self) -> Address {
            self.min.clone()
        }
        fn get_mnemonic_string(&self) -> String {
            String::new()
        }
        fn get_comment(&self, _comment_type: crate::program::seam_stubs::CommentType) -> Option<String> {
            None
        }
        fn get_comment_as_array(
            &self,
            _comment_type: crate::program::seam_stubs::CommentType,
        ) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(
            &mut self,
            _comment_type: crate::program::seam_stubs::CommentType,
            _comment: Option<String>,
        ) {
        }
        fn set_comment_as_array(
            &mut self,
            _comment_type: crate::program::seam_stubs::CommentType,
            _comment: &[String],
        ) {
        }
        fn get_length(&self) -> i32 {
            1
        }
        fn get_bytes(&self) -> Result<Vec<u8>, crate::program::model::mem::MemoryAccessException> {
            Ok(Vec::new())
        }
        fn get_bytes_in_code_unit(
            &self,
            _buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), crate::program::model::mem::MemoryAccessException> {
            Ok(())
        }
        fn contains(&self, test_addr: &Address) -> bool {
            *test_addr == self.min
        }
        fn compare_to(&self, addr: &Address) -> i32 {
            if *addr == self.min {
                0
            } else {
                1
            }
        }
        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: crate::program::model::symbol::RefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}
        fn get_mnemonic_references(&self) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }
        fn get_operand_references(
            &self,
            _index: i32,
        ) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }
        fn get_primary_reference(
            &self,
            _index: i32,
        ) -> Option<Arc<dyn crate::program::model::symbol::Reference>> {
            None
        }
        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: crate::program::model::symbol::RefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}
        fn get_references_from(&self) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }
        fn get_reference_iterator_to(
            &self,
        ) -> Box<dyn crate::program::model::symbol::ReferenceIterator> {
            Box::new(crate::program::model::symbol::EmptyReferenceIterator)
        }
        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            unimplemented!("not exercised by CodeSymbol::get_object")
        }
        fn get_external_reference(
            &self,
            _op_index: i32,
        ) -> Option<Arc<dyn crate::program::model::symbol::ExternalReference>> {
            None
        }
        fn remove_external_reference(&mut self, _op_index: i32) {}
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn crate::program::model::symbol::Reference>) {}
        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: SourceType,
            _ref_type: crate::program::model::symbol::RefType,
        ) {
        }
        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &crate::program::model::lang::register::Register,
            _source_type: SourceType,
            _ref_type: crate::program::model::symbol::RefType,
        ) {
        }
        fn get_num_operands(&self) -> i32 {
            0
        }
        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }
        fn get_scalar(&self, _op_index: i32) -> Option<crate::program::model::scalar::Scalar> {
            None
        }
    }

    struct MockCodeSymbol {
        symbol: MockSymbol,
        cu: Option<Arc<MockCodeUnit>>,
        external_location: Option<Arc<dyn ExternalLocation>>,
        primary_symbol_at_address: Option<Arc<dyn Symbol>>,
        primary_flag: bool,
        demoted: Vec<i64>,
        notified: bool,
        check_is_primary: bool,
        external_program_address: Option<Address>,
        external_data_type_prefix: Option<String>,
    }

    impl Symbol for MockCodeSymbol {
        fn get_address(&self) -> Address {
            self.symbol.get_address()
        }
        fn get_name(&self) -> &str {
            self.symbol.get_name()
        }
        fn get_symbol_type(&self) -> SymbolType {
            CodeSymbol::get_symbol_type(self)
        }
        fn get_source(&self) -> SourceType {
            self.symbol.get_source()
        }
        fn is_primary(&self) -> bool {
            CodeSymbol::is_primary(self)
        }
        fn get_id(&self) -> i64 {
            self.symbol.get_id()
        }
        fn get_parent_id(&self) -> i64 {
            self.symbol.get_parent_id()
        }
        fn is_external(&self) -> bool {
            self.symbol.is_external()
        }
    }

    impl CodeSymbol for MockCodeSymbol {
        fn delete_with_option(&mut self, _keep_references: bool) -> bool {
            true
        }

        fn external_location(&self) -> Option<Arc<dyn ExternalLocation>> {
            self.external_location.clone()
        }

        fn code_unit_containing(&self, _address: &Address) -> Option<Arc<dyn CodeUnit>> {
            self.cu.clone().map(|cu| cu as Arc<dyn CodeUnit>)
        }

        fn check_is_primary(&self) -> bool {
            self.check_is_primary
        }

        fn primary_symbol_at_address(&self) -> Option<Arc<dyn Symbol>> {
            self.primary_symbol_at_address.clone()
        }

        fn demote_primary_symbol(&mut self, old: &Arc<dyn Symbol>) {
            self.demoted.push(old.get_id());
        }

        fn set_primary_flag(&mut self, primary: bool) {
            self.primary_flag = primary;
        }

        fn notify_primary_symbol_set(&mut self, _old_primary: Option<Arc<dyn Symbol>>) {
            self.notified = true;
        }

        fn get_program_location(&self) -> Option<Box<dyn ProgramLocation>> {
            None
        }

        fn is_valid_parent(&self, _parent: &dyn Namespace) -> bool {
            true
        }

        fn external_program_address(&self) -> Option<Address> {
            self.external_program_address.clone()
        }

        fn external_data_type_prefix(&self) -> Option<String> {
            self.external_data_type_prefix.clone()
        }

        fn base_do_get_name(&self) -> String {
            self.symbol.name.clone()
        }

        fn validate_external_name_source(
            &self,
            new_name: Option<&str>,
            source: SourceType,
        ) -> SourceType {
            match new_name {
                None => SourceType::Default,
                Some(name) if name.is_empty() => SourceType::Default,
                _ => source,
            }
        }
    }

    fn plain_symbol(name: &str, source: SourceType, external: bool) -> MockCodeSymbol {
        MockCodeSymbol {
            symbol: MockSymbol {
                name: name.to_string(),
                address: test_address(0x1000),
                source,
                external,
            },
            cu: None,
            external_location: None,
            primary_symbol_at_address: None,
            primary_flag: false,
            demoted: Vec::new(),
            notified: false,
            check_is_primary: false,
            external_program_address: None,
            external_data_type_prefix: None,
        }
    }

    #[test]
    fn defaults_match_java_code_symbol() {
        let sym = plain_symbol("LAB_1000", SourceType::UserDefined, false);
        assert_eq!(CodeSymbol::get_symbol_type(&sym), SymbolType::Label);
        assert!(!CodeSymbol::is_primary(&sym));
    }

    #[test]
    fn is_primary_true_for_default_source_or_external() {
        let default_named = plain_symbol("LAB_1000", SourceType::Default, false);
        assert!(CodeSymbol::is_primary(&default_named));

        let external = plain_symbol("EXT_1000", SourceType::UserDefined, true);
        assert!(CodeSymbol::is_primary(&external));

        let mut named = plain_symbol("named", SourceType::UserDefined, false);
        named.check_is_primary = true;
        assert!(CodeSymbol::is_primary(&named));
    }

    #[test]
    fn get_object_returns_code_unit_at_min_address() {
        let mut sym = plain_symbol("LAB_1000", SourceType::UserDefined, false);
        sym.cu = Some(Arc::new(MockCodeUnit {
            min: test_address(0x1000),
        }));

        match sym.get_object() {
            Some(CodeSymbolObject::CodeUnit(cu)) => {
                assert_eq!(cu.get_min_address(), test_address(0x1000));
            }
            _ => panic!("expected a CodeUnit"),
        }
    }

    #[test]
    fn get_object_returns_none_when_no_containing_code_unit() {
        let sym = plain_symbol("LAB_1000", SourceType::UserDefined, false);
        assert!(sym.get_object().is_none());
    }

    #[test]
    fn get_object_returns_external_location_when_external() {
        struct MockExternalLocation;
        impl ExternalLocation for MockExternalLocation {}

        let mut sym = plain_symbol("EXT_1000", SourceType::UserDefined, true);
        sym.external_location = Some(Arc::new(MockExternalLocation));

        assert!(matches!(
            sym.get_object(),
            Some(CodeSymbolObject::External(_))
        ));
    }

    #[test]
    fn set_primary_refuses_for_external_address() {
        let space = AddressSpace::new("EXTERNAL", 32, 1, AddressSpaceType::External, 2);
        let mut sym = plain_symbol("EXT_1000", SourceType::UserDefined, true);
        sym.symbol.address = Address::new(space, 0);

        assert!(!sym.set_primary());
        assert!(!sym.primary_flag);
    }

    #[test]
    fn set_primary_refuses_when_existing_primary_is_a_function_symbol() {
        struct MockFunctionSymbol;
        impl Symbol for MockFunctionSymbol {
            fn get_address(&self) -> Address {
                test_address(0x1000)
            }
            fn get_name(&self) -> &str {
                "some_func"
            }
            fn get_symbol_type(&self) -> SymbolType {
                SymbolType::Function
            }
            fn get_source(&self) -> SourceType {
                SourceType::UserDefined
            }
            fn is_primary(&self) -> bool {
                true
            }
            fn get_id(&self) -> i64 {
                42
            }
            fn get_parent_id(&self) -> i64 {
                -1
            }
        }

        let mut sym = plain_symbol("LAB_1000", SourceType::UserDefined, false);
        sym.primary_symbol_at_address = Some(Arc::new(MockFunctionSymbol));

        assert!(!sym.set_primary());
        assert!(!sym.primary_flag);
        assert!(sym.demoted.is_empty());
    }

    #[test]
    fn set_primary_demotes_existing_label_symbol_and_promotes_self() {
        let mut sym = plain_symbol("LAB_1000", SourceType::UserDefined, false);
        sym.primary_symbol_at_address = Some(Arc::new(MockSymbol {
            name: "old_label".to_string(),
            address: test_address(0x1000),
            source: SourceType::UserDefined,
            external: false,
        }));

        assert!(sym.set_primary());
        assert!(sym.primary_flag);
        assert_eq!(sym.demoted, vec![1]);
        assert!(sym.notified);
    }

    #[test]
    fn do_get_name_uses_external_default_name_for_default_external_symbols() {
        let mut sym = plain_symbol("ignored_when_default", SourceType::Default, true);
        sym.external_program_address = Some(test_address(0x1000));

        assert_eq!(
            sym.do_get_name(),
            DefaultSymbolUtilities.get_default_external_name(&test_address(0x1000), None)
        );

        sym.external_data_type_prefix = Some("char".to_string());
        assert_eq!(
            sym.do_get_name(),
            DefaultSymbolUtilities.get_default_external_name(&test_address(0x1000), Some("char"))
        );
    }

    #[test]
    fn do_get_name_falls_back_to_base_name_when_no_external_program_address() {
        let sym = plain_symbol("ignored_when_default", SourceType::Default, true);
        assert_eq!(sym.do_get_name(), "ignored_when_default");
    }

    #[test]
    fn do_get_name_falls_back_to_base_name_for_non_default_source() {
        let sym = plain_symbol("named_label", SourceType::UserDefined, false);
        assert_eq!(sym.do_get_name(), "named_label");
    }

    #[test]
    fn validate_name_source_promotes_default_to_analysis_for_non_external() {
        let sym = plain_symbol("named_label", SourceType::UserDefined, false);
        assert_eq!(
            sym.validate_name_source(Some("named_label"), SourceType::Default),
            SourceType::Analysis
        );
        assert_eq!(
            sym.validate_name_source(Some("named_label"), SourceType::UserDefined),
            SourceType::UserDefined
        );
    }

    #[test]
    fn validate_name_source_defers_to_external_check_for_external_symbols() {
        let sym = plain_symbol("EXT_1000", SourceType::UserDefined, true);
        assert_eq!(
            sym.validate_name_source(Some(""), SourceType::UserDefined),
            SourceType::Default
        );
        assert_eq!(
            sym.validate_name_source(Some("real_name"), SourceType::UserDefined),
            SourceType::UserDefined
        );
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let mut sym: Box<dyn CodeSymbol> =
            Box::new(plain_symbol("obj_safe_label", SourceType::UserDefined, false));
        assert_eq!(sym.get_name(), "obj_safe_label");
        assert!(sym.delete());
        assert!(sym.get_object().is_none());
    }
}
