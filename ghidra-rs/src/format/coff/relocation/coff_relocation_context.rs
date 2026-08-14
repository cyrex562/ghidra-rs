use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use crate::format::relocation_exception::RelocationError;
use crate::format::seam_stubs::{CoffFileHeader, CoffRelocation, CoffSectionHeader};
use crate::program::model::address::Address;
use crate::program::model::listing::program::Program;
use crate::program::model::symbol::Symbol;

/// COFF relocation context data used by
/// [`CoffRelocationHandler`](crate::format::coff::relocation::coff_relocation_handler::CoffRelocationHandler)
/// during processing of relocations.
pub struct CoffRelocationContext {
    program: Arc<dyn Program>,
    header: Box<dyn CoffFileHeader>,
    /// Symbol lookup, keyed by COFF symbol-table index.
    ///
    /// Java keys this map by `CoffSymbol` object identity: `header.getSymbolAtIndex(index)`
    /// returns the same reference on every call, so looking the returned object back up in
    /// `Map<CoffSymbol, Symbol>` finds the entry originally inserted for that symbol. The
    /// unported `CoffFileHeader`/`CoffSymbol` seam stubs hand back a fresh `Box` per call and
    /// have no identity to key on, so this port keys directly by the index that produces that
    /// identity in Java -- an equivalent lookup once `symbols_map` is built consistently.
    symbols_map: HashMap<i64, Arc<dyn Symbol>>,
    section: Option<Box<dyn CoffSectionHeader>>,
    context_map: HashMap<String, Box<dyn Any + Send + Sync>>,
}

impl CoffRelocationContext {
    /// Construct COFF relocation context.
    ///
    /// # Arguments
    /// * `program` - program to which relocations are applied
    /// * `header` - COFF file header
    /// * `symbols_map` - symbol lookup, keyed by COFF symbol-table index
    pub fn new(
        program: Arc<dyn Program>,
        header: Box<dyn CoffFileHeader>,
        symbols_map: HashMap<i64, Arc<dyn Symbol>>,
    ) -> Self {
        Self {
            program,
            header,
            symbols_map,
            section: None,
            context_map: HashMap::new(),
        }
    }

    /// Reset context at start of COFF section relocation processing.
    pub fn reset_context(&mut self, coff_section: Box<dyn CoffSectionHeader>) {
        self.section = Some(coff_section);
        self.context_map.clear();
    }

    /// Get program to which relocations are being applied.
    pub fn get_program(&self) -> &Arc<dyn Program> {
        &self.program
    }

    /// Get COFF section to which relocations are being applied.
    pub fn get_section(&self) -> Option<&dyn CoffSectionHeader> {
        self.section.as_deref()
    }

    /// Get symbol required to process a relocation. Should only be invoked when a symbol is
    /// required, since some relocations may not require a symbol.
    ///
    /// # Errors
    /// Returns [`RelocationError`] if the symbol is not found.
    pub fn get_symbol(
        &self,
        relocation: &dyn CoffRelocation,
    ) -> Result<Arc<dyn Symbol>, RelocationError> {
        let index = relocation.get_symbol_index();
        // Exercise the header's index resolution for parity with Java (a real implementation
        // may lazily parse the symbol table here); see the `symbols_map` field doc for why the
        // returned value itself cannot be used as the map key through this seam.
        let _ = self.header.get_symbol_at_index(index);
        self.symbols_map
            .get(&index)
            .cloned()
            .ok_or_else(|| RelocationError::new("missing required symbol"))
    }

    /// Get address of symbol required to process a relocation. Should only be invoked when a
    /// symbol is required, since some relocations may not require a symbol.
    ///
    /// # Errors
    /// Returns [`RelocationError`] if the symbol is not found.
    pub fn get_symbol_address(
        &self,
        relocation: &dyn CoffRelocation,
    ) -> Result<Address, RelocationError> {
        Ok(self.get_symbol(relocation)?.get_address())
    }

    /// Get and, if absent, compute a context value for the specified key.
    pub fn compute_context_value_if_absent<F>(
        &mut self,
        key: &str,
        mapping_function: F,
    ) -> &(dyn Any + Send + Sync)
    where
        F: FnOnce(&str) -> Box<dyn Any + Send + Sync>,
    {
        if !self.context_map.contains_key(key) {
            let value = mapping_function(key);
            self.context_map.insert(key.to_string(), value);
        }
        self.context_map.get(key).unwrap().as_ref()
    }

    /// Store a context value for the specified key.
    pub fn put_context_value(&mut self, key: impl Into<String>, value: Box<dyn Any + Send + Sync>) {
        self.context_map.insert(key.into(), value);
    }

    /// Get the context value for the specified key, or `None` if absent.
    pub fn get_context_value(&self, key: &str) -> Option<&(dyn Any + Send + Sync)> {
        self.context_map.get(key).map(|v| v.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{SourceType, SymbolType};

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.coff".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
    }

    struct MockCoffFileHeader;
    impl CoffFileHeader for MockCoffFileHeader {
        fn get_magic(&self) -> i16 {
            0x014c
        }
        fn get_section_count(&self) -> i16 {
            0
        }
        fn get_timestamp(&self) -> i32 {
            0
        }
        fn get_symbol_table_pointer(&self) -> i32 {
            0
        }
        fn get_symbol_table_entries(&self) -> i32 {
            0
        }
        fn get_optional_header_size(&self) -> i16 {
            0
        }
        fn get_flags(&self) -> i16 {
            0
        }
        fn get_target_id(&self) -> std::io::Result<i16> {
            Ok(0)
        }
        fn get_image_base(&self, _: bool) -> i64 {
            0
        }
        fn get_machine_name(&self) -> String {
            String::new()
        }
        fn get_machine(&self) -> i16 {
            0x014c
        }
        fn parse_section_headers(&self) -> std::io::Result<()> {
            Ok(())
        }
        fn parse(&self, _: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_sections(&self) -> Vec<Box<dyn CoffSectionHeader>> {
            vec![]
        }
        fn get_symbols(&self) -> Vec<Box<dyn crate::format::seam_stubs::CoffSymbol>> {
            vec![]
        }
        fn get_symbol_at_index(&self, _: i64) -> Box<dyn crate::format::seam_stubs::CoffSymbol> {
            struct StubSymbol;
            impl crate::format::seam_stubs::CoffSymbol for StubSymbol {}
            Box::new(StubSymbol)
        }
        fn sizeof(&self) -> i32 {
            0
        }
        fn get_optional_header(&self) -> Box<dyn crate::format::seam_stubs::AoutHeader> {
            unimplemented!()
        }
        fn is_valid(&self) -> std::io::Result<bool> {
            Ok(true)
        }
        fn to_data_type(
            &self,
        ) -> std::io::Result<Box<dyn crate::program::model::data::data_type::DataType>> {
            Err(std::io::Error::new(std::io::ErrorKind::Other, "unimplemented"))
        }
    }

    struct MockRelocation {
        symbol_index: i64,
    }
    impl CoffRelocation for MockRelocation {
        fn sizeof(&self) -> i32 {
            10
        }
        fn get_address(&self) -> i64 {
            0x1000
        }
        fn get_symbol_index(&self) -> i64 {
            self.symbol_index
        }
        fn get_extended_address(&self) -> i16 {
            0
        }
        fn get_type(&self) -> i16 {
            0
        }
        fn to_data_type(
            &self,
        ) -> std::io::Result<Box<dyn crate::program::model::data::data_type::DataType>> {
            Err(std::io::Error::new(std::io::ErrorKind::Other, "unimplemented"))
        }
    }

    struct MockSymbol {
        address: Address,
    }
    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_name(&self) -> &str {
            "mock_symbol"
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }
        fn get_source(&self) -> SourceType {
            SourceType::Analysis
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            1
        }
        fn get_parent_id(&self) -> i64 {
            0
        }
    }

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    fn context_with_symbol(index: i64, address: Address) -> CoffRelocationContext {
        let mut symbols_map: HashMap<i64, Arc<dyn Symbol>> = HashMap::new();
        symbols_map.insert(index, Arc::new(MockSymbol { address }));
        CoffRelocationContext::new(
            Arc::new(MockProgram),
            Box::new(MockCoffFileHeader),
            symbols_map,
        )
    }

    #[test]
    fn get_symbol_returns_mapped_symbol() {
        let address = test_address(0x400000);
        let ctx = context_with_symbol(3, address.clone());
        let relocation = MockRelocation { symbol_index: 3 };

        let symbol = ctx.get_symbol(&relocation).expect("symbol should be found");
        assert_eq!(symbol.get_address(), address);
    }

    #[test]
    fn get_symbol_errors_when_missing() {
        let ctx = context_with_symbol(3, test_address(0x400000));
        let relocation = MockRelocation { symbol_index: 99 };

        let err = match ctx.get_symbol(&relocation) {
            Err(err) => err,
            Ok(_) => panic!("symbol should be missing"),
        };
        assert_eq!(err.message(), "missing required symbol");
    }

    #[test]
    fn get_symbol_address_matches_java_delegation() {
        let address = test_address(0x401000);
        let ctx = context_with_symbol(1, address.clone());
        let relocation = MockRelocation { symbol_index: 1 };

        let resolved = ctx.get_symbol_address(&relocation).expect("address should resolve");
        assert_eq!(resolved, address);
    }

    #[test]
    fn reset_context_replaces_section_and_clears_context_map() {
        struct StubSection;
        impl CoffSectionHeader for StubSection {}

        let mut ctx = context_with_symbol(1, test_address(0));
        ctx.put_context_value("k", Box::new(42i32));
        assert!(ctx.get_context_value("k").is_some());

        ctx.reset_context(Box::new(StubSection));

        assert!(ctx.get_context_value("k").is_none());
        assert!(ctx.get_section().is_some());
    }

    #[test]
    fn compute_context_value_if_absent_computes_once() {
        let mut ctx = context_with_symbol(1, test_address(0));
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        for _ in 0..2 {
            let calls = calls.clone();
            let value = ctx.compute_context_value_if_absent("k", move |_| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Box::new(7i32)
            });
            assert_eq!(value.downcast_ref::<i32>(), Some(&7));
        }

        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn put_context_value_overwrites_existing() {
        let mut ctx = context_with_symbol(1, test_address(0));
        ctx.put_context_value("k", Box::new(1i32));
        ctx.put_context_value("k", Box::new(2i32));

        let value = ctx.get_context_value("k").expect("value present");
        assert_eq!(value.downcast_ref::<i32>(), Some(&2));
    }

    #[test]
    fn get_program_returns_constructed_program() {
        let ctx = context_with_symbol(1, test_address(0));
        assert_eq!(Program::get_name(ctx.get_program().as_ref()), "mock.coff");
    }
}
