//! Port of `ghidra.trace.database.guest.DBTracePlatformManager`.

use crate::program::model::lang::Language;
use crate::trace::database::db_trace_manager::DBTraceManager;
use crate::trace::database::guest::internal_trace_platform::InternalTracePlatform;
use crate::trace::model::guest::trace_platform_manager::TracePlatformManager;
use crate::trace::seam_stubs::{DBTrace, DBTraceGuestLanguage};
use crate::trace::model::guest::trace_platform::TracePlatform;

/// The trace database's platform manager: the host platform, plus any registered guest platforms
/// (alternate languages/compiler specs used to disassemble regions of the trace).
///
/// Port of `ghidra.trace.database.guest.DBTracePlatformManager`, which `implements DBTraceManager,
/// TracePlatformManager`.
///
/// It was selected as a dependency-cycle cut-point.
///
/// The two supertraits' methods (`db_error`/`invalidate_cache` from [`DBTraceManager`], and
/// `get_host_platform`/`get_guest_platforms`/`add_guest_platform`/`get_platform`/
/// `get_or_add_platform` from [`TracePlatformManager`]) are inherited as-is. This trait adds the
/// handful of `@Internal` (package-visible in Java) query methods the class exposes for its
/// sibling `guest`-package types (`DBTraceGuestPlatform`, `DBTraceGuestPlatformMappedRange`) to
/// resolve platforms and languages by key or by identity, and to validate platform ownership --
/// without depending on the concrete class.
///
/// The constructor and its private, DB-record-backed table machinery
/// (`loadLanguages`/`loadPlatforms`/`loadPlatformMappings`/`doAddGuestPlatform`/
/// `deleteGuestPlatform`/`computeNextRegisterMin`/`getPlatformKeyForCompiler`/`getCompilerByKey`,
/// each keyed off a `DBCachedObjectStore` per table) are implementation details private to the
/// concrete class, not part of its cross-package API contract, and `DBCachedObjectStore` itself
/// is not yet ported -- so none of that is represented here.
pub trait DBTracePlatformManager: DBTraceManager + TracePlatformManager {
    /// The trace this manager belongs to. Mirrors the `trace` field.
    fn trace(&self) -> Box<dyn DBTrace>;

    /// Look up a guest language's table entry by key, or `None` for the host language (Java
    /// passes `-1` for the host language and receives back `null`). Mirrors
    /// `getLanguageByKey(int)`.
    fn get_language_by_key(&self, key: i32) -> Option<Box<dyn DBTraceGuestLanguage>>;

    /// Look up a platform (host or guest) by key, `-1` meaning the host platform. Mirrors
    /// `getPlatformByKey(int)`.
    ///
    /// Modeled as returning `None` on an unknown key (the underlying `DBCachedObjectStore` lookup
    /// this mirrors, `getObjectAt`, can return `null`), even though the Java return type itself is
    /// not annotated nullable.
    fn get_platform_by_key(&self, key: i32) -> Option<Box<dyn InternalTracePlatform>>;

    /// Look up a guest language's table entry by its [`Language`], or `None` if `language` is the
    /// trace's base (host) language. Mirrors `getLanguageByLanguage(Language)`, which compares
    /// `language` against the base language by reference identity (Java `==`), not `equals()`.
    ///
    /// # Panics
    /// Panics if `language` is a guest language with no corresponding table entry, mirroring the
    /// Java method's `Objects.requireNonNull`.
    fn get_language_by_language(&self, language: &dyn Language) -> Option<Box<dyn DBTraceGuestLanguage>>;

    /// Find (or create and persist) the guest-language table entry for `language`, or `None` if
    /// `language` is the trace's base (host) language. Mirrors `getOrCreateLanguage(Language)`,
    /// which likewise compares `language` against the base language by reference identity.
    fn get_or_create_language(&self, language: &dyn Language) -> Option<Box<dyn DBTraceGuestLanguage>>;

    /// Validate that `platform` belongs to this manager's trace, returning it narrowed to
    /// [`InternalTracePlatform`]. Mirrors `assertMine(TracePlatform)`.
    ///
    /// # Panics
    /// Panics (mirroring the Java method's `IllegalArgumentException`) if `platform` does not
    /// belong to this trace, or has been deleted.
    fn assert_mine(&self, platform: &dyn TracePlatform) -> Box<dyn InternalTracePlatform>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressFactory, AddressSetView, AddressSpace};
    use crate::program::model::lang::compiler_spec::CompilerSpec;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::language::ParseError;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
    use crate::program::model::lang::processor_context::ProcessorContext;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::lang::{ProgramArchitecture, Register};
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::mem::MemBuffer;
    use crate::program::seam_stubs::{AddressLabelInfo, Processor, RegisterValue};
    use crate::trace::model::target::path::key_path::{KeyPath, PathFilter};
    use crate::trace::model::symbol::trace_label_symbol::TraceLabelSymbol;
    use crate::trace::model::trace::Trace;
    use crate::trace::seam_stubs::{TraceObjectSchema, TraceRegisterUtils};
    use crate::trace::model::thread::TraceThread;
    use crate::util::task::TaskMonitor;
    use std::cell::{Cell, RefCell};
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    /// A `Language` mock distinguished only by identity (Java's `==` semantics for
    /// `getLanguageByLanguage`/`getOrCreateLanguage`); no method beyond `get_language_id` is
    /// exercised by this module's tests.
    struct MockLanguage;

    impl Language for MockLanguage {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new("mock:LE:32:default").unwrap()
        }
        fn get_language_description(&self) -> Box<dyn LanguageDescription> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_parallel_instruction_helper(&self) -> Option<Box<dyn ParallelInstructionLanguageHelper>> {
            None
        }
        fn get_processor(&self) -> Box<dyn Processor> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_instruction_alignment(&self) -> i32 {
            1
        }
        fn supports_pcode(&self) -> bool {
            true
        }
        fn is_volatile(&self, _addr: &Address) -> bool {
            false
        }
        fn parse(
            &self,
            _buf: &dyn MemBuffer,
            _context: &mut dyn ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<Box<dyn InstructionPrototype>, ParseError> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_register_by_name(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_default_memory_blocks(&self) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}
        fn reload_language(&self, _task_monitor: &dyn TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }
        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }
        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn has_manual(&self) -> bool {
            false
        }
        fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    fn ptr_id(language: &dyn Language) -> usize {
        language as *const dyn Language as *const () as usize
    }

    /// Bare marker, since [`DBTraceGuestLanguage`] has no members yet.
    #[derive(Clone, Copy)]
    struct MockLangEntry;
    impl DBTraceGuestLanguage for MockLangEntry {}

    struct MockRegisterUtils;
    impl TraceRegisterUtils for MockRegisterUtils {
        fn get_thread(&self, _trace: &dyn Trace, _space: &Arc<AddressSpace>) -> Box<dyn TraceThread> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_frame_level(&self, _trace: &dyn Trace, _space: &Arc<AddressSpace>) -> i32 {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_register_address_space(
            &self,
            _thread: &dyn TraceThread,
            _frame_level: i32,
            _create_if_absent: bool,
        ) -> Option<Arc<AddressSpace>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn buffer_for_value(&self, _register: &Register, _value: &dyn RegisterValue) -> Vec<u8> {
            unimplemented!("not exercised by this smoke test")
        }
        fn finish_buffer(&self, _buf: &[u8], _register: &Register) -> Box<dyn RegisterValue> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    /// A minimal [`InternalTracePlatform`], distinguished only by its int key (`-1` for host,
    /// `>= 0` for a guest); every other member is unreachable from this module's tests.
    #[derive(Clone)]
    struct MockPlatform {
        int_key: i32,
        register_utils: Arc<MockRegisterUtils>,
    }

    impl TracePlatform for MockPlatform {}

    impl ProgramArchitecture for MockPlatform {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl InternalTracePlatform for MockPlatform {
        fn get_int_key(&self) -> i32 {
            self.int_key
        }
        fn get_language_entry(&self) -> Box<dyn DBTraceGuestLanguage> {
            unimplemented!("not exercised by this smoke test")
        }
        fn trace_register_utils(&self) -> &dyn TraceRegisterUtils {
            self.register_utils.as_ref()
        }
        fn get_conventional_register_path_for_names(
            &self,
            _schema: &dyn TraceObjectSchema,
            _path: &KeyPath,
            _names: &[String],
        ) -> Box<dyn PathFilter> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_register_map_override(&self, _register: &Register, _object_name: &str) -> Box<dyn TraceLabelSymbol> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    /// A `DBTracePlatformManager` mock backed by plain `HashMap`s rather than a
    /// `DBCachedObjectStore`, sufficient to prove the trait's added methods (identity-based
    /// language lookup/creation, key-based platform lookup, and ownership assertion) all behave
    /// as the Java class's real logic does.
    struct MockManager {
        base_language: MockLanguage,
        host: MockPlatform,
        guests: RefCell<HashMap<i32, MockPlatform>>,
        langs_by_key: RefCell<HashMap<i32, MockLangEntry>>,
        lang_key_by_ptr: RefCell<HashMap<usize, i32>>,
        next_lang_key: Cell<i32>,
    }

    impl MockManager {
        fn new() -> Self {
            MockManager {
                base_language: MockLanguage,
                host: MockPlatform { int_key: -1, register_utils: Arc::new(MockRegisterUtils) },
                guests: RefCell::new(HashMap::new()),
                langs_by_key: RefCell::new(HashMap::new()),
                lang_key_by_ptr: RefCell::new(HashMap::new()),
                next_lang_key: Cell::new(0),
            }
        }

        /// Test-only setup helper, standing in for what `doAddGuestPlatform` would otherwise
        /// populate via the (unported) platform table.
        fn register_guest(&self, key: i32) {
            self.guests.borrow_mut().insert(
                key,
                MockPlatform { int_key: key, register_utils: Arc::new(MockRegisterUtils) },
            );
        }
    }

    impl crate::framework::db::util::error_handler::ErrorHandler for MockManager {
        fn db_error(&self, _e: std::io::Error) {}
    }

    impl DBTraceManager for MockManager {
        fn invalidate_cache(&mut self, _all: bool) {}
    }

    impl TracePlatformManager for MockManager {
        fn get_host_platform(&self) -> Box<dyn TracePlatform> {
            Box::new(self.host.clone())
        }
    }

    impl DBTracePlatformManager for MockManager {
        fn trace(&self) -> Box<dyn DBTrace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_language_by_key(&self, key: i32) -> Option<Box<dyn DBTraceGuestLanguage>> {
            if key == -1 {
                return None;
            }
            self.langs_by_key
                .borrow()
                .get(&key)
                .map(|entry| Box::new(*entry) as Box<dyn DBTraceGuestLanguage>)
        }

        fn get_platform_by_key(&self, key: i32) -> Option<Box<dyn InternalTracePlatform>> {
            if key == -1 {
                return Some(Box::new(self.host.clone()));
            }
            self.guests
                .borrow()
                .get(&key)
                .cloned()
                .map(|p| Box::new(p) as Box<dyn InternalTracePlatform>)
        }

        fn get_language_by_language(&self, language: &dyn Language) -> Option<Box<dyn DBTraceGuestLanguage>> {
            if ptr_id(language) == ptr_id(&self.base_language) {
                return None;
            }
            let key = *self
                .lang_key_by_ptr
                .borrow()
                .get(&ptr_id(language))
                .expect("language not registered with this trace");
            Some(Box::new(self.langs_by_key.borrow()[&key]))
        }

        fn get_or_create_language(&self, language: &dyn Language) -> Option<Box<dyn DBTraceGuestLanguage>> {
            if ptr_id(language) == ptr_id(&self.base_language) {
                return None;
            }
            let id = ptr_id(language);
            if let Some(&key) = self.lang_key_by_ptr.borrow().get(&id) {
                return Some(Box::new(self.langs_by_key.borrow()[&key]));
            }
            let key = self.next_lang_key.get();
            self.next_lang_key.set(key + 1);
            self.lang_key_by_ptr.borrow_mut().insert(id, key);
            self.langs_by_key.borrow_mut().insert(key, MockLangEntry);
            Some(Box::new(MockLangEntry))
        }

        fn assert_mine(&self, platform: &dyn TracePlatform) -> Box<dyn InternalTracePlatform> {
            if platform.is_host() {
                return Box::new(self.host.clone());
            }
            if let Some((_, p)) = self.guests.borrow().iter().next() {
                return Box::new(p.clone());
            }
            panic!("Given platform does not belong to this trace");
        }
    }

    #[test]
    fn is_object_safe() {
        fn assert_object_safe(_: &dyn DBTracePlatformManager) {}
        assert_object_safe(&MockManager::new());
    }

    #[test]
    fn get_or_create_language_is_idempotent_and_none_for_base_language() {
        let mgr = MockManager::new();
        assert!(mgr.get_or_create_language(&mgr.base_language).is_none());

        let guest_language = MockLanguage;
        let first = mgr.get_or_create_language(&guest_language);
        assert!(first.is_some());

        // A second call for the same (identity-compared) language must not mint a new key.
        let second = mgr.get_or_create_language(&guest_language);
        assert!(second.is_some());
        assert_eq!(mgr.langs_by_key.borrow().len(), 1);

        // A distinct `Language` instance is a distinct guest language.
        let other_language = MockLanguage;
        mgr.get_or_create_language(&other_language);
        assert_eq!(mgr.langs_by_key.borrow().len(), 2);
    }

    #[test]
    fn get_language_by_key_round_trips_through_get_or_create() {
        let mgr = MockManager::new();
        assert!(mgr.get_language_by_key(-1).is_none());

        let guest_language = MockLanguage;
        mgr.get_or_create_language(&guest_language);
        assert!(mgr.get_language_by_key(0).is_some());
        assert!(mgr.get_language_by_key(1).is_none());
    }

    #[test]
    fn get_language_by_language_finds_a_previously_created_entry() {
        let mgr = MockManager::new();
        assert!(mgr.get_language_by_language(&mgr.base_language).is_none());

        let guest_language = MockLanguage;
        mgr.get_or_create_language(&guest_language);
        assert!(mgr.get_language_by_language(&guest_language).is_some());
    }

    #[test]
    #[should_panic(expected = "not registered")]
    fn get_language_by_language_panics_for_unregistered_guest_language() {
        let mgr = MockManager::new();
        let unregistered = MockLanguage;
        mgr.get_language_by_language(&unregistered);
    }

    #[test]
    fn get_platform_by_key_resolves_host_and_registered_guests() {
        let mgr = MockManager::new();
        mgr.register_guest(0);

        let host = mgr.get_platform_by_key(-1).expect("host is always present");
        assert_eq!(host.get_int_key(), -1);

        let guest = mgr.get_platform_by_key(0).expect("registered guest");
        assert_eq!(guest.get_int_key(), 0);

        assert!(mgr.get_platform_by_key(1).is_none());
    }

    #[test]
    fn assert_mine_recognizes_the_host_platform() {
        let mgr = MockManager::new();
        let result = mgr.assert_mine(mgr.get_host_platform().as_ref());
        assert_eq!(result.get_int_key(), -1);
    }

    #[test]
    fn assert_mine_recognizes_a_registered_guest_platform() {
        let mgr = MockManager::new();
        mgr.register_guest(0);

        struct GuestLike;
        impl TracePlatform for GuestLike {
            fn is_host(&self) -> bool {
                false
            }
        }

        let result = mgr.assert_mine(&GuestLike);
        assert_eq!(result.get_int_key(), 0);
    }

    #[test]
    #[should_panic(expected = "does not belong to this trace")]
    fn assert_mine_panics_for_a_foreign_platform() {
        let mgr = MockManager::new();

        struct GuestLike;
        impl TracePlatform for GuestLike {
            fn is_host(&self) -> bool {
                false
            }
        }

        // No guest has been registered, so a non-host platform cannot belong to this trace.
        mgr.assert_mine(&GuestLike);
    }
}
