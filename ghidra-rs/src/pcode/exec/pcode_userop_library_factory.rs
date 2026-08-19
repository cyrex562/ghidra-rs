//! A discoverable factory for creating a pluggable userop library, automatically picked up by the
//! default emulator.
//!
//! Corresponds to `ghidra.pcode.exec.PcodeUseropLibraryFactory`.
//!
//! Java discovers implementors via `ClassSearcher`, a classpath scan for `ExtensionPoint`
//! subclasses. Rust has no reflection/classpath scanning; following the convention already used
//! for other `ClassSearcher`-backed lookups (see
//! [`PluginUtils`](crate::framework::plugintool::util::PluginUtils) and
//! [`PluginsConfiguration`](crate::framework::plugintool::PluginsConfiguration)), the two
//! `create_userop_library_*` functions below take the candidate factories as an explicit slice
//! instead of discovering them via a classpath scan.
//!
//! Likewise, this crate's [`SleighLanguage`] port does not yet expose a `getProperty` accessor
//! (`Language::get_property`/`get_property_or` are not implemented for it), so
//! [`create_userop_library_for_language`] takes the language's `useropLibs` pspec value as an
//! explicit `useroplib_ids` parameter rather than reading it off `language` directly.

use std::collections::HashMap;

use crate::pcode::exec::pcode_arithmetic::PcodeArithmetic;
use crate::pcode::exec::pcode_userop_library::{nil, PcodeUseropLibrary};
use crate::program::model::lang::ghidra_language_property_keys::GhidraLanguagePropertyKeys;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::util::{ExtensionPoint, Msg};

/// Default implementor of [`GhidraLanguagePropertyKeys`], used only to read the standard
/// `useropLibs` key name without duplicating the string literal here.
struct DefaultLanguagePropertyKeys;

impl GhidraLanguagePropertyKeys for DefaultLanguagePropertyKeys {}

/// The property key for useropLib ids in pspec files. Port of `KEY_USEROP_LIBS`.
pub fn key_userop_libs() -> &'static str {
    DefaultLanguagePropertyKeys.useroplibs()
}

/// A discoverable factory for creating a pluggable userop library, automatically picked up by the
/// default emulator.
///
/// `T` is the type of values in the emulator's state (Java's per-`create`-method type parameter
/// `<T>`; hoisted onto the trait since a generic method isn't object-safe, and callers need
/// `dyn PcodeUseropLibraryFactory<T>` to select among factories discovered for a fixed `T`).
///
/// The Java doc requires "a public default constructor"; that requirement doesn't translate to
/// Rust (implementors are just registered by whatever holds the `factories` slice passed to
/// [`create_userop_library_from_id`]/[`create_userop_library_for_language`]).
pub trait PcodeUseropLibraryFactory<T: 'static>: ExtensionPoint {
    /// Get the id of this factory.
    ///
    /// Port of `getId()`. Java's default implementation reads the id off a `@UseropLibrary`
    /// annotation, logging a warning and returning `null` if the annotation is missing. Rust has
    /// no runtime annotations, so this becomes a required method that every implementor supplies
    /// directly.
    fn id(&self) -> &str;

    /// Create the userop library as identified for the given language and arithmetic.
    ///
    /// Port of `create(SleighLanguage, PcodeArithmetic<T>)`.
    fn create(
        &self,
        language: &SleighLanguage,
        arithmetic: &dyn PcodeArithmetic<T>,
    ) -> Box<dyn PcodeUseropLibrary<T>>;
}

/// Create the userop library as identified for the given language and arithmetic.
///
/// Port of `createUseropLibraryFromId(String, SleighLanguage, PcodeArithmetic)`. `factories`
/// stands in for the Java `ClassSearcher.getInstances(PcodeUseropLibraryFactory.class)` scan --
/// see the module docs.
///
/// If the given id cannot be found, an empty library ([`nil`]) is returned and a warning logged.
/// If multiple factories have the given id (this is considered a bug), then a warning is logged
/// and the first match in `factories` order is selected.
pub fn create_userop_library_from_id<T: 'static>(
    id: &str,
    language: &SleighLanguage,
    arithmetic: &dyn PcodeArithmetic<T>,
    factories: &[&dyn PcodeUseropLibraryFactory<T>],
) -> Box<dyn PcodeUseropLibrary<T>> {
    let matches: Vec<&dyn PcodeUseropLibraryFactory<T>> =
        factories.iter().copied().filter(|f| f.id() == id).collect();
    if matches.is_empty() {
        Msg::warn(
            "PcodeUseropLibraryFactory",
            &format!("No userop library with the id: {id}"),
        );
        return Box::new(nil::<T>());
    }
    if matches.len() > 1 {
        Msg::warn(
            "PcodeUseropLibraryFactory",
            &format!("Multiple userop libraries with the id: {id}. Selection is undefined."),
        );
    }
    matches[0].create(language, arithmetic)
}

/// Create the userop library for the given language.
///
/// Port of `createUseropLibraryForLanguage(SleighLanguage, PcodeArithmetic)`. This composes all
/// of the libraries named in `useroplib_ids` -- the language's pspec `useropLibs` property (see
/// [`key_userop_libs`]), a comma-separated list of ids -- in the order listed. `factories` stands
/// in for the Java `ClassSearcher.getInstances(PcodeUseropLibraryFactory.class)` scan -- see the
/// module docs.
///
/// Currently, duplicate userops (by name) are not permitted, so we compose libraries in the order
/// listed, in case that changes, as it would matter then.
pub fn create_userop_library_for_language<T: 'static>(
    language: &SleighLanguage,
    arithmetic: &dyn PcodeArithmetic<T>,
    useroplib_ids: &str,
    factories: &[&dyn PcodeUseropLibraryFactory<T>],
) -> Box<dyn PcodeUseropLibrary<T>> {
    let lib_ids: Vec<&str> = useroplib_ids.split(',').collect();
    let mut matches: HashMap<&str, &dyn PcodeUseropLibraryFactory<T>> = HashMap::new();
    for factory in factories.iter().copied() {
        if lib_ids.contains(&factory.id()) {
            matches.insert(factory.id(), factory);
        }
    }
    let mut result: Box<dyn PcodeUseropLibrary<T>> = Box::new(nil::<T>());
    for id in lib_ids {
        if let Some(factory) = matches.get(id) {
            let lib = factory.create(language, arithmetic);
            result = result.compose(lib.as_ref());
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::exec::pcode_userop_library::{
        ErasedPcodeUseropLibrary, PcodeUseropDefinition, UseropMap,
    };
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::pcode::{OpCode, PackedDecode};
    use std::sync::{Arc, Mutex};

    type Log = Arc<Mutex<Vec<&'static str>>>;

    /// A userop definition carrying just the name the library is keyed by; enough to observe
    /// which libraries' userops made it into a composition.
    struct NamedUserop(&'static str);

    impl PcodeUseropDefinition<i64> for NamedUserop {
        fn get_name(&self) -> &str {
            self.0
        }
        fn get_input_count(&self) -> i32 {
            0
        }
        fn execute(
            &self,
            _executor: &crate::pcode::exec::pcode_executor::PcodeExecutor<i64>,
            _library: &dyn PcodeUseropLibrary<i64>,
            _op: &crate::program::model::pcode::PcodeOp,
            _out_var: Option<&crate::program::model::pcode::Varnode>,
            _in_vars: &[crate::program::model::pcode::Varnode],
        ) {
            unimplemented!("test double is never invoked")
        }
        fn is_functional(&self) -> bool {
            true
        }
        fn has_side_effects(&self) -> bool {
            false
        }
        fn modifies_context(&self) -> bool {
            false
        }
        fn can_inline_pcode(&self) -> bool {
            false
        }
        fn get_output_type(&self) -> Option<std::any::TypeId> {
            None
        }
        fn get_java_method(&self) -> Option<()> {
            None
        }
        fn get_defining_library(&self) -> Option<&dyn ErasedPcodeUseropLibrary> {
            None
        }
    }

    /// A library defining exactly one userop, named after the factory that created it.
    struct NamedLibrary {
        userops: UseropMap<i64>,
    }

    impl NamedLibrary {
        fn new(name: &'static str) -> Self {
            Self {
                userops: [(name.to_string(), Arc::new(NamedUserop(name)) as Arc<dyn PcodeUseropDefinition<i64>>)]
                    .into_iter()
                    .collect(),
            }
        }
    }

    impl ErasedPcodeUseropLibrary for NamedLibrary {}

    impl PcodeUseropLibrary<i64> for NamedLibrary {
        fn get_userops(&self) -> &UseropMap<i64> {
            &self.userops
        }
    }

    fn sorted_names(lib: &dyn PcodeUseropLibrary<i64>) -> Vec<String> {
        let mut names: Vec<String> = lib.get_userops().keys().cloned().collect();
        names.sort();
        names
    }

    struct NamedFactory {
        id: &'static str,
        log: Log,
    }

    impl ExtensionPoint for NamedFactory {}

    impl PcodeUseropLibraryFactory<i64> for NamedFactory {
        fn id(&self) -> &str {
            self.id
        }

        /// Records that this factory was asked for a library, so the *order* in which libraries
        /// are composed is observable -- Java's documented "compose libraries in the order listed"
        /// behavior.
        fn create(&self, _language: &SleighLanguage, _arithmetic: &dyn PcodeArithmetic<i64>) -> Box<dyn PcodeUseropLibrary<i64>> {
            self.log.lock().unwrap().push(self.id);
            Box::new(NamedLibrary::new(self.id))
        }
    }

    /// Minimal arithmetic over `i64`, implementing only the methods `PcodeArithmetic` leaves
    /// abstract (mirroring the `LittleEndianBytesArithmetic` test fixture in `pcode_arithmetic`).
    /// Unused by the assertions below -- present only because `create` requires one.
    struct StubArithmetic;

    impl PcodeArithmetic<i64> for StubArithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }
        fn unary_op(&self, _opcode: OpCode, _sizeout: i32, _sizein1: i32, in1: &i64) -> i64 {
            *in1
        }
        fn binary_op(
            &self,
            _opcode: OpCode,
            _sizeout: i32,
            _sizein1: i32,
            in1: &i64,
            _sizein2: i32,
            _in2: &i64,
        ) -> i64 {
            *in1
        }
        fn mod_before_store(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &i64,
            _sizein_value: i32,
            in_value: &i64,
        ) -> i64 {
            *in_value
        }
        fn mod_after_load(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &i64,
            _sizein_value: i32,
            in_value: &i64,
        ) -> i64 {
            *in_value
        }
        fn from_const_bytes(&self, value: &[u8]) -> i64 {
            let mut bytes = [0u8; 8];
            let n = value.len().min(8);
            bytes[..n].copy_from_slice(&value[..n]);
            i64::from_le_bytes(bytes)
        }
        fn to_concrete(
            &self,
            value: &i64,
            _purpose: crate::pcode::exec::pcode_arithmetic::Purpose,
        ) -> Result<Vec<u8>, crate::pcode::exec::concretion_error::ConcretionError> {
            Ok(value.to_le_bytes().to_vec())
        }
        fn size_of(&self, _value: &i64) -> i64 {
            8
        }
    }

    /// Builds a minimal but real `SleighLanguage`, by feeding a hand-assembled packed-binary
    /// `<sleigh>` document through the crate's real `PackedDecode`. Identical to the fixture used
    /// by `abstract_sleigh_pcode_userop_definition`'s own `test_language`; `SleighLanguage`'s
    /// fields are private outside its module, so a literal construction isn't available here.
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

    #[allow(dead_code)]
    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        space.address(offset)
    }

    #[test]
    fn key_userop_libs_matches_java_pspec_key() {
        assert_eq!(key_userop_libs(), "useropLibs");
    }

    #[test]
    fn from_id_returns_nil_when_no_match() {
        let language = test_language();
        let arithmetic = StubArithmetic;
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let foo = NamedFactory { id: "foo", log: log.clone() };
        let factories: [&dyn PcodeUseropLibraryFactory<i64>; 1] = [&foo];

        let nil = create_userop_library_from_id("missing", &language, &arithmetic, &factories);
        // Java returns PcodeUseropLibrary.nil(): a library defining no userops. The non-matching
        // factory is never asked for one.
        assert!(nil.get_userops().is_empty());
        assert!(log.lock().unwrap().is_empty());
    }

    #[test]
    fn from_id_selects_the_matching_factory() {
        let language = test_language();
        let arithmetic = StubArithmetic;
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let foo = NamedFactory { id: "foo", log: log.clone() };
        let bar = NamedFactory { id: "bar", log: log.clone() };
        let factories: [&dyn PcodeUseropLibraryFactory<i64>; 2] = [&foo, &bar];

        let lib = create_userop_library_from_id("bar", &language, &arithmetic, &factories);
        assert_eq!(sorted_names(lib.as_ref()), vec!["bar"]);
        assert_eq!(*log.lock().unwrap(), vec!["bar"]);
    }

    #[test]
    fn for_language_composes_requested_ids_in_listed_order_and_skips_missing() {
        let language = test_language();
        let arithmetic = StubArithmetic;
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let foo = NamedFactory { id: "foo", log: log.clone() };
        let bar = NamedFactory { id: "bar", log: log.clone() };
        let baz = NamedFactory { id: "baz", log: log.clone() };
        // Registered out of request order, to prove composition follows `useroplib_ids`'s order,
        // not registration order. "missing" has no factory and Java silently skips it.
        let factories: [&dyn PcodeUseropLibraryFactory<i64>; 3] = [&baz, &bar, &foo];

        let result = create_userop_library_for_language(
            &language,
            &arithmetic,
            "foo,missing,bar,baz",
            &factories,
        );
        // Every requested library's userops are present in the composition...
        assert_eq!(sorted_names(result.as_ref()), vec!["bar", "baz", "foo"]);
        // ... and they were composed in the order the ids were listed.
        assert_eq!(*log.lock().unwrap(), vec!["foo", "bar", "baz"]);
    }
}
