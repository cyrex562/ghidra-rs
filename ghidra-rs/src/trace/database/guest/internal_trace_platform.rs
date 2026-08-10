use std::sync::Arc;

use crate::program::model::address::{Address, AddressRange, AddressSpace};
use crate::program::model::lang::{ProgramArchitecture, Register};
use crate::program::model::symbol::Symbol;
use crate::trace::model::symbol::trace_label_symbol::TraceLabelSymbol;
use crate::trace::model::symbol::trace_label_symbol_view::TraceLabelSymbolView;
use crate::trace::model::symbol::trace_namespace_symbol_view::TraceNamespaceSymbolView;
use crate::trace::model::symbol::trace_symbol::TraceSymbol;
use crate::trace::model::symbol::trace_symbol_no_duplicates_view::TraceSymbolNoDuplicatesView;
use crate::trace::model::symbol::trace_symbol_with_location_view::TraceSymbolWithLocationView;
use crate::trace::model::target::path::key_path::{KeyPath, PathFilter};
use crate::trace::model::target::trace_object_manager::TraceObjectManager;
use crate::trace::model::trace::Trace;
use crate::trace::seam_stubs::{DBTraceGuestLanguage, TraceObjectSchema, TraceRegisterUtils};
use crate::trace::model::guest::trace_platform::TracePlatform;
use crate::trace::model::target::trace_object::TraceObject;

/// Namespace key used to look up (or register) the conventional register-object mapping for
/// big-endian registers. Mirrors `InternalTracePlatform.REG_MAP_BE`.
pub const REG_MAP_BE: &str = "__reg_map_be__";

/// Namespace key used to look up (or register) the conventional register-object mapping for
/// little-endian registers. Mirrors `InternalTracePlatform.REG_MAP_LE`.
pub const REG_MAP_LE: &str = "__reg_map_le__";

/// Picks [`REG_MAP_BE`] or [`REG_MAP_LE`] according to the register's endianness. Mirrors the
/// static `InternalTracePlatform.regMap(Register)`.
pub fn reg_map(register: &Register) -> &'static str {
    if register.is_big_endian() {
        REG_MAP_BE
    } else {
        REG_MAP_LE
    }
}

/// The internal (package-private in Java) extension of [`TracePlatform`] shared by the host and
/// guest platform implementations.
///
/// Port of `ghidra.trace.database.guest.InternalTracePlatform`.
///
/// It was selected as a dependency-cycle cut-point.
///
/// A few of the Java default methods are represented differently here:
///
/// * `getAddressFactory()` only exists in Java to resolve a diamond between `TracePlatform`'s
///   default (`getLanguage().getAddressFactory()`) and `ProgramArchitecture`'s abstract method of
///   the same signature. [`TracePlatform`](crate::trace::model::guest::trace_platform::TracePlatform)
///   names its equivalent `platform_address_factory` rather than `get_address_factory` precisely
///   to avoid that diamond, so there is no ambiguity to resolve in Rust: implementors simply
///   satisfy [`ProgramArchitecture::get_address_factory`] directly, and this trait does not
///   redeclare it.
///
/// * The four `getConventionalRegisterPath` overloads chain down to a leaf
///   (`getConventionalRegisterPath(TraceObjectSchema, KeyPath, Collection<String>)`) that walks a
///   schema's element/attribute tree (via `TraceObjectSchema.searchFor`) and builds a
///   `PathMatcher` from the results. Neither the schema-search machinery nor `PathMatcher` (a
///   concrete, fairly large implementation of
///   [`PathFilter`](crate::trace::model::target::path::key_path::PathFilter)) has been ported
///   yet, so that leaf is a required method here
///   ([`Self::get_conventional_register_path_for_names`]); the other three overloads are Rust
///   defaults that reduce to it exactly as the Java defaults do.
///
/// * `addRegisterMapOverride`'s Java default looks up (or creates) a namespace-typed global
///   symbol (`TraceNamespaceSymbol`) by name. The ported
///   [`TraceSymbolNoDuplicatesView::get_global_named`] (inherited by `namespaces()`) can only
///   return the interface's own upper bound,
///   `Arc<dyn `[`TraceSymbol`]`>`, since Rust has no covariant trait-method returns (the same
///   limitation documented on
///   [`TraceSymbolWithLocationView`](crate::trace::model::symbol::trace_symbol_with_location_view::TraceSymbolWithLocationView)).
///   That widened type cannot be used as the `&dyn `[`crate::trace::model::symbol::trace_namespace_symbol::TraceNamespaceSymbol`]``
///   parent required by `namespaces().add(..)` / `labels().create(..)`, so
///   [`Self::add_register_map_override`] is a required method here rather than a default.
///
/// * `getConventionalRegisterRange`'s Java default further validates/rewraps its result against
///   the given overlay space's overlay-vs-physical-space relationship (register-space overlay
///   wrapping, or a same-space assertion for memory-mapped registers). The concrete
///   [`AddressSpace`] port does not yet model overlay/physical spaces (see
///   `AbstractAddressSpace`'s overlay methods, which are not implemented for it), so
///   [`Self::get_conventional_register_range`] omits that validation; `overlay` is accepted for
///   API parity with the Java method (and the `TracePlatform` placeholder's own
///   `get_conventional_register_range`) but is currently unused.
///
///   Because [`TracePlatform`] already declares a same-named, same-signature
///   `get_conventional_register_range` (mirroring the Java override relationship this method
///   exists to express), a type implementing both traits must disambiguate calls with UFCS
///   (`InternalTracePlatform::get_conventional_register_range(&x, ..)`), exactly where Java would
///   otherwise resolve to the more specific override automatically.
pub trait InternalTracePlatform: TracePlatform + ProgramArchitecture {
    /// Get the entry's key in the table as an integer.
    fn get_int_key(&self) -> i32;

    /// Get this platform's guest-language table entry.
    fn get_language_entry(&self) -> Box<dyn DBTraceGuestLanguage>;

    /// The `TraceRegisterUtils` instance used to resolve a register's occupied address range.
    /// Mirrors the static `TraceRegisterUtils.rangeForRegister` call made by
    /// [`Self::get_conventional_register_range`]'s default.
    fn trace_register_utils(&self) -> &dyn TraceRegisterUtils;

    /// Get the conventional (host-mapped) address range occupied by the given platform register.
    /// Mirrors `getConventionalRegisterRange(AddressSpace, Register)`.
    ///
    /// # Panics
    /// Panics if `register` is not mapped to the host, mirroring the Java method's
    /// `IllegalArgumentException`.
    fn get_conventional_register_range(&self, overlay: &Arc<AddressSpace>, register: &Register) -> AddressRange {
        let _ = overlay;
        let guest_range = self.trace_register_utils().range_for_register(register);
        self.map_guest_to_host_range(&guest_range)
            .unwrap_or_else(|| panic!("Register {} is not mapped", register.name()))
    }

    /// List the register's name, its upper/lower-case variants, and the same for each alias, in
    /// insertion order with duplicates removed. Mirrors `InternalTracePlatform.listRegNames`.
    fn list_reg_names(&self, register: &Register) -> Vec<String> {
        let mut result: Vec<String> = Vec::new();
        let candidates = std::iter::once(register.name().to_string())
            .chain(std::iter::once(register.name().to_uppercase()))
            .chain(std::iter::once(register.name().to_lowercase()))
            .chain(
                register
                    .aliases()
                    .flat_map(|alias| [alias.clone(), alias.to_uppercase(), alias.to_lowercase()]),
            );
        for candidate in candidates {
            if !result.contains(&candidate) {
                result.push(candidate);
            }
        }
        result
    }

    /// Get the names or indices of the register object for the given platform register. Mirrors
    /// `getConventionalRegisterObjectNames`.
    fn get_conventional_register_object_names(&self, register: &Register) -> Vec<String> {
        let Some(host_min) = self.map_guest_to_host(register.address().clone()) else {
            return self.list_reg_names(register);
        };
        let symbol_manager = self.get_trace().get_symbol_manager();
        let Some(ns_reg_map_id) = symbol_manager
            .namespaces()
            .get_global_named(reg_map(register))
            .map(|s| Symbol::get_id(s.as_ref()))
        else {
            return self.list_reg_names(register);
        };
        let labels: Vec<String> = symbol_manager
            .labels()
            .get_at(0, &host_min, false)
            .into_iter()
            .filter(|s| {
                s.get_parent_trace_namespace()
                    .map(|ns| Symbol::get_id(ns.as_ref()))
                    == Some(ns_reg_map_id)
            })
            .map(|s| Symbol::get_name(s.as_ref()).to_string())
            .collect();
        if labels.is_empty() {
            self.list_reg_names(register)
        } else {
            labels
        }
    }

    /// Get the expected path where an object defining the register value would be, given the
    /// possible names of the register on the target. Mirrors
    /// `getConventionalRegisterPath(TraceObjectSchema, KeyPath, Collection<String>)`.
    ///
    /// This is the leaf of the four `getConventionalRegisterPath` overloads; see the trait-level
    /// documentation for why it is required rather than a default.
    fn get_conventional_register_path_for_names(
        &self,
        schema: &dyn TraceObjectSchema,
        path: &KeyPath,
        names: &[String],
    ) -> Box<dyn PathFilter>;

    /// Get the expected path where an object defining the register value would be. Mirrors
    /// `getConventionalRegisterPath(TraceObjectSchema, KeyPath, Register)`.
    fn get_conventional_register_path(
        &self,
        schema: &dyn TraceObjectSchema,
        path: &KeyPath,
        register: &Register,
    ) -> Box<dyn PathFilter> {
        let names = self.get_conventional_register_object_names(register);
        self.get_conventional_register_path_for_names(schema, path, &names)
    }

    /// Get the expected path where an object defining the register value would be, rooted at the
    /// given container object. Mirrors `getConventionalRegisterPath(TraceObject, Register)`.
    fn get_conventional_register_path_for_object(
        &self,
        container: &dyn TraceObject,
        register: &Register,
    ) -> Box<dyn PathFilter> {
        let schema = container.get_schema();
        let path = container.get_canonical_path();
        self.get_conventional_register_path(schema.as_ref(), &path, register)
    }

    /// Get the expected path where an object defining the register value would be, rooted at the
    /// trace's root schema. Mirrors `getConventionalRegisterPath(AddressSpace, Register)`.
    ///
    /// Returns `None` if the trace has no root schema, or if the root schema has no successor at
    /// `overlay`'s name -- both of which are `null` returns in the Java method.
    fn get_conventional_register_path_for_space(
        &self,
        overlay: &Arc<AddressSpace>,
        register: &Register,
    ) -> Option<Box<dyn PathFilter>> {
        let path = KeyPath::parse(overlay.name()).ok()?;
        let root_schema = self.get_trace().get_object_manager().get_root_schema()?;
        let schema = root_schema.get_successor_schema(&path)?;
        Some(self.get_conventional_register_path(schema.as_ref(), &path, register))
    }

    /// Add a label that conventionally maps the value of a `TraceRegister` in the object manager
    /// to a register from this platform. Mirrors `addRegisterMapOverride`.
    ///
    /// This is a required method rather than a default; see the trait-level documentation for
    /// why.
    ///
    /// # Panics
    /// Should panic (mirroring the Java method's `IllegalStateException`) if `register` is not
    /// mapped to the host.
    fn add_register_map_override(&self, register: &Register, object_name: &str) -> Box<dyn TraceLabelSymbol>;

    /// Get the address range covered by all registers in this platform's language, or `None` if
    /// the language has no register addresses. Mirrors `getRegistersRange`.
    fn get_registers_range(&self) -> Option<AddressRange> {
        let language = self.get_language();
        let register_space = language.get_address_factory().get_register_space()?;
        let register_addresses = language.get_register_addresses();
        let min = register_addresses
            .addresses_from(&register_space.min_address(), true)
            .next()?;
        let max = register_addresses
            .addresses_from(&register_space.max_address(), false)
            .next()?;
        Some(AddressRange::new(min, max))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressFactory, AddressSpaceType};
    use crate::program::model::lang::{CompilerSpec, Language};
    use crate::trace::seam_stubs::TraceThread;
    use std::cell::RefCell;
    use std::rc::Rc;

    fn make_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn make_register(space: &Arc<AddressSpace>, name: &str, offset: i64, num_bytes: i32, aliases: &[&str]) -> Rc<RefCell<Register>> {
        let reg = Register::new(name, "", space.address(offset), num_bytes, false, 0);
        for alias in aliases {
            reg.borrow_mut().add_alias(*alias);
        }
        reg
    }

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
        // `range_for_register` uses the trait's real default (computed from the register itself).

        fn buffer_for_value(
            &self,
            _register: &Register,
            _value: &dyn crate::program::seam_stubs::RegisterValue,
        ) -> Vec<u8> {
            unimplemented!("not exercised by this smoke test")
        }

        fn finish_buffer(
            &self,
            _buf: &[u8],
            _register: &Register,
        ) -> Box<dyn crate::program::seam_stubs::RegisterValue> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockPlatform {
        register_utils: MockRegisterUtils,
        host_shift: i64,
    }

    impl TracePlatform for MockPlatform {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn map_guest_to_host(&self, _address: Address) -> Option<Address> {
            // Forces `get_conventional_register_object_names`'s unmapped fallback branch.
            None
        }

        fn map_guest_to_host_range(&self, range: &AddressRange) -> Option<AddressRange> {
            Some(AddressRange::new(
                range.min_address().add_wrap(self.host_shift),
                range.max_address().add_wrap(self.host_shift),
            ))
        }
    }

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
            0
        }

        fn get_language_entry(&self) -> Box<dyn DBTraceGuestLanguage> {
            unimplemented!("not exercised by this smoke test")
        }

        fn trace_register_utils(&self) -> &dyn TraceRegisterUtils {
            &self.register_utils
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

    #[test]
    fn list_reg_names_dedupes_case_variants_and_puts_the_name_first() {
        let space = make_space();
        let reg = make_register(&space, "R0", 0, 4, &["zero", "ZR"]);
        let platform = MockPlatform {
            register_utils: MockRegisterUtils,
            host_shift: 0,
        };

        let names = platform.list_reg_names(&reg.borrow());

        // The register's own name and its case variants come first, in that order -- that part
        // is a real ordering guarantee, and Java's `getConventionalRegisterObjectNames` relies
        // on it.
        assert_eq!(&names[..2], &["R0", "r0"]);

        // The alias-derived names are NOT ordered. `Register::aliases` is a `HashSet`, exactly as
        // Java's `Register.aliases` is a `HashSet<String>`, so their relative order varies per
        // run. Asserting one made this test fail on roughly 40% of runs -- and because the
        // nightly gate parks any port that leaves a test failing, it parked six otherwise-good
        // ports in the hours after it landed. Assert the contract the code actually provides:
        // every alias contributes its own case variants, deduped.
        let mut aliases: Vec<&str> = names[2..].iter().map(String::as_str).collect();
        aliases.sort_unstable();
        assert_eq!(aliases, ["ZERO", "ZR", "zero", "zr"]);
    }

    #[test]
    fn list_reg_names_has_no_duplicates_for_all_uppercase_name() {
        let space = make_space();
        // An already-uppercase name collapses the name/upper variants into one entry.
        let reg = make_register(&space, "SP", 0, 4, &[]);
        let platform = MockPlatform {
            register_utils: MockRegisterUtils,
            host_shift: 0,
        };

        let names = platform.list_reg_names(&reg.borrow());
        assert_eq!(names, vec!["SP", "sp"]);
    }

    #[test]
    fn get_conventional_register_range_maps_through_platform_and_register_utils() {
        let space = make_space();
        let reg = make_register(&space, "R1", 0x100, 4, &[]);
        let platform = MockPlatform {
            register_utils: MockRegisterUtils,
            host_shift: 0x1000,
        };

        let range = InternalTracePlatform::get_conventional_register_range(&platform, &space, &reg.borrow());
        assert_eq!(range.min_address(), &space.address(0x100 + 0x1000));
        assert_eq!(range.max_address(), &space.address(0x103 + 0x1000));
    }

    #[test]
    #[should_panic(expected = "is not mapped")]
    fn get_conventional_register_range_panics_when_unmapped() {
        struct UnmappedPlatform(MockRegisterUtils);
        impl TracePlatform for UnmappedPlatform {
            fn get_trace(&self) -> Box<dyn Trace> {
                unimplemented!()
            }
            fn map_guest_to_host_range(&self, _range: &AddressRange) -> Option<AddressRange> {
                None
            }
        }
        impl ProgramArchitecture for UnmappedPlatform {
            fn get_language(&self) -> Box<dyn Language> {
                unimplemented!()
            }
            fn get_address_factory(&self) -> Box<dyn AddressFactory> {
                unimplemented!()
            }
            fn get_compiler_spec(&self) -> Box<dyn CompilerSpec> {
                unimplemented!()
            }
        }
        impl InternalTracePlatform for UnmappedPlatform {
            fn get_int_key(&self) -> i32 {
                0
            }
            fn get_language_entry(&self) -> Box<dyn DBTraceGuestLanguage> {
                unimplemented!()
            }
            fn trace_register_utils(&self) -> &dyn TraceRegisterUtils {
                &self.0
            }
            fn get_conventional_register_path_for_names(
                &self,
                _schema: &dyn TraceObjectSchema,
                _path: &KeyPath,
                _names: &[String],
            ) -> Box<dyn PathFilter> {
                unimplemented!()
            }
            fn add_register_map_override(&self, _register: &Register, _object_name: &str) -> Box<dyn TraceLabelSymbol> {
                unimplemented!()
            }
        }

        let space = make_space();
        let reg = make_register(&space, "R2", 0, 4, &[]);
        let platform = UnmappedPlatform(MockRegisterUtils);
        InternalTracePlatform::get_conventional_register_range(&platform, &space, &reg.borrow());
    }

    #[test]
    fn get_conventional_register_object_names_falls_back_when_unmapped() {
        let space = make_space();
        let reg = make_register(&space, "R3", 0, 4, &["thirdreg"]);
        let platform = MockPlatform {
            register_utils: MockRegisterUtils,
            host_shift: 0,
        };

        // `map_guest_to_host` returns `None` in this mock, so the default falls back to
        // `list_reg_names` without ever touching a trace/symbol manager.
        let names = platform.get_conventional_register_object_names(&reg.borrow());
        assert_eq!(names, platform.list_reg_names(&reg.borrow()));
    }

    #[test]
    fn is_object_safe() {
        fn assert_object_safe(_: &dyn InternalTracePlatform) {}
        let space = make_space();
        let reg = make_register(&space, "R4", 0, 4, &[]);
        let platform = MockPlatform {
            register_utils: MockRegisterUtils,
            host_shift: 0,
        };
        assert_object_safe(&platform);
        let _ = reg;
    }
}
