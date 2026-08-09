//! A "library" of p-code userops available to a p-code executor.
//!
//! Corresponds to `ghidra.pcode.exec.PcodeUseropLibrary`.
//!
//! The library can provide definitions of p-code userops already declared by the executor's
//! language as well as completely new userops accessible to Sleigh/p-code later compiled for the
//! executor. The recommended way to implement a library is to extend
//! `AnnotatedPcodeUseropLibrary` (not yet ported).
//!
//! Java's static `getOperandType(Class<?>)` resolves the library's `T` reflectively, at runtime,
//! from a `Class` object. Rust resolves `T` statically, so the reflective form has no analog; the
//! closest equivalent, [`operand_type`], simply reports the [`TypeId`] of a statically known `T`.

use std::any::TypeId;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use crate::decompiler::slghsymbol::user_op_symbol::UserOpSymbol;
use crate::pcode::seam_stubs::{ComposedPcodeUseropLibrary, PcodeExecutor};
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::pcode::{PcodeOp, Varnode};
use crate::sleigh::grammar::location::Location;

/// The userops of a library, keyed by (symbol) name.
///
/// Java's `Map<String, PcodeUseropDefinition<T>>`. The values are `Arc`s rather than plain boxes
/// because composing libraries (see [`PcodeUseropLibrary::compose`]) collects the definitions of
/// several libraries into one map without taking those libraries' definitions away from them --
/// exactly what Java gets for free from sharing references.
pub type UseropMap<T> = HashMap<String, Arc<dyn PcodeUseropDefinition<T>>>;

/// A library whose value type has been erased: the Rust rendering of Java's wildcard
/// `PcodeUseropLibrary<?>`.
///
/// Java's wildcard existential type (a library over *some* unknown value domain) has no
/// generic-preserving Rust shape, so, following the convention already used for
/// [`ErasedPcodeExecutorStatePiece`](crate::pcode::seam_stubs::ErasedPcodeExecutorStatePiece),
/// this is a bare, object-safe marker that every library also implements. It is a supertrait of
/// [`PcodeUseropLibrary`], so a generic `impl PcodeUseropLibrary<T>` (or a
/// `&dyn PcodeUseropLibrary<T>`) satisfies it without an explicit conversion.
///
/// Nothing in the crate inspects an erased library's members yet -- the one wildcard-typed
/// parameter,
/// [`SleighPcodeUseropDefinition::program_for`](crate::pcode::exec::sleigh_pcode_userop_definition::SleighPcodeUseropDefinition::program_for),
/// only forwards it to the not-yet-ported `SleighProgramCompiler`, which calls
/// [`PcodeUseropLibrary::get_symbols`] on it. When that lands, `get_symbols` (which does not
/// mention `T`) can move onto this trait.
pub trait ErasedPcodeUseropLibrary {}

/// The definition of a p-code userop.
///
/// `T` is the type of parameter accepted (and possibly returned) by the userop.
pub trait PcodeUseropDefinition<T: 'static> {
    /// Get the name of the userop.
    ///
    /// This is the symbol assigned to the userop when compiling new Sleigh code. It cannot
    /// conflict with existing userops (except those declared, but not defined, by the executor's
    /// language) or other symbols of the executor's language. If this userop is to be used
    /// generically across many languages, choose an unlikely name. Conventionally, these start
    /// with two underscores `__`.
    fn get_name(&self) -> &str;

    /// Get the number of *input* operands accepted by the userop, or -1 if it is variadic.
    fn get_input_count(&self) -> i32;

    /// Invoke/execute the userop.
    ///
    /// `library` is the complete library for this execution; note it may have been composed from
    /// more than the one defining this userop. `op` is the [`OpCode::CallOther`](crate::program::model::pcode::OpCode)
    /// op. `out_var` is the destination varnode for the userop's output when invoked as an rval,
    /// and `None` otherwise (Java's `null`). `in_vars` are the input varnodes as ordered in the
    /// source.
    fn execute(
        &self,
        executor: &dyn PcodeExecutor<T>,
        library: &dyn PcodeUseropLibrary<T>,
        op: &PcodeOp,
        out_var: Option<&Varnode>,
        in_vars: &[Varnode],
    );

    /// Invoke/execute the raw userop.
    ///
    /// Port of the `execute(PcodeExecutor, PcodeUseropLibrary, PcodeOp)` overload; Rust has no
    /// overloading, so it carries a distinct name.
    ///
    /// **NOTE:** The first input to the raw p-code op is the id of this userop. The userop inputs
    /// are thus at indices 1..N.
    fn execute_raw(
        &self,
        executor: &dyn PcodeExecutor<T>,
        library: &dyn PcodeUseropLibrary<T>,
        op: &PcodeOp,
    ) {
        self.execute(executor, library, op, op.output.as_ref(), &op.inputs[1..]);
    }

    /// Indicates whether this userop is a "pure function."
    ///
    /// This means all inputs are given in the arguments to the userop and the output, if
    /// applicable, is given via the return. Technically, this is only with respect to the emulated
    /// machine state. If the library carries its own state, and the userop is stateful with
    /// respect to the library, it is still okay to set this to true. When this is set to false,
    /// the underlying execution engine must ensure the machine state is consistent, because the
    /// userop may access any part of it directly.
    ///
    /// **WARNING:** The term "inputs" includes disassembly context, which can only be obtained out
    /// of band; userops that require it are *not* "pure functions."
    fn is_functional(&self) -> bool;

    /// Indicates whether this userop may have side effects.
    ///
    /// Even if [`is_functional`](Self::is_functional) is true, it is possible for a userop to have
    /// side effects, e.g., updating a field in a library or printing to the screen.
    fn has_side_effects(&self) -> bool;

    /// Indicates that this userop may modify the decode context.
    ///
    /// This means the userop may set a field in `contextreg`, which could thus affect how
    /// subsequent instructions are decoded. Executors which decode ahead must consider this.
    fn modifies_context(&self) -> bool;

    /// Indicates whether this userop definition produces p-code suitable for inlining in place of
    /// its invocation.
    ///
    /// Generally, if all the userop definition does is feed additional p-code to the executor with
    /// the same userop library, then it is suitable for inlining.
    fn can_inline_pcode(&self) -> bool;

    /// If this userop is defined as a native callback, get the type of the output.
    ///
    /// Java returns the `Class<?>` of the output parameter (or the callback's return type), and
    /// `null` when there is no callback. [`TypeId`] is Rust's runtime type handle, so this returns
    /// `Option<TypeId>`, `None` standing in for Java's `null`.
    fn get_output_type(&self) -> Option<TypeId>;

    /// If this userop is defined as a Java callback, get the method.
    ///
    /// Rust has no analog of `java.lang.reflect.Method`, so -- matching the convention already
    /// used by
    /// [`AbstractSleighPcodeUseropDefinitionBase::get_java_method`](crate::pcode::exec::abstract_sleigh_pcode_userop_definition::AbstractSleighPcodeUseropDefinitionBase::get_java_method)
    /// -- this carries no payload and is always `None` for ported definitions.
    fn get_java_method(&self) -> Option<()>;

    /// Get the library that defines (or "owns") this userop.
    ///
    /// A userop can become part of other composed libraries, so the library from which this userop
    /// was retrieved may not be the same as the one that defined it. This returns the one that
    /// defined it.
    ///
    /// As a special consideration, if this userop is a wrapper around another, and this wrapper
    /// returns the java method of the delegate, this *must* return the defining library of the
    /// delegate. If this is not defined by a native callback, this may be `None`.
    fn get_defining_library(&self) -> Option<&dyn ErasedPcodeUseropLibrary>;
}

/// A "library" of p-code userops available to a p-code executor.
///
/// `T` is the type of values accepted by the p-code userops.
pub trait PcodeUseropLibrary<T: 'static>: ErasedPcodeUseropLibrary {
    /// Get all the userops defined in this library, keyed by (symbol) name.
    ///
    /// Java hands back the library's own (usually unmodifiable) map; this borrows it, so a
    /// composing library can copy out the definition handles it needs without the library
    /// rebuilding a map per call.
    fn get_userops(&self) -> &UseropMap<T>;

    /// Compose this and the given library into a new library having all userops defined between
    /// the two, `override_` allowing `lib` to override userops from this library.
    ///
    /// Java short-circuits and returns `this` when handed `null` or the `NIL` singleton. Rust has
    /// no null, and `NIL` is not a singleton here (see [`nil`]), so this always builds the
    /// composed library; composing an empty library contributes no userops, so the result is
    /// equivalent.
    fn compose_with_override(
        &self,
        lib: &dyn PcodeUseropLibrary<T>,
        override_: bool,
    ) -> Box<dyn PcodeUseropLibrary<T>> {
        Box::new(ComposedPcodeUseropLibrary::from_userops(
            ComposedPcodeUseropLibrary::compose_userop_maps(
                [self.get_userops(), lib.get_userops()],
                override_,
            ),
        ))
    }

    /// Compose this and the given library into a new library, forbidding overrides.
    fn compose(&self, lib: &dyn PcodeUseropLibrary<T>) -> Box<dyn PcodeUseropLibrary<T>> {
        self.compose_with_override(lib, false)
    }

    /// Get named symbols defined by this library that are not already declared in `language`,
    /// keyed by the new userop index assigned to each.
    ///
    /// Indices continue from the count of userops the language already declares, and the library's
    /// userops are considered in name order (Java wraps the map in a `TreeMap`), so the assignment
    /// is deterministic. A userop whose name is already taken is skipped; real duplicates cause a
    /// warning during execution.
    ///
    /// Java reads the language's declared userop names via
    /// `SleighLanguage.getNumberOfUserDefinedOpNames()`/`getUserDefinedOpName(int)`. This crate's
    /// [`SleighLanguage`] does not expose those accessors, so the names are read from its symbol
    /// table's `user_ops` (the same list those accessors index into).
    fn get_symbols(&self, language: &SleighLanguage) -> HashMap<i32, UserOpSymbol> {
        let mut symbols = HashMap::new();
        let mut all_names: HashSet<String> = HashSet::new();
        let symtab = language.get_symbol_table();
        let lang_op_count = symtab.user_ops.len() as i32;
        for &id in &symtab.user_ops {
            if let Some(sym) = symtab.find_symbol(id) {
                all_names.insert(sym.header().name.clone());
            }
        }
        let mut next_op_no = lang_op_count;
        let by_name: BTreeMap<&String, &Arc<dyn PcodeUseropDefinition<T>>> =
            self.get_userops().iter().collect();
        for uop in by_name.values() {
            let op_name = uop.get_name();
            if !all_names.insert(op_name.to_string()) {
                // Real duplicates will cause a warning during execution
                continue;
            }
            let op_no = next_op_no;
            next_op_no += 1;
            // Java uses `getClass().getName()`; `type_name_of_val` is its Rust counterpart, and
            // resolves to the implementing type since default methods are monomorphized per impl.
            let loc = Location::new(
                format!("{}:{}", std::any::type_name_of_val(self), op_name),
                0,
            );
            let mut sym = UserOpSymbol::with_name(loc, op_name);
            sym.set_index(op_no);
            symbols.insert(op_no, sym);
        }
        symbols
    }
}

/// The empty userop library.
///
/// Executors cannot accept a "null" library. Instead, give them this one, via [`nil`].
pub struct EmptyPcodeUseropLibrary<T: 'static> {
    userops: UseropMap<T>,
}

impl<T: 'static> EmptyPcodeUseropLibrary<T> {
    /// Construct the empty library.
    pub fn new() -> Self {
        Self { userops: HashMap::new() }
    }
}

impl<T: 'static> Default for EmptyPcodeUseropLibrary<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: 'static> ErasedPcodeUseropLibrary for EmptyPcodeUseropLibrary<T> {}

impl<T: 'static> PcodeUseropLibrary<T> for EmptyPcodeUseropLibrary<T> {
    fn get_userops(&self) -> &UseropMap<T> {
        &self.userops
    }

    // Java also overrides `compose(lib)` here to hand back `lib` itself. That is an allocation
    // shortcut, not a behavioral difference: the inherited implementation composes nothing onto
    // `lib`'s userops, so the result is an equivalent library either way. Handing back `lib` is
    // not expressible from a borrow, so the shortcut is dropped.
}

/// The empty userop library, typed to match the executor's value type.
///
/// Java exposes a `NIL` singleton plus a `nil()` accessor that casts it, unchecked, to the caller's
/// `T`. Rust's generics make the cast unnecessary -- and unsound to imitate -- so this returns a
/// fresh (empty, so zero-allocation) library already typed as `T`.
pub fn nil<T: 'static>() -> EmptyPcodeUseropLibrary<T> {
    EmptyPcodeUseropLibrary::new()
}

/// Get the operand type `T` of a library.
///
/// Java's `getOperandType(Class<?>)` recovers `T` reflectively from a class, returning `null` for
/// a class that is not a library at all and `Object` for one implementing the raw type. Rust has
/// neither reflection nor raw types: a library's `T` is always statically known, so this just
/// reports its [`TypeId`].
pub fn operand_type<T: 'static>() -> TypeId {
    TypeId::of::<T>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::DefaultAddressFactory;
    use crate::program::model::pcode::PackedDecode;

    /// A minimal userop definition, carrying only the name and input count the tests assert on.
    struct NamedUserop {
        name: String,
        input_count: i32,
    }

    impl NamedUserop {
        fn arc(name: &str, input_count: i32) -> Arc<dyn PcodeUseropDefinition<i64>> {
            Arc::new(Self { name: name.to_string(), input_count })
        }
    }

    impl PcodeUseropDefinition<i64> for NamedUserop {
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_input_count(&self) -> i32 {
            self.input_count
        }
        fn execute(
            &self,
            _executor: &dyn PcodeExecutor<i64>,
            _library: &dyn PcodeUseropLibrary<i64>,
            _op: &PcodeOp,
            _out_var: Option<&Varnode>,
            _in_vars: &[Varnode],
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
        fn get_output_type(&self) -> Option<TypeId> {
            None
        }
        fn get_java_method(&self) -> Option<()> {
            None
        }
        fn get_defining_library(&self) -> Option<&dyn ErasedPcodeUseropLibrary> {
            None
        }
    }

    /// A library holding exactly the userops it was built with.
    struct MapLibrary {
        userops: UseropMap<i64>,
    }

    impl MapLibrary {
        fn of(names: &[&str]) -> Self {
            Self {
                userops: names
                    .iter()
                    .map(|n| (n.to_string(), NamedUserop::arc(n, 1)))
                    .collect(),
            }
        }
    }

    impl ErasedPcodeUseropLibrary for MapLibrary {}

    impl PcodeUseropLibrary<i64> for MapLibrary {
        fn get_userops(&self) -> &UseropMap<i64> {
            &self.userops
        }
    }

    fn sorted_names<T: 'static>(lib: &dyn PcodeUseropLibrary<T>) -> Vec<String> {
        let mut names: Vec<String> = lib.get_userops().keys().cloned().collect();
        names.sort();
        names
    }

    /// Builds a minimal but real `SleighLanguage` (declaring no userops of its own), by feeding a
    /// hand-assembled packed-binary `<sleigh>` document through the crate's real `PackedDecode`.
    /// Identical to the fixture used by `abstract_sleigh_pcode_userop_definition`;
    /// `SleighLanguage`'s fields are private outside its module, so a literal construction isn't
    /// available here.
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

    #[test]
    fn nil_library_defines_no_userops() {
        // Java: EmptyPcodeUseropLibrary.getUserops() returns Map.of()
        let library = nil::<i64>();
        assert!(library.get_userops().is_empty());
    }

    #[test]
    fn composing_with_nil_yields_the_other_librarys_userops() {
        // Java: NIL.compose(lib) == lib -- observationally, a library with exactly lib's userops.
        let lib = MapLibrary::of(&["__a", "__b"]);
        let composed = nil::<i64>().compose(&lib);
        assert_eq!(sorted_names(composed.as_ref()), vec!["__a", "__b"]);

        // ... and in the other direction, composing nil onto a library adds nothing.
        let composed = lib.compose(&nil::<i64>());
        assert_eq!(sorted_names(composed.as_ref()), vec!["__a", "__b"]);
    }

    #[test]
    fn compose_unions_userops_of_both_libraries() {
        let left = MapLibrary::of(&["__a", "__b"]);
        let right = MapLibrary::of(&["__c"]);
        let composed = left.compose(&right);
        assert_eq!(sorted_names(composed.as_ref()), vec!["__a", "__b", "__c"]);
    }

    #[test]
    #[should_panic(expected = "Cannot compose libraries with conflicting definitions on __dup")]
    fn compose_rejects_conflicting_definitions_without_override() {
        // Java: ComposedPcodeUseropLibrary.composeUserops throws IllegalArgumentException.
        let left = MapLibrary::of(&["__dup"]);
        let right = MapLibrary::of(&["__dup"]);
        let _ = left.compose(&right);
    }

    #[test]
    fn compose_with_override_allows_the_right_library_to_win() {
        let left = MapLibrary { userops: [("__dup".to_string(), NamedUserop::arc("__dup", 1))].into_iter().collect() };
        let right = MapLibrary { userops: [("__dup".to_string(), NamedUserop::arc("__dup", 7))].into_iter().collect() };
        let composed = left.compose_with_override(&right, true);
        assert_eq!(sorted_names(composed.as_ref()), vec!["__dup"]);
        // The right library's definition (input count 7) replaced the left's (input count 1).
        assert_eq!(composed.get_userops()["__dup"].get_input_count(), 7);
    }

    #[test]
    fn get_symbols_numbers_userops_from_the_language_op_count_in_name_order() {
        // The fixture language declares no userops of its own, so indices start at 0, and Java's
        // `new TreeMap<>(getUserops())` fixes the order by name: __a -> 0, __b -> 1, __c -> 2.
        let language = test_language();
        assert_eq!(language.get_symbol_table().user_ops.len(), 0);

        let library = MapLibrary::of(&["__c", "__a", "__b"]);
        let symbols = library.get_symbols(&language);

        assert_eq!(symbols.len(), 3);
        assert_eq!(symbols[&0].symbol().name(), "__a");
        assert_eq!(symbols[&1].symbol().name(), "__b");
        assert_eq!(symbols[&2].symbol().name(), "__c");
        // Java sets each symbol's index to the key it is filed under.
        for (op_no, sym) in &symbols {
            assert_eq!(sym.index(), *op_no);
        }
    }

    #[test]
    fn get_symbols_of_the_empty_library_is_empty() {
        let language = test_language();
        assert!(nil::<i64>().get_symbols(&language).is_empty());
    }

    #[test]
    fn operand_type_reports_the_static_value_type() {
        // Java's getOperandType(cls) recovers T from the class; here T is statically known.
        assert_eq!(operand_type::<i64>(), TypeId::of::<i64>());
        assert_ne!(operand_type::<i64>(), TypeId::of::<Vec<u8>>());
    }
}
