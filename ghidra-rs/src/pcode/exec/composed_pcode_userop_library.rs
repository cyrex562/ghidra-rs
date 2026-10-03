//! A p-code userop library composed of other libraries.
//!
//! Corresponds to `ghidra.pcode.exec.ComposedPcodeUseropLibrary`.
//!
//! This crate previously stood this class up as a seam stub
//! (`crate::pcode::seam_stubs::ComposedPcodeUseropLibrary`) so that
//! [`PcodeUseropLibrary::compose_with_override`](crate::pcode::exec::pcode_userop_library::PcodeUseropLibrary::compose_with_override)
//! had something to construct before the real class was ported. This module is that real port;
//! [`PcodeUseropLibrary::compose_with_override`] now builds this type instead. The seam stub is
//! left in place (unused by anything in this crate) since touching it is outside this port's
//! scope.

use std::collections::HashMap;
use std::sync::Arc;

use crate::pcode::exec::pcode_userop_library::{
    ErasedPcodeUseropLibrary, PcodeUseropLibrary, UseropMap,
};

/// A p-code userop library composed of other libraries.
///
/// `T` is the type of values processed by the library.
pub struct ComposedPcodeUseropLibrary<T: 'static> {
    userops: UseropMap<T>,
}

impl<T: 'static> ComposedPcodeUseropLibrary<T> {
    /// Construct a composed userop library from the given libraries.
    ///
    /// Port of `ComposedPcodeUseropLibrary(Collection<PcodeUseropLibrary<T>>, boolean)`. This uses
    /// [`compose_userops`](Self::compose_userops), so its restrictions apply here too: name
    /// collisions are not allowed unless `override_` is set, in which case libraries later in
    /// `libraries` win over earlier ones.
    pub fn new(libraries: &[&dyn PcodeUseropLibrary<T>], override_: bool) -> Self {
        Self { userops: Self::compose_userops(libraries, override_) }
    }

    /// Construct the composed library directly over an already-merged map, as produced by
    /// [`compose_userops`](Self::compose_userops) or
    /// [`compose_userop_maps`](Self::compose_userop_maps).
    ///
    /// Not part of the Java class (whose only field is populated by its constructor); kept as a
    /// convenience for callers -- notably
    /// [`PcodeUseropLibrary::compose_with_override`](crate::pcode::exec::pcode_userop_library::PcodeUseropLibrary::compose_with_override)
    /// -- that already hold the merged map and would otherwise have to rebuild it.
    pub fn from_userops(userops: UseropMap<T>) -> Self {
        Self { userops }
    }

    /// Obtain a map representing the composition of userops from all the given libraries.
    ///
    /// Port of the static `composeUserops(Collection<PcodeUseropLibrary<T>>, boolean)`.
    ///
    /// Name collisions are not allowed. If any two libraries export the same symbol, even if the
    /// definitions happen to do the same thing, it is an error -- unless `override_` is set,
    /// allowing libraries later in `libraries` to override userops from libraries earlier in it.
    ///
    /// # Panics
    ///
    /// If two libraries export the same userop name and `override_` is `false`, matching Java's
    /// `IllegalArgumentException`.
    pub fn compose_userops(libraries: &[&dyn PcodeUseropLibrary<T>], override_: bool) -> UseropMap<T> {
        Self::compose_userop_maps(libraries.iter().map(|lib| lib.get_userops()), override_)
    }

    /// As [`compose_userops`](Self::compose_userops), but over the libraries' userop maps
    /// directly, for callers that hold the maps rather than the libraries.
    pub fn compose_userop_maps<'a>(
        maps: impl IntoIterator<Item = &'a UseropMap<T>>,
        override_: bool,
    ) -> UseropMap<T> {
        let mut userops: UseropMap<T> = HashMap::new();
        for map in maps {
            for def in map.values() {
                let existing = userops.insert(def.get_name().to_string(), Arc::clone(def));
                if existing.is_some() && !override_ {
                    panic!(
                        "Cannot compose libraries with conflicting definitions on {}",
                        def.get_name()
                    );
                }
            }
        }
        userops
    }
}

impl<T: 'static> ErasedPcodeUseropLibrary for ComposedPcodeUseropLibrary<T> {}

impl<T: 'static> PcodeUseropLibrary<T> for ComposedPcodeUseropLibrary<T> {
    fn get_userops(&self) -> &UseropMap<T> {
        &self.userops
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::exec::pcode_executor::PcodeExecutor;
    use crate::pcode::exec::pcode_userop_library::PcodeUseropDefinition;
    use crate::program::model::pcode::{PcodeOp, Varnode};
    use std::any::TypeId;

    /// A minimal userop definition, carrying only the name the tests assert on.
    struct NamedUserop {
        name: String,
    }

    impl NamedUserop {
        fn arc(name: &str) -> Arc<dyn PcodeUseropDefinition<i64>> {
            Arc::new(Self { name: name.to_string() })
        }
    }

    impl PcodeUseropDefinition<i64> for NamedUserop {
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_input_count(&self) -> i32 {
            0
        }
        fn execute(
            &self,
            _executor: &PcodeExecutor<i64>,
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
                userops: names.iter().map(|n| (n.to_string(), NamedUserop::arc(n))).collect(),
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

    #[test]
    fn composes_userops_from_every_library() {
        let a = MapLibrary::of(&["__a"]);
        let b = MapLibrary::of(&["__b", "__c"]);
        let composed = ComposedPcodeUseropLibrary::new(&[&a, &b], false);
        assert_eq!(sorted_names(&composed), vec!["__a", "__b", "__c"]);
    }

    #[test]
    fn empty_input_composes_to_an_empty_library() {
        let composed: ComposedPcodeUseropLibrary<i64> = ComposedPcodeUseropLibrary::new(&[], false);
        assert!(composed.get_userops().is_empty());
    }

    #[test]
    #[should_panic(expected = "Cannot compose libraries with conflicting definitions on __dup")]
    fn conflicting_names_without_override_panics() {
        // Java: ComposedPcodeUseropLibrary.composeUserops throws IllegalArgumentException.
        let a = MapLibrary::of(&["__dup"]);
        let b = MapLibrary::of(&["__dup"]);
        ComposedPcodeUseropLibrary::new(&[&a, &b], false);
    }

    #[test]
    fn conflicting_names_with_override_lets_the_later_library_win() {
        let a = MapLibrary::of(&["__dup"]);
        let b = MapLibrary::of(&["__dup"]);
        let composed = ComposedPcodeUseropLibrary::new(&[&a, &b], true);
        // Both libraries define "__dup" with distinct instances; the later one (b's) should win.
        assert!(std::ptr::eq(
            Arc::as_ptr(&composed.get_userops()["__dup"]) as *const (),
            Arc::as_ptr(&b.get_userops()["__dup"]) as *const ()
        ));
    }

    #[test]
    fn compose_userop_maps_merges_maps_directly() {
        let a = MapLibrary::of(&["__x"]);
        let b = MapLibrary::of(&["__y"]);
        let merged =
            ComposedPcodeUseropLibrary::compose_userop_maps([a.get_userops(), b.get_userops()], false);
        let mut names: Vec<&String> = merged.keys().collect();
        names.sort();
        assert_eq!(names, vec!["__x", "__y"]);
    }

    #[test]
    fn from_userops_wraps_a_prebuilt_map_directly() {
        let a = MapLibrary::of(&["__z"]);
        let map = ComposedPcodeUseropLibrary::compose_userops(&[&a], false);
        let composed = ComposedPcodeUseropLibrary::from_userops(map);
        assert_eq!(sorted_names(&composed), vec!["__z"]);
    }
}
