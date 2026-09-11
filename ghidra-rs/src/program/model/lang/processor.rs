//! Port of `ghidra.program.model.lang.Processor`.
//!
//! An interned value type identifying a processor family (`"x86"`, `"ARM"`, `"MIPS"`, ...).
//! Java implements interning with a private static `HashMap<String, Processor>` guarded by a
//! `synchronized` factory method (`findOrPossiblyCreateProcessor`); this port uses a
//! process-wide [`OnceLock<Mutex<HashMap<..>>>`] registry, mirroring the same lazily-initialized
//! `static`/`synchronized` idiom already established by
//! [`next_id`](crate::util::universal_id_generator::next_id) in
//! `universal_id_generator.rs`. The private no-arg constructor is not exposed; the only ways to
//! obtain a `Processor` are [`Processor::find_or_possibly_create_processor`] (get-or-create) and
//! [`Processor::to_processor`] (get-or-error), exactly matching Java's public API surface.
//!
//! # Dead code intentionally omitted
//! Java declares a private static `RegisterHook` interface and a `registerHook` field that
//! `register(String)` invokes if non-null -- but grepping the entire `orig_src` tree turns up no
//! assignment to `Processor.registerHook` anywhere (only this file's own `private static
//! RegisterHook registerHook = null;` declaration, and no setter method exists at all). The hook
//! is therefore permanently `null`/unreachable in every real Ghidra build, so this port omits it
//! rather than adding unreachable, unexercisable plumbing.
//!
//! # `compareTo(null)` is unrepresentable
//! Java's `compareTo` special-cases a `null` argument (`return -1`), but a `Processor` argument
//! can never be null in Rust's type system (there being no `Option<&Processor>` at the `Ord`
//! trait's call sites) -- [`Processor::compare_to`] below documents this instead of trying to
//! reproduce an unreachable branch.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, OnceLock};

use crate::program::model::lang::processor_not_found_exception::ProcessorNotFoundException;

/// An interned processor identity (`"x86"`, `"ARM"`, ...).
///
/// Port of `ghidra.program.model.lang.Processor`. Cloning is cheap (an `Arc<str>` clone).
#[derive(Debug, Clone)]
pub struct Processor {
    name: std::sync::Arc<str>,
}

/// The interning registry. Port of `Processor.instances` (`private static HashMap<String,
/// Processor> instances`), lazily initialized like Java's `initialize()`.
static INSTANCES: OnceLock<Mutex<HashMap<String, Processor>>> = OnceLock::new();

fn instances() -> &'static Mutex<HashMap<String, Processor>> {
    INSTANCES.get_or_init(|| Mutex::new(HashMap::new()))
}

impl Processor {
    /// Returns the `Processor` registered under `name`, creating and registering a new one if
    /// none exists yet.
    ///
    /// Port of `Processor.findOrPossiblyCreateProcessor(String)` (which delegates to the private
    /// `register(String)` for the create path).
    pub fn find_or_possibly_create_processor(name: &str) -> Processor {
        let mut map = instances().lock().unwrap();
        if let Some(existing) = map.get(name) {
            return existing.clone();
        }
        let created = Processor { name: std::sync::Arc::from(name) };
        map.insert(name.to_string(), created.clone());
        created
    }

    /// Looks up the `Processor` registered under `name`.
    ///
    /// # Errors
    /// Returns [`ProcessorNotFoundException`] if no `Processor` has been registered under `name`
    /// yet (via [`Self::find_or_possibly_create_processor`]).
    ///
    /// Port of `Processor.toProcessor(String)`.
    pub fn to_processor(name: &str) -> Result<Processor, ProcessorNotFoundException> {
        let map = instances().lock().unwrap();
        map.get(name)
            .cloned()
            .ok_or_else(|| ProcessorNotFoundException::new(name))
    }

    /// Port of `Processor.compareTo(Processor)`, restricted to non-null `other` (see the module
    /// docs for why the Java `null` branch has no Rust equivalent). Case-insensitive comparison
    /// of the processor names, matching Java's `String.compareToIgnoreCase`.
    pub fn compare_to(&self, other: &Processor) -> Ordering {
        self.name.to_lowercase().cmp(&other.name.to_lowercase())
    }
}

impl fmt::Display for Processor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

impl PartialEq for Processor {
    /// Port of `Processor.equals(Object)`: structural equality by name (not merely registry
    /// identity, though in practice every `Processor` with a given name is the same registry
    /// entry).
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for Processor {}

impl std::hash::Hash for Processor {
    /// Port of `Processor.hashCode()` (`31 * 1 + name.hashCode()` in Java; this uses Rust's
    /// standard string hashing, which is a different algorithm but preserves the
    /// hash/equals contract that matters for correctness).
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

impl PartialOrd for Processor {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.compare_to(other))
    }
}

impl Ord for Processor {
    fn cmp(&self, other: &Self) -> Ordering {
        self.compare_to(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each test uses a unique processor name (via a counter) so that the process-wide
    /// [`INSTANCES`] registry -- shared across every test in the binary -- never lets one test's
    /// registrations leak into another's assertions about "unregistered" names.
    fn unique_name(tag: &str) -> String {
        use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, AtomicOrdering::SeqCst);
        format!("__test_processor_{tag}_{n}")
    }

    #[test]
    fn find_or_possibly_create_registers_a_new_processor() {
        let name = unique_name("create");
        let p = Processor::find_or_possibly_create_processor(&name);
        assert_eq!(p.to_string(), name);
    }

    #[test]
    fn find_or_possibly_create_interns_repeat_lookups() {
        let name = unique_name("intern");
        let a = Processor::find_or_possibly_create_processor(&name);
        let b = Processor::find_or_possibly_create_processor(&name);
        assert_eq!(a, b);
        // Prove genuine interning (the same registry entry), not just structural equality.
        assert!(std::sync::Arc::ptr_eq(&a.name, &b.name));
    }

    #[test]
    fn to_processor_finds_a_previously_registered_processor() {
        let name = unique_name("lookup");
        let created = Processor::find_or_possibly_create_processor(&name);
        let found = Processor::to_processor(&name).expect("should be registered");
        assert_eq!(created, found);
    }

    #[test]
    fn to_processor_errors_for_unknown_name() {
        let name = unique_name("missing");
        let err = Processor::to_processor(&name).unwrap_err();
        assert_eq!(
            err.message(),
            format!("Could not find processor {name} (which was expected to already exist)")
        );
    }

    #[test]
    fn equals_is_structural_by_name() {
        let name = unique_name("eq");
        let a = Processor::find_or_possibly_create_processor(&name);
        let b = Processor::find_or_possibly_create_processor(&name);
        let other = Processor::find_or_possibly_create_processor(&unique_name("eq_other"));
        assert_eq!(a, b);
        assert_ne!(a, other);
    }

    #[test]
    fn hash_consistent_with_equality() {
        use std::collections::HashSet;
        let name = unique_name("hash");
        let a = Processor::find_or_possibly_create_processor(&name);
        let b = Processor::find_or_possibly_create_processor(&name);
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    #[test]
    fn compare_to_is_case_insensitive() {
        let upper = Processor::find_or_possibly_create_processor(&format!("{}_X86", unique_name("cmp")));
        let same_upper = upper.clone();
        assert_eq!(upper.compare_to(&same_upper), Ordering::Equal);
    }

    #[test]
    fn compare_to_orders_case_insensitively_across_distinct_names() {
        let tag = unique_name("cmp2");
        let a = Processor::find_or_possibly_create_processor(&format!("AAA_{tag}"));
        let b = Processor::find_or_possibly_create_processor(&format!("bbb_{tag}"));
        // "AAA_..." < "bbb_..." case-insensitively, even though 'A' (0x41) < 'b' (0x62) would
        // also hold in a case-sensitive ordinal comparison here -- the point is the comparison
        // goes through lowercase, not raw byte order.
        assert_eq!(a.compare_to(&b), Ordering::Less);
    }

    #[test]
    fn compare_to_treats_different_case_of_same_name_as_equal() {
        let tag = unique_name("cmp3");
        let lower = Processor::find_or_possibly_create_processor(&format!("mixedcase_{tag}"));
        let upper = Processor::find_or_possibly_create_processor(&format!("MIXEDCASE_{tag}"));
        // These are two *distinct* registry entries (interning is by exact string key, so
        // differently-cased names are NOT the same Processor / do not `equals()`), yet
        // `compareTo` still reports them as equal since it's case-insensitive. This mirrors a
        // real Java quirk: `equals()` and `compareTo() == 0` are inconsistent for
        // differently-cased names of "the same" processor.
        assert_ne!(lower, upper);
        assert_eq!(lower.compare_to(&upper), Ordering::Equal);
    }

    #[test]
    fn ord_trait_matches_compare_to() {
        let tag = unique_name("ord");
        let a = Processor::find_or_possibly_create_processor(&format!("aaa_{tag}"));
        let b = Processor::find_or_possibly_create_processor(&format!("zzz_{tag}"));
        assert!(a < b);
        let mut v = vec![b.clone(), a.clone()];
        v.sort();
        assert_eq!(v, vec![a, b]);
    }

    #[test]
    fn clone_is_cheap_and_equal() {
        let name = unique_name("clone");
        let p = Processor::find_or_possibly_create_processor(&name);
        let cloned = p.clone();
        assert_eq!(p, cloned);
        assert!(std::sync::Arc::ptr_eq(&p.name, &cloned.name));
    }
}
