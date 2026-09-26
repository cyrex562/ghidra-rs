//! Port of `ghidra.program.model.gclass.ClassID`.
//!
//! Unique ID of a program class type, pairing a [`CategoryPath`] with a [`SymbolPath`]. Per the
//! real Java doc comment: "Not sure if there will be different implementation for definition vs.
//! compiled vs. program vs. debug." -- and per an inline comment, the class deliberately avoids
//! `DataTypePath` since that "doesn't work in light of conflicts" (a `DataTypePath` built from a
//! not-yet-conflicted type can be invalidated once the type resolves to a `.conflict` name out
//! from underneath it).
//!
//! Java:
//!
//! ```java
//! public class ClassID implements Comparable<ClassID> {
//!     private final SymbolPath symbolPath;
//!     private final CategoryPath categoryPath;
//!     static final int classNameHash = Objects.hash(ClassID.class.getName());
//!
//!     public ClassID(CategoryPath categoryPath, SymbolPath symbolPath) { ... }
//!     public CategoryPath getCategoryPath() { ... }
//!     public SymbolPath getSymbolPath() { ... }
//!     public String toString() { return String.format("%s --- %s", categoryPath, symbolPath); }
//!     public int compareTo(ClassID o) { ... } // symbolPath first, then categoryPath
//!     public int hashCode() { return Objects.hash(categoryPath, symbolPath); }
//!     public boolean equals(Object obj) { ... }
//! }
//! ```
//!
//! `SymbolPath` in this crate is an object-safe trait (see
//! [`crate::app::util::symbol_path::SymbolPath`]) rather than a concrete class, so this port
//! stores it as `Box<dyn SymbolPath>` -- matching the storage convention already used by, e.g.,
//! `demangler::md_mang_utils` -- and delegates equality/ordering to the trait's own
//! [`equals_path`](crate::app::util::symbol_path::SymbolPath::equals_path)/
//! [`compare_to`](crate::app::util::symbol_path::SymbolPath::compare_to), which are themselves
//! ports of the real Java `SymbolPath.equals`/`SymbolPath.compareTo`.
//!
//! # `classNameHash`: dead code, faithfully preserved
//!
//! The real Java class declares `static final int classNameHash =
//! Objects.hash(ClassID.class.getName())` (`ClassID.java:35`), but nothing in the real Ghidra
//! codebase ever reads that field -- not even other methods of `ClassID` itself. It is inert,
//! write-only dead code. This port reproduces its *value* via [`class_name_hash`] (a function
//! rather than a `static`, since Rust has no direct equivalent of a lazily-computed-once
//! `static final int` initialized from a non-const expression without extra machinery that
//! nothing here would ever read), so the faithful-porting rule is honored without inventing a use
//! for a field the real class itself never uses.
//!
//! # `hashCode`/`Hash`: `dyn SymbolPath` has no `std::hash::Hash` impl
//!
//! `Box<dyn SymbolPath>` cannot derive `Hash` directly (trait objects can't implement `Hash` and
//! stay object-safe). Since `SymbolPath::path()` is built recursively from the exact same
//! `name()`/`parent()` chain that [`SymbolPath::equals_path`] compares structurally, two paths
//! that are `equals_path`-equal always produce the same `path()` string, so hashing on that string
//! preserves the `Hash`/`Eq` contract.

use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use crate::app::util::symbol_path::SymbolPath;
use crate::program::model::data::category_path::CategoryPath;

/// Unique ID of a Program Class Type. Port of `ghidra.program.model.gclass.ClassID`.
pub struct ClassID {
    symbol_path: Box<dyn SymbolPath>,
    category_path: CategoryPath,
}

impl ClassID {
    /// `ClassID(CategoryPath, SymbolPath)`.
    pub fn new(category_path: CategoryPath, symbol_path: Box<dyn SymbolPath>) -> Self {
        Self { category_path, symbol_path }
    }

    /// `getCategoryPath()`.
    pub fn get_category_path(&self) -> &CategoryPath {
        &self.category_path
    }

    /// `getSymbolPath()`.
    pub fn get_symbol_path(&self) -> &dyn SymbolPath {
        self.symbol_path.as_ref()
    }

    /// `compareTo(ClassID)`: compares `symbolPath` first, falling back to `categoryPath` only
    /// when the symbol paths compare equal.
    pub fn compare_to(&self, other: &ClassID) -> Ordering {
        let ret = self.symbol_path.compare_to(other.symbol_path.as_ref());
        if ret != Ordering::Equal {
            return ret;
        }
        self.category_path.cmp(&other.category_path)
    }
}

/// `toString()`: `"%s --- %s"` formatted from `categoryPath` then `symbolPath`.
///
/// Java's `CategoryPath.toString()` returns its `getPath()` value, and `SymbolPath.toString()`
/// returns its `getPath()` value; this crate's [`CategoryPath`]'s `Display` and
/// `dyn SymbolPath`'s `Display` (see `symbol_path.rs`) both mirror that, so `{}` formatting each
/// reproduces the Java output verbatim.
impl std::fmt::Display for ClassID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} --- {}", self.category_path, self.symbol_path)
    }
}

impl std::fmt::Debug for ClassID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClassID")
            .field("symbol_path", &self.symbol_path.path())
            .field("category_path", &self.category_path)
            .finish()
    }
}

impl PartialEq for ClassID {
    fn eq(&self, other: &Self) -> bool {
        self.category_path == other.category_path && self.symbol_path.equals_path(other.symbol_path.as_ref())
    }
}

impl Eq for ClassID {}

impl PartialOrd for ClassID {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.compare_to(other))
    }
}

impl Ord for ClassID {
    fn cmp(&self, other: &Self) -> Ordering {
        self.compare_to(other)
    }
}

impl Hash for ClassID {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // See the module docs: `dyn SymbolPath` isn't `Hash`, so its `path()` string (which is
        // structurally consistent with `equals_path`) stands in for it.
        self.category_path.hash(state);
        self.symbol_path.path().hash(state);
    }
}

/// Value of the real Java `static final int classNameHash = Objects.hash(ClassID.class.getName())`
/// (`ClassID.java:35`). See the module docs for why this is a dead-code field faithfully
/// reproduced despite having no readers anywhere in the real Ghidra codebase.
pub fn class_name_hash() -> i32 {
    // `Objects.hash(Object...)` for a single value is `Arrays.hashCode(new Object[]{value})`,
    // i.e. `31 * 1 + value.hashCode()`.
    31i32.wrapping_mul(1).wrapping_add(java_string_hash("ghidra.program.model.gclass.ClassID"))
}

/// Computes the Java `String.hashCode()` equivalent for a string. Mirrors the small local helper
/// of the same name duplicated elsewhere in this crate (e.g. `item_checkout_status.rs`,
/// `symbol_manager.rs`) rather than a shared utility.
fn java_string_hash(s: &str) -> i32 {
    let mut hash = 0i32;
    for c in s.encode_utf16() {
        hash = hash.wrapping_mul(31).wrapping_add(c as i32);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::symbol_path::SymbolPathNode;
    use std::collections::hash_map::DefaultHasher;

    fn sp(s: &str) -> Box<dyn SymbolPath> {
        Box::new(SymbolPathNode::parse(s).unwrap())
    }

    fn cat(s: &str) -> CategoryPath {
        CategoryPath::parse(s).unwrap()
    }

    #[test]
    fn accessors_return_constructor_arguments() {
        let id = ClassID::new(cat("/a/b"), sp("Foo::Bar"));
        assert_eq!(id.get_category_path(), &cat("/a/b"));
        assert_eq!(id.get_symbol_path().path(), "Foo::Bar");
    }

    #[test]
    fn to_string_formats_category_then_symbol_path_with_triple_dash() {
        let id = ClassID::new(cat("/a/b"), sp("Foo::Bar"));
        assert_eq!(id.to_string(), "/a/b --- Foo::Bar");
    }

    #[test]
    fn equal_when_both_paths_match() {
        let a = ClassID::new(cat("/a/b"), sp("Foo::Bar"));
        let b = ClassID::new(cat("/a/b"), sp("Foo::Bar"));
        assert_eq!(a, b);
    }

    #[test]
    fn not_equal_when_category_path_differs() {
        let a = ClassID::new(cat("/a/b"), sp("Foo::Bar"));
        let b = ClassID::new(cat("/a/c"), sp("Foo::Bar"));
        assert_ne!(a, b);
    }

    #[test]
    fn not_equal_when_symbol_path_differs() {
        let a = ClassID::new(cat("/a/b"), sp("Foo::Bar"));
        let b = ClassID::new(cat("/a/b"), sp("Foo::Baz"));
        assert_ne!(a, b);
    }

    #[test]
    fn equal_instances_hash_equal() {
        let a = ClassID::new(cat("/a/b"), sp("Foo::Bar"));
        let b = ClassID::new(cat("/a/b"), sp("Foo::Bar"));

        let mut ha = DefaultHasher::new();
        a.hash(&mut ha);
        let mut hb = DefaultHasher::new();
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn compare_to_prefers_symbol_path_over_category_path() {
        // Different symbolPath -> symbolPath ordering wins even though categoryPath ordering
        // would disagree ("/z" > "/a", but the symbolPath comparison decides first and is not
        // even consulted for categoryPath in this case since it doesn't tie).
        let a = ClassID::new(cat("/z"), sp("Foo::Aaa"));
        let b = ClassID::new(cat("/a"), sp("Foo::Bbb"));
        assert_eq!(a.compare_to(&b), Ordering::Less);
    }

    #[test]
    fn compare_to_falls_back_to_category_path_when_symbol_paths_are_equal() {
        let a = ClassID::new(cat("/a"), sp("Foo::Bar"));
        let b = ClassID::new(cat("/z"), sp("Foo::Bar"));
        assert_eq!(a.compare_to(&b), a.get_category_path().cmp(b.get_category_path()));
        assert_ne!(a.compare_to(&b), Ordering::Equal.then(Ordering::Greater));
        assert_eq!(a.compare_to(&b), Ordering::Less);
    }

    #[test]
    fn class_name_hash_matches_the_java_objects_hash_single_value_formula() {
        // Objects.hash("ghidra.program.model.gclass.ClassID") == 31 + name.hashCode().
        let expected = 31i32.wrapping_add(java_string_hash("ghidra.program.model.gclass.ClassID"));
        assert_eq!(class_name_hash(), expected);
        // Sanity: this dead field is deterministic across calls, as a real `static final` would
        // be, even though nothing in the real Ghidra codebase ever reads it.
        assert_eq!(class_name_hash(), class_name_hash());
    }
}
