//! Port of `ghidra.util.database.ObjectKey`: an opaque handle uniquely identifying a
//! database-backed object.
//!
//! The Java class wraps a `db.Table` reference (compared by *identity*, not `equals`) and a
//! `long` key, precomputing a combined hash from `System.identityHashCode(table)` and `key`.
//! `Table` instances in this crate are shared via `Arc<RwLock<Table>>` (see
//! [`DBHandle::get_table`](crate::framework::db::db_handle::DBHandle::get_table)), so identity is
//! expressed the same way as elsewhere in this crate (e.g.
//! [`Id`](crate::generic::id::Id)/[`TraceClosedPluginEvent`](crate::app::plugin::core::debug::event::trace_closed_plugin_event::TraceClosedPluginEvent)):
//! `Arc::ptr_eq` for identity equality, `Arc::as_ptr` for an identity-hash stand-in.
//!
//! # A genuine Java bug, reproduced faithfully
//!
//! `ObjectKey.compareTo` (lines 58-67 of the original) is:
//! ```java
//! public int compareTo(ObjectKey that) {
//!     int result;
//!     if (this.table != that.table) {
//!         return System.identityHashCode(this.table) - System.identityHashCode(that.table);
//!     }
//!     result = Long.compareUnsigned(this.key, that.key);
//!     if (result != 0) {
//!         return result;
//!     }
//!     return 0;
//! }
//! ```
//! Returning the *difference* of two hash codes from `compareTo`/`compare` is a well-known Java
//! antipattern: `int` subtraction silently wraps on overflow, which can violate the
//! `Comparable` contract's antisymmetry requirement (`sgn(x.compareTo(y)) ==
//! -sgn(y.compareTo(x))`) whenever the two hash codes are far enough apart. This port keeps the
//! exact same arithmetic -- see [`hash_diff`] and its test -- rather than silently upgrading it
//! to a well-behaved comparator.

use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, RwLock};

use crate::framework::db::Table;

/// An opaque handle uniquely identifying a database-backed object. Mirrors
/// `ghidra.util.database.ObjectKey`.
pub struct ObjectKey {
    table: Arc<RwLock<Table>>,
    key: i64,
}

impl ObjectKey {
    /// Mirrors `ObjectKey(Table, long)`.
    pub fn new(table: Arc<RwLock<Table>>, key: i64) -> Self {
        Self { table, key }
    }

    /// The wrapped table.
    pub fn table(&self) -> &Arc<RwLock<Table>> {
        &self.table
    }

    /// The wrapped key.
    pub fn key(&self) -> i64 {
        self.key
    }

    /// Stand-in for `System.identityHashCode(Object)` applied to the wrapped `Table`: the
    /// identity of the backing allocation, derived from the `Arc`'s pointer address (same idiom
    /// as [`TraceClosedPluginEvent::new`](crate::app::plugin::core::debug::event::trace_closed_plugin_event::TraceClosedPluginEvent::new)).
    fn identity_hash(table: &Arc<RwLock<Table>>) -> i32 {
        (Arc::as_ptr(table) as *const () as usize) as i32
    }

    /// Mirrors `ObjectKey.compareTo(ObjectKey)`, including its cross-table branch's overflow bug
    /// (see module docs).
    pub fn compare_to(&self, that: &ObjectKey) -> i32 {
        if !Arc::ptr_eq(&self.table, &that.table) {
            return hash_diff(Self::identity_hash(&self.table), Self::identity_hash(&that.table));
        }
        let result = compare_unsigned(self.key, that.key);
        if result != 0 {
            return result;
        }
        0
    }
}

/// The exact arithmetic from `ObjectKey.compareTo`'s cross-table branch: a plain `int`
/// subtraction of two identity hash codes, with no overflow guard. `i32::wrapping_sub` mirrors
/// Java `int` subtraction's own silent wraparound, so this reproduces the bug rather than fixing
/// it.
fn hash_diff(a: i32, b: i32) -> i32 {
    a.wrapping_sub(b)
}

/// Mirrors `Long.compareUnsigned(long, long)`, which the JDK implements as comparing `x +
/// Long.MIN_VALUE` against `y + Long.MIN_VALUE` -- equivalent to comparing the two values as
/// `u64`. Unlike the cross-table branch above, this one is a well-behaved three-way comparator.
fn compare_unsigned(a: i64, b: i64) -> i32 {
    match (a as u64).cmp(&(b as u64)) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

impl PartialEq for ObjectKey {
    /// Mirrors `ObjectKey.equals(Object)`: tables are compared by reference identity (`!=`), not
    /// `Table.equals`.
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.table, &other.table) && self.key == other.key
    }
}

impl Eq for ObjectKey {}

impl fmt::Debug for ObjectKey {
    /// `Table` (unlike Java's `Table`, whose default `toString` is always available) doesn't
    /// implement [`fmt::Debug`], so this formats the table by identity (matching how equality
    /// and hashing already treat it) rather than requiring a `Debug` bound on `Table` itself.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectKey")
            .field("table", &Arc::as_ptr(&self.table))
            .field("key", &self.key)
            .finish()
    }
}

impl Hash for ObjectKey {
    /// Mirrors `Objects.hash(System.identityHashCode(table), key)`: consistent with [`PartialEq`]
    /// above (same table identity + same key hash the same), though not bit-for-bit identical to
    /// the JVM's own hash algorithm -- nothing in this crate depends on the literal integer
    /// value, only on the hash/equals contract holding.
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.table).hash(state);
        self.key.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::buffer_mgr::BufferMgr;
    use crate::framework::db::schema::Schema;
    use crate::framework::db::FieldType;
    use std::collections::HashSet;

    fn make_table(name: &str) -> Arc<RwLock<Table>> {
        let schema = Arc::new(Schema::new(0, FieldType::Long, "key".to_string(), vec![], vec![], vec![]));
        let buffer_mgr = Arc::new(RwLock::new(BufferMgr::new(BufferMgr::DEFAULT_BUFFER_SIZE)));
        Arc::new(RwLock::new(Table::new(name.to_string(), schema, buffer_mgr)))
    }

    #[test]
    fn equal_when_same_table_identity_and_key() {
        let table = make_table("t1");
        let a = ObjectKey::new(table.clone(), 42);
        let b = ObjectKey::new(table.clone(), 42);
        assert_eq!(a, b);
    }

    #[test]
    fn not_equal_when_key_differs() {
        let table = make_table("t1");
        let a = ObjectKey::new(table.clone(), 1);
        let b = ObjectKey::new(table.clone(), 2);
        assert_ne!(a, b);
    }

    #[test]
    fn not_equal_when_table_differs_even_with_same_name_and_key() {
        // Mirrors the Java `this.table != that.table` reference check: two distinct `Table`
        // instances are never equal, regardless of their contents.
        let table_a = make_table("same_name");
        let table_b = make_table("same_name");
        let a = ObjectKey::new(table_a, 7);
        let b = ObjectKey::new(table_b, 7);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_consistent_with_eq() {
        let table = make_table("t1");
        let a = ObjectKey::new(table.clone(), 5);
        let b = ObjectKey::new(table.clone(), 5);
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    #[test]
    fn compare_to_same_table_orders_by_unsigned_key() {
        let table = make_table("t1");
        // -1i64 has a huge unsigned value, so it must sort *after* 1 despite being negative as
        // a signed long -- this is exactly what `Long.compareUnsigned` guarantees.
        let low = ObjectKey::new(table.clone(), 1);
        let high_unsigned = ObjectKey::new(table.clone(), -1);
        assert_eq!(low.compare_to(&high_unsigned), -1);
        assert_eq!(high_unsigned.compare_to(&low), 1);
    }

    #[test]
    fn compare_to_same_table_and_key_is_zero() {
        let table = make_table("t1");
        let a = ObjectKey::new(table.clone(), 99);
        let b = ObjectKey::new(table.clone(), 99);
        assert_eq!(a.compare_to(&b), 0);
    }

    #[test]
    fn compare_to_cross_table_uses_identity_hash_difference() {
        let table_a = make_table("a");
        let table_b = make_table("b");
        let x = ObjectKey::new(table_a, 0);
        let y = ObjectKey::new(table_b, 0);
        // Cross-table comparisons never consult the key at all, only table identity.
        assert_eq!(x.compare_to(&y), ObjectKey::identity_hash(&x.table).wrapping_sub(ObjectKey::identity_hash(&y.table)));
    }

    /// Faithfully reproduces the genuine Java bug in `ObjectKey.compareTo`'s cross-table branch
    /// (see module docs): returning `hashA - hashB` from a comparator can overflow `int` and
    /// violate the `Comparable` antisymmetry contract (`sgn(x.compareTo(y)) ==
    /// -sgn(y.compareTo(x))`).
    ///
    /// Concretely: `0 - i32::MIN` overflows to `i32::MIN` (its only representable "negation"),
    /// same as `i32::MIN - 0` is already `i32::MIN`. So *both* `hash_diff(MIN, 0)` and
    /// `hash_diff(0, MIN)` come out negative -- a real comparator must never agree on sign in
    /// both directions like this.
    #[test]
    fn hash_diff_reproduces_javas_compareto_overflow_bug() {
        let forward = hash_diff(i32::MIN, 0);
        let backward = hash_diff(0, i32::MIN);
        assert_eq!(forward, i32::MIN);
        assert_eq!(backward, i32::MIN);
        // Antisymmetry says these should have opposite signs; the bug means they don't.
        assert_eq!(forward.signum(), backward.signum());
    }

    #[test]
    fn table_and_key_accessors() {
        let table = make_table("t1");
        let key = ObjectKey::new(table.clone(), 123);
        assert!(Arc::ptr_eq(key.table(), &table));
        assert_eq!(key.key(), 123);
    }
}
