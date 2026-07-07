use std::marker::PhantomData;

/// A map from spatial data shapes (`DS`) to values (`T`), supporting spatial
/// queries (`Q`).
///
/// This is the primary interface for R-tree–backed maps used by the
/// debugging/trace infrastructure.
///
/// Java's `Map.Entry<DS, T>` is represented here as the tuple `(DS, T)`.
/// Java's two overloaded `remove` methods are split into
/// [`remove_shape_value`](SpatialMap::remove_shape_value) and
/// [`remove_entry`](SpatialMap::remove_entry).
///
/// Corresponds to `ghidra.util.database.spatial.SpatialMap`.
pub trait SpatialMap<DS, T, Q> {
    /// Put an entry into the map, returning the value as stored.
    ///
    /// The map may copy or modify the given value; the returned value is the
    /// authoritative stored form. This allows a "blank" entry to be created
    /// with a given shape and then populated by the caller.
    fn put(&mut self, shape: DS, value: T) -> T;

    /// Remove a single entry matching both `shape` and `value`.
    ///
    /// Returns `true` if the map was modified. Prefer
    /// [`remove_entry`](SpatialMap::remove_entry) when you hold a reference
    /// obtained directly from this map.
    ///
    /// Corresponds to `remove(DS, T)` in the Java source.
    fn remove_shape_value(&mut self, shape: &DS, value: &T) -> bool;

    /// Remove a previously-obtained `(shape, value)` entry from the map.
    ///
    /// When `entry` comes directly from this map the implementation may avoid
    /// a redundant search. Falls back to shape/value lookup otherwise.
    ///
    /// Corresponds to `remove(Entry<DS, T>)` in the Java source.
    fn remove_entry(&mut self, entry: &(DS, T)) -> bool;

    /// Returns the number of entries in the map.
    ///
    /// May not be a O(1) operation if this map is the result of
    /// [`reduce`](SpatialMap::reduce).
    fn size(&self) -> usize;

    /// Returns `true` if the map contains no entries.
    fn is_empty(&self) -> bool;

    /// Returns all `(shape, value)` entries.
    fn entries(&self) -> Vec<(DS, T)>;

    /// Returns all `(shape, value)` entries in sorted order.
    fn ordered_entries(&self) -> Vec<(DS, T)>;

    /// Returns all shape keys.
    fn keys(&self) -> Vec<DS>;

    /// Returns all shape keys in sorted order.
    fn ordered_keys(&self) -> Vec<DS>;

    /// Returns all values.
    fn values(&self) -> Vec<T>;

    /// Returns all values in sorted order.
    fn ordered_values(&self) -> Vec<T>;

    /// Returns a reduced view of this map containing only entries matched by
    /// `query`.
    fn reduce(&self, query: Q) -> Box<dyn SpatialMap<DS, T, Q>>;

    /// Returns the first `(shape, value)` entry, or `None` if empty.
    fn first_entry(&self) -> Option<(DS, T)>;

    /// Returns the first shape key, or `None` if empty.
    fn first_key(&self) -> Option<DS>;

    /// Returns the first value, or `None` if empty.
    fn first_value(&self) -> Option<T>;

    /// Removes all entries.
    fn clear(&mut self);
}

/// An immutable, always-empty [`SpatialMap`].
///
/// Mutation methods panic, mirroring the Java source which throws
/// `IllegalArgumentException` when callers attempt to modify the empty
/// singleton.
///
/// Corresponds to `ghidra.util.database.spatial.SpatialMap.EmptySpatialMap`.
pub struct EmptySpatialMap<DS, T, Q> {
    _phantom: PhantomData<(DS, T, Q)>,
}

impl<DS, T, Q> EmptySpatialMap<DS, T, Q> {
    /// Creates a new empty spatial map.
    pub fn new() -> Self {
        EmptySpatialMap { _phantom: PhantomData }
    }
}

impl<DS, T, Q> Default for EmptySpatialMap<DS, T, Q> {
    fn default() -> Self {
        Self::new()
    }
}

impl<DS: 'static, T: 'static, Q: 'static> SpatialMap<DS, T, Q> for EmptySpatialMap<DS, T, Q> {
    fn put(&mut self, _shape: DS, _value: T) -> T {
        panic!("cannot add to an empty spatial map")
    }

    fn remove_shape_value(&mut self, _shape: &DS, _value: &T) -> bool {
        panic!("cannot remove from an empty spatial map")
    }

    fn remove_entry(&mut self, _entry: &(DS, T)) -> bool {
        panic!("cannot remove from an empty spatial map")
    }

    fn size(&self) -> usize {
        0
    }

    fn is_empty(&self) -> bool {
        true
    }

    fn entries(&self) -> Vec<(DS, T)> {
        vec![]
    }

    fn ordered_entries(&self) -> Vec<(DS, T)> {
        vec![]
    }

    fn keys(&self) -> Vec<DS> {
        vec![]
    }

    fn ordered_keys(&self) -> Vec<DS> {
        vec![]
    }

    fn values(&self) -> Vec<T> {
        vec![]
    }

    fn ordered_values(&self) -> Vec<T> {
        vec![]
    }

    fn reduce(&self, _query: Q) -> Box<dyn SpatialMap<DS, T, Q>> {
        Box::new(EmptySpatialMap::new())
    }

    fn first_entry(&self) -> Option<(DS, T)> {
        None
    }

    fn first_key(&self) -> Option<DS> {
        None
    }

    fn first_value(&self) -> Option<T> {
        None
    }

    fn clear(&mut self) {
        // already empty — nothing to do
    }
}

/// Returns a boxed, always-empty [`SpatialMap`].
///
/// Corresponds to `SpatialMap.emptyMap()` in the Java source.
pub fn empty_map<DS: 'static, T: 'static, Q: 'static>() -> Box<dyn SpatialMap<DS, T, Q>> {
    Box::new(EmptySpatialMap::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Concrete types used as stand-ins for DS, T, Q in tests.
    #[derive(Debug, Clone, PartialEq)]
    struct Shape(i32);
    #[derive(Debug, Clone, PartialEq)]
    struct Value(String);
    #[derive(Debug)]
    struct AnyQuery;

    // ── EmptySpatialMap read methods ──────────────────────────────────────

    #[test]
    fn empty_map_size_is_zero() {
        let m: EmptySpatialMap<Shape, Value, AnyQuery> = EmptySpatialMap::new();
        assert_eq!(m.size(), 0);
    }

    #[test]
    fn empty_map_is_empty() {
        let m: EmptySpatialMap<Shape, Value, AnyQuery> = EmptySpatialMap::new();
        assert!(m.is_empty());
    }

    #[test]
    fn empty_map_entries_is_empty_vec() {
        let m: EmptySpatialMap<Shape, Value, AnyQuery> = EmptySpatialMap::new();
        assert!(m.entries().is_empty());
    }

    #[test]
    fn empty_map_ordered_entries_is_empty_vec() {
        let m: EmptySpatialMap<Shape, Value, AnyQuery> = EmptySpatialMap::new();
        assert!(m.ordered_entries().is_empty());
    }

    #[test]
    fn empty_map_keys_is_empty_vec() {
        let m: EmptySpatialMap<Shape, Value, AnyQuery> = EmptySpatialMap::new();
        assert!(m.keys().is_empty());
    }

    #[test]
    fn empty_map_ordered_keys_is_empty_vec() {
        let m: EmptySpatialMap<Shape, Value, AnyQuery> = EmptySpatialMap::new();
        assert!(m.ordered_keys().is_empty());
    }

    #[test]
    fn empty_map_values_is_empty_vec() {
        let m: EmptySpatialMap<Shape, Value, AnyQuery> = EmptySpatialMap::new();
        assert!(m.values().is_empty());
    }

    #[test]
    fn empty_map_ordered_values_is_empty_vec() {
        let m: EmptySpatialMap<Shape, Value, AnyQuery> = EmptySpatialMap::new();
        assert!(m.ordered_values().is_empty());
    }

    #[test]
    fn empty_map_first_entry_is_none() {
        let m: EmptySpatialMap<Shape, Value, AnyQuery> = EmptySpatialMap::new();
        assert!(m.first_entry().is_none());
    }

    #[test]
    fn empty_map_first_key_is_none() {
        let m: EmptySpatialMap<Shape, Value, AnyQuery> = EmptySpatialMap::new();
        assert!(m.first_key().is_none());
    }

    #[test]
    fn empty_map_first_value_is_none() {
        let m: EmptySpatialMap<Shape, Value, AnyQuery> = EmptySpatialMap::new();
        assert!(m.first_value().is_none());
    }

    #[test]
    fn empty_map_clear_is_noop() {
        let mut m: EmptySpatialMap<Shape, Value, AnyQuery> = EmptySpatialMap::new();
        m.clear(); // must not panic
        assert!(m.is_empty());
    }

    #[test]
    fn empty_map_reduce_returns_empty_map() {
        let m: EmptySpatialMap<Shape, Value, AnyQuery> = EmptySpatialMap::new();
        let reduced = m.reduce(AnyQuery);
        assert!(reduced.is_empty());
        assert_eq!(reduced.size(), 0);
    }

    // ── EmptySpatialMap mutation panics ───────────────────────────────────

    #[test]
    #[should_panic(expected = "cannot add to an empty spatial map")]
    fn empty_map_put_panics() {
        let mut m: EmptySpatialMap<Shape, Value, AnyQuery> = EmptySpatialMap::new();
        m.put(Shape(1), Value("x".into()));
    }

    #[test]
    #[should_panic(expected = "cannot remove from an empty spatial map")]
    fn empty_map_remove_shape_value_panics() {
        let mut m: EmptySpatialMap<Shape, Value, AnyQuery> = EmptySpatialMap::new();
        m.remove_shape_value(&Shape(1), &Value("x".into()));
    }

    #[test]
    #[should_panic(expected = "cannot remove from an empty spatial map")]
    fn empty_map_remove_entry_panics() {
        let mut m: EmptySpatialMap<Shape, Value, AnyQuery> = EmptySpatialMap::new();
        m.remove_entry(&(Shape(1), Value("x".into())));
    }

    // ── empty_map() helper ────────────────────────────────────────────────

    #[test]
    fn empty_map_fn_returns_empty_boxed_map() {
        let m: Box<dyn SpatialMap<Shape, Value, AnyQuery>> = empty_map();
        assert!(m.is_empty());
        assert_eq!(m.size(), 0);
        assert!(m.first_entry().is_none());
    }

    #[test]
    fn empty_map_fn_reduce_is_also_empty() {
        let m: Box<dyn SpatialMap<Shape, Value, AnyQuery>> = empty_map();
        let reduced = m.reduce(AnyQuery);
        assert!(reduced.is_empty());
    }

    // ── Default impl ──────────────────────────────────────────────────────

    #[test]
    fn empty_spatial_map_default_is_empty() {
        let m: EmptySpatialMap<Shape, Value, AnyQuery> = Default::default();
        assert!(m.is_empty());
    }
}
