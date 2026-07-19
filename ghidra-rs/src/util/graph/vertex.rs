use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

use crate::util::graph::keyed_object::KeyedObject;

/// A vertex tied to an optional referent value, identified by a unique key.
///
/// Port of `ghidra.util.graph.Vertex` (deprecated since Ghidra 10.2), cut to a trait to break
/// a dependency cycle at this node in the port graph. The Java class assigns its `key` at
/// construction time via the process-wide `KeyedObjectFactory` singleton
/// (`ghidra.util.graph.KeyedObjectFactory`, not yet ported); that assignment is an
/// implementation detail of construction rather than part of the public surface, so
/// implementers are expected to obtain a unique key however their concrete backend prefers and
/// report it via [`KeyedObject::key`].
///
/// The only operation the Java class performs on its referent `Object` is `toString()` (in
/// `toString()` and `name()`), so the referent is represented here as `&dyn Display` rather than
/// `&dyn Any`, matching exactly what this trait's default methods need.
#[deprecated(note = "Deprecated since Ghidra 10.2")]
pub trait Vertex: KeyedObject {
    /// Returns the object this vertex refers to, or `None` if it has no referent.
    fn referent(&self) -> Option<&dyn fmt::Display>;

    /// Returns the name of this vertex. If the vertex has a referent, the referent's display
    /// form is used (with spaces replaced by underscores) prefixed with `"Vertex:"`; otherwise
    /// the key is used, prefixed with `"Vertex_"`.
    fn name(&self) -> String {
        match self.referent() {
            Some(r) => format!("Vertex:{}", r.to_string().replace(' ', "_")),
            None => format!("Vertex_{:x}", self.key() as u64),
        }
    }
}

#[allow(deprecated)]
impl fmt::Display for dyn Vertex {
    /// Port of `Vertex#toString()`: the referent's display form, or `"Nexus"` if there is none.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.referent() {
            Some(r) => write!(f, "{}", r),
            None => write!(f, "Nexus"),
        }
    }
}

#[allow(deprecated)]
impl PartialEq for dyn Vertex {
    /// Port of `Vertex#equals(Object)`: true iff and only if the other vertex has the same key.
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key()
    }
}

#[allow(deprecated)]
impl Eq for dyn Vertex {}

#[allow(deprecated)]
impl Hash for dyn Vertex {
    /// Port of `Vertex#hashCode()`, which narrows the `long` key to an `int`.
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.key() as i32).hash(state);
    }
}

#[allow(deprecated)]
impl PartialOrd for dyn Vertex {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[allow(deprecated)]
impl Ord for dyn Vertex {
    /// Port of `Vertex#compareTo(Vertex)`, which compares keys with the operands reversed
    /// (`other.key() - self.key()`), i.e. descending key order.
    fn cmp(&self, other: &Self) -> Ordering {
        other.key().cmp(&self.key())
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    struct MockVertex {
        key: i64,
        referent: Option<String>,
    }

    impl KeyedObject for MockVertex {
        fn key(&self) -> i64 {
            self.key
        }
    }

    impl Vertex for MockVertex {
        fn referent(&self) -> Option<&dyn fmt::Display> {
            self.referent.as_ref().map(|s| s as &dyn fmt::Display)
        }
    }

    #[test]
    fn name_uses_referent_with_spaces_replaced() {
        let v = MockVertex { key: 1, referent: Some("hello world".to_string()) };
        let obj: &dyn Vertex = &v;
        assert_eq!(obj.name(), "Vertex:hello_world");
    }

    #[test]
    fn name_falls_back_to_hex_key_without_referent() {
        let v = MockVertex { key: 0xAB, referent: None };
        let obj: &dyn Vertex = &v;
        assert_eq!(obj.name(), "Vertex_ab");
    }

    #[test]
    fn display_falls_back_to_nexus_without_referent() {
        let v = MockVertex { key: 1, referent: None };
        let obj: &dyn Vertex = &v;
        assert_eq!(obj.to_string(), "Nexus");
    }

    #[test]
    fn display_uses_referent() {
        let v = MockVertex { key: 1, referent: Some("thing".to_string()) };
        let obj: &dyn Vertex = &v;
        assert_eq!(obj.to_string(), "thing");
    }

    #[test]
    fn equals_compares_by_key_only() {
        let a = MockVertex { key: 5, referent: Some("a".to_string()) };
        let b = MockVertex { key: 5, referent: Some("b".to_string()) };
        let a_ref: &dyn Vertex = &a;
        let b_ref: &dyn Vertex = &b;
        assert!(a_ref == b_ref);
    }

    #[test]
    fn compare_is_by_descending_key() {
        let lo = MockVertex { key: 1, referent: None };
        let hi = MockVertex { key: 2, referent: None };
        let lo_ref: &dyn Vertex = &lo;
        let hi_ref: &dyn Vertex = &hi;
        assert_eq!(lo_ref.cmp(hi_ref), Ordering::Greater);
        assert_eq!(hi_ref.cmp(lo_ref), Ordering::Less);
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let v: Box<dyn Vertex> = Box::new(MockVertex { key: 42, referent: None });
        assert_eq!(v.key(), 42);
    }
}
