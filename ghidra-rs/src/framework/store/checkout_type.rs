//! Port of `ghidra.framework.store.CheckoutType`.
//!
//! Java declares this as a three-constant `enum` and nothing extends it, so a Rust `enum` is the
//! faithful shape. It was first ported as an object-safe trait with `Normal`/`Exclusive`/
//! `Transient` unit structs as implementors, to "break a dependency cycle at this cut-point" --
//! but a fixed three-constant enum has no cycle to break: it depends on nothing. Meanwhile a
//! *second* definition, correctly shaped as an enum, sat in `framework/seam_stubs.rs`, and call
//! sites split between the two. `local_folder_item.rs` imported both, aliasing one
//! `RealCheckoutType`.
//!
//! Both are now this one type. See `OWNERSHIP_MIGRATION.md` and the `STRUCT` verdict in
//! `CONVENTION_QUEUE.tsv`: a Java `class`/`enum` that nothing extends has no hierarchy to
//! dispatch over, so a trait is the wrong shape for it.

/// Identifies the type of checkout.
///
/// Port of `ghidra.framework.store.CheckoutType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CheckoutType {
    /// Checkout is a normal non-exclusive checkout.
    #[default]
    Normal,

    /// A persistent exclusive checkout, which ensures no other checkout can occur while this
    /// checkout persists.
    Exclusive,

    /// Like [`Exclusive`](CheckoutType::Exclusive), but persists only while the associated
    /// client connection is alive. Permitted only for remote versioned file systems that
    /// support its use.
    Transient,
}

impl CheckoutType {
    /// The abbreviated identifier used when serializing this checkout type.
    ///
    /// Mirrors `CheckoutType.getID()`, which returns `name().charAt(0)`.
    pub fn get_id(self) -> i32 {
        match self {
            CheckoutType::Normal => 'N' as i32,
            CheckoutType::Exclusive => 'E' as i32,
            CheckoutType::Transient => 'T' as i32,
        }
    }

    /// The checkout type with the given id, or `None` if the id is not one of them.
    ///
    /// Mirrors the static factory `CheckoutType.getCheckoutType(int)`, which linearly searches
    /// `values()`.
    pub fn from_id(type_id: i32) -> Option<Self> {
        [
            CheckoutType::Normal,
            CheckoutType::Exclusive,
            CheckoutType::Transient,
        ]
        .into_iter()
        .find(|t| t.get_id() == type_id)
    }

    /// Every checkout type, mirroring `CheckoutType.values()`.
    pub fn values() -> [CheckoutType; 3] {
        [
            CheckoutType::Normal,
            CheckoutType::Exclusive,
            CheckoutType::Transient,
        ]
    }
}

/// The checkout type with the given id, or `None` if the id is not one of them.
///
/// Retained as a free function because call sites ported from Java's static
/// `CheckoutType.getCheckoutType(int)` spell it this way; it delegates to
/// [`CheckoutType::from_id`].
pub fn get_checkout_type(type_id: i32) -> Option<CheckoutType> {
    CheckoutType::from_id(type_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_match_the_java_constants_first_letters() {
        // Java's getID() is name().charAt(0).
        assert_eq!(CheckoutType::Normal.get_id(), 'N' as i32);
        assert_eq!(CheckoutType::Exclusive.get_id(), 'E' as i32);
        assert_eq!(CheckoutType::Transient.get_id(), 'T' as i32);
    }

    #[test]
    fn from_id_round_trips_every_value(
    ) {
        for t in CheckoutType::values() {
            assert_eq!(CheckoutType::from_id(t.get_id()), Some(t));
        }
    }

    #[test]
    fn from_id_rejects_an_unknown_id() {
        assert_eq!(CheckoutType::from_id(0), None);
        assert_eq!(CheckoutType::from_id('X' as i32), None);
    }

    #[test]
    fn the_free_function_matches_the_associated_one() {
        assert_eq!(get_checkout_type('E' as i32), Some(CheckoutType::Exclusive));
        assert_eq!(get_checkout_type(0), None);
    }

    /// The point of the conversion: an exhaustive `match` is now possible, which the trait
    /// could never offer -- any new checkout type would have had to be found by reading call
    /// sites.
    #[test]
    fn matching_is_exhaustive() {
        fn describe(t: CheckoutType) -> &'static str {
            match t {
                CheckoutType::Normal => "normal",
                CheckoutType::Exclusive => "exclusive",
                CheckoutType::Transient => "transient",
            }
        }
        assert_eq!(
            CheckoutType::values().map(describe),
            ["normal", "exclusive", "transient"]
        );
    }

    #[test]
    fn is_copy_and_comparable_so_it_can_be_passed_by_value() {
        let t = CheckoutType::Exclusive;
        let copied = t;
        assert_eq!(t, copied);
        assert_ne!(t, CheckoutType::Normal);
    }
}
