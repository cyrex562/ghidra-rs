/// Identifies the type of checkout.
///
/// Port of `ghidra.framework.store.CheckoutType`. In Java this is a fixed three-constant `enum`
/// (`NORMAL`, `EXCLUSIVE`, `TRANSIENT`); this port maps it to an object-safe trait so that other
/// core types can depend on checkout-type behavior without depending on a concrete enum, breaking
/// a dependency cycle at this cut-point. [`Normal`], [`Exclusive`], and [`Transient`] are the
/// trait's three implementors, mirroring the Java enum constants.
pub trait CheckoutType {
    /// Get the abbreviated/short name for this checkout type for use with serialization.
    ///
    /// Mirrors `CheckoutType.getID()`, which returns `name().charAt(0)`.
    fn get_id(&self) -> i32;
}

/// Checkout is a normal non-exclusive checkout.
///
/// Mirrors the Java `CheckoutType.NORMAL` constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Normal;

impl CheckoutType for Normal {
    fn get_id(&self) -> i32 {
        'N' as i32
    }
}

/// Checkout is a persistent exclusive checkout which ensures no other checkout can occur while
/// this checkout persists.
///
/// Mirrors the Java `CheckoutType.EXCLUSIVE` constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Exclusive;

impl CheckoutType for Exclusive {
    fn get_id(&self) -> i32 {
        'E' as i32
    }
}

/// Similar to an [`Exclusive`] checkout, this checkout only persists while the associated
/// client-connection is alive. This checkout is only permitted for remote versioned file systems
/// which support its use.
///
/// Mirrors the Java `CheckoutType.TRANSIENT` constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Transient;

impl CheckoutType for Transient {
    fn get_id(&self) -> i32 {
        'T' as i32
    }
}

/// Get the [`CheckoutType`] whose id corresponds to the specified type id, or `None` if the id is
/// invalid.
///
/// Mirrors the static factory `CheckoutType.getCheckoutType(int)`, which linearly searches
/// `values()`. Returns a boxed trait object rather than a concrete type since the whole point of
/// this trait is to decouple callers from any single concrete `CheckoutType` implementor.
pub fn get_checkout_type(type_id: i32) -> Option<Box<dyn CheckoutType>> {
    match type_id {
        id if id == Normal.get_id() => Some(Box::new(Normal)),
        id if id == Exclusive.get_id() => Some(Box::new(Exclusive)),
        id if id == Transient.get_id() => Some(Box::new(Transient)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A non-standard mock implementor, proving the trait is object-safe and usable beyond the
    /// three built-in implementors.
    struct MockCheckoutType(i32);

    impl CheckoutType for MockCheckoutType {
        fn get_id(&self) -> i32 {
            self.0
        }
    }

    #[test]
    fn test_object_safety_and_ids() {
        let types: Vec<Box<dyn CheckoutType>> =
            vec![Box::new(Normal), Box::new(Exclusive), Box::new(Transient)];
        let ids: Vec<i32> = types.iter().map(|t| t.get_id()).collect();
        assert_eq!(ids, vec!['N' as i32, 'E' as i32, 'T' as i32]);
    }

    #[test]
    fn test_mock_impl_object_safety() {
        let mock: Box<dyn CheckoutType> = Box::new(MockCheckoutType(42));
        assert_eq!(mock.get_id(), 42);
    }

    #[test]
    fn test_get_checkout_type_round_trip() {
        assert_eq!(get_checkout_type('N' as i32).unwrap().get_id(), 'N' as i32);
        assert_eq!(get_checkout_type('E' as i32).unwrap().get_id(), 'E' as i32);
        assert_eq!(get_checkout_type('T' as i32).unwrap().get_id(), 'T' as i32);
    }

    #[test]
    fn test_get_checkout_type_invalid_id() {
        assert!(get_checkout_type(0).is_none());
        assert!(get_checkout_type('X' as i32).is_none());
    }
}
