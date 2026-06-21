/// Marker trait for ISF objects.
///
/// Corresponds to the empty `IsfObject` Java interface in Ghidra's
/// `Debugger-isf` module. Types implement this trait to participate in the
/// ISF type hierarchy without carrying additional behaviour.
pub trait IsfObject {}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dummy;
    impl IsfObject for Dummy {}

    #[test]
    fn marker_trait_is_implementable() {
        fn accepts<T: IsfObject>(_: &T) {}
        let d = Dummy;
        accepts(&d);
    }

    #[test]
    fn multiple_types_can_implement_isf_object() {
        struct A;
        struct B;
        impl IsfObject for A {}
        impl IsfObject for B {}

        fn accepts<T: IsfObject>(_: &T) {}
        accepts(&A);
        accepts(&B);
    }
}
