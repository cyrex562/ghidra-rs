/// Marker trait for types whose instances should be recursively marked up by
/// the struct-mapping framework.
///
/// This is the Rust equivalent of the Java `@Markup` annotation used in
/// Ghidra's struct-mapping framework.  In Java the annotation is placed on
/// fields or methods (targeting `FIELD` and `METHOD`) so the framework can
/// discover, via reflection, which values to pass back through the recursive
/// mark-up pipeline.  Because Rust has no field- or method-level annotations,
/// the same contract is expressed as a marker trait: a type that implements
/// `Markup` signals that instances of that type (or collections thereof)
/// returned from a method or stored in a field should be fed back into the
/// mark-up pipeline.
///
/// The trait carries no methods — its presence alone is the signal, mirroring
/// the Java annotation which also has no elements.
pub trait Markup {}

#[cfg(test)]
mod tests {
    use super::Markup;

    struct SimpleMarkupType;
    impl Markup for SimpleMarkupType {}

    struct AnotherType;
    impl Markup for AnotherType {}

    struct NotMarkup;

    #[test]
    fn type_implements_markup() {
        fn requires_markup<T: Markup>(_: &T) {}
        let v = SimpleMarkupType;
        requires_markup(&v);
    }

    #[test]
    fn multiple_types_can_implement_markup() {
        fn requires_markup<T: Markup>(_: &T) {}
        requires_markup(&SimpleMarkupType);
        requires_markup(&AnotherType);
    }

    #[test]
    fn markup_is_object_safe() {
        let _: Box<dyn Markup> = Box::new(SimpleMarkupType);
    }

    #[test]
    fn markup_works_with_vec_element_type() {
        fn collect_markup<T: Markup>(items: Vec<T>) -> usize {
            items.len()
        }
        let v = vec![SimpleMarkupType, SimpleMarkupType];
        assert_eq!(collect_markup(v), 2);
    }

    #[test]
    fn non_implementing_type_does_not_satisfy_bound() {
        // Compile-time check: this function should NOT accept NotMarkup.
        // We verify the positive case only — the negative is enforced by the
        // type system and would be a compile error if attempted.
        fn requires_markup<T: Markup>(_: &T) {}
        let _: fn(&SimpleMarkupType) = requires_markup;
        // If NotMarkup implemented Markup, the framework would wrongly recurse
        // into it.  The trait not being implemented is the contract.
        let _: &NotMarkup = &NotMarkup; // just uses the type to silence dead_code
    }
}
