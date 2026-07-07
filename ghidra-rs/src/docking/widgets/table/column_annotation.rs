/// Marker trait indicating that an implementor exposes table column data.
///
/// Corresponds to the `@ColumnAnnotation` Java annotation
/// (`docking.widgets.table.ColumnAnnotation`), which is a runtime-retained,
/// method-targeted marker annotation with no parameters.  In Rust the closest
/// idiomatic equivalent is a marker trait that types opt into to signal
/// column-getter semantics.
pub trait ColumnAnnotation {}

#[cfg(test)]
mod tests {
    use super::*;

    struct MyColumn;
    impl ColumnAnnotation for MyColumn {}

    #[test]
    fn marker_trait_is_implementable() {
        fn accepts_column<T: ColumnAnnotation>(_: &T) {}
        accepts_column(&MyColumn);
    }

    #[test]
    fn marker_trait_is_object_safe_via_bound() {
        fn requires_column<T: ColumnAnnotation + ?Sized>() {}
        requires_column::<MyColumn>();
    }
}
