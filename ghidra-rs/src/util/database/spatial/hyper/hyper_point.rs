/// Marker trait for a point in a hyper-dimensional index.
///
/// Corresponds to the empty interface `ghidra.util.database.spatial.hyper.HyperPoint`.
pub trait HyperPoint {}

#[cfg(test)]
mod tests {
    use super::*;

    struct ConcretePoint;
    impl HyperPoint for ConcretePoint {}

    #[test]
    fn concrete_type_implements_hyper_point() {
        fn accepts<P: HyperPoint>(_p: &P) {}
        let p = ConcretePoint;
        accepts(&p);
    }
}
