/// A four-element heterogeneous tuple, mirroring `generic.stl.Quad<T1, T2, T3, T4>`.
pub struct Quad<T1, T2, T3, T4> {
    pub first: T1,
    pub second: T2,
    pub third: T3,
    pub fourth: T4,
}

impl<T1, T2, T3, T4> Quad<T1, T2, T3, T4> {
    /// Creates a new `Quad` with the given four values.
    ///
    /// Mirrors the Java constructor `new Quad<>(first, second, third, fourth)`.
    pub fn new(first: T1, second: T2, third: T3, fourth: T4) -> Self {
        Self { first, second, third, fourth }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_stores_all_fields() {
        let q = Quad::new(1u8, "hello", 3.14f64, true);
        assert_eq!(q.first, 1u8);
        assert_eq!(q.second, "hello");
        assert!((q.third - 3.14f64).abs() < 1e-10);
        assert!(q.fourth);
    }

    #[test]
    fn fields_are_independently_mutable() {
        let mut q = Quad::new(0i32, 0i32, 0i32, 0i32);
        q.first = 10;
        q.second = 20;
        q.third = 30;
        q.fourth = 40;
        assert_eq!(q.first, 10);
        assert_eq!(q.second, 20);
        assert_eq!(q.third, 30);
        assert_eq!(q.fourth, 40);
    }

    #[test]
    fn works_with_heap_allocated_types() {
        let q = Quad::new(vec![1, 2], String::from("abc"), Box::new(99i32), Some(false));
        assert_eq!(q.first, vec![1, 2]);
        assert_eq!(q.second, "abc");
        assert_eq!(*q.third, 99);
        assert_eq!(q.fourth, Some(false));
    }
}
