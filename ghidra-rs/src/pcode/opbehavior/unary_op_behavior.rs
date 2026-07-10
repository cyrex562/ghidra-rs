use super::op_behavior::OpBehavior;

/// Trait representing a unary (1-input) p-code operation.
///
/// This trait encodes the behavior of p-code operations that take exactly one input
/// operand and produce a single output. Implementations provide evaluation methods
/// for both 64-bit and 128-bit integer arithmetic.
///
/// # Overflow Semantics
///
/// Both `evaluate_unary_i64` and `evaluate_unary_i128` may set bits beyond the
/// specified output size. Callers must truncate results to `sizeout` bytes themselves
/// for correct behavior. This design conserves emulation cycles by avoiding redundant
/// truncation in the evaluation layer.
///
/// # Method Names
///
/// Java `UnaryOpBehavior` defines two methods with the same name but different
/// parameter/return types (method overloading). Rust does not support overloading,
/// so we use distinct names:
/// - `evaluate_unary_i64` → 64-bit evaluation (Java: `evaluateUnary(int, int, long)`)
/// - `evaluate_unary_i128` → 128-bit evaluation (Java: `evaluateUnary(int, int, BigInteger)`)
///
/// Corresponds to `ghidra.pcode.opbehavior.UnaryOpBehavior`.
pub trait UnaryOpBehavior: Sized {
    /// Return the p-code opcode associated with this behavior.
    fn opcode(&self) -> i32;

    /// Evaluate the unary operation using 64-bit unsigned integer arithmetic.
    ///
    /// # Arguments
    /// - `sizeout`: Intended output size in bytes
    /// - `sizein`: Size of the input in bytes
    /// - `unsigned_in1`: Unsigned input value
    ///
    /// # Returns
    ///
    /// The operation result. Note that if the operation overflows, bits may be set
    /// beyond `sizeout`. Even though results should be treated as unsigned, they
    /// may be returned as a signed i64 value. It is expected that the returned
    /// result always be properly truncated by the caller.
    fn evaluate_unary_i64(&self, sizeout: i32, sizein: i32, unsigned_in1: i64) -> i64;

    /// Evaluate the unary operation using 128-bit unsigned integer arithmetic.
    ///
    /// # Arguments
    /// - `sizeout`: Intended output size in bytes
    /// - `sizein`: Size of the input in bytes
    /// - `unsigned_in1`: Unsigned input value
    ///
    /// # Returns
    ///
    /// The operation result. Note that if the operation overflows, bits may be set
    /// beyond `sizeout`. Even though results should be treated as unsigned, they
    /// may be returned as a signed i128 value. It is expected that the returned
    /// result always be properly truncated by the caller.
    fn evaluate_unary_i128(&self, sizeout: i32, sizein: i32, unsigned_in1: i128) -> i128;
}

/// Wrapper providing convenient trait object support for unary operations.
///
/// Implements the `UnaryOpBehavior` trait by delegating to an `OpBehavior` instance
/// and abstract methods that must be implemented by concrete subclasses.
pub struct UnaryOpBehaviorImpl<T> {
    inner: OpBehavior,
    evaluator: T,
}

impl<T> UnaryOpBehaviorImpl<T> {
    /// Construct a new unary operation behavior.
    pub fn new(opcode: i32, evaluator: T) -> Self {
        Self {
            inner: OpBehavior::new(opcode),
            evaluator,
        }
    }

    /// Return a reference to the underlying opcode.
    pub fn inner(&self) -> OpBehavior {
        self.inner
    }

    /// Return a reference to the evaluator.
    pub fn evaluator(&self) -> &T {
        &self.evaluator
    }

    /// Return a mutable reference to the evaluator.
    pub fn evaluator_mut(&mut self) -> &mut T {
        &mut self.evaluator
    }

    /// Consume this wrapper and return the evaluator.
    pub fn into_evaluator(self) -> T {
        self.evaluator
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestUnaryOp;

    impl TestUnaryOp {
        fn new(opcode: i32) -> UnaryOpBehaviorImpl<Self> {
            UnaryOpBehaviorImpl::new(opcode, TestUnaryOp)
        }
    }

    impl UnaryOpBehavior for UnaryOpBehaviorImpl<TestUnaryOp> {
        fn opcode(&self) -> i32 {
            self.inner.opcode()
        }

        fn evaluate_unary_i64(&self, _sizeout: i32, _sizein: i32, in1: i64) -> i64 {
            in1.wrapping_neg()
        }

        fn evaluate_unary_i128(&self, _sizeout: i32, _sizein: i32, in1: i128) -> i128 {
            in1.wrapping_neg()
        }
    }

    #[test]
    fn new_stores_opcode() {
        let b = TestUnaryOp::new(42);
        assert_eq!(b.opcode(), 42);
    }

    #[test]
    fn evaluate_unary_i64_with_zero() {
        let b = TestUnaryOp::new(1);
        assert_eq!(b.evaluate_unary_i64(8, 8, 0), 0);
    }

    #[test]
    fn evaluate_unary_i64_negation() {
        let b = TestUnaryOp::new(1);
        assert_eq!(b.evaluate_unary_i64(8, 8, 1), -1i64);
    }

    #[test]
    fn evaluate_unary_i64_negation_full_bits() {
        let b = TestUnaryOp::new(1);
        let all_bits = 0xffffffffffffffffu64 as i64;
        assert_eq!(b.evaluate_unary_i64(8, 8, all_bits), 1);
    }

    #[test]
    fn evaluate_unary_i128_with_zero() {
        let b = TestUnaryOp::new(1);
        assert_eq!(b.evaluate_unary_i128(16, 16, 0), 0);
    }

    #[test]
    fn evaluate_unary_i128_negation() {
        let b = TestUnaryOp::new(1);
        assert_eq!(b.evaluate_unary_i128(16, 16, 1), -1i128);
    }

    #[test]
    fn evaluate_unary_i128_large_value() {
        let b = TestUnaryOp::new(1);
        let large: i128 = 0xffffffffffffffff0000000000000000u128 as i128;
        assert_eq!(b.evaluate_unary_i128(16, 16, large), -large);
    }

    #[test]
    fn wrapper_provides_access_to_evaluator() {
        let b = TestUnaryOp::new(7);
        assert_eq!(b.inner().opcode(), 7);
    }

    #[test]
    fn wrapper_preserves_opcode() {
        let b1 = TestUnaryOp::new(5);
        let b2 = TestUnaryOp::new(5);
        assert_eq!(b1.opcode(), b2.opcode());
    }

    #[test]
    fn different_opcodes_are_distinct() {
        let b1 = TestUnaryOp::new(1);
        let b2 = TestUnaryOp::new(2);
        assert_ne!(b1.opcode(), b2.opcode());
    }

    #[test]
    fn into_evaluator_consumes_wrapper() {
        let b = TestUnaryOp::new(3);
        let _eval = b.into_evaluator();
    }
}
