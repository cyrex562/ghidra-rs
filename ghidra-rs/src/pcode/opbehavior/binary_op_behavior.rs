use super::op_behavior::OpBehavior;

/// Trait representing a binary (2-input) p-code operation.
///
/// This trait encodes the behavior of p-code operations that take exactly two input
/// operands and produce a single output. Implementations provide evaluation methods
/// for both 64-bit and 128-bit integer arithmetic.
///
/// # Overflow Semantics
///
/// Both `evaluate_binary_i64` and `evaluate_binary_i128` may set bits beyond the
/// specified output size. Callers must truncate results to `sizeout` bytes themselves
/// for correct behavior. This design conserves emulation cycles by avoiding redundant
/// truncation in the evaluation layer.
///
/// # Method Names
///
/// Java `BinaryOpBehavior` defines two methods with the same name but different
/// parameter/return types (method overloading). Rust does not support overloading,
/// so we use distinct names:
/// - `evaluate_binary_i64` → 64-bit evaluation (Java: `evaluateBinary(int, int, long, long)`)
/// - `evaluate_binary_i128` → 128-bit evaluation (Java: `evaluateBinary(int, int, BigInteger, BigInteger)`)
///
/// Corresponds to `ghidra.pcode.opbehavior.BinaryOpBehavior`.
pub trait BinaryOpBehavior: Sized {
    /// Return the p-code opcode associated with this behavior.
    fn opcode(&self) -> i32;

    /// Evaluate the binary operation using 64-bit unsigned integer arithmetic.
    ///
    /// # Arguments
    /// - `sizeout`: Intended output size in bytes
    /// - `sizein`: Size of the first input in bytes
    /// - `unsigned_in1`: First unsigned input
    /// - `unsigned_in2`: Second unsigned input
    ///
    /// # Returns
    ///
    /// The operation result. Note that if the operation overflows, bits may be set
    /// beyond `sizeout`. Even though results should be treated as unsigned, they
    /// may be returned as a signed i64 value. It is expected that the returned
    /// result always be properly truncated by the caller.
    fn evaluate_binary_i64(&self, sizeout: i32, sizein: i32, unsigned_in1: i64, unsigned_in2: i64) -> i64;

    /// Evaluate the binary operation using 128-bit unsigned integer arithmetic.
    ///
    /// # Arguments
    /// - `sizeout`: Intended output size in bytes
    /// - `sizein`: Size of the first input in bytes
    /// - `unsigned_in1`: First unsigned input
    /// - `unsigned_in2`: Second unsigned input
    ///
    /// # Returns
    ///
    /// The operation result. Note that if the operation overflows, bits may be set
    /// beyond `sizeout`. Even though results should be treated as unsigned, they
    /// may be returned as a signed i128 value. It is expected that the returned
    /// result always be properly truncated by the caller.
    fn evaluate_binary_i128(&self, sizeout: i32, sizein: i32, unsigned_in1: i128, unsigned_in2: i128) -> i128;
}

/// Wrapper providing convenient trait object support for binary operations.
///
/// Implements the `BinaryOpBehavior` trait by delegating to an `OpBehavior` instance
/// and abstract methods that must be implemented by concrete subclasses.
pub struct BinaryOpBehaviorImpl<T> {
    inner: OpBehavior,
    evaluator: T,
}

impl<T> BinaryOpBehaviorImpl<T> {
    /// Construct a new binary operation behavior.
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

    struct TestBinaryOp;

    impl TestBinaryOp {
        fn new(opcode: i32) -> BinaryOpBehaviorImpl<Self> {
            BinaryOpBehaviorImpl::new(opcode, TestBinaryOp)
        }

        /// The bare evaluator carries no opcode of its own.
        fn opcode(&self) -> i32 {
            0
        }
    }

    impl BinaryOpBehavior for BinaryOpBehaviorImpl<TestBinaryOp> {
        fn opcode(&self) -> i32 {
            self.inner.opcode()
        }

        fn evaluate_binary_i64(&self, _sizeout: i32, _sizein: i32, in1: i64, in2: i64) -> i64 {
            in1 & in2
        }

        fn evaluate_binary_i128(&self, _sizeout: i32, _sizein: i32, in1: i128, in2: i128) -> i128 {
            in1 & in2
        }
    }

    #[test]
    fn new_stores_opcode() {
        let b = TestBinaryOp::new(42);
        assert_eq!(b.opcode(), 42);
    }

    #[test]
    fn evaluate_binary_i64_with_zeros() {
        let b = TestBinaryOp::new(1);
        assert_eq!(b.evaluate_binary_i64(8, 8, 0, 0), 0);
    }

    #[test]
    fn evaluate_binary_i64_and_operation() {
        let b = TestBinaryOp::new(1);
        assert_eq!(b.evaluate_binary_i64(8, 8, 0xff, 0x0f), 0x0f);
    }

    #[test]
    fn evaluate_binary_i64_full_bits() {
        let b = TestBinaryOp::new(1);
        let all_bits = 0xffffffffffffffffu64 as i64;
        assert_eq!(b.evaluate_binary_i64(8, 8, all_bits, all_bits), all_bits);
    }

    #[test]
    fn evaluate_binary_i128_with_zeros() {
        let b = TestBinaryOp::new(1);
        assert_eq!(b.evaluate_binary_i128(16, 16, 0, 0), 0);
    }

    #[test]
    fn evaluate_binary_i128_and_operation() {
        let b = TestBinaryOp::new(1);
        assert_eq!(b.evaluate_binary_i128(16, 16, 0xffffffff, 0x0000ffff), 0x0000ffff);
    }

    #[test]
    fn evaluate_binary_i128_large_values() {
        let b = TestBinaryOp::new(1);
        let large1: i128 = 0xffffffffffffffff0000000000000000u128 as i128;
        let large2: i128 = 0x00000000000000000000000000000000i128;
        assert_eq!(b.evaluate_binary_i128(16, 16, large1, large2), 0);
    }

    #[test]
    fn wrapper_provides_access_to_evaluator() {
        let b = TestBinaryOp::new(7);
        assert_eq!(b.evaluator().opcode(), 0); // TestBinaryOp has no opcode
        assert_eq!(b.inner().opcode(), 7);
    }

    #[test]
    fn wrapper_preserves_opcode() {
        let b1 = TestBinaryOp::new(5);
        let b2 = TestBinaryOp::new(5);
        assert_eq!(b1.opcode(), b2.opcode());
    }

    #[test]
    fn different_opcodes_are_distinct() {
        let b1 = TestBinaryOp::new(1);
        let b2 = TestBinaryOp::new(2);
        assert_ne!(b1.opcode(), b2.opcode());
    }

    #[test]
    fn into_evaluator_consumes_wrapper() {
        let b = TestBinaryOp::new(3);
        let _eval = b.into_evaluator();
    }
}
