//! Minimal placeholder traits/types for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use thiserror::Error;

use crate::generic::ulong_span;

/// Placeholder for `generic.expressions.ExpressionValue`, needed by
/// [`crate::generic::expressions::expression_evaluator::ExpressionEvaluator`].
///
/// The real interface also declares `applyUnaryOperator`/`applyBinaryOperator` (which take
/// `generic.expressions.ExpressionOperator`, itself unported), but `ExpressionEvaluator`'s own
/// trait surface never calls those directly -- that dispatch lives inside each concrete
/// evaluator's parsing algorithm. Only the accessor `ExpressionEvaluator.parseAsLong` needs
/// (recovering the `LongExpressionValue` special case) is declared here.
pub trait ExpressionValueLike {
    /// Returns the long value carried by this expression value, mirroring the
    /// `instanceof LongExpressionValue` check in `ExpressionEvaluator.parseAsLong`, or `None` if
    /// this value is not a long-valued result.
    fn as_long(&self) -> Option<i64>;
}

/// Placeholder for `generic.expressions.ExpressionException`, needed by
/// [`crate::generic::expressions::expression_evaluator::ExpressionEvaluator`].
///
/// The Java original is a trivial single-field checked exception, so this placeholder already
/// carries its full behavior.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[error("{0}")]
pub struct ExpressionException(pub String);

impl ExpressionException {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// Placeholder for `ghidra.generic.util.datastruct.SemisparseByteArray`, needed by
/// [`crate::pcode::exec::bytes_pcode_executor_state_space::BytesPcodeExecutorStateSpace`] as its
/// byte-addressed backing store.
///
/// Java backs this with fixed-size blocks plus a `MutableULongSpanSet` of defined spans, purely
/// as a performance optimization; only that optimization is skipped here; observable behavior
/// (which offsets are initialized, and what they read back as) is preserved via a per-byte sparse
/// map plus a merged, disjoint list of defined spans. Only the operations
/// `BytesPcodeExecutorStateSpace` actually calls are declared: `getDirect`, `putAll`, and
/// `contiguousAvailableAfter` are omitted. Java's `getUninitialized`/`getInitialized` return a
/// `ULongSpanSet`, itself unported; since every caller here only ever iterates the result, a plain
/// `Vec` of spans stands in for it.
#[derive(Clone, Default)]
pub struct SemisparseByteArray {
    inner: Arc<Mutex<SemisparseInner>>,
}

#[derive(Default)]
struct SemisparseInner {
    data: HashMap<u64, u8>,
    /// Sorted, pairwise-disjoint, non-adjacent inclusive spans of initialized offsets.
    defined: Vec<(u64, u64)>,
}

impl SemisparseByteArray {
    /// Port of `new SemisparseByteArray()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Port of `SemisparseByteArray.fork()`: an independent deep copy.
    pub fn fork(&self) -> Self {
        let inner = self.inner.lock().unwrap();
        Self {
            inner: Arc::new(Mutex::new(SemisparseInner {
                data: inner.data.clone(),
                defined: inner.defined.clone(),
            })),
        }
    }

    /// Port of `SemisparseByteArray.clear()`.
    pub fn clear(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.data.clear();
        inner.defined.clear();
    }

    /// Port of `SemisparseByteArray.getData(long, byte[])`: fills `data` from the stored bytes
    /// starting at `loc`, leaving uninitialized positions untouched (callers pre-zero `data`, as
    /// in Java).
    pub fn get_data(&self, loc: u64, data: &mut [u8]) {
        let inner = self.inner.lock().unwrap();
        for (i, b) in data.iter_mut().enumerate() {
            if let Some(&v) = inner.data.get(&loc.wrapping_add(i as u64)) {
                *b = v;
            }
        }
    }

    /// Port of `SemisparseByteArray.putData(long, byte[], int, int)`.
    pub fn put_data(&self, loc: u64, data: &[u8], offset: i32, length: i32) {
        if length <= 0 {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        let offset = offset as usize;
        let length = length as usize;
        for i in 0..length {
            inner.data.insert(loc.wrapping_add(i as u64), data[offset + i]);
        }
        let span = ulong_span::extent(loc, length as u64);
        add_span(&mut inner.defined, span.min, span.max);
    }

    /// Port of `SemisparseByteArray.isInitialized(long, long)`.
    pub fn is_initialized(&self, a: u64, b: u64) -> bool {
        complement(&self.inner.lock().unwrap().defined, a, b).is_empty()
    }

    /// Port of `SemisparseByteArray.getUninitialized(long, long)`.
    pub fn get_uninitialized(&self, a: u64, b: u64) -> Vec<ulong_span::Impl> {
        complement(&self.inner.lock().unwrap().defined, a, b)
            .into_iter()
            .map(|(min, max)| ulong_span::Impl { min, max })
            .collect()
    }
}

/// Whether `[a_min, a_max]` overlaps or is immediately adjacent to `[b_min, b_max]` (so the two
/// should merge into one span), without overflowing at the domain boundary.
fn touches_or_overlaps(a_min: u64, a_max: u64, b_min: u64, b_max: u64) -> bool {
    if a_max >= b_min && b_max >= a_min {
        return true;
    }
    if a_max < u64::MAX && a_max + 1 == b_min {
        return true;
    }
    if b_max < u64::MAX && b_max + 1 == a_min {
        return true;
    }
    false
}

/// Merge `[min, max]` into a sorted, disjoint, non-adjacent span list.
fn add_span(defined: &mut Vec<(u64, u64)>, min: u64, max: u64) {
    let mut merged_min = min;
    let mut merged_max = max;
    defined.retain(|&(lo, hi)| {
        if touches_or_overlaps(merged_min, merged_max, lo, hi) {
            merged_min = merged_min.min(lo);
            merged_max = merged_max.max(hi);
            false
        } else {
            true
        }
    });
    defined.push((merged_min, merged_max));
    defined.sort_unstable_by_key(|&(lo, _)| lo);
}

/// The sub-ranges of `[a, b]` not covered by any span in the sorted, disjoint `defined` list.
fn complement(defined: &[(u64, u64)], a: u64, b: u64) -> Vec<(u64, u64)> {
    if a > b {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut cursor = a;
    for &(lo, hi) in defined {
        if hi < cursor {
            continue;
        }
        if lo > b {
            break;
        }
        if lo > cursor {
            result.push((cursor, lo - 1));
        }
        if hi == u64::MAX {
            return result;
        }
        cursor = cursor.max(hi + 1);
        if cursor > b {
            return result;
        }
    }
    result.push((cursor, b));
    result
}

#[cfg(test)]
mod semisparse_byte_array_tests {
    use super::*;

    #[test]
    fn put_then_get_round_trips_and_tracks_initialization() {
        let arr = SemisparseByteArray::new();
        assert!(!arr.is_initialized(10, 13));

        arr.put_data(10, &[1, 2, 3, 4], 0, 4);
        assert!(arr.is_initialized(10, 13));
        assert!(!arr.is_initialized(10, 14));

        let mut out = [0u8; 4];
        arr.get_data(10, &mut out);
        assert_eq!(out, [1, 2, 3, 4]);

        let uninit = arr.get_uninitialized(8, 15);
        assert_eq!(uninit, vec![ulong_span::Impl { min: 8, max: 9 }, ulong_span::Impl { min: 14, max: 15 }]);
    }

    #[test]
    fn fork_is_independent_of_the_original() {
        let arr = SemisparseByteArray::new();
        arr.put_data(0, &[9], 0, 1);

        let forked = arr.fork();
        forked.put_data(1, &[7], 0, 1);

        assert!(!arr.is_initialized(1, 1));
        assert!(forked.is_initialized(0, 1));
    }

    #[test]
    fn clear_resets_initialization_and_data() {
        let arr = SemisparseByteArray::new();
        arr.put_data(0, &[1, 2], 0, 2);
        arr.clear();

        assert!(!arr.is_initialized(0, 1));
        // Uninitialized positions are left untouched (as in Java); callers are expected to
        // pre-zero the destination, as they do here.
        let mut out = [0u8; 2];
        arr.get_data(0, &mut out);
        assert_eq!(out, [0, 0]);
    }
}

/// Placeholder for `generic.lsh.vector.VectorCompare`, referenced by [`crate::generic::lsh::vector::lsh_vector::LSHVector`].
///
/// The real Java interface declares two methods: `fillOut()` and `toString()`.
/// This placeholder is only the shape hint; replace with the real port when available.
pub trait VectorCompare: Send + Sync {
    /// Placeholder for `VectorCompare.fillOut()`.
    fn fill_out(&self);

    /// Placeholder for `VectorCompare.toString()`.
    fn to_string(&self) -> String;
}

/// Placeholder for `generic.lsh.vector.LSHVectorFactory`, referenced by
/// [`crate::feature::bsim::query::description::FunctionDescription::restore_xml`], which only
/// passes it through to the signature record's restore path. No members are needed yet;
/// replace with the real port when `LSHVectorFactory.java` is ported.
#[derive(Debug, Default, Clone)]
pub struct LSHVectorFactory;
