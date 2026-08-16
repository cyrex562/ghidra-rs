//! Minimal placeholder traits/types for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use thiserror::Error;

use crate::generic::lsh::vector::hash_entry::HashEntry;
use crate::generic::lsh::vector::lsh_vector::LSHVector;
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
/// passes it through to the signature record's restore path, and by
/// [`GenSignatures`](crate::feature::bsim::query::gen_signatures::GenSignatures), which needs the
/// signature settings the factory was configured with.
/// Replace with the real port when `LSHVectorFactory.java` is ported.
#[derive(Debug, Default, Clone)]
pub struct LSHVectorFactory {
    settings: i32,
}

impl LSHVectorFactory {
    /// A factory configured with the given encoded signature settings.
    ///
    /// Java configures the factory through `set(WeightFactory, IDFLookup, int settings)`; only
    /// the settings are modelled here.
    pub fn with_settings(settings: i32) -> Self {
        Self { settings }
    }

    /// Java: `LSHVectorFactory.getSettings()`, the encoded bit-field of the signature strategy
    /// this factory generates vectors for.
    pub fn get_settings(&self) -> i32 {
        self.settings
    }

    /// Java: `LSHVectorFactory.buildVector(int[] feature)`, which folds duplicate feature hashes
    /// together and weights each by the factory's weight table.
    ///
    /// The placeholder has no weight table, so every distinct hash gets weight 1.0 and the term
    /// frequency is the number of times the hash appears -- enough for the vector to carry its
    /// features, which is all the current callers need.
    pub fn build_vector(&self, feature: &[i32]) -> WeightedLSHCosineVector {
        WeightedLSHCosineVector::from_features(feature)
    }

    /// Java: `LSHVectorFactory.buildZeroVector()`.
    pub fn build_zero_vector(&self) -> WeightedLSHCosineVector {
        WeightedLSHCosineVector::from_features(&[])
    }
}

/// Placeholder for the unported Java type `generic.lsh.vector.WeightedLSHCosineVector`, the
/// concrete [`LSHVector`] that [`LSHVectorFactory::build_vector`] returns.
///
/// Only the accessors are modelled; the comparison and serialization halves of [`LSHVector`]
/// need the weight/IDF machinery that is not ported yet, so they are inert. Replace with the
/// real port when `WeightedLSHCosineVector.java` is ported.
#[derive(Debug, Default, Clone)]
pub struct WeightedLSHCosineVector {
    hashes: Vec<HashEntry>,
}

impl WeightedLSHCosineVector {
    /// Build a vector from raw 32-bit feature hashes, folding duplicates into a term frequency.
    pub fn from_features(feature: &[i32]) -> Self {
        let mut sorted: Vec<i32> = feature.to_vec();
        sorted.sort_unstable();
        let mut hashes: Vec<HashEntry> = Vec::new();
        let mut i = 0;
        while i < sorted.len() {
            let hash = sorted[i];
            let mut count = 1;
            while i + count < sorted.len() && sorted[i + count] == hash {
                count += 1;
            }
            hashes.push(HashEntry::with_weight(hash, count as i32, 1.0));
            i += count;
        }
        Self { hashes }
    }
}

impl LSHVector for WeightedLSHCosineVector {
    fn num_entries(&self) -> i32 {
        self.hashes.len() as i32
    }

    fn get_entry(&self, i: i32) -> Option<HashEntry> {
        usize::try_from(i).ok().and_then(|i| self.hashes.get(i)).copied()
    }

    fn get_entries(&self) -> Vec<HashEntry> {
        self.hashes.clone()
    }

    fn get_length(&self) -> f64 {
        self.hashes.iter().map(|e| e.get_coeff() * e.get_coeff()).sum::<f64>().sqrt()
    }

    fn compare<T: LSHVector + ?Sized>(&self, _op2: &T, _data: &dyn VectorCompare) -> f64 {
        0.0
    }

    fn compare_counts<T: LSHVector + ?Sized>(&self, _op2: &T, _data: &dyn VectorCompare) {}

    fn compare_detail<T: LSHVector + ?Sized>(&self, _op2: &T, _buf: &mut String) -> f64 {
        0.0
    }

    fn save_xml(&self, _fwrite: &mut dyn std::io::Write) -> std::io::Result<()> {
        Ok(())
    }

    fn save_sql(&self) -> String {
        String::new()
    }

    fn save_base64(&self, _buffer: &mut [char], _encoder: &[char]) {}

    fn restore_xml<P: crate::util::xml::xml_pull_parser::XmlPullParser>(
        &mut self,
        _parser: &mut P,
        _weight_factory: &crate::generic::lsh::vector::weight_factory::WeightFactory,
        _idf_lookup: &crate::generic::lsh::vector::idf_lookup::IdfLookup,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    fn restore_sql(
        &mut self,
        _sql: &str,
        _weight_factory: &crate::generic::lsh::vector::weight_factory::WeightFactory,
        _idf_lookup: &crate::generic::lsh::vector::idf_lookup::IdfLookup,
    ) -> std::io::Result<()> {
        Ok(())
    }

    fn restore_base64(
        &mut self,
        _input: &mut dyn std::io::Read,
        _buffer: &[char],
        _wfactory: &crate::generic::lsh::vector::weight_factory::WeightFactory,
        _idflookup: &crate::generic::lsh::vector::idf_lookup::IdfLookup,
        _decode: &[i32],
    ) -> std::io::Result<()> {
        Ok(())
    }

    fn calc_unique_hash(&self) -> u64 {
        self.hashes.iter().fold(0u64, |acc, e| acc.wrapping_mul(31).wrapping_add(e.get_hash() as u64))
    }
}

/// Placeholder for the unported Java type `GThemeValueMap`, referenced by
/// [`crate::generic::theme::application_theme_defaults::ApplicationThemeDefaults`].
/// Generated stub: only a shape hint. Replace with the real port when available.
pub trait GThemeValueMap: Send + Sync {
    fn add_color(&self, value: &dyn ColorValue) -> Box<dyn ColorValue>;
    fn add_font(&self, value: &dyn FontValue) -> Box<dyn FontValue>;
    fn add_icon(&self, value: &dyn IconValue) -> Box<dyn IconValue>;
    fn add_property(&self, value: &dyn JavaPropertyValue) -> Box<dyn JavaPropertyValue>;
    fn get_color(&self, id: &str) -> Box<dyn ColorValue>;
    fn get_font(&self, id: &str) -> Box<dyn FontValue>;
    fn get_icon(&self, id: &str) -> Box<dyn IconValue>;
    fn get_property(&self, id: &str) -> Box<dyn JavaPropertyValue>;
    fn load(&self, value_map: &dyn GThemeValueMap);
    fn get_colors(&self) -> Vec<Box<dyn ColorValue>>;
    fn get_fonts(&self) -> Vec<Box<dyn FontValue>>;
    fn get_icons(&self) -> Vec<Box<dyn IconValue>>;
    fn get_properties(&self) -> Vec<Box<dyn JavaPropertyValue>>;
    fn contains_color(&self, id: &str) -> bool;
    fn contains_font(&self, id: &str) -> bool;
    fn contains_icon(&self, id: &str) -> bool;
    fn contains_property(&self, id: &str) -> bool;
    fn size(&self) -> Box<dyn std::any::Any>;
    fn clear(&self);
    fn is_empty(&self) -> bool;
    fn remove_color(&self, id: &str);
    fn remove_font(&self, id: &str);
    fn remove_icon(&self, id: &str);
    fn remove_property(&self, id: &str);
    fn get_changed_values(&self, base: &dyn GThemeValueMap) -> Box<dyn GThemeValueMap>;
    fn get_external_icon_files(&self) -> Vec<Box<dyn File>>;
    fn hash_code(&self) -> i32;
    fn equals(&self, obj: &dyn std::any::Any) -> bool;
    fn check_for_unresolved_references(&self);
    fn get_color_ids(&self) -> Vec<String>;
    fn get_font_ids(&self) -> Vec<String>;
    fn get_icon_ids(&self) -> Vec<String>;
    fn get_property_ids(&self) -> Vec<String>;
    fn get_resolved_color(&self, id: &str) -> Box<dyn Color>;
    fn get_resolved_font(&self, id: &str) -> Box<dyn Font>;
    fn get_resolved_icon(&self, id: &str) -> Box<dyn Icon>;
    fn get_resolved_property(&self, id: &str) -> Box<dyn std::any::Any>;
}

/// Placeholder for dependent types referenced by [`GThemeValueMap`].
pub trait ColorValue: Send + Sync {}
pub trait FontValue: Send + Sync {}
pub trait IconValue: Send + Sync {}
pub trait JavaPropertyValue: Send + Sync {}
pub trait File: Send + Sync {}
pub trait Color: Send + Sync {}
pub trait Font: Send + Sync {}
pub trait Icon: Send + Sync {}

/// Placeholder for the unported Java type `LafType`, referenced by
/// [`crate::generic::theme::application_theme_defaults::ApplicationThemeDefaults`].
/// Generated stub: only a shape hint. Replace with the real port when available.
pub trait LafType: Send + Sync {
    fn get_display_string(&self) -> String;
    fn get_name(&self) -> String;
    fn uses_dark_defaults(&self) -> bool;
    fn from_name(&self, name: &str) -> Box<dyn LafType>;
    fn is_supported(&self) -> bool;
    fn get_look_and_feel_manager(&self, theme_manager: &dyn ApplicationThemeManager) -> Box<dyn LookAndFeelManager>;
    fn get_default_look_and_feel(&self) -> Box<dyn LafType>;
    fn to_string(&self) -> String;
}

/// Placeholder for dependent types referenced by [`LafType`].
pub trait ApplicationThemeManager: Send + Sync {}
pub trait LookAndFeelManager: Send + Sync {}

/// Placeholder for the unported Java type `ThemeEvent`, referenced by
/// [`crate::generic::theme::theme_listener::ThemeListener`].
/// Generated stub: only a shape hint. Replace with the real port when available.
pub trait ThemeEvent: Send + Sync {
    fn is_color_changed(&self, id: &str) -> bool;
    fn is_font_changed(&self, id: &str) -> bool;
    fn is_icon_changed(&self, id: &str) -> bool;
    fn is_look_and_feel_changed(&self) -> bool;
    fn has_any_color_changed(&self) -> bool;
    fn has_any_font_changed(&self) -> bool;
    fn has_any_icon_changed(&self) -> bool;
    fn have_all_values_changed(&self) -> bool;
}
