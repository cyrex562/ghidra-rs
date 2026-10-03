//! Port of `ghidra.machinelearning.functionfinding.RandomForestRowObject`.
//!
//! A row object for a table whose rows are associated with models trained to find function
//! starts. Java is a concrete leaf class (nothing extends it), so this becomes a plain `struct`.
//!
//! # Seams
//!
//! * **`org.tribuo.ensemble.EnsembleModel<Label>` (the trained model).** Tribuo is a third-party
//!   ML library with no Rust port in this crate (see
//!   [`RandomForestFunctionFinderPlugin`](super::random_forest_function_finder_plugin)'s module
//!   docs for the same gap). This row object never calls a method on the model -- it only stores
//!   the constructor argument and returns it from a getter -- so it is carried as a type-erased
//!   `Arc<dyn Any + Send + Sync>` handle, the same convention that sibling file already
//!   established for other unported tribuo-shaped values.
//! * **`RandomForestTrainingTask.{TP,FP,TN,FN}`.** The Java constructor indexes `confusionMatrix`
//!   by these four `public static final int` constants declared on `RandomForestTrainingTask`.
//!   That class's own port is blocked on tribuo (`Dataset<Label>`, `CART` trainers, etc. --
//!   see `RandomForestTrainingTask.java`), but the four constants themselves are pure data with
//!   no tribuo dependency, so they are reproduced directly here as [`CM_TP`]/[`CM_FP`]/[`CM_TN`]/
//!   [`CM_FN`] rather than pulling in a stub for the whole (unrelated) task class.
//! * **`java.math.BigInteger` (context register values).** No arbitrary-precision integer type
//!   exists in this crate. [`RegisterValue`](crate::program::model::lang::register_value::RegisterValue)
//!   already committed the crate's register-value ceiling to `u128` (128 bits covers every
//!   register width this crate models), so context register values are carried as `u128` here
//!   too rather than introducing a new representation.
//! * **`java.math.BigDecimal` (precision/recall).** No decimal type exists in this crate either.
//!   Both fields are `TP / (TP + FP)` and `TP / (TP + FN)` scaled to 2 decimal digits with
//!   `RoundingMode.HALF_EVEN` ("banker's rounding"); reproduced with `f64` division plus a
//!   half-to-even rounding helper ([`round_half_even_2dp`]) rather than a bignum crate, since the
//!   inputs are small integer counts where `f64` has no meaningful precision loss.

use std::any::Any;
use std::sync::Arc;

use crate::program::model::address::AddressSet;

/// Confusion-matrix slot index for true positives. Mirrors `RandomForestTrainingTask.TP`.
pub const CM_TP: usize = 0;
/// Confusion-matrix slot index for false positives. Mirrors `RandomForestTrainingTask.FP`.
pub const CM_FP: usize = 1;
/// Confusion-matrix slot index for true negatives. Mirrors `RandomForestTrainingTask.TN`.
pub const CM_TN: usize = 2;
/// Confusion-matrix slot index for false negatives. Mirrors `RandomForestTrainingTask.FN`.
pub const CM_FN: usize = 3;
/// Confusion-matrix array length. Mirrors `RandomForestTrainingTask.CONFUSION_MATRIX_SIZE`.
pub const CONFUSION_MATRIX_SIZE: usize = 4;

/// `numerator / denominator`, scaled to 2 decimal digits with round-half-to-even.
///
/// Mirrors `new BigDecimal(numerator).divide(new BigDecimal(denominator), 2,
/// RoundingMode.HALF_EVEN)`. Caller guarantees `denominator != 0`.
fn round_half_even_2dp(numerator: f64, denominator: f64) -> f64 {
    let scaled = numerator / denominator * 100.0;
    let floor = scaled.floor();
    let diff = scaled - floor;
    let rounded = if (diff - 0.5).abs() < 1e-9 {
        // Exactly halfway: round to the even neighbor.
        if (floor as i64) % 2 == 0 {
            floor
        } else {
            floor + 1.0
        }
    } else {
        scaled.round()
    };
    rounded / 100.0
}

/// A row in a table associating a trained random-forest model with its evaluation results.
///
/// Port of `ghidra.machinelearning.functionfinding.RandomForestRowObject`.
pub struct RandomForestRowObject {
    precision: Option<f64>,
    recall: Option<f64>,
    num_pre_bytes: i32,
    num_initial_bytes: i32,
    sampling_factor: i32,
    include_bit_level_features: bool,
    context_registers: Vec<String>,
    context_register_values: Vec<u128>,
    random_forest: Arc<dyn Any + Send + Sync>,
    test_errors: AddressSet,
    training_positive: AddressSet,
    confusion_matrix: [i32; CONFUSION_MATRIX_SIZE],
}

impl RandomForestRowObject {
    /// Constructs a row.
    ///
    /// `random_forest` is the trained model, carried as a type-erased handle -- see the module
    /// docs' Seams section for why.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        num_pre_bytes: i32,
        num_initial_bytes: i32,
        sampling_factor: i32,
        confusion_matrix: [i32; CONFUSION_MATRIX_SIZE],
        random_forest: Arc<dyn Any + Send + Sync>,
        test_errors: AddressSet,
        training_positive: AddressSet,
        include_bit_level_features: bool,
    ) -> Self {
        let tp = confusion_matrix[CM_TP] as f64;
        let fp = confusion_matrix[CM_FP] as f64;
        let fnv = confusion_matrix[CM_FN] as f64;

        let precision_denom = tp + fp;
        let precision = if precision_denom == 0.0 {
            None
        } else {
            Some(round_half_even_2dp(tp, precision_denom))
        };

        let recall_denom = tp + fnv;
        let recall = if recall_denom == 0.0 {
            None
        } else {
            Some(round_half_even_2dp(tp, recall_denom))
        };

        Self {
            precision,
            recall,
            num_pre_bytes,
            num_initial_bytes,
            sampling_factor,
            random_forest,
            test_errors,
            context_registers: Vec::new(),
            context_register_values: Vec::new(),
            confusion_matrix,
            include_bit_level_features,
            training_positive,
        }
    }

    /// Sets the values for context registers the model is aware of.
    ///
    /// # Panics
    ///
    /// Panics if `reg_list` and `value_list` differ in length. Java: `IllegalArgumentException`,
    /// an unchecked exception with no direct `Result`-typed equivalent in this port's
    /// constructors/setters (see e.g. `SFOverviewInfo::new`'s docs elsewhere in this crate for the
    /// same convention).
    pub fn set_context_registers_and_values(
        &mut self,
        reg_list: Vec<String>,
        value_list: Vec<u128>,
    ) {
        if reg_list.len() != value_list.len() {
            panic!("Register list and value list must have the same size!");
        }
        self.context_registers = reg_list;
        self.context_register_values = value_list;
    }

    /// Returns whether the model is aware of any context registers.
    pub fn is_context_restricted(&self) -> bool {
        !self.context_registers.is_empty()
    }

    /// Returns the names of the context registers the model is aware of.
    pub fn context_register_list(&self) -> &[String] {
        &self.context_registers
    }

    /// Returns the values of the context registers the model is aware of.
    pub fn context_register_values(&self) -> &[u128] {
        &self.context_register_values
    }

    /// Returns the precision of the model on the test set, or `None` if undefined (zero
    /// predicted positives).
    pub fn precision(&self) -> Option<f64> {
        self.precision
    }

    /// Returns the recall of the model on the test set, or `None` if undefined (zero actual
    /// positives).
    pub fn recall(&self) -> Option<f64> {
        self.recall
    }

    /// Returns whether bit-level features were included when training the model.
    pub fn include_bit_level_features(&self) -> bool {
        self.include_bit_level_features
    }

    /// Returns the number of pre-bytes used when training the model.
    pub fn num_pre_bytes(&self) -> i32 {
        self.num_pre_bytes
    }

    /// Returns the sampling factor used when training the model.
    pub fn sampling_factor(&self) -> i32 {
        self.sampling_factor
    }

    /// Returns the number of initial bytes used when training the model.
    pub fn num_initial_bytes(&self) -> i32 {
        self.num_initial_bytes
    }

    /// Returns the model, as a type-erased handle. See the module docs' Seams section.
    pub fn random_forest(&self) -> &Arc<dyn Any + Send + Sync> {
        &self.random_forest
    }

    /// Returns the addresses in the test set where the model made an error.
    pub fn test_errors(&self) -> &AddressSet {
        &self.test_errors
    }

    /// Returns the number of false positives the model produces when classifying the test set.
    pub fn num_false_positives(&self) -> i32 {
        self.confusion_matrix[CM_FP]
    }

    /// Returns the set of function starts in the training set.
    pub fn training_positives(&self) -> &AddressSet {
        &self.training_positive
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> Arc<dyn Any + Send + Sync> {
        Arc::new(())
    }

    /// TP=8, FP=2, TN=85, FN=5 -> precision = 8/10 = 0.80, recall = 8/13 = 0.6153... rounds to 0.62
    /// (Java: `new BigDecimal(8).divide(new BigDecimal(13), 2, RoundingMode.HALF_EVEN)` = 0.62).
    #[test]
    fn constructor_computes_precision_and_recall() {
        let cm = [8, 2, 85, 5];
        let row = RandomForestRowObject::new(
            4,
            16,
            10,
            cm,
            model(),
            AddressSet::new(),
            AddressSet::new(),
            true,
        );
        assert_eq!(row.precision(), Some(0.80));
        assert_eq!(row.recall(), Some(0.62));
        assert_eq!(row.num_false_positives(), 2);
        assert_eq!(row.num_pre_bytes(), 4);
        assert_eq!(row.num_initial_bytes(), 16);
        assert_eq!(row.sampling_factor(), 10);
        assert!(row.include_bit_level_features());
        assert!(!row.is_context_restricted());
    }

    /// TP=0, FP=0 -> precision denominator zero -> `None`, matching Java's `precision = null`.
    #[test]
    fn zero_denominator_precision_is_none() {
        let cm = [0, 0, 100, 5];
        let row = RandomForestRowObject::new(
            4, 16, 10, cm, model(), AddressSet::new(), AddressSet::new(), false,
        );
        assert_eq!(row.precision(), None);
        // recall = 0 / (0 + 5) = 0.00, still defined.
        assert_eq!(row.recall(), Some(0.0));
    }

    /// TP=0, FN=0 -> recall denominator zero -> `None`.
    #[test]
    fn zero_denominator_recall_is_none() {
        let cm = [0, 5, 100, 0];
        let row = RandomForestRowObject::new(
            4, 16, 10, cm, model(), AddressSet::new(), AddressSet::new(), false,
        );
        assert_eq!(row.precision(), Some(0.0));
        assert_eq!(row.recall(), None);
    }

    #[test]
    fn set_context_registers_and_values_round_trip() {
        let cm = [1, 0, 0, 0];
        let mut row = RandomForestRowObject::new(
            4, 16, 10, cm, model(), AddressSet::new(), AddressSet::new(), false,
        );
        assert!(!row.is_context_restricted());
        row.set_context_registers_and_values(
            vec!["contextreg".to_string()],
            vec![7u128],
        );
        assert!(row.is_context_restricted());
        assert_eq!(row.context_register_list(), &["contextreg".to_string()]);
        assert_eq!(row.context_register_values(), &[7u128]);
    }

    #[test]
    #[should_panic(expected = "must have the same size")]
    fn set_context_registers_and_values_mismatched_lengths_panics() {
        let cm = [1, 0, 0, 0];
        let mut row = RandomForestRowObject::new(
            4, 16, 10, cm, model(), AddressSet::new(), AddressSet::new(), false,
        );
        row.set_context_registers_and_values(vec!["a".to_string(), "b".to_string()], vec![1u128]);
    }
}
