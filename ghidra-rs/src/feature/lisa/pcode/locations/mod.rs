pub mod inst_location;

pub use inst_location::InstLocation;

use std::any::Any;
use std::cmp::Ordering;

/// Trait representing a code location in the LiSA analysis framework.
///
/// This trait mirrors the interface of `it.unive.lisa.program.cfg.CodeLocation`
/// from the LiSA library, adapted for Rust's type system.
pub trait CodeLocation: Any {
    /// Compares this code location with another.
    ///
    /// Returns an ordering based on the semantic position of the locations,
    /// or `Ordering::Less` if the comparison cannot be performed.
    fn compare_to(&self, other: &dyn CodeLocation) -> Ordering;

    /// Returns a string representation of the code location.
    fn get_code_location(&self) -> String;

    /// Returns this code location as an `Any` for downcasting.
    fn as_any(&self) -> &dyn Any;
}
