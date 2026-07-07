/// Parameters controlling a run of the closed sequence pattern mining algorithm.
///
/// Mirrors `ghidra.closedpatternmining.SequenceMiningParams`.
pub struct SequenceMiningParams {
    min_percentage: f64,
    required_bits_of_check: i32,
    use_binary: bool,
}

impl SequenceMiningParams {
    /// Creates a new [`SequenceMiningParams`].
    ///
    /// - `min_percentage`: fraction of sequences in the database that must contain a pattern
    ///   for it to be considered "frequent".
    /// - `min_bits_of_check`: minimum number of non-ditted (fixed) bits a pattern must have
    ///   before it is shown to the user.
    /// - `use_binary`: when `true`, sequences are treated as binary strings; when `false`,
    ///   they are treated as nibble (character) sequences.
    pub fn new(min_percentage: f64, min_bits_of_check: i32, use_binary: bool) -> Self {
        Self {
            min_percentage,
            required_bits_of_check: min_bits_of_check,
            use_binary,
        }
    }

    /// Returns the minimum percentage of sequences that must contain a pattern for it to be
    /// deemed "frequent".
    pub fn get_min_percentage(&self) -> f64 {
        self.min_percentage
    }

    /// Returns the minimum number of fixed bits a pattern must contain before it is displayed
    /// to the user.
    pub fn get_required_bits_of_check(&self) -> i32 {
        self.required_bits_of_check
    }

    /// Returns whether sequences are treated as binary strings (`true`) or nibble sequences
    /// (`false`).
    pub fn get_use_binary(&self) -> bool {
        self.use_binary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_and_accessors() {
        let params = SequenceMiningParams::new(0.75, 8, true);
        assert_eq!(params.get_min_percentage(), 0.75);
        assert_eq!(params.get_required_bits_of_check(), 8);
        assert!(params.get_use_binary());
    }

    #[test]
    fn nibble_mode() {
        let params = SequenceMiningParams::new(0.5, 4, false);
        assert!(!params.get_use_binary());
    }

    #[test]
    fn zero_percentage() {
        let params = SequenceMiningParams::new(0.0, 0, false);
        assert_eq!(params.get_min_percentage(), 0.0);
        assert_eq!(params.get_required_bits_of_check(), 0);
    }

    #[test]
    fn full_percentage() {
        let params = SequenceMiningParams::new(1.0, 64, true);
        assert_eq!(params.get_min_percentage(), 1.0);
        assert_eq!(params.get_required_bits_of_check(), 64);
    }
}
