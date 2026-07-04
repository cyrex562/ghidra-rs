use super::RelocationStatus;

/// Provides the status and byte-length of a processed relocation during the program load process.
///
/// Intended to be used internally by a relocation handler. A positive byte-length is only
/// required for a status of [`RelocationStatus::Applied`] or [`RelocationStatus::AppliedOther`].
/// Use if [`RelocationStatus::Unknown`] should be avoided and is intended for relocation data
/// upgrades when actual status cannot be determined.
///
/// Singleton instances are provided for relocations which did not directly result in original
/// loaded memory modification.
///
/// Mirrors `ghidra.program.model.reloc.RelocationResult`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelocationResult {
    /// The relocation status
    pub status: RelocationStatus,
    /// The number of original bytes modified at relocation offset if successfully
    /// applied and memory bytes were modified.
    pub byte_length: i32,
}

impl RelocationResult {
    /// Creates a new `RelocationResult`.
    pub const fn new(status: RelocationStatus, byte_length: i32) -> Self {
        Self {
            status,
            byte_length,
        }
    }

    /// Returns the status of this relocation result.
    pub const fn status(&self) -> RelocationStatus {
        self.status
    }

    /// Returns the byte length of this relocation result.
    pub const fn byte_length(&self) -> i32 {
        self.byte_length
    }

    /// See [`RelocationStatus::Failure`]
    pub const FAILURE: Self = Self::new(RelocationStatus::Failure, 0);

    /// See [`RelocationStatus::Unsupported`]
    pub const UNSUPPORTED: Self = Self::new(RelocationStatus::Unsupported, 0);

    /// See [`RelocationStatus::Skipped`]
    pub const SKIPPED: Self = Self::new(RelocationStatus::Skipped, 0);

    /// See [`RelocationStatus::Partial`]
    pub const PARTIAL: Self = Self::new(RelocationStatus::Partial, 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_relocation_result() {
        let result = RelocationResult::new(RelocationStatus::Applied, 4);
        assert_eq!(result.status(), RelocationStatus::Applied);
        assert_eq!(result.byte_length(), 4);
    }

    #[test]
    fn failure_singleton() {
        assert_eq!(RelocationResult::FAILURE.status(), RelocationStatus::Failure);
        assert_eq!(RelocationResult::FAILURE.byte_length(), 0);
    }

    #[test]
    fn unsupported_singleton() {
        assert_eq!(
            RelocationResult::UNSUPPORTED.status(),
            RelocationStatus::Unsupported
        );
        assert_eq!(RelocationResult::UNSUPPORTED.byte_length(), 0);
    }

    #[test]
    fn skipped_singleton() {
        assert_eq!(RelocationResult::SKIPPED.status(), RelocationStatus::Skipped);
        assert_eq!(RelocationResult::SKIPPED.byte_length(), 0);
    }

    #[test]
    fn partial_singleton() {
        assert_eq!(RelocationResult::PARTIAL.status(), RelocationStatus::Partial);
        assert_eq!(RelocationResult::PARTIAL.byte_length(), 0);
    }

    #[test]
    fn relocation_result_copy() {
        let result1 = RelocationResult::new(RelocationStatus::Applied, 8);
        let result2 = result1;
        assert_eq!(result1, result2);
    }

    #[test]
    fn relocation_result_equality() {
        let result1 = RelocationResult::new(RelocationStatus::Applied, 4);
        let result2 = RelocationResult::new(RelocationStatus::Applied, 4);
        assert_eq!(result1, result2);

        let result3 = RelocationResult::new(RelocationStatus::Applied, 8);
        assert_ne!(result1, result3);

        let result4 = RelocationResult::new(RelocationStatus::Skipped, 4);
        assert_ne!(result1, result4);
    }

    #[test]
    fn applied_requires_positive_byte_length() {
        let result = RelocationResult::new(RelocationStatus::Applied, 4);
        assert!(result.byte_length() > 0);
    }

    #[test]
    fn applied_other_requires_positive_byte_length() {
        let result = RelocationResult::new(RelocationStatus::AppliedOther, 2);
        assert!(result.byte_length() > 0);
    }

    #[test]
    fn failure_has_zero_byte_length() {
        assert_eq!(RelocationResult::FAILURE.byte_length(), 0);
    }

    #[test]
    fn unsupported_has_zero_byte_length() {
        assert_eq!(RelocationResult::UNSUPPORTED.byte_length(), 0);
    }

    #[test]
    fn skipped_has_zero_byte_length() {
        assert_eq!(RelocationResult::SKIPPED.byte_length(), 0);
    }

    #[test]
    fn partial_has_zero_byte_length() {
        assert_eq!(RelocationResult::PARTIAL.byte_length(), 0);
    }
}
