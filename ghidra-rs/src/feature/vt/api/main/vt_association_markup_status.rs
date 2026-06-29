const INITIALIZED: i32 = 0x1;
const HAS_UNEXAMINED: i32 = 0x2;
const HAS_APPLIED: i32 = 0x4;
const HAS_REJECTED: i32 = 0x8;
const HAS_DONT_CARE: i32 = 0x10;
const HAS_DONT_KNOW: i32 = 0x20;
const HAS_ERRORS: i32 = 0x40;

/// High-level overview of the markup-item state for a version-tracking association.
///
/// The `status` field is a compact bit-field; each bit records whether at least one
/// markup item in the associated group is in that particular state.  A zero value
/// means the status has never been initialised (the association has not yet been
/// accepted).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VtAssociationMarkupStatus {
    status: i32,
}

impl VtAssociationMarkupStatus {
    /// Creates an uninitialised status (all bits clear).
    pub fn new() -> Self {
        Self { status: 0 }
    }

    /// Creates a status directly from the packed bit-field value returned by
    /// [`status_value`].
    pub fn from_status(status: i32) -> Self {
        Self { status }
    }

    /// Creates an initialised status from individual flags.
    pub fn from_flags(
        has_unexamined: bool,
        has_applied: bool,
        has_rejected: bool,
        has_dont_care: bool,
        has_dont_know: bool,
        has_errors: bool,
    ) -> Self {
        let mut status = INITIALIZED;
        if has_unexamined { status |= HAS_UNEXAMINED; }
        if has_applied    { status |= HAS_APPLIED; }
        if has_rejected   { status |= HAS_REJECTED; }
        if has_dont_care  { status |= HAS_DONT_CARE; }
        if has_dont_know  { status |= HAS_DONT_KNOW; }
        if has_errors     { status |= HAS_ERRORS; }
        Self { status }
    }

    /// Returns `true` if the status has been initialised (i.e. the association has
    /// been accepted at least once).
    pub fn is_initialized(&self) -> bool {
        self.status & INITIALIZED != 0
    }

    /// Returns `true` if at least one markup item has not yet been applied or
    /// marked as considered.
    pub fn has_unexamined_markup(&self) -> bool {
        self.status & HAS_UNEXAMINED != 0
    }

    /// Returns `true` if at least one markup item has been applied.
    pub fn has_applied_markup(&self) -> bool {
        self.status & HAS_APPLIED != 0
    }

    /// Returns `true` if at least one markup item has been rejected.
    pub fn has_rejected_markup(&self) -> bool {
        self.status & HAS_REJECTED != 0
    }

    /// Returns `true` if at least one markup item has been marked as "Don't Care".
    pub fn has_dont_care_markup(&self) -> bool {
        self.status & HAS_DONT_CARE != 0
    }

    /// Returns `true` if at least one markup item has been marked as "Don't Know".
    pub fn has_dont_know_markup(&self) -> bool {
        self.status & HAS_DONT_KNOW != 0
    }

    /// Returns `true` if at least one markup item encountered an error when
    /// attempting to apply.
    pub fn has_errors(&self) -> bool {
        self.status & HAS_ERRORS != 0
    }

    /// Returns the packed bit-field value for serialisation or persistence.
    pub fn status_value(&self) -> i32 {
        self.status
    }

    /// Returns `true` if every markup item has been applied (no unexamined,
    /// rejected, don't-care, don't-know, or error items remain).
    pub fn is_fully_applied(&self) -> bool {
        self.status == INITIALIZED || self.status == (INITIALIZED | HAS_APPLIED)
    }

    /// Returns a human-readable description listing the active status flags.
    pub fn description(&self) -> String {
        let mut buf = String::new();
        if self.has_unexamined_markup() {
            buf.push_str("Has one or more unexamined markup items.\n");
        }
        if self.has_applied_markup() {
            buf.push_str("Has one or more applied markup items.\n");
        }
        if self.has_errors() {
            buf.push_str("Has one or more markup items that failed to apply.\n");
        }
        if self.has_dont_care_markup() {
            buf.push_str("Has one or more \"Don't Care\" markup items.\n");
        }
        if self.has_dont_know_markup() {
            buf.push_str("Has one or more \"Don't Know\" markup items.\n");
        }
        buf
    }
}

impl Default for VtAssociationMarkupStatus {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialOrd for VtAssociationMarkupStatus {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VtAssociationMarkupStatus {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.status.cmp(&other.status)
    }
}

impl std::fmt::Display for VtAssociationMarkupStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Markup Status: {}", self.description())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_uninitialized() {
        let s = VtAssociationMarkupStatus::default();
        assert!(!s.is_initialized());
        assert_eq!(s.status_value(), 0);
    }

    #[test]
    fn from_status_roundtrip() {
        let s = VtAssociationMarkupStatus::from_status(0x47);
        assert_eq!(s.status_value(), 0x47);
    }

    #[test]
    fn from_flags_sets_initialized_bit() {
        let s = VtAssociationMarkupStatus::from_flags(false, false, false, false, false, false);
        assert!(s.is_initialized());
        assert_eq!(s.status_value(), INITIALIZED);
    }

    #[test]
    fn from_flags_all_true() {
        let s = VtAssociationMarkupStatus::from_flags(true, true, true, true, true, true);
        assert!(s.is_initialized());
        assert!(s.has_unexamined_markup());
        assert!(s.has_applied_markup());
        assert!(s.has_rejected_markup());
        assert!(s.has_dont_care_markup());
        assert!(s.has_dont_know_markup());
        assert!(s.has_errors());
    }

    #[test]
    fn is_fully_applied_only_initialized() {
        let s = VtAssociationMarkupStatus::from_flags(false, false, false, false, false, false);
        assert!(s.is_fully_applied());
    }

    #[test]
    fn is_fully_applied_with_applied_flag() {
        let s = VtAssociationMarkupStatus::from_flags(false, true, false, false, false, false);
        assert!(s.is_fully_applied());
    }

    #[test]
    fn is_fully_applied_false_when_unexamined() {
        let s = VtAssociationMarkupStatus::from_flags(true, false, false, false, false, false);
        assert!(!s.is_fully_applied());
    }

    #[test]
    fn is_fully_applied_false_when_uninitialized() {
        let s = VtAssociationMarkupStatus::new();
        assert!(!s.is_fully_applied());
    }

    #[test]
    fn equality_based_on_status_field() {
        let a = VtAssociationMarkupStatus::from_status(0x5);
        let b = VtAssociationMarkupStatus::from_status(0x5);
        let c = VtAssociationMarkupStatus::from_status(0x7);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn ordering_by_status_value() {
        let lo = VtAssociationMarkupStatus::from_status(1);
        let hi = VtAssociationMarkupStatus::from_status(10);
        assert!(lo < hi);
        assert!(hi > lo);
        assert_eq!(lo.cmp(&lo), std::cmp::Ordering::Equal);
    }

    #[test]
    fn description_lists_active_flags() {
        let s = VtAssociationMarkupStatus::from_flags(true, false, false, false, false, true);
        let d = s.description();
        assert!(d.contains("unexamined"));
        assert!(d.contains("failed to apply"));
        assert!(!d.contains("applied markup"));
    }

    #[test]
    fn display_includes_prefix() {
        let s = VtAssociationMarkupStatus::from_flags(false, true, false, false, false, false);
        assert!(s.to_string().starts_with("Markup Status: "));
    }

    #[test]
    fn hash_equal_objects_same_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let a = VtAssociationMarkupStatus::from_status(0x3);
        let b = VtAssociationMarkupStatus::from_status(0x3);
        let mut ha = DefaultHasher::new();
        a.hash(&mut ha);
        let mut hb = DefaultHasher::new();
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }
}
