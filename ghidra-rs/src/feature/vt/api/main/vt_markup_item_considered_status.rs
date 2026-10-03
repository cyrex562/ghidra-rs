use super::vt_markup_item_status::VtMarkupItemStatus;

/// A status that the user can set on an item to signal that the item has been considered, but
/// not applied. This is useful for markup items that the user knows are incorrect or doesn't
/// care about. By setting the considered status of a markup item to one of these values, the
/// user can filter out items based upon that status.
///
/// Port of `ghidra.feature.vt.api.main.VTMarkupItemConsideredStatus`.
///
/// See `VTMarkupItem::setConsidered`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VtMarkupItemConsideredStatus {
    /// Indicates that a markup item has not been considered. This value exists in order to
    /// reset one of the other values in this enum.
    Unconsidered,

    /// Indicates that a markup item should be ignored because the user doesn't know if it
    /// should be applied.
    IgnoreDontKnow,

    /// Indicates that a markup item should be ignored because the user doesn't care if it
    /// should be applied.
    IgnoreDontCare,

    /// Indicates that the markup item should not be applied.
    Reject,
}

impl VtMarkupItemConsideredStatus {
    /// The status applied to the markup item when `VTMarkupItem::setConsidered` is called.
    ///
    /// Port of `VTMarkupItemConsideredStatus.getMarkupItemStatus()`.
    pub fn markup_item_status(&self) -> VtMarkupItemStatus {
        match self {
            Self::Unconsidered => VtMarkupItemStatus::Unapplied,
            Self::IgnoreDontKnow => VtMarkupItemStatus::DontKnow,
            Self::IgnoreDontCare => VtMarkupItemStatus::DontCare,
            Self::Reject => VtMarkupItemStatus::Rejected,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unconsidered_maps_to_unapplied() {
        assert_eq!(
            VtMarkupItemConsideredStatus::Unconsidered.markup_item_status(),
            VtMarkupItemStatus::Unapplied
        );
    }

    #[test]
    fn ignore_dont_know_maps_to_dont_know() {
        assert_eq!(
            VtMarkupItemConsideredStatus::IgnoreDontKnow.markup_item_status(),
            VtMarkupItemStatus::DontKnow
        );
    }

    #[test]
    fn ignore_dont_care_maps_to_dont_care() {
        assert_eq!(
            VtMarkupItemConsideredStatus::IgnoreDontCare.markup_item_status(),
            VtMarkupItemStatus::DontCare
        );
    }

    #[test]
    fn reject_maps_to_rejected() {
        assert_eq!(
            VtMarkupItemConsideredStatus::Reject.markup_item_status(),
            VtMarkupItemStatus::Rejected
        );
    }

    #[test]
    fn every_variant_maps_to_a_distinct_status() {
        let variants = [
            VtMarkupItemConsideredStatus::Unconsidered,
            VtMarkupItemConsideredStatus::IgnoreDontKnow,
            VtMarkupItemConsideredStatus::IgnoreDontCare,
            VtMarkupItemConsideredStatus::Reject,
        ];
        let mut statuses: Vec<VtMarkupItemStatus> =
            variants.iter().map(|v| v.markup_item_status()).collect();
        let unique_count = {
            statuses.sort_by_key(|s| format!("{s:?}"));
            statuses.dedup();
            statuses.len()
        };
        assert_eq!(unique_count, variants.len());
    }
}
