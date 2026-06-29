/// Whether a version-tracking markup item's destination address can be edited.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VtMarkupItemDestinationAddressEditStatus {
    /// The destination address may be changed by the user.
    Editable,
    /// The destination address is locked to the function's entry point.
    UneditableFunctionEntryPoint,
    /// The destination address is locked to a data address.
    UneditableDataAddress,
    /// The match's association status prevents editing the destination address.
    UneditableUnappliableAssociationStatus,
    /// The markup item's own status prevents editing the destination address.
    UneditableUnappliableMarkupStatus,
}

impl VtMarkupItemDestinationAddressEditStatus {
    /// Returns the human-readable description for this status.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Editable =>
                "This item's destination address is editable.",
            Self::UneditableFunctionEntryPoint =>
                "This item's destination address is based on the \
                 function's entry point and can't be edited.",
            Self::UneditableDataAddress =>
                "This item's destination address is based on the \
                 address of data and can't be edited.",
            Self::UneditableUnappliableAssociationStatus =>
                "This markup item's Match status prevents its \
                 destination address from being edited.",
            Self::UneditableUnappliableMarkupStatus =>
                "This markup item's status prevents its \
                 destination address from being edited.",
        }
    }
}

impl std::fmt::Display for VtMarkupItemDestinationAddressEditStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Editable => "EDITABLE",
            Self::UneditableFunctionEntryPoint => "UNEDITABLE_FUNCTION_ENTRY_POINT",
            Self::UneditableDataAddress => "UNEDITABLE_DATA_ADDRESS",
            Self::UneditableUnappliableAssociationStatus => "UNEDITABLE_UNAPPLIABLE_ASSOCIATION_STATUS",
            Self::UneditableUnappliableMarkupStatus => "UNEDITABLE_UNAPPLIABLE_MARKUP_STATUS",
        };
        write!(f, "{}: {}", name, self.description())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editable_description() {
        assert_eq!(
            VtMarkupItemDestinationAddressEditStatus::Editable.description(),
            "This item's destination address is editable.",
        );
    }

    #[test]
    fn uneditable_function_entry_point_description() {
        let s = VtMarkupItemDestinationAddressEditStatus::UneditableFunctionEntryPoint
            .description();
        assert!(s.contains("function's entry point"));
        assert!(s.contains("can't be edited"));
    }

    #[test]
    fn uneditable_data_address_description() {
        let s = VtMarkupItemDestinationAddressEditStatus::UneditableDataAddress.description();
        assert!(s.contains("address of data"));
        assert!(s.contains("can't be edited"));
    }

    #[test]
    fn uneditable_association_status_description() {
        let s = VtMarkupItemDestinationAddressEditStatus::UneditableUnappliableAssociationStatus
            .description();
        assert!(s.contains("Match status"));
        assert!(s.contains("destination address"));
    }

    #[test]
    fn uneditable_markup_status_description() {
        let s = VtMarkupItemDestinationAddressEditStatus::UneditableUnappliableMarkupStatus
            .description();
        assert!(s.contains("markup item's status"));
        assert!(s.contains("destination address"));
    }

    #[test]
    fn display_includes_variant_name_and_description() {
        let v = VtMarkupItemDestinationAddressEditStatus::Editable;
        let s = v.to_string();
        assert!(s.starts_with("EDITABLE: "));
        assert!(s.contains("editable"));
    }

    #[test]
    fn display_uneditable_function_entry_point() {
        let v = VtMarkupItemDestinationAddressEditStatus::UneditableFunctionEntryPoint;
        assert!(v.to_string().starts_with("UNEDITABLE_FUNCTION_ENTRY_POINT: "));
    }

    #[test]
    fn variants_are_copy_and_eq() {
        let a = VtMarkupItemDestinationAddressEditStatus::Editable;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(a, VtMarkupItemDestinationAddressEditStatus::UneditableDataAddress);
    }

    #[test]
    fn all_variants_have_non_empty_description() {
        let variants = [
            VtMarkupItemDestinationAddressEditStatus::Editable,
            VtMarkupItemDestinationAddressEditStatus::UneditableFunctionEntryPoint,
            VtMarkupItemDestinationAddressEditStatus::UneditableDataAddress,
            VtMarkupItemDestinationAddressEditStatus::UneditableUnappliableAssociationStatus,
            VtMarkupItemDestinationAddressEditStatus::UneditableUnappliableMarkupStatus,
        ];
        for v in variants {
            assert!(!v.description().is_empty());
        }
    }
}
