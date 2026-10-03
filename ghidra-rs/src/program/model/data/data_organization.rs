//! Port of `ghidra.program.model.data.DataOrganization`.
//!
//! Java declares `DataOrganization` as an interface whose only implementation is
//! `DataOrganizationImpl`, so the interface's methods (including its default `isEquivalent`) are
//! ported on the concrete
//! [`DataOrganizationImpl`](super::data_organization_impl::DataOrganizationImpl), which every
//! caller takes. The interface's one constant lives here.

/// Value returned by
/// [`DataOrganizationImpl::get_absolute_max_alignment`](super::data_organization_impl::DataOrganizationImpl::get_absolute_max_alignment)
/// when the data organization does not specifically limit the maximum alignment.
///
/// Port of `DataOrganization.NO_MAXIMUM_ALIGNMENT`.
pub const NO_MAXIMUM_ALIGNMENT: i32 = 0;
