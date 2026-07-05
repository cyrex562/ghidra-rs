use crate::program::seam_stubs::DataType;

/// Identifies a flavor of data offered by a [`DataTypeTransferable`], standing in for
/// `java.awt.datatransfer.DataFlavor`. Ghidra's local flavors are always the MIME type
/// `application/x-java-jvm-local-objectref; class=ghidra.program.model.data.DataTypeImpl`
/// paired with a human-readable description, so equality/lookup is done on the MIME string,
/// mirroring `DataFlavor.equals`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataFlavor {
    mime_type: String,
    description: String,
}

impl DataFlavor {
    pub fn new(mime_type: impl Into<String>, description: impl Into<String>) -> Self {
        Self { mime_type: mime_type.into(), description: description.into() }
    }

    /// The MIME type string identifying this flavor.
    pub fn mime_type(&self) -> &str {
        &self.mime_type
    }

    /// A human-readable description of this flavor.
    pub fn description(&self) -> &str {
        &self.description
    }
}

/// Error returned by [`DataTypeTransferable::transfer_data`] when the requested flavor is not
/// supported, standing in for `java.awt.datatransfer.UnsupportedFlavorException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedFlavorError(pub DataFlavor);

impl std::fmt::Display for UnsupportedFlavorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unsupported data flavor: {}", self.0.description())
    }
}

impl std::error::Error for UnsupportedFlavorError {}

/// Data that is available for drag/drop and clipboard transfers. The transferred data is a
/// [`DataType`], standing in for `java.awt.datatransfer.Transferable` combined with
/// `java.awt.datatransfer.ClipboardOwner`.
///
/// Port of `ghidra.program.model.data.DataTypeTransferable`.
pub trait DataTypeTransferable {
    /// Returns all data flavors that this instance supports.
    fn transfer_data_flavors(&self) -> Vec<DataFlavor>;

    /// Returns whether the specified data flavor is supported.
    fn is_data_flavor_supported(&self, flavor: &DataFlavor) -> bool {
        self.transfer_data_flavors().iter().any(|supported| supported == flavor)
    }

    /// Returns the transfer data for the given flavor, or an error if the flavor is not
    /// supported.
    fn transfer_data(
        &self,
        flavor: &DataFlavor,
    ) -> Result<Box<dyn DataType>, UnsupportedFlavorError>;

    /// Called when this instance is no longer the clipboard owner.
    fn lost_ownership(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType;
    impl DataType for MockDataType {}

    fn local_data_type_flavor() -> DataFlavor {
        DataFlavor::new(
            "application/x-java-jvm-local-objectref; class=ghidra.program.model.data.DataTypeImpl",
            "Local data type object",
        )
    }

    fn local_builtin_data_type_flavor() -> DataFlavor {
        DataFlavor::new(
            "application/x-java-jvm-local-objectref; class=ghidra.program.model.data.DataTypeImpl",
            "Local BuiltIn data type object",
        )
    }

    struct MockDataTypeTransferable {
        flavors: Vec<DataFlavor>,
    }

    impl DataTypeTransferable for MockDataTypeTransferable {
        fn transfer_data_flavors(&self) -> Vec<DataFlavor> {
            self.flavors.clone()
        }

        fn transfer_data(
            &self,
            flavor: &DataFlavor,
        ) -> Result<Box<dyn DataType>, UnsupportedFlavorError> {
            if self.is_data_flavor_supported(flavor) {
                Ok(Box::new(MockDataType))
            } else {
                Err(UnsupportedFlavorError(flavor.clone()))
            }
        }
    }

    fn mock() -> MockDataTypeTransferable {
        MockDataTypeTransferable {
            flavors: vec![local_data_type_flavor(), local_builtin_data_type_flavor()],
        }
    }

    #[test]
    fn supports_declared_flavors() {
        let transferable = mock();
        assert!(transferable.is_data_flavor_supported(&local_data_type_flavor()));
        assert!(transferable.is_data_flavor_supported(&local_builtin_data_type_flavor()));
    }

    #[test]
    fn rejects_unknown_flavor() {
        let transferable = mock();
        let unknown = DataFlavor::new("text/plain", "Plain text");
        assert!(!transferable.is_data_flavor_supported(&unknown));
        assert!(transferable.transfer_data(&unknown).is_err());
    }

    #[test]
    fn transfer_data_returns_data_type_for_supported_flavor() {
        let transferable = mock();
        assert!(transferable.transfer_data(&local_data_type_flavor()).is_ok());
    }

    #[test]
    fn usable_as_trait_object() {
        let transferable = mock();
        let dyn_transferable: &dyn DataTypeTransferable = &transferable;
        assert_eq!(dyn_transferable.transfer_data_flavors().len(), 2);
        dyn_transferable.lost_ownership();
    }
}
