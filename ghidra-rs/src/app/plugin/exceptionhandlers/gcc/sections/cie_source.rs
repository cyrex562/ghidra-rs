//! Ported from `ghidra.app.plugin.exceptionhandlers.gcc.sections.CieSource`.
//!
//! Provides GCC exception handling model classes the means to obtain a Common Information Entry
//! (CIE) object for a given address.

use crate::app::seam_stubs::Cie;
use crate::program::model::address::Address;
use crate::program::model::mem::MemoryAccessException;
use crate::app::plugin::exceptionhandlers::gcc::ExceptionHandlerFrameException;
use std::error::Error;
use std::fmt;

/// Error type for CieSource operations, wrapping both possible exception types.
#[derive(Debug)]
pub enum CieSourceError {
    /// Memory access failed.
    MemoryAccess(MemoryAccessException),
    /// Exception handling frame error occurred.
    ExceptionHandlerFrame(ExceptionHandlerFrameException),
}

impl fmt::Display for CieSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CieSourceError::MemoryAccess(e) => write!(f, "Memory access error: {}", e),
            CieSourceError::ExceptionHandlerFrame(e) => {
                write!(f, "Exception handler frame error: {}", e)
            }
        }
    }
}

impl Error for CieSourceError {}

impl From<MemoryAccessException> for CieSourceError {
    fn from(e: MemoryAccessException) -> Self {
        CieSourceError::MemoryAccess(e)
    }
}

impl From<ExceptionHandlerFrameException> for CieSourceError {
    fn from(e: ExceptionHandlerFrameException) -> Self {
        CieSourceError::ExceptionHandlerFrame(e)
    }
}

/// Provides GCC exception handling model classes the means to obtain a Common Information Entry
/// (CIE) object for a given address.
///
/// Java `interface CieSource` -- a genuine extension point with one abstract method, implemented
/// by concrete CIE source implementations.
pub trait CieSource {
    /// For the provided address, return a Common Information Entry (CIE).
    ///
    /// # Arguments
    /// * `curr_address` - the address with the CIE
    ///
    /// # Returns
    /// The Cie at `curr_address`
    ///
    /// # Errors
    /// * Returns `CieSourceError::MemoryAccess` if memory for the CIE couldn't be read
    /// * Returns `CieSourceError::ExceptionHandlerFrame` if a problem was encountered
    fn get_cie(&self, curr_address: &Address) -> Result<Box<dyn Cie>, CieSourceError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A minimal stub implementor for testing purposes.
    struct StubCieSource;

    /// A minimal stub Cie for testing purposes.
    struct StubCie {
        address: Address,
    }

    impl Cie for StubCie {
        fn is_in_debug_frame(&self) -> bool {
            false
        }

        fn create(&self, _cie_address: &Address) -> std::io::Result<()> {
            Ok(())
        }

        fn get_next_address(&self) -> Address {
            self.address.clone()
        }

        fn get_augmentation_string(&self) -> String {
            String::from("test")
        }

        fn get_fde_encoding(&self) -> i32 {
            0
        }

        fn get_fde_decoder(&self) -> Box<dyn crate::app::plugin::exceptionhandlers::gcc::DwarfEHDecoder> {
            unimplemented!()
        }

        fn get_lsda_encoding(&self) -> i32 {
            0
        }

        fn get_lsda_decoder(&self) -> Box<dyn crate::app::plugin::exceptionhandlers::gcc::DwarfEHDecoder> {
            unimplemented!()
        }

        fn get_address(&self) -> Address {
            self.address.clone()
        }

        fn get_data_alignment(&self) -> i32 {
            1
        }

        fn get_code_alignment(&self) -> i32 {
            1
        }

        fn is_end_of_frame(&self) -> bool {
            false
        }

        fn get_segment_size(&self) -> i32 {
            0
        }

        fn get_return_address_register_column(&self) -> i32 {
            0
        }

        fn get_cie_id(&self) -> i32 {
            0
        }
    }

    impl CieSource for StubCieSource {
        fn get_cie(&self, curr_address: &Address) -> Result<Box<dyn Cie>, CieSourceError> {
            Ok(Box::new(StubCie {
                address: curr_address.clone(),
            }))
        }
    }

    #[test]
    fn test_get_cie_success() {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, 0x1000);
        let source = StubCieSource;
        let result = source.get_cie(&addr);
        assert!(result.is_ok());
        let cie = result.unwrap();
        assert_eq!(cie.get_data_alignment(), 1);
        assert_eq!(cie.get_code_alignment(), 1);
        assert_eq!(cie.get_augmentation_string(), "test");
    }

    #[test]
    fn test_cie_source_error_display() {
        let mem_err = MemoryAccessException::new("test memory error");
        let err: CieSourceError = mem_err.into();
        let msg = err.to_string();
        assert!(msg.contains("Memory access error"));
    }

    #[test]
    fn test_cie_source_error_display_ehframe() {
        let frame_err = ExceptionHandlerFrameException::with_message("test frame error");
        let err: CieSourceError = frame_err.into();
        let msg = err.to_string();
        assert!(msg.contains("Exception handler frame error"));
    }
}
