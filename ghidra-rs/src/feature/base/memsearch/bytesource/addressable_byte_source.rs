use std::sync::Arc;

use crate::feature::base::memsearch::bytesource::SearchRegion;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::util::program_location::ProgramLocation;

/// Trait for reading bytes from a program. This provides a level of indirection for reading the
/// bytes of a program so that the provider of the bytes can possibly do more than just reading the
/// bytes from the static program. For example, a debugger would have the opportunity to refresh the
/// bytes first.
///
/// This trait also provides methods for determining what regions of memory can be queried and
/// what address sets are associated with those regions. This would allow clients to present choices
/// about what areas of memory they are interested in AND are valid to be examined.
pub trait AddressableByteSource: Send + Sync {
	/// Retrieves the byte values for an address range.
	///
	/// # Arguments
	/// - `address`: The address of the first byte in the range
	/// - `bytes`: The byte slice to store the retrieved byte values
	/// - `length`: The number of bytes to retrieve
	///
	/// # Returns
	/// The number of bytes actually retrieved
	fn get_bytes(&self, address: &Address, bytes: &mut [u8], length: usize) -> usize;

	/// Returns a list of memory regions where each region has an associated address set of valid
	/// addresses that can be read.
	///
	/// # Returns
	/// A vector of boxed trait objects representing readable regions
	fn get_searchable_regions(&self) -> Vec<Box<dyn SearchRegion>>;

	/// Invalidates any caching of byte values. This is intended to provide a hint in debugging
	/// scenario that we are about to issue a sequence of byte value requests where we are
	/// re-acquiring previous requested byte values to look for changes.
	fn invalidate(&mut self);

	/// Convert byte source address to the canonical (static) location
	///
	/// # Arguments
	/// - `address`: Address to be converted
	///
	/// # Returns
	/// Canonical location
	fn get_canonical_location(&self, address: &Address) -> Box<dyn ProgramLocation>;

	/// Rebase a canonical location in the current byte source
	///
	/// # Arguments
	/// - `location`: Location to be rebased
	///
	/// # Returns
	/// Address for new byte source
	fn rebase_from_canonical(&self, location: &dyn ProgramLocation) -> Address;
}

/// Creates a simple ProgramLocation from a program and address.
/// This is equivalent to the Java static helper method `generateProgramLocation`.
pub fn generate_program_location(
	program: Arc<dyn Program>,
	address: &Address,
) -> Box<dyn ProgramLocation> {
	Box::new(SimpleProgramLocation {
		program,
		address: address.clone(),
		byte_address: address.clone(),
	})
}

struct SimpleProgramLocation {
	program: Arc<dyn Program>,
	address: Address,
	byte_address: Address,
}

impl ProgramLocation for SimpleProgramLocation {
	fn get_program(&self) -> Arc<dyn Program> {
		self.program.clone()
	}

	fn get_address(&self) -> Address {
		self.address.clone()
	}

	fn get_byte_address(&self) -> Address {
		self.byte_address.clone()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::framework::model::DomainObject;
	use crate::program::model::address::{
		AddressFactory, AddressSpace, AddressSpaceType, DefaultAddressFactory,
	};

	struct MockProgram {
		factory: Arc<dyn AddressFactory>,
	}

	impl DomainObject for MockProgram {}

	impl Program for MockProgram {
		fn get_name(&self) -> String {
			"test".to_string()
		}
		fn get_language_id(&self) -> String {
			"x86".to_string()
		}
		fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
			Some(self.factory.clone())
		}
	}

	struct TestByteSource {
		data: Vec<u8>,
	}

	impl AddressableByteSource for TestByteSource {
		fn get_bytes(&self, _address: &Address, bytes: &mut [u8], length: usize) -> usize {
			let to_copy = std::cmp::min(length, std::cmp::min(bytes.len(), self.data.len()));
			bytes[..to_copy].copy_from_slice(&self.data[..to_copy]);
			to_copy
		}

		fn get_searchable_regions(&self) -> Vec<Box<dyn SearchRegion>> {
			vec![]
		}

		fn invalidate(&mut self) {}

		fn get_canonical_location(&self, address: &Address) -> Box<dyn ProgramLocation> {
			generate_program_location(
				Arc::new(MockProgram {
					factory: Arc::new(DefaultAddressFactory::new(vec![])) as Arc<dyn AddressFactory>,
				}),
				address,
			)
		}

		fn rebase_from_canonical(&self, location: &dyn ProgramLocation) -> Address {
			location.get_address()
		}
	}

	#[test]
	fn get_bytes_returns_correct_length() {
		let source = TestByteSource {
			data: vec![0x01, 0x02, 0x03, 0x04, 0x05],
		};
		let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
		let address = Address::new(ram, 0x1000);

		let mut buffer = vec![0u8; 10];
		let bytes_read = source.get_bytes(&address, &mut buffer, 3);

		assert_eq!(bytes_read, 3);
		assert_eq!(&buffer[..3], &[0x01, 0x02, 0x03]);
	}

	#[test]
	fn get_bytes_respects_buffer_size() {
		let source = TestByteSource {
			data: vec![0x01, 0x02, 0x03, 0x04, 0x05],
		};
		let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
		let address = Address::new(ram, 0x1000);

		let mut buffer = vec![0u8; 2];
		let bytes_read = source.get_bytes(&address, &mut buffer, 5);

		assert_eq!(bytes_read, 2);
		assert_eq!(&buffer[..], &[0x01, 0x02]);
	}

	#[test]
	fn invalidate_can_be_called() {
		let mut source = TestByteSource {
			data: vec![0x01, 0x02],
		};
		source.invalidate();
	}

	#[test]
	fn generate_program_location_creates_valid_location() {
		let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
		let address = Address::new(ram, 0x2000);
		let program = Arc::new(MockProgram {
			factory: Arc::new(DefaultAddressFactory::new(vec![])) as Arc<dyn AddressFactory>,
		});

		let location = generate_program_location(program.clone(), &address);

		assert_eq!(location.get_address(), address);
		assert_eq!(location.get_byte_address(), address);
		assert_eq!(location.get_ref_address(), None);
	}

	#[test]
	fn trait_is_object_safe() {
		let boxed: Box<dyn AddressableByteSource> = Box::new(TestByteSource {
			data: vec![0x01, 0x02, 0x03],
		});
		let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
		let address = Address::new(ram, 0x1000);

		let mut buffer = vec![0u8; 3];
		let bytes_read = boxed.get_bytes(&address, &mut buffer, 2);

		assert_eq!(bytes_read, 2);
		assert_eq!(&buffer[..2], &[0x01, 0x02]);
	}
}
