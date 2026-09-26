use crate::feature::base::memsearch::bytesource::SearchRegion;
use crate::program::model::address::AddressSetView;
use crate::program::model::listing::Program;

/// Enum specifying selectable regions within a Program that users can select for memory searches.
/// Corresponds to `ghidra.features.base.memsearch.bytesource.ProgramSearchRegion` in Java.
#[derive(Debug, Clone, Copy)]
pub enum ProgramSearchRegion {
	/// Searches all memory blocks that represent loaded program instructions and data.
	Loaded,
	/// Searches non-loaded initialized blocks.
	Other,
}

impl ProgramSearchRegion {
	/// Returns all available search regions.
	pub fn all() -> [&'static dyn SearchRegion; 2] {
		[&Self::Loaded, &Self::Other]
	}
}

impl SearchRegion for ProgramSearchRegion {
	fn get_name(&self) -> &str {
		match self {
			Self::Loaded => "Loaded Blocks",
			Self::Other => "All Other Blocks",
		}
	}

	fn get_description(&self) -> &str {
		match self {
			Self::Loaded => "Searches all memory blocks that represent loaded program instructions and data",
			Self::Other => "Searches non-loaded initialized blocks",
		}
	}

	fn get_addresses(&self, program: &dyn Program) -> Box<dyn AddressSetView> {
		match self {
			Self::Loaded => program.get_loaded_and_initialized_address_set(),
			Self::Other => {
				let all = program.get_all_initialized_address_set();
				let loaded = program.get_loaded_and_initialized_address_set();
				Box::new(all.subtract(&*loaded))
			}
		}
	}

	fn is_default(&self) -> bool {
		matches!(self, Self::Loaded)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::framework::model::DomainObject;
	use crate::program::model::address::AddressSet;

	struct MockProgram {
		has_memory: bool,
	}

	impl DomainObject for MockProgram {}

	impl Program for MockProgram {
		fn get_name(&self) -> String {
			"test".to_string()
		}

		fn get_language_id(&self) -> String {
			"x86".to_string()
		}

		fn get_loaded_and_initialized_address_set(&self) -> Box<dyn AddressSetView> {
			if self.has_memory {
				Box::new(AddressSet::new())
			} else {
				Box::new(AddressSet::new())
			}
		}

		fn get_all_initialized_address_set(&self) -> Box<dyn AddressSetView> {
			if self.has_memory {
				Box::new(AddressSet::new())
			} else {
				Box::new(AddressSet::new())
			}
		}
	}

	#[test]
	fn loaded_is_default() {
		assert!(ProgramSearchRegion::Loaded.is_default());
		assert!(!ProgramSearchRegion::Other.is_default());
	}

	#[test]
	fn loaded_name_and_description() {
		let region = ProgramSearchRegion::Loaded;
		assert_eq!(region.get_name(), "Loaded Blocks");
		assert_eq!(
			region.get_description(),
			"Searches all memory blocks that represent loaded program instructions and data"
		);
	}

	#[test]
	fn other_name_and_description() {
		let region = ProgramSearchRegion::Other;
		assert_eq!(region.get_name(), "All Other Blocks");
		assert_eq!(region.get_description(), "Searches non-loaded initialized blocks");
	}

	#[test]
	fn all_returns_all_regions() {
		let all = ProgramSearchRegion::all();
		assert_eq!(all.len(), 2);
		assert_eq!(all[0].get_name(), "Loaded Blocks");
		assert_eq!(all[1].get_name(), "All Other Blocks");
	}

	#[test]
	fn get_addresses_with_no_memory() {
		let program = MockProgram { has_memory: false };
		let region = ProgramSearchRegion::Loaded;
		let addresses = region.get_addresses(&program);
		assert!(addresses.is_empty());
	}

	#[test]
	fn get_addresses_returns_address_set() {
		let program = MockProgram { has_memory: true };
		let region = ProgramSearchRegion::Loaded;
		let addresses = region.get_addresses(&program);
		assert!(addresses.is_empty());
	}

	#[test]
	fn trait_is_object_safe() {
		let boxed: Box<dyn SearchRegion> = Box::new(ProgramSearchRegion::Loaded);
		assert_eq!(boxed.get_name(), "Loaded Blocks");
		assert!(boxed.is_default());
	}
}
