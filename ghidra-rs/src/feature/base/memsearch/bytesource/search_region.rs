use crate::program::model::address::AddressSetView;
use crate::program::model::listing::Program;

/// Trait to specify a named region within a byte source (Program) that users can select to
/// specify `AddressSetView`s that can be searched.
pub trait SearchRegion: Send + Sync {
	/// Returns the name of the region.
	fn get_name(&self) -> &str;

	/// Returns a description of the region.
	fn get_description(&self) -> &str;

	/// Returns the set of addresses from a specific program that is associated with this region.
	///
	/// # Arguments
	/// - `program`: the program that determines the specific addresses for a named region
	///
	/// # Returns
	/// A boxed trait object representing the set of addresses for this region as applied to
	/// the given program
	fn get_addresses(&self, program: &dyn Program) -> Box<dyn AddressSetView>;

	/// Returns true if this region should be included in the default selection of which regions
	/// to search.
	fn is_default(&self) -> bool;
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::program::model::address::{AddressSet, Address};

	struct TestSearchRegion {
		name: String,
		description: String,
		default: bool,
	}

	impl SearchRegion for TestSearchRegion {
		fn get_name(&self) -> &str {
			&self.name
		}

		fn get_description(&self) -> &str {
			&self.description
		}

		fn get_addresses(&self, _program: &dyn Program) -> Box<dyn AddressSetView> {
			Box::new(AddressSet::new())
		}

		fn is_default(&self) -> bool {
			self.default
		}
	}

	#[test]
	fn region_returns_name() {
		let region = TestSearchRegion {
			name: "Test Region".to_string(),
			description: "Test Description".to_string(),
			default: false,
		};
		assert_eq!(region.get_name(), "Test Region");
	}

	#[test]
	fn region_returns_description() {
		let region = TestSearchRegion {
			name: "Test Region".to_string(),
			description: "A region for testing".to_string(),
			default: false,
		};
		assert_eq!(region.get_description(), "A region for testing");
	}

	#[test]
	fn region_returns_is_default() {
		let default_region = TestSearchRegion {
			name: "Default".to_string(),
			description: "A default region".to_string(),
			default: true,
		};
		assert!(default_region.is_default());

		let non_default_region = TestSearchRegion {
			name: "Non-Default".to_string(),
			description: "A non-default region".to_string(),
			default: false,
		};
		assert!(!non_default_region.is_default());
	}

	#[test]
	fn region_returns_empty_addresses() {
		struct TestProgram;
		impl Program for TestProgram {
			fn get_name(&self) -> &str {
				"test"
			}
			fn get_language_id(&self) -> &str {
				"x86"
			}
		}

		let region = TestSearchRegion {
			name: "Empty Region".to_string(),
			description: "Empty addresses".to_string(),
			default: false,
		};
		let program = TestProgram;
		let addresses = region.get_addresses(&program);
		assert!(addresses.is_empty());
	}

	#[test]
	fn trait_is_object_safe() {
		let boxed: Box<dyn SearchRegion> = Box::new(TestSearchRegion {
			name: "Boxed".to_string(),
			description: "Can be boxed".to_string(),
			default: true,
		});
		assert_eq!(boxed.get_name(), "Boxed");
		assert_eq!(boxed.get_description(), "Can be boxed");
		assert!(boxed.is_default());
	}
}
