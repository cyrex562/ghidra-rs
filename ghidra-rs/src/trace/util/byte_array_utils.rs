use crate::program::model::address::{Address, AddressSet};

/// Compute the address set where two byte arrays differ, given a start address.
///
/// # Arguments
///
/// * `start` - the address of the first byte in each array
/// * `a` - the first array
/// * `b` - the second array
///
/// # Returns
///
/// The address set where the arrays differ
///
/// # Panics
///
/// Panics if the arrays are not the same length.
pub fn compute_diffs_address_set(start: &Address, a: &[u8], b: &[u8]) -> AddressSet {
	if a.len() != b.len() {
		panic!("Arrays must be the same length");
	}

	let mut result = AddressSet::new();

	let mut diff_start: Option<Address> = None;
	for i in 0..a.len() {
		if a[i] == b[i] {
			if let Some(start_addr) = diff_start.take() {
				let end_addr = start.add_wrap(i as i64 - 1);
				result.add_range(&start_addr, &end_addr);
			}
		} else if diff_start.is_none() {
			diff_start = Some(start.add_wrap(i as i64));
		}
	}

	if let Some(start_addr) = diff_start {
		let end = start.add_wrap(a.len() as i64 - 1);
		result.add_range(&start_addr, &end);
	}

	result
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::program::model::address::address_set::AddressSetView;
	use crate::program::model::address::{AddressSpace, AddressSpaceType};
	use std::sync::Arc;

	fn create_test_address_space() -> Arc<AddressSpace> {
		AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0)
	}

	fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
		space.address(offset)
	}

	#[test]
	fn test_identical_arrays() {
		let space = create_test_address_space();
		let start = addr(&space, 0x1000);
		let a = [1u8, 2, 3, 4, 5];
		let b = [1u8, 2, 3, 4, 5];

		let result = compute_diffs_address_set(&start, &a, &b);

		assert!(result.is_empty());
	}

	#[test]
	fn test_all_different() {
		let space = create_test_address_space();
		let start = addr(&space, 0x1000);
		let a = [1u8, 2, 3, 4, 5];
		let b = [6u8, 7, 8, 9, 10];

		let result = compute_diffs_address_set(&start, &a, &b);

		assert!(!result.is_empty());
		assert!(result.contains(&addr(&space, 0x1000)));
		assert!(result.contains(&addr(&space, 0x1004)));
	}

	#[test]
	fn test_difference_at_start() {
		let space = create_test_address_space();
		let start = addr(&space, 0x1000);
		let a = [1u8, 2, 3, 4, 5];
		let b = [9u8, 2, 3, 4, 5];

		let result = compute_diffs_address_set(&start, &a, &b);

		assert!(result.contains(&addr(&space, 0x1000)));
		assert!(!result.contains(&addr(&space, 0x1001)));
	}

	#[test]
	fn test_difference_at_end() {
		let space = create_test_address_space();
		let start = addr(&space, 0x1000);
		let a = [1u8, 2, 3, 4, 5];
		let b = [1u8, 2, 3, 4, 9];

		let result = compute_diffs_address_set(&start, &a, &b);

		assert!(!result.contains(&addr(&space, 0x1000)));
		assert!(result.contains(&addr(&space, 0x1004)));
	}

	#[test]
	fn test_multiple_differences() {
		let space = create_test_address_space();
		let start = addr(&space, 0x1000);
		let a = [1u8, 2, 3, 4, 5, 6, 7, 8];
		let b = [9u8, 2, 3, 4, 5, 6, 7, 9];

		let result = compute_diffs_address_set(&start, &a, &b);

		assert!(result.contains(&addr(&space, 0x1000)));
		assert!(result.contains(&addr(&space, 0x1007)));
		assert!(!result.contains(&addr(&space, 0x1001)));
	}

	#[test]
	fn test_gap_in_differences() {
		let space = create_test_address_space();
		let start = addr(&space, 0x1000);
		let a = [1u8, 2, 3, 4, 5, 6, 7, 8];
		let b = [9u8, 2, 3, 10, 5, 6, 7, 11];

		let result = compute_diffs_address_set(&start, &a, &b);

		assert!(result.contains(&addr(&space, 0x1000)));
		assert!(result.contains(&addr(&space, 0x1003)));
		assert!(result.contains(&addr(&space, 0x1007)));
		assert!(!result.contains(&addr(&space, 0x1001)));
		assert!(!result.contains(&addr(&space, 0x1004)));
	}

	#[test]
	#[should_panic(expected = "Arrays must be the same length")]
	fn test_different_lengths() {
		let space = create_test_address_space();
		let start = addr(&space, 0x1000);
		let a = [1u8, 2, 3];
		let b = [1u8, 2, 3, 4];

		compute_diffs_address_set(&start, &a, &b);
	}

	#[test]
	fn test_empty_arrays() {
		let space = create_test_address_space();
		let start = addr(&space, 0x1000);
		let a: [u8; 0] = [];
		let b: [u8; 0] = [];

		let result = compute_diffs_address_set(&start, &a, &b);

		assert!(result.is_empty());
	}
}
