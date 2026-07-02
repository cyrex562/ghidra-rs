use crate::util::bytesearch::{ExtendedByteSequence, Match};

/// ByteMatcher is the base trait for an object that can be used to scan bytes looking for sequences
/// that match some criteria. As a convenience, it also stores the input string and settings that
/// were used to generate this ByteMatcher.
///
/// # Type Parameters
/// - `T`: The type of object used by the client to identify the matched pattern
pub trait ByteMatcher<T> {
	/// Scans the given byte sequence and returns all matches found.
	///
	/// # Arguments
	/// - `bytes`: the byte sequence to scan for matching patterns
	///
	/// # Returns
	/// An iterator over all matches found in the byte sequence
	fn match_bytes(&self, bytes: &ExtendedByteSequence) -> Vec<Match<T>>;

	/// Returns a human-readable description of this byte matcher.
	///
	/// # Returns
	/// A string describing the matcher's purpose or pattern
	fn get_description(&self) -> String;
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::feature::base::memsearch::bytesequence::ByteArrayByteSequence;
	use crate::util::bytesearch::Match;

	struct TestMatcher {
		description: String,
	}

	impl ByteMatcher<u32> for TestMatcher {
		fn match_bytes(&self, _bytes: &ExtendedByteSequence) -> Vec<Match<u32>> {
			vec![Match::new(0xDEADBEEFu32, 0u64, 4)]
		}

		fn get_description(&self) -> String {
			self.description.clone()
		}
	}

	#[test]
	fn matcher_returns_description() {
		let matcher = TestMatcher {
			description: "Test Pattern".to_string(),
		};
		assert_eq!(matcher.get_description(), "Test Pattern");
	}

	#[test]
	fn matcher_finds_matches() {
		let matcher = TestMatcher {
			description: "Test".to_string(),
		};
		let main = Box::new(ByteArrayByteSequence::new(&[0xDE, 0xAD, 0xBE, 0xEF]));
		let extended = ExtendedByteSequence::new(main, None, None, 0);
		let matches = matcher.match_bytes(&extended);

		assert_eq!(matches.len(), 1);
		assert_eq!(matches[0].get_pattern(), &0xDEADBEEFu32);
		assert_eq!(matches[0].get_start(), 0u64);
		assert_eq!(matches[0].get_length(), 4);
	}

	#[test]
	fn multiple_matchers_can_have_different_descriptions() {
		let matcher1 = TestMatcher {
			description: "Matcher 1".to_string(),
		};
		let matcher2 = TestMatcher {
			description: "Matcher 2".to_string(),
		};

		assert_eq!(matcher1.get_description(), "Matcher 1");
		assert_eq!(matcher2.get_description(), "Matcher 2");
		assert_ne!(matcher1.get_description(), matcher2.get_description());
	}

	#[test]
	fn trait_is_object_safe() {
		let boxed: Box<dyn ByteMatcher<u32>> = Box::new(TestMatcher {
			description: "Boxed".to_string(),
		});
		assert_eq!(boxed.get_description(), "Boxed");
	}
}
