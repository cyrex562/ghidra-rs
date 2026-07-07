use crate::sleigh::grammar::Location;

/// Utilities for formatting log messages with optional location information.
///
/// Corresponds to `ghidra.pcode.utils.MessageFormattingUtils`.

/// Formats a log message with an optional location prefix.
///
/// If a location is provided, it will be prepended to the message in the format:
/// `filename:lineno: message`. The result is trimmed of leading/trailing whitespace.
///
/// # Arguments
/// * `location` - Optional source location (filename and line number)
/// * `message` - The message to format
///
/// # Returns
/// Formatted string with location prepended if present, trimmed.
pub fn format(location: Option<&Location>, message: &str) -> String {
	let mut result = String::new();
	if let Some(loc) = location {
		result.push_str(&format!("{}: ", loc));
	}
	result.push_str(message);
	result.trim().to_string()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn format_with_location() {
		let location = Location::new("test.sleigh", 42);
		let message = "Test message";
		let result = format(Some(&location), message);
		assert_eq!(result, "test.sleigh:42: Test message");
	}

	#[test]
	fn format_without_location() {
		let message = "Test message";
		let result = format(None, message);
		assert_eq!(result, "Test message");
	}

	#[test]
	fn format_with_location_and_empty_message() {
		let location = Location::new("file.sl", 1);
		let result = format(Some(&location), "");
		assert_eq!(result, "file.sl:1:");
	}

	#[test]
	fn format_trims_whitespace() {
		let location = Location::new("foo.sleigh", 10);
		let result = format(Some(&location), "  message with spaces  ");
		assert_eq!(result, "foo.sleigh:10:   message with spaces");
	}

	#[test]
	fn format_preserves_internal_whitespace() {
		let location = Location::new("bar.sleigh", 5);
		let message = "message  with  multiple  spaces";
		let result = format(Some(&location), message);
		assert_eq!(result, "bar.sleigh:5: message  with  multiple  spaces");
	}

	#[test]
	fn format_with_multiword_filename() {
		let location = Location::new("/path/to/file.sleigh", 100);
		let message = "Error occurred";
		let result = format(Some(&location), message);
		assert_eq!(result, "/path/to/file.sleigh:100: Error occurred");
	}
}
