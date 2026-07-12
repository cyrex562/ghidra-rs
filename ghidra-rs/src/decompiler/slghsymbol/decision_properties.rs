//! Models `ghidra.pcodeCPort.slghsymbol.DecisionProperties`.

use crate::decompiler::slghpattern::DisjointPattern;
use crate::pcode::utils::message_formatting_utils;
use crate::sleigh::grammar::Location;

/// A constructor-like trait defining the interface for objects that DecisionProperties can work with.
pub trait ConstructorLike: Send + Sync {
	/// Returns the location where this constructor was defined.
	fn location(&self) -> Option<&Location>;

	/// Returns whether this constructor is in an error state.
	fn is_error(&self) -> bool;

	/// Sets the error state of this constructor.
	fn set_error(&mut self, val: bool);

	/// Returns a display representation of this constructor for error messages.
	fn display(&self) -> String;
}

/// Tracks and formats errors detected during pattern matching and conflict resolution.
///
/// Models `ghidra.pcodeCPort.slghsymbol.DecisionProperties`, which collects errors related to
/// identical and conflicting constructor patterns. This information is used during SLEIGH
/// compilation to report issues with pattern ambiguities.
pub struct DecisionProperties {
	ident_errors: Vec<String>,
	conflict_errors: Vec<String>,
}

impl DecisionProperties {
	/// Creates a new DecisionProperties with empty error lists.
	pub fn new() -> Self {
		Self {
			ident_errors: Vec::new(),
			conflict_errors: Vec::new(),
		}
	}

	/// Returns the list of errors for identical patterns.
	pub fn ident_errors(&self) -> &[String] {
		&self.ident_errors
	}

	/// Returns the list of errors for conflicting patterns.
	pub fn conflict_errors(&self) -> &[String] {
		&self.conflict_errors
	}

	/// Records that two constructors have identical patterns.
	///
	/// If neither constructor is already in an error state, marks both as errors
	/// and records formatted error messages.
	pub fn identical_pattern(
		&mut self,
		a: &mut dyn ConstructorLike,
		b: &mut dyn ConstructorLike,
	) {
		if !a.is_error() && !b.is_error() {
			a.set_error(true);
			b.set_error(true);

			let msg = format!(
				"Constructors with identical patterns:\n   {}\n   {}",
				a.display(),
				b.display()
			);

			self.ident_errors
				.push(message_formatting_utils::format(a.location(), &msg));
			self.ident_errors
				.push(message_formatting_utils::format(b.location(), &msg));
		}
	}

	/// Records that two constructors have conflicting patterns.
	///
	/// If neither constructor is already in an error state, marks both as errors
	/// and records formatted error messages describing the pattern conflict.
	pub fn conflicting_pattern(
		&mut self,
		_pa: &dyn DisjointPattern,
		a: &mut dyn ConstructorLike,
		_pb: &dyn DisjointPattern,
		b: &mut dyn ConstructorLike,
	) {
		if !a.is_error() && !b.is_error() {
			a.set_error(true);
			b.set_error(true);

			let msg = format!(
				"Constructor patterns cannot be distinguished: \n   <pattern> {}\n   <pattern> {}",
				a.display(),
				b.display()
			);

			self.conflict_errors
				.push(message_formatting_utils::format(a.location(), &msg));
			self.conflict_errors
				.push(message_formatting_utils::format(b.location(), &msg));
		}
	}
}

impl Default for DecisionProperties {
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	struct MockConstructor {
		location: Option<Location>,
		in_error: bool,
		name: String,
	}

	impl MockConstructor {
		fn new(name: impl Into<String>, location: Option<Location>) -> Self {
			Self {
				location,
				in_error: false,
				name: name.into(),
			}
		}
	}

	impl ConstructorLike for MockConstructor {
		fn location(&self) -> Option<&Location> {
			self.location.as_ref()
		}

		fn is_error(&self) -> bool {
			self.in_error
		}

		fn set_error(&mut self, val: bool) {
			self.in_error = val;
		}

		fn display(&self) -> String {
			self.name.clone()
		}
	}

	struct MockPattern;

	impl DisjointPattern for MockPattern {}

	#[test]
	fn new_initializes_empty_lists() {
		let props = DecisionProperties::new();
		assert_eq!(props.ident_errors().len(), 0);
		assert_eq!(props.conflict_errors().len(), 0);
	}

	#[test]
	fn identical_pattern_marks_both_as_error() {
		let mut props = DecisionProperties::new();
		let mut ctor_a = MockConstructor::new("ctor_a", None);
		let mut ctor_b = MockConstructor::new("ctor_b", None);

		assert!(!ctor_a.is_error());
		assert!(!ctor_b.is_error());

		props.identical_pattern(&mut ctor_a, &mut ctor_b);

		assert!(ctor_a.is_error());
		assert!(ctor_b.is_error());
	}

	#[test]
	fn identical_pattern_collects_errors() {
		let mut props = DecisionProperties::new();
		let mut ctor_a = MockConstructor::new("ctor_a", None);
		let mut ctor_b = MockConstructor::new("ctor_b", None);

		props.identical_pattern(&mut ctor_a, &mut ctor_b);

		assert_eq!(props.ident_errors().len(), 2);
		assert!(props
			.ident_errors()[0]
			.contains("Constructors with identical patterns"));
		assert!(props.ident_errors()[0].contains("ctor_a"));
		assert!(props
			.ident_errors()[1]
			.contains("Constructors with identical patterns"));
		assert!(props.ident_errors()[1].contains("ctor_b"));
	}

	#[test]
	fn identical_pattern_with_location() {
		let mut props = DecisionProperties::new();
		let loc_a = Location::new("test.sla", 10);
		let loc_b = Location::new("test.sla", 20);
		let mut ctor_a = MockConstructor::new("ctor_a", Some(loc_a));
		let mut ctor_b = MockConstructor::new("ctor_b", Some(loc_b));

		props.identical_pattern(&mut ctor_a, &mut ctor_b);

		assert!(props.ident_errors()[0].contains("test.sla:10:"));
		assert!(props.ident_errors()[1].contains("test.sla:20:"));
	}

	#[test]
	fn identical_pattern_skips_already_errored_constructors() {
		let mut props = DecisionProperties::new();
		let mut ctor_a = MockConstructor::new("ctor_a", None);
		let mut ctor_b = MockConstructor::new("ctor_b", None);
		ctor_a.set_error(true);

		props.identical_pattern(&mut ctor_a, &mut ctor_b);

		assert_eq!(props.ident_errors().len(), 0);
		assert!(!ctor_b.is_error());
	}

	#[test]
	fn conflicting_pattern_marks_both_as_error() {
		let mut props = DecisionProperties::new();
		let pattern_a = MockPattern;
		let mut ctor_a = MockConstructor::new("ctor_a", None);
		let pattern_b = MockPattern;
		let mut ctor_b = MockConstructor::new("ctor_b", None);

		assert!(!ctor_a.is_error());
		assert!(!ctor_b.is_error());

		props.conflicting_pattern(&pattern_a, &mut ctor_a, &pattern_b, &mut ctor_b);

		assert!(ctor_a.is_error());
		assert!(ctor_b.is_error());
	}

	#[test]
	fn conflicting_pattern_collects_errors() {
		let mut props = DecisionProperties::new();
		let pattern_a = MockPattern;
		let mut ctor_a = MockConstructor::new("ctor_a", None);
		let pattern_b = MockPattern;
		let mut ctor_b = MockConstructor::new("ctor_b", None);

		props.conflicting_pattern(&pattern_a, &mut ctor_a, &pattern_b, &mut ctor_b);

		assert_eq!(props.conflict_errors().len(), 2);
		assert!(props
			.conflict_errors()[0]
			.contains("Constructor patterns cannot be distinguished"));
	}

	#[test]
	fn conflicting_pattern_skips_already_errored_constructors() {
		let mut props = DecisionProperties::new();
		let pattern_a = MockPattern;
		let mut ctor_a = MockConstructor::new("ctor_a", None);
		let pattern_b = MockPattern;
		let mut ctor_b = MockConstructor::new("ctor_b", None);
		ctor_b.set_error(true);

		props.conflicting_pattern(&pattern_a, &mut ctor_a, &pattern_b, &mut ctor_b);

		assert_eq!(props.conflict_errors().len(), 0);
		assert!(!ctor_a.is_error());
	}

	#[test]
	fn default_creates_empty_properties() {
		let props = DecisionProperties::default();
		assert_eq!(props.ident_errors().len(), 0);
		assert_eq!(props.conflict_errors().len(), 0);
	}

	#[test]
	fn multiple_error_pairs() {
		let mut props = DecisionProperties::new();
		let mut ctor_1 = MockConstructor::new("ctor_1", None);
		let mut ctor_2 = MockConstructor::new("ctor_2", None);
		let mut ctor_3 = MockConstructor::new("ctor_3", None);
		let mut ctor_4 = MockConstructor::new("ctor_4", None);

		props.identical_pattern(&mut ctor_1, &mut ctor_2);
		props.identical_pattern(&mut ctor_3, &mut ctor_4);

		assert_eq!(props.ident_errors().len(), 4);
		assert!(ctor_1.is_error());
		assert!(ctor_2.is_error());
		assert!(ctor_3.is_error());
		assert!(ctor_4.is_error());
	}

	#[test]
	fn mixed_errors_identical_and_conflicting() {
		let mut props = DecisionProperties::new();
		let mut ctor_a = MockConstructor::new("ctor_a", None);
		let mut ctor_b = MockConstructor::new("ctor_b", None);
		let mut ctor_c = MockConstructor::new("ctor_c", None);
		let mut ctor_d = MockConstructor::new("ctor_d", None);
		let pattern_a = MockPattern;
		let pattern_b = MockPattern;

		props.identical_pattern(&mut ctor_a, &mut ctor_b);
		props.conflicting_pattern(&pattern_a, &mut ctor_c, &pattern_b, &mut ctor_d);

		assert_eq!(props.ident_errors().len(), 2);
		assert_eq!(props.conflict_errors().len(), 2);
	}
}
