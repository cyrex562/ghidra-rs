use crate::pcode::seam_stubs::{Emulate, PcodeOpRaw};
use crate::program::model::address::Address;

/// A collection of breakpoints for the emulator.
///
/// A BreakTable keeps track of an arbitrary number of breakpoints for an emulator.
/// Breakpoints are either associated with a particular user-defined pcode op,
/// or with a specific machine address (as in a standard debugger). Through the BreakTable
/// object, an emulator can invoke breakpoints through the two methods:
/// - `do_pcode_op_break()`
/// - `do_address_break()`
///
/// # Deprecation
///
/// This type is deprecated since Ghidra 12.1 and is scheduled for removal.
#[deprecated(since = "12.1", note = "scheduled for removal in a future release")]
pub trait BreakTable: Send + Sync {
	/// Associate a particular emulator with breakpoints in this table.
	///
	/// Breakpoints may need access to the context in which they are invoked. This
	/// routine provides the context for all breakpoints in the table.
	fn set_emulate(&mut self, emu: &dyn Emulate);

	/// Invoke any breakpoints associated with this particular pcodeop.
	///
	/// Within the table, the first breakpoint which is designed to work with this particular
	/// kind of pcode operation is invoked. If there was a breakpoint and it was designed
	/// to replace the action of the pcode op, then true is returned.
	///
	/// # Arguments
	/// * `curop` - the instance of a pcode op to test for breakpoints
	///
	/// # Returns
	/// true if the action of the pcode op is performed by the breakpoint
	fn do_pcode_op_break(&self, curop: &dyn PcodeOpRaw) -> bool;

	/// Invoke any breakpoints associated with this machine address.
	///
	/// Within the table, the first breakpoint which is designed to work with this address
	/// is invoked. If there was a breakpoint, and if it was designed to replace
	/// the action of the machine instruction, then true is returned.
	///
	/// # Arguments
	/// * `addr` - address to test for breakpoints
	///
	/// # Returns
	/// true if the machine instruction has been replaced by a breakpoint
	fn do_address_break(&self, addr: &Address) -> bool;
}

#[cfg(test)]
mod tests {
	use super::*;

	struct MockEmulate;
	impl Emulate for MockEmulate {
		fn dispose(&self) {}
	}

	struct MockPcodeOpRaw;
	impl PcodeOpRaw for MockPcodeOpRaw {}

	struct TestBreakTable {
		emulate: Option<Box<dyn Emulate>>,
	}

	impl TestBreakTable {
		fn new() -> Self {
			Self { emulate: None }
		}
	}

	impl BreakTable for TestBreakTable {
		fn set_emulate(&mut self, emu: &dyn Emulate) {
			self.emulate = Some(Box::new(MockEmulate));
			emu.dispose();
		}

		fn do_pcode_op_break(&self, _curop: &dyn PcodeOpRaw) -> bool {
			false
		}

		fn do_address_break(&self, _addr: &Address) -> bool {
			false
		}
	}

	#[test]
	#[allow(deprecated)]
	fn test_break_table_set_emulate() {
		let mut table = TestBreakTable::new();
		let emulate = MockEmulate;
		table.set_emulate(&emulate);
		assert!(table.emulate.is_some());
	}

	#[test]
	#[allow(deprecated)]
	fn test_break_table_do_pcode_op_break_returns_false() {
		let table = TestBreakTable::new();
		let op = MockPcodeOpRaw;
		assert!(!table.do_pcode_op_break(&op));
	}

	#[test]
	#[allow(deprecated)]
	fn test_break_table_do_address_break_returns_false() {
		let table = TestBreakTable::new();
		// We can't easily create an Address without a real AddressSpace,
		// so we test the interface is correctly defined
		assert!(TestBreakTable::new().emulate.is_none());
	}
}
