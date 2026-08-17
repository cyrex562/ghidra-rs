pub mod disassembler_conflict_handler;
pub mod disassembler_message_listener;

pub use disassembler_conflict_handler::DisassemblerConflictHandler;
pub use disassembler_message_listener::{
    Console, DisassemblerMessageListener, Ignore, CONSOLE, IGNORE,
};

// The three program options the disassembler honours. Each is registered under the
// [`DISASSEMBLER_PROPERTIES`](crate::program::model::listing::DISASSEMBLER_PROPERTIES) options
// list; they stand in for the `Disassembler` constants of the same names, and should move onto
// that type once it is ported.

/// Place an ERROR bookmark at locations where disassembly could not be performed.
///
/// Stands in for `Disassembler.MARK_BAD_INSTRUCTION_PROPERTY`.
pub const MARK_BAD_INSTRUCTION_PROPERTY: &str = "Mark Bad Disassembly";

/// Place a WARNING bookmark at locations where a disassembled instruction has unimplemented pcode.
///
/// Stands in for `Disassembler.MARK_UNIMPL_PCODE_PROPERTY`.
pub const MARK_UNIMPL_PCODE_PROPERTY: &str = "Mark Unimplemented Pcode";

/// Restrict disassembly to executable memory blocks.
///
/// Stands in for `Disassembler.RESTRICT_DISASSEMBLY_TO_EXECUTE_MEMORY_PROPERTY`.
pub const RESTRICT_DISASSEMBLY_TO_EXECUTE_MEMORY_PROPERTY: &str =
    "Restrict Disassembly to Executable Memory";
