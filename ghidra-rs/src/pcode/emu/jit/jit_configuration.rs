//! The configuration for a JIT-accelerated emulator.
//!
//! Port of `ghidra.pcode.emu.jit.JitConfiguration`, a Java `record`.

use std::collections::HashSet;

/// The configuration for a JIT-accelerated emulator.
///
/// Port of `ghidra.pcode.emu.jit.JitConfiguration`. The record's six components are carried as
/// public fields, matching Java's generated accessors (e.g. `maxPassageInstructions()` becomes
/// reading the [`max_passage_instructions`](Self::max_passage_instructions) field directly).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JitConfiguration {
    /// The (soft) maximum number of instructions to decode per translated passage. A passage can
    /// consist of several control-flow connected basic blocks. The decoder will decode contiguous
    /// streams of instructions with fall-through (called *strides*), adding seeds where it
    /// encounters branches. It will not stop mid-stride, but checks the instruction count before
    /// proceeding to another seed. If it exceeds the max, it stops.
    pub max_passage_instructions: i32,
    /// The (soft) maximum number of p-code ops. This is similar to
    /// [`max_passage_instructions`](Self::max_passage_instructions), but limits the number of
    /// p-code ops generated. **NOTE:** the JVM limits each method to 65,535 total bytes of
    /// bytecode. If this limit is exceeded, the ASM library throws an exception. When this
    /// happens, the compiler will retry the whole process, but with this configuration parameter
    /// halved.
    pub max_passage_ops: i32,
    /// The maximum number of strides to include.
    pub max_passage_strides: i32,
    /// See [`Opt::RemoveUnusedOperations`].
    pub remove_unused_operations: bool,
    /// See [`Opt::EmitCounters`].
    pub emit_counters: bool,
    /// See [`Opt::LogStackTraces`].
    pub log_stack_traces: bool,
}

/// Fluent specifiers for the boolean options of [`JitConfiguration`].
///
/// Port of `JitConfiguration.Opt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Opt {
    /// Some p-code ops produce outputs that are never used later. One common case is flags
    /// computed from arithmetic operations. If this option is enabled, the JIT compiler will
    /// remove those p-code ops.
    RemoveUnusedOperations,
    /// Causes the translator to emit a call to
    /// [`JitPcodeThread::count`](crate::pcode::emu::jit::jit_pcode_thread::JitPcodeThread::count)
    /// at the start of each basic block.
    EmitCounters,
    /// Causes the translator to emit code to print a stack trace in its exception handlers.
    LogStackTraces,
}

impl JitConfiguration {
    /// Port of the canonical constructor `JitConfiguration(int, int, int, boolean, boolean,
    /// boolean)`.
    pub fn new(
        max_passage_instructions: i32,
        max_passage_ops: i32,
        max_passage_strides: i32,
        remove_unused_operations: bool,
        emit_counters: bool,
        log_stack_traces: bool,
    ) -> Self {
        Self {
            max_passage_instructions,
            max_passage_ops,
            max_passage_strides,
            remove_unused_operations,
            emit_counters,
            log_stack_traces,
        }
    }

    /// Construct a configuration with default maxes and the given boolean options.
    ///
    /// Port of `JitConfiguration(Set<Opt>)` and `JitConfiguration(Opt...)`, unified into one
    /// method since Rust has no varargs: pass an array, a `Vec`, or a `HashSet` of [`Opt`].
    pub fn from_opts(opts: impl IntoIterator<Item = Opt>) -> Self {
        let opts: HashSet<Opt> = opts.into_iter().collect();
        Self {
            max_passage_instructions: 1000,
            max_passage_ops: 5000,
            max_passage_strides: 10,
            remove_unused_operations: opts.contains(&Opt::RemoveUnusedOperations),
            emit_counters: opts.contains(&Opt::EmitCounters),
            log_stack_traces: opts.contains(&Opt::LogStackTraces),
        }
    }
}

/// Port of the no-arg `JitConfiguration()`, i.e. `this(1000, 5000, 10, true, true, false)`.
impl Default for JitConfiguration {
    fn default() -> Self {
        Self {
            max_passage_instructions: 1000,
            max_passage_ops: 5000,
            max_passage_strides: 10,
            remove_unused_operations: true,
            emit_counters: true,
            log_stack_traces: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_java_no_arg_ctor() {
        let config = JitConfiguration::default();
        assert_eq!(1000, config.max_passage_instructions);
        assert_eq!(5000, config.max_passage_ops);
        assert_eq!(10, config.max_passage_strides);
        assert!(config.remove_unused_operations);
        assert!(config.emit_counters);
        assert!(!config.log_stack_traces);
    }

    #[test]
    fn from_opts_sets_only_given_flags() {
        let config = JitConfiguration::from_opts([Opt::EmitCounters]);
        assert_eq!(1000, config.max_passage_instructions);
        assert_eq!(5000, config.max_passage_ops);
        assert_eq!(10, config.max_passage_strides);
        assert!(!config.remove_unused_operations);
        assert!(config.emit_counters);
        assert!(!config.log_stack_traces);
    }

    #[test]
    fn from_opts_empty_is_all_false() {
        let config = JitConfiguration::from_opts([]);
        assert!(!config.remove_unused_operations);
        assert!(!config.emit_counters);
        assert!(!config.log_stack_traces);
    }

    #[test]
    fn new_matches_java_canonical_ctor() {
        let config = JitConfiguration::new(1, 2, 3, true, false, true);
        assert_eq!(
            JitConfiguration {
                max_passage_instructions: 1,
                max_passage_ops: 2,
                max_passage_strides: 3,
                remove_unused_operations: true,
                emit_counters: false,
                log_stack_traces: true,
            },
            config
        );
    }
}
