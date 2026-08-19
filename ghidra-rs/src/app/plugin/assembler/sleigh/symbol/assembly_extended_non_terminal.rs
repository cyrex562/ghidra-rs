//! Mirrors `ghidra.app.plugin.assembler.sleigh.symbol.AssemblyExtendedNonTerminal`.

use std::sync::Arc;

use crate::app::seam_stubs::AssemblyNonTerminal;

/// The type of non-terminal for an "extended grammar".
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.symbol.AssemblyExtendedNonTerminal`, a concrete
/// class extending `AssemblyNonTerminal` that wraps another non-terminal together with a start
/// and end LR0-parser state. This type was chosen as a cut-point for a dependency cycle running
/// through the extended grammar, production, and symbol types (the prior placeholder it replaces
/// was referenced by
/// [`AssemblyExtendedGrammar`](crate::app::plugin::assembler::sleigh::grammars::AssemblyExtendedGrammar)).
///
/// The Java class stores `start`, `nt`, and `end`, and derives its own display name once at
/// construction time as `start + "[" + nt.name + "]" + end`; `getName()`/`toString()` then
/// special-case `end == -1` (no extension) by delegating to the wrapped non-terminal instead of
/// returning that derived name. Since this is ported as a trait rather than a concrete struct,
/// [`end`](Self::end), [`wrapped`](Self::wrapped), and [`own_name`](Self::own_name) stand in for
/// those fields, and [`get_name`](Self::get_name) reproduces the special-cased delegation as a
/// default method built from them.
///
/// [`AssemblyNonTerminal`] isn't ported yet either; this port extends its existing placeholder in
/// [`crate::app::seam_stubs`] with the `get_name`/`Display` surface this type actually calls on
/// its wrapped non-terminal (`nt.getName()`, `nt.toString()`), rather than leaving it empty.
pub trait AssemblyExtendedNonTerminal: AssemblyNonTerminal {
    /// The end state for this extended non-terminal, or `-1` if it merely wraps
    /// [`wrapped`](Self::wrapped) without extension.
    fn end(&self) -> i32;

    /// The non-terminal this extended non-terminal is derived from.
    ///
    /// Mirrors the `nt` field passed to `AssemblyExtendedNonTerminal`'s constructor.
    fn wrapped(&self) -> Arc<dyn AssemblyNonTerminal>;

    /// This extended non-terminal's own name.
    ///
    /// Mirrors the `name` field `AssemblyExtendedNonTerminal` inherits from `AssemblySymbol`,
    /// built by its constructor as `start + "[" + nt.name + "]" + end`.
    fn own_name(&self) -> String;

    /// Get the name of this extended non-terminal.
    ///
    /// Mirrors `AssemblyExtendedNonTerminal.getName()`, which overrides `AssemblySymbol.getName()`
    /// (inherited via `AssemblyNonTerminal`, which does not itself override it) to delegate to the
    /// wrapped non-terminal's name when there is no end state, otherwise returning its own name.
    fn get_name(&self) -> String {
        if self.end() == -1 {
            self.wrapped().get_name()
        }
        else {
            self.own_name()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PlainNonTerminal(&'static str);

    impl std::fmt::Display for PlainNonTerminal {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "[{}]", self.0)
        }
    }

    impl AssemblyNonTerminal for PlainNonTerminal {
        fn get_name(&self) -> String {
            self.0.to_string()
        }
    }

    /// Exercises both branches of `getName()`'s delegation, matching the real class's behavior
    /// rather than a trivially-true assertion.
    struct ExtendedNonTerminal {
        end: i32,
        wrapped: Arc<dyn AssemblyNonTerminal>,
        own_name: String,
    }

    impl std::fmt::Display for ExtendedNonTerminal {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            if self.end == -1 {
                write!(f, "{}", self.wrapped)
            }
            else {
                write!(f, "{}", self.own_name)
            }
        }
    }

    impl AssemblyNonTerminal for ExtendedNonTerminal {
        fn get_name(&self) -> String {
            AssemblyExtendedNonTerminal::get_name(self)
        }
    }

    impl AssemblyExtendedNonTerminal for ExtendedNonTerminal {
        fn end(&self) -> i32 {
            self.end
        }

        fn wrapped(&self) -> Arc<dyn AssemblyNonTerminal> {
            self.wrapped.clone()
        }

        fn own_name(&self) -> String {
            self.own_name.clone()
        }
    }

    #[test]
    fn get_name_delegates_to_wrapped_when_no_end_state() {
        let inner: Arc<dyn AssemblyNonTerminal> = Arc::new(PlainNonTerminal("insn"));
        let ext = ExtendedNonTerminal {
            end: -1,
            wrapped: inner,
            own_name: "3[insn]7".to_string(),
        };
        assert_eq!(AssemblyExtendedNonTerminal::get_name(&ext), "insn");
    }

    #[test]
    fn get_name_returns_own_name_when_extended() {
        let inner: Arc<dyn AssemblyNonTerminal> = Arc::new(PlainNonTerminal("insn"));
        let ext = ExtendedNonTerminal {
            end: 7,
            wrapped: inner,
            own_name: "3[insn]7".to_string(),
        };
        assert_eq!(AssemblyExtendedNonTerminal::get_name(&ext), "3[insn]7");
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let inner: Arc<dyn AssemblyNonTerminal> = Arc::new(PlainNonTerminal("insn"));
        let ext = ExtendedNonTerminal {
            end: -1,
            wrapped: inner,
            own_name: "3[insn]7".to_string(),
        };
        let as_dyn: &dyn AssemblyExtendedNonTerminal = &ext;
        assert_eq!(AssemblyExtendedNonTerminal::get_name(as_dyn), "insn");
        // `Display` delegates to the wrapped non-terminal's own `toString()` format, distinct
        // from its bare `getName()`.
        assert_eq!(format!("{as_dyn}"), "[insn]");
    }
}
