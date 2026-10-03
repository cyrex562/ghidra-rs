//! Port of `ghidra.plugin.importer.LcsSelectionListener`.

use crate::plugin::importer::LcsSelectionEvent;

/// A listener notified when a language/compiler-spec selection is made in the importer UI.
///
/// Port of `ghidra.plugin.importer.LcsSelectionListener`, a single-method (functional) interface.
/// Ported as a trait per this crate's convention for Java listener interfaces; implementors
/// provide [`value_changed`](Self::value_changed).
pub trait LcsSelectionListener {
    /// Called when the language/compiler-spec selection changes.
    ///
    /// Port of `LcsSelectionListener.valueChanged(LcsSelectionEvent)`.
    fn value_changed(&mut self, e: &LcsSelectionEvent);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::importer::lcs_selection_event::Type;
    use crate::program::model::lang::language_compiler_spec_pair::LanguageCompilerSpecPair;

    fn pair() -> LanguageCompilerSpecPair {
        LanguageCompilerSpecPair::new("x86:LE:32:default", "gcc")
    }

    /// A minimal implementer recording every event it receives, proving the trait is usable and
    /// exercising real (non-trivial) behavior rather than a trivially-true assertion.
    #[derive(Default)]
    struct RecordingListener {
        received: Vec<LcsSelectionEvent>,
    }

    impl LcsSelectionListener for RecordingListener {
        fn value_changed(&mut self, e: &LcsSelectionEvent) {
            self.received.push(e.clone());
        }
    }

    #[test]
    fn value_changed_receives_the_event() {
        let mut listener = RecordingListener::default();
        let event = LcsSelectionEvent::new(pair(), Type::Selected);
        listener.value_changed(&event);
        assert_eq!(listener.received.len(), 1);
        assert_eq!(listener.received[0], event);
    }

    #[test]
    fn value_changed_can_be_called_multiple_times() {
        let mut listener = RecordingListener::default();
        listener.value_changed(&LcsSelectionEvent::new(pair(), Type::Selected));
        listener.value_changed(&LcsSelectionEvent::new(pair(), Type::Picked));
        assert_eq!(listener.received.len(), 2);
        assert_eq!(listener.received[1].get_type(), Type::Picked);
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let mut listener = RecordingListener::default();
        let as_dyn: &mut dyn LcsSelectionListener = &mut listener;
        as_dyn.value_changed(&LcsSelectionEvent::new(pair(), Type::Selected));
    }
}
