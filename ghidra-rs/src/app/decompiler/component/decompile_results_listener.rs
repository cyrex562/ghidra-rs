use crate::app::seam_stubs::DecompileData;

/// Port of `ghidra.app.decompiler.component.DecompileResultsListener`.
///
/// Java is an `interface` with 1 abstract method and 0 in-repo implementors, so this becomes a
/// `trait` (rule R-interface-open-ext-point).
///
/// `DecompileData` is a concrete class (not an interface) that is not yet ported; this method
/// only passes it through, so it reuses the existing pass-through placeholder at
/// [`crate::app::seam_stubs::DecompileData`] -- the same one
/// [`DecompilerCallbackHandler::decompile_data_changed`](crate::app::decompiler::component::decompiler_callback_handler::DecompilerCallbackHandler::decompile_data_changed)
/// already uses -- rather than defining a second one.
pub trait DecompileResultsListener {
    /// Mirrors `setDecompileData(DecompileData)`.
    fn set_decompile_data(&mut self, decompile_data: &DecompileData);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal recording implementation, used to verify dispatch and trait-object usability.
    #[derive(Default)]
    struct RecordingListener {
        set_count: usize,
    }

    impl DecompileResultsListener for RecordingListener {
        fn set_decompile_data(&mut self, _decompile_data: &DecompileData) {
            self.set_count += 1;
        }
    }

    #[test]
    fn set_decompile_data_is_dispatched() {
        let mut listener = RecordingListener::default();
        listener.set_decompile_data(&DecompileData);
        listener.set_decompile_data(&DecompileData);
        assert_eq!(listener.set_count, 2);
    }

    #[test]
    fn usable_as_trait_object() {
        let mut listener: Box<dyn DecompileResultsListener> =
            Box::new(RecordingListener::default());
        listener.set_decompile_data(&DecompileData);
    }
}
