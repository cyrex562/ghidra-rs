//! Port of `ghidra.app.decompiler.parallel.DecompileConfigurer`.
//!
//! A callback interface that will be given a newly created `DecompInterface` to configure.
//!
//! # Shape
//!
//! Java is an `interface` with 1 abstract method and 8 in-repo implementors, so this becomes a
//! `trait` (rule R-interface-open-ext-point, per `scripts/shape_rules.py`).
//!
//! # Seams
//!
//! * **`DecompInterface`.** Not yet ported. Added as a minimal empty placeholder trait in
//!   [`seam_stubs`] -- see that trait's doc comment for why `configure` takes it mutably even
//!   though it declares no members yet.

use super::seam_stubs::DecompInterface;

/// A callback interface that will be given a newly created [`DecompInterface`] to configure.
///
/// Port of the Java interface `ghidra.app.decompiler.parallel.DecompileConfigurer`.
pub trait DecompileConfigurer {
    /// Configures the given decompiler.
    ///
    /// Mirrors `DecompileConfigurer.configure(DecompInterface)`. Takes the decompiler mutably:
    /// every real implementor (e.g. `SwitchAnalysisDecompileConfigurer`,
    /// `ConventionAnalysisDecompileConfigurer`) calls mutating setup methods on it
    /// (`toggleCCode`, `setOptions`, ...).
    fn configure(&self, decompiler: &mut dyn DecompInterface);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct FakeDecompInterface;
    impl DecompInterface for FakeDecompInterface {}

    /// A configurer that records how many times it was asked to configure a decompiler.
    ///
    /// `DecompInterface` has no members yet (see the module docs), so a real implementor's
    /// mutating calls (`toggleCCode`, `setOptions`, ...) cannot be observed through it directly;
    /// this proves instead that the trait is object-safe and dispatches to the right
    /// implementation with the decompiler reference reaching the callee.
    struct CountingConfigurer {
        calls: Arc<AtomicUsize>,
    }

    impl DecompileConfigurer for CountingConfigurer {
        fn configure(&self, _decompiler: &mut dyn DecompInterface) {
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn configure_dispatches_through_the_trait_object() {
        let calls = Arc::new(AtomicUsize::new(0));
        let configurer: Box<dyn DecompileConfigurer> =
            Box::new(CountingConfigurer { calls: calls.clone() });
        let mut decompiler = FakeDecompInterface;

        configurer.configure(&mut decompiler);
        configurer.configure(&mut decompiler);

        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
