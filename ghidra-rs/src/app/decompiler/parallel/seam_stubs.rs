//! Minimal placeholder traits for core types that
//! [`DecompileConfigurer`](super::DecompileConfigurer) references before the real Rust port of
//! that type exists yet. See `STUBS.tsv` for provenance.

/// Placeholder for `ghidra.app.decompiler.DecompInterface`, referenced by
/// [`DecompileConfigurer`](super::DecompileConfigurer) before the real class is ported.
///
/// Java's `DecompInterface` is a concrete class (not an interface), so this would ordinarily be a
/// struct rather than a trait; it is a trait here only because [`DecompileConfigurer`] needs an
/// object-safe stand-in it can pass around as `&mut dyn DecompInterface` before the concrete type
/// exists. `DecompileConfigurer` itself only ever passes this type through as a parameter to
/// `configure` (its real implementors -- e.g. `SwitchAnalysisDecompileConfigurer`,
/// `ConventionAnalysisDecompileConfigurer`, both still TODO -- are the ones that call mutating
/// methods like `toggleCCode`/`setOptions` on it), so no members are needed yet.
pub trait DecompInterface {}

/// Placeholder for `generic.DominantPair<K, V>` (a `generic.stl.Pair` whose equality and hash
/// consider only `first`), referenced by [`DecompilerReducer`](super::DecompilerReducer) before
/// the real class is ported. `DecompilerReducer` only receives these as input, so only the two
/// public fields Java's `Pair` exposes (and its constructor) are provided.
#[derive(Debug, Clone)]
pub struct DominantPair<K, V> {
    /// The dominant (identity-bearing) element.
    pub first: K,
    /// The associated value.
    pub second: V,
}

impl<K, V> DominantPair<K, V> {
    /// Mirrors `new DominantPair<>(key, value)`.
    pub fn new(first: K, second: V) -> Self {
        Self { first, second }
    }
}
