//! Utility for defining and placing labels.
//!
//! Port of `ghidra.pcode.emu.jit.gen.util.Lbl`.
//!
//! Labels are used as control-flow targets, to specify the scope of local variables, and to
//! specify the bounds of `try`-`catch` blocks. The Java type parameter `N` statically encodes the
//! stack contents expected where the label is placed; see [`Emitter`] for the full scheme.

use std::fmt;
use std::marker::PhantomData;

use crate::pcode::emu::jit::gen::util::emitter::{Dead, Emitter, Next};
use crate::pcode::seam_stubs::Label;

/// A label targeting a position in generated JVM bytecode, together with the stack contents
/// expected there.
///
/// Port of `ghidra.pcode.emu.jit.gen.util.Lbl`. `N` is a phantom marker -- erased in Java too,
/// since generics there are type-erased -- encoding the expected stack shape; it carries no
/// runtime data, so equality and hashing consider only the wrapped [`Label`].
pub struct Lbl<N> {
    /// The wrapped ASM label.
    pub label: Label,
    _marker: PhantomData<N>,
}

impl<N> fmt::Debug for Lbl<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lbl").field("label", &self.label).finish()
    }
}

impl<N> Clone for Lbl<N> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<N> Copy for Lbl<N> {}

impl<N> PartialEq for Lbl<N> {
    fn eq(&self, other: &Self) -> bool {
        self.label == other.label
    }
}

impl<N> Eq for Lbl<N> {}

/// A tuple providing both a (new) label and a resulting emitter.
///
/// Port of `Lbl.LblEm`. `LN` is the label's stack contents; `N` is the emitter's, which is the
/// same as the label's unless the emitter is [`Dead`].
pub struct LblEm<LN, N> {
    /// The label.
    pub lbl: Lbl<LN>,
    /// The emitter.
    pub em: Emitter<N>,
}

impl<N: Next> Lbl<N> {
    /// Create a fresh label with any expected stack contents.
    ///
    /// Using this to forward-declare labels requires the caller to explicate the expected stack.
    /// Consider using [`Lbl::place`] instead, which facilitates inference of the stack contents.
    ///
    /// Port of the static `Lbl.create()`.
    pub fn create() -> Self {
        Self { label: Label::new(), _marker: PhantomData }
    }

    /// Generate and place a label where execution could already reach.
    ///
    /// The returned label's stack matches `em`'s stack, since the code could be reached by
    /// multiple paths, likely fall-through and a jump to the returned label.
    ///
    /// Port of the static `Lbl.place(Emitter)`.
    pub fn place(mut em: Emitter<N>) -> LblEm<N, N> {
        let lbl = Self::create();
        em.visit_label(&lbl.label);
        LblEm { lbl, em }
    }

    /// Place this label at a position where execution could already reach.
    ///
    /// `em`'s stack and this label's stack must agree, since the code is reachable by multiple
    /// paths, likely fall-through and a jump to this label.
    ///
    /// Port of the static `Lbl.place(Emitter, Lbl)`.
    pub fn place_at(&self, mut em: Emitter<N>) -> Emitter<N> {
        em.visit_label(&self.label);
        em
    }

    /// Place this label at a position where execution could not otherwise reach.
    ///
    /// `em` must be dead, i.e., if it were to emit code, that code would be unreachable. Placing
    /// this (already-referenced) label makes the code following it reachable again, with the
    /// stack that results from the referencing code. If this label has not yet been referenced,
    /// it must have been forward-declared with the expected stack via [`Lbl::create`]. There is
    /// no dead equivalent of [`Lbl::place`], since there is no way to know the resulting stack.
    ///
    /// Port of the static `Lbl.placeDead(Emitter, Lbl)`.
    pub fn place_dead(&self, mut em: Emitter<Dead>) -> Emitter<N> {
        em.visit_label(&self.label);
        em.recast()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StackShape;
    impl Next for StackShape {}

    #[test]
    fn create_yields_distinct_labels() {
        // Each `new Label()` in Java is a fresh, reference-distinct object.
        let a = Lbl::<StackShape>::create();
        let b = Lbl::<StackShape>::create();
        assert_ne!(a, b);
        assert_eq!(a, a);
    }

    #[test]
    fn place_records_the_generated_label_on_the_emitter() {
        let em = Emitter::<StackShape>::default();
        // Constructing an emitter opens its root scope, which places a label of its own.
        let opened = em.last_visited();

        let LblEm { lbl, em } = Lbl::place(em);
        assert_ne!(opened, Some(lbl.label));
        assert_eq!(em.last_visited(), Some(lbl.label));
    }

    #[test]
    fn place_at_records_the_given_label_on_the_emitter() {
        let lbl = Lbl::<StackShape>::create();
        let em = Emitter::<StackShape>::default();

        let em = lbl.place_at(em);
        assert_eq!(em.last_visited(), Some(lbl.label));
    }

    #[test]
    fn place_dead_resurrects_the_emitter_with_the_label_recorded() {
        let lbl = Lbl::<StackShape>::create();
        let dead_em = Emitter::<Dead>::default();

        let em = lbl.place_dead(dead_em);
        assert_eq!(em.last_visited(), Some(lbl.label));
    }
}
