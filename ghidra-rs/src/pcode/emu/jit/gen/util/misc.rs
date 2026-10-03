//! Miscellaneous code-generation utilities.
//!
//! Port of `ghidra.pcode.emu.jit.gen.util.Misc`.
//!
//! Java declares this as an interface purely as a namespace for static helpers; it has no
//! instance members and nothing implements it. Rust has no need for a type to hang statics off
//! of, so this is a plain module of free functions instead.
//!
//! Java's `Misc.cast1` is not ported: it exists only to reinterpret a stack shape known (by a
//! generic bound) to be [`Ent`] as literally `Emitter<Ent<N1, T1>>`, working around Java's lack of
//! subtyping between type-level list shapes. As documented on [`Ent`], Rust callers write
//! `Emitter<Ent<N, T>>` directly wherever they need it, so the cast has nothing left to do.

use crate::pcode::emu::jit::gen::util::emitter::{Dead, Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::lbl::Lbl;
use crate::pcode::emu::jit::gen::util::types::{BType, TRef};
use crate::pcode::seam_stubs::Label;

/// A handle to an (incomplete) `try`-`catch` block.
///
/// Port of `Misc.TryCatchBlock<T, N>`. Java's `T extends Throwable` type parameter only ever
/// flowed into `TRef<T>`; since [`TRef`] is not generic in this port (there is no Java reflection
/// to key it on), `T` carries no information here and is dropped.
pub struct TryCatchBlock<N: Next> {
    /// The label to place at the end of the `try` block.
    pub end: Lbl<N>,
    /// The label to place at the handler, i.e., the start of the `catch` block. The stack there
    /// is the same as at the block bounds, but with the exception type pushed.
    pub handler: Lbl<Ent<N, TRef>>,
    /// The emitter at the start of the `try` block.
    pub em: Emitter<N>,
}

/// Start a `try`-`catch` block.
///
/// This places a label to mark the start of the `try` block. The caller must provide labels for
/// the end and the handler, and must place each in turn -- ideally the handler with
/// [`Lbl::place_dead`], since it marks a position otherwise unreachable.
///
/// Port of the static `Misc.tryCatch`.
pub fn try_catch<N: Next>(
    em: Emitter<N>,
    end: Lbl<N>,
    handler: Lbl<Ent<N, TRef>>,
    ty: &TRef,
) -> TryCatchBlock<N> {
    let start = Lbl::create();
    let em = start.place_at(em);
    em.mv().visit_try_catch_block(start.label, end.label, handler.label, ty.internal_name());
    TryCatchBlock { end, handler, em }
}

/// Place a line number.
///
/// Port of the static `Misc.lineNumber`.
pub fn line_number<N>(em: Emitter<N>, number: i32) -> Emitter<N> {
    let label = Label::new();
    em.mv().visit_label(label);
    em.mv().visit_line_number(number, label);
    em
}

/// Finish emitting bytecode.
///
/// This is where [`MethodVisitor::visit_maxs`](crate::pcode::seam_stubs::MethodVisitor::visit_maxs)
/// is invoked. Frameworks that require bytecode generation can try to enforce this by requiring
/// bytecode generation methods to return `()` from an emitter of type [`Dead`], as the usual
/// convention (see the Java doc) is:
///
/// ```ignore
/// em.emit(|em| ...)
///   .emit(|em| ...)
///   .emit(finish)
/// ```
///
/// Port of the static `Misc.finish`. Java wraps `visitMaxs` in a `try`-`catch` that logs and
/// swallows any exception; the stub `MethodVisitor` this wraps cannot fail, so there is nothing
/// to catch here.
pub fn finish(em: Emitter<Dead>) {
    em.root_scope().close();
    em.mv().visit_maxs(0, 0);
    em.mv().visit_end();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::gen::util::emitter::{start, Bot, BOTTOM};
    use crate::pcode::emu::jit::gen::util::types::TInt;

    #[test]
    fn line_number_places_a_label_and_records_the_line() {
        let em = start(crate::pcode::seam_stubs::MethodVisitor::new());
        let em = line_number(em, 42);
        let recorded = em.mv().line_numbers().to_vec();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].0, 42);
        assert_eq!(Some(recorded[0].1), em.last_visited());
    }

    #[test]
    fn try_catch_places_start_and_records_the_block() {
        let em = start(crate::pcode::seam_stubs::MethodVisitor::new());
        let end: Lbl<Bot> = Lbl::create();
        let handler: Lbl<Ent<Bot, TRef>> = Lbl::create();
        let ty = TRef::of_class("java/lang/Exception");

        let block = try_catch(em, end, handler, &ty);

        let recorded = block.em.mv().try_catch_blocks().to_vec();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].1, end.label);
        assert_eq!(recorded[0].2, handler.label);
        assert_eq!(recorded[0].3, "java/lang/Exception");
        // The start label placed by tryCatch is distinct from both end and handler.
        assert_ne!(recorded[0].0, end.label);
        assert_ne!(recorded[0].0, handler.label);
    }

    #[test]
    fn finish_closes_the_root_scope_and_visits_maxs_then_end() {
        let em = start(crate::pcode::seam_stubs::MethodVisitor::new());
        em.root_scope().decl(TInt, "x");
        let dead: Emitter<Dead> = em.clone().recast();

        finish(dead);

        // Closing the root scope declares its vars, i.e., "x" gets an end label.
        let mv = em.mv();
        assert_eq!(mv.local_variables().len(), 1);
        assert_eq!(mv.maxs(), Some((0, 0)));
        assert!(mv.ended());
    }

    #[test]
    fn cast1_has_no_port() {
        // Documents the intentional omission; see the module docs. Ensures BOTTOM stays used.
        let _: Bot = BOTTOM;
    }
}
