//! Minimal placeholder traits for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

/// Placeholder for `ghidra.pcodeCPort.address.RangeList`, needed by
/// [`crate::decompiler::translate::Translate::high_ptr_possible`] (backs the Java `nohighptr`
/// field).
pub trait RangeList: Send + Sync {
    /// Whether `[loc, loc + size)` falls within one of the registered ranges.
    fn in_range(
        &self,
        loc: &crate::program::model::address::Address,
        size: i32,
    ) -> bool;
}

/// Placeholder for `ghidra.pcodeCPort.slghsymbol.Constructor`, needed by
/// [`crate::decompiler::slghpatexpress::OperandValue`] to resolve its operand index against the
/// constructor that defines it, and (extended below) by
/// [`crate::decompiler::slgh_compile::SleighCompile`], which builds up a `Constructor`'s operand
/// list, pattern equation, context changes, and p-code sections while parsing a `.slaspec` file.
/// `Constructor` itself has not been ported to a concrete struct yet (only the narrower
/// [`crate::decompiler::slghsymbol::ConstructorLike`] seam used by `DecisionProperties` exists so
/// far).
pub trait Constructor: Send + Sync {
    /// This constructor's source location (Java's `Constructor.location` field).
    fn location(&self) -> &crate::sleigh::grammar::Location;

    /// The operand symbol at `index` (`Constructor.getOperand`).
    fn get_operand(&self, index: i32) -> &crate::decompiler::slghsymbol::OperandSymbol;

    /// Resolves `replace`/`listpos` through the defining expression of the operand at `index`
    /// (`getOperand(index).getDefiningExpression().getSubValue(replace, listpos)`).
    /// `OperandSymbol`'s defining-expression field has not been ported yet, so this seam bundles
    /// the two-step Java traversal into a single method rather than splitting it further.
    fn get_operand_sub_value(
        &self,
        index: i32,
        replace: &[i64],
        listpos: &mut crate::decompiler::utils::MutableInt,
    ) -> i64;

    /// This constructor's parent subtable's id (`Constructor.getParent().getId()`).
    fn parent_id(&self) -> u64;

    /// This constructor's own id (`Constructor.getId()`).
    fn id(&self) -> u64;

    /// Sets this constructor's own id (`Constructor.setId`), used by
    /// `SubtableSymbol.addConstructor` to assign each constructor its index within the
    /// subtable's own constructor list.
    fn set_id(&mut self, id: u64);

    /// Collects every locally-exported value across this constructor's p-code result handle,
    /// appending onto `results` (`Constructor.collectLocalExports`), used by
    /// `SubtableSymbol.collectLocalValues`.
    fn collect_local_exports(&self, results: &mut Vec<i64>);

    /// The number of operands defined so far (`Constructor.getNumOperands`), used by
    /// `SleighCompile.newOperand`/`defineInvisibleOperand` to assign the next operand's index.
    fn num_operands(&self) -> i32;

    /// Appends a visible operand, returning its assigned index (`Constructor.addOperand`).
    fn add_operand(&mut self, sym: crate::decompiler::slghsymbol::OperandSymbol) -> i32;

    /// Appends an invisible operand, i.e. one with no corresponding token/context field of its
    /// own (`Constructor.addInvisibleOperand`), returning its assigned index.
    fn add_invisible_operand(&mut self, sym: crate::decompiler::slghsymbol::OperandSymbol) -> i32;

    /// Mutable access to the operand at `index`, needed by `SleighCompile.defineOperand`/
    /// `selfDefine` to fill in the operand's defining pattern expression or symbol after it was
    /// added (`OperandSymbol` itself doesn't carry that field yet, so this only exposes what
    /// currently exists on the port).
    fn get_operand_mut(&mut self, index: i32) -> &mut crate::decompiler::slghsymbol::OperandSymbol;

    /// Records which source file (by index into the global source-file table) this constructor
    /// was defined in (`Constructor.setSourceFileIndex`).
    fn set_source_file_index(&mut self, index: i32);

    /// Attaches the pattern equation built up while parsing this constructor's match pattern
    /// (`Constructor.addEquation`).
    fn add_equation(
        &mut self,
        pateq: Box<dyn crate::decompiler::slghpatexpress::PatternEquationOps>,
    );

    /// Strips a trailing whitespace placeholder from the constructor's print pieces
    /// (`Constructor.removeTrailingSpace`).
    fn remove_trailing_space(&mut self);

    /// Attaches this constructor's context changes, i.e. the `[...]` block evaluated when the
    /// constructor matches (`Constructor.addContext`).
    fn add_context(&mut self, contvec: Vec<Box<dyn crate::decompiler::slghsymbol::ContextChange>>);

    /// Sets the main (unnamed) p-code section's template (`Constructor.setMainSection`).
    fn set_main_section(
        &mut self,
        section: Option<crate::program::model::lang::sleigh::template::ConstructTpl>,
    );

    /// Sets a named p-code section's template at `index` (`Constructor.setNamedSection`).
    fn set_named_section(
        &mut self,
        section: crate::program::model::lang::sleigh::template::ConstructTpl,
        index: i32,
    );
}

/// Placeholder for `ghidra.pcodeCPort.slghsymbol.SubtableSymbol`, needed by
/// [`crate::decompiler::slgh_compile::SleighCompile::new_table`] and
/// [`crate::decompiler::slgh_compile::SleighCompile::create_constructor`]. `SubtableSymbol` is a
/// [`crate::decompiler::slghsymbol::TripleSymbol`] that owns a growable list of the
/// [`Constructor`]s that can produce it; only the members `SleighCompile` actually calls are
/// stubbed here.
pub trait SubtableSymbol: crate::decompiler::slghsymbol::TripleSymbol {
    /// This subtable's name (Java's inherited `SleighSymbol.getName()`).
    fn name(&self) -> &str;

    /// Appends a newly parsed constructor to this subtable, returning its index within the
    /// subtable (`SubtableSymbol.addConstructor`).
    fn add_constructor(&mut self, ct: Box<dyn Constructor>) -> i32;
}

/// Placeholder for `ghidra.pcodeCPort.slghsymbol.TokenSymbol`, needed by
/// [`crate::decompiler::slgh_compile::SleighCompile::define_token`] and
/// [`crate::decompiler::slgh_compile::SleighCompile::add_token_field`]. The real Java class is a
/// thin wrapper pairing a [`crate::decompiler::context::Token`] with a `SleighSymbol`; only the
/// token accessor `SleighCompile` needs is stubbed here.
pub trait TokenSymbol: Send + Sync {
    /// The token this symbol wraps (`TokenSymbol.getToken`).
    fn token(&self) -> &crate::decompiler::context::Token;
}
