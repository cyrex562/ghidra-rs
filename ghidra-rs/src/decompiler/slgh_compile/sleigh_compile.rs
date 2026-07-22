//! Models `ghidra.pcodeCPort.slgh_compile.SleighCompile`.

use crate::decompiler::seam_stubs::{Constructor, PatternExpression, SubtableSymbol, TokenSymbol, ValueSymbol};
use crate::decompiler::sleigh_base::SleighBase;
use crate::decompiler::slgh_compile::{ExprTree, FieldQuality, SectionVector, SpaceQuality};
use crate::decompiler::slghpatexpress::PatternEquationOps;
use crate::decompiler::slghsymbol::{ContextChange, ContextSymbol, MacroSymbol, OperandSymbol, SpaceSymbol, TripleSymbol, VarnodeSymbol};
use crate::program::model::lang::sleigh::template::{ConstructTpl, OpTpl};
use crate::sleigh::grammar::Location;

/// Compiles a SLEIGH language module (a `.slaspec` file) into the symbol table, pattern, and
/// p-code data this crate needs to disassemble/decompile a processor's instructions.
///
/// Mirrors the concrete class `ghidra.pcodeCPort.slgh_compile.SleighCompile`, which extends
/// `SleighBase` and is driven by the ANTLR-generated SLEIGH grammar parser (`SleighCompiler`,
/// `SleighParser`, `SleighLexer` under `ghidra.sleigh.grammar`) via callback methods like
/// [`SleighCompile::new_space`], [`SleighCompile::create_constructor`], and
/// [`SleighCompile::build_constructor`], one per grammar production. Java's `curct`/`curmacro`
/// fields (the constructor/macro currently being parsed) are implementation details of a
/// concrete implementor rather than part of this trait's surface, except where the grammar
/// callbacks pass the in-progress `Constructor` explicitly (`newOperand`, `buildConstructor`).
///
/// Several methods reference core SLEIGH compile-time types
/// ([`crate::decompiler::seam_stubs::Constructor`],
/// [`crate::decompiler::seam_stubs::SubtableSymbol`],
/// [`crate::decompiler::seam_stubs::TokenSymbol`]) that are not yet ported to concrete structs;
/// those are represented as minimal placeholder traits (see
/// [`crate::decompiler::seam_stubs`]) rather than guessed-at concrete types.
///
/// Not ported: `run_compilation`/`main`, which drive the full ANTLR lexer/parser/preprocessor
/// pipeline and the `.sla` file encoders (`XmlEncode`/`PackedEncode`/`SlaFormat`) — none of which
/// are in scope for this cycle-breaking pass — and `setOptions(SleighCompileOptions)`, superseded
/// here by [`SleighCompile::set_all_options`] (mirroring the Java overload that takes the same
/// options as individual parameters, which `setOptions` merely unpacks into).
pub trait SleighCompile: SleighBase {
    /// Records a compile error at `location` and increments the error count (Java's
    /// `reportError(Location, String)`).
    fn report_error(&mut self, location: Option<&Location>, msg: &str);

    /// Records a compile warning at `location` and increments the warning count (Java's
    /// `reportWarning`).
    fn report_warning(&mut self, location: Option<&Location>, msg: &str);

    /// Records that a NOP constructor was detected at `location`, for later reporting by
    /// `checkNops` (Java's `recordNop`).
    fn record_nop(&mut self, location: Location);

    /// The number of errors recorded so far (Java's `numErrors`).
    fn num_errors(&self) -> i32;

    /// The number of warnings recorded so far (Java's `numWarnings`).
    fn num_warnings(&self) -> i32;

    /// Whether to warn about unnecessary `ZEXT`/`SEXT` operations (Java's
    /// `setUnnecessaryPcodeWarning`).
    fn set_unnecessary_pcode_warning(&mut self, val: bool);

    /// Whether to warn about temporaries that are written but never read (Java's
    /// `setDeadTempWarning`).
    fn set_dead_temp_warning(&mut self, val: bool);

    /// Whether to warn about token/context fields that are defined but never used (Java's
    /// `setUnusedFieldWarning`).
    fn set_unused_field_warning(&mut self, val: bool);

    /// Whether the `local` keyword is required to declare a temporary variable (Java's
    /// `setEnforceLocalKeyWord`, forwarded to the (unported) `pcode` sub-compiler).
    fn set_enforce_local_key_word(&mut self, val: bool);

    /// Whether most pattern-conflict errors are downgraded and ignored (Java's
    /// `setLenientConflict`).
    fn set_lenient_conflict(&mut self, val: bool);

    /// Whether local-export operand collisions are reported individually rather than just
    /// counted (Java's `setLocalCollisionWarning`).
    fn set_local_collision_warning(&mut self, val: bool);

    /// Whether NOP constructors are reported individually rather than just counted (Java's
    /// `setAllNopWarning`).
    fn set_all_nop_warning(&mut self, val: bool);

    /// Whether case-insensitive duplicate register names are treated as an error (Java's
    /// `setInsensitiveDuplicateError`).
    fn set_insensitive_duplicate_error(&mut self, val: bool);

    /// Whether the compiled output is written in the XML debug format instead of the packed
    /// `.sla` format (Java's `setDebugOutput`).
    fn set_debug_output(&mut self, val: bool);

    /// Finalizes the bit layout of every context field defined so far, assigning each a
    /// non-overlapping bit range within its backing context register (Java's
    /// `calcContextLayout`). A no-op once the layout has already been locked.
    fn calc_context_layout(&mut self);

    /// Looks up a preprocessor `#define`d value (Java's `getPreprocValue`, restated to return an
    /// `Option` rather than a `Pair<Boolean, String>`).
    fn get_preproc_value(&self, nm: &str) -> Option<&str>;

    /// Defines (or redefines) a preprocessor value (Java's `setPreprocValue`).
    fn set_preproc_value(&mut self, nm: &str, value: &str);

    /// Removes a preprocessor definition, returning whether one existed (Java's
    /// `undefinePreprocValue`).
    fn undefine_preproc_value(&mut self, nm: &str) -> bool;

    /// Defines a new token of `sz` bits, added to the token table and the symbol table (Java's
    /// `defineToken`). `endian` follows the Java convention: `0` inherits the language's default
    /// endianness, negative is little-endian, positive is big-endian.
    fn define_token(&mut self, location: Location, name: &str, sz: i64, endian: i32) -> Box<dyn TokenSymbol>;

    /// Defines a field within `sym`'s token, adding it to the symbol table as a `ValueSymbol`
    /// (Java's `addTokenField`).
    fn add_token_field(&mut self, location: Location, sym: &dyn TokenSymbol, qual: &FieldQuality);

    /// Registers a candidate context field for later layout by [`SleighCompile::calc_context_layout`]
    /// (Java's `addContextField`). Returns `false` without registering it if the context layout has
    /// already been locked.
    fn add_context_field(&mut self, location: Location, sym: &VarnodeSymbol, qual: &FieldQuality) -> bool;

    /// Defines a new address space and its `SpaceSymbol` (Java's `newSpace`).
    fn new_space(&mut self, location: Location, qual: &SpaceQuality);

    /// Sets the language's target endianness; must be called before any space/symbol is defined,
    /// since it also creates the predefined symbols (`inst_start`, `inst_next`, ...) (Java's
    /// `setEndian`).
    fn set_endian(&mut self, end: i32);

    /// Sets the instruction alignment, in bytes (Java's `setAlignment`).
    fn set_alignment(&mut self, val: i32);

    /// Defines a contiguous run of named varnodes of `size` bytes each, starting at `off` within
    /// `spacesym`'s space (Java's `defineVarnodes`). A name of `"_"` skips that slot.
    fn define_varnodes(
        &mut self,
        spacesym: &SpaceSymbol,
        off: i64,
        size: i32,
        names: &[String],
        locations: &[Location],
    );

    /// Defines `name` as a `[bitoffset, bitoffset + numb)` bit range within `sym` (Java's
    /// `defineBitrange`). Byte-aligned ranges are folded into an ordinary varnode symbol;
    /// otherwise a dedicated bitrange symbol is created.
    fn define_bitrange(
        &mut self,
        location: Location,
        name: &str,
        sym: &VarnodeSymbol,
        bitoffset: i32,
        numb: i32,
    );

    /// Defines a list of pseudo-ops (user-defined p-code operations) (Java's `addUserOp`).
    fn add_user_op(&mut self, names: &[String], locations: &[Location]);

    /// Nulls out every entry in `symlist` after its first occurrence (compared by symbol id, the
    /// Rust stand-in for Java's `==` reference identity, since every ported `SleighSymbol` is
    /// assigned a unique id at creation), returning one duplicated id if any were found (Java's
    /// `dedupSymbolList`).
    fn dedup_symbol_list(&self, symlist: &mut [Option<i32>]) -> Option<i32> {
        let mut found = None;
        for i in 0..symlist.len() {
            let Some(id) = symlist[i] else { continue };
            for j in (i + 1)..symlist.len() {
                if symlist[j] == Some(id) {
                    found = Some(id);
                    symlist[j] = None;
                }
            }
        }
        found
    }

    /// Attaches an integer value to each symbol in `symlist`, replacing it with a `ValueMapSymbol`
    /// (Java's `attachValues`).
    fn attach_values(
        &mut self,
        symlist: &mut [Option<Box<dyn ValueSymbol>>],
        locations: &[Location],
        numlist: &[i64],
    );

    /// Attaches a display name to each symbol in `symlist`, replacing it with a `NameSymbol`
    /// (Java's `attachNames`).
    fn attach_names(
        &mut self,
        symlist: &mut [Option<Box<dyn ValueSymbol>>],
        locations: &[Location],
        names: &[String],
    );

    /// Attaches a register varnode to each symbol in `symlist`, replacing it with a
    /// `VarnodeListSymbol` (Java's `attachVarnodes`).
    fn attach_varnodes(
        &mut self,
        symlist: &mut [Option<Box<dyn ValueSymbol>>],
        locations: &[Location],
        varlist: &[Option<VarnodeSymbol>],
    );

    /// Defines a new subtable symbol (Java's `newTable`).
    fn new_table(&mut self, location: Location, nm: &str) -> Box<dyn SubtableSymbol>;

    /// Appends a new named operand to `ct` (Java's `newOperand`).
    fn new_operand(&mut self, location: Location, ct: &mut dyn Constructor, nm: &str);

    /// Constrains an already-defined family-symbol operand to equal `patexp` (Java's
    /// `constrainOperand`). Returns `None`, after reporting an error, if `sym` isn't yet defined
    /// as a family symbol (a value/context/subtable symbol).
    fn constrain_operand(
        &mut self,
        location: Location,
        sym: &OperandSymbol,
        patexp: Box<dyn PatternExpression>,
    ) -> Option<Box<dyn PatternEquationOps>>;

    /// Defines `sym`'s pattern directly from `patexp`, marking its offset as irrelevant since it
    /// has no separate constraining equation of its own (Java's `defineOperand`).
    fn define_operand(&mut self, location: Location, sym: &mut OperandSymbol, patexp: Box<dyn PatternExpression>);

    /// Defines an invisible operand wrapping `sym`, appended to the constructor currently being
    /// parsed (Java's `defineInvisibleOperand`).
    fn define_invisible_operand(&mut self, location: Location, sym: &dyn TripleSymbol) -> Box<dyn PatternEquationOps>;

    /// Defines `sym` in terms of the global symbol sharing its name (Java's `selfDefine`).
    fn self_define(&mut self, sym: &mut OperandSymbol);

    /// Builds a context-modification directive setting `sym`'s field to `pe`'s value while
    /// matching (Java's `contextMod`). Returns `false`, without adding to `vec`, if `pe`
    /// references the instruction end/next2 address (not yet known while matching).
    fn context_mod(
        &mut self,
        vec: &mut Vec<Box<dyn ContextChange>>,
        sym: &dyn ContextSymbol,
        pe: &dyn PatternExpression,
    ) -> bool;

    /// Builds a context-commit directive, which exports `cvar`'s field value once `sym` has
    /// fully matched (Java's `contextSet`).
    fn context_set(&mut self, vec: &mut Vec<Box<dyn ContextChange>>, sym: &dyn TripleSymbol, cvar: &dyn ContextSymbol);

    /// Begins defining a new macro named `name` with the given parameter names, added to the
    /// symbol table (Java's `createMacro`).
    fn create_macro(&mut self, location: Location, name: &str, params: &[String], locations: &[Location]) -> MacroSymbol;

    /// Propagates the `isCodeAddress` quality from `sym`'s formal parameters onto the actual
    /// operands passed at this macro invocation (Java's `compareMacroParams`).
    fn compare_macro_params(&mut self, sym: &MacroSymbol, param: &[Box<dyn ExprTree>]);

    /// Builds the p-code template for invoking macro `sym` with the given actual parameters
    /// (Java's `createMacroUse`). Reports an error and returns an empty vector if the parameter
    /// count doesn't match.
    fn create_macro_use(&mut self, location: Location, sym: &MacroSymbol, param: Vec<Box<dyn ExprTree>>) -> Vec<OpTpl>;

    /// Begins defining a new constructor under `sym` (or the innermost enclosing `with` block's
    /// subtable, or the root `instruction` table, if `sym` is `None`) (Java's `createConstructor`).
    fn create_constructor(&mut self, location: Location, sym: Option<&dyn SubtableSymbol>) -> Box<dyn Constructor>;

    /// Pushes a new `with` block, whose subtable/pattern/context-changes are prepended to every
    /// constructor defined within it (Java's `pushWith`).
    fn push_with(
        &mut self,
        ss: Option<Box<dyn SubtableSymbol>>,
        pateq: Option<Box<dyn PatternEquationOps>>,
        contvec: Option<Vec<Box<dyn ContextChange>>>,
    );

    /// Pops the innermost `with` block (Java's `popWith`).
    fn pop_with(&mut self);

    /// Finishes defining `big`: attaches its p-code sections, its pattern equation (prepended
    /// with any enclosing `with` blocks' patterns), and its context changes (Java's
    /// `buildConstructor`).
    fn build_constructor(
        &mut self,
        big: &mut dyn Constructor,
        pateq: Option<Box<dyn PatternEquationOps>>,
        contvec: Option<Vec<Box<dyn ContextChange>>>,
        vec: Option<SectionVector>,
    );

    /// Finishes defining macro `sym`'s body, expanding any submacro invocations within `rtl`
    /// (Java's `buildMacro`).
    fn build_macro(&mut self, sym: &mut MacroSymbol, rtl: ConstructTpl);

    /// Applies every compiler option in one call (Java's `setAllOptions`, and the parameter
    /// unpacking `setOptions(SleighCompileOptions)` performs before delegating to it).
    #[allow(clippy::too_many_arguments)]
    fn set_all_options(
        &mut self,
        preprocs: &[(String, String)],
        unnecessary_pcode_warning: bool,
        lenient_conflict: bool,
        all_collision_warning: bool,
        all_nop_warning: bool,
        dead_temp_warning: bool,
        unused_field_warning: bool,
        enforce_local_key_word: bool,
        case_sensitive_register_names: bool,
        debug_output: bool,
    ) {
        for (k, v) in preprocs {
            self.set_preproc_value(k, v);
        }
        self.set_unnecessary_pcode_warning(unnecessary_pcode_warning);
        self.set_lenient_conflict(lenient_conflict);
        self.set_local_collision_warning(all_collision_warning);
        self.set_all_nop_warning(all_nop_warning);
        self.set_dead_temp_warning(dead_temp_warning);
        self.set_unused_field_warning(unused_field_warning);
        self.set_enforce_local_key_word(enforce_local_key_word);
        self.set_insensitive_duplicate_error(!case_sensitive_register_names);
        self.set_debug_output(debug_output);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::context::SleighError;
    use crate::decompiler::sleigh_base::NamedSymbolProvider;
    use crate::decompiler::slghsymbol::SleighSymbol;
    use crate::decompiler::space::AddrSpace;
    use crate::decompiler::translate::{BasicSpaceProvider, Translate};
    use crate::program::model::address::Address;
    use crate::program::model::pcode::encoder::Encoder;
    use std::collections::HashMap;
    use std::io;

    struct MockSleighCompile {
        errors: i32,
        warnings: i32,
        preproc: HashMap<String, String>,
        unnecessary_pcode_warning: bool,
        debug_output: bool,
    }

    impl MockSleighCompile {
        fn new() -> Self {
            Self {
                errors: 0,
                warnings: 0,
                preproc: HashMap::new(),
                unnecessary_pcode_warning: false,
                debug_output: false,
            }
        }
    }

    impl NamedSymbolProvider for MockSleighCompile {
        fn find_symbol(&self, _nm: &str) -> Option<&SleighSymbol> {
            None
        }
    }

    impl BasicSpaceProvider for MockSleighCompile {
        fn get_default_space(&self) -> &dyn AddrSpace {
            unimplemented!("not exercised by these tests")
        }

        fn get_constant_space(&self) -> &dyn AddrSpace {
            unimplemented!("not exercised by these tests")
        }
    }

    impl Translate for MockSleighCompile {
        fn is_big_endian(&self) -> bool {
            true
        }

        fn alignment(&self) -> i32 {
            1
        }

        fn get_unique_base(&self) -> i64 {
            0
        }

        fn get_iop_space(&self) -> Option<&dyn AddrSpace> {
            None
        }

        fn get_fspec_space(&self) -> Option<&dyn AddrSpace> {
            None
        }

        fn get_stack_space(&self) -> Option<&dyn AddrSpace> {
            None
        }

        fn get_unique_space(&self) -> Option<&dyn AddrSpace> {
            None
        }

        fn num_spaces(&self) -> i32 {
            0
        }

        fn get_space(&self, _i: i32) -> &dyn AddrSpace {
            unimplemented!("not exercised by these tests")
        }

        fn no_high_ptr(&self) -> &dyn crate::decompiler::seam_stubs::RangeList {
            unimplemented!("not exercised by these tests")
        }

        fn instruction_length(&self, _baseaddr: &Address) -> i32 {
            0
        }

        fn print_assembly(&self, _out: &mut dyn std::io::Write, _size: i32, _baseaddr: &Address) -> std::io::Result<i32> {
            Ok(0)
        }

        fn get_default_size(&self) -> i32 {
            4
        }
    }

    impl SleighBase for MockSleighCompile {
        fn find_symbol_by_id(&self, _id: i32) -> Option<&SleighSymbol> {
            None
        }

        fn is_initialized(&self) -> bool {
            true
        }

        fn get_register(&self, nm: &str) -> Result<crate::program::model::pcode::VarnodeData, SleighError> {
            Err(SleighError::new(
                format!("Unknown register name '{}'", nm),
                Location::new("test.sla", 1),
            ))
        }

        fn get_register_name(&self, _base: &dyn AddrSpace, _off: i64, _size: i32) -> String {
            String::new()
        }

        fn user_ops(&self) -> &[String] {
            &[]
        }

        fn encode(&self, _encoder: &mut dyn Encoder) -> io::Result<()> {
            Ok(())
        }
    }

    impl SleighCompile for MockSleighCompile {
        fn report_error(&mut self, _location: Option<&Location>, _msg: &str) {
            self.errors += 1;
        }

        fn report_warning(&mut self, _location: Option<&Location>, _msg: &str) {
            self.warnings += 1;
        }

        fn record_nop(&mut self, _location: Location) {}

        fn num_errors(&self) -> i32 {
            self.errors
        }

        fn num_warnings(&self) -> i32 {
            self.warnings
        }

        fn set_unnecessary_pcode_warning(&mut self, val: bool) {
            self.unnecessary_pcode_warning = val;
        }

        fn set_dead_temp_warning(&mut self, _val: bool) {}

        fn set_unused_field_warning(&mut self, _val: bool) {}

        fn set_enforce_local_key_word(&mut self, _val: bool) {}

        fn set_lenient_conflict(&mut self, _val: bool) {}

        fn set_local_collision_warning(&mut self, _val: bool) {}

        fn set_all_nop_warning(&mut self, _val: bool) {}

        fn set_insensitive_duplicate_error(&mut self, _val: bool) {}

        fn set_debug_output(&mut self, val: bool) {
            self.debug_output = val;
        }

        fn calc_context_layout(&mut self) {}

        fn get_preproc_value(&self, nm: &str) -> Option<&str> {
            self.preproc.get(nm).map(|s| s.as_str())
        }

        fn set_preproc_value(&mut self, nm: &str, value: &str) {
            self.preproc.insert(nm.to_string(), value.to_string());
        }

        fn undefine_preproc_value(&mut self, nm: &str) -> bool {
            self.preproc.remove(nm).is_some()
        }

        fn define_token(&mut self, _location: Location, _name: &str, _sz: i64, _endian: i32) -> Box<dyn TokenSymbol> {
            unimplemented!("not exercised by these tests")
        }

        fn add_token_field(&mut self, _location: Location, _sym: &dyn TokenSymbol, _qual: &FieldQuality) {}

        fn add_context_field(&mut self, _location: Location, _sym: &VarnodeSymbol, _qual: &FieldQuality) -> bool {
            true
        }

        fn new_space(&mut self, _location: Location, _qual: &SpaceQuality) {}

        fn set_endian(&mut self, _end: i32) {}

        fn set_alignment(&mut self, _val: i32) {}

        fn define_varnodes(
            &mut self,
            _spacesym: &SpaceSymbol,
            _off: i64,
            _size: i32,
            _names: &[String],
            _locations: &[Location],
        ) {
        }

        fn define_bitrange(
            &mut self,
            _location: Location,
            _name: &str,
            _sym: &VarnodeSymbol,
            _bitoffset: i32,
            _numb: i32,
        ) {
        }

        fn add_user_op(&mut self, _names: &[String], _locations: &[Location]) {}

        fn attach_values(
            &mut self,
            _symlist: &mut [Option<Box<dyn ValueSymbol>>],
            _locations: &[Location],
            _numlist: &[i64],
        ) {
        }

        fn attach_names(
            &mut self,
            _symlist: &mut [Option<Box<dyn ValueSymbol>>],
            _locations: &[Location],
            _names: &[String],
        ) {
        }

        fn attach_varnodes(
            &mut self,
            _symlist: &mut [Option<Box<dyn ValueSymbol>>],
            _locations: &[Location],
            _varlist: &[Option<VarnodeSymbol>],
        ) {
        }

        fn new_table(&mut self, _location: Location, _nm: &str) -> Box<dyn SubtableSymbol> {
            unimplemented!("not exercised by these tests")
        }

        fn new_operand(&mut self, _location: Location, _ct: &mut dyn Constructor, _nm: &str) {}

        fn constrain_operand(
            &mut self,
            _location: Location,
            _sym: &OperandSymbol,
            _patexp: Box<dyn PatternExpression>,
        ) -> Option<Box<dyn PatternEquationOps>> {
            None
        }

        fn define_operand(&mut self, _location: Location, _sym: &mut OperandSymbol, _patexp: Box<dyn PatternExpression>) {}

        fn define_invisible_operand(
            &mut self,
            _location: Location,
            _sym: &dyn TripleSymbol,
        ) -> Box<dyn PatternEquationOps> {
            unimplemented!("not exercised by these tests")
        }

        fn self_define(&mut self, _sym: &mut OperandSymbol) {}

        fn context_mod(
            &mut self,
            _vec: &mut Vec<Box<dyn ContextChange>>,
            _sym: &dyn ContextSymbol,
            _pe: &dyn PatternExpression,
        ) -> bool {
            true
        }

        fn context_set(&mut self, _vec: &mut Vec<Box<dyn ContextChange>>, _sym: &dyn TripleSymbol, _cvar: &dyn ContextSymbol) {}

        fn create_macro(&mut self, location: Location, name: &str, _params: &[String], _locations: &[Location]) -> MacroSymbol {
            MacroSymbol::new(location, name, 0)
        }

        fn compare_macro_params(&mut self, _sym: &MacroSymbol, _param: &[Box<dyn ExprTree>]) {}

        fn create_macro_use(&mut self, _location: Location, _sym: &MacroSymbol, _param: Vec<Box<dyn ExprTree>>) -> Vec<OpTpl> {
            Vec::new()
        }

        fn create_constructor(&mut self, _location: Location, _sym: Option<&dyn SubtableSymbol>) -> Box<dyn Constructor> {
            unimplemented!("not exercised by these tests")
        }

        fn push_with(
            &mut self,
            _ss: Option<Box<dyn SubtableSymbol>>,
            _pateq: Option<Box<dyn PatternEquationOps>>,
            _contvec: Option<Vec<Box<dyn ContextChange>>>,
        ) {
        }

        fn pop_with(&mut self) {}

        fn build_constructor(
            &mut self,
            _big: &mut dyn Constructor,
            _pateq: Option<Box<dyn PatternEquationOps>>,
            _contvec: Option<Vec<Box<dyn ContextChange>>>,
            _vec: Option<SectionVector>,
        ) {
        }

        fn build_macro(&mut self, _sym: &mut MacroSymbol, _rtl: ConstructTpl) {}
    }

    #[test]
    fn trait_is_object_safe_and_usable_via_dyn() {
        let mut compile = MockSleighCompile::new();
        let dyn_compile: &mut dyn SleighCompile = &mut compile;
        dyn_compile.report_error(None, "boom");
        dyn_compile.report_warning(None, "careful");
        assert_eq!(dyn_compile.num_errors(), 1);
        assert_eq!(dyn_compile.num_warnings(), 1);
        dyn_compile.set_debug_output(true);
    }

    #[test]
    fn preproc_values_round_trip() {
        let mut compile = MockSleighCompile::new();
        assert_eq!(compile.get_preproc_value("FOO"), None);
        compile.set_preproc_value("FOO", "1");
        assert_eq!(compile.get_preproc_value("FOO"), Some("1"));
        assert!(compile.undefine_preproc_value("FOO"));
        assert_eq!(compile.get_preproc_value("FOO"), None);
        assert!(!compile.undefine_preproc_value("FOO"));
    }

    #[test]
    fn set_all_options_applies_every_setting_through_the_default_impl() {
        let mut compile = MockSleighCompile::new();
        compile.set_all_options(
            &[("A".to_string(), "1".to_string())],
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            true,
        );
        assert_eq!(compile.get_preproc_value("A"), Some("1"));
        assert!(compile.unnecessary_pcode_warning);
        assert!(compile.debug_output);
    }

    #[test]
    fn dedup_symbol_list_nulls_out_duplicates_after_first_occurrence() {
        let compile = MockSleighCompile::new();
        let mut symlist = vec![Some(1), Some(2), Some(1), None, Some(2)];
        let dup = compile.dedup_symbol_list(&mut symlist);
        assert_eq!(dup, Some(2));
        assert_eq!(symlist, vec![Some(1), Some(2), None, None, None]);
    }

    #[test]
    fn dedup_symbol_list_returns_none_when_all_unique() {
        let compile = MockSleighCompile::new();
        let mut symlist = vec![Some(1), Some(2), Some(3)];
        assert_eq!(compile.dedup_symbol_list(&mut symlist), None);
        assert_eq!(symlist, vec![Some(1), Some(2), Some(3)]);
    }
}
