//! Port of `ghidra.app.util.exporter.CommentLineDispenser`.
//!
//! Java's `hasMoreLines()`/`getNextLine()`/`index` all take no receiver-mutation constraints in
//! Java (plain instance methods), but this crate's [`AbstractLineDispenser`] trait declares
//! [`get_next_line`](AbstractLineDispenser::get_next_line) and
//! [`index`](AbstractLineDispenser::index) with `&self` receivers even though Java's
//! `getNextLine()` mutates the inherited `index` field (`comments[index++]`). This mirrors the
//! same `&self`-vs.-Java-mutation gap this crate has already solved elsewhere (e.g.
//! [`DefaultAddressIteratorConverter`](crate::program::util::address_iterator_converter::DefaultAddressIteratorConverter))
//! via interior mutability: `index` is held in a [`Cell`], since `usize` is `Copy` and needs no
//! more than get/set.

use std::cell::Cell;

use crate::app::util::exporter::abstract_line_dispenser::{clip, AbstractLineDispenser};
use crate::program::model::listing::Variable;
use crate::util::string_utilities::StringUtilities;

/// Dispenses the lines of a variable's comment, one at a time, clipped to a fixed width.
///
/// Port of the package-private `ghidra.app.util.exporter.CommentLineDispenser`.
pub struct CommentLineDispenser {
    comments: Vec<String>,
    width: usize,
    fill_amount: usize,
    index: Cell<usize>,
}

impl CommentLineDispenser {
    /// Constructs a dispenser over `var`'s comment, split into lines.
    ///
    /// Port of `CommentLineDispenser(Variable, int, int, String)`.
    ///
    /// `prefix` is accepted purely for constructor-signature parity with Java, then discarded --
    /// a faithfully reproduced quirk: the Java constructor never assigns its `prefix` parameter
    /// to the inherited `AbstractLineDispenser.prefix` field, which therefore stays `null` (in
    /// this port, [`AbstractLineDispenser::prefix`] returns `None`) regardless of what is passed
    /// in.
    pub fn new(var: &dyn Variable, width: usize, fill_amount: usize, prefix: &str) -> Self {
        let _ = prefix;
        let comment = var.get_comment().unwrap_or_default();
        let comments = comment.to_lines(true);
        CommentLineDispenser { comments, width, fill_amount, index: Cell::new(0) }
    }
}

impl AbstractLineDispenser for CommentLineDispenser {
    /// Port of `hasMoreLines()`.
    fn has_more_lines(&self) -> bool {
        self.index.get() < self.comments.len()
    }

    /// Port of `getNextLine()`. Java returns `null` once exhausted; since this trait's
    /// [`get_next_line`](AbstractLineDispenser::get_next_line) returns a plain (non-`Option`)
    /// `String`, an empty string stands in for that `null` -- callers are expected to check
    /// [`has_more_lines`](AbstractLineDispenser::has_more_lines) first, exactly as Java callers
    /// are expected to check `hasMoreLines()` before trusting a non-null result.
    fn get_next_line(&self) -> String {
        if self.has_more_lines() {
            let i = self.index.get();
            self.index.set(i + 1);
            clip(&self.comments[i], self.width)
        } else {
            String::new()
        }
    }

    /// Port of `dispose()`, an empty override in Java.
    fn dispose(&mut self) {}

    /// Java's inherited `isHTML` field defaults to `false` and is never assigned by this class.
    fn is_html(&self) -> bool {
        false
    }

    fn width(&self) -> usize {
        self.width
    }

    fn fill_amount(&self) -> usize {
        self.fill_amount
    }

    /// Java's inherited `prefix` field is never assigned by this class's constructor (see
    /// [`Self::new`]'s docs), so it stays `null`.
    fn prefix(&self) -> Option<&str> {
        None
    }

    fn index(&self) -> usize {
        self.index.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::Address;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::lang::RegisterRef;
    use crate::program::model::listing::variable::{
        SetVariableNameError, UnsupportedOperationError,
    };
    use crate::program::model::listing::variable_storage::VariableStorage;
    use crate::program::model::listing::{Function, Program};
    use crate::program::model::pcode::Varnode;
    use crate::program::model::symbol::{SourceType, Symbol};
    use crate::util::exception::InvalidInputException;
    use std::cmp::Ordering;
    use std::sync::Arc;

    /// A `Variable` double exposing only a configurable comment; every other method panics,
    /// since `CommentLineDispenser` only ever calls `get_comment()`.
    struct MockVariable {
        comment: Option<String>,
    }

    impl Variable for MockVariable {
        fn get_data_type(&self) -> Box<dyn DataType> {
            unimplemented!("not exercised by this test")
        }
        fn set_data_type_with_storage(
            &mut self,
            _data_type: Box<dyn DataType>,
            _storage: Box<dyn VariableStorage>,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            unimplemented!("not exercised by this test")
        }
        fn set_data_type(
            &mut self,
            _data_type: Box<dyn DataType>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            unimplemented!("not exercised by this test")
        }
        fn set_data_type_aligned(
            &mut self,
            _data_type: Box<dyn DataType>,
            _align_stack: bool,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            unimplemented!("not exercised by this test")
        }
        fn get_name(&self) -> Option<String> {
            unimplemented!("not exercised by this test")
        }
        fn get_length(&self) -> i32 {
            unimplemented!("not exercised by this test")
        }
        fn is_valid(&self) -> bool {
            unimplemented!("not exercised by this test")
        }
        fn get_function(&self) -> Option<Box<dyn Function>> {
            unimplemented!("not exercised by this test")
        }
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by this test")
        }
        fn get_source(&self) -> SourceType {
            unimplemented!("not exercised by this test")
        }
        fn set_name(&mut self, _name: &str, _source: SourceType) -> Result<(), SetVariableNameError> {
            unimplemented!("not exercised by this test")
        }
        fn get_comment(&self) -> Option<String> {
            self.comment.clone()
        }
        fn set_comment(&mut self, _comment: Option<String>) {
            unimplemented!("not exercised by this test")
        }
        fn get_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
            unimplemented!("not exercised by this test")
        }
        fn get_first_storage_varnode(&self) -> Option<Varnode> {
            unimplemented!("not exercised by this test")
        }
        fn get_last_storage_varnode(&self) -> Option<Varnode> {
            unimplemented!("not exercised by this test")
        }
        fn is_stack_variable(&self) -> bool {
            unimplemented!("not exercised by this test")
        }
        fn has_stack_storage(&self) -> bool {
            unimplemented!("not exercised by this test")
        }
        fn is_register_variable(&self) -> bool {
            unimplemented!("not exercised by this test")
        }
        fn get_register(&self) -> Option<RegisterRef> {
            unimplemented!("not exercised by this test")
        }
        fn get_registers(&self) -> Option<Vec<RegisterRef>> {
            unimplemented!("not exercised by this test")
        }
        fn get_min_address(&self) -> Option<Address> {
            unimplemented!("not exercised by this test")
        }
        fn get_stack_offset(&self) -> Result<i32, UnsupportedOperationError> {
            unimplemented!("not exercised by this test")
        }
        fn is_memory_variable(&self) -> bool {
            unimplemented!("not exercised by this test")
        }
        fn is_unique_variable(&self) -> bool {
            unimplemented!("not exercised by this test")
        }
        fn is_compound_variable(&self) -> bool {
            unimplemented!("not exercised by this test")
        }
        fn has_assigned_storage(&self) -> bool {
            unimplemented!("not exercised by this test")
        }
        fn get_first_use_offset(&self) -> i32 {
            unimplemented!("not exercised by this test")
        }
        fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
            unimplemented!("not exercised by this test")
        }
        fn is_equivalent(&self, _variable: &dyn Variable) -> bool {
            unimplemented!("not exercised by this test")
        }
        fn compare_to(&self, _other: &dyn Variable) -> Ordering {
            unimplemented!("not exercised by this test")
        }
    }

    fn dispenser(comment: Option<&str>, width: usize, fill_amount: usize) -> CommentLineDispenser {
        let var = MockVariable { comment: comment.map(str::to_string) };
        CommentLineDispenser::new(&var, width, fill_amount, "unused-prefix")
    }

    #[test]
    fn single_line_comment_dispenses_one_clipped_line() {
        let d = dispenser(Some("hello"), 10, 0);
        assert!(d.has_more_lines());
        assert_eq!(d.get_next_line(), "hello     ");
        assert!(!d.has_more_lines());
    }

    #[test]
    fn multi_line_comment_dispenses_each_line_in_order() {
        let d = dispenser(Some("line one\nline two\nline three"), 8, 0);
        assert_eq!(d.get_next_line(), "line one");
        assert_eq!(d.get_next_line(), "line two");
        // "line three" (10 chars) exceeds width 8, so `clip` truncates to 5 chars plus an
        // ellipsis: `AbstractLineDispenser::clip`'s `width >= 4` branch is
        // `format!("{}...", &s[..width - 3])`.
        assert_eq!(d.get_next_line(), "line ...");
        assert!(!d.has_more_lines());
    }

    #[test]
    fn exhausted_dispenser_returns_empty_string() {
        let d = dispenser(Some("only"), 4, 0);
        assert_eq!(d.get_next_line(), "only");
        assert!(!d.has_more_lines());
        // Stands in for Java's `null` once exhausted; see the trait impl's own doc comment.
        assert_eq!(d.get_next_line(), "");
    }

    #[test]
    fn none_comment_yields_no_lines() {
        // Mirrors `StringUtilities.toLines(null)` returning an empty array.
        let d = dispenser(None, 10, 0);
        assert!(!d.has_more_lines());
        assert_eq!(d.get_next_line(), "");
    }

    #[test]
    fn empty_comment_yields_no_lines() {
        let d = dispenser(Some(""), 10, 0);
        assert!(!d.has_more_lines());
    }

    #[test]
    fn prefix_argument_is_accepted_but_has_no_effect() {
        // Faithful quirk: Java's constructor never stores `prefix` on the inherited field.
        let var = MockVariable { comment: Some("x".to_string()) };
        let d1 = CommentLineDispenser::new(&var, 5, 0, "PREFIX_A");
        let d2 = CommentLineDispenser::new(&var, 5, 0, "PREFIX_B");
        assert_eq!(d1.prefix(), None);
        assert_eq!(d2.prefix(), None);
        assert_eq!(d1.prefix(), d2.prefix());
    }

    #[test]
    fn width_and_fill_amount_accessors_round_trip() {
        let d = dispenser(Some("x"), 12, 3);
        assert_eq!(d.width(), 12);
        assert_eq!(d.fill_amount(), 3);
    }

    #[test]
    fn is_html_is_always_false() {
        let d = dispenser(Some("x"), 5, 0);
        assert!(!d.is_html());
    }

    #[test]
    fn index_tracks_lines_consumed() {
        let d = dispenser(Some("a\nb\nc"), 1, 0);
        assert_eq!(d.index(), 0);
        d.get_next_line();
        assert_eq!(d.index(), 1);
        d.get_next_line();
        d.get_next_line();
        assert_eq!(d.index(), 3);
    }

    #[test]
    fn object_safe_as_boxed_trait() {
        let var = MockVariable { comment: Some("boxed".to_string()) };
        let mut boxed: Box<dyn AbstractLineDispenser> =
            Box::new(CommentLineDispenser::new(&var, 5, 0, ""));
        assert!(boxed.has_more_lines());
        assert_eq!(boxed.get_next_line(), "boxed");
        boxed.dispose();
    }
}
