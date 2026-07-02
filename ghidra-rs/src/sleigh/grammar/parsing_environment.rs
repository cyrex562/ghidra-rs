use std::cell::RefCell;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::rc::Rc;

use super::{BailoutException, LineArrayListWriter, Locator};

struct Inner {
    writer: Rc<RefCell<LineArrayListWriter>>,
    locator: Rc<RefCell<Locator>>,
    children: HashSet<ParsingEnvironment>,
    lexing_errors: i32,
    parsing_errors: i32,
}

/// Tracks lexing/parsing error counts, plus the shared [`Locator`] and
/// [`LineArrayListWriter`] used while running the Sleigh preprocessor and grammar.
///
/// Mirrors `ghidra.sleigh.grammar.ParsingEnvironment`. Java gives each
/// `ParsingEnvironment` object identity and lets child environments (built via
/// the copy constructor) share the parent's `writer`/`locator` object
/// references while still tracking their own error counts. This is
/// reproduced here with `Rc<RefCell<_>>`: cloning a `ParsingEnvironment`
/// yields another handle to the *same* environment (matching Java reference
/// semantics), while [`ParsingEnvironment::new_child`] creates a distinct
/// child that is registered in the parent's child set and shares the
/// parent's locator/writer.
///
/// The Java class also formats ANTLR `RecognitionException`s into
/// human-readable messages (`getErrorHeader`, `getLexerErrorMessage`,
/// `getParserErrorMessage`, `getErrorMessage`, `getTokenErrorDisplay`). This
/// crate has no ANTLR runtime bridge -- see the precedent documented on
/// [`RadixBigInteger`](super::RadixBigInteger)'s static `parse` method -- so
/// those ANTLR-exception-formatting methods are not ported here.
#[derive(Clone)]
pub struct ParsingEnvironment(Rc<RefCell<Inner>>);

impl ParsingEnvironment {
    /// Mirrors `ParsingEnvironment(LineArrayListWriter)`: creates a root
    /// environment with a fresh [`Locator`].
    pub fn new(writer: LineArrayListWriter) -> Self {
        Self(Rc::new(RefCell::new(Inner {
            writer: Rc::new(RefCell::new(writer)),
            locator: Rc::new(RefCell::new(Locator::new())),
            children: HashSet::new(),
            lexing_errors: 0,
            parsing_errors: 0,
        })))
    }

    /// Mirrors `ParsingEnvironment(ParsingEnvironment)`: creates a child
    /// environment that shares `parent`'s writer and locator, and registers
    /// itself in `parent`'s child set.
    pub fn new_child(parent: &ParsingEnvironment) -> Self {
        let (writer, locator) = {
            let inner = parent.0.borrow();
            (Rc::clone(&inner.writer), Rc::clone(&inner.locator))
        };
        let child = Self(Rc::new(RefCell::new(Inner {
            writer,
            locator,
            children: HashSet::new(),
            lexing_errors: 0,
            parsing_errors: 0,
        })));
        parent.0.borrow_mut().children.insert(child.clone());
        child
    }

    /// Mirrors `getLexingErrors`: this environment's own lexing error count
    /// plus its direct children's (not grandchildren's) counts.
    pub fn get_lexing_errors(&self) -> i32 {
        let inner = self.0.borrow();
        inner.lexing_errors + Self::child_env_lexing_errors(&inner)
    }

    fn child_env_lexing_errors(inner: &Inner) -> i32 {
        inner.children.iter().map(|env| env.0.borrow().lexing_errors).sum()
    }

    /// Mirrors `getParsingErrors`: this environment's own parsing error count
    /// plus its direct children's (not grandchildren's) counts.
    pub fn get_parsing_errors(&self) -> i32 {
        let inner = self.0.borrow();
        inner.parsing_errors + Self::child_env_parsing_errors(&inner)
    }

    fn child_env_parsing_errors(inner: &Inner) -> i32 {
        inner.children.iter().map(|env| env.0.borrow().parsing_errors).sum()
    }

    /// Mirrors `lexingError`.
    pub fn lexing_error(&self) {
        self.0.borrow_mut().lexing_errors += 1;
    }

    /// Mirrors `parsingError`.
    pub fn parsing_error(&self) {
        self.0.borrow_mut().parsing_errors += 1;
    }

    /// Mirrors `getLocator`.
    pub fn get_locator(&self) -> Rc<RefCell<Locator>> {
        Rc::clone(&self.0.borrow().locator)
    }

    /// Mirrors `getWriter`.
    pub fn get_writer(&self) -> Rc<RefCell<LineArrayListWriter>> {
        Rc::clone(&self.0.borrow().writer)
    }

    /// Mirrors `format(BailoutException)`.
    pub fn format(&self, be: &BailoutException) -> String {
        let lexing_errors = self.get_lexing_errors();
        let parsing_errors = self.get_parsing_errors();
        if lexing_errors > 0 {
            if parsing_errors > 0 {
                return format!(
                    "{be}: {lexing_errors} lexing errors, {parsing_errors} parsing errors"
                );
            }
            return format!("{be}: {lexing_errors} lexing errors");
        }
        if parsing_errors > 0 {
            return format!("{be}: {parsing_errors} parsing errors");
        }
        be.to_string()
    }
}

impl PartialEq for ParsingEnvironment {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for ParsingEnvironment {}

impl Hash for ParsingEnvironment {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Rc::as_ptr(&self.0).hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::Location;

    #[test]
    fn new_environment_starts_with_no_errors() {
        let env = ParsingEnvironment::new(LineArrayListWriter::new());
        assert_eq!(env.get_lexing_errors(), 0);
        assert_eq!(env.get_parsing_errors(), 0);
    }

    #[test]
    fn lexing_and_parsing_error_increment_counts() {
        let env = ParsingEnvironment::new(LineArrayListWriter::new());
        env.lexing_error();
        env.lexing_error();
        env.parsing_error();
        assert_eq!(env.get_lexing_errors(), 2);
        assert_eq!(env.get_parsing_errors(), 1);
    }

    #[test]
    fn child_shares_parent_writer_and_locator() {
        let parent = ParsingEnvironment::new(LineArrayListWriter::new());
        let child = ParsingEnvironment::new_child(&parent);

        assert!(Rc::ptr_eq(&parent.get_writer(), &child.get_writer()));
        assert!(Rc::ptr_eq(&parent.get_locator(), &child.get_locator()));
    }

    #[test]
    fn child_locator_mutation_visible_through_parent() {
        let parent = ParsingEnvironment::new(LineArrayListWriter::new());
        let child = ParsingEnvironment::new_child(&parent);

        child
            .get_locator()
            .borrow_mut()
            .register_location(10, Location::new("child.sleigh", 1));

        let location = parent.get_locator().borrow().get_location(10).unwrap();
        assert_eq!(location.filename, "child.sleigh");
    }

    #[test]
    fn parent_aggregates_direct_child_error_counts() {
        let parent = ParsingEnvironment::new(LineArrayListWriter::new());
        let child = ParsingEnvironment::new_child(&parent);

        parent.lexing_error();
        child.lexing_error();
        child.lexing_error();
        child.parsing_error();

        assert_eq!(parent.get_lexing_errors(), 3);
        assert_eq!(parent.get_parsing_errors(), 1);
        // The child's own view does not include the parent's errors.
        assert_eq!(child.get_lexing_errors(), 2);
    }

    #[test]
    fn grandchild_errors_are_not_double_counted_by_root() {
        let root = ParsingEnvironment::new(LineArrayListWriter::new());
        let child = ParsingEnvironment::new_child(&root);
        let grandchild = ParsingEnvironment::new_child(&child);

        grandchild.lexing_error();

        // Only direct children are summed, matching the Java implementation.
        assert_eq!(root.get_lexing_errors(), 0);
        assert_eq!(child.get_lexing_errors(), 1);
    }

    #[test]
    fn clone_is_the_same_environment() {
        let env = ParsingEnvironment::new(LineArrayListWriter::new());
        let clone = env.clone();
        clone.lexing_error();
        assert_eq!(env.get_lexing_errors(), 1);
        assert_eq!(env, clone);
    }

    #[test]
    fn distinct_environments_are_not_equal() {
        let a = ParsingEnvironment::new(LineArrayListWriter::new());
        let b = ParsingEnvironment::new(LineArrayListWriter::new());
        assert_ne!(a, b);
    }

    #[test]
    fn distinct_environments_can_coexist_in_a_hash_set() {
        let parent = ParsingEnvironment::new(LineArrayListWriter::new());
        let child_a = ParsingEnvironment::new_child(&parent);
        let child_b = ParsingEnvironment::new_child(&parent);

        let mut set = HashSet::new();
        set.insert(child_a.clone());
        set.insert(child_b.clone());
        set.insert(child_a.clone());
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn format_with_no_errors_returns_message_only() {
        let env = ParsingEnvironment::new(LineArrayListWriter::new());
        let be = BailoutException::with_message("aborted");
        assert_eq!(env.format(&be), "aborted");
    }

    #[test]
    fn format_with_only_lexing_errors() {
        let env = ParsingEnvironment::new(LineArrayListWriter::new());
        env.lexing_error();
        env.lexing_error();
        let be = BailoutException::with_message("aborted");
        assert_eq!(env.format(&be), "aborted: 2 lexing errors");
    }

    #[test]
    fn format_with_only_parsing_errors() {
        let env = ParsingEnvironment::new(LineArrayListWriter::new());
        env.parsing_error();
        let be = BailoutException::with_message("aborted");
        assert_eq!(env.format(&be), "aborted: 1 parsing errors");
    }

    #[test]
    fn format_with_both_lexing_and_parsing_errors() {
        let env = ParsingEnvironment::new(LineArrayListWriter::new());
        env.lexing_error();
        env.parsing_error();
        env.parsing_error();
        let be = BailoutException::with_message("aborted");
        assert_eq!(env.format(&be), "aborted: 1 lexing errors, 2 parsing errors");
    }
}
