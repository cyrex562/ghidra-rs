//! Specialization of the (unported) `MDMang` driver that builds a "genericized" copy of the
//! mangled string, substituting each parsed name fragment with a stable placeholder
//! (`name0`, `name1`, ...) instead of its real text.
//!
//! Mirrors `mdemangler.MDMangGenericize`, cut to a trait to break a dependency cycle: it is a
//! cut-point between the still-unported `MDMang`/`MDMangObjectParser` driver pair (`mdemangler`/
//! `mdemangler.object`) and its own genericization state. `MDMang` itself is only ported so far as
//! the narrow rendering-helper seam [`crate::demangler::seam_stubs::MdMangLike`]; the parts of
//! `MDMang`'s surface this class actually overrides or depends on (`resetState`, `initState`, the
//! character-cursor methods, and `MDMangObjectParser.determineItemAndParse`) are represented here
//! as required (implementor-supplied) trait methods instead of a second, broader `MDMang` seam --
//! see [`MdMangGenericize::reset_base_state`], [`MdMangGenericize::init_state`], and
//! [`MdMangGenericize::parse_item`].
//!
//! The character cursor itself (`MDMang.iter`, an `MDCharacterIterator`) *is* already ported for
//! real as [`MdCharacterIterator`](crate::demangler::md_character_iterator::MdCharacterIterator),
//! so every method this class overrides for cursor movement (`next`, `getAndIncrement`,
//! `increment`) and its own private `appendRemainder` are given full, real default
//! implementations here, built directly on that type.

use std::collections::HashMap;

use crate::demangler::md_character_iterator::{MdCharacterIterator, DONE};
use crate::demangler::seam_stubs::{MdExceptionLike, MdFragmentNameLike, MdParsableItemLike};

/// Owned state backing the fragment-genericization bookkeeping.
///
/// Mirrors the `MDMangGenericize` private fields `uniqueCount`, `nextUnique`, and
/// `uniqueFragments`. Kept as a plain data struct (rather than folded directly into the trait)
/// since it is this class's own state, not a placeholder for an unported type.
#[derive(Debug, Default)]
pub struct GenericFragmentState {
    /// Mirrors `MDMangGenericize.uniqueCount`.
    pub unique_count: i64,
    /// Mirrors `MDMangGenericize.nextUnique`: the pre-computed candidate name for the next
    /// not-yet-seen fragment.
    pub next_unique: String,
    /// Mirrors `MDMangGenericize.uniqueFragments`: memoized fragment-text -> generic-name map.
    pub unique_fragments: HashMap<String, String>,
}

impl GenericFragmentState {
    /// Creates the next unique fragment placeholder name (`"name" + count`) for potential use,
    /// advancing the counter.
    ///
    /// Mirrors the private `MDMangGenericize.nextUnique()`.
    fn compute_next_unique(&mut self) -> String {
        self.unique_count += 1;
        format!("name{}", self.unique_count)
    }
}

/// Specialization of the `MDMang` driver that builds a genericized copy of the mangled string.
///
/// Mirrors `mdemangler.MDMangGenericize`. See the module docs for why the unported parts of the
/// `MDMang` base class this type extends are represented as required trait methods rather than a
/// second seam trait.
pub trait MdMangGenericize {
    /// Read access to the character cursor over the mangled string.
    ///
    /// Stands in for `MDMang.iter`.
    fn char_iter(&self) -> &MdCharacterIterator;

    /// Mutable access to the character cursor over the mangled string.
    ///
    /// Stands in for `MDMang.iter`.
    fn char_iter_mut(&mut self) -> &mut MdCharacterIterator;

    /// Read access to the genericized copy of the mangled string built up so far.
    ///
    /// Mirrors `MDMangGenericize.genericizedString`.
    fn generic_buffer(&self) -> &str;

    /// Mutable access to the genericized copy of the mangled string built up so far.
    ///
    /// Mirrors `MDMangGenericize.genericizedString`.
    fn generic_buffer_mut(&mut self) -> &mut String;

    /// Mutable access to the fragment-genericization bookkeeping.
    ///
    /// Mirrors `MDMangGenericize.uniqueCount`/`nextUnique`/`uniqueFragments`.
    fn unique_state_mut(&mut self) -> &mut GenericFragmentState;

    /// Resets whatever base-class (`MDMang`) state this class doesn't itself own: the parse
    /// context stack and the cursor index.
    ///
    /// Mirrors the `super.resetState()` call inside the override of `resetState()`, i.e.
    /// `MDMang.resetState()` (`contextStack = new ArrayList<>(); setIndex(0);`). Required since
    /// `MDMang`'s context stack (`MDContext`) is not ported.
    fn reset_base_state(&mut self);

    /// Prepares for a fresh demangle pass: validates the mangled string is set, (re)creates the
    /// character cursor from it, and calls [`MdMangGenericize::reset_state`].
    ///
    /// Mirrors the inherited (unoverridden) `MDMang.initState()`. Required since it depends on
    /// `MDMang`'s own `mangled` field and blank-string validation, neither of which is ported.
    fn init_state(&mut self) -> Result<(), Box<dyn MdExceptionLike>>;

    /// Parses the item for the mangled string at the cursor's current (fresh) position.
    ///
    /// Mirrors `MDMangObjectParser.determineItemAndParse(this)`. Required since
    /// `MDMangObjectParser` needs the full (unported) `MDMang` grammar-dispatch surface to
    /// implement for real; see
    /// [`MdMangObjectParserLike`](crate::demangler::seam_stubs::MdMangObjectParserLike).
    fn parse_item(&mut self) -> Result<Box<dyn MdParsableItemLike>, Box<dyn MdExceptionLike>>;

    /// Resets per-pass state: the base `MDMang` state, then this class's own genericization
    /// bookkeeping.
    ///
    /// Mirrors the `@Override` of `resetState()`.
    fn reset_state(&mut self) {
        self.reset_base_state();
        self.generic_buffer_mut().clear();
        let state = self.unique_state_mut();
        state.unique_count = -1;
        state.unique_fragments.clear();
        state.next_unique = state.compute_next_unique();
    }

    /// Demangles the string already stored and returns the parsed item, having also built up the
    /// genericized copy of the mangled string in [`MdMangGenericize::generic_buffer`].
    ///
    /// Mirrors the `@Override` of `demangle()`.
    fn demangle(&mut self) -> Result<Box<dyn MdParsableItemLike>, Box<dyn MdExceptionLike>> {
        self.init_state()?;
        let item = self.parse_item()?;
        self.append_remainder();
        Ok(item)
    }

    /// Returns the character at the current cursor position without advancing.
    ///
    /// Inherited unchanged from `MDMang.peek()` (not overridden by `MDMangGenericize`); exposed
    /// here since [`MdMangGenericize::parse_fragment_name_md`] needs it.
    fn peek(&self) -> char {
        self.char_iter().peek()
    }

    /// Advances the cursor by one and returns the character at the new position, without adding
    /// it to the genericized buffer.
    ///
    /// Mirrors the `@Override` of `next()`, which is intentionally left unchanged from
    /// `MDMang.next()`: callers that want the consumed character genericized must use
    /// [`MdMangGenericize::get_and_increment`] instead.
    fn next(&mut self) -> char {
        self.char_iter_mut().next()
    }

    /// Returns the character at the current cursor position, then advances by one, adding the
    /// returned character to the genericized buffer.
    ///
    /// Mirrors the `@Override` of `getAndIncrement()`.
    fn get_and_increment(&mut self) -> char {
        let c = self.char_iter_mut().get_and_increment();
        self.generic_buffer_mut().push(c);
        c
    }

    /// Advances the cursor by one, adding the consumed character to the genericized buffer.
    ///
    /// Mirrors the `@Override` of `increment()`, which (like the original) consumes via
    /// `getAndIncrement()` rather than a plain cursor increment.
    fn increment(&mut self) {
        let c = self.char_iter_mut().get_and_increment();
        self.generic_buffer_mut().push(c);
    }

    /// Advances the cursor by `count`, adding each consumed character to the genericized buffer.
    ///
    /// Mirrors the `@Override` of `increment(int)`.
    fn increment_by(&mut self, count: usize) {
        for _ in 0..count {
            let c = self.char_iter_mut().get_and_increment();
            self.generic_buffer_mut().push(c);
        }
    }

    /// Returns the genericized copy of the mangled string built up so far.
    ///
    /// Mirrors `getGenericSymbol()`.
    fn generic_symbol(&self) -> String {
        self.generic_buffer().to_string()
    }

    /// Parses a fragment name using the base (`MD`) fragment-name grammar, then converts it to a
    /// generic name fragment and appends that to the genericized buffer. Returns the real
    /// (non-generic) parsed name, as the original does.
    ///
    /// Mirrors the `@Override` of `parseFragmentName(MDFragmentName)`. The `fragment` parameter is
    /// accepted (unused) for signature parity with the Java override -- like the original, this
    /// override never reads or writes any of the `MDFragmentName` instance's own fields.
    fn parse_fragment_name(
        &mut self,
        _fragment: &mut dyn MdFragmentNameLike,
    ) -> Result<String, Box<dyn MdExceptionLike>> {
        let name = self.parse_fragment_name_md();
        self.create_and_append_generic_fragment(&name);
        Ok(name)
    }

    /// Parses a fragment name using the base (`MD`) grammar: consumes letters, digits, and
    /// `_$<>-.` characters from the cursor (via [`MdMangGenericize::next`], so the consumed
    /// characters are *not* added to the genericized buffer) until a non-matching character or the
    /// end of input is reached.
    ///
    /// Mirrors `MDFragmentName.parseFragmentName_Md()`, inlined here since that method only reads
    /// cursor state (`dmang.peek()`/`dmang.next()`), never any field of the `MDFragmentName`
    /// instance it is nominally called on -- so it is identical whether invoked as `fn` calling
    /// back into `dmang`, or (as here) `dmang` performing it directly. The real `MDFragmentName`
    /// port can delegate its `parseFragmentName_Md()` to this method.
    fn parse_fragment_name_md(&mut self) -> String {
        let mut frag = String::new();
        loop {
            let ch = self.peek();
            if ch == DONE {
                break;
            }
            let is_fragment_char =
                ch.is_alphabetic() || ch.is_numeric() || matches!(ch, '_' | '$' | '<' | '>' | '-' | '.');
            if !is_fragment_char {
                break;
            }
            frag.push(ch);
            self.next();
        }
        frag
    }

    /// Converts `fragment` to a generic name fragment and appends it to the genericized buffer. If
    /// the fragment has been seen before, reuses the generic name previously devised for it.
    ///
    /// Mirrors the private `createAndAppendGenericFragment(String)`, including its "fixup" for
    /// fragments beginning with `'A'` (the anonymous-namespace encoding): the pending candidate
    /// name is prefixed with an extra `'A'` every time such a fragment is seen, even if that
    /// fragment already has a memoized name and the candidate ends up going unused this round --
    /// this is a faithful port of that behavior, not a bug fix.
    fn create_and_append_generic_fragment(&mut self, fragment: &str) {
        if fragment.is_empty() {
            return;
        }
        if fragment.starts_with('A') {
            let state = self.unique_state_mut();
            state.next_unique = format!("A{}", state.next_unique);
        }
        let unique_fragment = {
            let state = self.unique_state_mut();
            if let Some(existing) = state.unique_fragments.get(fragment) {
                existing.clone()
            } else {
                let candidate = state.next_unique.clone();
                state.unique_fragments.insert(fragment.to_string(), candidate.clone());
                state.next_unique = state.compute_next_unique();
                candidate
            }
        };
        self.generic_buffer_mut().push_str(&unique_fragment);
    }

    /// Appends any not-yet-consumed tail of the mangled string to the genericized buffer verbatim.
    ///
    /// Mirrors the private `appendRemainder()`.
    fn append_remainder(&mut self) {
        let remainder = {
            let it = self.char_iter();
            if it.get_index() < it.get_length() {
                Some(it.get_string().chars().skip(it.get_index()).collect::<String>())
            } else {
                None
            }
        };
        if let Some(remainder) = remainder {
            self.generic_buffer_mut().push_str(&remainder);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demangler::seam_stubs::MdMangObjectParserLike;

    #[derive(Debug)]
    struct MockException(String);

    impl std::fmt::Display for MockException {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl MdExceptionLike for MockException {}

    struct MockParsableItem;

    impl MdParsableItemLike for MockParsableItem {}

    /// Trivial stand-in proving [`MdMangObjectParserLike`] is usable (it has no members to
    /// exercise beyond existing as a marker type).
    struct MockObjectParser;

    impl MdMangObjectParserLike for MockObjectParser {}

    struct MockFragmentName {
        name: Option<String>,
    }

    impl MdFragmentNameLike for MockFragmentName {
        fn get_name(&self) -> String {
            self.name.clone().unwrap_or_default()
        }

        fn set_name(&mut self, name: String) {
            self.name = Some(name);
        }

        fn insert(&self, _dmang: &dyn crate::demangler::seam_stubs::MdMangLike, _builder: &mut String) {}
    }

    struct MockGenericize {
        mangled: String,
        iter: MdCharacterIterator,
        buffer: String,
        state: GenericFragmentState,
        base_reset_calls: usize,
        parse_should_fail: bool,
    }

    impl MockGenericize {
        fn new(mangled: &str) -> Self {
            Self {
                mangled: mangled.to_string(),
                iter: MdCharacterIterator::new(mangled),
                buffer: String::new(),
                state: GenericFragmentState::default(),
                base_reset_calls: 0,
                parse_should_fail: false,
            }
        }
    }

    impl MdMangGenericize for MockGenericize {
        fn char_iter(&self) -> &MdCharacterIterator {
            &self.iter
        }

        fn char_iter_mut(&mut self) -> &mut MdCharacterIterator {
            &mut self.iter
        }

        fn generic_buffer(&self) -> &str {
            &self.buffer
        }

        fn generic_buffer_mut(&mut self) -> &mut String {
            &mut self.buffer
        }

        fn unique_state_mut(&mut self) -> &mut GenericFragmentState {
            &mut self.state
        }

        fn reset_base_state(&mut self) {
            self.base_reset_calls += 1;
            self.iter.set_index(0);
        }

        fn init_state(&mut self) -> Result<(), Box<dyn MdExceptionLike>> {
            if self.mangled.trim().is_empty() {
                return Err(Box::new(MockException("MDMang: Mangled string is null or blank.".into())));
            }
            self.iter = MdCharacterIterator::new(self.mangled.clone());
            self.reset_state();
            Ok(())
        }

        fn parse_item(&mut self) -> Result<Box<dyn MdParsableItemLike>, Box<dyn MdExceptionLike>> {
            if self.parse_should_fail {
                return Err(Box::new(MockException("parse failed".into())));
            }
            // Consume a "name" fragment (letters) up to '@', mirroring how a real parser would
            // call back into parse_fragment_name for a name component.
            let mut dummy = MockFragmentName { name: None };
            let name = self.parse_fragment_name(&mut dummy).unwrap();
            dummy.set_name(name);
            if self.peek() == '@' {
                self.increment();
            }
            Ok(Box::new(MockParsableItem))
        }
    }

    #[test]
    fn reset_state_initializes_first_unique_name_and_calls_base_reset() {
        let mut mock = MockGenericize::new("Foo@@bar");
        mock.reset_state();

        assert_eq!(mock.base_reset_calls, 1);
        assert_eq!(mock.state.unique_count, 0);
        assert_eq!(mock.state.next_unique, "name0");
        assert!(mock.generic_buffer().is_empty());
    }

    #[test]
    fn get_and_increment_appends_consumed_char_to_generic_buffer() {
        let mut mock = MockGenericize::new("abc");
        mock.reset_state();

        assert_eq!(mock.get_and_increment(), 'a');
        assert_eq!(mock.get_and_increment(), 'b');
        assert_eq!(mock.generic_buffer(), "ab");
    }

    #[test]
    fn next_does_not_genericize() {
        let mut mock = MockGenericize::new("abc");
        mock.reset_state();

        assert_eq!(mock.next(), 'b');
        assert!(mock.generic_buffer().is_empty(), "next() must not append to the genericized buffer");
    }

    #[test]
    fn increment_by_appends_all_consumed_chars() {
        let mut mock = MockGenericize::new("hello");
        mock.reset_state();

        mock.increment_by(3);

        assert_eq!(mock.generic_buffer(), "hel");
        assert_eq!(mock.char_iter().get_index(), 3);
    }

    #[test]
    fn parse_fragment_name_md_stops_at_non_fragment_char() {
        let mut mock = MockGenericize::new("Foo_Bar<Baz>@@rest");
        mock.reset_state();

        let frag = mock.parse_fragment_name_md();

        assert_eq!(frag, "Foo_Bar<Baz>");
        assert_eq!(mock.peek(), '@');
        assert!(mock.generic_buffer().is_empty(), "parse_fragment_name_md must not genericize");
    }

    #[test]
    fn create_and_append_generic_fragment_reuses_name_for_repeated_fragment() {
        let mut mock = MockGenericize::new("");
        mock.reset_state();

        mock.create_and_append_generic_fragment("Widget");
        mock.create_and_append_generic_fragment("Gadget");
        mock.create_and_append_generic_fragment("Widget");

        assert_eq!(mock.generic_buffer(), "name0name1name0");
    }

    #[test]
    fn create_and_append_generic_fragment_ignores_empty_fragment() {
        let mut mock = MockGenericize::new("");
        mock.reset_state();

        mock.create_and_append_generic_fragment("");

        assert!(mock.generic_buffer().is_empty());
        assert_eq!(mock.state.unique_count, 0, "empty fragment must not consume a unique name");
    }

    #[test]
    fn anonymous_namespace_fragment_gets_a_prefixed_name() {
        let mut mock = MockGenericize::new("");
        mock.reset_state();

        mock.create_and_append_generic_fragment("A0xdeadbeef");

        assert_eq!(mock.generic_buffer(), "Aname0");
    }

    #[test]
    fn get_generic_symbol_returns_current_buffer() {
        let mut mock = MockGenericize::new("ab");
        mock.reset_state();
        mock.get_and_increment();

        assert_eq!(mock.generic_symbol(), "a");
    }

    #[test]
    fn demangle_appends_remainder_after_parse() {
        let mut mock = MockGenericize::new("Foo@@rest");

        let result = mock.demangle();

        assert!(result.is_ok());
        // "Foo" is genericized to "name0" by parse_fragment_name, then the first "@" is consumed
        // via increment() (also genericized), leaving the second "@" plus "rest" unconsumed, which
        // append_remainder() appends verbatim.
        assert_eq!(mock.generic_symbol(), "name0@@rest");
    }

    #[test]
    fn demangle_propagates_init_state_error_for_blank_mangled_string() {
        let mut mock = MockGenericize::new("   ");

        let result = mock.demangle();

        assert!(result.is_err());
    }

    #[test]
    fn demangle_propagates_parse_item_error() {
        let mut mock = MockGenericize::new("Foo@@rest");
        mock.parse_should_fail = true;

        let result = mock.demangle();

        assert!(result.is_err());
    }

    #[test]
    fn trait_object_is_usable() {
        let mut mock = MockGenericize::new("xyz");
        let dmang: &mut dyn MdMangGenericize = &mut mock;

        dmang.reset_state();
        assert_eq!(dmang.get_and_increment(), 'x');
        assert_eq!(dmang.generic_symbol(), "x");
    }
}
