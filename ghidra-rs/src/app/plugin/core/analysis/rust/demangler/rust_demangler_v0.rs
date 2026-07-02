//! Demangles Rust symbols mangled according to the V0 format.
//!
//! Maps to `ghidra.app.plugin.core.analysis.rust.demangler.RustDemanglerV0`.
//!
//! Ported and adapted from `rustc-demangle` (<https://github.com/rust-lang/rustc-demangle>).
//!
//! See <https://rust-lang.github.io/rfcs/2603-rust-symbol-name-mangling-v0.html>.

/// Message returned (or embedded) when the demangler's recursion limit is hit.
pub const RECURSION_LIMIT_MESSAGE: &str = "{recursion limit reached}";

/// Maximum path/type/const nesting depth the demangler will follow.
pub const MAX_DEPTH: i32 = 500;

/// Demangles a symbol according to the v0 format.
pub fn demangle(symbol: &str) -> Option<String> {
    demangle_internal(symbol, false)
}

/// Demangles a Rust V0 mangled symbol using an alternate format that omits
/// hash/disambiguator suffixes.
pub fn demangle_alternate(symbol: &str) -> Option<String> {
    demangle_internal(symbol, true)
}

fn demangle_internal(symbol: &str, alternate: bool) -> Option<String> {
    if symbol.is_empty() {
        return None;
    }

    let inner = strip_prefix(symbol)?;
    if inner.is_empty() {
        return None;
    }

    if !inner.is_ascii() {
        return None;
    }

    if !starts_with_upper_path(inner) {
        return None;
    }

    let parser = Parser::new(inner);

    let dry_run: ParseResult<()> = (|| {
        let after_first = Printer::dry_run_parse_path(parser, false, alternate)?;
        if starts_with_upper_path(after_first.remaining()) {
            Printer::dry_run_parse_path(after_first, false, alternate)?;
        }
        Ok(())
    })();
    if dry_run.is_err() {
        return None;
    }

    let mut printer = Printer::new(parser, true, alternate);
    match printer.print_path(true) {
        Ok(()) => {
            let result = printer.finish();
            let mut suffix = printer.remaining().to_string();
            if !suffix.is_empty() {
                let keep_suffix = suffix.starts_with('.')
                    && !suffix.starts_with(".llvm")
                    && !suffix.starts_with("@@");
                if !keep_suffix {
                    suffix.clear();
                }
            }
            Some(if suffix.is_empty() { result } else { format!("{result}{suffix}") })
        }
        Err(e) if e.is_recursed_too_deep() => Some(e.message().to_string()),
        Err(_) => None,
    }
}

/// Removes known rust prefixes.
fn strip_prefix(symbol: &str) -> Option<&str> {
    if symbol.len() > 2 && symbol.starts_with("_R") {
        return Some(&symbol[2..]);
    }
    if symbol.len() > 1 && symbol.starts_with('R') {
        return Some(&symbol[1..]);
    }
    if symbol.len() > 3 && symbol.starts_with("__R") {
        return Some(&symbol[3..]);
    }
    None
}

/// Rust v0 manglings always begin with a capital letter describing the top-level path kind.
fn starts_with_upper_path(text: &str) -> bool {
    matches!(text.as_bytes().first(), Some(b) if b.is_ascii_uppercase())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseErrorKind {
    Invalid,
    RecursedTooDeep,
}

#[derive(Debug, Clone, Copy)]
struct ParseError {
    kind: ParseErrorKind,
}

impl ParseError {
    fn invalid() -> Self {
        ParseError { kind: ParseErrorKind::Invalid }
    }

    fn recursed_too_deep() -> Self {
        ParseError { kind: ParseErrorKind::RecursedTooDeep }
    }

    fn is_recursed_too_deep(&self) -> bool {
        self.kind == ParseErrorKind::RecursedTooDeep
    }

    fn message(&self) -> &'static str {
        match self.kind {
            ParseErrorKind::RecursedTooDeep => RECURSION_LIMIT_MESSAGE,
            ParseErrorKind::Invalid => "{invalid syntax}",
        }
    }
}

type ParseResult<T> = Result<T, ParseError>;

/// Stateful cursor used while walking the v0 grammar. The parser owns the original
/// mangled string, maintains the current offset, and keeps a recursion counter so we can
/// mirror rustc's depth limits when following backrefs.
#[derive(Clone, Copy)]
struct Parser<'a> {
    sym: &'a str,
    next: usize,
    depth: i32,
}

impl<'a> Parser<'a> {
    fn new(sym: &'a str) -> Self {
        Parser { sym, next: 0, depth: 0 }
    }

    fn with_state(sym: &'a str, next: usize, depth: i32) -> Self {
        Parser { sym, next, depth }
    }

    /// Returns the remaining string to be demangled.
    fn remaining(&self) -> &'a str {
        &self.sym[self.next..]
    }

    /// Returns the next character without consuming it, or `-1` if the cursor is exhausted.
    fn peek(&self) -> i32 {
        self.sym.as_bytes().get(self.next).map(|&b| b as i32).unwrap_or(-1)
    }

    /// Advances the cursor when the next character matches `expected`.
    fn eat(&mut self, expected: u8) -> bool {
        if self.peek() == expected as i32 {
            self.next += 1;
            true
        } else {
            false
        }
    }

    /// Consumes and returns the next character.
    fn next_char(&mut self) -> ParseResult<u8> {
        if self.next >= self.sym.len() {
            return Err(ParseError::invalid());
        }
        let c = self.sym.as_bytes()[self.next];
        self.next += 1;
        Ok(c)
    }

    fn push_depth(&mut self) -> ParseResult<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(ParseError::recursed_too_deep());
        }
        Ok(())
    }

    fn pop_depth(&mut self) {
        self.depth -= 1;
    }

    /// Reads a sequence of hexadecimal digits terminated by `'_'` and exposes them as a
    /// [`HexNibbles`] helper.
    fn hex_nibbles(&mut self) -> ParseResult<HexNibbles<'a>> {
        let start = self.next;
        loop {
            let c = self.next_char()?;
            if is_hex_digit(c) {
                continue;
            }
            if c == b'_' {
                break;
            }
            return Err(ParseError::invalid());
        }
        Ok(HexNibbles::new(&self.sym[start..self.next - 1]))
    }

    /// Parses a decimal digit character.
    fn digit10(&mut self) -> ParseResult<i32> {
        let p = self.peek();
        if p >= b'0' as i32 && p <= b'9' as i32 {
            self.next += 1;
            return Ok(p - b'0' as i32);
        }
        Err(ParseError::invalid())
    }

    /// Parses the next base-62 digit.
    fn digit62(&mut self) -> ParseResult<u32> {
        let p = self.peek();
        if p >= b'0' as i32 && p <= b'9' as i32 {
            self.next += 1;
            return Ok((p - b'0' as i32) as u32);
        }
        if p >= b'a' as i32 && p <= b'z' as i32 {
            self.next += 1;
            return Ok(10 + (p - b'a' as i32) as u32);
        }
        if p >= b'A' as i32 && p <= b'Z' as i32 {
            self.next += 1;
            return Ok(36 + (p - b'A' as i32) as u32);
        }
        Err(ParseError::invalid())
    }

    /// Reads a base-62 integer terminated by `'_'` and returns the decoded value.
    fn integer62(&mut self) -> ParseResult<u64> {
        if self.eat(b'_') {
            return Ok(0);
        }

        let mut value: u64 = 0;
        while !self.eat(b'_') {
            let digit = self.digit62()?;
            value = multiply_add_base62(value, digit)?;
        }
        add_exact_u64(value, 1)
    }

    /// Optionally consumes a base-62 integer prefixed by `tag` and returns the decoded value.
    fn opt_integer62(&mut self, tag: u8) -> ParseResult<u64> {
        if !self.eat(tag) {
            return Ok(0);
        }
        add_exact_u64(self.integer62()?, 1)
    }

    /// Parses the optional `s` disambiguator used to render hash-like suffixes.
    fn disambiguator(&mut self) -> ParseResult<u64> {
        self.opt_integer62(b's')
    }

    /// Reads the namespace designator that precedes nested paths.
    fn namespace(&mut self) -> ParseResult<Option<u8>> {
        let c = self.next_char()?;
        if c.is_ascii_uppercase() {
            return Ok(Some(c));
        }
        if c.is_ascii_lowercase() {
            return Ok(None);
        }
        Err(ParseError::invalid())
    }

    /// Resolves a backreference, returning a new parser positioned at the referenced start.
    fn backref(&mut self) -> ParseResult<Parser<'a>> {
        let start = self.next - 1;
        let offset = self.integer62()?;
        if offset >= start as u64 {
            return Err(ParseError::invalid());
        }
        let mut p = Parser::with_state(self.sym, offset as usize, self.depth);
        p.push_depth()?;
        Ok(p)
    }

    /// Parses an identifier, handling punycode (for non-ASCII) and optional disambiguator suffixes.
    fn ident(&mut self) -> ParseResult<Ident> {
        let is_punycode = self.eat(b'u');
        let mut len = self.digit10()?;
        if len != 0 {
            loop {
                let peek = self.peek();
                if peek < b'0' as i32 || peek > b'9' as i32 {
                    break;
                }
                self.next += 1;
                len = multiply_exact_i32(len, 10)?;
                len = add_exact_i32(len, peek - b'0' as i32)?;
            }
        }

        self.eat(b'_');

        if len < 0 || self.next as i64 + len as i64 > self.sym.len() as i64 {
            return Err(ParseError::invalid());
        }
        let len = len as usize;
        let raw = &self.sym[self.next..self.next + len];
        self.next += len;

        if is_punycode {
            let sep = raw.rfind('_');
            let (ascii, punycode) = match sep {
                Some(idx) => (&raw[..idx], &raw[idx + 1..]),
                None => ("", raw),
            };
            if punycode.is_empty() {
                return Err(ParseError::invalid());
            }
            return Ok(Ident::new(ascii.to_string(), punycode.to_string()));
        }

        Ok(Ident::new(raw.to_string(), String::new()))
    }
}

/// Pretty printer that mirrors the upstream rustc-demangle formatter. It consumes parsed
/// tokens by delegating back into [`Parser`] and emits either the normal or the alternate
/// (hash-stripped) textual form depending on the `alternate` flag.
struct Printer<'a> {
    parser: Parser<'a>,
    out: Option<String>,
    bound_lifetime_depth: i32,
    alternate: bool,
}

impl<'a> Printer<'a> {
    fn new(parser: Parser<'a>, capture: bool, alternate: bool) -> Self {
        Printer { parser, out: if capture { Some(String::new()) } else { None }, bound_lifetime_depth: 0, alternate }
    }

    fn dry_run_parse_path(parser: Parser<'a>, in_value: bool, alternate: bool) -> ParseResult<Parser<'a>> {
        let mut printer = Printer::new(parser, false, alternate);
        printer.print_path(in_value)?;
        Ok(printer.parser)
    }

    /// Returns the accumulated demangled output.
    fn finish(&mut self) -> String {
        self.out.take().unwrap_or_default()
    }

    /// Returns any suffix that was not consumed during the primary parse (e.g. `.llvm` decorations).
    fn remaining(&self) -> &'a str {
        self.parser.remaining()
    }

    /// Prints a v0 path grammar node. This mirrors the legacy implementation's `RustPath.parse`.
    fn print_path(&mut self, in_value: bool) -> ParseResult<()> {
        self.parser.push_depth()?;

        let tag = self.parser.next_char()?;
        match tag {
            b'C' => {
                // crate root / plain identifier
                let dis = self.parser.disambiguator()?;
                let name = self.parser.ident()?;
                let rendered = name.render();
                self.print(&rendered);
                if dis != 0 && !self.alternate {
                    self.print_char('[');
                    self.print_lower_hex(dis);
                    self.print_char(']');
                }
            }
            b'N' => {
                // nested path (module::item)
                let ns = self.parser.namespace()?;
                self.print_path(in_value)?;
                let dis = self.parser.disambiguator()?;
                let name = self.parser.ident()?;

                if let Some(ns_char) = ns {
                    self.print("::{");
                    match ns_char {
                        b'C' => self.print("closure"),
                        b'S' => self.print("shim"),
                        other => self.print_char(other as char),
                    }
                    if !name.is_empty() {
                        self.print_char(':');
                        let rendered = name.render();
                        self.print(&rendered);
                    }
                    self.print_char('#');
                    self.print_u64(dis);
                    self.print_char('}');
                } else if !name.is_empty() {
                    self.print("::");
                    let rendered = name.render();
                    self.print(&rendered);
                }
            }
            // 'M' inherent impl path (<impl-path>::item), 'X' trait impl path
            // (<T as Trait>::item), 'Y' trait definition (<T as Trait>)
            b'M' | b'X' | b'Y' => {
                if tag != b'Y' {
                    self.parser.disambiguator()?;
                    self.skipping_printing(|pr| pr.print_path(false))?;
                }
                self.print_char('<');
                self.print_type()?;
                if tag != b'M' {
                    self.print(" as ");
                    self.print_path(false)?;
                }
                self.print_char('>');
            }
            b'I' => {
                // path with generic arguments
                self.print_path(in_value)?;
                if in_value {
                    self.print("::");
                }
                self.print_char('<');
                self.print_sep_list(|pr| pr.print_generic_arg(), ", ")?;
                self.print_char('>');
            }
            b'B' => {
                // backreference into previously seen path
                self.print_backref(move |pr| pr.print_path(in_value))?;
            }
            _ => return Err(ParseError::invalid()),
        }

        self.parser.pop_depth();
        Ok(())
    }

    /// Prints a single generic argument (lifetime, const, or type).
    fn print_generic_arg(&mut self) -> ParseResult<()> {
        if self.parser.eat(b'L') {
            let lt = self.parser.integer62()?;
            self.print_lifetime_from_index(lt)?;
        } else if self.parser.eat(b'K') {
            self.print_const(false)?;
        } else {
            self.print_type()?;
        }
        Ok(())
    }

    /// Prints a type node (the equivalent of legacy `RustType.parse`).
    fn print_type(&mut self) -> ParseResult<()> {
        let tag = self.parser.next_char()?;
        if let Some(basic) = basic_type(tag) {
            self.print(basic);
            return Ok(());
        }

        self.parser.push_depth()?;

        match tag {
            b'R' | b'Q' => {
                // &T / &mut T
                self.print_char('&');
                if self.parser.eat(b'L') {
                    let lt = self.parser.integer62()?;
                    if lt != 0 {
                        self.print_lifetime_from_index(lt)?;
                        self.print_char(' ');
                    }
                }
                if tag != b'R' {
                    self.print("mut ");
                }
                self.print_type()?;
            }
            b'P' | b'O' => {
                // *const T / *mut T
                self.print_char('*');
                if tag == b'P' {
                    self.print("const ");
                } else {
                    self.print("mut ");
                }
                self.print_type()?;
            }
            b'A' | b'S' => {
                // [T; N] / [T]
                self.print_char('[');
                self.print_type()?;
                if tag == b'A' {
                    self.print("; ");
                    self.print_const(true)?;
                }
                self.print_char(']');
            }
            b'T' => {
                // tuple (T1, T2, ...)
                self.print_char('(');
                let count = self.print_sep_list(Printer::print_type, ", ")?;
                if count == 1 {
                    self.print_char(',');
                }
                self.print_char(')');
            }
            b'F' => {
                // fn(...) -> ...
                self.in_binder(|pr| {
                    let is_unsafe = pr.parser.eat(b'U');
                    let mut abi: Option<String> = None;
                    if pr.parser.eat(b'K') {
                        if pr.parser.eat(b'C') {
                            abi = Some("C".to_string());
                        } else {
                            let ident = pr.parser.ident()?;
                            if !ident.punycode.is_empty() || ident.ascii.is_empty() {
                                return Err(ParseError::invalid());
                            }
                            abi = Some(ident.ascii);
                        }
                    }

                    if is_unsafe {
                        pr.print("unsafe ");
                    }

                    if let Some(abi) = &abi {
                        pr.print("extern \"");
                        for (i, part) in abi.split('_').enumerate() {
                            if i != 0 {
                                pr.print_char('-');
                            }
                            pr.print(part);
                        }
                        pr.print("\" ");
                    }

                    pr.print("fn(");
                    pr.print_sep_list(Printer::print_type, ", ")?;
                    pr.print_char(')');

                    if !pr.parser.eat(b'u') {
                        pr.print(" -> ");
                        pr.print_type()?;
                    }
                    Ok(())
                })?;
            }
            b'D' => {
                // dyn Trait + bounds
                self.print("dyn ");
                self.in_binder(|pr| pr.print_sep_list(Printer::print_dyn_trait, " + ").map(|_| ()))?;
                if !self.parser.eat(b'L') {
                    return Err(ParseError::invalid());
                }
                let lt = self.parser.integer62()?;
                if lt != 0 {
                    self.print(" + ");
                    self.print_lifetime_from_index(lt)?;
                }
            }
            b'B' => {
                // backref to previously printed type
                self.print_backref(Printer::print_type)?;
            }
            b'W' => {
                // type with pattern (unstable internal form)
                self.print_type()?;
                self.print(" is ");
                self.print_pat()?;
            }
            _ => {
                // rewind for path parsing
                self.parser.next -= 1;
                self.print_path(false)?;
            }
        }

        self.parser.pop_depth();
        Ok(())
    }

    /// Prints either a plain path or a path with `<...>` generics, returning whether the caller
    /// should emit the closing `>` (needed for dyn-trait associated bindings).
    fn print_path_maybe_open_generics(&mut self) -> ParseResult<bool> {
        if self.parser.eat(b'B') {
            let mut open = false;
            self.print_backref(|pr| {
                open = pr.print_path_maybe_open_generics()?;
                Ok(())
            })?;
            return Ok(open);
        }
        if self.parser.eat(b'I') {
            self.print_path(false)?;
            self.print_char('<');
            self.print_sep_list(Printer::print_generic_arg, ", ")?;
            return Ok(true);
        }
        self.print_path(false)?;
        Ok(false)
    }

    /// Prints a single trait appearing inside a `dyn` object, including associated type bindings.
    fn print_dyn_trait(&mut self) -> ParseResult<()> {
        let mut open = self.print_path_maybe_open_generics()?;
        while self.parser.eat(b'p') {
            if !open {
                self.print_char('<');
                open = true;
            } else {
                self.print(", ");
            }
            let name = self.parser.ident()?;
            let rendered = name.render();
            self.print(&rendered);
            self.print(" = ");
            self.print_type()?;
        }
        if open {
            self.print_char('>');
        }
        Ok(())
    }

    /// Prints pattern fragments used by the unstable `is` syntax (range unions, etc.).
    fn print_pat(&mut self) -> ParseResult<()> {
        let tag = self.parser.next_char()?;
        match tag {
            b'R' => {
                self.print_const(false)?;
                self.print("..=");
                self.print_const(false)?;
            }
            b'O' => {
                self.parser.push_depth()?;
                self.print_pat()?;
                while !self.parser.eat(b'E') {
                    self.print(" | ");
                    self.print_pat()?;
                }
                self.parser.pop_depth();
            }
            b'N' => {
                self.print("!null");
            }
            _ => return Err(ParseError::invalid()),
        }
        Ok(())
    }

    /// Prints a constant expression appearing either as a value or inside generics.
    fn print_const(&mut self, in_value: bool) -> ParseResult<()> {
        let tag = self.parser.next_char()?;
        self.parser.push_depth()?;

        let mut opened_brace = false;
        let require_wrap = !in_value;

        match tag {
            b'p' => {
                // `_` placeholder
                self.print_char('_');
            }
            b'h' | b't' | b'm' | b'y' | b'o' | b'j' => {
                // unsigned integers
                self.print_const_uint(tag)?;
            }
            b'a' | b's' | b'l' | b'x' | b'n' | b'i' => {
                // signed integers
                if self.parser.eat(b'n') {
                    self.print_char('-');
                }
                self.print_const_uint(tag)?;
            }
            b'b' => {
                // bool
                let hex = self.parser.hex_nibbles()?;
                let v = hex.try_parse_uint().ok_or_else(ParseError::invalid)?;
                match v {
                    0 => self.print("false"),
                    1 => self.print("true"),
                    _ => return Err(ParseError::invalid()),
                }
            }
            b'c' => {
                // char literal
                let hex = self.parser.hex_nibbles()?;
                let value = hex.try_parse_uint().ok_or_else(ParseError::invalid)?;
                if value > char::MAX as u64 {
                    return Err(ParseError::invalid());
                }
                let ch = char::from_u32(value as u32).ok_or_else(ParseError::invalid)?;
                let mut data = String::new();
                data.push(ch);
                self.print_quoted_escaped_chars('\'', &data);
            }
            b'e' => {
                // str literal (stored as *"...")
                if require_wrap {
                    opened_brace = true;
                    self.print_char('{');
                }
                self.print_char('*');
                self.print_const_str_literal()?;
            }
            b'R' | b'Q' => {
                // references in const position
                if tag == b'R' && self.parser.eat(b'e') {
                    self.print_const_str_literal()?;
                } else {
                    if require_wrap {
                        opened_brace = true;
                        self.print_char('{');
                    }
                    self.print_char('&');
                    if tag != b'R' {
                        self.print("mut ");
                    }
                    self.print_const(true)?;
                }
            }
            b'A' => {
                // array literal
                if require_wrap {
                    opened_brace = true;
                    self.print_char('{');
                }
                self.print_char('[');
                self.print_sep_list(|pr| pr.print_const(true), ", ")?;
                self.print_char(']');
            }
            b'T' => {
                // tuple literal
                if require_wrap {
                    opened_brace = true;
                    self.print_char('{');
                }
                self.print_char('(');
                let count = self.print_sep_list(|pr| pr.print_const(true), ", ")?;
                if count == 1 {
                    self.print_char(',');
                }
                self.print_char(')');
            }
            b'V' => {
                // enum/struct literal
                if require_wrap {
                    opened_brace = true;
                    self.print_char('{');
                }
                self.print_path(true)?;
                let variant = self.parser.next_char()?;
                match variant {
                    b'U' => {}
                    b'T' => {
                        self.print_char('(');
                        self.print_sep_list(|pr| pr.print_const(true), ", ")?;
                        self.print_char(')');
                    }
                    b'S' => {
                        self.print(" { ");
                        self.print_sep_list(
                            |pr| {
                                pr.parser.disambiguator()?;
                                let name = pr.parser.ident()?;
                                let rendered = name.render();
                                pr.print(&rendered);
                                pr.print(": ");
                                pr.print_const(true)?;
                                Ok(())
                            },
                            ", ",
                        )?;
                        self.print(" }");
                    }
                    _ => return Err(ParseError::invalid()),
                }
            }
            b'B' => {
                // backref
                self.print_backref(move |pr| pr.print_const(in_value))?;
            }
            _ => return Err(ParseError::invalid()),
        }

        if opened_brace {
            self.print_char('}');
        }

        self.parser.pop_depth();
        Ok(())
    }

    /// Formats a hexadecimal string literal as a quoted `"..."` string.
    fn print_const_str_literal(&mut self) -> ParseResult<()> {
        let hex = self.parser.hex_nibbles()?;
        let decoded = hex.try_parse_str().ok_or_else(ParseError::invalid)?;
        self.print_quoted_escaped_chars('"', &decoded);
        Ok(())
    }

    /// Emits an integer literal, appending the suffix when alternate formatting is disabled.
    fn print_const_uint(&mut self, ty_tag: u8) -> ParseResult<()> {
        let hex = self.parser.hex_nibbles()?;
        match hex.try_parse_uint() {
            Some(value) => self.print_u64(value),
            None => {
                self.print("0x");
                self.print(hex.nibbles);
            }
        }
        if let Some(ty) = basic_type(ty_tag) {
            if !self.alternate {
                self.print(ty);
            }
        }
        Ok(())
    }

    /// Replays a previously printed node referenced by a `B` backref tag.
    fn print_backref<F>(&mut self, mut consumer: F) -> ParseResult<()>
    where
        F: FnMut(&mut Printer<'a>) -> ParseResult<()>,
    {
        let backref = self.parser.backref()?;
        if self.out.is_none() {
            return Ok(());
        }
        let saved = self.parser;
        self.parser = backref;
        let result = consumer(self);
        self.parser = saved;
        result
    }

    /// Handles the `for<...>` binder that introduces late-bound lifetimes.
    fn in_binder<F>(&mut self, mut consumer: F) -> ParseResult<()>
    where
        F: FnMut(&mut Printer<'a>) -> ParseResult<()>,
    {
        let count = self.parser.opt_integer62(b'G')?;
        if self.out.is_none() {
            return consumer(self);
        }
        if count > 0 {
            self.print("for<");
            for i in 0..count {
                if i != 0 {
                    self.print(", ");
                }
                self.bound_lifetime_depth += 1;
                self.print_lifetime_from_index(1)?;
            }
            self.print("> ");
        }
        consumer(self)?;
        self.bound_lifetime_depth -= count as i32;
        Ok(())
    }

    /// Utility for comma-separated lists terminated by `'E'`.
    fn print_sep_list<F>(&mut self, mut consumer: F, sep: &str) -> ParseResult<i32>
    where
        F: FnMut(&mut Printer<'a>) -> ParseResult<()>,
    {
        let mut count = 0;
        while !self.parser.eat(b'E') {
            if count != 0 {
                self.print(sep);
            }
            consumer(self)?;
            count += 1;
        }
        Ok(count)
    }

    /// Converts the encoded lifetime index into a textual representation (e.g. `'a`).
    fn print_lifetime_from_index(&mut self, lt: u64) -> ParseResult<()> {
        if self.out.is_none() {
            return Ok(());
        }
        self.print_char('\'');
        if lt == 0 {
            self.print_char('_');
            return Ok(());
        }
        let depth = self.bound_lifetime_depth as i64 - lt as i64;
        if depth < 0 {
            return Err(ParseError::invalid());
        }
        if depth < 26 {
            self.print_char((b'a' + depth as u8) as char);
        } else {
            self.print_char('_');
            self.print_u64(depth as u64);
        }
        Ok(())
    }

    /// Temporarily disables output while still consuming the parse tree (used for impl paths).
    fn skipping_printing<F>(&mut self, mut consumer: F) -> ParseResult<()>
    where
        F: FnMut(&mut Printer<'a>) -> ParseResult<()>,
    {
        let original = self.out.take();
        consumer(self)?;
        self.out = original;
        Ok(())
    }

    fn print(&mut self, text: &str) {
        if let Some(out) = &mut self.out {
            out.push_str(text);
        }
    }

    fn print_char(&mut self, c: char) {
        if let Some(out) = &mut self.out {
            out.push(c);
        }
    }

    fn print_u64(&mut self, value: u64) {
        if let Some(out) = &mut self.out {
            out.push_str(&value.to_string());
        }
    }

    fn print_lower_hex(&mut self, value: u64) {
        if let Some(out) = &mut self.out {
            out.push_str(&format!("{value:x}"));
        }
    }

    fn print_quoted_escaped_chars(&mut self, quote: char, data: &str) {
        let out = match &mut self.out {
            Some(out) => out,
            None => return,
        };
        out.push(quote);
        for cp in data.chars() {
            if (quote == '\'' && cp == '"') || (quote == '"' && cp == '\'') {
                out.push(cp);
                continue;
            }
            match cp {
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\0' => out.push_str("\\0"),
                '"' if quote == '"' => out.push_str("\\\""),
                '"' => out.push('"'),
                '\'' if quote == '\'' => out.push_str("\\'"),
                '\'' => out.push('\''),
                other => {
                    let cpv = other as u32;
                    if cpv < 0x20 || cpv == 0x7f {
                        out.push_str(&format!("\\x{cpv:02x}"));
                    } else {
                        out.push(other);
                    }
                }
            }
        }
        out.push(quote);
    }
}

/// A demangled identifier, optionally punycode-encoded for non-ASCII names.
struct Ident {
    ascii: String,
    punycode: String,
}

impl Ident {
    fn new(ascii: String, punycode: String) -> Self {
        Ident { ascii, punycode }
    }

    fn is_empty(&self) -> bool {
        self.ascii.is_empty() && self.punycode.is_empty()
    }

    fn render(&self) -> String {
        if self.punycode.is_empty() {
            return self.ascii.clone();
        }

        match self.decode_punycode() {
            Some(decoded) => decoded.into_iter().filter_map(char::from_u32).collect(),
            None => {
                let mut builder = String::from("punycode{");
                if !self.ascii.is_empty() {
                    builder.push_str(&self.ascii);
                    builder.push('-');
                }
                builder.push_str(&self.punycode);
                builder.push('}');
                builder
            }
        }
    }

    /// Decodes the punycode payload used for non-ASCII identifiers. Returns `None` when the
    /// sequence is malformed so callers can fall back to the `punycode{...}` representation.
    fn decode_punycode(&self) -> Option<Vec<u32>> {
        if self.punycode.is_empty() {
            return None;
        }

        let mut output: Vec<u32> = self.ascii.chars().map(|c| c as u32).collect();

        let base: i32 = 36;
        let t_min: i32 = 1;
        let t_max: i32 = 26;
        let skew: i32 = 38;
        let mut damp: u64 = 700;
        let mut bias: i32 = 72;
        let mut i: u64 = 0;
        let mut n: u64 = 0x80;

        let bytes = self.punycode.as_bytes();
        let mut index = 0usize;

        while index < bytes.len() {
            let mut delta: u64 = 0;
            let mut w: u64 = 1;
            let mut k: i32 = base;
            loop {
                if index >= bytes.len() {
                    return None;
                }
                let c = bytes[index];
                index += 1;
                let digit: i32 = if c.is_ascii_lowercase() {
                    (c - b'a') as i32
                } else if c.is_ascii_digit() {
                    26 + (c - b'0') as i32
                } else {
                    return None;
                };

                let product = w.checked_mul(digit as u64)?;
                delta = delta.checked_add(product)?;

                let t = clamp_i32(k.wrapping_sub(bias), t_min, t_max);
                if digit < t {
                    break;
                }
                w = w.checked_mul((base - t) as u64)?;
                k = k.wrapping_add(base);
            }

            let out_len = output.len() as i32 + 1;
            i = i.checked_add(delta)?;
            n = n.checked_add(i / out_len as u64)?;
            i %= out_len as u64;

            if n > char::MAX as u64 || i > i32::MAX as u64 {
                return None;
            }
            let cp = n as u32;
            char::from_u32(cp)?;
            output.insert(i as usize, cp);
            i += 1;

            delta /= damp;
            damp = 2;
            delta += delta / out_len as u64;
            let mut k_adjust: i32 = 0;
            while delta > (((base - t_min) as u64) * (t_max as u64)) / 2 {
                delta /= (base - t_min) as u64;
                k_adjust = k_adjust.wrapping_add(base);
            }
            let numer = ((base - t_min + 1) as u64) * delta;
            let denom = delta + skew as u64;
            let quotient = (numer / denom) as i32;
            bias = k_adjust.wrapping_add(quotient);
        }

        Some(output)
    }
}

/// A run of hexadecimal digits parsed from the mangled string, decodable either as an integer
/// or as UTF-8 bytes.
struct HexNibbles<'a> {
    nibbles: &'a str,
}

impl<'a> HexNibbles<'a> {
    fn new(nibbles: &'a str) -> Self {
        HexNibbles { nibbles }
    }

    fn try_parse_uint(&self) -> Option<u64> {
        let trimmed = strip_leading_zeros(self.nibbles);
        if trimmed.len() > 16 {
            return None;
        }
        let mut value: u64 = 0;
        for c in trimmed.bytes() {
            value = (value << 4) | hex_value(c) as u64;
        }
        Some(value)
    }

    fn try_parse_str(&self) -> Option<String> {
        if self.nibbles.len() % 2 != 0 {
            return None;
        }
        let bytes_str = self.nibbles.as_bytes();
        let mut bytes = Vec::with_capacity(bytes_str.len() / 2);
        for chunk in bytes_str.chunks(2) {
            let hi = hex_value(chunk[0]);
            let lo = hex_value(chunk[1]);
            bytes.push((hi << 4) | lo);
        }
        String::from_utf8(bytes).ok()
    }
}

/// Maps the single-character primitive tags to their textual forms (e.g. `'a'` => `i8`).
/// The ordering matches the original implementation to ease diffing against upstream rustc-demangle.
fn basic_type(tag: u8) -> Option<&'static str> {
    match tag {
        b'a' => Some("i8"),
        b'b' => Some("bool"),
        b'c' => Some("char"),
        b'd' => Some("f64"),
        b'e' => Some("str"),
        b'f' => Some("f32"),
        b'h' => Some("u8"),
        b'i' => Some("isize"),
        b'j' => Some("usize"),
        b'l' => Some("i32"),
        b'm' => Some("u32"),
        b'n' => Some("i128"),
        b'o' => Some("u128"),
        b'p' => Some("_"),
        b's' => Some("i16"),
        b't' => Some("u16"),
        b'u' => Some("()"),
        b'v' => Some("..."),
        b'x' => Some("i64"),
        b'y' => Some("u64"),
        b'z' => Some("!"),
        _ => None,
    }
}

/// Utility used by the punycode decoder to mimic rustc's bias adjustment logic.
fn clamp_i32(value: i32, min: i32, max: i32) -> i32 {
    if value < min {
        min
    } else if value > max {
        max
    } else {
        value
    }
}

/// Parses a single hexadecimal nibble character. Only called with characters already
/// validated by [`is_hex_digit`].
fn hex_value(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => 10 + (c - b'a'),
        b'A'..=b'F' => 10 + (c - b'A'),
        _ => panic!("invalid hex digit: {}", c as char),
    }
}

fn strip_leading_zeros(value: &str) -> &str {
    value.trim_start_matches('0')
}

fn is_hex_digit(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

fn multiply_add_base62(value: u64, digit: u32) -> ParseResult<u64> {
    value.checked_mul(62).and_then(|v| v.checked_add(digit as u64)).ok_or_else(ParseError::invalid)
}

fn add_exact_u64(a: u64, b: u64) -> ParseResult<u64> {
    a.checked_add(b).ok_or_else(ParseError::invalid)
}

fn multiply_exact_i32(a: i32, b: i32) -> ParseResult<i32> {
    a.checked_mul(b).ok_or_else(ParseError::invalid)
}

fn add_exact_i32(a: i32, b: i32) -> ParseResult<i32> {
    a.checked_add(b).ok_or_else(ParseError::invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_demangle(mangled: &str, expected: &str) {
        let demangled = demangle(mangled);
        assert_eq!(demangled.as_deref(), Some(expected), "unexpected demangle result for {mangled}");
    }

    fn assert_demangle_alternate(mangled: &str, expected: &str) {
        let demangled = demangle_alternate(mangled);
        assert_eq!(demangled.as_deref(), Some(expected), "unexpected demangle result for {mangled}");
    }

    fn assert_const(payload: &str, display_value: &str, hashed_value: Option<&str>) {
        assert_demangle_alternate(&format!("_RIC0K{payload}E"), &format!("::<{display_value}>"));
        if let Some(hashed_value) = hashed_value {
            assert_demangle(&format!("_RIC0K{payload}E"), &format!("::<{hashed_value}>"));
        }
    }

    // ── basic paths ──────────────────────────────────────────────────────────

    #[test]
    fn simple_paths() {
        assert_demangle_alternate("_RNvCsL39EUhRVRM_5tests4main", "tests::main");
        assert_demangle_alternate("_RNvCsL39EUhRVRM_5tests6test_1", "tests::test_1");
        assert_demangle_alternate(
            "_RNvMCsL39EUhRVRM_5testsNtB2_10TestStruct8method_1",
            "<tests::tests::TestStruct>::method_1",
        );
        assert_demangle_alternate(
            "_RNvNtNtCsL39EUhRVRM_5tests5stuff6stuff26test_3",
            "tests::stuff::stuff2::test_3",
        );
    }

    #[test]
    fn empty_and_invalid_input() {
        assert_eq!(demangle(""), None);
        assert_eq!(demangle("not_rust"), None);
        assert_eq!(demangle("_R"), None);
    }

    #[test]
    fn crate_with_leading_digit() {
        assert_demangle_alternate("_RNvC6_123foo3bar", "123foo::bar");
    }

    #[test]
    fn crate_with_zero_disambiguator() {
        assert_demangle("_RC4f128", "f128");
        assert_demangle_alternate("_RC4f128", "f128");
    }

    #[test]
    fn utf8_idents() {
        let expected = "utf8_idents::\u{10e1}\u{10d0}\u{10ed}\u{10db}\u{10d4}\u{10da}\u{10d0}\u{10d3}_\u{10d2}\u{10d4}\u{10db}\u{10e0}\u{10d8}\u{10d4}\u{10da}\u{10d8}_\u{10e1}\u{10d0}\u{10d3}\u{10d8}\u{10da}\u{10d8}";
        assert_demangle_alternate(
            "_RNqCs4fqI2P2rA04_11utf8_identsu30____7hkackfecea1cbdathfdh9hlq6y",
            expected,
        );
    }

    #[test]
    fn closures() {
        assert_demangle_alternate(
            "_RNCNCNgCs6DXkGYLi8lr_2cc5spawn00B5_",
            "cc::spawn::{closure#0}::{closure#0}",
        );
        let expected = "<core::slice::Iter<u8> as core::iter::iterator::Iterator>::rposition::<core::slice::memchr::memrchr::{closure#1}>::{closure#0}";
        assert_demangle_alternate(
            "_RNCINkXs25_NgCsbmNqQUJIY6D_4core5sliceINyB9_4IterhENuNgNoBb_4iter8iterator8Iterator9rpositionNCNgNpB9_6memchr7memrchrs_0E0Bb_",
            expected,
        );
    }

    #[test]
    fn dyn_trait() {
        assert_demangle_alternate(
            "_RINbNbCskIICzLVDPPb_5alloc5alloc8box_freeDINbNiB4_5boxed5FnBoxuEp6OutputuEL_ECs1iopQbuBiw2_3std",
            "alloc::alloc::box_free::<dyn alloc::boxed::FnBox<(), Output = ()>>",
        );
    }

    #[test]
    fn pattern_types() {
        assert_demangle_alternate("_RMC0WmRm1_m9_", "<u32 is 1..=9>");
        assert_demangle_alternate("_RMC0WmORm1_m2_Rm5_m6_E", "<u32 is 1..=2 | 5..=6>");
        assert_eq!(demangle("_RMC0WmORm1_m2_Rm5_m6_"), None);
    }

    #[test]
    fn const_generics_preview() {
        assert_demangle_alternate(
            "_RMC0INtC8arrayvec8ArrayVechKj7b_E",
            "<arrayvec::ArrayVec<u8, 123>>",
        );
        assert_const("j7b_", "123", Some("123usize"));
    }

    #[test]
    fn min_const_generics() {
        assert_const("p", "_", None);
        assert_const("hb_", "11", Some("11u8"));
        assert_const("off00ff00ff00ff00ff_", "0xff00ff00ff00ff00ff", Some("0xff00ff00ff00ff00ffu128"));
        assert_const("s98_", "152", Some("152i16"));
        assert_const("anb_", "-11", Some("-11i8"));
        assert_const("b0_", "false", None);
        assert_const("b1_", "true", None);
        assert_const("c76_", "'v'", None);
        assert_const("c22_", "'\"'", None);
        assert_const("ca_", "'\\n'", None);
        assert_const("c2202_", "'\u{2202}'", None);
    }

    #[test]
    fn const_str() {
        assert_const("e616263_", "{*\"abc\"}", None);
        assert_const("e27_", "{*\"'\"}", None);
        assert_const("e090a_", "{*\"\\t\\n\"}", None);
    }

    #[test]
    fn const_ref_str() {
        assert_const("Re616263_", "\"abc\"", None);
        assert_const("Re27_", "\"'\"", None);
        assert_const("Re090a_", "\"\\t\\n\"", None);
    }

    #[test]
    fn const_ref() {
        assert_const("Rp", "{&_}", None);
        assert_const("Rh7b_", "{&123}", None);
        assert_const("Rb0_", "{&false}", None);
        assert_const("Rc58_", "{&'X'}", None);
        assert_const("RRRh0_", "{&&&0}", None);
        assert_const("RRRe_", "{&&\"\"}", None);
        assert_const("QAE", "{&mut []}", None);
    }

    #[test]
    fn const_array() {
        assert_const("AE", "{[]}", None);
        assert_const("Aj0_E", "{[0]}", None);
        assert_const("Ah1_h2_h3_E", "{[1, 2, 3]}", None);
        assert_const("ARe61_Re62_Re63_E", "{[\"a\", \"b\", \"c\"]}", None);
        assert_const("AAh1_h2_EAh3_h4_EE", "{[[1, 2], [3, 4]]}", None);
    }

    #[test]
    fn const_tuple() {
        assert_const("TE", "{()}", None);
        assert_const("Tj0_E", "{(0,)}", None);
        assert_const("Th1_b0_E", "{(1, false)}", None);
        assert_const("TRe616263_c78_RAh1_h2_h3_EE", "{(\"abc\", 'x', &[1, 2, 3])}", None);
    }

    #[test]
    fn const_adt() {
        assert_const("VNvINtNtC4core6option6OptionjE4NoneU", "{core::option::Option::<usize>::None}", None);
        assert_const(
            "VNvINtNtC4core6option6OptionjE4SomeTj0_E",
            "{core::option::Option::<usize>::Some(0)}",
            None,
        );
        assert_const(
            "VNtC3foo3BarS1sRe616263_2chc78_5sliceRAh1_h2_h3_EE",
            "{foo::Bar { s: \"abc\", ch: 'x', slice: &[1, 2, 3] }}",
            None,
        );
    }

    #[test]
    fn exponential_explosion() {
        let symbol = "_RMC0".to_string() + "TTTTTT" + "p" + "B8_E" + "B7_E" + "B6_E" + "B5_E" + "B4_E" + "B3_E";
        let expected = "<((((((_, _), (_, _)), ((_, _), (_, _))), (((_, _), (_, _)), ((_, _), (_, _)))), ((((_, _), (_, _)), ((_, _), (_, _))), (((_, _), (_, _)), ((_, _), (_, _))))), (((((_, _), (_, _)), ((_, _), (_, _))), (((_, _), (_, _)), ((_, _), (_, _)))), ((((_, _), (_, _)), ((_, _), (_, _))), (((_, _), (_, _)), ((_, _), (_, _))))))>";
        assert_demangle_alternate(&symbol, expected);
    }

    #[test]
    fn thinlto_suffix() {
        assert_demangle_alternate("_RC3foo.llvm.9D1C9369", "foo");
        assert_demangle_alternate("_RC3foo.llvm.9D1C9369@@16", "foo");
        assert_demangle_alternate("_RNvC9backtrace3foo.llvm.A5310EB9", "backtrace::foo");
    }

    #[test]
    fn extra_suffix() {
        assert_demangle_alternate(
            "_RNvNtNtNtNtCs92dm3009vxr_4rand4rngs7adapter9reseeding4fork23FORK_HANDLER_REGISTERED.0.0",
            "rand::rngs::adapter::reseeding::fork::FORK_HANDLER_REGISTERED.0.0",
        );
    }

    #[test]
    fn perf_tool_cases() {
        assert_demangle_alternate(
            "_RNvMsr_NtCs3ssYzQotkvD_3std4pathNtB5_7PathBuf3newCs15kBYyAo9fc_7mycrate",
            "<std::path::PathBuf>::new",
        );
        assert_demangle_alternate("_RNvCs15kBYyAo9fc_7mycrate7example", "mycrate::example");
        assert_demangle_alternate(
            "_RNvXCs15kBYyAo9fc_7mycrateNtB2_7ExampleNtB2_5Trait3foo",
            "<mycrate::Example as mycrate::Trait>::foo",
        );
        assert_demangle_alternate(
            "_RNCNvCsgStHSCytQ6I_7mycrate4main0B3_",
            "mycrate::main::{closure#0}",
        );
        assert_demangle_alternate(
            "_RNCNvCsgStHSCytQ6I_7mycrate4mains_0B3_",
            "mycrate::main::{closure#1}",
        );
        assert_demangle_alternate(
            "_RINvCsgStHSCytQ6I_7mycrate7examplelKj1_EB2_",
            "mycrate::example::<i32, 1>",
        );
        assert_demangle_alternate(
            "_RINvCs7qp2U7fqm6G_7mycrate7exampleFG0_RL1_hRL0_tEuEB2_",
            "mycrate::example::<for<'a, 'b> fn(&'a u8, &'b u16)>",
        );
        assert_demangle_alternate(
            "_RINvCs7qp2U7fqm6G_7mycrate7exampleKy12345678_EB2_",
            "mycrate::example::<305419896>",
        );
        assert_demangle_alternate(
            "_RNvNvMCsd9PVOYlP1UU_7mycrateINtB4_7ExamplepKpE3foo14EXAMPLE_STATIC",
            "<mycrate::Example<_, _>>::foo::EXAMPLE_STATIC",
        );
        assert_demangle_alternate(
            "_RINvCs7qp2U7fqm6G_7mycrate7exampleAtj8_EB2_",
            "mycrate::example::<[u16; 8]>",
        );
        assert_demangle_alternate(
            "_RINvCs7qp2U7fqm6G_7mycrate7exampleNtB2_7ExampleBw_EB2_",
            "mycrate::example::<mycrate::Example, mycrate::Example>",
        );
        assert_demangle_alternate(
            "_RNvNvNvCs7qp2U7fqm6G_7mycrate7EXAMPLE7___getit5___KEY",
            "mycrate::EXAMPLE::__getit::__KEY",
        );
    }

    // ── recursion limit ──────────────────────────────────────────────────────

    #[test]
    fn recursion_limit_leaks() {
        for (sym_leaf, expected_leaf) in [("p", "_"), ("Rp", "&_"), ("C1x", "x")] {
            let mut sym = String::from("_RIC0p");
            let mut expected = String::from("::<_");
            for _ in 0..(MAX_DEPTH * 2) {
                sym.push_str(sym_leaf);
                expected.push_str(", ");
                expected.push_str(expected_leaf);
            }
            sym.push('E');
            expected.push('>');
            assert_demangle_alternate(&sym, &expected);
        }
    }

    #[test]
    fn recursion_limit_backref_free_bypass() {
        let depth = 100_000;
        let mut sym = format!("_RIC{depth}");
        let backref_start = sym.len() - 2;
        for _ in 0..depth {
            sym.push('R');
        }
        sym.push('B');
        sym.push(std::char::from_digit(((backref_start - 1) % 36) as u32, 36).unwrap());
        sym.push('_');
        sym.push('E');

        let demangled = demangle(&sym).unwrap_or_else(|| RECURSION_LIMIT_MESSAGE.to_string());
        assert!(demangled.contains(RECURSION_LIMIT_MESSAGE));
    }
}
