//! Port of `ghidra.app.util.bin.format.golang.rtti.GoSymbolName`.

use std::fmt;
use std::sync::Arc;

use once_cell::sync::Lazy;
use regex::Regex;

use super::go_symbol_name_type::GoSymbolNameType;
use crate::program::model::listing::function::Function;
use crate::program::model::listing::Program;
use crate::program::model::symbol::{
    DefaultSymbolUtilities, Namespace, SourceType, SymbolType, SymbolUtilities,
};

/// Represents a Go symbol name.
///
/// Handles formats such as:
///
/// * `"package/domain.name/packagename.(*ReceiverTypeName).Functionname"`
/// * `"package/domain.name/packagename.(*ReceiverTypeName[genericinfo { method(); fieldname fieldtype; }]).Functionname"`
/// * `"package/domain.name/packagename.Functionname[genericinfo]"`
/// * `"type:.eq.[39]package/domain.name/packagename.Functionname"`
///
/// Java `record` components that may be `null` are `Option`s here:
///
/// * `symbol_name`: full name of the Go symbol (only `None` for [`from_package_path`](Self::from_package_path))
/// * `package_path`: portion of the symbol name that is the packagePath (path+packagename)
/// * `package_name`: portion of the symbol name that is the package name
/// * `receiver_string`: portion of the symbol name that is the receiver string (only found when
///   the receiver is in the form of `"(*typename)"`)
/// * `generic_info`: portion of the symbol name found inside of a generics `"[blah]"`
/// * `base_name`: symbol base name
/// * `prefix`: portion of the symbol name that was prepended to the main symbol info
/// * `symtype`: what kind of object this name is referencing
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GoSymbolName {
    symbol_name: Option<String>,
    package_path: Option<String>,
    package_name: Option<String>,
    receiver_string: Option<String>,
    generic_info: Option<String>,
    base_name: Option<String>,
    prefix: Option<String>,
    symtype: Option<GoSymbolNameType>,
}

static TYPE_PREFIX_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(type[:.]\.([a-z]+)\.)(.*?[^\x{00B7}]+)(\x{00B7}[0-9]+)?$").expect("valid regex")
});

static TYPE_PREFIX_SUB_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^type[:.]\.([a-z]+)\.$").expect("valid regex"));

const GO_SHAPE_PREFIX: &str = "go.shape.";

impl GoSymbolName {
    /// The canonical record constructor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        symbol_name: Option<String>,
        package_path: Option<String>,
        package_name: Option<String>,
        receiver_string: Option<String>,
        generic_info: Option<String>,
        base_name: Option<String>,
        prefix: Option<String>,
        symtype: Option<GoSymbolNameType>,
    ) -> Self {
        GoSymbolName {
            symbol_name,
            package_path,
            package_name,
            receiver_string,
            generic_info,
            base_name,
            prefix,
            symtype,
        }
    }

    /// The private `GoSymbolName(String)` constructor: an unparsed symbol name.
    fn unparsed(symbol_name: &str) -> Self {
        GoSymbolName::new(
            Some(symbol_name.to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(GoSymbolNameType::Unknown),
        )
    }

    /// Fixes the specified string if it contains any of the Go special symbolname characters:
    /// middle-dot (`U+00B7` -> `.`) and the weird slash (`U+2215` -> `/`).
    pub fn fix_golang_special_symbolname_chars(s: &str) -> String {
        if s.contains('\u{00B7}') || s.contains('\u{2215}') {
            s.replace('\u{00B7}', ".").replace('\u{2215}', "/")
        }
        else {
            s.to_string()
        }
    }

    /// `parseTypeName(String)`.
    pub fn parse_type_name(s: &str) -> GoSymbolName {
        Self::parse_type_name_in(s, None)
    }

    /// `parseTypeName(String, String)`: parses a Go type name, using `package_path` as the
    /// package path when the name only carries the (matching) trailing package name.
    pub fn parse_type_name_in(s: &str, package_path: Option<&str>) -> GoSymbolName {
        let end_of_prefix = index_of_any(s, "*[]0123456789.", 0, false).unwrap_or(0);
        let prefix_str = &s[..end_of_prefix];

        let mut s = &s[end_of_prefix..];
        let mut type_name_limit = index_of_any(s, " {([", 0, true).unwrap_or(s.len());

        // Java: s.lastIndexOf('/', typeNameLimit - 1)
        let package_path_end = s[..type_name_limit].rfind('/');
        let found_abs_pkg_path = package_path_end.is_some();
        let mut package_str = String::new();
        if let Some(ppe) = package_path_end {
            package_str.push_str(&s[..ppe + 1]);
            s = &s[ppe + 1..];
            type_name_limit -= ppe + 1;
        }

        // Java: s.lastIndexOf('.', typeNameLimit - 1)
        if let Some(type_name_start) = s[..type_name_limit].rfind('.') {
            package_str.push_str(&s[..type_name_start]);
            s = &s[type_name_start + 1..];
        }
        let type_name = s;

        if let Some(pp) = package_path {
            if !found_abs_pkg_path && !pp.is_empty() && pp.ends_with(package_str.as_str()) {
                package_str = pp.to_string();
            }
        }

        let sep = if !package_str.is_empty() && !package_str.ends_with('/') { "." } else { "" };
        let canonical_name = format!("{prefix_str}{package_str}{sep}{type_name}");
        let package_name = extract_package_name(&package_str);
        GoSymbolName::new(
            Some(canonical_name),
            Some(package_str),
            Some(package_name),
            None,
            None,
            Some(type_name.to_string()),
            Some(prefix_str.to_string()),
            Some(GoSymbolNameType::DataType),
        )
    }

    /// `parse(String)`: parses a symbol name; an unparseable name produces an "unparsed"
    /// instance (no package path) of type [`GoSymbolNameType::Unknown`].
    pub fn parse(s: &str) -> GoSymbolName {
        Self::parse_impl(s).unwrap_or_else(|| GoSymbolName::unparsed(s))
    }

    fn parse_impl(s: &str) -> Option<GoSymbolName> {
        if s.starts_with("go:") {
            // don't try to parse "go:...." symbols
            return None;
        }
        let orig_str = s;

        // Special handling for "type:" .eq. and .hash. prefixes
        if let Some(m) = TYPE_PREFIX_PATTERN.captures(s) {
            let prefix_str = m.get(1).map_or("", |g| g.as_str());
            let type_str = m.get(3).map_or("", |g| g.as_str());
            let type_sn = Self::parse_type_name_in(type_str, Some(""));
            return Some(GoSymbolName::new(
                Some(s.to_string()),
                type_sn.package_path,
                type_sn.package_name,
                None,
                None,
                Some(type_str.to_string()),
                Some(prefix_str.to_string()),
                Some(GoSymbolNameType::Func),
            ));
        }

        let fixed = Self::fix_golang_special_symbolname_chars(orig_str);
        let s = fixed.as_str();

        let pkg_info_limit = index_of_any(s, "([", 0, true).unwrap_or(s.len());

        // "d/p.(xxxx).yyyy.zzz" or "d/p.xxx" or "d/p.xxx[yyy].zzz" or "d/p.xxx.yyy.zzz"
        // Java: s.lastIndexOf('/', pkgInfoLimit) -- searches from pkgInfoLimit inclusive
        let search_end = (pkg_info_limit + 1).min(s.len());
        let last_slash = s[..search_end].rfind('/');
        let dot_search_start = last_slash.map_or(0, |i| i + 1);
        let pkg_dot = dot_search_start + s[dot_search_start..].find('.')?;
        let pkg_str = &s[..pkg_dot];

        let parts = split_nested_string_on(&s[pkg_dot + 1..], '.');
        let first_part = parts[0].as_str();
        let mut base_index = 0;

        let mut recv_str: Option<String> = None;
        let mut generics_str: Option<String> = None;
        if first_part.len() >= 2 && first_part.starts_with('(') && first_part.ends_with(')') {
            let (recv, generics) = split_generics(&first_part[1..first_part.len() - 1]);
            recv_str = Some(recv);
            generics_str = generics;
            base_index += 1;
        }

        let base_symbol_name = if base_index == 0 && parts.len() == 1 {
            // only consider generic string on normal func, not nested or lambdas
            let (name, generics) = split_generics(first_part);
            generics_str = generics;
            name
        }
        else {
            parts[base_index..].join(".")
        };
        let last_part = parts.last().map(String::as_str);
        let symtype = if parts.len() == base_index + 1 {
            GoSymbolNameType::from_name_with_dash_suffix(last_part.unwrap_or(""))
        }
        else {
            GoSymbolNameType::from_name_suffix(last_part)
        };

        Some(GoSymbolName::new(
            Some(orig_str.to_string()),
            Some(pkg_str.to_string()),
            Some(extract_package_name(pkg_str)),
            recv_str,
            generics_str,
            Some(base_symbol_name),
            None,
            Some(symtype),
        ))
    }

    /// Constructs a minimal `GoSymbolName` instance from the supplied values
    /// (`from(String, String)`).
    ///
    /// `package_name` does not handle package paths, eg. `"runtime"`; `symbol_name` is the full
    /// symbol name, eg. `"runtime.foo"`.
    pub fn from(package_name: &str, symbol_name: &str) -> GoSymbolName {
        GoSymbolName::new(
            Some(symbol_name.to_string()),
            Some(package_name.to_string()),
            Some(package_name.to_string()),
            None,
            None,
            None,
            None,
            None,
        )
    }

    /// Constructs a `GoSymbolName` instance that only has a package path / package name
    /// (`fromPackagePath(String)`).
    pub fn from_package_path(package_path: &str) -> GoSymbolName {
        let tmp = Self::parse(&format!("{package_path}.TMP"));
        GoSymbolName::new(None, tmp.package_path, tmp.package_name, None, None, None, None, None)
    }

    /// `isMethod()`.
    pub fn is_method(&self) -> bool {
        self.receiver_string.is_some()
    }

    /// `hasGenerics()`.
    pub fn has_generics(&self) -> bool {
        self.generic_info.is_some()
    }

    /// `isUnparsed()`.
    pub fn is_unparsed(&self) -> bool {
        self.package_path.is_none()
    }

    /// `isAnonType()`.
    pub fn is_anon_type(&self) -> bool {
        self.base_name.as_deref().is_some_and(|b| b.starts_with("struct { "))
    }

    /// The `symbolName` record component.
    pub fn symbol_name(&self) -> Option<&str> {
        self.symbol_name.as_deref()
    }

    /// The portion the symbol name that is the packagePath (path+packagename), or `None`
    /// (`getPackagePath()` / record accessor `packagePath()`).
    pub fn get_package_path(&self) -> Option<&str> {
        self.package_path.as_deref()
    }

    /// Portion of the symbol name that is the package name, or `None` (`getPackageName()`).
    pub fn get_package_name(&self) -> Option<&str> {
        self.package_name.as_deref()
    }

    /// `hasReceiver()`.
    pub fn has_receiver(&self) -> bool {
        self.receiver_string.is_some()
    }

    /// Portion of the symbol name that is the receiver string (with its generics, if any), or
    /// `None` (`getReceiverString()`).
    pub fn get_receiver_string(&self) -> Option<String> {
        self.get_receiver_string_with(self.generic_info.as_deref())
    }

    /// The receiver string with `modified_generics` substituted for its generics
    /// (`getReceiverString(String)`).
    pub fn get_receiver_string_with(&self, modified_generics: Option<&str>) -> Option<String> {
        let recv = self.receiver_string.as_ref()?;
        match modified_generics {
            Some(g) if !g.is_empty() => Some(format!("{recv}[{g}]")),
            _ => Some(recv.clone()),
        }
    }

    /// `getReceiverTypeName()`: the receiver string parsed as a type name.
    ///
    /// Java would throw a `NullPointerException` for a symbol without a receiver; this returns
    /// `None` instead.
    pub fn get_receiver_type_name(&self) -> Option<GoSymbolName> {
        let recv = self.get_receiver_string()?;
        Some(Self::parse_type_name_in(&recv, self.get_package_path()))
    }

    /// `getReceiverTypeName(String)`; `None` for a symbol without a receiver.
    pub fn get_receiver_type_name_with(&self, modified_generics: Option<&str>) -> Option<GoSymbolName> {
        let recv = self.get_receiver_string_with(modified_generics)?;
        Some(Self::parse_type_name_in(&recv, self.get_package_path()))
    }

    /// `getShapelessGenericsString()`: the generic parts with any `go.shape.` prefix removed,
    /// comma separated.
    pub fn get_shapeless_generics_string(&self) -> Option<String> {
        self.generic_info.as_ref()?;
        Some(
            self.get_generic_parts()
                .iter()
                .map(|s| s.strip_prefix(GO_SHAPE_PREFIX).unwrap_or(s).to_string())
                .collect::<Vec<_>>()
                .join(","),
        )
    }

    /// The receiver string without any generics (`getStrippedReceiverString()`).
    pub fn get_stripped_receiver_string(&self) -> Option<&str> {
        self.receiver_string.as_deref()
    }

    /// `getGenericsString()`.
    pub fn get_generics_string(&self) -> Option<&str> {
        self.generic_info.as_deref()
    }

    /// `getGenericParts()`: the generics string split on its top-level commas.
    ///
    /// Java throws a `NullPointerException` when there is no generics string; this returns an
    /// empty list.
    pub fn get_generic_parts(&self) -> Vec<String> {
        match &self.generic_info {
            Some(g) => split_nested_string_on(g, ','),
            None => Vec::new(),
        }
    }

    /// `getStrippedSymbolString()`: the symbol name with the generics info removed.
    pub fn get_stripped_symbol_string(&self) -> String {
        let Some(package_path) = &self.package_path
        else {
            // unparsed/unsupported symbol name format
            return self.as_string().to_string();
        };
        let base = self.base_name.as_deref().unwrap_or("null");
        if self.is_method() {
            format!(
                "{package_path}.({}).{base}",
                self.get_stripped_receiver_string().unwrap_or("null")
            )
        }
        else {
            format!("{package_path}.{base}")
        }
    }

    /// Returns a new `GoSymbolName` with the current instance's information (which should be
    /// without receiver info) re-interpreted to be a non-pointer receiver symbol
    /// (`asNonPtrReceiverSymbolName()`).
    ///
    /// Example, symbol `"package.name1.name2"` would normally be parsed as a non-receiver symbol
    /// with a complex basename of `"name1.name2"`, and this method will return a version that
    /// is equivalent of `"package.(name1).name2"`.
    pub fn as_non_ptr_receiver_symbol_name(&self) -> Option<GoSymbolName> {
        let base_name = self.base_name.as_deref()?;
        let dot_index = base_name.find('.')?;
        let new_recv = &base_name[..dot_index];
        let new_base = &base_name[dot_index + 1..];
        let new_type =
            if new_base.ends_with("-fm") { Some(GoSymbolNameType::MethodWrapper) } else { self.symtype };
        Some(GoSymbolName::new(
            self.symbol_name.clone(),
            self.package_path.clone(),
            self.package_name.clone(),
            Some(new_recv.to_string()),
            self.generic_info.clone(),
            Some(new_base.to_string()),
            self.prefix.clone(),
            new_type,
        ))
    }

    /// `isNonPtrReceiverCandidate()`: the base name contains exactly one `.`.
    pub fn is_non_ptr_receiver_candidate(&self) -> bool {
        match self.base_name.as_deref() {
            Some(b) => match b.find('.') {
                Some(first) => b.rfind('.') == Some(first),
                None => false,
            },
            None => false,
        }
    }

    /// The full name of the Go symbol (`asString()`); `""` where Java would return `null`
    /// (only an instance made by [`from_package_path`](Self::from_package_path)).
    pub fn as_string(&self) -> &str {
        self.symbol_name.as_deref().unwrap_or("")
    }

    /// `getBaseName()`.
    pub fn get_base_name(&self) -> Option<&str> {
        self.base_name.as_deref()
    }

    /// `getBaseTypeName()`: the prefix (if any) followed by the base name.
    pub fn get_base_type_name(&self) -> String {
        format!(
            "{}{}",
            self.prefix.as_deref().unwrap_or(""),
            self.base_name.as_deref().unwrap_or("null")
        )
    }

    /// `getNameType()`.
    pub fn get_name_type(&self) -> Option<GoSymbolNameType> {
        self.symtype
    }

    /// `getPrefix()`.
    pub fn get_prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }

    /// `getTypePrefixSubKeyword()`: the keyword of a `"type:.xxx."` prefix (eg. `"eq"`).
    pub fn get_type_prefix_sub_keyword(&self) -> Option<String> {
        TYPE_PREFIX_SUB_PATTERN
            .captures(self.prefix.as_deref().unwrap_or(""))
            .and_then(|m| m.get(1))
            .map(|g| g.as_str().to_string())
    }

    /// Returns the portion of the package path before the package name, eg. `"internal/sys"`
    /// would become `"internal/"` (`getTruncatedPackagePath()`); `None` if there is no path
    /// portion of the string.
    pub fn get_truncated_package_path(&self) -> Option<String> {
        match (&self.package_path, &self.package_name) {
            (Some(pp), Some(pn)) if pp.len() > pn.len() => Some(pp[..pp.len() - pn.len()].to_string()),
            _ => None,
        }
    }

    /// Returns a Ghidra namespace based on the Go package path, or the program's root namespace
    /// if no package path information is present (`getSymbolNamespace(Program)`).
    pub fn get_symbol_namespace(&self, program: &dyn Program) -> Option<Arc<dyn Namespace>> {
        let root_ns = program.get_global_namespace()?;
        if let Some(pp) = self.package_path.as_deref().filter(|pp| !pp.trim().is_empty()) {
            if let Some(mut symbol_table) = program.get_symbol_table() {
                if let Ok(ns) = symbol_table.get_or_create_name_space(root_ns.clone(), pp, SourceType::Imported) {
                    return Some(ns);
                }
                // ignore, fall thru
            }
        }
        Some(root_ns)
    }

    /// The matching Ghidra function (based on namespace and symbol name) (`getFunction(Program)`).
    pub fn get_function(&self, program: &dyn Program) -> Option<Arc<dyn Function>> {
        let ns = self.get_symbol_namespace(program)?;
        let sym = DefaultSymbolUtilities.get_unique_symbol_in_namespace(program, self.as_string(), Some(ns.as_ref()))?;
        if sym.get_symbol_type() == SymbolType::Function {
            sym.as_function()
        }
        else {
            None
        }
    }
}

impl fmt::Display for GoSymbolName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_string())
    }
}

/// Java `extractPackageName(String)`: the last path element of a package path.
fn extract_package_name(pkg_str: &str) -> String {
    match pkg_str.rfind('/') {
        Some(i) => pkg_str[i + 1..].to_string(),
        None => pkg_str.to_string(),
    }
}

/// Java `indexOfAny(String, String, int, boolean)`: the index of the first char at or after
/// `start` whose membership in `chars` equals `chars_match`.
fn index_of_any(s: &str, chars: &str, start: usize, chars_match: bool) -> Option<usize> {
    s.char_indices()
        .skip_while(|(i, _)| *i < start)
        .find(|(_, ch)| chars.contains(*ch) == chars_match)
        .map(|(i, _)| i)
}

/// Splits a string on occurrences of a specific char at the 'top' level of the string, ignoring
/// the split char when found inside of nested delimited sections of the string.
///
/// Nesting is delimited by `(`, `{`, `[` chars and their matching closing element. A string with
/// unbalanced nesting is returned unsplit.
fn split_nested_string_on(s: &str, split_char: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut nesting_stack: Vec<char> = Vec::new();
    let mut part_start = 0;
    for (i, ch) in s.char_indices() {
        match ch {
            '{' => nesting_stack.push('}'),
            '(' => nesting_stack.push(')'),
            '[' => nesting_stack.push(']'),
            '}' | ')' | ']' => {
                if nesting_stack.pop() != Some(ch) {
                    return vec![s.to_string()]; // failed to successfully split the string
                }
            }
            _ => {
                if ch == split_char && nesting_stack.is_empty() {
                    parts.push(s[part_start..i].to_string());
                    part_start = i + ch.len_utf8();
                }
            }
        }
    }
    parts.push(s[part_start..].to_string());
    parts
}

/// Java `splitGenerics(String)`: splits `"name[generics]"` into its name and generics parts.
pub(crate) fn split_generics(s: &str) -> (String, Option<String>) {
    match s.find('[') {
        Some(gen_start) if s.ends_with(']') => {
            (s[..gen_start].to_string(), Some(s[gen_start + 1..s.len() - 1].to_string()))
        }
        _ => (s.to_string(), None),
    }
}

#[cfg(test)]
mod tests {
    //! Port of `GoSymbolNameTest`.
    use super::*;

    fn s(v: &str) -> Option<&str> {
        Some(v)
    }

    #[test]
    fn test_parse() {
        let gsn = GoSymbolName::parse("internal/fmtsort.(*SortedMap).Len");
        assert_eq!(gsn.get_package_path(), s("internal/fmtsort"));
        assert_eq!(gsn.get_package_name(), s("fmtsort"));
        assert_eq!(gsn.get_receiver_string().as_deref(), s("*SortedMap"));

        let gsn = GoSymbolName::parse("runtime..inittask");
        assert_eq!(gsn.get_package_path(), s("runtime"));
        assert_eq!(gsn.get_package_name(), s("runtime"));
        assert_eq!(gsn.get_base_name(), s(".inittask"));
        assert_eq!(gsn.get_receiver_string(), None);
        assert_eq!(gsn.as_string(), "runtime..inittask");

        let gsn = GoSymbolName::parse("crypto/ecdsa.inverse[go.shape.*uint8]");
        assert_eq!(gsn.get_package_path(), s("crypto/ecdsa"));
        assert_eq!(gsn.get_package_name(), s("ecdsa"));
        assert_eq!(gsn.get_receiver_string(), None);

        let gsn = GoSymbolName::parse("time.parseRFC3339[go.shape.[]uint8]");
        assert_eq!(gsn.get_package_path(), s("time"));
        assert_eq!(gsn.get_package_name(), s("time"));
        assert_eq!(gsn.get_receiver_string(), None);
        assert_eq!(gsn.get_generics_string(), s("go.shape.[]uint8"));
        assert_eq!(gsn.get_base_name(), s("parseRFC3339"));
        assert_eq!(gsn.get_stripped_symbol_string(), "time.parseRFC3339");

        let gsn = GoSymbolName::parse("sync/atomic.(*Pointer[interface_{}]).Load");
        assert_eq!(gsn.get_package_path(), s("sync/atomic"));
        assert_eq!(gsn.get_package_name(), s("atomic"));
        assert_eq!(gsn.get_receiver_string().as_deref(), s("*Pointer[interface_{}]"));
        assert_eq!(gsn.get_stripped_symbol_string(), "sync/atomic.(*Pointer).Load");
        assert_eq!(gsn.get_generics_string(), s("interface_{}"));
        assert_eq!(gsn.get_generic_parts(), vec!["interface_{}"]);

        let gsn = GoSymbolName::parse(
            "slices.stableCmpFunc[go.shape.struct { Key reflect.Value; Value reflect.Value }]",
        );
        assert_eq!(gsn.get_package_path(), s("slices"));
        assert_eq!(gsn.get_package_name(), s("slices"));
        assert_eq!(gsn.get_base_name(), s("stableCmpFunc"));
        assert_eq!(gsn.get_receiver_string(), None);
        assert_eq!(gsn.get_generics_string(), s("go.shape.struct { Key reflect.Value; Value reflect.Value }"));
        assert_eq!(gsn.get_generic_parts().len(), 1);

        let gsn = GoSymbolName::parse(
            "main.(*genericstruct[go.shape.string,go.shape.int,go.shape.string]).bar_takes_genericstruct",
        );
        assert_eq!(gsn.get_package_path(), s("main"));
        assert_eq!(gsn.get_package_name(), s("main"));
        assert_eq!(
            gsn.get_receiver_string().as_deref(),
            s("*genericstruct[go.shape.string,go.shape.int,go.shape.string]")
        );
        assert_eq!(gsn.get_generics_string(), s("go.shape.string,go.shape.int,go.shape.string"));
        assert_eq!(gsn.get_generic_parts(), vec!["go.shape.string", "go.shape.int", "go.shape.string"]);

        let gensym1 = GoSymbolName::parse_type_name_in(&gsn.get_generic_parts()[0], gsn.get_package_name());
        assert_eq!(gensym1.get_package_name(), s("go.shape"));
        assert_eq!(gensym1.get_package_path(), s("go.shape"));
        assert_eq!(gensym1.get_base_name(), s("string"));

        let gsn = GoSymbolName::parse(
            "main.(*genericstruct[go.shape.interface_{_F();_FF(bool);_FFF(bool,_int)_},go.shape.int,go.shape.string]).bar_takes_genericstruct",
        );
        assert_eq!(gsn.get_package_path(), s("main"));
        assert_eq!(gsn.get_package_name(), s("main"));
        assert_eq!(
            gsn.get_receiver_string().as_deref(),
            s("*genericstruct[go.shape.interface_{_F();_FF(bool);_FFF(bool,_int)_},go.shape.int,go.shape.string]")
        );
        assert_eq!(
            gsn.get_generics_string(),
            s("go.shape.interface_{_F();_FF(bool);_FFF(bool,_int)_},go.shape.int,go.shape.string")
        );
        assert_eq!(
            gsn.get_generic_parts(),
            vec!["go.shape.interface_{_F();_FF(bool);_FFF(bool,_int)_}", "go.shape.int", "go.shape.string"]
        );
        assert_eq!(gsn.get_stripped_symbol_string(), "main.(*genericstruct).bar_takes_genericstruct");

        let rtn = gsn.get_receiver_type_name().unwrap();
        assert_eq!(rtn.get_package_path(), s("main"));
        assert_eq!(rtn.get_package_name(), s("main"));
        assert_eq!(
            rtn.as_string(),
            "*main.genericstruct[go.shape.interface_{_F();_FF(bool);_FFF(bool,_int)_},go.shape.int,go.shape.string]"
        );
    }

    #[test]
    fn test_package_path_with_dots() {
        let gsn = GoSymbolName::parse("vendor/golang.org/x/text/unicode/norm.(*reorderBuffer).compose");
        assert_eq!(gsn.get_package_path(), s("vendor/golang.org/x/text/unicode/norm"));
        assert_eq!(gsn.get_package_name(), s("norm"));
        assert_eq!(gsn.get_receiver_string().as_deref(), s("*reorderBuffer"));
        assert_eq!(gsn.get_base_name(), s("compose"));
    }

    #[test]
    fn test_typename_with_long_pp() {
        let gsn = GoSymbolName::parse(
            "type:.eq.github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/internal/base.Client[go.shape.struct { github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/internal/generated.internal *github.com/Azure/azure-sdk-for-go/sdk/azcore.Client; github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/internal/generated.endpoint string }]",
        );
        assert_eq!(gsn.get_package_path(), s("github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/internal/base"));
    }

    #[test]
    fn test_slashes_in_recv_generics_str() {
        let gsn = GoSymbolName::parse("sync/atomic.(*Pointer[net/http.response]).Store");
        assert_eq!(gsn.get_package_path(), s("sync/atomic"));
        assert_eq!(gsn.get_package_name(), s("atomic"));
        assert_eq!(gsn.get_receiver_string().as_deref(), s("*Pointer[net/http.response]"));
        assert_eq!(gsn.get_base_name(), s("Store"));
    }

    #[test]
    fn test_go_prefix() {
        let gsn = GoSymbolName::parse("go:(*struct_{_runtime.gList;_runtime.n_int32_}).runtime.empty");
        assert_eq!(gsn.get_package_path(), None);
        assert_eq!(gsn.get_package_name(), None);
        assert_eq!(gsn.get_receiver_string(), None);
        assert_eq!(gsn.get_stripped_symbol_string(), "go:(*struct_{_runtime.gList;_runtime.n_int32_}).runtime.empty");
        assert!(gsn.is_unparsed());
        assert_eq!(gsn.get_name_type(), Some(GoSymbolNameType::Unknown));
    }

    #[test]
    fn test_anon_func() {
        let gsn = GoSymbolName::parse("runtime.addOneOpenDeferFrame.func1");
        assert_eq!(gsn.get_package_path(), s("runtime"));
        assert_eq!(gsn.get_package_name(), s("runtime"));
        assert_eq!(gsn.get_base_name(), s("addOneOpenDeferFrame.func1"));
        assert_eq!(gsn.get_name_type(), Some(GoSymbolNameType::AnonFunc));
        assert_eq!(gsn.get_receiver_string(), None);
    }

    #[test]
    fn test_simple_generic() {
        let gsn = GoSymbolName::parse("internal/poll.somefunc[go.shape.bool]");
        assert_eq!(gsn.get_package_path(), s("internal/poll"));
        assert_eq!(gsn.get_package_name(), s("poll"));
        assert_eq!(gsn.get_base_name(), s("somefunc"));
        assert_eq!(gsn.get_receiver_string(), None);
        assert_eq!(gsn.get_generics_string(), s("go.shape.bool"));
        assert_eq!(gsn.get_name_type(), Some(GoSymbolNameType::Func));
        assert_eq!(gsn.get_shapeless_generics_string().as_deref(), s("bool"));

        let gsn = GoSymbolName::parse("internal/poll.somefunc[go.shape.bool].func5");
        assert_eq!(gsn.get_package_path(), s("internal/poll"));
        assert_eq!(gsn.get_package_name(), s("poll"));
        assert_eq!(gsn.get_base_name(), s("somefunc[go.shape.bool].func5"));
        assert_eq!(gsn.get_generics_string(), None);
        assert_eq!(gsn.get_receiver_string(), None);
        assert_eq!(gsn.get_name_type(), Some(GoSymbolNameType::AnonFunc));
    }

    #[test]
    fn test_recv_generic() {
        let sni = GoSymbolName::parse("sync/atomic.(*Pointer[os.dirInfo]).CompareAndSwap");
        assert_eq!(sni.get_package_path(), s("sync/atomic"));
        assert_eq!(sni.get_package_name(), s("atomic"));
        assert_eq!(sni.get_receiver_string().as_deref(), s("*Pointer[os.dirInfo]"));
        assert_eq!(sni.get_stripped_receiver_string(), s("*Pointer"));
        assert_eq!(sni.get_generics_string(), s("os.dirInfo"));
        assert_eq!(sni.get_generic_parts(), vec!["os.dirInfo"]);
        assert_eq!(sni.get_stripped_symbol_string(), "sync/atomic.(*Pointer).CompareAndSwap");

        let gsn = sni.get_receiver_type_name().unwrap();
        assert_eq!(gsn.get_package_path(), s("sync/atomic"));
        assert_eq!(gsn.get_package_name(), s("atomic"));
        assert_eq!(gsn.get_base_name(), s("Pointer[os.dirInfo]"));
        assert_eq!(gsn.get_prefix(), s("*"));
        assert_eq!(gsn.as_string(), "*sync/atomic.Pointer[os.dirInfo]");
    }

    #[test]
    fn test_nested_recv_strings() {
        let sni = GoSymbolName::parse("runtime.(*sweepLocked).sweep.(*mheap).freeSpan.func4");
        assert_eq!(sni.get_package_path(), s("runtime"));
        assert_eq!(sni.get_package_name(), s("runtime"));
        assert_eq!(sni.get_base_name(), s("sweep.(*mheap).freeSpan.func4"));
        assert_eq!(sni.get_receiver_string().as_deref(), s("*sweepLocked"));
        assert_eq!(sni.get_name_type(), Some(GoSymbolNameType::AnonFunc));

        let sni = GoSymbolName::parse("runtime.(*sweepLocked[genericinfo{ func() }]).sweep.(*mheap).freeSpan.func4");
        assert_eq!(sni.get_package_path(), s("runtime"));
        assert_eq!(sni.get_package_name(), s("runtime"));
        assert_eq!(sni.get_base_name(), s("sweep.(*mheap).freeSpan.func4"));
        assert_eq!(sni.get_receiver_string().as_deref(), s("*sweepLocked[genericinfo{ func() }]"));
        assert_eq!(sni.get_stripped_receiver_string(), s("*sweepLocked"));
        assert_eq!(sni.get_name_type(), Some(GoSymbolNameType::AnonFunc));
    }

    #[test]
    fn test_type_names() {
        let sni = GoSymbolName::parse_type_name_in("int", Some(""));
        assert_eq!(sni.get_package_name(), s(""));
        assert_eq!(sni.get_package_path(), s(""));
        assert_eq!(sni.get_base_name(), s("int"));
        assert_eq!(sni.as_string(), "int");
        assert_eq!(sni.get_prefix(), s(""));

        let sni = GoSymbolName::parse_type_name_in("plaintypename", Some("package1"));
        assert_eq!(sni.get_package_name(), s("package1"));
        assert_eq!(sni.get_package_path(), s("package1"));
        assert_eq!(sni.get_base_name(), s("plaintypename"));
        assert_eq!(sni.as_string(), "package1.plaintypename");
        assert_eq!(sni.get_prefix(), s(""));

        let sni = GoSymbolName::parse_type_name_in("*[][3][..]plaintypename", Some("package1"));
        assert_eq!(sni.get_package_name(), s("package1"));
        assert_eq!(sni.get_package_path(), s("package1"));
        assert_eq!(sni.get_base_name(), s("plaintypename"));
        assert_eq!(sni.as_string(), "*[][3][..]package1.plaintypename");
        assert_eq!(sni.get_prefix(), s("*[][3][..]"));

        let sni = GoSymbolName::parse_type_name_in("*atomic.Pointer[interface {}]", Some("sync/atomic"));
        assert_eq!(sni.get_package_name(), s("atomic"));
        assert_eq!(sni.get_package_path(), s("sync/atomic"));
        assert_eq!(sni.get_base_name(), s("Pointer[interface {}]"));
        assert_eq!(sni.as_string(), "*sync/atomic.Pointer[interface {}]");
        assert_eq!(sni.get_prefix(), s("*"));

        // mismatch package name
        let sni = GoSymbolName::parse_type_name_in("*atomic.Pointer[interface {}]", Some("sync/atomicx"));
        assert_eq!(sni.get_package_name(), s("atomic"));
        assert_eq!(sni.get_package_path(), s("atomic"));
        assert_eq!(sni.get_base_name(), s("Pointer[interface {}]"));
        assert_eq!(sni.as_string(), "*atomic.Pointer[interface {}]");
        assert_eq!(sni.get_prefix(), s("*"));

        let sni = GoSymbolName::parse_type_name_in("struct { runtime.gList; runtime.n int32 }", None);
        assert_eq!(sni.get_package_name(), s(""));
        assert_eq!(sni.get_package_path(), s(""));
        assert_eq!(sni.get_base_name(), s("struct { runtime.gList; runtime.n int32 }"));
        assert_eq!(sni.as_string(), "struct { runtime.gList; runtime.n int32 }");
        assert_eq!(sni.get_prefix(), s(""));
        assert!(sni.is_anon_type());

        let sni = GoSymbolName::parse_type_name_in("go.shape.interface { Foo() type }", None);
        assert_eq!(sni.get_package_name(), s("go.shape"));
        assert_eq!(sni.get_package_path(), s("go.shape"));
        assert_eq!(sni.get_base_name(), s("interface { Foo() type }"));
        assert_eq!(sni.as_string(), "go.shape.interface { Foo() type }");
        assert_eq!(sni.get_prefix(), s(""));

        let sni = GoSymbolName::parse_type_name_in("*[]runtime.ancestorInfo", None);
        assert_eq!(sni.get_package_name(), s("runtime"));
        assert_eq!(sni.get_package_path(), s("runtime"));
        assert_eq!(sni.get_base_name(), s("ancestorInfo"));
        assert_eq!(sni.as_string(), "*[]runtime.ancestorInfo");
        assert_eq!(sni.get_prefix(), s("*[]"));

        let sni =
            GoSymbolName::parse_type_name_in("*metadata.mdValue", Some("google.golang.org/grpc/internal/metadata"));
        assert_eq!(sni.get_package_name(), s("metadata"));
        assert_eq!(sni.get_package_path(), s("google.golang.org/grpc/internal/metadata"));
        assert_eq!(sni.get_base_name(), s("mdValue"));
        assert_eq!(sni.as_string(), "*google.golang.org/grpc/internal/metadata.mdValue");
        assert_eq!(sni.get_prefix(), s("*"));

        let sni = GoSymbolName::parse_type_name_in("*func(blah) blah", Some("package1"));
        assert_eq!(sni.get_package_name(), s("package1"));
        assert_eq!(sni.get_package_path(), s("package1"));
        assert_eq!(sni.get_base_name(), s("func(blah) blah"));
        assert_eq!(sni.as_string(), "*package1.func(blah) blah");
        assert_eq!(sni.get_prefix(), s("*"));

        let sni = GoSymbolName::parse_type_name_in("gopkg.in/struct { }", Some(""));
        assert_eq!(sni.get_package_name(), s(""));
        assert_eq!(sni.get_package_path(), s("gopkg.in/"));
        assert_eq!(sni.get_base_name(), s("struct { }"));
        assert_eq!(sni.as_string(), "gopkg.in/struct { }");
        assert_eq!(sni.get_prefix(), s(""));

        let anon = "struct { ProjectID string \"json:\\\"project_id\\\"\"; Project string \"json:\\\"project\\\"\" }";
        let sni = GoSymbolName::parse_type_name_in(&format!("*{anon}"), Some(""));
        assert_eq!(sni.get_package_name(), s(""));
        assert_eq!(sni.get_package_path(), s(""));
        assert_eq!(sni.get_base_name(), s(anon));
        assert_eq!(sni.as_string(), format!("*{anon}"));
        assert_eq!(sni.get_prefix(), s("*"));
    }

    #[test]
    fn test_type_name_package() {
        let sni = GoSymbolName::parse_type_name_in("github.com/restic/restic/internal/debug.eofDetectRoundTripper", None);
        assert_eq!(sni.get_package_name(), s("debug"));
        assert_eq!(sni.get_package_path(), s("github.com/restic/restic/internal/debug"));
        assert_eq!(sni.get_base_name(), s("eofDetectRoundTripper"));
        assert_eq!(sni.as_string(), "github.com/restic/restic/internal/debug.eofDetectRoundTripper");
        assert_eq!(sni.get_prefix(), s(""));
        assert_eq!(sni.get_truncated_package_path().as_deref(), s("github.com/restic/restic/internal/"));
    }

    #[test]
    fn test_non_ptr_receiver() {
        let sni = GoSymbolName::parse("runtime.sometype.SomeMethod");
        assert_eq!(sni.get_package_path(), s("runtime"));
        assert_eq!(sni.get_package_name(), s("runtime"));
        assert_eq!(sni.get_base_name(), s("sometype.SomeMethod"));
        assert_eq!(sni.get_receiver_string(), None);
        assert_eq!(sni.get_name_type(), Some(GoSymbolNameType::Unknown));
        assert!(sni.is_non_ptr_receiver_candidate());

        let sni = sni.as_non_ptr_receiver_symbol_name().unwrap();
        assert_eq!(sni.get_package_path(), s("runtime"));
        assert_eq!(sni.get_package_name(), s("runtime"));
        assert_eq!(sni.get_base_name(), s("SomeMethod"));
        assert_eq!(sni.get_receiver_string().as_deref(), s("sometype"));
    }

    #[test]
    fn test_parse_type_symbol() {
        let sni = GoSymbolName::parse("type:.eq.runtime/internal/atomic.Int64");
        assert_eq!(sni.get_package_path(), s("runtime/internal/atomic"));
        assert_eq!(sni.get_package_name(), s("atomic"));
        assert_eq!(sni.get_receiver_string(), None);
        assert_eq!(sni.get_prefix(), s("type:.eq."));
        assert_eq!(sni.get_type_prefix_sub_keyword().as_deref(), s("eq"));

        let sni = GoSymbolName::parse("type:.eq.struct_{_runtime.gList;_runtime.n_int32_}");
        assert_eq!(sni.get_package_path(), s(""));
        assert_eq!(sni.get_package_name(), s(""));
        assert_eq!(sni.get_receiver_string(), None);
        assert_eq!(sni.get_prefix(), s("type:.eq."));

        let sni = GoSymbolName::parse("type:.eq.sync/atomic.Pointer[interface_{}]");
        assert_eq!(sni.get_package_path(), s("sync/atomic"));
        assert_eq!(sni.get_package_name(), s("atomic"));
        assert_eq!(sni.get_receiver_string(), None);
        assert_eq!(sni.get_prefix(), s("type:.eq."));

        let sni = GoSymbolName::parse("type:.eq.[...]internal/cpu.option");
        assert_eq!(sni.get_package_path(), s("internal/cpu"));
        assert_eq!(sni.get_package_name(), s("cpu"));
        assert_eq!(sni.get_base_name(), s("[...]internal/cpu.option"));
        assert_eq!(sni.get_receiver_string(), None);
        assert_eq!(sni.get_prefix(), s("type:.eq."));

        let sni = GoSymbolName::parse("type:.eq.[39]vendor/golang.org/x/sys/cpu.option");
        assert_eq!(sni.get_package_path(), s("vendor/golang.org/x/sys/cpu"));
        assert_eq!(sni.get_package_name(), s("cpu"));
        assert_eq!(sni.get_base_name(), s("[39]vendor/golang.org/x/sys/cpu.option"));
        assert_eq!(sni.get_receiver_string(), None);
        assert_eq!(sni.get_prefix(), s("type:.eq."));
    }

    #[test]
    fn test_special_chars_and_factories() {
        assert_eq!(GoSymbolName::fix_golang_special_symbolname_chars("a\u{00B7}b\u{2215}c"), "a.b/c");
        let sni = GoSymbolName::parse("runtime\u{00B7}foo");
        assert_eq!(sni.get_package_path(), s("runtime"));
        assert_eq!(sni.get_base_name(), s("foo"));
        // the original (unfixed) string is kept as the symbol name
        assert_eq!(sni.as_string(), "runtime\u{00B7}foo");

        let pp = GoSymbolName::from_package_path("github.com/foo/bar");
        assert_eq!(pp.get_package_path(), s("github.com/foo/bar"));
        assert_eq!(pp.get_package_name(), s("bar"));
        assert_eq!(pp.symbol_name(), None);

        let f = GoSymbolName::from("runtime", "runtime.foo");
        assert_eq!(f.as_string(), "runtime.foo");
        assert_eq!(f.get_package_path(), s("runtime"));
        assert_eq!(f.get_name_type(), None);

        let mw = GoSymbolName::parse("pkg.typ.Meth-fm");
        assert_eq!(mw.as_non_ptr_receiver_symbol_name().unwrap().get_name_type(), Some(GoSymbolNameType::MethodWrapper));
        assert_eq!(GoSymbolName::parse("main.foo").to_string(), "main.foo");
    }

    #[test]
    fn test_split_helpers() {
        assert_eq!(split_generics("foo[bar]"), ("foo".to_string(), Some("bar".to_string())));
        assert_eq!(split_generics("foo[]"), ("foo".to_string(), Some(String::new())));
        assert_eq!(split_generics("foo[bar"), ("foo[bar".to_string(), None));
        assert_eq!(split_nested_string_on("a.(b.c).d", '.'), vec!["a", "(b.c)", "d"]);
        assert_eq!(split_nested_string_on("a.(b.c.d", '.'), vec!["a", "(b.c.d"]);
        assert_eq!(split_nested_string_on("a.b).c", '.'), vec!["a.b).c"]);
    }
}
