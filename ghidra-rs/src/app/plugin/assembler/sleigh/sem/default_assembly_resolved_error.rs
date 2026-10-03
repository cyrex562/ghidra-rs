//! Mirrors `ghidra.app.plugin.assembler.sleigh.sem.DefaultAssemblyResolvedError`.

use std::cmp::Ordering;
use std::rc::Rc;

use super::{AbstractAssemblyResolution, AssemblyResolution, AssemblyResolvedError};

/// An [`AssemblyResolution`] indicating the occurrence of a (usually semantic) error.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.sem.DefaultAssemblyResolvedError`. Unlike
/// [`DefaultAssemblyResolvedBackfill`](super::DefaultAssemblyResolvedBackfill), which was cut to a
/// trait because every one of its meaningful methods needs the not-yet-ported
/// `AbstractAssemblyResolutionFactory` builder machinery, this class's two behaviorally
/// significant overrides -- `withRight` and `parent` -- each just build a *new* instance of this
/// same class from already-known fields (`error`, `description`, `children`), which this port can
/// do directly without that machinery. It's therefore ported as a concrete, constructible struct:
/// the first genuine (non-mock) implementor of [`AssemblyResolution`] in this crate.
///
/// Java's `protected final` fields (`error`, plus the inherited `description`/`children`/`right`)
/// are private here, exposed only through the trait accessors, since nothing outside this module
/// needs direct field access (unlike Java, where same-package/subclass code could reach in).
///
/// `children` and `right` are stored as `Rc<dyn AssemblyResolution>` rather than
/// `Box<dyn AssemblyResolution>`: Java shares the same child/right-sibling *references* across
/// `withRight`/`parent`'s freshly-built instances (via the builder's `children(children)` /
/// `right(right)` calls, which just copy the reference, not the data), but `AssemblyResolution`
/// deliberately doesn't require `Clone` (no way to duplicate a `Box<dyn AssemblyResolution>`).
/// `Rc` gives the same cheap-reference-sharing behavior; [`AssemblyResolution`]'s blanket
/// `impl for Rc<dyn AssemblyResolution>` (see that trait's own doc comment) lets an `Rc`-held
/// child still be handed out as an ordinary, independently-owned `Box<dyn AssemblyResolution>`
/// wherever the trait's `get_children`/`get_right` signatures require one.
///
/// Java's protected constructor (taking a factory, for builder-only construction) becomes
/// [`new`](Self::new), a plain public constructor -- there being no builder to gate construction
/// through here.
#[derive(Clone, Debug)]
pub struct DefaultAssemblyResolvedError {
    description: String,
    children: Vec<Rc<dyn AssemblyResolution>>,
    right: Option<Rc<dyn AssemblyResolution>>,
    error: String,
}

impl DefaultAssemblyResolvedError {
    /// Construct a new error record.
    ///
    /// Mirrors the protected `DefaultAssemblyResolvedError(AbstractAssemblyResolutionFactory<?,?>,
    /// String, List<? extends AssemblyResolution>, AssemblyResolution, String)` constructor, minus
    /// the unused-here `factory` parameter.
    pub fn new(
        description: impl Into<String>,
        error: impl Into<String>,
        children: Vec<Rc<dyn AssemblyResolution>>,
        right: Option<Rc<dyn AssemblyResolution>>,
    ) -> Self {
        Self { description: description.into(), children, right, error: error.into() }
    }

    /// Construct a new error record with no children and no right sibling.
    ///
    /// A convenience for the common case; not present in the Java source (which always goes
    /// through the builder, defaulting unset fields to empty/`null`).
    pub fn leaf(description: impl Into<String>, error: impl Into<String>) -> Self {
        Self::new(description, error, Vec::new(), None)
    }

    /// Mirrors Java's `String.hashCode()`: `s[0]*31^(n-1) + s[1]*31^(n-2) + ... + s[n-1]`,
    /// computed over UTF-16 code units (as Java `char`s are) with wrapping 32-bit arithmetic.
    fn java_string_hash_code(s: &str) -> i32 {
        let mut hash: i32 = 0;
        for unit in s.encode_utf16() {
            hash = hash.wrapping_mul(31).wrapping_add(unit as i32);
        }
        hash
    }

    /// Mirrors `DefaultAssemblyResolvedError.equals(Object obj)` more literally than the
    /// idiomatic [`PartialEq`] impl above it, to faithfully reproduce a genuine bug in the
    /// original: its body is
    ///
    /// ```java
    /// if (this == obj) return true;
    /// if (this.getClass() != obj.getClass()) return false;
    /// DefaultAssemblyResolvedError that = (DefaultAssemblyResolvedError) obj;
    /// if (!this.error.equals(that.error)) return false;
    /// return true;
    /// ```
    ///
    /// which calls `obj.getClass()` without a preceding null check, so `equals(null)` throws
    /// `NullPointerException` instead of returning `false` as the `Object.equals` contract
    /// requires. Passing `None` here panics for the same reason, matching that same defect.
    pub fn equals_object(&self, obj: Option<&DefaultAssemblyResolvedError>) -> bool {
        let that = obj.expect(
            "DefaultAssemblyResolvedError.equals(Object) NPEs on a null `obj` in the real Java \
             source (it calls obj.getClass() without a null check first) -- reproduced faithfully",
        );
        self.error == that.error
    }
}

/// Mirrors `DefaultAssemblyResolvedError.equals(Object)`'s comparison itself: by `error` alone,
/// ignoring `description`/`children`/`right` even though they can differ between two records that
/// this considers equal. This is a real, faithful quirk of the original -- not "fixed" here to
/// also compare the other fields.
impl PartialEq for DefaultAssemblyResolvedError {
    fn eq(&self, other: &Self) -> bool {
        self.error == other.error
    }
}

impl std::fmt::Display for DefaultAssemblyResolvedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Mirrors `AbstractAssemblyResolution.toString()`, which is exactly `toString("")`.
        write!(f, "{}", self.to_string_indented_default(""))
    }
}

impl AssemblyResolution for DefaultAssemblyResolvedError {
    fn get_description(&self) -> String {
        self.description.clone()
    }

    fn get_children(&self) -> Vec<Box<dyn AssemblyResolution>> {
        self.children.iter().map(|c| Box::new(c.clone()) as Box<dyn AssemblyResolution>).collect()
    }

    fn has_children(&self) -> bool {
        !self.children.is_empty()
    }

    fn get_right(&self) -> Option<Box<dyn AssemblyResolution>> {
        self.right.as_ref().map(|r| Box::new(r.clone()) as Box<dyn AssemblyResolution>)
    }

    /// Mirrors `DefaultAssemblyResolvedError.lineToString()`: `error + " (" + description + ")"`.
    fn line_to_string(&self) -> String {
        format!("{} ({})", self.error, self.description)
    }

    fn is_backfill(&self) -> bool {
        false
    }

    fn is_error(&self) -> bool {
        true
    }

    /// Mirrors `DefaultAssemblyResolvedError.shift(int)`, which unconditionally `return
    /// this;` -- an error's encoding position is meaningless, so shifting is a no-op. Since Rust
    /// can't return the literal same boxed instance from a `&self` method, this returns a full
    /// (cheap: `Rc`-backed) duplicate instead, which is behaviorally equivalent given this type is
    /// otherwise treated as an immutable value throughout.
    fn shift(&self, _amt: i32) -> Box<dyn AssemblyResolution> {
        Box::new(self.clone())
    }

    /// Mirrors `DefaultAssemblyResolvedError.parent(String, int)`:
    ///
    /// ```java
    /// return factory.newErrorBuilder()
    ///         .error(error)
    ///         .description(description)
    ///         .children(getAllRight())
    ///         .build();
    /// ```
    ///
    /// Note `op_count` (Java's `opCount`) is read nowhere in that body -- a real, faithful quirk
    /// (not a bug exactly, just an unused parameter of the shared `parent(String, int)` shape that
    /// this particular override has no use for) reproduced here rather than silently dropped from
    /// the signature.
    fn parent(&self, description: &str, _op_count: i32) -> Box<dyn AssemblyResolution> {
        let children: Vec<Rc<dyn AssemblyResolution>> =
            self.get_all_right().into_iter().map(Rc::from).collect();
        Box::new(DefaultAssemblyResolvedError {
            description: description.to_string(),
            children,
            right: None,
            error: self.error.clone(),
        })
    }

    /// Mirrors `AbstractAssemblyResolution.collectAllRight(Collection)`.
    fn collect_all_right(&self, into: &mut Vec<Box<dyn AssemblyResolution>>) {
        into.push(Box::new(self.clone()));
        if let Some(right) = &self.right {
            right.collect_all_right(into);
        }
    }

    fn to_string_indented(&self, indent: &str) -> String {
        self.to_string_indented_default(indent)
    }

    /// Mirrors `AbstractAssemblyResolution.compareTo(AssemblyResolution)`:
    /// `this.toString().compareTo(that.toString())` -- annotated `// LAZY` in the real Ghidra
    /// source. Faithfully reproduced including that laziness: since `equals` above compares only
    /// `error`, while `toString()`/`compareTo` factor in `description` (and children) too, two
    /// records Java's `equals` would call equal can still compare unequal here, exactly as in the
    /// original.
    fn compare_to(&self, other: &dyn AssemblyResolution) -> Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

impl AssemblyResolvedError for DefaultAssemblyResolvedError {
    fn get_error(&self) -> String {
        self.error.clone()
    }
}

impl AbstractAssemblyResolution for DefaultAssemblyResolvedError {
    /// Mirrors `DefaultAssemblyResolvedError.computeHash()`: `error.hashCode()`.
    fn compute_hash(&self) -> i32 {
        Self::java_string_hash_code(&self.error)
    }

    /// Mirrors `DefaultAssemblyResolvedError.withRight(AssemblyResolution)`:
    ///
    /// ```java
    /// return factory.newErrorBuilder()
    ///         .error(error)
    ///         .description(description)
    ///         .children(children)
    ///         .right(right)
    ///         .build();
    /// ```
    fn with_right(&self, right: Option<Box<dyn AssemblyResolution>>) -> Box<dyn AssemblyResolution> {
        Box::new(DefaultAssemblyResolvedError {
            description: self.description.clone(),
            children: self.children.clone(),
            right: right.map(Rc::from),
            error: self.error.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_error_and_description_round_trip() {
        let err = DefaultAssemblyResolvedError::leaf("while resolving foo", "unknown symbol");
        assert_eq!(err.get_error(), "unknown symbol");
        assert_eq!(err.get_description(), "while resolving foo");
    }

    #[test]
    fn is_error_true_is_backfill_false() {
        let err = DefaultAssemblyResolvedError::leaf("d", "e");
        assert!(err.is_error());
        assert!(!err.is_backfill());
    }

    #[test]
    fn line_to_string_matches_java_format() {
        let err = DefaultAssemblyResolvedError::leaf("operand 0", "bad register");
        assert_eq!(err.line_to_string(), "bad register (operand 0)");
    }

    #[test]
    fn display_matches_line_to_string_when_childless() {
        let err = DefaultAssemblyResolvedError::leaf("d", "e");
        assert_eq!(err.to_string(), err.line_to_string());
    }

    #[test]
    fn display_appends_indented_children() {
        let child: Rc<dyn AssemblyResolution> =
            Rc::new(DefaultAssemblyResolvedError::leaf("child desc", "child err"));
        let parent = DefaultAssemblyResolvedError::new("parent desc", "parent err", vec![child], None);
        assert_eq!(parent.to_string(), "parent err (parent desc):\n  child err (child desc)");
    }

    #[test]
    fn has_children_reflects_child_count() {
        let leaf = DefaultAssemblyResolvedError::leaf("d", "e");
        assert!(!leaf.has_children());

        let child: Rc<dyn AssemblyResolution> = Rc::new(leaf.clone());
        let parent = DefaultAssemblyResolvedError::new("d2", "e2", vec![child], None);
        assert!(parent.has_children());
    }

    #[test]
    fn shift_returns_an_equivalent_unchanged_record() {
        // Mirrors DefaultAssemblyResolvedError.shift(int), which unconditionally `return this;`.
        let err = DefaultAssemblyResolvedError::leaf("d", "e");
        let shifted = err.shift(1234);
        assert_eq!(shifted.get_description(), "d");
        assert_eq!(shifted.line_to_string(), err.line_to_string());
        assert!(shifted.is_error());
    }

    #[test]
    fn with_right_attaches_sibling_and_preserves_error_and_description() {
        let err = DefaultAssemblyResolvedError::leaf("d", "e");
        let sibling: Box<dyn AssemblyResolution> =
            Box::new(DefaultAssemblyResolvedError::leaf("sib desc", "sib err"));

        let with_sibling = AbstractAssemblyResolution::with_right(&err, Some(sibling));

        assert_eq!(with_sibling.get_description(), "d");
        assert_eq!(with_sibling.line_to_string(), "e (d)");
        let right = with_sibling.get_right().expect("right sibling should be attached");
        assert_eq!(right.get_description(), "sib desc");
    }

    #[test]
    fn without_right_detaches_sibling() {
        let sibling: Rc<dyn AssemblyResolution> =
            Rc::new(DefaultAssemblyResolvedError::leaf("sib", "sib err"));
        let err = DefaultAssemblyResolvedError::new("d", "e", Vec::new(), Some(sibling));
        assert!(err.get_right().is_some());

        let detached = AbstractAssemblyResolution::without_right(&err);
        assert!(detached.get_right().is_none());
    }

    #[test]
    fn parent_ignores_op_count_and_collects_right_chain_as_children() {
        // Mirrors DefaultAssemblyResolvedError.parent(String, int): `opCount` is read nowhere in
        // the real Java body, so two calls differing only in that argument must be identical.
        let tail: Rc<dyn AssemblyResolution> =
            Rc::new(DefaultAssemblyResolvedError::leaf("tail", "tail err"));
        let head = DefaultAssemblyResolvedError::new("head", "head err", Vec::new(), Some(tail));

        let parent_a = head.parent("new parent", 0);
        let parent_b = head.parent("new parent", 99);

        assert_eq!(parent_a.get_description(), parent_b.get_description());
        assert_eq!(parent_a.line_to_string(), parent_b.line_to_string());
        assert_eq!(parent_a.get_description(), "new parent");
        // getAllRight() collects `head` itself, then its right sibling `tail`.
        assert_eq!(parent_a.get_children().len(), 2);
        assert_eq!(parent_a.get_children()[0].get_description(), "head");
        assert_eq!(parent_a.get_children()[1].get_description(), "tail");
        // The Java builder never sets `right` for the parent, so it has none.
        assert!(parent_a.get_right().is_none());
    }

    #[test]
    fn compute_hash_matches_java_string_hash_code() {
        // "" hashes to 0; "a" to 97; "ab" to 97*31 + 98 = 3105; both well-known reference values.
        assert_eq!(DefaultAssemblyResolvedError::java_string_hash_code(""), 0);
        assert_eq!(DefaultAssemblyResolvedError::java_string_hash_code("a"), 97);
        assert_eq!(DefaultAssemblyResolvedError::java_string_hash_code("ab"), 3105);
        assert_eq!(DefaultAssemblyResolvedError::java_string_hash_code("Hello"), 69609650);

        let err = DefaultAssemblyResolvedError::leaf("ignored", "Hello");
        assert_eq!(err.compute_hash(), 69609650);
        assert_eq!(err.hash_code(), err.compute_hash());
    }

    #[test]
    fn equals_object_compares_error_field_only() {
        // Faithful quirk: DefaultAssemblyResolvedError.equals(Object) only ever inspects `error`,
        // so two records with different descriptions still compare equal.
        let a = DefaultAssemblyResolvedError::leaf("desc A", "same error");
        let b = DefaultAssemblyResolvedError::leaf("desc B", "same error");
        assert!(a.equals_object(Some(&b)));
        assert_eq!(a, b); // idiomatic `PartialEq` mirrors the same quirk.

        let c = DefaultAssemblyResolvedError::leaf("desc A", "different error");
        assert!(!a.equals_object(Some(&c)));
        assert_ne!(a, c);
    }

    #[test]
    fn equals_object_panics_on_null_reproducing_java_npe_bug() {
        // DefaultAssemblyResolvedError.equals(Object obj) calls `obj.getClass()` before any null
        // check, so `equals(null)` throws NullPointerException in the real Java source instead of
        // returning `false` as the `Object.equals` contract requires. Scoping `catch_unwind`
        // tightly around just this one call (rather than trusting a loose `#[should_panic]` on a
        // larger test body) verifies the panic happens at exactly this call, not elsewhere.
        let a = DefaultAssemblyResolvedError::leaf("d", "e");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| a.equals_object(None)));
        assert!(result.is_err(), "equals_object(None) must panic, mirroring Java's NullPointerException");
    }

    #[test]
    fn compare_to_is_lazily_toString_based_and_can_disagree_with_equals() {
        // Faithful quirk: AbstractAssemblyResolution.compareTo is `// LAZY` toString-comparison,
        // inconsistent with DefaultAssemblyResolvedError's own error-only `equals`. Two records
        // with the same `error` but different `description` are `equals`-equal yet compare
        // unequal via `compare_to`.
        let a = DefaultAssemblyResolvedError::leaf("desc A", "same error");
        let b = DefaultAssemblyResolvedError::leaf("desc B", "same error");
        assert_eq!(a, b);
        assert_ne!(a.compare_to(&b), Ordering::Equal);

        let c = DefaultAssemblyResolvedError::leaf("desc A", "same error");
        assert_eq!(a.compare_to(&c), Ordering::Equal);
    }

    #[test]
    fn collect_all_right_walks_the_right_chain() {
        let tail: Rc<dyn AssemblyResolution> =
            Rc::new(DefaultAssemblyResolvedError::leaf("tail", "tail err"));
        let head = DefaultAssemblyResolvedError::new("head", "head err", Vec::new(), Some(tail));

        let all = head.get_all_right();
        let descs: Vec<String> = all.iter().map(|r| r.get_description()).collect();
        assert_eq!(descs, vec!["head".to_string(), "tail".to_string()]);
    }

    #[test]
    fn as_resolved_patterns_and_as_backfill_are_none() {
        // This class represents only errors, never patterns or backfills.
        let err = DefaultAssemblyResolvedError::leaf("d", "e");
        let dyn_err: &dyn AssemblyResolution = &err;
        assert!(dyn_err.as_resolved_patterns().is_none());
        assert!(dyn_err.as_backfill().is_none());
    }

    #[test]
    fn trait_object_is_usable_as_assembly_resolution() {
        let err: Box<dyn AssemblyResolution> =
            Box::new(DefaultAssemblyResolvedError::leaf("d", "e"));
        assert!(err.is_error());
        assert_eq!(err.get_description(), "d");
    }
}
