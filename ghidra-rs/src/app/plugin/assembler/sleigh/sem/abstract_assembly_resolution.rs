use super::AssemblyResolution;

/// The common behavior shared by every concrete kind of assembly resolution record (a
/// successfully resolved pattern, a backfill, or an error).
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyResolution`, the abstract base
/// class of `DefaultAssemblyResolvedPatterns`, `DefaultAssemblyResolvedBackfill`, and
/// `DefaultAssemblyResolvedError`, chosen as a cut-point for the dependency cycle running through
/// those concrete classes and [`AbstractAssemblyResolutionFactory`](
/// super::AbstractAssemblyResolutionFactory) (which builds them) and back into
/// `AbstractAssemblyResolution` itself (via its `factory` field).
///
/// Java's protected `factory` field is dropped from this trait's surface: none of the methods
/// below need it (only *other*, not-yet-ported concrete-construction code in the Java class does),
/// so keeping it out avoids reintroducing the very cycle this cut-point exists to break.
/// Similarly, Java's `description`/`children`/`right` fields aren't re-declared here since the
/// accessors that expose them (`getDescription`, `getChildren`, `getRight`) already live on this
/// trait's [`AssemblyResolution`] supertrait.
///
/// `getDescription`, `getChildren`, `getRight`, `hasChildren`, `compareTo`, and the abstract
/// `shift`/`withRight` (its non-`withoutRight` sibling) are likewise already covered by
/// `AssemblyResolution` (`withRight` is added fresh here, since only this class introduces it).
/// What remains -- and is ported below -- is the behavior `AbstractAssemblyResolution` actually
/// adds on top of that interface: hashing, right-sibling collection, child-string rendering, and
/// the `withRight`/`withoutRight` pair.
pub trait AbstractAssemblyResolution: AssemblyResolution {
    /// Compute this record's hash code.
    ///
    /// Mirrors the protected abstract `AbstractAssemblyResolution.computeHash()`, which each
    /// concrete subclass implements from its own fields.
    fn compute_hash(&self) -> i32;

    /// This record's hash code.
    ///
    /// Mirrors `AbstractAssemblyResolution.hashCode()`. Java memoizes the result behind a private
    /// mutable field on first call; that caching is dropped here since a shared default trait
    /// method has no per-instance storage to cache into, so this simply recomputes via
    /// [`compute_hash`](Self::compute_hash) every call. Implementors needing memoization can still
    /// override this method with their own interior-mutable cache.
    fn hash_code(&self) -> i32 {
        self.compute_hash()
    }

    /// Collect this record and every right-sibling that follows it into one list.
    ///
    /// Mirrors the protected `AbstractAssemblyResolution.getAllRight()`, built atop
    /// [`AssemblyResolution::collect_all_right`].
    fn get_all_right(&self) -> Vec<Box<dyn AssemblyResolution>> {
        let mut result = Vec::new();
        self.collect_all_right(&mut result);
        result
    }

    /// Render this record's children, one per line, each prefixed by `indent`.
    ///
    /// Mirrors the protected `AbstractAssemblyResolution.childrenToString(String)`. Subclasses
    /// with an additional, subclass-specific notion of children should override this (matching the
    /// Java class's own documented override point).
    fn children_to_string(&self, indent: &str) -> String {
        self.get_children()
            .iter()
            .map(|child| child.to_string_indented(indent))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Default rendering for [`AssemblyResolution::to_string_indented`], combining
    /// [`AssemblyResolution::line_to_string`] with [`children_to_string`](Self::children_to_string)
    /// when this record has children.
    ///
    /// Mirrors `AbstractAssemblyResolution.toString(String)`. Named distinctly from
    /// `to_string_indented` (rather than provided as that supertrait method's default) because
    /// Rust doesn't let a subtrait supply a default body for a required supertrait method;
    /// implementors of `to_string_indented` can simply delegate to this method's body.
    fn to_string_indented_default(&self, indent: &str) -> String {
        let mut sb = String::new();
        sb.push_str(indent);
        sb.push_str(&self.line_to_string());
        if self.has_children() {
            sb.push_str(":\n");
            let new_indent = format!("{indent}  ");
            sb.push_str(&self.children_to_string(&new_indent));
        }
        sb
    }

    /// Get this same resolution, but with the given right sibling (or `None` to detach it).
    ///
    /// Mirrors the abstract `AbstractAssemblyResolution.withRight(AssemblyResolution)`; `None`
    /// mirrors Java's nullable parameter.
    fn with_right(&self, right: Option<Box<dyn AssemblyResolution>>) -> Box<dyn AssemblyResolution>;

    /// Get this same resolution, but without any right siblings.
    ///
    /// Mirrors `AbstractAssemblyResolution.withoutRight()`, a real default method built atop
    /// [`with_right`](Self::with_right), same as in Java.
    fn without_right(&self) -> Box<dyn AssemblyResolution> {
        self.with_right(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[derive(Clone, Debug)]
    struct Res {
        desc: String,
        children: Vec<Res>,
        right: Option<Box<Res>>,
    }

    impl std::fmt::Display for Res {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.desc)
        }
    }

    impl AssemblyResolution for Res {
        fn get_description(&self) -> String {
            self.desc.clone()
        }
        fn get_children(&self) -> Vec<Box<dyn AssemblyResolution>> {
            self.children
                .iter()
                .map(|c| Box::new(c.clone()) as Box<dyn AssemblyResolution>)
                .collect()
        }
        fn has_children(&self) -> bool {
            !self.children.is_empty()
        }
        fn get_right(&self) -> Option<Box<dyn AssemblyResolution>> {
            self.right.as_ref().map(|r| Box::new((**r).clone()) as Box<dyn AssemblyResolution>)
        }
        fn line_to_string(&self) -> String {
            self.desc.clone()
        }
        fn is_backfill(&self) -> bool {
            false
        }
        fn is_error(&self) -> bool {
            false
        }
        fn shift(&self, _amt: i32) -> Box<dyn AssemblyResolution> {
            Box::new(self.clone())
        }
        fn parent(&self, description: &str, _op_count: i32) -> Box<dyn AssemblyResolution> {
            Box::new(Res { desc: description.to_string(), children: vec![], right: None })
        }
        fn collect_all_right(&self, into: &mut Vec<Box<dyn AssemblyResolution>>) {
            into.push(Box::new(self.clone()));
            if let Some(right) = &self.right {
                right.collect_all_right(into);
            }
        }
        fn to_string_indented(&self, indent: &str) -> String {
            self.to_string_indented_default(indent)
        }
        fn compare_to(&self, other: &dyn AssemblyResolution) -> Ordering {
            self.desc.cmp(&other.get_description())
        }
    }

    impl AbstractAssemblyResolution for Res {
        fn compute_hash(&self) -> i32 {
            self.desc.len() as i32
        }
        fn with_right(&self, right: Option<Box<dyn AssemblyResolution>>) -> Box<dyn AssemblyResolution> {
            let right = right.map(|r| {
                Box::new(Res { desc: r.get_description(), children: vec![], right: None })
            });
            Box::new(Res { desc: self.desc.clone(), children: self.children.clone(), right })
        }
    }

    fn leaf(desc: &str) -> Res {
        Res { desc: desc.to_string(), children: vec![], right: None }
    }

    #[test]
    fn hash_code_delegates_to_compute_hash() {
        let r = leaf("abcd");
        assert_eq!(r.hash_code(), 4);
        assert_eq!(r.hash_code(), r.compute_hash());
    }

    #[test]
    fn get_all_right_collects_this_and_every_sibling() {
        let chain = Res {
            desc: "a".to_string(),
            children: vec![],
            right: Some(Box::new(Res {
                desc: "b".to_string(),
                children: vec![],
                right: Some(Box::new(leaf("c"))),
            })),
        };
        let all = chain.get_all_right();
        let descs: Vec<String> = all.iter().map(|r| r.get_description()).collect();
        assert_eq!(descs, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
    }

    #[test]
    fn get_all_right_on_leaf_is_just_itself() {
        let r = leaf("solo");
        let all = r.get_all_right();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].get_description(), "solo");
    }

    #[test]
    fn children_to_string_joins_indented_children() {
        let parent = Res {
            desc: "parent".to_string(),
            children: vec![leaf("x"), leaf("y")],
            right: None,
        };
        assert_eq!(parent.children_to_string("  "), "  x\n  y");
    }

    #[test]
    fn to_string_indented_default_without_children() {
        let r = leaf("op0");
        assert_eq!(r.to_string_indented_default(">> "), ">> op0");
    }

    #[test]
    fn to_string_indented_default_with_children_appends_indented_block() {
        let parent = Res {
            desc: "parent".to_string(),
            children: vec![leaf("kid")],
            right: None,
        };
        assert_eq!(parent.to_string_indented_default(""), "parent:\n  kid");
    }

    #[test]
    fn without_right_detaches_right_sibling() {
        let r = Res {
            desc: "a".to_string(),
            children: vec![],
            right: Some(Box::new(leaf("b"))),
        };
        let detached = r.without_right();
        assert!(detached.get_right().is_none());
        assert_eq!(detached.get_description(), "a");
    }

    #[test]
    fn with_right_attaches_given_sibling() {
        let r = leaf("a");
        let with_sibling = r.with_right(Some(Box::new(leaf("b"))));
        let right = with_sibling.get_right().expect("right sibling should be attached");
        assert_eq!(right.get_description(), "b");
    }

    #[test]
    fn trait_is_object_safe() {
        let r: Box<dyn AbstractAssemblyResolution> = Box::new(leaf("obj"));
        assert_eq!(r.hash_code(), 3);
        assert!(r.without_right().get_right().is_none());
    }
}
