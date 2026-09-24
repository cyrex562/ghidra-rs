use crate::feature::lisa::pcode::locations::inst_location::InstLocation;
use crate::program::model::listing::Program;
use crate::program::seam_stubs::RegisterValue;

/// Placeholder for `it.unive.lisa.program.cfg.ProgramPoint`, narrowed to exactly what
/// [`PcodeNonRelationalValueDomain::get_value_at_program_point`] needs: the [`InstLocation`] it
/// occurs at, plus -- if it represents an assignment -- the textual form of the assignment's
/// left-hand-side expression.
///
/// The full LiSA CFG framework this interface is built on
/// (`it.unive.lisa.program.cfg.ProgramPoint`, `.statement.Assignment`,
/// `it.unive.lisa.analysis.SemanticOracle`, `it.unive.lisa.analysis.nonrelational.value.
/// BaseNonRelationalValueDomain`, `it.unive.lisa.symbolic.value.PushAny`,
/// `it.unive.lisa.analysis.SemanticException`) is an external third-party dependency with no
/// Rust port anywhere in this crate and no other caller needing it yet, so only this narrow
/// surface -- what `getValue(ProgramPoint)`'s body actually touches (`pp.getLocation()` and,
/// after an `instanceof Assignment` check, `((Assignment) pp).getLeft().toString()`) -- is
/// declared here, following this crate's established seam-stub convention for out-of-scope
/// external dependencies (e.g. [`crate::util::seam_stubs`]).
pub trait ProgramPoint {
    /// The location this program point occurs at. Mirrors `pp.getLocation()`, downcast to
    /// `InstLocation` (the only `Location` implementation `PcodeNonRelationalValueDomain`'s Java
    /// caller ever constructs a `ProgramPoint` from).
    fn location(&self) -> &InstLocation;

    /// The left-hand-side expression's string form, if this program point represents an
    /// assignment. Mirrors the Java `pp instanceof Assignment a` check plus
    /// `a.getLeft().toString()`; `None` corresponds to `pp` not being an `Assignment`.
    fn assignment_left(&self) -> Option<String>;
}

/// A non-relational abstract-interpretation value domain over p-code register values.
///
/// Port of `ghidra.lisa.pcode.analyses.PcodeNonRelationalValueDomain<T>`.
///
/// Two aspects of the Java interface have no equivalent in this port:
///
/// - Java's `T extends PcodeNonRelationalValueDomain<T>` F-bound and `extends
///   BaseNonRelationalValueDomain<T>` supertrait exist only to satisfy `evalPushAny`'s override
///   (`top()` comes from `BaseNonRelationalValueDomain`). Since `BaseNonRelationalValueDomain`
///   is unported (see [`ProgramPoint`]'s doc comment), both are dropped here: `T` is just the
///   domain's value type, with no self-referential bound.
/// - `evalPushAny(PushAny, ProgramPoint, SemanticOracle)` is not ported: its body is only ever
///   `T v = getValue(pp); return v == null ? top() : v;` -- trivial once
///   [`Self::get_value_at_program_point`] and a `top()` (from the unported
///   `BaseNonRelationalValueDomain`) both exist, so it is left for a future, real
///   `BaseNonRelationalValueDomain` port to add back as a one-line override rather than
///   fabricated against placeholder `PushAny`/`SemanticOracle`/`SemanticException` types here.
pub trait PcodeNonRelationalValueDomain<T> {
    /// Computes this domain's value for a given register value (which may be absent, mirroring
    /// Java's nullable `RegisterValue rv`). Mirrors `getValue(RegisterValue)`.
    fn get_value(&self, rv: Option<&dyn RegisterValue>) -> Option<T>;

    /// Computes this domain's value at a given program point, by resolving the point's
    /// assignment target (if any) back to a register and reading its value at the containing
    /// function's entry point. Mirrors `getValue(ProgramPoint)`.
    ///
    /// Java reaches the register's value via `f.getProgram().getProgramContext()
    /// .getRegisterValue(r, f.getEntryPoint())`, an implicit read through the `Function`'s own
    /// `Program`. This port instead takes `program` explicitly, because this crate's
    /// [`Program::get_program_context`] requires `&mut self` (an independent, already-established
    /// API shape unrelated to this port), while [`crate::program::model::listing::Function::
    /// get_program`] only ever hands back a shared `Arc<dyn Program>` -- there is no way to
    /// recover a unique `&mut dyn Program` from that shared reference. Callers thus supply the
    /// same `Program` `pp`'s function belongs to, mutably, from outside.
    ///
    /// Also reorders Java's `InstLocation loc = ...; Function f = loc.function(); if (f != null
    /// && pp instanceof Assignment a) { ... }` to check `assignment_left()` first: both orderings
    /// are equivalent (neither read has a side effect the other depends on), and checking the
    /// assignment first lets a non-assignment program point skip `location()`/`function()`
    /// entirely.
    fn get_value_at_program_point(&self, pp: &dyn ProgramPoint, program: &mut dyn Program) -> Option<T> {
        if let Some(left) = pp.assignment_left() {
            let function = pp.location().function();
            if let Some(register_space) =
                program.get_address_factory().and_then(|factory| factory.get_register_space())
            {
                if let Ok(Some(address)) = register_space.parse_address(&left, true) {
                    if let Some(register_ref) = program.get_register_at(&address) {
                        let entry_point = function.get_entry_point();
                        if let Some(context) = program.get_program_context() {
                            let register = register_ref;
                            if let Some(rv) = context.get_register_value(&register, &entry_point) {
                                return self.get_value(Some(rv.as_ref()));
                            }
                        }
                    }
                }
            }
        }

        // Java: `catch (AddressFormatException e) { // IGNORE }` then falls through to
        // `getValue((RegisterValue) null)`. Every path above that doesn't early-return (not an
        // assignment, no register space, unparseable address, no such register, no program
        // context, no recorded value) converges on the same fallback here.
        self.get_value(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::register::{Register, RegisterRef};
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    #[derive(Clone, PartialEq, Eq, Debug)]
    struct TaggedValue(String);

    struct MockRegisterValue {
        register: RegisterRef,
    }

    impl RegisterValue for MockRegisterValue {
        fn get_register(&self) -> RegisterRef {
            self.register.clone()
        }
        fn get_register_value(&self, _register: &Register) -> Box<dyn RegisterValue> {
            unimplemented!("not exercised by this smoke test")
        }
        fn has_any_value(&self) -> bool {
            true
        }
        fn get_unsigned_value_ignore_mask(&self) -> u128 {
            0
        }
        fn has_value(&self) -> bool {
            true
        }
        fn combine_values(&self, _other: &dyn RegisterValue) -> Box<dyn RegisterValue> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    /// A domain whose value is just a tag of whatever `RegisterValue` (or lack thereof) it was
    /// given -- enough to prove both `get_value` and `get_value_at_program_point`'s fallback
    /// path, without a real interval/sign/etc. lattice.
    struct TaggingDomain;

    impl PcodeNonRelationalValueDomain<TaggedValue> for TaggingDomain {
        fn get_value(&self, rv: Option<&dyn RegisterValue>) -> Option<TaggedValue> {
            rv.map(|rv| TaggedValue(rv.get_register().name().to_string()))
        }
    }

    fn register_ref(name: &str) -> RegisterRef {
        let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0);
        let address = Address::new(space, 0);
        Register::new(name, "", address, 4, false, 0)
    }

    /// A `ProgramPoint` that never represents an assignment. Its `location()` is never called by
    /// `get_value_at_program_point` in that case (see the reordering documented on that method),
    /// so it is left `unimplemented!()` here -- constructing a real `InstLocation` needs a real
    /// `Arc<dyn Function>`, which this non-assignment-path smoke test has no need for.
    struct NonAssignmentPoint;

    impl ProgramPoint for NonAssignmentPoint {
        fn location(&self) -> &InstLocation {
            unimplemented!("not exercised: this program point is never an assignment")
        }
        fn assignment_left(&self) -> Option<String> {
            None
        }
    }

    /// A minimal `Program`, sufficient only to satisfy `get_value_at_program_point`'s parameter
    /// type for the non-assignment fallback path (which never calls any of its methods).
    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    #[test]
    fn get_value_returns_none_when_register_value_is_absent() {
        let domain = TaggingDomain;
        assert_eq!(domain.get_value(None), None);
    }

    #[test]
    fn get_value_tags_the_register_name() {
        let domain = TaggingDomain;
        let rv = MockRegisterValue { register: register_ref("eax") };
        assert_eq!(domain.get_value(Some(&rv)), Some(TaggedValue("eax".to_string())));
    }

    #[test]
    fn get_value_at_program_point_falls_back_to_get_value_none_for_non_assignment() {
        let domain = TaggingDomain;
        let mut program = MockProgram;
        assert_eq!(
            domain.get_value_at_program_point(&NonAssignmentPoint, &mut program),
            None
        );
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let domain: Box<dyn PcodeNonRelationalValueDomain<TaggedValue>> = Box::new(TaggingDomain);
        assert_eq!(domain.get_value(None), None);
    }
}
