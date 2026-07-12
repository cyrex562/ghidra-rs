//! Models `ghidra.pcodeCPort.slghpattern.DisjointPattern`.

use std::fmt;

use crate::decompiler::seam_stubs::Pattern;
use crate::decompiler::slghpattern::PatternBlock;

/// A pattern whose instruction-bit and context-bit constraints are each captured by a single
/// [`PatternBlock`], rather than by an OR of several sub-patterns.
///
/// Models the abstract class `ghidra.pcodeCPort.slghpattern.DisjointPattern`, which extends
/// `Pattern` (stubbed as [`Pattern`] pending its own port).
pub trait DisjointPattern: Pattern {
    /// The context block (`context == true`) or instruction block (`context == false`), or
    /// `None` if this pattern places no constraint on that half.
    fn get_block(&self, context: bool) -> Option<&PatternBlock>;

    /// The number of disjuncts making up this pattern; always `0` for a plain disjoint pattern.
    fn num_disjoint(&self) -> i32 {
        0
    }

    /// The `i`th disjunct; always `None` for a plain disjoint pattern.
    fn get_disjoint(&self, _i: i32) -> Option<&dyn DisjointPattern> {
        None
    }

    /// `size` mask bits starting at `startbit` of the instruction or context block.
    fn get_mask(&self, startbit: i32, size: i32, context: bool) -> i32 {
        match self.get_block(context) {
            Some(block) => block.get_mask(startbit, size),
            None => 0,
        }
    }

    /// `size` value bits starting at `startbit` of the instruction or context block.
    fn get_value(&self, startbit: i32, size: i32, context: bool) -> i32 {
        match self.get_block(context) {
            Some(block) => block.get_value(startbit, size),
            None => 0,
        }
    }

    /// The length, in bytes, of the instruction or context block.
    fn get_length(&self, context: bool) -> i32 {
        match self.get_block(context) {
            Some(block) => block.get_length(),
            None => 0,
        }
    }

    /// Whether this pattern's mask is non-zero everywhere `op2`'s mask is non-zero, and the
    /// values agree there.
    fn specializes(&self, op2: &dyn DisjointPattern) -> bool {
        let mut a = self.get_block(false);
        let b = op2.get_block(false);
        if let Some(b) = b {
            if !b.is_always_true() {
                match a {
                    None => return false,
                    Some(a) => {
                        if !a.specializes(b) {
                            return false;
                        }
                    }
                }
            }
        }
        a = self.get_block(true);
        let b = op2.get_block(true);
        if let Some(b) = b {
            if !b.is_always_true() {
                match a {
                    None => return false,
                    Some(a) => {
                        if !a.specializes(b) {
                            return false;
                        }
                    }
                }
            }
        }
        true
    }

    /// Whether this pattern matches exactly the same instructions as `op2`.
    fn identical(&self, op2: &dyn DisjointPattern) -> bool {
        let mut a = self.get_block(false);
        let mut b = op2.get_block(false);
        if let Some(b) = b {
            match a {
                None => {
                    if !b.is_always_true() {
                        return false;
                    }
                }
                Some(a) => {
                    if !a.identical(b) {
                        return false;
                    }
                }
            }
        } else if let Some(a) = a {
            if !a.is_always_true() {
                return false;
            }
        }
        a = self.get_block(true);
        b = op2.get_block(true);
        if let Some(b) = b {
            match a {
                None => {
                    if !b.is_always_true() {
                        return false;
                    }
                }
                Some(a) => {
                    if !a.identical(b) {
                        return false;
                    }
                }
            }
        } else if let Some(a) = a {
            if !a.is_always_true() {
                return false;
            }
        }
        true
    }

    /// Whether this pattern is equal to the intersection of `op1` and `op2`.
    fn resolves_intersect(&self, op1: &dyn DisjointPattern, op2: &dyn DisjointPattern) -> bool {
        if !resolve_intersect_block(
            op1.get_block(false),
            op2.get_block(false),
            self.get_block(false),
        ) {
            return false;
        }
        resolve_intersect_block(op1.get_block(true), op2.get_block(true), self.get_block(true))
    }
}

/// Whether `thisblock` equals the intersection of `bl1` and `bl2`, where any of the three may be
/// absent (matching Java's use of `null` for "always true").
///
/// Models the static method
/// `ghidra.pcodeCPort.slghpattern.DisjointPattern.resolveIntersectBlock`.
pub fn resolve_intersect_block(
    bl1: Option<&PatternBlock>,
    bl2: Option<&PatternBlock>,
    thisblock: Option<&PatternBlock>,
) -> bool {
    let inter: Option<PatternBlock> = if bl1.is_none() {
        bl2.cloned()
    } else if bl2.is_none() {
        bl1.cloned()
    } else {
        Some(bl1.unwrap().intersect(bl2.unwrap()))
    };

    match inter {
        None => thisblock.is_none(),
        Some(inter) => match thisblock {
            None => false,
            Some(thisblock) => thisblock.identical(&inter),
        },
    }
}

impl fmt::Display for dyn DisjointPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DisjointPattern{{")?;
        match self.get_block(true) {
            Some(block) => write!(f, "{}", block)?,
            None => write!(f, "null")?,
        }
        write!(f, " : ")?;
        match self.get_block(false) {
            Some(block) => write!(f, "{}", block)?,
            None => write!(f, "null")?,
        }
        write!(f, "}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trivial mock holding an instruction block and a context block, proving the trait's
    /// default methods behave like the Java overrides and that it is object-safe.
    struct MockDisjoint {
        instr: Option<PatternBlock>,
        context: Option<PatternBlock>,
    }

    impl Pattern for MockDisjoint {}

    impl DisjointPattern for MockDisjoint {
        fn get_block(&self, context: bool) -> Option<&PatternBlock> {
            if context {
                self.context.as_ref()
            } else {
                self.instr.as_ref()
            }
        }
    }

    fn block(mask: i32, val: i32) -> PatternBlock {
        PatternBlock::new(0, mask, val)
    }

    #[test]
    fn num_disjoint_and_get_disjoint_are_trivial() {
        let p = MockDisjoint { instr: None, context: None };
        assert_eq!(p.num_disjoint(), 0);
        assert!(p.get_disjoint(0).is_none());
    }

    #[test]
    fn get_mask_value_length_default_to_zero_when_block_absent() {
        let p = MockDisjoint { instr: None, context: None };
        assert_eq!(p.get_mask(0, 8, false), 0);
        assert_eq!(p.get_value(0, 8, false), 0);
        assert_eq!(p.get_length(false), 0);
    }

    #[test]
    fn get_mask_value_length_delegate_to_block() {
        let p = MockDisjoint {
            instr: Some(block(0xff00_0000u32 as i32, 0xab00_0000u32 as i32)),
            context: None,
        };
        assert_eq!(p.get_mask(0, 8, false) as u32, 0xff);
        assert_eq!(p.get_value(0, 8, false) as u32, 0xab);
        assert_eq!(p.get_length(false), 1);
    }

    #[test]
    fn specializes_true_when_no_constraint_on_op2() {
        let a = MockDisjoint { instr: None, context: None };
        let b = MockDisjoint { instr: None, context: None };
        assert!(a.specializes(&b));
    }

    #[test]
    fn specializes_false_when_missing_required_block() {
        let a = MockDisjoint { instr: None, context: None };
        let b = MockDisjoint {
            instr: Some(block(0xff00_0000u32 as i32, 0xaa00_0000u32 as i32)),
            context: None,
        };
        assert!(!a.specializes(&b));
    }

    #[test]
    fn specializes_true_when_more_specific() {
        let general = MockDisjoint {
            instr: Some(block(0xff00_0000u32 as i32, 0xaa00_0000u32 as i32)),
            context: None,
        };
        let specific = MockDisjoint {
            instr: Some(block(0xffff_0000u32 as i32, 0xaa12_0000u32 as i32)),
            context: None,
        };
        assert!(specific.specializes(&general));
        assert!(!general.specializes(&specific));
    }

    #[test]
    fn identical_true_for_two_always_true_patterns() {
        let a = MockDisjoint { instr: None, context: None };
        let b = MockDisjoint { instr: None, context: None };
        assert!(a.identical(&b));
    }

    #[test]
    fn identical_false_when_only_one_side_has_a_block() {
        let a = MockDisjoint { instr: None, context: None };
        let b = MockDisjoint {
            instr: Some(block(0xff00_0000u32 as i32, 0xaa00_0000u32 as i32)),
            context: None,
        };
        assert!(!a.identical(&b));
        assert!(!b.identical(&a));
    }

    #[test]
    fn identical_true_for_matching_blocks() {
        let a = MockDisjoint {
            instr: Some(block(0xffff_0000u32 as i32, 0x1234_0000u32 as i32)),
            context: None,
        };
        let b = MockDisjoint {
            instr: Some(block(0xffff_0000u32 as i32, 0x1234_0000u32 as i32)),
            context: None,
        };
        assert!(a.identical(&b));
    }

    #[test]
    fn resolve_intersect_block_null_blocks_match_null_thisblock() {
        assert!(resolve_intersect_block(None, None, None));
        assert!(!resolve_intersect_block(
            None,
            None,
            Some(&block(0xff00_0000u32 as i32, 0xaa00_0000u32 as i32))
        ));
    }

    #[test]
    fn resolve_intersect_block_true_when_thisblock_matches_intersection() {
        let a = block(0xff00_0000u32 as i32, 0xaa00_0000u32 as i32);
        let b = block(0x00ff_0000u32 as i32, 0x00bb_0000u32 as i32);
        let combined = a.intersect(&b);
        assert!(resolve_intersect_block(Some(&a), Some(&b), Some(&combined)));
    }

    #[test]
    fn resolve_intersect_block_false_when_thisblock_missing() {
        let a = block(0xff00_0000u32 as i32, 0xaa00_0000u32 as i32);
        let b = block(0x00ff_0000u32 as i32, 0x00bb_0000u32 as i32);
        assert!(!resolve_intersect_block(Some(&a), Some(&b), None));
    }

    #[test]
    fn resolves_intersect_delegates_per_half() {
        let a = block(0xff00_0000u32 as i32, 0xaa00_0000u32 as i32);
        let b = block(0x00ff_0000u32 as i32, 0x00bb_0000u32 as i32);
        let combined = a.intersect(&b);

        let op1 = MockDisjoint { instr: Some(a), context: None };
        let op2 = MockDisjoint { instr: Some(b), context: None };
        let this = MockDisjoint { instr: Some(combined), context: None };

        assert!(this.resolves_intersect(&op1, &op2));
    }

    #[test]
    fn display_uses_null_for_missing_blocks_and_shows_context_then_instruction() {
        let p = MockDisjoint {
            instr: Some(block(0xf000_0000u32 as i32, 0x9000_0000u32 as i32)),
            context: None,
        };
        let dyn_p: &dyn DisjointPattern = &p;
        let text = format!("{}", dyn_p);
        assert!(text.starts_with("DisjointPattern{null : "));
        assert!(text.contains("1001...."));
        assert!(text.ends_with("}"));
    }
}
