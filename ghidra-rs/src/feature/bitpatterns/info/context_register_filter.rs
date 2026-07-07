use std::collections::{HashMap, HashSet};
use std::fmt;

/// Filters lists of context register (name, value) pairs.
///
/// Mirrors `ghidra.bitpatterns.info.ContextRegisterFilter`. The filter holds
/// at most one allowed value per named register. A list of register readings
/// passes the filter if every reading whose register name is tracked by the
/// filter has the exact value recorded for that register.
///
/// Java's `BigInteger` is represented as `i128`, consistent with the rest of
/// the `bitpatterns::info` module.
#[derive(Debug, Clone, Default)]
pub struct ContextRegisterFilter {
    context_registers: HashSet<String>,
    values: HashMap<String, i128>,
}

impl ContextRegisterFilter {
    /// Creates an empty filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a (register, value) pair to the filter.
    ///
    /// Returns `Err` if `context_register` already has a value recorded,
    /// mirroring the `IllegalStateException` thrown by the Java source.
    pub fn add_reg_and_value_to_filter(
        &mut self,
        context_register: &str,
        value: i128,
    ) -> Result<(), String> {
        if self.context_registers.contains(context_register) {
            return Err(String::from(
                "Filter can have only one value per register!",
            ));
        }
        self.context_registers.insert(context_register.to_string());
        self.values.insert(context_register.to_string(), value);
        Ok(())
    }

    /// Returns `true` if every reading in `context_register_infos` whose
    /// register is tracked by this filter has the recorded allowed value.
    ///
    /// Each element is a `(register_name, value)` pair, matching the accessor
    /// contract of `ContextRegisterInfo::getContextRegister` /
    /// `ContextRegisterInfo::getValue`.
    pub fn allows(&self, context_register_infos: &[(impl AsRef<str>, i128)]) -> bool {
        for (reg, val) in context_register_infos {
            let reg = reg.as_ref();
            if let Some(&allowed) = self.values.get(reg) {
                if *val != allowed {
                    return false;
                }
            }
        }
        true
    }

    /// Returns a compact semicolon-separated `name=value` string suitable for
    /// table cells, mirroring `getCompactString()` from the Java source.
    pub fn get_compact_string(&self) -> String {
        let mut registers: Vec<&str> =
            self.context_registers.iter().map(String::as_str).collect();
        registers.sort();
        let parts: Vec<String> = registers
            .iter()
            .map(|r| format!("{}={}", r, self.values[*r]))
            .collect();
        parts.join(";")
    }

    /// Returns a reference to the internal register-to-value map.
    pub fn get_value_map(&self) -> &HashMap<String, i128> {
        &self.values
    }
}

impl PartialEq for ContextRegisterFilter {
    fn eq(&self, other: &Self) -> bool {
        self.context_registers == other.context_registers && self.values == other.values
    }
}

impl Eq for ContextRegisterFilter {}

impl std::hash::Hash for ContextRegisterFilter {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Reproduce the Java: hash = 31*hash + contextRegisters.hashCode()
        // then hash = 31*hash + values.hashCode(). We iterate sorted keys so
        // the result is deterministic regardless of HashSet/HashMap ordering.
        let mut registers: Vec<&str> =
            self.context_registers.iter().map(String::as_str).collect();
        registers.sort();
        registers.hash(state);
        let mut pairs: Vec<(&str, i128)> = self
            .values
            .iter()
            .map(|(k, v)| (k.as_str(), *v))
            .collect();
        pairs.sort_by_key(|(k, _)| *k);
        pairs.hash(state);
    }
}

impl fmt::Display for ContextRegisterFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Context Register Filter: \n")?;
        let mut registers: Vec<&str> =
            self.context_registers.iter().map(String::as_str).collect();
        registers.sort();
        for reg in registers {
            writeln!(f, "{}: {}", reg, self.values[reg])?;
        }
        writeln!(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_filter_allows_anything() {
        let filter = ContextRegisterFilter::new();
        assert!(filter.allows(&[("any_reg", 42i128)]));
        let empty: &[(&str, i128)] = &[];
        assert!(filter.allows(empty));
    }

    #[test]
    fn test_add_and_allows_matching_value() {
        let mut filter = ContextRegisterFilter::new();
        filter.add_reg_and_value_to_filter("TMode", 1).unwrap();
        assert!(filter.allows(&[("TMode", 1i128)]));
    }

    #[test]
    fn test_allows_rejects_wrong_value() {
        let mut filter = ContextRegisterFilter::new();
        filter.add_reg_and_value_to_filter("TMode", 1).unwrap();
        assert!(!filter.allows(&[("TMode", 0i128)]));
    }

    #[test]
    fn test_allows_ignores_untracked_register() {
        let mut filter = ContextRegisterFilter::new();
        filter.add_reg_and_value_to_filter("TMode", 1).unwrap();
        // "Other" is not tracked — still passes
        assert!(filter.allows(&[("TMode", 1i128), ("Other", 99i128)]));
    }

    #[test]
    fn test_allows_empty_list_always_passes() {
        let mut filter = ContextRegisterFilter::new();
        filter.add_reg_and_value_to_filter("TMode", 1).unwrap();
        let empty: &[(&str, i128)] = &[];
        assert!(filter.allows(empty));
    }

    #[test]
    fn test_duplicate_register_returns_err() {
        let mut filter = ContextRegisterFilter::new();
        filter.add_reg_and_value_to_filter("TMode", 1).unwrap();
        let result = filter.add_reg_and_value_to_filter("TMode", 0);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Filter can have only one value per register!"
        );
    }

    #[test]
    fn test_equality_same_content() {
        let mut a = ContextRegisterFilter::new();
        a.add_reg_and_value_to_filter("R1", 5).unwrap();
        let mut b = ContextRegisterFilter::new();
        b.add_reg_and_value_to_filter("R1", 5).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_equality_different_values() {
        let mut a = ContextRegisterFilter::new();
        a.add_reg_and_value_to_filter("R1", 5).unwrap();
        let mut b = ContextRegisterFilter::new();
        b.add_reg_and_value_to_filter("R1", 6).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_equality_different_registers() {
        let mut a = ContextRegisterFilter::new();
        a.add_reg_and_value_to_filter("R1", 5).unwrap();
        let mut b = ContextRegisterFilter::new();
        b.add_reg_and_value_to_filter("R2", 5).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_get_compact_string_single() {
        let mut filter = ContextRegisterFilter::new();
        filter.add_reg_and_value_to_filter("TMode", 1).unwrap();
        assert_eq!(filter.get_compact_string(), "TMode=1");
    }

    #[test]
    fn test_get_compact_string_multiple_sorted() {
        let mut filter = ContextRegisterFilter::new();
        filter.add_reg_and_value_to_filter("Z", 9).unwrap();
        filter.add_reg_and_value_to_filter("A", 3).unwrap();
        assert_eq!(filter.get_compact_string(), "A=3;Z=9");
    }

    #[test]
    fn test_get_compact_string_empty() {
        let filter = ContextRegisterFilter::new();
        assert_eq!(filter.get_compact_string(), "");
    }

    #[test]
    fn test_display_format() {
        let mut filter = ContextRegisterFilter::new();
        filter.add_reg_and_value_to_filter("TMode", 1).unwrap();
        let s = filter.to_string();
        assert!(s.starts_with("Context Register Filter: \n"));
        assert!(s.contains("TMode: 1\n"));
    }

    #[test]
    fn test_get_value_map() {
        let mut filter = ContextRegisterFilter::new();
        filter.add_reg_and_value_to_filter("R1", 7).unwrap();
        let map = filter.get_value_map();
        assert_eq!(map.get("R1"), Some(&7i128));
    }

    #[test]
    fn test_multiple_tracked_registers_partial_pass() {
        let mut filter = ContextRegisterFilter::new();
        filter.add_reg_and_value_to_filter("A", 1).unwrap();
        filter.add_reg_and_value_to_filter("B", 2).unwrap();
        // A matches, B does not → should fail
        assert!(!filter.allows(&[("A", 1i128), ("B", 99i128)]));
        // Both match
        assert!(filter.allows(&[("A", 1i128), ("B", 2i128)]));
    }
}
