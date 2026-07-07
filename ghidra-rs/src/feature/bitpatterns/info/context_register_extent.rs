use std::collections::{HashMap, HashSet};

/// Accumulated context register information across a set of function bodies.
///
/// Mirrors `ghidra.bitpatterns.info.ContextRegisterExtent`. Stores, for each
/// named context register, the set of distinct values it assumes. All query
/// methods return sorted results to match the Java source behaviour.
///
/// Java's `BigInteger` is represented here as `i128`, which is large enough
/// for any realistic Ghidra context register width.
#[derive(Debug, Clone, Default)]
pub struct ContextRegisterExtent {
    context_registers: HashSet<String>,
    regs_to_values: HashMap<String, HashSet<i128>>,
}

impl ContextRegisterExtent {
    /// Creates an empty `ContextRegisterExtent`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Accumulates register/value pairs into the extent.
    ///
    /// Each element of `info` is a `(register_name, value)` pair. `None` or an
    /// empty slice is a no-op, matching the Java null/empty-list guard.
    pub fn add_context_info(&mut self, info: &[(impl AsRef<str>, i128)]) {
        for (register, value) in info {
            self.add_register_and_value(register.as_ref(), *value);
        }
    }

    fn add_register_and_value(&mut self, register: &str, value: i128) {
        if !self.context_registers.contains(register) {
            self.context_registers.insert(register.to_string());
            self.regs_to_values
                .insert(register.to_string(), HashSet::new());
        }
        self.regs_to_values
            .get_mut(register)
            .expect("register was just inserted")
            .insert(value);
    }

    /// Returns an alphabetically sorted list of context register names.
    pub fn get_context_registers(&self) -> Vec<String> {
        let mut list: Vec<String> = self.context_registers.iter().cloned().collect();
        list.sort();
        list
    }

    /// Returns a sorted list of values the register assumes in this extent.
    ///
    /// Returns an empty `Vec` when `register` is unknown.
    pub fn get_values_for_register(&self, register: &str) -> Vec<i128> {
        match self.regs_to_values.get(register) {
            Some(set) => {
                let mut values: Vec<i128> = set.iter().copied().collect();
                values.sort();
                values
            }
            None => Vec::new(),
        }
    }
}

impl std::fmt::Display for ContextRegisterExtent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let registers = self.get_context_registers();
        if registers.is_empty() {
            return Ok(());
        }
        for register in &registers {
            write!(f, "Register: {}\n", register)?;
            let values = self.get_values_for_register(register);
            write!(f, "Values: ")?;
            for (i, v) in values.iter().enumerate() {
                if i < values.len() - 1 {
                    write!(f, "{}, ", v)?;
                } else {
                    write!(f, "{}\n\n", v)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_extent() {
        let extent = ContextRegisterExtent::new();
        assert!(extent.get_context_registers().is_empty());
        assert!(extent.get_values_for_register("testRegister").is_empty());
        assert_eq!(extent.to_string(), "");
    }

    #[test]
    fn test_empty_slice_is_noop() {
        let mut extent = ContextRegisterExtent::new();
        let empty: &[(String, i128)] = &[];
        extent.add_context_info(empty);
        assert!(extent.get_context_registers().is_empty());
    }

    #[test]
    fn test_registers_and_values() {
        let mut extent = ContextRegisterExtent::new();
        let info: &[(&str, i128)] = &[("B", 1), ("A", 2), ("A", 1)];
        extent.add_context_info(info);

        let regs = extent.get_context_registers();
        assert_eq!(regs, vec!["A", "B"]);

        let a_values = extent.get_values_for_register("A");
        assert_eq!(a_values, vec![1, 2]);

        let b_values = extent.get_values_for_register("B");
        assert_eq!(b_values, vec![1]);
    }

    #[test]
    fn test_unknown_register_returns_empty() {
        let extent = ContextRegisterExtent::new();
        assert!(extent.get_values_for_register("nonexistent").is_empty());
    }

    #[test]
    fn test_duplicate_values_deduplicated() {
        let mut extent = ContextRegisterExtent::new();
        extent.add_context_info(&[("R", 42i128), ("R", 42i128), ("R", 7i128)]);
        let values = extent.get_values_for_register("R");
        assert_eq!(values, vec![7, 42]);
    }

    #[test]
    fn test_to_string_non_empty() {
        let mut extent = ContextRegisterExtent::new();
        extent.add_context_info(&[("TMode", 0i128), ("TMode", 1i128)]);
        let s = extent.to_string();
        assert!(s.starts_with("Register: TMode\n"));
        assert!(s.contains("Values: 0, 1\n\n"));
    }

    #[test]
    fn test_to_string_multiple_registers_sorted() {
        let mut extent = ContextRegisterExtent::new();
        extent.add_context_info(&[("Z", 9i128), ("A", 3i128)]);
        let s = extent.to_string();
        let a_pos = s.find("Register: A").unwrap();
        let z_pos = s.find("Register: Z").unwrap();
        assert!(a_pos < z_pos, "registers must be alphabetically ordered");
    }

    #[test]
    fn test_accumulate_across_multiple_calls() {
        let mut extent = ContextRegisterExtent::new();
        extent.add_context_info(&[("X", 1i128)]);
        extent.add_context_info(&[("X", 2i128), ("Y", 5i128)]);
        assert_eq!(extent.get_context_registers(), vec!["X", "Y"]);
        assert_eq!(extent.get_values_for_register("X"), vec![1, 2]);
        assert_eq!(extent.get_values_for_register("Y"), vec![5]);
    }
}
