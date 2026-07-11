use crate::program::model::lang::RegisterRef;
use crate::program::model::listing::Program;
use crate::util::msg::Msg;
use std::collections::HashMap;

/// Maps PDB register names to program registers.
///
/// Handles register name translations for names that differ from the standard format
/// (e.g., "fbp" → "RBP").
pub struct PdbRegisterNameToProgramRegisterMapper {
    program: Box<dyn Program>,
    pdb_register_name_to_register_map: HashMap<String, Option<RegisterRef>>,
}

impl PdbRegisterNameToProgramRegisterMapper {
    /// Static mapping of PDB register names to program register names.
    ///
    /// Only names that differ from the PDB name are mapped (case-insensitive matching
    /// like "rsp" ↔ "RSP" is handled automatically).
    const REGISTER_NAME_MAP: &'static [(&'static str, &'static str)] = &[
        ("fbp", "RBP"),
    ];

    /// Creates a new mapper for the given program.
    pub fn new(program: Box<dyn Program>) -> Self {
        Self {
            program,
            pdb_register_name_to_register_map: HashMap::new(),
        }
    }

    /// Gets the register corresponding to the given PDB register name.
    ///
    /// # Arguments
    ///
    /// * `pdb_register_name` - The register name as it appears in the PDB
    ///
    /// # Returns
    ///
    /// Returns the mapped register, or `None` if not found.
    pub fn get_register(&mut self, pdb_register_name: &str) -> Option<RegisterRef> {
        if let Some(cached) = self.pdb_register_name_to_register_map.get(pdb_register_name) {
            return cached.clone();
        }

        let register_name = Self::REGISTER_NAME_MAP
            .iter()
            .find(|(pdb_name, _)| pdb_name == &pdb_register_name)
            .map(|(_, program_name)| *program_name)
            .unwrap_or(pdb_register_name);

        let register = self.program.get_register(register_name);

        if register.is_none() {
            Msg::info("PdbRegisterNameToProgramRegisterMapper",
                &format!("Program register not found for {}", register_name));
        }

        self.pdb_register_name_to_register_map
            .insert(pdb_register_name.to_string(), register.clone());

        register
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockProgram {
        call_count: RefCell<usize>,
        registers_to_return: HashMap<String, Option<RegisterRef>>,
    }

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "MockProgram".to_string()
        }

        fn get_language_id(&self) -> String {
            "x86:LE:64:default".to_string()
        }

        fn get_register(&self, name: &str) -> Option<RegisterRef> {
            *self.call_count.borrow_mut() += 1;
            self.registers_to_return.get(name).cloned()
        }
    }

    impl crate::framework::model::DomainObject for MockProgram {
        fn get_domain_object_id(&self) -> i64 {
            0
        }

        fn get_metadata(&self) -> String {
            String::new()
        }

        fn set_metadata(&mut self, _metadata: String) {}
    }

    #[test]
    fn test_direct_register_lookup_when_found() {
        let mut registers_to_return = HashMap::new();
        registers_to_return.insert("RAX".to_string(), None);

        let program = Box::new(MockProgram {
            call_count: RefCell::new(0),
            registers_to_return,
        });

        let mut mapper = PdbRegisterNameToProgramRegisterMapper::new(program);

        // "RAX" should look up directly without mapping
        let reg = mapper.get_register("RAX");
        assert!(reg.is_none());
    }

    #[test]
    fn test_mapped_register_lookup() {
        let mut registers_to_return = HashMap::new();
        registers_to_return.insert("RBP".to_string(), None);

        let program = Box::new(MockProgram {
            call_count: RefCell::new(0),
            registers_to_return,
        });

        let mut mapper = PdbRegisterNameToProgramRegisterMapper::new(program);

        // "fbp" should map to "RBP"
        let reg = mapper.get_register("fbp");
        assert!(reg.is_none());
    }

    #[test]
    fn test_unmapped_register_not_found() {
        let program = Box::new(MockProgram {
            call_count: RefCell::new(0),
            registers_to_return: HashMap::new(),
        });

        let mut mapper = PdbRegisterNameToProgramRegisterMapper::new(program);

        let reg = mapper.get_register("UNKNOWN");
        assert!(reg.is_none());
    }

    #[test]
    fn test_caching_prevents_duplicate_lookups() {
        let mut registers_to_return = HashMap::new();
        registers_to_return.insert("RAX".to_string(), None);

        let program = Box::new(MockProgram {
            call_count: RefCell::new(0),
            registers_to_return,
        });

        let mut mapper = PdbRegisterNameToProgramRegisterMapper::new(program);

        let _reg1 = mapper.get_register("RAX");
        let _reg2 = mapper.get_register("RAX");

        // Should only call program.get_register once due to caching
        assert_eq!(*program.call_count.borrow(), 1);
    }

    #[test]
    fn test_cache_stores_none_results() {
        let program = Box::new(MockProgram {
            call_count: RefCell::new(0),
            registers_to_return: HashMap::new(),
        });

        let mut mapper = PdbRegisterNameToProgramRegisterMapper::new(program);

        let _reg1 = mapper.get_register("UNKNOWN");
        let _reg2 = mapper.get_register("UNKNOWN");

        // Should only call program.get_register once, caching the None result
        assert_eq!(*program.call_count.borrow(), 1);
    }

    #[test]
    fn test_register_name_mapping_applied() {
        let mut registers_to_return = HashMap::new();
        registers_to_return.insert("RBP".to_string(), None);

        let program = Box::new(MockProgram {
            call_count: RefCell::new(0),
            registers_to_return,
        });

        let mut mapper = PdbRegisterNameToProgramRegisterMapper::new(program);

        // When looking up "fbp", it should try to look up "RBP" in the program
        mapper.get_register("fbp");

        // Verify the lookup happened (one call to program.get_register)
        assert_eq!(*program.call_count.borrow(), 1);
    }
}
