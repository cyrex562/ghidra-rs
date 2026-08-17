//! Port of `ghidra.app.util.bin.format.objc.ObjcState`.
//!
//! Java's `ObjcState` is a data class holding collections for tracking applied structures,
//! methods, code attributes, and class/instance variable information during Objective-C format
//! processing.

use std::collections::{HashMap, HashSet};
use std::io;

use crate::format::seam_stubs::{LibObjcOptimization, Objc1TypeEncodings, Objc2Class, Objc2InstanceVariable};
use crate::format::objc::objc_method::ObjcMethod;
use crate::program::model::address::Address;
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::listing::program::Program;

/// Port of `ghidra.app.util.bin.format.objc.ObjcState`.
///
/// Holds mutable state during Objective-C binary format analysis. Tracks which structures
/// have been applied, method locations, thumb code markers, class definitions, and instance
/// variable information.
pub struct ObjcState {
    /// Set of indices of structures that have been applied to the program.
    pub been_applied: HashSet<i64>,

    /// Map of method addresses to their method objects.
    pub method_map: HashMap<Address, Box<dyn ObjcMethod>>,

    /// Set of addresses known to contain thumb code.
    pub thumb_code_locations: HashSet<Address>,

    /// Map of class indices to their class objects.
    pub class_index_map: HashMap<i64, Box<dyn Objc2Class>>,

    /// Map of instance variable addresses to instance variable objects.
    pub variable_map: HashMap<Address, Box<dyn Objc2InstanceVariable>>,

    /// Optional dyld_shared_cache libobjc optimization data.
    pub lib_objc_optimization: Option<Box<dyn LibObjcOptimization>>,

    /// Type encodings for Objective-C 1.0 format (handles method signature parsing).
    pub encodings: Box<dyn Objc1TypeEncodings>,
}

impl ObjcState {
    /// Creates a new ObjcState instance.
    ///
    /// Java: `ObjcState(Program program, CategoryPath categoryPath)` constructor.
    /// The encodings are initialized with the program's default pointer size and category path.
    pub fn new(program: &dyn Program, category_path: CategoryPath) -> io::Result<Self> {
        let pointer_size = program.get_default_pointer_size() as i32;
        let encodings = create_objc1_type_encodings(pointer_size, category_path)?;

        Ok(ObjcState {
            been_applied: HashSet::new(),
            method_map: HashMap::new(),
            thumb_code_locations: HashSet::new(),
            class_index_map: HashMap::new(),
            variable_map: HashMap::new(),
            lib_objc_optimization: None,
            encodings,
        })
    }

    /// Clears all state maps and sets.
    ///
    /// Java: `close()` (implements Closeable).
    pub fn close(&mut self) {
        self.been_applied.clear();
        self.method_map.clear();
        self.thumb_code_locations.clear();
        // Note: classIndexMap and variableMap are NOT cleared in Java's close()
    }
}

/// Placeholder helper for creating Objc1TypeEncodings instances.
/// This will be replaced when Objc1TypeEncodings is properly ported.
fn create_objc1_type_encodings(
    _pointer_size: i32,
    _category_path: CategoryPath,
) -> io::Result<Box<dyn Objc1TypeEncodings>> {
    // Placeholder: in a real implementation, this would construct the actual Objc1TypeEncodings.
    // For now, return a stub that implements the trait.
    Err(io::Error::new(
        io::ErrorKind::Other,
        "Objc1TypeEncodings not yet ported",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: ObjcState can be created with a basic setup.
    #[test]
    fn test_objc_state_creation_stubs() {
        // Note: this is a stub test since ObjcState requires dyn Program and
        // Objc1TypeEncodings to be fully constructed. A real test would use a mock Program.
        // For now, we just verify the struct can be instantiated manually.

        let state = ObjcState {
            been_applied: HashSet::new(),
            method_map: HashMap::new(),
            thumb_code_locations: HashSet::new(),
            class_index_map: HashMap::new(),
            variable_map: HashMap::new(),
            lib_objc_optimization: None,
            encodings: create_stub_encodings(),
        };

        assert!(state.been_applied.is_empty());
        assert!(state.method_map.is_empty());
        assert!(state.thumb_code_locations.is_empty());
        assert!(state.class_index_map.is_empty());
        assert!(state.variable_map.is_empty());
        assert!(state.lib_objc_optimization.is_none());
    }

    /// Test that close() clears the appropriate collections.
    #[test]
    fn test_objc_state_close() {
        let mut state = ObjcState {
            been_applied: {
                let mut s = HashSet::new();
                s.insert(1);
                s.insert(2);
                s
            },
            method_map: HashMap::new(),
            thumb_code_locations: {
                let mut s = HashSet::new();
                // Would add Address instances here with a real test
                s
            },
            class_index_map: {
                let mut m = HashMap::new();
                m.insert(100, create_stub_class());
                m
            },
            variable_map: HashMap::new(),
            lib_objc_optimization: None,
            encodings: create_stub_encodings(),
        };

        // Verify state before close
        assert_eq!(state.been_applied.len(), 2);
        assert_eq!(state.class_index_map.len(), 1);

        state.close();

        // After close, been_applied and thumb_code_locations should be cleared
        assert!(state.been_applied.is_empty());
        assert!(state.thumb_code_locations.is_empty());
        // Note: class_index_map is NOT cleared per Java behavior
        assert_eq!(state.class_index_map.len(), 1);
    }

    fn create_stub_encodings() -> Box<dyn Objc1TypeEncodings> {
        Box::new(StubObjc1TypeEncodings)
    }

    fn create_stub_class() -> Box<dyn Objc2Class> {
        Box::new(StubObjc2Class)
    }

    struct StubObjc1TypeEncodings;
    impl Objc1TypeEncodings for StubObjc1TypeEncodings {
        fn to_string(&self) -> String {
            "stub".to_string()
        }
        fn process_method_signature(
            &self,
            _program: &dyn Program,
            _method_address: &Address,
            _mangled_signature: &str,
            _method_type: &crate::format::objc::objc_method_type::ObjcMethodType,
        ) {
        }
        fn to_function_signature(
            &self,
            _method_name: &str,
            _mangled_signature: &str,
        ) -> Box<dyn crate::format::seam_stubs::FunctionSignature> {
            Box::new(StubFunctionSignature)
        }
        fn process_instance_variable_signature(
            &self,
            _program: &dyn Program,
            _instance_variable_address: &Address,
            _mangled_type: &str,
            _instance_variable_size: i32,
        ) {
        }
    }

    struct StubObjc2Class;
    impl Objc2Class for StubObjc2Class {
        fn equals(&self, _that: &dyn std::any::Any) -> bool {
            false
        }
        fn hash_code(&self) -> i32 {
            0
        }
        fn get_isa(&self) -> Box<dyn Objc2Class> {
            Box::new(StubObjc2Class)
        }
        fn get_super_class(&self) -> Box<dyn Objc2Class> {
            Box::new(StubObjc2Class)
        }
        fn get_cache(&self) -> Box<dyn crate::format::seam_stubs::Objc2Cache> {
            Box::new(StubObjc2Cache)
        }
        fn get_v_table(&self) -> Box<dyn crate::format::seam_stubs::Objc2Implementation> {
            Box::new(StubObjc2Implementation)
        }
        fn get_data(&self) -> Box<dyn crate::format::seam_stubs::Objc2ClassRW> {
            Box::new(StubObjc2ClassRW)
        }
        fn get_index(&self) -> i64 {
            0
        }
        fn to_data_type(
            &self,
        ) -> std::io::Result<Box<dyn crate::program::model::data::data_type::DataType>> {
            Err(io::Error::new(io::ErrorKind::Other, "stub"))
        }
        fn apply_to(
            &self,
            _namespace: &dyn crate::program::model::symbol::Namespace,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct StubFunctionSignature;
    impl crate::format::seam_stubs::FunctionSignature for StubFunctionSignature {
        fn to_string(&self) -> String {
            "stub".to_string()
        }
    }

    struct StubObjc2Cache;
    impl crate::format::seam_stubs::Objc2Cache for StubObjc2Cache {
        fn equals(&self, _that: &dyn std::any::Any) -> bool {
            false
        }
        fn hash_code(&self) -> i32 {
            0
        }
        fn to_data_type(
            &self,
        ) -> std::io::Result<Box<dyn crate::program::model::data::data_type::DataType>> {
            Err(io::Error::new(io::ErrorKind::Other, "stub"))
        }
    }

    struct StubObjc2Implementation;
    impl crate::format::seam_stubs::Objc2Implementation for StubObjc2Implementation {
        fn equals(&self, _that: &dyn std::any::Any) -> bool {
            false
        }
        fn hash_code(&self) -> i32 {
            0
        }
        fn to_data_type(
            &self,
        ) -> std::io::Result<Box<dyn crate::program::model::data::data_type::DataType>> {
            Err(io::Error::new(io::ErrorKind::Other, "stub"))
        }
    }

    struct StubObjc2ClassRW;
    impl crate::format::seam_stubs::Objc2ClassRW for StubObjc2ClassRW {
        fn equals(&self, _that: &dyn std::any::Any) -> bool {
            false
        }
        fn hash_code(&self) -> i32 {
            0
        }
        fn to_data_type(
            &self,
        ) -> std::io::Result<Box<dyn crate::program::model::data::data_type::DataType>> {
            Err(io::Error::new(io::ErrorKind::Other, "stub"))
        }
    }
}
