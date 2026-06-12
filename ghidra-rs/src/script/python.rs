use crate::program::database::ProgramDB;
use crate::program::model::address::Address;
use crate::program::model::symbol::{SourceType, SymbolTable};
use crate::program::model::listing::Program;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::fs;
use std::sync::{Arc, RwLock};
use std::ffi::CString;

#[pyclass(from_py_object)]
#[derive(Clone)]
pub struct PyAddress {
    pub inner: Address,
}

#[pymethods]
impl PyAddress {
    fn get_offset(&self) -> i64 {
        self.inner.offset()
    }

    fn get_space_name(&self) -> String {
        self.inner.space().name().to_string()
    }

    fn add(&self, displacement: i64) -> PyResult<Self> {
        let new_addr = self.inner.add(displacement)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{:?}", e)))?;
        Ok(Self { inner: new_addr })
    }

    fn __repr__(&self) -> String {
        format!("{}", self.inner)
    }
}

#[pyclass(from_py_object)]
#[derive(Clone)]
pub struct PyProgram {
    pub inner: Arc<RwLock<ProgramDB>>,
}

#[pymethods]
impl PyProgram {
    fn get_name(&self) -> String {
        let p = self.inner.read().unwrap();
        p.get_name().to_string()
    }

    fn get_language_id(&self) -> String {
        let p = self.inner.read().unwrap();
        p.get_language_id().to_string()
    }

    fn create_label(&self, address: &PyAddress, name: &str) -> PyResult<()> {
        let p = self.inner.read().unwrap();
        let symbol_table_arc = p.get_symbol_table();
        let mut symbol_table = symbol_table_arc.write().unwrap();
        symbol_table.create_label(&address.inner, name, SourceType::UserDefined)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?;
        Ok(())
    }

    fn get_symbols(&self, address: &PyAddress) -> PyResult<Vec<PySymbol>> {
        let p = self.inner.read().unwrap();
        let symbol_table_arc = p.get_symbol_table();
        let symbol_table = symbol_table_arc.read().unwrap();
        let symbols = symbol_table.get_symbols(&address.inner)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))?;
        
        let py_symbols = symbols
            .into_iter()
            .map(|s| PySymbol {
                name: s.get_name().to_string(),
                offset: address.inner.offset(),
            })
            .collect();
        Ok(py_symbols)
    }
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct PySymbol {
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub offset: i64,
}

#[pymethods]
impl PySymbol {
    fn __repr__(&self) -> String {
        format!("Symbol '{}' @ 0x{:x}", self.name, self.offset)
    }
}

pub struct PythonScriptRunner;

impl PythonScriptRunner {
    pub fn run_script(
        script_path: &str,
        program: Arc<RwLock<ProgramDB>>,
        current_address: Option<Address>,
    ) -> Result<(), String> {
        let script_content = fs::read_to_string(script_path)
            .map_err(|e| format!("Failed to read script file: {}", e))?;

        Python::initialize();

        Python::attach(|py| {
            let globals = PyDict::new(py);
            
            // Expose currentProgram
            let py_program = PyProgram { inner: program };
            globals.set_item("currentProgram", py_program)
                .map_err(|e| format!("Failed to set currentProgram: {:?}", e))?;

            // Expose currentAddress if present
            if let Some(addr) = current_address {
                let py_addr = PyAddress { inner: addr };
                globals.set_item("currentAddress", py_addr)
                    .map_err(|e| format!("Failed to set currentAddress: {:?}", e))?;
            } else {
                globals.set_item("currentAddress", py.None())
                    .map_err(|e| format!("Failed to set currentAddress: {:?}", e))?;
            }

            let c_str = CString::new(script_content)
                .map_err(|e| format!("Script content has null byte: {:?}", e))?;

            // Execute the script
            py.run(c_str.as_c_str(), Some(&globals), None)
                .map_err(|e| {
                    format!("Python script failed: {:?}", e)
                })?;

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::ProgramDB;
    use crate::program::model::address::{Address, DefaultAddressFactory};
    use crate::program::model::address::factory::AddressFactory;
    use crate::program::model::lang::sleigh::SleighLanguage;
    use crate::program::model::pcode::PackedDecode;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_python_script_execution() {
        // Build mock language and address factory
        let mut data = vec![];
        // <sleigh version="4" bigendian="false">
        data.extend_from_slice(&[0x60, 0xA1, 0xE0, 0xA2, 0x21, 4, 0xE0, 0xA3, 0x10]);
        // <spaces defaultspace="ram">
        data.extend_from_slice(&[0x60, 0xA2, 0xE0, 0xA9, 0x71, 3, b'r', b'a', b'm']);
        // <space_other/>
        data.extend_from_slice(&[0x60, 0xAD, 0xA0, 0xAD]);
        // <space name="ram" size="4" index="1" delay="1"/>
        data.extend_from_slice(&[
            0x60, 0xA5, 0xCC, 0x71, 3, b'r', b'a', b'm', 0xCF, 0x21, 4, 0xC9, 0x21, 1, 0xE0, 0xAA,
            0x21, 1, 0xA0, 0xA5,
        ]);
        // </spaces>
        data.extend_from_slice(&[0xA0, 0x80 | 34]);
        // <symbol_table scopesize="1" symbolsize="0">
        data.extend_from_slice(&[0x60, 0xA6, 0xE0, 0xAD, 0x21, 1, 0xE0, 0xAE, 0x21, 0]);
        // <scope id="0" parent="0"/>
        data.extend_from_slice(&[0x56, 0xC3, 0x41, 0, 0xD6, 0x41, 0, 0x96]);
        // </symbol_table>
        data.extend_from_slice(&[0xA0, 0x80 | 38]);
        // </sleigh>
        data.extend_from_slice(&[0xA0, 0x80 | 33]);

        let factory = Arc::new(DefaultAddressFactory::new(vec![]));
        let decoder = PackedDecode::new(factory, data);
        let language = Arc::new(SleighLanguage::decode(&decoder, "test".to_string()).unwrap());
        let program = Arc::new(RwLock::new(ProgramDB::new("test_prog".to_string(), language.clone()).unwrap()));

        let space = language
            .get_address_factory()
            .get_address_space_by_name("ram")
            .unwrap();
        let addr = Address::new(space, 0x1000);

        // Write a temp python script
        let mut tmp_file = NamedTempFile::new().unwrap();
        let python_code = r#"
print(f"Running script on program: {currentProgram.get_name()}")
currentProgram.create_label(currentAddress, "python_label")
symbols = currentProgram.get_symbols(currentAddress)
print(f"Created symbols: {symbols}")
assert len(symbols) == 1
assert symbols[0].name == "python_label"
"#;
        write!(tmp_file, "{}", python_code).unwrap();

        PythonScriptRunner::run_script(
            tmp_file.path().to_str().unwrap(),
            program.clone(),
            Some(addr.clone()),
        ).unwrap();

        // Verify that the label was created in the program
        let symbol_table_arc = program.read().unwrap().get_symbol_table();
        let symbol_table = symbol_table_arc.read().unwrap();
        let symbols = symbol_table.get_symbols(&addr).unwrap();
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].get_name(), "python_label");
    }
}
