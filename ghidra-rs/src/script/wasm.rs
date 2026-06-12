use crate::program::database::ProgramDB;
use crate::program::model::address::Address;
use crate::program::model::symbol::{SourceType, SymbolTable};
use std::sync::{Arc, RwLock};
use wasmer::{imports, Function, Instance, Module, Store, FunctionEnv, FunctionEnvMut};

pub struct WasmEnv {
    pub program: Arc<RwLock<ProgramDB>>,
    pub current_addr: Option<Address>,
}

pub struct WasmPluginRunner;

impl WasmPluginRunner {
    pub fn run_plugin(
        wasm_bytes: &[u8],
        program: Arc<RwLock<ProgramDB>>,
        current_addr: Option<Address>,
    ) -> Result<(), String> {
        let mut store = Store::default();
        let module = Module::new(&store, wasm_bytes)
            .map_err(|e| format!("Failed to compile WASM: {:?}", e))?;

        let env = WasmEnv {
            program,
            current_addr,
        };
        let env_share = FunctionEnv::new(&mut store, env);

        // Define imports
        let import_object = imports! {
            "env" => {
                "create_label_at_offset" => Function::new_typed_with_env(&mut store, &env_share, |env_mut: FunctionEnvMut<WasmEnv>, offset: i64| {
                    let env = env_mut.data();
                    let program_arc = env.program.clone();
                    let current_addr = env.current_addr.clone();

                    if let Some(addr) = current_addr {
                        let p = program_arc.read().unwrap();
                        let space = addr.space();
                        let target_addr = Address::new(space.clone(), offset);
                        let symbol_table_arc = p.get_symbol_table();
                        let mut symbol_table = symbol_table_arc.write().unwrap();
                        let _ = symbol_table.create_label(&target_addr, "wasm_label", SourceType::UserDefined);
                    }
                })
            }
        };

        let instance = Instance::new(&mut store, &module, &import_object)
            .map_err(|e| format!("Failed to instantiate WASM: {:?}", e))?;

        let run_fn = instance.exports.get_function("ghidra_plugin_main")
            .map_err(|e| format!("Could not find ghidra_plugin_main in WASM module: {:?}", e))?;

        run_fn.call(&mut store, &[])
            .map_err(|e| format!("Error calling ghidra_plugin_main: {:?}", e))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::ProgramDB;
    use crate::program::model::address::factory::AddressFactory;
    use crate::program::model::address::{Address, DefaultAddressFactory};
    use crate::program::model::lang::sleigh::SleighLanguage;
    use crate::program::model::pcode::PackedDecode;

    #[test]
    fn test_wasm_plugin_execution() {
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

        // WAT code for the WASM module
        let wat_code = r#"
(module
  (import "env" "create_label_at_offset" (func $create_label (param i64)))
  (func (export "ghidra_plugin_main")
    (call $create_label (i64.const 4096))
  )
)
"#;
        let wasm_bytes = wasmer::wat2wasm(wat_code.as_bytes()).unwrap();

        WasmPluginRunner::run_plugin(
            &wasm_bytes,
            program.clone(),
            Some(addr.clone()),
        ).unwrap();

        // Verify that the label was created at offset 4096 (0x1000)
        let symbol_table_arc = program.read().unwrap().get_symbol_table();
        let symbol_table = symbol_table_arc.read().unwrap();
        let symbols = symbol_table.get_symbols(&addr).unwrap();
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].get_name(), "wasm_label");
    }
}
