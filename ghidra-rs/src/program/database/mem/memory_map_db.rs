use crate::framework::db::record::DBRecord;
use crate::framework::db::{DBHandle, Field, FieldType, Schema, Table};
use crate::program::database::map::AddressMapDB;
use crate::program::database::mem::memory_block_db::MemoryBlockDB;
use crate::program::model::address::Address;
use crate::program::model::mem::{Memory, MemoryAccessException, MemoryBlock};
use std::io;
use std::sync::{Arc, RwLock};

pub const MEM_BLOCK_TABLE_NAME: &str = "Memory Blocks";
pub const SUB_BLOCK_TABLE_NAME: &str = "Sub Memory Blocks";

pub struct MemoryMapDB {
    db_handle: Arc<RwLock<DBHandle>>,
    addr_map: Arc<RwLock<AddressMapDB>>,
    is_big_endian: bool,
    mem_block_table: Arc<RwLock<Table>>,
    sub_block_table: Arc<RwLock<Table>>,
    blocks: Vec<Arc<RwLock<dyn MemoryBlock>>>,
}

impl MemoryMapDB {
    pub fn new(
        db_handle: Arc<RwLock<DBHandle>>,
        addr_map: Arc<RwLock<AddressMapDB>>,
        is_big_endian: bool,
    ) -> io::Result<Self> {
        let block_schema = Schema::new(
            3,
            FieldType::Long,
            "Key".to_string(),
            vec![
                FieldType::String, // Name
                FieldType::String, // Comments
                FieldType::String, // Source Name
                FieldType::Byte,   // Flags
                FieldType::Long,   // Start Address
                FieldType::Long,   // Length
                FieldType::Int,    // Segment
            ],
            vec![
                "Name".to_string(),
                "Comments".to_string(),
                "Source Name".to_string(),
                "Flags".to_string(),
                "Start Address".to_string(),
                "Length".to_string(),
                "Segment".to_string(),
            ],
            vec![],
        );

        let sub_block_schema = Schema::new(
            3,
            FieldType::Long,
            "Key".to_string(),
            vec![
                FieldType::Long, // Parent ID
                FieldType::Byte, // Type
                FieldType::Long, // Length
                FieldType::Long, // Starting Offset
                FieldType::Int,  // Source ID
                FieldType::Long, // Source Address/Offset
            ],
            vec![
                "Parent ID".to_string(),
                "Type".to_string(),
                "Length".to_string(),
                "Starting Offset".to_string(),
                "Source ID".to_string(),
                "Source Address/Offset".to_string(),
            ],
            vec![],
        );

        let (mem_block_table, sub_block_table) = {
            let mut handle = db_handle.write().unwrap();
            let table1 =
                handle.create_table(MEM_BLOCK_TABLE_NAME.to_string(), Arc::new(block_schema))?;
            let table2 = handle
                .create_table(SUB_BLOCK_TABLE_NAME.to_string(), Arc::new(sub_block_schema))?;
            (table1, table2)
        };

        Ok(Self {
            db_handle,
            addr_map,
            is_big_endian,
            mem_block_table,
            sub_block_table,
            blocks: Vec::new(),
        })
    }

    pub fn create_block(
        &mut self,
        name: String,
        start: Address,
        size: u64,
        flags: u8,
    ) -> io::Result<Arc<RwLock<MemoryBlockDB>>> {
        let mut table = self.mem_block_table.write().unwrap();
        let key = table.get_next_key();
        let mut record = DBRecord::new(table.get_schema(), Field::Long(Some(key)));

        let addr_key = self.addr_map.read().unwrap().get_key(&start, true);

        record.set_string(0, Some(name));
        record.set_string(1, None); // Comments
        record.set_string(2, None); // Source Name
        record.set_byte(3, flags as i8);
        record.set_long(4, addr_key);
        record.set_long(5, size as i64);
        record.set_int(6, 0); // Segment

        table.put_record(record.clone())?;

        let block = Arc::new(RwLock::new(MemoryBlockDB::new(
            record,
            self.addr_map.clone(),
        )));
        self.blocks
            .push(block.clone() as Arc<RwLock<dyn MemoryBlock>>);

        Ok(block)
    }

    pub fn add_block(&mut self, block: Arc<RwLock<dyn MemoryBlock>>) {
        self.blocks.push(block);
    }
}

impl Memory for MemoryMapDB {
    fn is_big_endian(&self) -> bool {
        self.is_big_endian
    }

    fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
        for block in &self.blocks {
            let b = block.read().unwrap();
            if addr >= &b.get_start() && addr <= &b.get_end() {
                return b.get_byte(addr);
            }
        }
        Err(MemoryAccessException(format!(
            "Address out of bounds: {:?}",
            addr
        )))
    }

    fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
        let mut total_read = 0;
        let mut cur_addr = addr.clone();
        let mut cur_dest = dest;

        for block in &self.blocks {
            let b = block.read().unwrap();
            if cur_addr >= b.get_start() && cur_addr <= b.get_end() {
                let read = b.get_bytes(&cur_addr, cur_dest);
                total_read += read;
                if read == cur_dest.len() {
                    break;
                }

                // Safe slicing without moving issues
                let (_, rest) = cur_dest.split_at_mut(read);
                cur_dest = rest;

                cur_addr = cur_addr.add(read as i64).unwrap_or(cur_addr.clone());
            }
        }
        total_read
    }

    fn set_bytes(&mut self, addr: &Address, source: &[u8]) -> Result<(), MemoryAccessException> {
        for block in &self.blocks {
            let mut b = block.write().unwrap();
            if addr >= &b.get_start() && addr <= &b.get_end() {
                b.set_bytes(addr, source)?;
                return Ok(());
            }
        }
        Err(MemoryAccessException(format!(
            "Address out of bounds: {:?}",
            addr
        )))
    }
}
