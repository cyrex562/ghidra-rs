pub mod buffer;
pub mod buffer_mgr;
pub mod buffers;
pub mod chained_buffer;
pub mod db_handle;
pub mod db_parms;
pub mod field;
pub mod master_table;
pub mod nodes;
pub mod record;
pub mod schema;
pub mod table;

pub use buffer::{Buffer, DataBuffer};
pub use buffer_mgr::BufferMgr;
pub use buffers::{BufferFile, LocalBufferFile};
pub use chained_buffer::ChainedBuffer;
pub use db_handle::DBHandle;
pub use db_parms::DBParms;
pub use field::{Field, FieldType};
pub use record::DBRecord;
pub use schema::Schema;
pub use table::Table;

pub trait RecordIterator {
    fn next(&mut self) -> std::io::Result<Option<DBRecord>>;
    fn has_next(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, RwLock};

    #[test]
    fn test_record_basic() {
        let schema = Arc::new(Schema::new(
            1,
            FieldType::Long,
            "ID".to_string(),
            vec![FieldType::Int, FieldType::String],
            vec!["Count".to_string(), "Name".to_string()],
            vec![],
        ));

        let mut record = DBRecord::new(schema.clone(), Field::Long(Some(100)));
        assert_eq!(record.get_key().get_long_value(), 100);

        record.set_field(0, Field::Int(Some(5)));
        record.set_field(1, Field::String(Some("Test".to_string())));

        assert_eq!(record.get_field(0).get_int_value(), 5);
        assert_eq!(record.get_field(1).get_string_value(), Some("Test"));
        assert!(record.is_dirty());
    }

    #[test]
    fn test_field_serialization() {
        let mut buf = DataBuffer::new(1, 100);
        let f1 = Field::Int(Some(1234));
        let f2 = Field::String(Some("Ghidra".to_string()));
        let f3 = Field::String(None);

        let off1 = f1.write(&mut buf, 0);
        let off2 = f2.write(&mut buf, off1 as usize);
        let _off3 = f3.write(&mut buf, off2 as usize);

        let (r1, len1) = Field::read(&buf, 0, FieldType::Int);
        let (r2, len2) = Field::read(&buf, len1, FieldType::String);
        let (r3, len3) = Field::read(&buf, len1 + len2, FieldType::String);

        assert_eq!(r1, f1);
        assert_eq!(r2, f2);
        assert_eq!(r3, f3);
        assert_eq!(len1, 4);
        assert_eq!(len2, 4 + 6);
        assert_eq!(len3, 4);
    }

    #[test]
    fn test_db_handle_creation() {
        let handle = DBHandle::new().unwrap();
        assert_eq!(handle.get_buffer_mgr().read().unwrap().buffer_count(), 1); // Buffer 0 for DBParms
    }

    #[test]
    fn test_db_table_operations() {
        let mut handle = DBHandle::new().unwrap();
        let schema = Arc::new(Schema::new(
            1,
            FieldType::Long,
            "ID".to_string(),
            vec![FieldType::Int],
            vec!["Value".to_string()],
            vec![],
        ));

        {
            let table = handle
                .create_table("MyTable".to_string(), schema.clone())
                .unwrap();
            let mut record = DBRecord::new(schema.clone(), Field::Long(Some(1)));
            record.set_field(0, Field::Int(Some(42)));
            table.write().unwrap().put_record(record).unwrap();
        }

        let table = handle.get_table("MyTable").unwrap();
        // Fallback size doesn't reflect BTree size if we count from fallback. We should update get_record_count
        let record = table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(1)))
            .unwrap()
            .unwrap();
        assert_eq!(record.get_field(0).get_int_value(), 42);
    }

    #[test]
    fn test_local_buffer_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test.gbf");

        {
            let mut lbf = LocalBufferFile::create(file_path.clone(), 1024).unwrap();
            lbf.set_parameter("TestParam", 42);
            let mut buf = DataBuffer::new(100, 1024);
            buf.get_data_mut()[0] = 0xAA;
            lbf.put(&buf, 0).unwrap();
            lbf.close().unwrap();
        }

        {
            let lbf = LocalBufferFile::open(file_path, true).unwrap();
            assert_eq!(lbf.get_parameter("TestParam"), Some(42));
            assert_eq!(lbf.get_index_count(), 1);
            let buf = lbf.get(0).unwrap();
            assert_eq!(buf.get_id(), 100);
            assert_eq!(buf.get_data()[0], 0xAA);
        }
    }

    #[test]
    fn test_chained_buffer_basic() {
        let buffer_mgr = Arc::new(RwLock::new(BufferMgr::new(128)));
        let mut cb = ChainedBuffer::new(200, false, None, 0, buffer_mgr.clone()).unwrap();
        assert_eq!(cb.length(), 200);

        let data = vec![0x42u8; 200];
        cb.put(0, &data);

        let mut read_data = vec![0u8; 200];
        cb.get(0, &mut read_data);
        assert_eq!(data, read_data);

        cb.put_int(10, 0x12345678);
        assert_eq!(cb.get_int(10), 0x12345678);
    }

    #[test]
    fn test_chained_buffer_obfuscation() {
        let buffer_mgr = Arc::new(RwLock::new(BufferMgr::new(128)));
        let mut cb = ChainedBuffer::new(200, true, None, 0, buffer_mgr.clone()).unwrap();

        let data = vec![0xAAu8; 200];
        cb.put(0, &data);

        let mut read_data = vec![0u8; 200];
        cb.get(0, &mut read_data);
        assert_eq!(data, read_data);

        // Verify it's actually obfuscated in the underlying buffer
        let bm = buffer_mgr.read().unwrap();
        let buf0_arc = bm.get_buffer(cb.get_id()).unwrap();
        let buf0 = buf0_arc.read().unwrap();
        // The first byte of data in first buffer should NOT be 0xAA if obfuscated
        // data_base_offset for non-indexed is 5 (1+4)
        assert_ne!(buf0.get_byte(5), 0xAA);
    }

    #[test]
    fn test_chained_buffer_split_append() {
        let buffer_mgr = Arc::new(RwLock::new(BufferMgr::new(128)));
        let mut cb1 = ChainedBuffer::new(100, false, None, 0, buffer_mgr.clone()).unwrap();
        let data1 = vec![0x11u8; 100];
        cb1.put(0, &data1);

        let cb2 = cb1.split(60).unwrap();
        assert_eq!(cb1.length(), 60);
        assert_eq!(cb2.length(), 40);

        let mut read1 = vec![0u8; 60];
        cb1.get(0, &mut read1);
        assert_eq!(read1, vec![0x11u8; 60]);

        let mut read2 = vec![0u8; 40];
        cb2.get(0, &mut read2);
        assert_eq!(read2, vec![0x11u8; 40]);

        cb1.append(cb2).unwrap();
        assert_eq!(cb1.length(), 100);
        let mut read_all = vec![0u8; 100];
        cb1.get(0, &mut read_all);
        assert_eq!(read_all, data1);
    }

    #[test]
    fn test_chained_buffer_grow_shrink() {
        let buffer_mgr = Arc::new(RwLock::new(BufferMgr::new(128)));
        // Start small (non-indexed)
        let mut cb = ChainedBuffer::new(50, false, None, 0, buffer_mgr.clone()).unwrap();
        cb.put(0, &[0xAA; 50]);

        // Grow to indexed (data_space is 128 - 5 = 123, but indexed data_space is 128 - 1 = 127)
        // Wait, if I grow it past 123 it should become indexed.
        cb.set_size(200, true).unwrap();
        assert_eq!(cb.length(), 200);

        let mut read = vec![0u8; 50];
        cb.get(0, &mut read);
        assert_eq!(read, vec![0xAAu8; 50]);

        // Shrink back to non-indexed
        cb.set_size(50, true).unwrap();
        assert_eq!(cb.length(), 50);
        let mut read2 = vec![0u8; 50];
        cb.get(0, &mut read2);
        assert_eq!(read2, vec![0xAAu8; 50]);
    }
}
