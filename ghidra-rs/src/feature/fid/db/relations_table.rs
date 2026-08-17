use crate::feature::fid::hash::fid_hash_quad::FidHashQuad;
use crate::feature::seam_stubs::FunctionRecord;
use crate::framework::db::db_handle::DBHandle;
use crate::framework::db::field::{Field, FieldType};
use crate::framework::db::record::DBRecord;
use crate::framework::db::schema::Schema;
use crate::framework::db::table::Table;
use crate::generic::hash::FNV1a64MessageDigest;

use super::relation_type::RelationType;

use std::io;
use std::sync::{Arc, RwLock};

/// Generates the hash smash for a superior id / inferior full hash pair.
///
/// Java: `FidDBUtils.generateSuperiorFullHashSmash(FunctionRecord, FunctionRecord)`.
/// `FidDBUtils` is not itself ported (it is a stateless static utility), so its two-line bodies
/// are mirrored here directly rather than through a stub trait.
fn generate_superior_full_hash_smash(
    superior_function: &dyn FunctionRecord,
    inferior_function: &dyn FunctionRecord,
) -> i64 {
    let hash_value =
        superior_function.get_key().wrapping_mul(FNV1a64MessageDigest::FNV_64_PRIME);
    hash_value ^ inferior_function.full_hash()
}

/// Java: `FidDBUtils.generateInferiorFullHashSmash(FunctionRecord, FunctionRecord)`.
fn generate_inferior_full_hash_smash(
    superior_function: &dyn FunctionRecord,
    inferior_function: &dyn FunctionRecord,
) -> i64 {
    let hash_value =
        inferior_function.get_key().wrapping_mul(FNV1a64MessageDigest::FNV_64_PRIME);
    hash_value ^ superior_function.full_hash()
}

/// Java: `FidDBUtils.generateSuperiorFullHashSmash(FunctionRecord, FidHashQuad)`, the overload
/// used when only a hash quad (not a resolved `FunctionRecord`) is known for the inferior side.
fn generate_superior_full_hash_smash_quad(
    superior_function: &dyn FunctionRecord,
    inferior_function: &dyn FidHashQuad,
) -> i64 {
    let hash_value =
        superior_function.get_key().wrapping_mul(FNV1a64MessageDigest::FNV_64_PRIME);
    hash_value ^ inferior_function.full_hash()
}

/// Java: `FidDBUtils.generateInferiorFullHashSmash(FidHashQuad, FunctionRecord)`, the overload
/// used when only a hash quad is known for the superior side.
fn generate_inferior_full_hash_smash_quad(
    superior_function: &dyn FidHashQuad,
    inferior_function: &dyn FunctionRecord,
) -> i64 {
    let hash_value =
        inferior_function.get_key().wrapping_mul(FNV1a64MessageDigest::FNV_64_PRIME);
    hash_value ^ superior_function.full_hash()
}

/// Tracks caller/callee (superior/inferior) relationships between functions in the FID database.
///
/// Port of `ghidra.feature.fid.db.RelationsTable`.
pub struct RelationsTable {
    inferior_table: Arc<RwLock<Table>>,
    superior_table: Arc<RwLock<Table>>,
}

impl RelationsTable {
    const INFERIOR_RELATIONS_TABLE: &'static str = "Inferior Table";
    const SUPERIOR_RELATIONS_TABLE: &'static str = "Superior Table";

    /// Mirrors `LibrariesTable.VERSION` (Java: `db/LibrariesTable.java:40`). `LibrariesTable` is
    /// not yet ported, so the schema version constant is duplicated here, the same way
    /// [`super::library_record`] mirrors `LibrariesTable`'s column layout.
    const SCHEMA_VERSION: i32 = 6;

    fn schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            Self::SCHEMA_VERSION,
            FieldType::Long,
            "Relation Smash".to_string(),
            vec![],
            vec![],
            vec![],
        ))
    }

    /// Attaches to the relations tables in an already-populated database.
    ///
    /// Java: `RelationsTable(DBHandle handle)`.
    pub fn new(handle: &DBHandle) -> io::Result<Self> {
        let inferior_table = handle.get_table(Self::INFERIOR_RELATIONS_TABLE).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "Inferior Table not found")
        })?;
        let superior_table = handle.get_table(Self::SUPERIOR_RELATIONS_TABLE).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "Superior Table not found")
        })?;
        Ok(Self { inferior_table, superior_table })
    }

    /// Creates the inferior and superior relations tables in a fresh database.
    ///
    /// Java: `static void createTables(DBHandle handle)`.
    pub fn create_tables(handle: &mut DBHandle) -> io::Result<()> {
        handle.create_table(Self::INFERIOR_RELATIONS_TABLE.to_string(), Self::schema())?;
        handle.create_table(Self::SUPERIOR_RELATIONS_TABLE.to_string(), Self::schema())?;
        Ok(())
    }

    /// Creates a relation from caller (superior) to callee (inferior) with the designated
    /// relation type.
    ///
    /// Java: `void createRelation(FunctionRecord, FunctionRecord, RelationType)`.
    pub fn create_relation(
        &self,
        superior_function: &dyn FunctionRecord,
        inferior_function: &dyn FunctionRecord,
        relation_type: RelationType,
    ) -> io::Result<()> {
        let superior_key =
            generate_superior_full_hash_smash(superior_function, inferior_function);
        let superior_record = DBRecord::new(Self::schema(), Field::Long(Some(superior_key)));
        self.superior_table.write().unwrap().put_record(superior_record)?;

        if relation_type != RelationType::InterLibraryCall {
            let inferior_key =
                generate_inferior_full_hash_smash(superior_function, inferior_function);
            let inferior_record = DBRecord::new(Self::schema(), Field::Long(Some(inferior_key)));
            self.inferior_table.write().unwrap().put_record(inferior_record)?;
        }
        Ok(())
    }

    /// Creates only an inferior relation, used for special distinguishing parent relationships
    /// with common functions.
    ///
    /// Java: `void createInferiorRelation(FunctionRecord, FunctionRecord)`.
    pub fn create_inferior_relation(
        &self,
        superior_function: &dyn FunctionRecord,
        inferior_function: &dyn FunctionRecord,
    ) -> io::Result<()> {
        let inferior_key =
            generate_inferior_full_hash_smash(superior_function, inferior_function);
        let inferior_record = DBRecord::new(Self::schema(), Field::Long(Some(inferior_key)));
        self.inferior_table.write().unwrap().put_record(inferior_record)?;
        Ok(())
    }

    /// Returns true if a relation exists between a superior (caller) function and a full hash
    /// representing the inferior (callee) function.
    ///
    /// Java: `boolean getSuperiorFullRelation(FunctionRecord, FidHashQuad)`.
    pub fn get_superior_full_relation(
        &self,
        superior_function: &dyn FunctionRecord,
        inferior_function: &dyn FidHashQuad,
    ) -> io::Result<bool> {
        let superior_key =
            generate_superior_full_hash_smash_quad(superior_function, inferior_function);
        let record = self
            .superior_table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(superior_key)))?;
        Ok(record.is_some())
    }

    /// Returns true if a relation exists between an inferior (callee) function and a full hash
    /// representing the superior (caller) function.
    ///
    /// Java: `boolean getInferiorFullRelation(FidHashQuad, FunctionRecord)`.
    pub fn get_inferior_full_relation(
        &self,
        superior_function: &dyn FidHashQuad,
        inferior_function: &dyn FunctionRecord,
    ) -> io::Result<bool> {
        let inferior_key =
            generate_inferior_full_hash_smash_quad(superior_function, inferior_function);
        let record = self
            .inferior_table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(inferior_key)))?;
        Ok(record.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeFunctionRecord {
        key: i64,
        full_hash: i64,
    }

    impl FidHashQuad for FakeFunctionRecord {
        fn code_unit_size(&self) -> i16 {
            0
        }
        fn full_hash(&self) -> i64 {
            self.full_hash
        }
        fn specific_hash_additional_size(&self) -> i8 {
            0
        }
        fn specific_hash(&self) -> i64 {
            0
        }
    }

    impl FunctionRecord for FakeFunctionRecord {
        fn get_key(&self) -> i64 {
            self.key
        }
        fn get_name(&self) -> String {
            format!("func_{}", self.key)
        }
        fn get_library_id(&self) -> i64 {
            1
        }
    }

    fn caller() -> FakeFunctionRecord {
        FakeFunctionRecord { key: 42, full_hash: 0x1234_5678_9abc_def0 }
    }

    fn callee() -> FakeFunctionRecord {
        FakeFunctionRecord { key: 99, full_hash: 0x0fed_cba9_8765_4321 }
    }

    #[test]
    fn hash_smash_matches_java_fnv1a64_prime_arithmetic() {
        // Java: hashValue = superiorFunction.getKey() * FNV1a64MessageDigest.FNV_64_PRIME;
        //       return hashValue ^ inferiorFunction.getFullHash();
        let caller = caller();
        let callee = callee();
        let expected =
            (caller.key.wrapping_mul(FNV1a64MessageDigest::FNV_64_PRIME)) ^ callee.full_hash;
        assert_eq!(generate_superior_full_hash_smash(&caller, &callee), expected);

        let expected_inferior =
            (callee.key.wrapping_mul(FNV1a64MessageDigest::FNV_64_PRIME)) ^ caller.full_hash;
        assert_eq!(generate_inferior_full_hash_smash(&caller, &callee), expected_inferior);
    }

    #[test]
    fn create_and_query_relation_round_trips() {
        let mut handle = DBHandle::new().expect("new db handle");
        RelationsTable::create_tables(&mut handle).expect("create tables");
        let table = RelationsTable::new(&handle).expect("attach to tables");

        let caller = caller();
        let callee = callee();

        table
            .create_relation(&caller, &callee, RelationType::DirectCall)
            .expect("create relation");

        assert!(table
            .get_superior_full_relation(&caller, &callee)
            .expect("query superior relation"));
        assert!(table
            .get_inferior_full_relation(&caller, &callee)
            .expect("query inferior relation"));

        let stranger = FakeFunctionRecord { key: 7, full_hash: 0xdead_beef };
        assert!(!table
            .get_superior_full_relation(&caller, &stranger)
            .expect("query missing superior relation"));
    }

    #[test]
    fn inter_library_call_skips_inferior_relation() {
        let mut handle = DBHandle::new().expect("new db handle");
        RelationsTable::create_tables(&mut handle).expect("create tables");
        let table = RelationsTable::new(&handle).expect("attach to tables");

        let caller = caller();
        let callee = callee();

        table
            .create_relation(&caller, &callee, RelationType::InterLibraryCall)
            .expect("create relation");

        assert!(table
            .get_superior_full_relation(&caller, &callee)
            .expect("query superior relation"));
        assert!(!table
            .get_inferior_full_relation(&caller, &callee)
            .expect("query inferior relation absent for inter-library call"));
    }

    #[test]
    fn create_inferior_relation_only_writes_inferior_table() {
        let mut handle = DBHandle::new().expect("new db handle");
        RelationsTable::create_tables(&mut handle).expect("create tables");
        let table = RelationsTable::new(&handle).expect("attach to tables");

        let caller = caller();
        let callee = callee();

        table
            .create_inferior_relation(&caller, &callee)
            .expect("create inferior relation");

        assert!(table
            .get_inferior_full_relation(&caller, &callee)
            .expect("query inferior relation"));
        assert!(!table
            .get_superior_full_relation(&caller, &callee)
            .expect("query superior relation absent"));
    }
}
