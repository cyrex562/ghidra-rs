//! Port of `ghidra.features.bsim.query.client.IDSQLResolution`.
//!
//! Java's `IDSQLResolution` is an abstract class managing filter elements (`FilterTemplate`) that
//! need to be resolved (typically to a database id) before they can be converted to an SQL clause.
//! It carries two `long` fields (`id1`, `id2`) and one abstract method (`resolve`), with four
//! concrete subclasses (`Architecture`, `Compiler`, `ExeCategory`, `ExternalFunction`). Rust has no
//! field inheritance, so [`IDSQLResolutionBase`] holds the two ids and each concrete type embeds
//! it; [`IDSQLResolution`] declares the one abstract method and forwards id access to the embedded
//! base, mirroring the split used by
//! [`VtMarkupType`](crate::feature::vt::api::markuptype::vt_markup_type::VtMarkupType).
//!
//! `AbstractSQLFunctionDatabase` (the `resolve` parameter type) sits on the far side of a
//! dependency cycle and is not ported yet, so `resolve` speaks the placeholder trait
//! [`crate::feature::seam_stubs::AbstractSQLFunctionDatabase`] for it.

use crate::feature::seam_stubs::{AbstractSQLFunctionDatabase, ExecutableRecord};

/// The shared state of an [`IDSQLResolution`]: the ids resolved so far.
///
/// Port of the `id1`/`id2` fields of `ghidra.features.bsim.query.client.IDSQLResolution`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IDSQLResolutionBase {
    /// Java `id1`: first resolved id.
    pub id1: i64,
    /// Java `id2`: second resolved id.
    pub id2: i64,
}

impl IDSQLResolutionBase {
    /// Java's implicit `id1 = 0; id2 = 0;` default field initialization.
    pub fn new() -> Self {
        Self { id1: 0, id2: 0 }
    }
}

/// A filter element awaiting resolution (typically to a database id) before it can be converted to
/// an SQL clause.
///
/// Port of `ghidra.features.bsim.query.client.IDSQLResolution`.
pub trait IDSQLResolution {
    /// The shared ids (`id1`/`id2`) every resolution carries.
    fn base(&self) -> &IDSQLResolutionBase;

    /// Mutable access to the shared ids, for `resolve` implementations to write through.
    fn base_mut(&mut self) -> &mut IDSQLResolutionBase;

    /// Java: `id1`.
    fn id1(&self) -> i64 {
        self.base().id1
    }

    /// Java: `id2`.
    fn id2(&self) -> i64 {
        self.base().id2
    }

    /// Java: `resolve(AbstractSQLFunctionDatabase<?> columnDatabase, ExecutableRecord exe)`
    /// (abstract).
    fn resolve(
        &mut self,
        column_database: &dyn AbstractSQLFunctionDatabase,
        exe: &ExecutableRecord,
    ) -> std::io::Result<()>;
}

/// Resolves an architecture name string to its database id.
///
/// Port of `IDSQLResolution.Architecture`.
pub struct Architecture {
    base: IDSQLResolutionBase,
    /// Java `archName`: architecture name as a string.
    arch_name: String,
}

impl Architecture {
    /// Java: `Architecture(String nm)`.
    pub fn new(nm: impl Into<String>) -> Self {
        Self { base: IDSQLResolutionBase::new(), arch_name: nm.into() }
    }
}

impl IDSQLResolution for Architecture {
    fn base(&self) -> &IDSQLResolutionBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut IDSQLResolutionBase {
        &mut self.base
    }

    fn resolve(
        &mut self,
        column_database: &dyn AbstractSQLFunctionDatabase,
        _exe: &ExecutableRecord,
    ) -> std::io::Result<()> {
        if self.base.id1 == 0 {
            self.base.id1 = column_database.query_arch_string(&self.arch_name)?;
        }
        Ok(())
    }
}

/// Resolves a compiler name string to its database id.
///
/// Port of `IDSQLResolution.Compiler`.
pub struct Compiler {
    base: IDSQLResolutionBase,
    /// Java `compilerName`: compiler name as a string.
    compiler_name: String,
}

impl Compiler {
    /// Java: `Compiler(String nm)`.
    pub fn new(nm: impl Into<String>) -> Self {
        Self { base: IDSQLResolutionBase::new(), compiler_name: nm.into() }
    }
}

impl IDSQLResolution for Compiler {
    fn base(&self) -> &IDSQLResolutionBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut IDSQLResolutionBase {
        &mut self.base
    }

    fn resolve(
        &mut self,
        column_database: &dyn AbstractSQLFunctionDatabase,
        _exe: &ExecutableRecord,
    ) -> std::io::Result<()> {
        if self.base.id1 == 0 {
            self.base.id1 = column_database.query_compiler_string(&self.compiler_name)?;
        }
        Ok(())
    }
}

/// Resolves a category/value pair of strings to their database ids.
///
/// Port of `IDSQLResolution.ExeCategory`.
pub struct ExeCategory {
    base: IDSQLResolutionBase,
    /// Java `categoryString`: name of category as a string.
    category_string: String,
    /// Java `valueString`: value of category as a string.
    value_string: String,
}

impl ExeCategory {
    /// Java: `ExeCategory(String cat, String val)`.
    pub fn new(cat: impl Into<String>, val: impl Into<String>) -> Self {
        Self { base: IDSQLResolutionBase::new(), category_string: cat.into(), value_string: val.into() }
    }
}

impl IDSQLResolution for ExeCategory {
    fn base(&self) -> &IDSQLResolutionBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut IDSQLResolutionBase {
        &mut self.base
    }

    fn resolve(
        &mut self,
        column_database: &dyn AbstractSQLFunctionDatabase,
        _exe: &ExecutableRecord,
    ) -> std::io::Result<()> {
        if self.base.id1 == 0 {
            self.base.id1 = column_database.query_category_string(&self.category_string)?;
            self.base.id2 = column_database.query_category_string(&self.value_string)?;
        }
        Ok(())
    }
}

/// Resolves an external function, named by the executable and function name, to its database id.
///
/// Port of `IDSQLResolution.ExternalFunction`.
pub struct ExternalFunction {
    base: IDSQLResolutionBase,
    /// Java `exeName`: name of executable containing external function.
    exe_name: String,
    /// Java `funcName`: name of external function.
    func_name: String,
}

impl ExternalFunction {
    /// Java: `ExternalFunction(String exe, String func)`.
    pub fn new(exe: impl Into<String>, func: impl Into<String>) -> Self {
        Self { base: IDSQLResolutionBase::new(), exe_name: exe.into(), func_name: func.into() }
    }
}

impl IDSQLResolution for ExternalFunction {
    fn base(&self) -> &IDSQLResolutionBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut IDSQLResolutionBase {
        &mut self.base
    }

    /// Java catches `LSHException` and rewraps it as a `SQLException`; both collapse to
    /// `io::Error` here, so the `?` below already reproduces that behavior.
    fn resolve(
        &mut self,
        column_database: &dyn AbstractSQLFunctionDatabase,
        exe: &ExecutableRecord,
    ) -> std::io::Result<()> {
        if self.base.id1 == 0 {
            self.base.id1 = column_database.recover_external_function_id(
                &self.exe_name,
                &self.func_name,
                exe.get_architecture(),
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::bsim::query::b_sim_server_info::BSimServerInfo;
    use crate::feature::bsim::query::description::DatabaseInformation;
    use crate::feature::bsim::query::function_database::{BSimError, ConnectionType, ErrorCategory, Status};
    use crate::feature::bsim::query::protocol::{BSimQuery, QueryResponseRecord};
    use std::sync::Arc;

    /// A minimal `AbstractSQLFunctionDatabase` that resolves every string to a fixed id, or fails
    /// once (mimicking a not-found lookup) when told to.
    struct MockColumnDatabase {
        next_id: std::sync::atomic::AtomicI64,
        fail: bool,
    }

    impl MockColumnDatabase {
        fn new() -> Self {
            Self { next_id: std::sync::atomic::AtomicI64::new(100), fail: false }
        }

        fn failing() -> Self {
            Self { next_id: std::sync::atomic::AtomicI64::new(100), fail: true }
        }

        fn allocate(&self) -> std::io::Result<i64> {
            if self.fail {
                return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "not found"));
            }
            Ok(self.next_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst))
        }
    }

    impl crate::feature::bsim::query::function_database::FunctionDatabase for MockColumnDatabase {
        fn get_status(&self) -> Status {
            Status::Ready
        }

        fn get_connection_type(&self) -> ConnectionType {
            ConnectionType::UnencryptedNoAuthentication
        }

        fn get_user_name(&self) -> String {
            "mock".to_string()
        }

        fn get_lsh_vector_factory(&self) -> Arc<crate::generic::seam_stubs::LSHVectorFactory> {
            panic!("not used by these tests")
        }

        fn get_info(&self) -> Option<DatabaseInformation> {
            None
        }

        fn compare_layout(&self) -> i32 {
            0
        }

        fn get_server_info(&self) -> BSimServerInfo {
            panic!("not used by these tests")
        }

        fn get_url_string(&self) -> String {
            "jdbc:mock://localhost".to_string()
        }

        fn initialize(&self) -> bool {
            true
        }

        fn close(&self) {}

        fn get_last_error(&self) -> BSimError {
            BSimError::new(ErrorCategory::Nonfatal, "none")
        }

        fn query(&self, _query: &dyn BSimQuery) -> Option<Box<dyn QueryResponseRecord>> {
            None
        }
    }

    impl crate::feature::bsim::query::sql_function_database::SQLFunctionDatabase for MockColumnDatabase {
        fn format_bit_and_sql(&self, v1: &str, v2: &str) -> String {
            format!("({} & {})", v1, v2)
        }
    }

    impl AbstractSQLFunctionDatabase for MockColumnDatabase {
        fn query_arch_string(&self, _value: &str) -> std::io::Result<i64> {
            self.allocate()
        }

        fn query_compiler_string(&self, _value: &str) -> std::io::Result<i64> {
            self.allocate()
        }

        fn query_category_string(&self, _value: &str) -> std::io::Result<i64> {
            self.allocate()
        }

        fn recover_external_function_id(
            &self,
            _exe_name: &str,
            _func_name: &str,
            _rep_arch: &str,
        ) -> std::io::Result<i64> {
            self.allocate()
        }
    }

    fn exe() -> ExecutableRecord {
        ExecutableRecord::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "helloworld", "x86:LE:64:default", "gcc")
    }

    #[test]
    fn architecture_resolves_id1_once() {
        let db = MockColumnDatabase::new();
        let mut resolution = Architecture::new("x86:LE:64:default");
        assert_eq!(resolution.id1(), 0);

        resolution.resolve(&db, &exe()).unwrap();
        assert_eq!(resolution.id1(), 100);
        assert_eq!(resolution.id2(), 0);

        // Java: `if (id1 == 0)` guards a second resolve from re-querying.
        resolution.resolve(&db, &exe()).unwrap();
        assert_eq!(resolution.id1(), 100);
    }

    #[test]
    fn compiler_resolves_id1() {
        let db = MockColumnDatabase::new();
        let mut resolution = Compiler::new("gcc");
        resolution.resolve(&db, &exe()).unwrap();
        assert_eq!(resolution.id1(), 100);
    }

    #[test]
    fn exe_category_resolves_both_ids() {
        let db = MockColumnDatabase::new();
        let mut resolution = ExeCategory::new("Compiler", "gcc");
        resolution.resolve(&db, &exe()).unwrap();
        assert_eq!(resolution.id1(), 100);
        assert_eq!(resolution.id2(), 101);
    }

    #[test]
    fn external_function_resolves_using_the_executables_architecture() {
        let db = MockColumnDatabase::new();
        let mut resolution = ExternalFunction::new("libc.so", "malloc");
        resolution.resolve(&db, &exe()).unwrap();
        assert_eq!(resolution.id1(), 100);
    }

    #[test]
    fn external_function_propagates_the_lookup_failure() {
        let db = MockColumnDatabase::failing();
        let mut resolution = ExternalFunction::new("missing.so", "malloc");
        assert!(resolution.resolve(&db, &exe()).is_err());
        // Java leaves id1 == 0 when the lookup throws before assignment.
        assert_eq!(resolution.id1(), 0);
    }
}
