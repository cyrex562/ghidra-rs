use crate::feature::bsim::query::description::DatabaseInformation;
use std::fmt;

/// Encapsulates connection and metadata information for a BSim database.
///
/// Pairs a server URL with the database metadata (name, owner, versioning, etc.).
///
/// Port of `ghidra.features.bsim.query.facade.DatabaseInfo`.
#[derive(Debug, Clone, PartialEq)]
pub struct DatabaseInfo {
    pub server_url: String,
    pub database_information: DatabaseInformation,
}

impl DatabaseInfo {
    pub fn new(server_url: String, database_information: DatabaseInformation) -> Self {
        Self { server_url, database_information }
    }

    pub fn get_server_url(&self) -> &str {
        &self.server_url
    }

    pub fn get_name(&self) -> Option<&str> {
        self.database_information.databasename.as_deref()
    }

    pub fn get_owner(&self) -> Option<&str> {
        self.database_information.owner.as_deref()
    }

    pub fn get_description(&self) -> Option<&str> {
        self.database_information.description.as_deref()
    }

    pub fn get_version(&self) -> String {
        format!("{}.{}", self.database_information.major, self.database_information.minor)
    }

    pub fn is_read_only(&self) -> bool {
        self.database_information.readonly
    }
}

impl fmt::Display for DatabaseInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Database: {}\n\tName: {}\n\tOwner: {}\n\tVersion: {}\n\tDescription: {}",
            self.server_url,
            self.get_name().unwrap_or(""),
            self.get_owner().unwrap_or(""),
            self.get_version(),
            self.get_description().unwrap_or("")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_getters() {
        let db_info = DatabaseInformation::new();
        let mut db_info = db_info.clone();
        db_info.databasename = Some("TestDB".to_string());
        db_info.owner = Some("TestOwner".to_string());
        db_info.description = Some("TestDesc".to_string());
        db_info.major = 1;
        db_info.minor = 2;
        db_info.readonly = true;

        let info = DatabaseInfo::new("http://localhost:8080".to_string(), db_info);

        assert_eq!(info.get_server_url(), "http://localhost:8080");
        assert_eq!(info.get_name(), Some("TestDB"));
        assert_eq!(info.get_owner(), Some("TestOwner"));
        assert_eq!(info.get_description(), Some("TestDesc"));
        assert_eq!(info.get_version(), "1.2");
        assert!(info.is_read_only());
    }

    #[test]
    fn test_getters_with_none_fields() {
        let db_info = DatabaseInformation::new();
        let mut db_info = db_info.clone();
        db_info.databasename = None;
        db_info.owner = None;
        db_info.description = None;

        let info = DatabaseInfo::new("http://localhost:8080".to_string(), db_info);

        assert_eq!(info.get_name(), None);
        assert_eq!(info.get_owner(), None);
        assert_eq!(info.get_description(), None);
    }

    #[test]
    fn test_get_version() {
        let mut db_info = DatabaseInformation::new();
        db_info.major = 2;
        db_info.minor = 5;

        let info = DatabaseInfo::new("http://localhost:8080".to_string(), db_info);
        assert_eq!(info.get_version(), "2.5");
    }

    #[test]
    fn test_is_read_only() {
        let mut db_info = DatabaseInformation::new();
        db_info.readonly = false;
        let mut info = DatabaseInfo::new("http://localhost:8080".to_string(), db_info);
        assert!(!info.is_read_only());

        info.database_information.readonly = true;
        assert!(info.is_read_only());
    }

    #[test]
    fn test_display_with_all_fields() {
        let mut db_info = DatabaseInformation::new();
        db_info.databasename = Some("MyDB".to_string());
        db_info.owner = Some("Alice".to_string());
        db_info.description = Some("Test database".to_string());
        db_info.major = 3;
        db_info.minor = 4;

        let info = DatabaseInfo::new("http://example.com:9000".to_string(), db_info);
        let s = info.to_string();

        assert!(s.contains("Database: http://example.com:9000"));
        assert!(s.contains("Name: MyDB"));
        assert!(s.contains("Owner: Alice"));
        assert!(s.contains("Version: 3.4"));
        assert!(s.contains("Description: Test database"));
    }

    #[test]
    fn test_display_with_none_fields() {
        let mut db_info = DatabaseInformation::new();
        db_info.databasename = None;
        db_info.owner = None;
        db_info.description = None;

        let info = DatabaseInfo::new("http://example.com".to_string(), db_info);
        let s = info.to_string();

        assert!(s.contains("Database: http://example.com"));
        assert!(s.contains("Name: "));
        assert!(s.contains("Owner: "));
        assert!(s.contains("Description: "));
    }

    #[test]
    fn test_clone_and_eq() {
        let mut db_info = DatabaseInformation::new();
        db_info.databasename = Some("TestDB".to_string());
        let info1 = DatabaseInfo::new("http://localhost".to_string(), db_info.clone());
        let info2 = info1.clone();

        assert_eq!(info1, info2);
    }

    #[test]
    fn test_equality_different_servers() {
        let db_info = DatabaseInformation::new();
        let info1 = DatabaseInfo::new("http://localhost".to_string(), db_info.clone());
        let info2 = DatabaseInfo::new("http://other".to_string(), db_info);

        assert_ne!(info1, info2);
    }
}
