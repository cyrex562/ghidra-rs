use std::cmp::Ordering;
use std::fmt;

/// Name associated with the anonymous user.
pub const ANONYMOUS_USERNAME: &str = "-anonymous-";

const PERMISSION_LABELS: [&str; 3] = ["read-only", "write", "admin"];

/// Permission level granted to a repository user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Permission {
    ReadOnly = 0,
    Write = 1,
    Admin = 2,
}

impl Permission {
    fn label(self) -> &'static str {
        PERMISSION_LABELS[self as usize]
    }
}

impl TryFrom<i32> for Permission {
    type Error = String;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Permission::ReadOnly),
            1 => Ok(Permission::Write),
            2 => Ok(Permission::Admin),
            _ => Err(format!(
                "Invalid type: {}; must be READ_ONLY, WRITE, or ADMIN",
                value
            )),
        }
    }
}

/// Container for a user name and repository permission level (read-only, write, or admin).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct User {
    name: String,
    permission: Permission,
}

impl User {
    /// Create a new `User` with the given name and [`Permission`].
    pub fn new(name: impl Into<String>, permission: Permission) -> Self {
        Self {
            name: name.into(),
            permission,
        }
    }

    /// Create a `User` from a raw Java-style permission integer
    /// (`0` = read-only, `1` = write, `2` = admin).
    pub fn with_permission_int(name: impl Into<String>, permission: i32) -> Result<Self, String> {
        Ok(Self {
            name: name.into(),
            permission: Permission::try_from(permission)?,
        })
    }

    /// Returns the user id/name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns `true` if this user has read-only permission.
    pub fn is_read_only(&self) -> bool {
        self.permission == Permission::ReadOnly
    }

    /// Returns `true` if this user has write or admin permission.
    pub fn has_write_permission(&self) -> bool {
        matches!(self.permission, Permission::Write | Permission::Admin)
    }

    /// Returns `true` if this user has admin permission.
    pub fn is_admin(&self) -> bool {
        self.permission == Permission::Admin
    }

    /// Returns the [`Permission`] assigned to this user.
    pub fn permission_type(&self) -> Permission {
        self.permission
    }
}

impl fmt::Display for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.permission.label())
    }
}

impl PartialOrd for User {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for User {
    fn cmp(&self, other: &Self) -> Ordering {
        self.name
            .cmp(&other.name)
            .then_with(|| self.permission.cmp(&other.permission))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_stores_fields() {
        let u = User::new("alice", Permission::Write);
        assert_eq!(u.name(), "alice");
        assert_eq!(u.permission_type(), Permission::Write);
    }

    #[test]
    fn test_anonymous_username_constant() {
        assert_eq!(ANONYMOUS_USERNAME, "-anonymous-");
    }

    #[test]
    fn test_is_read_only() {
        let u = User::new("alice", Permission::ReadOnly);
        assert!(u.is_read_only());
        assert!(!u.has_write_permission());
        assert!(!u.is_admin());
    }

    #[test]
    fn test_write_permission() {
        let u = User::new("bob", Permission::Write);
        assert!(!u.is_read_only());
        assert!(u.has_write_permission());
        assert!(!u.is_admin());
    }

    #[test]
    fn test_admin_permission() {
        let u = User::new("carol", Permission::Admin);
        assert!(!u.is_read_only());
        assert!(u.has_write_permission());
        assert!(u.is_admin());
    }

    #[test]
    fn test_display_read_only() {
        let u = User::new("dave", Permission::ReadOnly);
        assert_eq!(u.to_string(), "dave (read-only)");
    }

    #[test]
    fn test_display_write() {
        let u = User::new("eve", Permission::Write);
        assert_eq!(u.to_string(), "eve (write)");
    }

    #[test]
    fn test_display_admin() {
        let u = User::new("frank", Permission::Admin);
        assert_eq!(u.to_string(), "frank (admin)");
    }

    #[test]
    fn test_eq_same_fields() {
        let a = User::new("grace", Permission::Write);
        let b = User::new("grace", Permission::Write);
        assert_eq!(a, b);
    }

    #[test]
    fn test_ne_different_permission() {
        let a = User::new("heidi", Permission::ReadOnly);
        let b = User::new("heidi", Permission::Write);
        assert_ne!(a, b);
    }

    #[test]
    fn test_ne_different_name() {
        let a = User::new("ivan", Permission::Admin);
        let b = User::new("judy", Permission::Admin);
        assert_ne!(a, b);
    }

    #[test]
    fn test_clone() {
        let a = User::new("karl", Permission::Write);
        assert_eq!(a.clone(), a);
    }

    #[test]
    fn test_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(User::new("lena", Permission::Admin));
        set.insert(User::new("lena", Permission::Admin));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_hash_differs_by_permission() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(User::new("mike", Permission::ReadOnly));
        set.insert(User::new("mike", Permission::Write));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_ord_by_name() {
        let a = User::new("alice", Permission::Admin);
        let b = User::new("bob", Permission::ReadOnly);
        assert!(a < b);
    }

    #[test]
    fn test_ord_same_name_by_permission() {
        let a = User::new("neil", Permission::ReadOnly);
        let b = User::new("neil", Permission::Write);
        let c = User::new("neil", Permission::Admin);
        assert!(a < b);
        assert!(b < c);
        assert!(a < c);
    }

    #[test]
    fn test_sort_vec() {
        let mut users = vec![
            User::new("carol", Permission::Admin),
            User::new("alice", Permission::Write),
            User::new("bob", Permission::ReadOnly),
        ];
        users.sort();
        assert_eq!(users[0].name(), "alice");
        assert_eq!(users[1].name(), "bob");
        assert_eq!(users[2].name(), "carol");
    }

    #[test]
    fn test_with_permission_int_valid() {
        let u = User::with_permission_int("oscar", 1).unwrap();
        assert_eq!(u.permission_type(), Permission::Write);
    }

    #[test]
    fn test_with_permission_int_invalid() {
        let err = User::with_permission_int("pat", 99).unwrap_err();
        assert!(err.contains("Invalid type: 99"));
        assert!(err.contains("READ_ONLY, WRITE, or ADMIN"));
    }

    #[test]
    fn test_with_permission_int_boundaries() {
        assert!(User::with_permission_int("a", 0).is_ok());
        assert!(User::with_permission_int("b", 2).is_ok());
        assert!(User::with_permission_int("c", -1).is_err());
        assert!(User::with_permission_int("d", 3).is_err());
    }

    #[test]
    fn test_debug_contains_struct_name() {
        let u = User::new("quinn", Permission::Admin);
        let dbg = format!("{:?}", u);
        assert!(dbg.contains("User"));
        assert!(dbg.contains("quinn"));
        assert!(dbg.contains("Admin"));
    }

    #[test]
    fn test_permission_try_from() {
        assert_eq!(Permission::try_from(0).unwrap(), Permission::ReadOnly);
        assert_eq!(Permission::try_from(1).unwrap(), Permission::Write);
        assert_eq!(Permission::try_from(2).unwrap(), Permission::Admin);
        assert!(Permission::try_from(3).is_err());
        assert!(Permission::try_from(-1).is_err());
    }
}
