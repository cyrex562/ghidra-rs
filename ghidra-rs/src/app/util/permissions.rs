/// Represents file permissions with read, write, and execute bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Permissions {
    /// All permissions enabled: read, write, and execute.
    pub const ALL: Permissions = Permissions {
        read: true,
        write: true,
        execute: true,
    };

    /// Read-only permission.
    pub const READ_ONLY: Permissions = Permissions {
        read: true,
        write: false,
        execute: false,
    };

    /// Read and execute permissions.
    pub const READ_EXECUTE: Permissions = Permissions {
        read: true,
        write: false,
        execute: true,
    };

    /// Creates a new Permissions instance with the specified read, write, and execute bits.
    pub const fn new(read: bool, write: bool, execute: bool) -> Self {
        Permissions { read, write, execute }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_permissions() {
        assert_eq!(Permissions::ALL.read, true);
        assert_eq!(Permissions::ALL.write, true);
        assert_eq!(Permissions::ALL.execute, true);
    }

    #[test]
    fn test_read_only() {
        assert_eq!(Permissions::READ_ONLY.read, true);
        assert_eq!(Permissions::READ_ONLY.write, false);
        assert_eq!(Permissions::READ_ONLY.execute, false);
    }

    #[test]
    fn test_read_execute() {
        assert_eq!(Permissions::READ_EXECUTE.read, true);
        assert_eq!(Permissions::READ_EXECUTE.write, false);
        assert_eq!(Permissions::READ_EXECUTE.execute, true);
    }

    #[test]
    fn test_new_constructor() {
        let perms = Permissions::new(true, false, true);
        assert_eq!(perms.read, true);
        assert_eq!(perms.write, false);
        assert_eq!(perms.execute, true);
    }

    #[test]
    fn test_all_false() {
        let perms = Permissions::new(false, false, false);
        assert_eq!(perms.read, false);
        assert_eq!(perms.write, false);
        assert_eq!(perms.execute, false);
    }

    #[test]
    fn test_clone_and_copy() {
        let perms1 = Permissions::ALL;
        let perms2 = perms1;
        assert_eq!(perms1, perms2);
    }

    #[test]
    fn test_equality() {
        let perms1 = Permissions::new(true, false, true);
        let perms2 = Permissions::new(true, false, true);
        assert_eq!(perms1, perms2);
    }
}
