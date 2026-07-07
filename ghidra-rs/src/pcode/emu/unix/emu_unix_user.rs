/// A simulated UNIX user.
///
/// Corresponds to `ghidra.pcode.emu.unix.EmuUnixUser`.
pub struct EmuUnixUser {
    /// The user's UID.
    pub uid: u32,
    /// The user's group IDs.
    pub gids: Vec<u32>,
}

impl EmuUnixUser {
    /// The default (root) user with UID 0 and no supplementary groups.
    pub const DEFAULT_USER: Self = Self {
        uid: 0,
        gids: Vec::new(),
    };

    /// Construct a new user with the given UID and group IDs.
    pub fn new(uid: u32, gids: impl IntoIterator<Item = u32>) -> Self {
        Self {
            uid,
            gids: gids.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_user_is_root() {
        assert_eq!(EmuUnixUser::DEFAULT_USER.uid, 0);
        assert!(EmuUnixUser::DEFAULT_USER.gids.is_empty());
    }

    #[test]
    fn new_user_stores_uid_and_gids() {
        let user = EmuUnixUser::new(1000, [1000u32, 100, 4]);
        assert_eq!(user.uid, 1000);
        assert_eq!(user.gids, vec![1000u32, 100, 4]);
    }

    #[test]
    fn new_user_empty_gids() {
        let user = EmuUnixUser::new(42, []);
        assert_eq!(user.uid, 42);
        assert!(user.gids.is_empty());
    }
}
