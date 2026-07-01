use super::EmuUnixUser;

/// The mode bit indicating read permission.
pub const MODE_R: i32 = 0o4;
/// The mode bit indicating write permission.
pub const MODE_W: i32 = 0o2;
/// The mode bit indicating execute permission.
pub const MODE_X: i32 = 0o1;

/// Collects the `stat` fields common to UNIX platforms.
///
/// See a UNIX manual for the exact meaning of each field.
///
/// Corresponds to `ghidra.pcode.emu.unix.EmuUnixFileStat`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EmuUnixFileStat {
    pub st_dev: i64,
    pub st_ino: i64,
    pub st_mode: i32,
    pub st_nlink: i64,
    pub st_uid: i32,
    pub st_gid: i32,
    pub st_rdev: i64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,

    pub st_atim_sec: i64,
    pub st_atim_nsec: i64,
    pub st_mtim_sec: i64,
    pub st_mtim_nsec: i64,
    pub st_ctim_sec: i64,
    pub st_ctim_nsec: i64,
}

impl EmuUnixFileStat {
    /// Check if the given user has the requested permissions on the file described by this stat.
    ///
    /// # Arguments
    ///
    /// * `req` - the requested permissions
    /// * `user` - the user requesting permission
    ///
    /// Returns true if permitted, false if denied.
    pub fn has_permissions(&self, req: i32, user: &EmuUnixUser) -> bool {
        if (self.st_mode & req) == req {
            return true;
        }
        if ((self.st_mode >> 6) & req) == req && user.uid == self.st_uid as u32 {
            return true;
        }
        if ((self.st_mode >> 3) & req) == req && user.gids.contains(&(self.st_gid as u32)) {
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn other_permission_bit_grants_access() {
        let stat = EmuUnixFileStat {
            st_mode: MODE_R,
            ..Default::default()
        };
        let user = EmuUnixUser::new(1000, [1000u32]);
        assert!(stat.has_permissions(MODE_R, &user));
    }

    #[test]
    fn owner_permission_bit_requires_matching_uid() {
        let stat = EmuUnixFileStat {
            st_mode: MODE_W << 6,
            st_uid: 42,
            ..Default::default()
        };
        let owner = EmuUnixUser::new(42, []);
        let stranger = EmuUnixUser::new(43, []);
        assert!(stat.has_permissions(MODE_W, &owner));
        assert!(!stat.has_permissions(MODE_W, &stranger));
    }

    #[test]
    fn group_permission_bit_requires_matching_gid() {
        let stat = EmuUnixFileStat {
            st_mode: MODE_X << 3,
            st_gid: 7,
            ..Default::default()
        };
        let in_group = EmuUnixUser::new(1000, [7u32, 8]);
        let not_in_group = EmuUnixUser::new(1000, [8u32]);
        assert!(stat.has_permissions(MODE_X, &in_group));
        assert!(!stat.has_permissions(MODE_X, &not_in_group));
    }

    #[test]
    fn no_matching_bits_denies_access() {
        let stat = EmuUnixFileStat::default();
        let user = EmuUnixUser::DEFAULT_USER;
        assert!(!stat.has_permissions(MODE_R, &user));
    }

    #[test]
    fn requesting_multiple_bits_requires_all_of_them() {
        let stat = EmuUnixFileStat {
            st_mode: MODE_R,
            ..Default::default()
        };
        let user = EmuUnixUser::DEFAULT_USER;
        assert!(!stat.has_permissions(MODE_R | MODE_W, &user));
    }
}
