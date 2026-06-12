#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatingSystem {
    Windows,
    Linux,
    MacOSX,
    FreeBSD,
    Unsupported,
}

impl OperatingSystem {
    pub const CURRENT: OperatingSystem = Self::find_current();

    pub fn name(&self) -> &'static str {
        match self {
            Self::Windows => "Windows",
            Self::Linux => "Linux",
            Self::MacOSX => "Mac OS X",
            Self::FreeBSD => "FreeBSD",
            Self::Unsupported => "Unsupported Operating System",
        }
    }

    const fn find_current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "macos") {
            Self::MacOSX
        } else if cfg!(target_os = "freebsd") {
            Self::FreeBSD
        } else {
            Self::Unsupported
        }
    }
}

impl std::fmt::Display for OperatingSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}({})", self, std::env::consts::OS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_os() {
        let current = OperatingSystem::CURRENT;
        #[cfg(target_os = "windows")]
        assert_eq!(current, OperatingSystem::Windows);
        #[cfg(target_os = "linux")]
        assert_eq!(current, OperatingSystem::Linux);
        #[cfg(target_os = "macos")]
        assert_eq!(current, OperatingSystem::MacOSX);
    }
}
