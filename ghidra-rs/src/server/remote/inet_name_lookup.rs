// Port of orig_src/Ghidra/Features/GhidraServer/src/main/java/ghidra/server/remote/InetNameLookup.java
//
// Original license header (Apache-2.0, IP: GHIDRA):
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//
//! Best-effort reverse DNS (canonical hostname) lookup, matching Java's
//! `InetNameLookup`.
//!
//! Reverse resolution itself (`getnameinfo`) has no `std` equivalent, so it is
//! implemented directly on top of the `libc` crate (already a dependency) on
//! Unix; on other platforms it always falls back to the numeric address, the
//! same outcome Java produces when reverse DNS is unavailable.

use std::io;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::util::msg::Msg;

/// Threshold (in milliseconds) above which a failed reverse lookup is
/// considered "slow" for the purposes of auto-disabling future lookups.
const MAX_TIME_MS: u128 = 10_000;

static LOOKUP_ENABLED: AtomicBool = AtomicBool::new(true);
static DISABLE_ON_FAILURE: AtomicBool = AtomicBool::new(false);

/// Static-use-only namespace for reverse DNS name lookups.
///
/// Port of `ghidra.server.remote.InetNameLookup`. The Java class is a
/// collection of static methods backed by process-wide `volatile` state;
/// here that state lives in module-level atomics.
pub struct InetNameLookup;

impl InetNameLookup {
    /// If `state` is `true`, a reverse lookup that both fails and takes
    /// longer than [`MAX_TIME_MS`] will automatically disable future lookups
    /// (see [`Self::is_enabled`]).
    pub fn set_disable_on_failure(state: bool) {
        DISABLE_ON_FAILURE.store(state, Ordering::SeqCst);
    }

    /// Enables or disables reverse DNS lookups performed by
    /// [`Self::get_canonical_host_name`].
    pub fn set_lookup_enabled(enable: bool) {
        LOOKUP_ENABLED.store(enable, Ordering::SeqCst);
    }

    /// Returns `true` if reverse DNS lookups are currently enabled.
    pub fn is_enabled() -> bool {
        LOOKUP_ENABLED.load(Ordering::SeqCst)
    }

    /// Gets the fully qualified domain name for this IP address or hostname.
    ///
    /// Best effort method, meaning we may not be able to return the FQDN
    /// depending on the underlying system configuration.
    ///
    /// # Arguments
    ///
    /// * `host` - IP address or hostname
    ///
    /// # Returns
    ///
    /// The fully qualified domain name for this IP address, or if the
    /// operation is not allowed/fails, the original host name specified.
    ///
    /// # Errors
    ///
    /// Returns an error if the forward lookup of the specified address fails.
    pub fn get_canonical_host_name(host: &str) -> io::Result<String> {
        let mut best_guess = host.to_string();
        if !Self::is_enabled() {
            return Ok(best_guess);
        }

        let mut found = false;
        let mut fastest = u128::MAX;
        for addr in resolve_all(host)? {
            let start = Instant::now();
            let numeric = numeric_host(addr);
            let name = reverse_lookup(addr).unwrap_or_else(|| numeric.clone());
            let elapsed_ms = start.elapsed().as_millis();
            if name != numeric {
                if host.eq_ignore_ascii_case(&name) {
                    // name found matches original - use it
                    return Ok(name);
                }
                // name found - update best guess
                best_guess = name;
                found = true;
            } else {
                // keep fastest reverse lookup time
                fastest = fastest.min(elapsed_ms);
            }
        }
        if !found {
            // if lookup failed to produce a name - log warning
            Msg::warn(
                "InetNameLookup",
                &format!(
                    "Failed to resolve IP Address: {host} \
                     (Reverse DNS may not be properly configured or you may have a network problem)"
                ),
            );
            if DISABLE_ON_FAILURE.load(Ordering::SeqCst) && fastest > MAX_TIME_MS {
                // if lookup failed and was slow - disable future lookups if disableOnFailure is true
                Msg::warn(
                    "InetNameLookup",
                    &"Reverse network name lookup has been disabled automatically due to lookup failure."
                        .to_string(),
                );
                LOOKUP_ENABLED.store(false, Ordering::SeqCst);
            }
        }
        Ok(best_guess)
    }
}

/// Resolves `host` to all of its IP addresses (forward lookup), mirroring
/// `InetAddress.getAllByName(host)`.
fn resolve_all(host: &str) -> io::Result<Vec<IpAddr>> {
    Ok((host, 0)
        .to_socket_addrs()?
        .map(|socket_addr| socket_addr.ip())
        .collect())
}

/// Returns the plain numeric presentation of `addr` (no DNS), mirroring
/// `InetAddress.getHostAddress()`.
fn numeric_host(addr: IpAddr) -> String {
    #[cfg(unix)]
    {
        unix_impl::getnameinfo(addr, libc::NI_NUMERICHOST).unwrap_or_else(|| addr.to_string())
    }
    #[cfg(not(unix))]
    {
        addr.to_string()
    }
}

/// Attempts a reverse DNS (PTR) lookup for `addr`, returning `None` if no
/// name could be resolved. Mirrors `InetAddress.getCanonicalHostName()`.
fn reverse_lookup(addr: IpAddr) -> Option<String> {
    #[cfg(unix)]
    {
        unix_impl::getnameinfo(addr, 0)
    }
    #[cfg(not(unix))]
    {
        let _ = addr;
        None
    }
}

#[cfg(unix)]
mod unix_impl {
    use std::ffi::CStr;
    use std::mem::size_of;
    use std::net::IpAddr;

    /// Calls the system `getnameinfo(3)` for `addr` with the given `flags`,
    /// returning the resolved host string on success.
    pub(super) fn getnameinfo(addr: IpAddr, flags: libc::c_int) -> Option<String> {
        let (storage, len) = to_sockaddr(addr);
        let mut host_buf = [0 as libc::c_char; 256];
        let ret = unsafe {
            libc::getnameinfo(
                std::ptr::addr_of!(storage) as *const libc::sockaddr,
                len,
                host_buf.as_mut_ptr(),
                host_buf.len() as libc::socklen_t,
                std::ptr::null_mut(),
                0,
                flags,
            )
        };
        if ret != 0 {
            return None;
        }
        let cstr = unsafe { CStr::from_ptr(host_buf.as_ptr()) };
        cstr.to_str().ok().map(|s| s.to_string())
    }

    fn to_sockaddr(addr: IpAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
        // SAFETY: a zeroed `sockaddr_storage` is a valid bit pattern; we then
        // populate only the fields required for the address family in use.
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let len = match addr {
            IpAddr::V4(v4) => {
                let sin = std::ptr::addr_of_mut!(storage) as *mut libc::sockaddr_in;
                unsafe {
                    (*sin).sin_family = libc::AF_INET as libc::sa_family_t;
                    (*sin).sin_addr = libc::in_addr {
                        s_addr: u32::from_ne_bytes(v4.octets()),
                    };
                }
                size_of::<libc::sockaddr_in>()
            }
            IpAddr::V6(v6) => {
                let sin6 = std::ptr::addr_of_mut!(storage) as *mut libc::sockaddr_in6;
                unsafe {
                    (*sin6).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                    (*sin6).sin6_addr = libc::in6_addr {
                        s6_addr: v6.octets(),
                    };
                }
                size_of::<libc::sockaddr_in6>()
            }
        };
        (storage, len as libc::socklen_t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // `LOOKUP_ENABLED` is process-global state (mirroring the Java statics),
    // so tests that mutate it must not run concurrently with each other.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_enabled_by_default() {
        let _guard = TEST_LOCK.lock().unwrap();
        InetNameLookup::set_lookup_enabled(true);
        assert!(InetNameLookup::is_enabled());
    }

    #[test]
    fn test_set_lookup_enabled_toggle() {
        let _guard = TEST_LOCK.lock().unwrap();
        InetNameLookup::set_lookup_enabled(false);
        assert!(!InetNameLookup::is_enabled());
        InetNameLookup::set_lookup_enabled(true);
        assert!(InetNameLookup::is_enabled());
    }

    #[test]
    fn test_get_canonical_host_name_when_disabled_returns_input_unchanged() {
        let _guard = TEST_LOCK.lock().unwrap();
        InetNameLookup::set_lookup_enabled(false);
        let result =
            InetNameLookup::get_canonical_host_name("some.invalid.host.example").unwrap();
        assert_eq!(result, "some.invalid.host.example");
        InetNameLookup::set_lookup_enabled(true);
    }

    #[test]
    fn test_get_canonical_host_name_for_loopback_ip() {
        let _guard = TEST_LOCK.lock().unwrap();
        InetNameLookup::set_lookup_enabled(true);
        // Best effort: must succeed (127.0.0.1 needs no network access to
        // resolve forward) and return a non-empty name or numeric fallback.
        let result = InetNameLookup::get_canonical_host_name("127.0.0.1").unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_set_disable_on_failure_does_not_panic() {
        let _guard = TEST_LOCK.lock().unwrap();
        InetNameLookup::set_disable_on_failure(true);
        InetNameLookup::set_disable_on_failure(false);
    }

    #[test]
    fn test_numeric_host_matches_display_for_loopback() {
        let addr: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(numeric_host(addr), "127.0.0.1");
    }
}
