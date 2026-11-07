//! Process hardening applied once at startup by binaries that hold vault keys: no core dumps,
//! and on Linux no ptrace or /proc/<pid>/mem access from same-user processes. Release builds
//! on macOS also refuse debugger attachment. Each step is best-effort and reports what failed.

/// Applies every protection this platform supports and returns the ones that could not be
/// applied, for the caller to log.
pub fn harden_process() -> Vec<&'static str> {
    let mut failed = Vec::new();
    #[cfg(unix)]
    {
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: setrlimit reads the struct we pass and changes only this process's limits.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) } != 0 {
            failed.push("disable core dumps");
        }
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_SET_DUMPABLE takes an integer flag and changes only this process.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            failed.push("block same-user ptrace and memory reads");
        }
    }
    #[cfg(all(target_os = "macos", not(debug_assertions)))]
    {
        const PT_DENY_ATTACH: libc::c_int = 31;
        // SAFETY: PT_DENY_ATTACH ignores the address and data arguments.
        if unsafe { libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) } != 0 {
            failed.push("deny debugger attachment");
        }
    }
    failed
}

#[cfg(test)]
mod tests {
    #[test]
    fn hardening_succeeds() {
        assert!(super::harden_process().is_empty());
    }
}
