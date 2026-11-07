//! Running a program with secrets in its environment, as `vaultos run` and the MCP bridge's
//! `run_with_secrets` do, with those values masked in what it prints.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use vaultos_core::mask::Masker;
use zeroize::Zeroizing;

/// Variables never passed on: a program run with secrets should not act as the agent.
const WITHHELD: [&str; 1] = ["VAULTOS_AGENT_TOKEN"];

/// The only variables a captured (agent's) command gets from this process's environment.
const KEPT: [&str; 10] = [
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "TMPDIR",
    "TZ",
];

/// How long output may keep arriving after the program's group is killed (from children that
/// left it).
const DRAIN: Duration = Duration::from_secs(2);

/// How long a stopped program has between SIGTERM and SIGKILL.
const GRACE: Duration = Duration::from_secs(2);

pub struct Program {
    pub argv: Vec<OsString>,
    pub cwd: Option<PathBuf>,
    /// Secrets added to (or replacing) this process's environment; they are masked.
    pub env: Vec<(String, Zeroizing<String>)>,
    /// Other variables to set (an env file's plain values), applied first and not masked.
    pub plain: Vec<(String, String)>,
}

impl std::fmt::Debug for Program {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Program")
            .field("program", &self.argv.first())
            .field("env", &self.env.len())
            .finish_non_exhaustive()
    }
}

impl Program {
    /// The command to spawn. A `clean` one gets only [`KEPT`] from this process's
    /// environment; otherwise it inherits it, less [`WITHHELD`].
    fn command(&self, clean: bool) -> std::io::Result<Command> {
        let Some((first, rest)) = self.argv.split_first() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no command was given",
            ));
        };
        let mut cmd = Command::new(first);
        cmd.args(rest);
        if let Some(dir) = &self.cwd {
            cmd.current_dir(dir);
        }
        if clean {
            cmd.env_clear();
            for name in KEPT {
                if let Some(v) = std::env::var_os(name) {
                    cmd.env(name, v);
                }
            }
        } else {
            for name in WITHHELD {
                cmd.env_remove(name);
            }
        }
        for (k, v) in &self.plain {
            cmd.env(k, v);
        }
        for (k, v) in &self.env {
            cmd.env(k, v.as_str());
        }
        Ok(cmd)
    }

    /// The values to mask: every one this program was given.
    fn masker(&self) -> Masker {
        Masker::new(self.env.iter().map(|(_, v)| v.as_str()))
    }
}

/// The exit code a shell would report: the program's, or 128 plus the signal that ended it.
pub fn exit_code(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}

/// Copies `from` to `sink` through a masker, in reads as they arrive.
fn pump(mut from: impl Read, mut masker: Option<Masker>, mut sink: impl FnMut(&[u8])) {
    let mut buf = Zeroizing::new(vec![0u8; 8192]);
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => match masker.as_mut() {
                Some(m) => sink(&m.push(&buf[..n])),
                None => sink(&buf[..n]),
            },
        }
    }
    if let Some(m) = masker.as_mut() {
        sink(&m.finish());
    }
}

/// Runs the program attached to this terminal: it reads this process's stdin, and its
/// output reaches this process's stdout and stderr, masked unless `mask` is false. ^C goes
/// to the program, and this process waits for it. Returns its exit code.
pub fn stream(program: &Program, mask: bool) -> std::io::Result<i32> {
    let mut cmd = program.command(false)?;
    if !mask {
        let status = cmd.status()?;
        return Ok(exit_code(status));
    }
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    ignore_interrupts();
    let (done_tx, done_rx) = mpsc::channel();
    let out = child.stdout.take().map(|s| {
        let m = program.masker();
        let tx = done_tx.clone();
        std::thread::spawn(move || {
            pump(s, Some(m), |b| {
                let mut o = std::io::stdout().lock();
                let _ = o.write_all(b).and_then(|()| o.flush());
            });
            let _ = tx.send(());
        })
    });
    let err = child.stderr.take().map(|s| {
        let m = program.masker();
        let tx = done_tx.clone();
        std::thread::spawn(move || {
            pump(s, Some(m), |b| {
                let mut e = std::io::stderr().lock();
                let _ = e.write_all(b).and_then(|()| e.flush());
            });
            let _ = tx.send(());
        })
    });
    drop(done_tx);
    let status = child.wait()?;
    let deadline = Instant::now() + DRAIN;
    for _ in out.iter().chain(err.iter()) {
        let left = deadline.saturating_duration_since(Instant::now());
        if done_rx.recv_timeout(left).is_err() {
            break;
        }
    }
    Ok(exit_code(status))
}

/// ^C and ^\ from the terminal reach the program, which shares this process's group; this
/// process outlives it to print the rest of its output and report its exit code.
fn ignore_interrupts() {
    // SAFETY: setting a signal's disposition to SIG_IGN installs no handler code.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGQUIT, libc::SIG_IGN);
    }
}

#[derive(Debug, Default)]
pub struct Captured {
    pub stdout: String,
    pub stderr: String,
    /// The exit code, as a shell reports it; absent when the program was stopped.
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    /// `stop` returned true before the program finished.
    pub stopped: bool,
    /// Output past the limit was dropped.
    pub truncated: bool,
}

/// Runs the program detached from any terminal, with only [`KEPT`] from this process's
/// environment plus the program's own variables: stdin is empty and it runs in its own process
/// group. Keeps at most `max_output` bytes of each stream, masked. After `timeout` the whole
/// group is stopped (SIGTERM, then SIGKILL two seconds later); when the program exits, whatever
/// it left running in its group is killed.
pub fn capture(
    program: &Program,
    timeout: Duration,
    max_output: usize,
) -> std::io::Result<Captured> {
    capture_until(program, timeout, max_output, &|| false)
}

/// One of the program's output pipes, read without blocking.
struct Stream {
    file: Option<std::fs::File>,
    masker: Masker,
    kept: Vec<u8>,
    cut: bool,
}

impl Stream {
    fn new(fd: std::os::fd::OwnedFd, masker: Masker) -> std::io::Result<Stream> {
        use std::os::fd::AsRawFd;
        let raw = fd.as_raw_fd();
        // SAFETY: fcntl on a descriptor this process owns; it changes only its flags.
        let ok = unsafe {
            let flags = libc::fcntl(raw, libc::F_GETFL);
            flags >= 0 && libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) >= 0
        };
        if !ok {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Stream {
            file: Some(fd.into()),
            masker,
            kept: Vec::new(),
            cut: false,
        })
    }

    fn keep(&mut self, b: &[u8], max: usize) {
        let room = max.saturating_sub(self.kept.len());
        if b.len() > room {
            self.cut = true;
        }
        self.kept.extend_from_slice(&b[..b.len().min(room)]);
    }

    /// Reads what is waiting; closes the stream at its end.
    fn read(&mut self, buf: &mut [u8], max: usize) {
        while let Some(f) = self.file.as_mut() {
            match f.read(buf) {
                Ok(0) => break,
                Ok(n) => {
                    let masked = self.masker.push(&buf[..n]);
                    self.keep(&masked, max);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return,
                Err(_) => break,
            }
        }
        self.close(max);
    }

    fn close(&mut self, max: usize) {
        if self.file.take().is_some() {
            let rest = self.masker.finish();
            self.keep(&rest, max);
        }
    }
}

#[derive(Clone, Copy)]
enum Phase {
    Running,
    /// SIGTERM was sent; SIGKILL follows at this time.
    Stopping(Instant),
    /// The group was killed; output is read until this time.
    Draining(Instant),
}

/// As [`capture`], also stopping the program as at the timeout once `stop` returns true.
/// Everything happens on the calling thread, and the pipes are closed when it returns.
pub fn capture_until(
    program: &Program,
    timeout: Duration,
    max_output: usize,
    stop: &dyn Fn() -> bool,
) -> std::io::Result<Captured> {
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    let mut cmd = program.command(true)?;
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = cmd.spawn()?;
    let group = -(child.id() as libc::pid_t);
    let kill = |signal| {
        // SAFETY: kill only sends a signal, to the child's own group (process_group(0)).
        unsafe { libc::kill(group, signal) };
    };
    let mut streams = Vec::new();
    for fd in [
        child.stdout.take().map(OwnedFd::from),
        child.stderr.take().map(OwnedFd::from),
    ] {
        match fd.map(|fd| Stream::new(fd, program.masker())).transpose() {
            Ok(s) => streams.push(s),
            Err(e) => {
                kill(libc::SIGKILL);
                let _ = child.wait();
                return Err(e);
            }
        }
    }
    let deadline = Instant::now() + timeout;
    let mut buf = Zeroizing::new(vec![0u8; 8192]);
    let mut status = None;
    let mut out = Captured::default();
    let mut phase = Phase::Running;
    loop {
        for s in streams.iter_mut().flatten() {
            s.read(&mut buf, max_output);
        }
        if status.is_none() {
            status = child.try_wait()?;
        }
        let now = Instant::now();
        let mut open: Vec<libc::pollfd> = streams
            .iter()
            .flatten()
            .filter_map(|s| s.file.as_ref())
            .map(|f| libc::pollfd {
                fd: f.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        match phase {
            Phase::Running if status.is_some() => {
                // What the program left running in its group goes with it.
                kill(libc::SIGKILL);
                phase = Phase::Draining(now + DRAIN);
                continue;
            }
            Phase::Running if now >= deadline || stop() => {
                out.timed_out = now >= deadline;
                out.stopped = !out.timed_out;
                kill(libc::SIGTERM);
                phase = Phase::Stopping(now + GRACE);
            }
            Phase::Stopping(until) if status.is_some() || now >= until => {
                kill(libc::SIGKILL);
                if status.is_none() {
                    status = Some(child.wait()?);
                }
                phase = Phase::Draining(now + DRAIN);
                continue;
            }
            Phase::Draining(until) if open.is_empty() || now >= until => break,
            _ => {}
        }
        if open.is_empty() {
            std::thread::sleep(Duration::from_millis(20));
        } else {
            // SAFETY: poll reads and writes only the `open.len()` entries of `open`.
            unsafe { libc::poll(open.as_mut_ptr(), open.len() as libc::nfds_t, 20) };
        }
    }
    for s in streams.iter_mut().flatten() {
        s.close(max_output);
        out.truncated |= s.cut;
    }
    let text = |i: usize| match streams.get(i) {
        Some(Some(s)) => String::from_utf8_lossy(&s.kept).into_owned(),
        _ => String::new(),
    };
    out.stdout = text(0);
    out.stderr = text(1);
    if !out.timed_out && !out.stopped {
        out.exit_code = status.map(exit_code);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test")]
    use super::*;

    fn sh(script: &str, value: &str) -> Program {
        Program {
            argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
            cwd: None,
            env: vec![("SYNTH_VALUE".into(), Zeroizing::new(value.into()))],
            plain: vec![("SYNTH_PLAIN".into(), "development".into())],
        }
    }

    #[test]
    fn captures_masked_output_and_exit_codes() {
        let p = sh(
            r#"printf 'value=%s %s\n' "$SYNTH_VALUE" "$SYNTH_PLAIN"; printf '%s' "$SYNTH_VALUE" >&2; exit 3"#,
            "synthetic-run-value",
        );
        let c = capture(&p, Duration::from_secs(20), 4096).unwrap();
        assert_eq!(c.stdout, "value=<concealed by VaultOS> development\n");
        assert_eq!(c.stderr, "<concealed by VaultOS>");
        assert_eq!(
            (c.exit_code, c.timed_out, c.truncated),
            (Some(3), false, false)
        );
    }

    #[test]
    fn gives_captured_programs_a_clean_environment() {
        // Cargo runs tests with this set; it stands for anything in the owner's environment.
        assert!(std::env::var_os("CARGO_PKG_NAME").is_some());
        let p = sh("/usr/bin/env", "synthetic-env-value");
        let c = capture(&p, Duration::from_secs(20), 65536).unwrap();
        assert!(!c.stdout.contains("CARGO_PKG_NAME"), "{}", c.stdout);
        assert!(c.stdout.contains("SYNTH_PLAIN=development"));
        assert!(c.stdout.contains("SYNTH_VALUE=<concealed by VaultOS>"));
    }

    #[test]
    fn kills_what_the_program_leaves_running() {
        let marker = std::env::temp_dir().join(format!("vaultos-run-left-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let script = format!("(sleep 1; touch '{}') & echo started", marker.display());
        let start = Instant::now();
        let c = capture(
            &sh(&script, "synthetic-unused"),
            Duration::from_secs(20),
            4096,
        )
        .unwrap();
        assert_eq!((c.stdout.as_str(), c.exit_code), ("started\n", Some(0)));
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(1500));
        assert!(!marker.exists(), "the background job outlived the run");
    }

    #[test]
    fn stops_when_asked() {
        let asked = Instant::now() + Duration::from_millis(200);
        let c = capture_until(
            &sh("echo begun; sleep 30", "synthetic-unused"),
            Duration::from_secs(60),
            4096,
            &|| Instant::now() >= asked,
        )
        .unwrap();
        assert!(c.stopped && !c.timed_out && c.exit_code.is_none());
        assert_eq!(c.stdout, "begun\n");
    }

    #[test]
    fn stops_programs_at_the_timeout_and_caps_output() {
        let p = sh(
            "yes synthetic-line | head -c 100000; sleep 30",
            "synthetic-unused",
        );
        let start = Instant::now();
        let c = capture(&p, Duration::from_millis(300), 1000).unwrap();
        assert!(c.timed_out && c.truncated && c.exit_code.is_none());
        assert_eq!(c.stdout.len(), 1000);
        assert!(start.elapsed() < Duration::from_secs(10));
    }
}
