//! Running a program with secrets in its environment, as `vaultos run` and the MCP bridge's
//! `run_with_secrets` do, with those values masked in what it prints.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use vaultos_core::mask::Masker;
use zeroize::Zeroizing;

/// Variables never passed on: a program run with secrets should not act as the agent.
const WITHHELD: [&str; 1] = ["VAULTOS_AGENT_TOKEN"];

/// How long output may keep arriving after the program exits (from children it left behind).
const DRAIN: Duration = Duration::from_secs(2);

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
    fn command(&self) -> std::io::Result<Command> {
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
        for name in WITHHELD {
            cmd.env_remove(name);
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
    let mut cmd = program.command()?;
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
    /// Output past the limit was dropped.
    pub truncated: bool,
}

/// Runs the program detached from any terminal (stdin is empty, in its own process group),
/// keeping at most `max_output` bytes of each stream, masked. After `timeout` the whole group
/// is stopped (SIGTERM, then SIGKILL two seconds later).
pub fn capture(
    program: &Program,
    timeout: Duration,
    max_output: usize,
) -> std::io::Result<Captured> {
    use std::os::unix::process::CommandExt;
    let mut cmd = program.command()?;
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = cmd.spawn()?;
    let (tx, rx) = mpsc::channel::<(bool, Vec<u8>, bool)>();
    for (is_out, stream) in [
        (
            true,
            child
                .stdout
                .take()
                .map(|s| Box::new(s) as Box<dyn Read + Send>),
        ),
        (
            false,
            child
                .stderr
                .take()
                .map(|s| Box::new(s) as Box<dyn Read + Send>),
        ),
    ] {
        let Some(stream) = stream else { continue };
        let m = program.masker();
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut kept = Vec::new();
            let mut cut = false;
            pump(stream, Some(m), |b| {
                let room = max_output.saturating_sub(kept.len());
                if b.len() > room {
                    cut = true;
                }
                kept.extend_from_slice(&b[..b.len().min(room)]);
            });
            let _ = tx.send((is_out, kept, cut));
        });
    }
    drop(tx);
    let (status, timed_out) = wait_until(&mut child, Instant::now() + timeout)?;
    let mut out = Captured {
        exit_code: status.map(exit_code),
        timed_out,
        ..Captured::default()
    };
    let deadline = Instant::now() + DRAIN;
    while let Ok((is_out, kept, cut)) =
        rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
    {
        let text = String::from_utf8_lossy(&kept).into_owned();
        if is_out {
            out.stdout = text;
        } else {
            out.stderr = text;
        }
        out.truncated |= cut;
    }
    Ok(out)
}

/// Waits for the child until `deadline`, then stops its process group.
fn wait_until(child: &mut Child, deadline: Instant) -> std::io::Result<(Option<ExitStatus>, bool)> {
    loop {
        if let Some(s) = child.try_wait()? {
            return Ok((Some(s), false));
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let group = -(child.id() as i32);
    // SAFETY: kill only sends a signal; the group is the child's own (process_group(0)).
    unsafe { libc::kill(group, libc::SIGTERM) };
    let grace = Instant::now() + Duration::from_secs(2);
    while Instant::now() < grace {
        if child.try_wait()?.is_some() {
            // SAFETY: as above; this reaches what the child left running in its group.
            unsafe { libc::kill(group, libc::SIGKILL) };
            return Ok((None, true));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // SAFETY: as above.
    unsafe { libc::kill(group, libc::SIGKILL) };
    let _ = child.wait();
    Ok((None, true))
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
