//! The Git commands sync runs, each with a timeout, no prompts, no hooks and literal paths.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use vaultos_core::crypto::sha256_hex;

const LOCAL: Duration = Duration::from_secs(60);
const NETWORK: Duration = Duration::from_secs(60);
const GIT_ENV: [(&str, &str); 3] = [
    ("GIT_TERMINAL_PROMPT", "0"),
    ("GIT_ASKPASS", "/bin/true"),
    ("SSH_ASKPASS", "/bin/true"),
];

/// A Git command's outcome: its trimmed output, or the first lines of its error.
#[derive(Clone, Debug)]
pub struct Out {
    pub ok: bool,
    pub out: String,
    pub error: String,
}

/// The outcome of a network step, with a code naming the kind of failure.
#[derive(Clone, Debug, Default)]
pub struct Remote {
    pub ok: bool,
    pub error: String,
    pub code: &'static str,
    pub changed: bool,
    pub remote_sha: Option<String>,
}

impl Remote {
    fn fail(code: &'static str, error: impl Into<String>) -> Remote {
        Remote {
            ok: false,
            error: error.into(),
            code,
            ..Remote::default()
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Divergence {
    pub ahead: u64,
    pub behind: u64,
}

/// The outcome of [`GitRepo::commit_paths`].
#[derive(Clone, Debug)]
pub struct Commit {
    pub ok: bool,
    pub committed: bool,
    pub sha: Option<String>,
    pub error: String,
}

fn first_lines(s: &str) -> String {
    scrub_urls(&s.trim().lines().take(4).collect::<Vec<_>>().join(" "))
}

/// Git's messages quote remote URLs in full. A user name and password, or a token in a query
/// string, would reach the daemon's log and the audit log, so both are masked.
fn scrub_urls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("://") {
        let (head, tail) = rest.split_at(i + 3);
        out.push_str(head);
        let end = tail
            .find(|c: char| c.is_whitespace() || matches!(c, '\'' | '"' | '<' | '>' | '`'))
            .unwrap_or(tail.len());
        let (url, after) = tail.split_at(end);
        let host_end = url.find(['/', '?', '#']).unwrap_or(url.len());
        let (authority, path) = url.split_at(host_end);
        match authority.rfind('@') {
            Some(at) => {
                out.push_str("***@");
                out.push_str(&authority[at + 1..]);
            }
            None => out.push_str(authority),
        }
        match path.find(['?', '#']) {
            Some(q) => {
                out.push_str(&path[..q]);
                out.push_str("?***");
            }
            None => out.push_str(path),
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Git's own control files, wherever they are.
fn control_file(rel: &str) -> bool {
    matches!(
        rel.rsplit('/').next().unwrap_or(rel),
        ".gitignore" | ".gitattributes" | ".gitmodules"
    )
}

/// Runs `git` with the arguments every sync command uses. Every path VaultOS hands Git is a
/// file or folder name, never a pattern: without `--literal-pathspecs` a stray file named
/// `records/*` would match every record.
fn run(repo: &Path, args: &[&str], timeout: Duration, env: &[(String, String)]) -> Out {
    let mut cmd = Command::new("git");
    cmd.args([
        "--literal-pathspecs",
        "-c",
        "core.hooksPath=/dev/null",
        "-C",
    ])
    .arg(repo)
    .args(args)
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .envs(GIT_ENV)
    .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    let fail = |error: String| Out {
        ok: false,
        out: String::new(),
        error,
    };
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return fail(format!("cannot run git: {e}")),
    };
    let (tx, rx) = mpsc::channel();
    for (which, pipe) in [
        (
            0u8,
            child
                .stdout
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
        ),
        (
            1u8,
            child
                .stderr
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
        ),
    ] {
        if let Some(mut pipe) = pipe {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = pipe.read_to_end(&mut buf);
                let _ = tx.send((which, buf));
            });
        }
    }
    drop(tx);
    let deadline = Instant::now() + timeout;
    let mut pause = Duration::from_millis(1);
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(pause);
                pause = (pause * 2).min(Duration::from_millis(20));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    // A persisted SSH master may hold an inherited pipe open after git itself has exited.
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    for _ in 0..2 {
        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok((0, b)) => stdout = b,
            Ok((_, b)) => stderr = b,
            Err(_) => break,
        }
    }
    let stdout = String::from_utf8_lossy(&stdout).trim_end().to_owned();
    let stderr = String::from_utf8_lossy(&stderr).into_owned();
    match status {
        Some(s) if s.success() => Out {
            ok: true,
            out: stdout,
            error: String::new(),
        },
        Some(s) => fail(first_lines(&format!(
            "{stderr} {stdout} git exited with {}",
            s.code()
                .map_or_else(|| "a signal".into(), |c| c.to_string())
        ))),
        None => fail(first_lines(&format!(
            "{stderr} git stopped after {}s; the remote may have timed out",
            timeout.as_secs()
        ))),
    }
}

/// One sync round fetches, pushes and fetches again to verify the push. Over SSH each of those
/// was a separate handshake. A private control socket per remote lets them share one
/// connection, and keeps it for a few minutes so the next autosync round reuses it too.
/// Anything the user configured for SSH wins, and an unsafe socket folder turns reuse off.
fn ssh_reuse_env(repo: &Path, remote: &str) -> Vec<(String, String)> {
    if std::env::var_os("GIT_SSH_COMMAND").is_some() || std::env::var_os("GIT_SSH").is_some() {
        return Vec::new();
    }
    let configured = run(repo, &["config", "--get", "core.sshCommand"], LOCAL, &[]);
    if configured.ok && !configured.out.is_empty() {
        return Vec::new();
    }
    let url = run(repo, &["remote", "get-url", remote], LOCAL, &[]);
    if !url.ok || url.out.is_empty() {
        return Vec::new();
    }
    let dir = std::env::temp_dir().join(format!("vaultos-ssh-{}", vaultos_core::session::euid()));
    let Some(dir_str) = dir.to_str() else {
        return Vec::new();
    };
    if !dir_str
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
    {
        return Vec::new();
    }
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    if let Err(e) = builder.create(&dir) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            return Vec::new();
        }
    }
    if !vaultos_core::session::private_to_us(&dir) {
        return Vec::new();
    }
    let socket = dir.join(&sha256_hex(url.out.as_bytes())[..16]);
    vec![(
        "GIT_SSH_COMMAND".into(),
        format!(
            "ssh -o ControlMaster=auto -o ControlPersist=300 -o ControlPath={}",
            socket.display()
        ),
    )]
}

/// Makes `dir` a checkout of the sync repository at `url`: a clone when the remote already
/// has a branch, otherwise a new repository on `main` with `origin` set. Says whether it
/// cloned. Commits need an author, so one is set for this checkout when Git has none.
pub fn prepare(dir: &Path, url: &str) -> Result<bool, String> {
    let url = url.trim();
    if url.is_empty() || url.len() > 2000 || url.starts_with('-') || url.contains(char::is_control)
    {
        return Err("Enter the Git address of your private sync repository".into());
    }
    if scrub_urls(url) != url {
        return Err("Leave passwords and tokens out of the address; Git's credential helper or an SSH key signs in".into());
    }
    if dir.join(".git").exists() {
        return Err("This device already has a sync checkout".into());
    }
    if std::fs::read_dir(dir).is_ok_and(|mut d| d.next().is_some()) {
        return Err(format!("{} is not empty", dir.display()));
    }
    let (Some(parent), Some(target)) = (dir.parent(), dir.to_str()) else {
        return Err("Invalid sync checkout path".into());
    };
    let heads = run(parent, &["ls-remote", "--heads", "--", url], NETWORK, &[]);
    if !heads.ok {
        return Err(format!("Cannot reach the sync repository: {}", heads.error));
    }
    let cloned = !heads.out.is_empty();
    let made = if cloned {
        run(parent, &["clone", "--quiet", "--", url, target], NETWORK, &[])
    } else {
        run(parent, &["init", "--quiet", "-b", "main", target], LOCAL, &[])
    };
    if !made.ok {
        return Err(format!("Cannot create the sync checkout: {}", made.error));
    }
    let git = |args: &[&str]| run(dir, args, LOCAL, &[]);
    if !cloned {
        let added = git(&["remote", "add", "origin", url]);
        if !added.ok {
            return Err(added.error);
        }
    }
    if git(&["config", "user.email"]).out.is_empty() {
        git(&["config", "user.name", "VaultOS Sync"]);
        git(&["config", "user.email", "sync@vaultos.local"]);
    }
    Ok(cloned)
}

/// A sync checkout. Its branch, remote and SSH settings are looked up once.
#[derive(Debug)]
pub struct GitRepo {
    dir: PathBuf,
    branch: OnceLock<String>,
    remote: OnceLock<String>,
    ssh: OnceLock<Vec<(String, String)>>,
}

impl GitRepo {
    pub fn new(dir: &Path) -> GitRepo {
        GitRepo {
            dir: dir.to_owned(),
            branch: OnceLock::new(),
            remote: OnceLock::new(),
            ssh: OnceLock::new(),
        }
    }

    fn git(&self, args: &[&str]) -> Out {
        run(&self.dir, args, LOCAL, &[])
    }

    fn net(&self, args: &[&str], remote: &str) -> Out {
        let env = self.ssh.get_or_init(|| ssh_reuse_env(&self.dir, remote));
        run(&self.dir, args, NETWORK, env)
    }

    pub fn is_repo(&self) -> bool {
        self.dir.join(".git").exists()
    }

    pub fn branch(&self) -> Option<String> {
        if let Some(b) = self.branch.get() {
            return Some(b.clone());
        }
        let r = self.git(&["rev-parse", "--abbrev-ref", "HEAD"]);
        (r.ok && !r.out.is_empty()).then(|| self.branch.get_or_init(|| r.out).clone())
    }

    pub fn remote_name(&self) -> Option<String> {
        if let Some(r) = self.remote.get() {
            return Some(r.clone());
        }
        let r = self.git(&["remote"]);
        if !r.ok {
            return None;
        }
        let names: Vec<&str> = r
            .out
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        let name = if names.contains(&"origin") {
            "origin"
        } else {
            names.first()?
        };
        Some(self.remote.get_or_init(|| name.to_owned()).clone())
    }

    pub fn head(&self) -> Option<String> {
        let r = self.git(&["rev-parse", "HEAD"]);
        r.ok.then_some(r.out)
    }

    /// The files under these paths that Git tracks, committed or staged.
    pub fn tracked_paths(&self, paths: &[&str]) -> Result<BTreeSet<String>, String> {
        let mut args = vec!["ls-files", "-z", "--"];
        args.extend_from_slice(paths);
        let r = self.git(&args);
        if !r.ok {
            return Err(r.error);
        }
        Ok(r.out
            .split('\0')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect())
    }

    /// The untracked files under these paths that Git's ignore rules hide from `git status`.
    pub fn ignored_paths(&self, paths: &[&str]) -> Result<Vec<String>, String> {
        let mut args = vec![
            "ls-files",
            "-z",
            "--others",
            "--ignored",
            "--exclude-standard",
            "--",
        ];
        args.extend_from_slice(paths);
        let r = self.git(&args);
        if !r.ok {
            return Err(r.error);
        }
        Ok(r.out
            .split('\0')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect())
    }

    /// Each path that differs from HEAD, staged or not. Files in an untracked folder are
    /// listed one by one.
    pub fn changed_paths(&self) -> Result<Vec<String>, String> {
        let r = self.git(&[
            "status",
            "--porcelain=v1",
            "-z",
            "--no-renames",
            "--untracked-files=all",
        ]);
        if !r.ok {
            return Err(r.error);
        }
        Ok(r.out
            .split('\0')
            .filter(|s| s.len() > 3)
            .map(|e| e[3..].to_owned())
            .collect())
    }

    pub fn fetch(&self) -> Remote {
        let Some(remote) = self.remote_name() else {
            return Remote::fail("NO_REMOTE", "no git remote configured");
        };
        let r = self.net(&["fetch", "--quiet", &remote], &remote);
        if !r.ok {
            return Remote::fail("REMOTE_UNREACHABLE", r.error);
        }
        Remote {
            ok: true,
            ..Remote::default()
        }
    }

    pub fn divergence(&self) -> Result<Divergence, String> {
        let (Some(branch), Some(remote)) = (self.branch(), self.remote_name()) else {
            return Err("no branch or remote".into());
        };
        let r = self.git(&[
            "rev-list",
            "--left-right",
            "--count",
            &format!("{remote}/{branch}...HEAD"),
        ]);
        if !r.ok {
            return Err(r.error);
        }
        let mut n = r.out.split_whitespace().map(|n| n.parse().unwrap_or(0));
        let behind = n.next().unwrap_or(0);
        let ahead = n.next().unwrap_or(0);
        Ok(Divergence { ahead, behind })
    }

    pub fn remote_head(&self) -> Option<String> {
        let (branch, remote) = (self.branch()?, self.remote_name()?);
        let r = self.git(&["rev-parse", &format!("{remote}/{branch}")]);
        r.ok.then_some(r.out)
    }

    /// Commits `paths` as they are in the working tree, and removes `untrack` from the
    /// repository while leaving those files on disk.
    pub fn commit_paths(&self, paths: &[String], message: &str, untrack: &[String]) -> Commit {
        let all: Vec<&str> = paths.iter().chain(untrack).map(String::as_str).collect();
        let done = |committed| Commit {
            ok: true,
            committed,
            sha: self.head(),
            error: String::new(),
        };
        // With no paths, `git add --` adds nothing but `git reset --` would unstage everything.
        if all.is_empty() {
            return done(false);
        }
        let fail_plain = |error: String| Commit {
            ok: false,
            committed: false,
            sha: None,
            error,
        };
        let pre = self.git(&["diff", "--cached", "--name-only"]);
        if !pre.ok {
            return fail_plain(pre.error);
        }
        let unrelated: Vec<&str> = pre
            .out
            .lines()
            .filter(|f| {
                !f.is_empty()
                    && !all
                        .iter()
                        .any(|p| f == p || f.strip_prefix(p).is_some_and(|r| r.starts_with('/')))
            })
            .take(3)
            .collect();
        if !unrelated.is_empty() {
            return fail_plain(format!(
                "Unrelated staged files; refusing to commit: {}",
                unrelated.join(", ")
            ));
        }
        // A failure after `git add` unstages the paths again. Left staged, they made the next
        // commit of other paths refuse, and Git does not rebase over staged changes.
        let fail = |error: String| {
            let mut args = vec!["reset", "--quiet", "--"];
            args.extend_from_slice(&all);
            self.git(&args);
            fail_plain(error)
        };
        if !paths.is_empty() {
            let mut args = vec!["add", "--"];
            args.extend(paths.iter().map(String::as_str));
            let r = self.git(&args);
            if !r.ok {
                return fail(r.error);
            }
            match self.converted(paths) {
                Ok(c) if c.is_empty() => {}
                Ok(c) => {
                    return fail(format!(
                        "Git would change the bytes of {} (a .gitattributes, info/attributes or line-ending rule); refusing to commit",
                        c.join(", ")
                    ))
                }
                Err(e) => return fail(e),
            }
        }
        if !untrack.is_empty() {
            let mut args = vec!["rm", "--cached", "--quiet", "--ignore-unmatch", "-r", "--"];
            args.extend(untrack.iter().map(String::as_str));
            let r = self.git(&args);
            if !r.ok {
                return fail(r.error);
            }
        }
        let staged = self.git(&["diff", "--cached", "--name-only"]);
        if !staged.ok {
            return fail(staged.error);
        }
        if staged.out.is_empty() {
            return done(false);
        }
        let c = self.git(&["commit", "--quiet", "-m", message]);
        if !c.ok {
            return fail(c.error);
        }
        done(true)
    }

    /// Of `paths`, the files whose staged content is not their bytes on disk: an attribute,
    /// filter or line-ending rule changed them on the way into Git, so a digest signed over
    /// the file would not match what peers receive.
    fn converted(&self, paths: &[String]) -> Result<Vec<String>, String> {
        let files: Vec<&str> = paths
            .iter()
            .map(String::as_str)
            .filter(|p| self.dir.join(p).is_file())
            .collect();
        if files.is_empty() {
            return Ok(Vec::new());
        }
        let mut args = vec!["hash-object", "--no-filters", "--"];
        args.extend(&files);
        let raw = self.git(&args);
        if !raw.ok {
            return Err(raw.error);
        }
        let mut args = vec!["ls-files", "--stage", "-z", "--"];
        args.extend(&files);
        let staged = self.git(&args);
        if !staged.ok {
            return Err(staged.error);
        }
        // `<mode> <object> <stage>\t<path>` per entry.
        let index: std::collections::HashMap<&str, &str> = staged
            .out
            .split('\0')
            .filter_map(|e| {
                let (meta, path) = e.split_once('\t')?;
                Some((path, meta.split_whitespace().nth(1)?))
            })
            .collect();
        Ok(files
            .iter()
            .zip(raw.out.split_whitespace())
            .filter(|(f, object)| index.get(*f) != Some(object))
            .map(|(f, _)| (*f).to_owned())
            .collect())
    }

    fn rebase_on_remote(&self) -> Remote {
        let (Some(branch), Some(remote)) = (self.branch(), self.remote_name()) else {
            return Remote::fail("GIT_HISTORY_DIVERGED", "no branch or remote");
        };
        // Git refuses to rebase over uncommitted changes to tracked files. That is a dirty
        // checkout, not diverged history, and is reported as one.
        let tracked = self.git(&["status", "--porcelain=v1", "--untracked-files=no"]);
        if tracked.ok && !tracked.out.is_empty() {
            let files: Vec<&str> = tracked
                .out
                .lines()
                .take(3)
                .map(|l| l.get(3..).unwrap_or(l))
                .collect();
            return Remote::fail(
                "LOCAL_SYNC_REPO_DIRTY",
                format!("uncommitted changes block the rebase: {}", files.join(", ")),
            );
        }
        let r = self.git(&["rebase", "--quiet", &format!("{remote}/{branch}")]);
        if r.ok {
            return Remote {
                ok: true,
                changed: true,
                ..Remote::default()
            };
        }
        self.git(&["rebase", "--abort"]);
        Remote::fail("GIT_HISTORY_DIVERGED", r.error)
    }

    /// Pushes HEAD, rebasing once onto the remote if it moved, then fetches again to check
    /// the remote now holds this commit.
    pub fn push(&self) -> Remote {
        let (Some(branch), Some(remote)) = (self.branch(), self.remote_name()) else {
            return Remote::fail("NO_REMOTE", "no git remote configured");
        };
        let refspec = format!("HEAD:{branch}");
        let mut r = self.net(&["push", "--quiet", &remote, &refspec], &remote);
        if !r.ok {
            let f = self.fetch();
            if !f.ok {
                return Remote::fail("REMOTE_UNREACHABLE", f.error);
            }
            let rb = self.rebase_on_remote();
            if !rb.ok {
                return rb;
            }
            // The rebase brought in commits nothing has verified yet. Their ciphertext is
            // checked by the next pull before anything is applied; a Git control file changes
            // what this checkout commits from now on, so it stops the push here.
            match self.tracked_paths(&["."]) {
                Ok(all) => {
                    let control: Vec<String> =
                        all.into_iter().filter(|f| control_file(f)).collect();
                    if !control.is_empty() {
                        return Remote::fail(
                            "SIGNATURE_INVALID",
                            format!(
                                "The remote added Git control files that change what sync commits; remove them with git rm: {}",
                                control.join(", ")
                            ),
                        );
                    }
                }
                Err(e) => return Remote::fail("GIT_HISTORY_DIVERGED", e),
            }
            r = self.net(&["push", "--quiet", &remote, &refspec], &remote);
        }
        if !r.ok {
            return Remote::fail("PUSH_REJECTED", r.error);
        }
        let readback = self.net(&["fetch", "--quiet", &remote], &remote);
        let head = self.head();
        if !readback.ok || head.is_none() || self.remote_head() != head {
            return Remote::fail("RECEIPT_UNVERIFIED", "Could not verify remote receipt");
        }
        Remote {
            ok: true,
            remote_sha: head,
            ..Remote::default()
        }
    }

    /// Brings the checkout up to the remote: fast-forward, or rebase this device's own
    /// commits on top.
    pub fn pull_ff(&self) -> Remote {
        let f = self.fetch();
        if !f.ok {
            return f;
        }
        let div = match self.divergence() {
            Ok(d) => d,
            Err(e) => return Remote::fail("GIT_HISTORY_DIVERGED", e),
        };
        if div.behind == 0 {
            return Remote {
                ok: true,
                ..Remote::default()
            };
        }
        if div.ahead > 0 {
            return self.rebase_on_remote();
        }
        let (Some(branch), Some(remote)) = (self.branch(), self.remote_name()) else {
            return Remote::fail("GIT_HISTORY_DIVERGED", "no branch or remote");
        };
        let r = self.git(&[
            "merge",
            "--quiet",
            "--ff-only",
            &format!("{remote}/{branch}"),
        ]);
        if !r.ok {
            return Remote::fail("GIT_HISTORY_DIVERGED", r.error);
        }
        Remote {
            ok: true,
            changed: true,
            ..Remote::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_never_carry_url_credentials() {
        let e = "fatal: unable to access 'https://user:synthetic-pass@git.example.invalid/r.git?token=synthetic-token': Could not resolve host";
        let s = scrub_urls(e);
        assert!(
            !s.contains("synthetic-pass") && !s.contains("synthetic-token"),
            "{s}"
        );
        assert!(
            s.contains("https://***@git.example.invalid/r.git?***'"),
            "{s}"
        );
        assert_eq!(
            scrub_urls("ssh://git.example.invalid/r.git and git@host:r.git"),
            "ssh://git.example.invalid/r.git and git@host:r.git"
        );
    }
}
