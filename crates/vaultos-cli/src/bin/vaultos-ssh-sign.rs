//! `vaultos-ssh-sign`: Git's `gpg.ssh.program` for keys the VaultOS app's SSH agent holds.
//! It takes ssh-keygen's arguments. `-Y sign` with a public key the app offers is signed by
//! the app (which asks the human first); everything else (other keys, `-Y verify`,
//! `find-principals`, `check-novalidate`) runs ssh-keygen with the same arguments.
//!
//!     git config --global gpg.format ssh
//!     git config --global gpg.ssh.program /path/to/vaultos-ssh-sign
//!     git config --global user.signingkey "key::ssh-ed25519 AAAA…"
//!     git config --global commit.gpgsign true

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use vaultos_client::ssh::{identities, sign, AgentError};
use vaultos_core::ssh::{parse_public_line, sshsig_armor, sshsig_signed_data};

const MAX_KEY_FILE: u64 = 64 * 1024;
const MAX_MESSAGE: u64 = 256 * 1024 * 1024;

/// What `-Y sign` asks for, when this program can do it itself.
struct Sign {
    namespace: String,
    key_file: PathBuf,
    files: Vec<PathBuf>,
}

fn parse(args: &[OsString]) -> Option<Sign> {
    let mut it = args.iter();
    let (mut mode, mut namespace, mut key_file, mut files) = (None, None, None, Vec::new());
    while let Some(a) = it.next() {
        match a.to_str() {
            Some("-Y") => mode = it.next()?.to_str(),
            Some("-n") => namespace = it.next()?.to_str(),
            Some("-f") => key_file = Some(PathBuf::from(it.next()?)),
            // The key is in an agent: that is what this program checks anyway.
            Some("-U") => {}
            // Options (-O) and anything else ssh-keygen knows better.
            Some(s) if s.starts_with('-') && s != "-" => return None,
            _ => files.push(PathBuf::from(a)),
        }
    }
    (mode? == "sign").then_some(())?;
    Some(Sign {
        namespace: namespace?.to_owned(),
        key_file: key_file?,
        files,
    })
}

fn read_limited(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    std::fs::File::open(path)?
        .take(max + 1)
        .read_to_end(&mut out)?;
    if out.len() as u64 > max {
        return Err(std::io::Error::other("the file is too large"));
    }
    Ok(out)
}

fn ssh_keygen(args: &[OsString]) -> ExitCode {
    let e = Command::new("ssh-keygen").args(args).exec();
    eprintln!("vaultos-ssh-sign: cannot run ssh-keygen: {e}");
    ExitCode::from(255)
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    // ssh-keygen has no --version, so this cannot shadow one of its options.
    if args.len() == 1 && args[0] == "--version" {
        let line = concat!("vaultos-ssh-sign ", env!("CARGO_PKG_VERSION"), "\n");
        return match std::io::stdout().write_all(line.as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(255),
        };
    }
    let Some(job) = parse(&args) else {
        return ssh_keygen(&args);
    };
    let Some(blob) = read_limited(&job.key_file, MAX_KEY_FILE)
        .ok()
        .and_then(|b| parse_public_line(String::from_utf8_lossy(&b).lines().next()?))
    else {
        // A private key file: ssh-keygen signs with it directly.
        return ssh_keygen(&args);
    };
    let socket = match vaultos_core::paths::default_data_dir()
        .and_then(|d| vaultos_core::session::ssh_socket_path(&d))
    {
        Ok(s) => s,
        Err(_) => return ssh_keygen(&args),
    };
    match identities(&socket) {
        Ok(keys) if keys.iter().any(|(b, _)| *b == blob) => {}
        Ok(keys) => {
            if keys.is_empty() {
                eprintln!("vaultos-ssh-sign: the VaultOS SSH agent offers no keys (is the app locked?); trying ssh-keygen");
            }
            return ssh_keygen(&args);
        }
        Err(_) => return ssh_keygen(&args),
    }
    let sign_one = |message: &[u8]| -> Result<String, String> {
        let data = sshsig_signed_data(&job.namespace, message);
        match sign(&socket, &blob, &data) {
            Ok(signature) => Ok(sshsig_armor(&blob, &job.namespace, &signature)),
            Err(AgentError::Refused) => {
                Err("VaultOS did not sign: the request was declined, or the vault locked".into())
            }
            Err(_) => Err("VaultOS's SSH agent did not answer".into()),
        }
    };
    let result = if job.files.is_empty() || job.files == [PathBuf::from("-")] {
        let mut message = Vec::new();
        std::io::stdin()
            .take(MAX_MESSAGE + 1)
            .read_to_end(&mut message)
            .map_err(|e| e.to_string())
            .and_then(|n| match n as u64 > MAX_MESSAGE {
                true => Err("the message is too large".into()),
                false => sign_one(&message),
            })
            .and_then(|armored| {
                std::io::stdout()
                    .write_all(armored.as_bytes())
                    .map_err(|e| e.to_string())
            })
    } else {
        job.files.iter().try_for_each(|f| {
            let message =
                read_limited(f, MAX_MESSAGE).map_err(|e| format!("{}: {e}", f.display()))?;
            let armored = sign_one(&message)?;
            let mut out = f.clone().into_os_string();
            out.push(".sig");
            std::fs::write(&out, armored).map_err(|e| format!("{}: {e}", Path::new(&out).display()))
        })
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vaultos-ssh-sign: {e}");
            ExitCode::from(255)
        }
    }
}
