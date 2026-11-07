//! The app's SSH agent, off until the human turns it on: OpenSSH's agent protocol on a
//! socket private to this user (`ssh-agent.sock`), serving the Ed25519 keys of `ssh_key`
//! items. It lists keys only while the vault is unlocked, and signs only after the human
//! confirms (Touch ID, or the app's dialog where there is none). A confirmation covers that
//! program and key for ten minutes or until the vault locks. It never adds, removes or
//! exports keys, and agent tokens play no part in it.

use crate::human::Peer;
use crate::server::{Confirm, Confirming, Shared};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use vaultos_core::session::{euid, prepare_socket_dir, ssh_socket_path};
use vaultos_core::ssh::{self, Purpose, Request, FAILURE, MAX_MESSAGE};
use vaultos_core::store::SshIdentity;
use vaultos_core::Error;

/// How long a confirmation covers the same program and key.
pub const REMEMBER: Duration = Duration::from_secs(600);

/// (program, key blob) → when it was confirmed, and the vault's lock count then.
type Approvals = HashMap<(PathBuf, Vec<u8>), (Instant, u64)>;

#[derive(Debug, Default)]
pub(crate) struct SshAgent {
    running: Mutex<Option<(PathBuf, tokio::task::JoinHandle<()>)>>,
    approved: Mutex<Approvals>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Starts listening, or returns the socket it already listens on.
pub(crate) fn start(shared: &Arc<Shared>, confirm: Confirm) -> Result<PathBuf, Error> {
    let mut running = lock(&shared.ssh.running);
    if let Some((socket, _)) = running.as_ref().filter(|(_, t)| !t.is_finished()) {
        return Ok(socket.clone());
    }
    let socket = ssh_socket_path(&shared.data_dir)?;
    prepare_socket_dir(&socket, &shared.data_dir)?;
    crate::server::remove_stale_socket(&socket)?;
    let listener = {
        let _rt = shared.runtime.enter();
        UnixListener::bind(&socket).map_err(Error::io("cannot listen on the SSH agent socket"))?
    };
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .map_err(Error::io("cannot restrict the SSH agent socket"))?;
    }
    let task = shared
        .runtime
        .spawn(accept(listener, shared.clone(), confirm));
    *running = Some((socket.clone(), task));
    Ok(socket)
}

/// Stops listening, removes the socket and forgets every confirmation.
pub(crate) fn stop(shared: &Shared) {
    if let Some((socket, task)) = lock(&shared.ssh.running).take() {
        task.abort();
        let _ = crate::server::remove_stale_socket(&socket);
    }
    lock(&shared.ssh.approved).clear();
}

pub(crate) fn socket(shared: &Shared) -> Option<PathBuf> {
    lock(&shared.ssh.running)
        .as_ref()
        .filter(|(_, t)| !t.is_finished())
        .map(|(s, _)| s.clone())
}

async fn accept(listener: UnixListener, shared: Arc<Shared>, confirm: Confirm) {
    let uid = euid();
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let Ok(cred) = stream.peer_cred() else {
            continue;
        };
        if cred.uid() != uid {
            continue;
        }
        let peer = Peer::of(cred.pid());
        tokio::spawn(serve(stream, peer, shared.clone(), confirm.clone()));
    }
}

/// One client: length-prefixed requests, answered in order, until it hangs up.
async fn serve(mut stream: UnixStream, peer: Peer, shared: Arc<Shared>, confirm: Confirm) {
    let peer = Arc::new(peer);
    loop {
        let mut len = [0u8; 4];
        if stream.read_exact(&mut len).await.is_err() {
            return;
        }
        let n = u32::from_be_bytes(len) as usize;
        if n == 0 || n > MAX_MESSAGE {
            return;
        }
        let mut message = vec![0u8; n];
        if stream.read_exact(&mut message).await.is_err() {
            return;
        }
        let (s, p, c) = (shared.clone(), peer.clone(), confirm.clone());
        let reply = tokio::task::spawn_blocking(move || answer(&s, &p, &c, &message))
            .await
            .unwrap_or_else(|_| vec![FAILURE]);
        let mut out = Vec::with_capacity(reply.len() + 4);
        ssh::put_string(&mut out, &reply);
        if stream.write_all(&out).await.is_err() {
            return;
        }
    }
}

fn answer(shared: &Shared, peer: &Peer, confirm: &Confirm, message: &[u8]) -> Vec<u8> {
    match Request::parse(message) {
        Ok(Request::List) => {
            let keys: Vec<_> = identities(shared)
                .into_iter()
                .map(|i| (i.blob, format!("{} ({})", i.item, i.project)))
                .collect();
            ssh::identities_answer(&keys)
        }
        Ok(Request::Sign { key, data }) => sign(shared, peer, confirm, key, data)
            .map_or_else(|| vec![FAILURE], |s| ssh::sign_response(&s)),
        _ => vec![FAILURE],
    }
}

fn identities(shared: &Shared) -> Vec<SshIdentity> {
    shared.with_store(|s| {
        if !s.is_unlocked() || s.reload_if_changed().is_err() {
            return Vec::new();
        }
        s.ssh_identities().unwrap_or_default()
    })
}

fn sign(
    shared: &Shared,
    peer: &Peer,
    confirm: &Confirm,
    key: &[u8],
    data: &[u8],
) -> Option<Vec<u8>> {
    let locks = shared.with_store(|s| s.lock_count());
    let id = identities(shared).into_iter().find(|i| i.blob == key)?;
    let remember = peer.exe.clone().map(|exe| (exe, key.to_vec()));
    let fresh = remember.as_ref().is_some_and(|r| {
        lock(&shared.ssh.approved)
            .get(r)
            .is_some_and(|(at, n)| *n == locks && at.elapsed() < REMEMBER)
    });
    if !fresh {
        if shared.confirming.swap(true, Ordering::SeqCst) {
            return None;
        }
        let _one = Confirming(&shared.confirming);
        if (confirm.0)(&reason(&id, data, peer)) != Some(true) {
            return None;
        }
        if let Some(r) = remember {
            lock(&shared.ssh.approved).insert(r, (Instant::now(), locks));
        }
    }
    shared.with_store(|s| {
        if s.lock_count() != locks {
            return None;
        }
        s.ssh_sign(key, data, &peer.named()).ok()
    })
}

/// The confirmation's words ("VaultOS is trying to …").
pub fn reason(id: &SshIdentity, data: &[u8], peer: &Peer) -> String {
    let key = format!(
        "the SSH key “{}” ({})",
        crate::human::clean(&id.item),
        crate::human::clean(&id.project)
    );
    let what = match ssh::purpose(data) {
        Purpose::Namespace(ns) if ns == "git" => format!("sign a Git commit or tag with {key}"),
        Purpose::Namespace(ns) => format!("sign “{}” data with {key}", crate::human::clean(&ns)),
        Purpose::Login(user) => format!("sign in as “{}” with {key}", crate::human::clean(&user)),
        Purpose::Unknown => format!("sign with {key}"),
    };
    format!("{what}, for {}", peer.shown())
}
