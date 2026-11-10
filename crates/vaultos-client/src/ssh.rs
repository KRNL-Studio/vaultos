//! A client for an SSH agent's socket (the app's, or any `SSH_AUTH_SOCK`): list its keys and
//! ask it to sign. `vaultos-ssh-sign` and `vaultos ssh keys` use it.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;
use vaultos_core::ssh::{
    self, put_string, Reader, FAILURE, IDENTITIES_ANSWER, MAX_MESSAGE, REQUEST_IDENTITIES,
    SIGN_REQUEST, SIGN_RESPONSE,
};

#[derive(Debug, PartialEq, Eq)]
pub enum AgentError {
    /// Nothing listens on the socket.
    Unreachable,
    /// The agent refused: the key is not there, the vault is locked, or the human declined.
    Refused,
    Protocol,
}

fn request(socket: &Path, message: &[u8], timeout: Duration) -> Result<Vec<u8>, AgentError> {
    let mut s = UnixStream::connect(socket).map_err(|_| AgentError::Unreachable)?;
    // Signing waits for the human; listing does not.
    let _ = s.set_read_timeout(Some(timeout));
    let mut out = Vec::with_capacity(message.len() + 4);
    put_string(&mut out, message);
    s.write_all(&out).map_err(|_| AgentError::Unreachable)?;
    let mut len = [0u8; 4];
    s.read_exact(&mut len).map_err(|_| AgentError::Protocol)?;
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > MAX_MESSAGE {
        return Err(AgentError::Protocol);
    }
    let mut reply = vec![0u8; n];
    s.read_exact(&mut reply).map_err(|_| AgentError::Protocol)?;
    Ok(reply)
}

/// The agent's keys: (public key blob, comment).
pub fn identities(socket: &Path) -> Result<Vec<(Vec<u8>, String)>, AgentError> {
    let reply = request(socket, &[REQUEST_IDENTITIES], Duration::from_secs(10))?;
    let mut r = Reader(&reply);
    if r.u8().map_err(|_| AgentError::Protocol)? != IDENTITIES_ANSWER {
        return Err(AgentError::Protocol);
    }
    let n = r.u32().map_err(|_| AgentError::Protocol)?;
    let mut out = Vec::new();
    for _ in 0..n.min(1024) {
        let blob = r.string().map_err(|_| AgentError::Protocol)?.to_vec();
        let comment = String::from_utf8_lossy(r.string().map_err(|_| AgentError::Protocol)?);
        out.push((blob, comment.into_owned()));
    }
    Ok(out)
}

/// A signature blob for `data` from the key `blob`. Waits up to two minutes for the human.
pub fn sign(socket: &Path, blob: &[u8], data: &[u8]) -> Result<Vec<u8>, AgentError> {
    let mut message = vec![SIGN_REQUEST];
    put_string(&mut message, blob);
    put_string(&mut message, data);
    ssh::put_u32(&mut message, 0);
    let reply = request(socket, &message, Duration::from_secs(120))?;
    let mut r = Reader(&reply);
    match r.u8().map_err(|_| AgentError::Protocol)? {
        SIGN_RESPONSE => Ok(r.string().map_err(|_| AgentError::Protocol)?.to_vec()),
        FAILURE => Err(AgentError::Refused),
        _ => Err(AgentError::Protocol),
    }
}
