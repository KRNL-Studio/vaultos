use thiserror::Error;

/// Every failure the core reports. Messages never contain secret values.
#[derive(Debug, Error)]
pub enum Error {
    /// Wrong password, wrong Secret Key, or a file that was modified.
    #[error("The password or Secret Key is wrong, or the vault file was modified")]
    Unlock,
    #[error("A Secret Key is required to unlock this vault")]
    SecretKeyRequired,
    #[error("Invalid Secret Key: {0}")]
    SecretKeyFormat(&'static str),
    #[error("The vault file failed its integrity check; it was modified or is damaged")]
    Integrity,
    #[error("Invalid encrypted vault: {0}")]
    Format(String),
    #[error("Unsupported vault format v{0}")]
    UnsupportedVersion(u64),
    #[error("This vault needs VaultOS format v{need}; this build understands v{have}")]
    TooNew { need: u64, have: u64 },
    #[error("Vault is locked")]
    Locked,
    #[error("This vault uses the previous format (v3). Upgrade it first; a backup is made before anything changes")]
    NeedsUpgrade,
    #[error("Vault already exists")]
    Exists,
    #[error(
        "Vault changed in another process; nothing was saved. Retry once the newer copy is loaded"
    )]
    Stale,
    #[error("Another VaultOS process is writing this vault")]
    Busy,
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    Conflict(String),
    #[error("The audit log failed verification: {0}")]
    Audit(String),
    #[error("{context}: {source}")]
    Io {
        context: &'static str,
        #[source]
        source: std::io::Error,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub(crate) fn io(context: &'static str) -> impl FnOnce(std::io::Error) -> Error {
        move |source| Error::Io { context, source }
    }

    pub(crate) fn invalid(msg: impl Into<String>) -> Error {
        Error::Invalid(msg.into())
    }

    pub(crate) fn not_found(msg: impl Into<String>) -> Error {
        Error::NotFound(msg.into())
    }

    pub(crate) fn forbidden(msg: impl Into<String>) -> Error {
        Error::Forbidden(msg.into())
    }

    /// HTTP-style status the API layer maps this error to.
    pub fn status(&self) -> u16 {
        match self {
            Error::Locked => 423,
            Error::Stale | Error::Busy | Error::Conflict(_) | Error::Exists => 409,
            Error::Forbidden(_) => 403,
            Error::NotFound(_) => 404,
            Error::Invalid(_) | Error::SecretKeyFormat(_) => 400,
            Error::Unlock | Error::SecretKeyRequired => 401,
            _ => 500,
        }
    }
}
