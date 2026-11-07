//! What `vaultos` and `vaultos-agent` share: failures with exit codes, JSON output, and
//! bounded reads from stdin into buffers that are zeroed when dropped.

use std::io::{Read, Write};
use zeroize::Zeroizing;

/// A failure to report: the message goes to stderr and `code` is the exit status.
#[derive(Debug)]
pub struct Fail {
    pub message: String,
    pub code: u8,
}

impl Fail {
    pub fn new(message: impl Into<String>) -> Fail {
        Fail {
            message: message.into(),
            code: 1,
        }
    }

    pub fn usage(message: impl Into<String>) -> Fail {
        Fail {
            message: message.into(),
            code: 2,
        }
    }
}

impl From<vaultos_core::Error> for Fail {
    fn from(e: vaultos_core::Error) -> Fail {
        Fail::new(e.to_string())
    }
}

impl From<vaultos_client::ClientError> for Fail {
    fn from(e: vaultos_client::ClientError) -> Fail {
        Fail {
            code: e.code.exit_code(),
            message: e.message,
        }
    }
}

pub type Result<T> = std::result::Result<T, Fail>;

/// Prints `value` as indented JSON, the way the JavaScript tools did.
pub fn emit(value: &impl serde::Serialize) -> Result<()> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|_| Fail::new("The result could not be encoded"))?;
    say(&text)
}

/// Prints one line on stdout.
pub fn say(text: &str) -> Result<()> {
    writeln!(std::io::stdout().lock(), "{text}").map_err(|_| Fail::new("cannot write to stdout"))
}

/// All of stdin as UTF-8, refusing more than `max` bytes.
pub fn read_stdin(max: usize, too_large: &str) -> Result<Zeroizing<String>> {
    // Sized up front and bounded by `take`, so the buffer never grows and leaves a copy.
    let mut buf = Zeroizing::new(Vec::with_capacity(max + 1));
    std::io::stdin()
        .lock()
        .take(max as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|_| Fail::new("cannot read stdin"))?;
    if buf.len() > max {
        return Err(Fail::new(too_large));
    }
    let text = std::str::from_utf8(&buf).map_err(|_| Fail::new("stdin is not UTF-8 text"))?;
    Ok(Zeroizing::new(text.to_owned()))
}
