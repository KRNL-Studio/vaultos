//! A minimal HTTP/1.1 client over the daemon's Unix socket: one request per connection
//! (`Connection: close`), JSON bodies, and buffers holding tokens or values zeroed when
//! dropped. The daemon is the only server it talks to.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;
use zeroize::Zeroizing;

/// Larger than any reply the daemon sends (listings, fingerprints).
const MAX_RESPONSE: u64 = 32 * 1024 * 1024;

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub body: Zeroizing<Vec<u8>>,
}

#[derive(Debug)]
pub enum HttpError {
    Connect(std::io::Error),
    Io(std::io::Error),
    Malformed,
}

/// Header values must be printable ASCII (tokens are checked before they get here).
fn header_ok(v: &str) -> bool {
    v.bytes().all(|b| (0x20..0x7f).contains(&b))
}

pub fn request(
    socket: &Path,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
) -> Result<Response, HttpError> {
    if !header_ok(target)
        || target.contains(' ')
        || headers.iter().any(|(k, v)| !header_ok(k) || !header_ok(v))
    {
        return Err(HttpError::Malformed);
    }
    let mut stream = UnixStream::connect(socket).map_err(HttpError::Connect)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(HttpError::Io)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(HttpError::Io)?;
    let body = body.unwrap_or(&[]);
    let mut out = Zeroizing::new(Vec::with_capacity(512 + body.len()));
    out.extend_from_slice(
        format!("{method} {target} HTTP/1.1\r\nHost: vaultosd\r\nConnection: close\r\n").as_bytes(),
    );
    for (k, v) in headers {
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if !body.is_empty() {
        out.extend_from_slice(b"Content-Type: application/json\r\n");
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    stream.write_all(&out).map_err(HttpError::Io)?;
    let raw = read_limited(&mut stream, MAX_RESPONSE).map_err(HttpError::Io)?;
    parse(&raw)
}

/// Reads to the end, keeping at most `limit` bytes. The buffer grows by copying into a new
/// one and zeroing the old, so no partial copy of a reply (which can carry values) is left
/// in freed memory.
fn read_limited(r: &mut impl Read, limit: u64) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut out = Zeroizing::new(Vec::with_capacity(16 * 1024));
    let mut buf = Zeroizing::new([0u8; 8192]);
    while out.len() < limit {
        let n = match r.read(&mut buf[..]) {
            Ok(0) => break,
            Ok(n) => n.min(limit - out.len()),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if out.len() + n > out.capacity() {
            let mut bigger =
                Zeroizing::new(Vec::with_capacity((out.capacity() * 2).max(out.len() + n)));
            bigger.extend_from_slice(&out);
            out = bigger;
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

fn parse(raw: &[u8]) -> Result<Response, HttpError> {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(HttpError::Malformed)?;
    let head = std::str::from_utf8(&raw[..end]).map_err(|_| HttpError::Malformed)?;
    let rest = &raw[end + 4..];
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or(HttpError::Malformed)?;
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        if k == "content-length" {
            length = v.parse::<usize>().ok();
        } else if k == "transfer-encoding" && v.eq_ignore_ascii_case("chunked") {
            chunked = true;
        }
    }
    let body = if chunked {
        dechunk(rest)?
    } else {
        let n = length.unwrap_or(rest.len());
        if n > rest.len() {
            return Err(HttpError::Malformed);
        }
        Zeroizing::new(rest[..n].to_vec())
    };
    Ok(Response { status, body })
}

fn dechunk(mut data: &[u8]) -> Result<Zeroizing<Vec<u8>>, HttpError> {
    let mut out = Zeroizing::new(Vec::new());
    loop {
        let line_end = data
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or(HttpError::Malformed)?;
        let size_text = std::str::from_utf8(&data[..line_end]).map_err(|_| HttpError::Malformed)?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| HttpError::Malformed)?;
        data = &data[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if data.len() < size + 2 {
            return Err(HttpError::Malformed);
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_chunked_replies() {
        let r = parse(b"HTTP/1.1 423 Locked\r\ncontent-length: 2\r\n\r\n{}").ok();
        assert_eq!(
            r.map(|r| (r.status, r.body.to_vec())),
            Some((423, b"{}".to_vec()))
        );
        let c = parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n{\"a\r\n4\r\n\":1}\r\n0\r\n\r\n").ok();
        assert_eq!(c.map(|r| r.body.to_vec()), Some(b"{\"a\":1}".to_vec()));
        assert!(parse(b"garbage").is_err());
    }
}
