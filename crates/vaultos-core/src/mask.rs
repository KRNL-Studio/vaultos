//! Masks secret values in a stream of output, as `vaultos run` and `run_with_secrets` print
//! a program's output. A value split across two reads is still masked: the end of a read
//! that could begin a value is held until the next one shows it is not.

use zeroize::Zeroizing;

pub const MASK: &[u8] = b"<concealed by VaultOS>";

/// Values shorter than this are not masked: they would hide ordinary output.
pub const MIN_LEN: usize = 4;

pub struct Masker {
    /// Longest first, so a value that contains another is masked whole.
    needles: Vec<Zeroizing<Vec<u8>>>,
    pending: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Masker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Masker")
            .field("values", &self.needles.len())
            .finish_non_exhaustive()
    }
}

impl Masker {
    pub fn new<'a>(values: impl IntoIterator<Item = &'a str>) -> Masker {
        let mut needles: Vec<Zeroizing<Vec<u8>>> = values
            .into_iter()
            .filter(|v| v.len() >= MIN_LEN)
            .map(|v| Zeroizing::new(v.as_bytes().to_vec()))
            .collect();
        needles.sort_by(|a, b| {
            b.len()
                .cmp(&a.len())
                .then_with(|| a.as_slice().cmp(b.as_slice()))
        });
        needles.dedup_by(|a, b| a.as_slice() == b.as_slice());
        Masker {
            needles,
            pending: Zeroizing::new(Vec::new()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.needles.is_empty()
    }

    /// Takes the next read and returns what can be shown so far.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(chunk);
        self.drain(false)
    }

    /// Returns everything still held, at the end of the stream.
    pub fn finish(&mut self) -> Vec<u8> {
        self.drain(true)
    }

    fn drain(&mut self, last: bool) -> Vec<u8> {
        let buf = &self.pending;
        let mut out = Vec::with_capacity(buf.len());
        let mut i = 0;
        'scan: while i < buf.len() {
            let rest = &buf[i..];
            // Hold while a longer value could still begin here, so the longest one is masked
            // however the output was cut into reads.
            if !last
                && self
                    .needles
                    .iter()
                    .any(|n| n.len() > rest.len() && n.starts_with(rest))
            {
                break;
            }
            for n in &self.needles {
                if rest.starts_with(n) {
                    out.extend_from_slice(MASK);
                    i += n.len();
                    continue 'scan;
                }
            }
            out.push(buf[i]);
            i += 1;
        }
        let held = Zeroizing::new(self.pending[i..].to_vec());
        self.pending = held;
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test")]
    use super::*;

    fn run(values: &[&str], chunks: &[&str]) -> String {
        let mut m = Masker::new(values.iter().copied());
        let mut out = Vec::new();
        for c in chunks {
            out.extend(m.push(c.as_bytes()));
        }
        out.extend(m.finish());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn masks_values_across_reads() {
        let m = "<concealed by VaultOS>";
        assert_eq!(
            run(&["synthetic-secret"], &["key=synthetic-secret\n"]),
            format!("key={m}\n")
        );
        assert_eq!(
            run(&["synthetic-secret"], &["key=synth", "etic-sec", "ret!"]),
            format!("key={m}!")
        );
        assert_eq!(run(&["synthetic-secret"], &["synth", "esis"]), "synthesis");
        assert_eq!(
            run(&["synthetic-secret"], &["ends with synth"]),
            "ends with synth"
        );
        assert_eq!(run(&["abc"], &["abc"]), "abc", "too short to mask");
        assert_eq!(
            run(&["secret", "secret-longer"], &["a secret-longer b secret"]),
            format!("a {m} b {m}")
        );
    }

    #[test]
    fn masks_the_longest_value_however_the_output_is_read() {
        let m = "<concealed by VaultOS>";
        let values = ["0000", "00000"];
        let whole = run(&values, &["00000000!"]);
        assert_eq!(whole, format!("{m}000!"));
        let bytes: Vec<String> = "00000000!".chars().map(String::from).collect();
        let bytes: Vec<&str> = bytes.iter().map(String::as_str).collect();
        assert_eq!(run(&values, &bytes), whole);
    }
}
