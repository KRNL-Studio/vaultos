//! Which site a URL belongs to, for the browser extension: its registrable domain, the
//! public suffix from the Public Suffix List plus one label. `www.example.co.uk` and
//! `accounts.example.co.uk` are one site; `a.github.io` and `b.github.io` are two. A login is
//! offered and filled only on a page of its own site (and its port, when the saved address
//! names one), over HTTPS, or plain HTTP to `localhost` or `127.0.0.1`.
//!
//! `public_suffix_list.dat` is the list from <https://publicsuffix.org/list/>, unmodified,
//! under the Mozilla Public License 2.0 (see the file's header).

use std::collections::HashSet;
use std::sync::OnceLock;

const LIST: &str = include_str!("public_suffix_list.dat");

#[derive(Default)]
struct Rules {
    exact: HashSet<String>,
    /// `*.ck` is kept as `ck`: any one label under it is a public suffix.
    wildcard: HashSet<String>,
    /// `!www.ck` is kept as `www.ck`: not a public suffix after all.
    exception: HashSet<String>,
}

fn rules() -> &'static Rules {
    static RULES: OnceLock<Rules> = OnceLock::new();
    RULES.get_or_init(|| {
        let mut r = Rules::default();
        for line in LIST.lines() {
            let rule = line.split_whitespace().next().unwrap_or("");
            if rule.is_empty() || rule.starts_with("//") {
                continue;
            }
            let (set, name) = if let Some(n) = rule.strip_prefix('!') {
                (&mut r.exception, n)
            } else if let Some(n) = rule.strip_prefix("*.") {
                (&mut r.wildcard, n)
            } else {
                (&mut r.exact, rule)
            };
            // Hosts arrive in their ASCII (punycode) form.
            if let Ok(ascii) = idna::domain_to_ascii(name) {
                set.insert(ascii);
            }
        }
        r
    })
}

/// The registrable domain of a lowercase ASCII host name, or `None` when the host is itself
/// a public suffix (or not a name).
pub fn registrable(host: &str) -> Option<String> {
    let labels: Vec<&str> = host.split('.').collect();
    if labels.iter().any(|l| l.is_empty()) {
        return None;
    }
    let r = rules();
    // From the longest suffix down, so the most specific rule wins; an exception is always
    // longer than the wildcard it overrides.
    for i in 0..labels.len() {
        let suffix = labels[i..].join(".");
        if r.exception.contains(&suffix) {
            return Some(suffix);
        }
        let under_wildcard =
            i + 1 < labels.len() && r.wildcard.contains(&labels[i + 1..].join("."));
        if r.exact.contains(&suffix) || under_wildcard {
            return (i > 0).then(|| labels[i - 1..].join("."));
        }
    }
    // The default rule: the last label is the public suffix.
    (labels.len() >= 2).then(|| labels[labels.len() - 2..].join("."))
}

/// A web address, as far as filling a login is concerned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Site {
    /// HTTPS, or plain HTTP to `localhost`, `*.localhost` or `127.0.0.1`.
    pub secure: bool,
    /// The host, lowercase ASCII; an IPv6 address in brackets.
    pub host: String,
    pub port: Option<u16>,
    /// The registrable domain; for an address, `localhost` or a public suffix, the host.
    pub site: String,
    /// An IP address or a name for this computer: matched by host and port, not by site.
    pub exact: bool,
}

/// Parses an `http` or `https` URL. A saved address without a scheme (`github.com`) is
/// taken as HTTPS.
pub fn site(raw: &str) -> Option<Site> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 2048 {
        return None;
    }
    let full = if raw.contains("://") {
        raw.to_owned()
    } else {
        format!("https://{raw}")
    };
    let u = url::Url::parse(&full).ok()?;
    let (host, local, exact) = match u.host()? {
        url::Host::Domain(d) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            let local = d == "localhost" || d.ends_with(".localhost");
            (d, local, local)
        }
        // Plain HTTP only where the extension runs on it: 127.0.0.1, not all of 127/8 or ::1.
        url::Host::Ipv4(a) => (a.to_string(), a == std::net::Ipv4Addr::LOCALHOST, true),
        url::Host::Ipv6(a) => (format!("[{a}]"), false, true),
    };
    let secure = match u.scheme() {
        "https" => true,
        "http" => local,
        _ => return None,
    };
    let site = if exact {
        host.clone()
    } else {
        registrable(&host).unwrap_or_else(|| host.clone())
    };
    Some(Site {
        secure,
        host,
        port: u.port(),
        site,
        exact,
    })
}

impl Site {
    /// Whether a login saved for `saved` belongs on this page: the same site, and the same
    /// port when the saved address names one; for an address or this computer, the same host
    /// and port.
    pub fn matches(&self, saved: &Site) -> bool {
        if self.exact || saved.exact {
            self.exact && saved.exact && self.host == saved.host && self.port == saved.port
        } else {
            self.site == saved.site && (saved.port.is_none() || saved.port == self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test")]
    use super::*;

    #[test]
    fn finds_registrable_domains() {
        for (host, want) in [
            ("example.com", Some("example.com")),
            ("www.accounts.example.com", Some("example.com")),
            ("shop.example.co.uk", Some("example.co.uk")),
            ("co.uk", None),
            ("com", None),
            ("alice.github.io", Some("alice.github.io")),
            ("github.io", None),
            ("a.b.ck", Some("a.b.ck")),
            ("b.ck", None),
            ("www.ck", Some("www.ck")),
            ("intranet.unknowntld", Some("intranet.unknowntld")),
            ("xn--fiqs8s", None),
            ("a..b", None),
        ] {
            assert_eq!(registrable(host).as_deref(), want, "{host}");
        }
    }

    #[test]
    fn matches_logins_to_pages() {
        let page = |u: &str| site(u).unwrap();
        let saved = page("github.com");
        assert!(page("https://gist.github.com/x").matches(&saved));
        assert!(!page("https://github.com.evil.example/login").matches(&saved));
        assert!(!page("https://alice.github.io").matches(&page("https://bob.github.io")));
        assert!(!page("http://github.com").secure);
        assert!(page("http://localhost:3000/login").secure);
        assert!(page("http://localhost:3000").matches(&page("http://localhost:3000/a")));
        assert!(!page("http://localhost:3000").matches(&page("http://localhost:4000")));
        assert!(!page("https://127.0.0.1").matches(&page("https://localhost")));
        assert!(page("http://127.0.0.1:8080").secure);
        assert!(!page("http://127.0.0.2").secure);
        assert!(!page("http://[::1]").secure);
        assert!(page("https://[::1]").secure);
        // A saved port is kept to; a saved address without one fits any port of its site.
        let admin = page("https://admin.example.com:8443");
        assert!(page("https://example.com:8443/x").matches(&admin));
        assert!(!page("https://tenant.example.com:9443").matches(&admin));
        assert!(!page("https://example.com").matches(&admin));
        assert!(page("https://example.com:9443").matches(&page("example.com")));
        assert!(page("https://example.com").matches(&page("https://example.com:443")));
        assert!(page("https://Example.COM.").matches(&page("example.com")));
        assert_eq!(page("https://bücher.example").host, "xn--bcher-kva.example");
        assert!(site("ftp://example.com").is_none());
        assert!(site("javascript:alert(1)").is_none());
        assert!(site("").is_none());
    }
}
