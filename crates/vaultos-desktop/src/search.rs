//! Ranked search over vault metadata for the search box and Quick Access (`search.js`).
//! It reads names, usernames, hosts and notes; values never enter the results.

use serde::Serialize;
use vaultos_core::store::ItemSummary;

const EXACT: f64 = 100.0;
const PREFIX: f64 = 60.0;
const WORD: f64 = 40.0;
const SUBSTRING: f64 = 25.0;
const FUZZY: f64 = 10.0;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Hit {
    pub project: String,
    pub key: String,
    pub provider: String,
    pub username: String,
    pub email: String,
    pub url: String,
    pub host: String,
    pub has_value: bool,
    pub expires_at: String,
    pub inject_approved: bool,
    pub updated_at: String,
    pub kind: String,
    pub has_otp: bool,
    pub favorite: bool,
    #[serde(skip)]
    score: f64,
}

pub fn host_of(url: &str) -> String {
    if url.is_empty() {
        return String::new();
    }
    let rest = match url.find("://") {
        Some(i)
            if i > 0
                && url[..i]
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c)) =>
        {
            &url[i + 3..]
        }
        _ => url,
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    let host = if host.starts_with('[') {
        host.split(']')
            .next()
            .map(|h| format!("{h}]"))
            .unwrap_or_default()
    } else {
        host.split(':').next().unwrap_or("").to_owned()
    };
    if host.chars().any(|c| c.is_whitespace()) {
        return String::new();
    }
    host.to_lowercase()
}

fn boundary(c: char) -> bool {
    c.is_whitespace() || "_-./@:".contains(c)
}

/// How well one lower-case token matches one lower-case field value.
pub fn match_score(value: &str, token: &str, fuzzy: bool) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    if value == token {
        return EXACT;
    }
    if value.starts_with(token) {
        return PREFIX;
    }
    if value.contains(token) {
        let word = value
            .match_indices(token)
            .any(|(at, _)| value[..at].chars().next_back().is_some_and(boundary));
        return if word { WORD } else { SUBSTRING };
    }
    let token: Vec<char> = token.chars().collect();
    if !fuzzy || token.len() < 2 {
        return 0.0;
    }
    // Subsequence match ("stsk" finds STRIPE_SECRET_KEY), penalised by the gaps it skips.
    let (mut i, mut gaps, mut last) = (0usize, 0i32, None::<usize>);
    for (j, c) in value.chars().enumerate() {
        if i == token.len() {
            break;
        }
        if c == token[i] {
            if last.is_some_and(|l| j != l + 1) {
                gaps += 1;
            }
            last = Some(j);
            i += 1;
        }
    }
    if i == token.len() {
        f64::from((10 - gaps).max(1)).min(FUZZY)
    } else {
        0.0
    }
}

/// Every whitespace-separated token must match some field; an item's score is the sum of
/// each token's best weighted match. An empty query lists recent changes.
pub fn search(projects: &[(String, Vec<ItemSummary>)], query: &str, limit: usize) -> Vec<Hit> {
    let lower = query.to_lowercase();
    let tokens: Vec<&str> = lower.split_whitespace().take(8).collect();
    let mut out = Vec::new();
    for (project, items) in projects {
        let project_lower = project.to_lowercase();
        for s in items {
            let host = host_of(&s.url);
            let fields = [
                (s.key.to_lowercase(), 1.0, true),
                (project_lower.clone(), 0.6, false),
                (s.provider.to_lowercase(), 0.5, false),
                (s.username.to_lowercase(), 0.5, false),
                (s.email.to_lowercase(), 0.5, false),
                (host.clone(), 0.5, false),
                (s.note.to_lowercase(), 0.3, false),
                (s.tags.join(" ").to_lowercase(), 0.5, false),
            ];
            let mut total = 0.0;
            for token in &tokens {
                let best = fields
                    .iter()
                    .map(|(v, w, fuzzy)| match_score(v, token, *fuzzy) * w)
                    .fold(0.0, f64::max);
                if best == 0.0 {
                    total = 0.0;
                    break;
                }
                total += best;
            }
            if tokens.is_empty() || total > 0.0 {
                out.push(Hit {
                    project: project.clone(),
                    key: s.key.clone(),
                    provider: s.provider.clone(),
                    username: s.username.clone(),
                    email: s.email.clone(),
                    url: s.url.clone(),
                    host,
                    has_value: s.has_value || s.has_password,
                    expires_at: s.expires_at.clone(),
                    inject_approved: s.inject_approved,
                    updated_at: s.updated_at.clone(),
                    kind: s.kind.clone(),
                    has_otp: s.has_otp,
                    favorite: s.favorite,
                    score: total,
                });
            }
        }
    }
    if tokens.is_empty() {
        out.sort_by(|a, b| b.updated_at.cmp(&a.updated_at).then(a.key.cmp(&b.key)));
    } else {
        out.sort_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then(a.key.len().cmp(&b.key.len()))
                .then(a.key.cmp(&b.key))
                .then(a.project.cmp(&b.project))
        });
    }
    out.truncate(limit.clamp(1, 200));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scores_like_the_javascript_search() {
        assert_eq!(
            match_score("stripe_secret_key", "stripe_secret_key", true),
            EXACT
        );
        assert_eq!(match_score("stripe_secret_key", "stripe", true), PREFIX);
        assert_eq!(match_score("stripe_secret_key", "secret", true), WORD);
        assert_eq!(match_score("stripesecret", "secret", true), SUBSTRING);
        assert_eq!(match_score("stripe_secret_key", "stsk", true), 8.0);
        assert_eq!(match_score("stripe_secret_key", "stsk", false), 0.0);
    }

    #[test]
    fn finds_hosts_in_urls() {
        assert_eq!(host_of("https://user@Example.com:8443/x?y"), "example.com");
        assert_eq!(host_of("dashboard.stripe.com/keys"), "dashboard.stripe.com");
        assert_eq!(host_of(""), "");
    }
}
