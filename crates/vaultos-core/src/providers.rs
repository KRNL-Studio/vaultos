//! Guesses a provider from a key name, as `providers.js` `match()` does. The table is
//! `providers.json`, exported from `providers.js`; `test/rust-providers.test.js` keeps the two
//! in step.

use serde::Deserialize;
use std::sync::OnceLock;

#[derive(Deserialize)]
struct Provider {
    id: String,
    keys: Vec<String>,
}

fn table() -> &'static [Provider] {
    static TABLE: OnceLock<Vec<Provider>> = OnceLock::new();
    TABLE.get_or_init(|| serde_json::from_str(include_str!("providers.json")).unwrap_or_default())
}

pub fn match_key(name: &str) -> String {
    let up = name.to_uppercase();
    let t = table();
    t.iter()
        .find(|p| p.keys.contains(&up))
        .or_else(|| {
            t.iter().find(|p| {
                p.id != "custom" && p.id != "password" && up.contains(&p.id.to_uppercase())
            })
        })
        .map_or_else(|| "custom".to_owned(), |p| p.id.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_like_javascript() {
        assert_eq!(match_key("VERCEL_TOKEN"), "vercel");
        assert_eq!(match_key("my_supabase_thing"), "supabase");
        assert_eq!(match_key("SOMETHING_ELSE"), "custom");
    }
}
