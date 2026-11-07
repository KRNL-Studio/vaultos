//! The .env parser against the `dotenv` package itself: `tests/fixtures/dotenv-cases.json`
//! holds inputs and what `dotenv.parse` returned (`scripts/make-dotenv-fixture.mjs`).

#![allow(clippy::unwrap_used, reason = "test")]

use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    input: String,
    parsed: Vec<(String, String)>,
}

#[test]
fn parses_exactly_as_dotenv_does() {
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("fixtures/dotenv-cases.json")).unwrap();
    assert!(cases.len() >= 18);
    for c in cases {
        let got: Vec<(String, String)> = vaultos_core::env::parse(&c.input)
            .unwrap()
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect();
        assert_eq!(got, c.parsed, "input: {:?}", c.input);
    }
}
