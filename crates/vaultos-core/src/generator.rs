//! The password generator (random characters, passphrases from the EFF large wordlist, PINs)
//! and a strength estimate for passwords people type.
//!
//! `eff_large_wordlist.txt` is the word column of the Electronic Frontier Foundation's large
//! wordlist (<https://www.eff.org/dice>, CC BY 3.0 US): 7,776 words, about 12.9 bits each.

use crate::crypto::fill_random;
use crate::error::{Error, Result};
use crate::secret::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::OnceLock;
use zeroize::Zeroizing;

const WORDLIST: &str = include_str!("eff_large_wordlist.txt");

pub fn words() -> &'static [&'static str] {
    static W: OnceLock<Vec<&'static str>> = OnceLock::new();
    W.get_or_init(|| WORDLIST.lines().filter(|w| !w.is_empty()).collect())
}

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!#$%&*+-.:=?@^_~";
/// Easily confused in print or when read aloud.
const AMBIGUOUS: &str = "Il1O0";

/// A uniform index below `n`, by rejection so no value is favoured.
fn below(n: usize) -> usize {
    let n = n as u64;
    let zone = u64::MAX - u64::MAX % n;
    loop {
        let mut b = [0u8; 8];
        fill_random(&mut b);
        let v = u64::from_le_bytes(b);
        if v < zone {
            return (v % n) as usize;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Recipe {
    #[serde(rename_all = "camelCase")]
    Random {
        length: usize,
        #[serde(default = "yes")]
        digits: bool,
        #[serde(default = "yes")]
        symbols: bool,
        #[serde(default)]
        avoid_ambiguous: bool,
    },
    #[serde(rename_all = "camelCase")]
    Passphrase {
        words: usize,
        #[serde(default = "dash")]
        separator: String,
        #[serde(default)]
        capitalize: bool,
        #[serde(default)]
        number: bool,
    },
    Pin {
        length: usize,
    },
}

fn yes() -> bool {
    true
}

fn dash() -> String {
    "-".into()
}

impl Default for Recipe {
    fn default() -> Recipe {
        Recipe::Random {
            length: 24,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }
}

#[derive(Debug)]
pub struct Generated {
    pub value: SecretString,
    /// The entropy of the recipe, in bits.
    pub bits: f64,
}

pub fn generate(recipe: &Recipe) -> Result<Generated> {
    match recipe {
        Recipe::Random {
            length,
            digits,
            symbols,
            avoid_ambiguous,
        } => {
            if !(8..=128).contains(length) {
                return Err(Error::invalid("Use 8 to 128 characters"));
            }
            let keep = |set: &str| -> Vec<char> {
                set.chars()
                    .filter(|c| !avoid_ambiguous || !AMBIGUOUS.contains(*c))
                    .collect()
            };
            let mut classes = vec![keep(LOWER), keep(UPPER)];
            if *digits {
                classes.push(keep(DIGITS));
            }
            if *symbols {
                classes.push(keep(SYMBOLS));
            }
            let all: Vec<char> = classes.concat();
            // Every chosen class appears at least once; redraw otherwise (rare from 8 up).
            loop {
                let out: Zeroizing<String> =
                    Zeroizing::new((0..*length).map(|_| all[below(all.len())]).collect());
                if classes.iter().all(|c| out.chars().any(|x| c.contains(&x))) {
                    let bits = *length as f64 * (all.len() as f64).log2();
                    return Ok(Generated {
                        value: SecretString::new(out.as_str()),
                        bits,
                    });
                }
            }
        }
        Recipe::Passphrase {
            words: n,
            separator,
            capitalize,
            number,
        } => {
            if !(3..=20).contains(n) {
                return Err(Error::invalid("Use 3 to 20 words"));
            }
            if separator.chars().count() > 3 || separator.chars().any(char::is_control) {
                return Err(Error::invalid("Use a separator of up to 3 characters"));
            }
            let list = words();
            let mut picked: Vec<Zeroizing<String>> = (0..*n)
                .map(|_| Zeroizing::new(list[below(list.len())].to_owned()))
                .collect();
            if *capitalize {
                for w in &mut picked {
                    let mut c = w.chars();
                    let first = c.next().map(|f| f.to_uppercase().collect::<String>());
                    *w = Zeroizing::new(format!("{}{}", first.unwrap_or_default(), c.as_str()));
                }
            }
            let mut bits = *n as f64 * (list.len() as f64).log2();
            if *number {
                let at = below(picked.len());
                let digit = below(10);
                picked[at].push_str(&digit.to_string());
                bits += (10.0 * *n as f64).log2();
            }
            let joined = Zeroizing::new(
                picked
                    .iter()
                    .map(|w| w.as_str())
                    .collect::<Vec<_>>()
                    .join(separator),
            );
            Ok(Generated {
                value: SecretString::new(joined.as_str()),
                bits,
            })
        }
        Recipe::Pin { length } => {
            if !(4..=32).contains(length) {
                return Err(Error::invalid("Use 4 to 32 digits"));
            }
            let out: Zeroizing<String> = Zeroizing::new(
                (0..*length)
                    .map(|_| char::from(b'0' + below(10) as u8))
                    .collect(),
            );
            Ok(Generated {
                value: SecretString::new(out.as_str()),
                bits: *length as f64 * 10f64.log2(),
            })
        }
    }
}

/// Words people build passwords from that the EFF list lacks; matched after undoing common
/// substitutions (`p@ssw0rd`).
const COMMON: &[&str] = &[
    "password",
    "passwd",
    "pass",
    "qwerty",
    "letmein",
    "welcome",
    "admin",
    "administrator",
    "login",
    "master",
    "dragon",
    "monkey",
    "football",
    "baseball",
    "soccer",
    "hockey",
    "iloveyou",
    "sunshine",
    "princess",
    "shadow",
    "superman",
    "batman",
    "trustno",
    "starwars",
    "whatever",
    "freedom",
    "hello",
    "secret",
    "access",
    "flower",
    "computer",
    "internet",
    "michael",
    "jennifer",
    "jordan",
    "hunter",
    "ranger",
    "buster",
    "killer",
    "charlie",
    "andrew",
    "thomas",
    "robert",
    "daniel",
    "jessica",
    "pepper",
    "ginger",
    "summer",
    "winter",
    "autumn",
    "orange",
    "banana",
    "chocolate",
    "mustang",
    "harley",
    "ferrari",
    "matrix",
    "changeme",
    "default",
    "guest",
    "root",
    "toor",
    "user",
    "temp",
    "demo",
    "test",
    "system",
    "server",
    "oracle",
    "mysql",
    "postgres",
    "love",
    "god",
    "angel",
    "baby",
    "lucky",
    "money",
    "cookie",
    "maggie",
    "ashley",
    "nicole",
    "abc",
];

const KEYBOARD: &[&str] = &[
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
    "qazwsxedc",
    "1qaz2wsx3edc",
];

fn dictionary() -> &'static HashSet<&'static str> {
    static D: OnceLock<HashSet<&'static str>> = OnceLock::new();
    D.get_or_init(|| {
        words()
            .iter()
            .copied()
            .filter(|w| w.len() >= 3)
            .chain(COMMON.iter().copied())
            .collect()
    })
}

fn class_bits(c: char) -> f64 {
    match c {
        'a'..='z' | 'A'..='Z' => 26f64.log2(),
        '0'..='9' => 10f64.log2(),
        c if c.is_ascii() => 33f64.log2(),
        _ => 7.0,
    }
}

fn unleet(c: char) -> char {
    match c {
        '0' => 'o',
        '1' | '!' => 'i',
        '3' => 'e',
        '4' | '@' => 'a',
        '5' | '$' => 's',
        '7' => 't',
        c => c.to_ascii_lowercase(),
    }
}

/// Roughly how many bits a guesser needs for a password a person chose: dictionary words,
/// keyboard runs, sequences, repeats and years cost far less than random characters. It is
/// an estimate in the spirit of zxcvbn, much smaller, and errs towards calling things weak.
pub fn estimate_bits(pw: &str) -> f64 {
    let orig: Vec<char> = pw.chars().collect();
    let norm: Vec<char> = orig.iter().map(|c| unleet(*c)).collect();
    let lower: Vec<char> = orig.iter().map(|c| c.to_ascii_lowercase()).collect();
    let dict = dictionary();
    let dict_bits = (dict.len() as f64).log2();
    // A character outside any pattern costs the bits of the pool the password draws from.
    let has = |f: fn(&char) -> bool| orig.iter().any(f);
    let pool: f64 = [
        (has(char::is_ascii_lowercase), 26.0),
        (has(char::is_ascii_uppercase), 26.0),
        (has(char::is_ascii_digit), 10.0),
        (has(|c| c.is_ascii() && !c.is_ascii_alphanumeric()), 33.0),
        (has(|c| !c.is_ascii()), 100.0),
    ]
    .iter()
    .filter(|(present, _)| *present)
    .map(|(_, n)| n)
    .sum();
    let char_bits = pool.max(1.0).log2();
    let mut bits = 0.0;
    let mut i = 0;
    while i < orig.len() {
        let rest = orig.len() - i;
        let mut best: Option<(usize, f64)> = None;
        let mut offer = |len: usize, cost: f64| {
            if best.is_none_or(|(l, _)| len > l) {
                best = Some((len, cost));
            }
        };
        // Dictionary words, longest first, with a bit for capitals and one for substitutions.
        for len in (3..=rest.min(20)).rev() {
            let word: String = norm[i..i + len].iter().collect();
            if dict.contains(word.as_str()) {
                let seg = &orig[i..i + len];
                let caps = seg.iter().any(char::is_ascii_uppercase);
                let leet = norm[i..i + len] != lower[i..i + len];
                offer(
                    len,
                    dict_bits + f64::from(u8::from(caps)) + f64::from(u8::from(leet)),
                );
                break;
            }
        }
        // Keyboard rows and their reverses.
        for row in KEYBOARD {
            let rev: String = row.chars().rev().collect();
            for r in [*row, rev.as_str()] {
                let run = (4..=rest.min(r.len()))
                    .rev()
                    .find(|n| r.contains(&lower[i..i + n].iter().collect::<String>()));
                if let Some(n) = run {
                    offer(n, 6.0 + (n as f64).log2());
                }
            }
        }
        // Runs like abc, 4321 and aaaa.
        let step = |a: char, b: char| b as i64 - a as i64;
        if rest >= 3 {
            let d = step(lower[i], lower[i + 1]);
            if d.abs() <= 1 && lower[i].is_ascii_alphanumeric() {
                let mut n = 2;
                while i + n < orig.len() && step(lower[i + n - 1], lower[i + n]) == d {
                    n += 1;
                }
                if n >= 3 {
                    offer(n, class_bits(orig[i]) + 1.0 + (n as f64).log2());
                }
            }
        }
        // Years from 1900 to 2099.
        if rest >= 4 {
            let y: String = orig[i..i + 4].iter().collect();
            if (y.starts_with("19") || y.starts_with("20")) && y.chars().all(|c| c.is_ascii_digit())
            {
                offer(4, 200f64.log2());
            }
        }
        match best {
            Some((len, cost)) => {
                bits += cost;
                i += len;
            }
            None => {
                bits += char_bits;
                i += 1;
            }
        }
    }
    bits
}

/// `weak` (under 40 bits), `fair` (under 60), `good` (under 80) or `strong`.
pub fn rating(bits: f64) -> &'static str {
    match bits {
        b if b < 40.0 => "weak",
        b if b < 60.0 => "fair",
        b if b < 80.0 => "good",
        _ => "strong",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wordlist_is_the_eff_large_list() {
        let w = words();
        assert_eq!(w.len(), 7776);
        assert_eq!(w.iter().collect::<HashSet<_>>().len(), 7776);
        assert_eq!((w[0], w[7775]), ("abacus", "zoom"));
    }

    #[test]
    fn recipes_follow_their_rules() {
        let r = Recipe::Random {
            length: 32,
            digits: true,
            symbols: false,
            avoid_ambiguous: true,
        };
        for _ in 0..50 {
            let g = generate(&r).unwrap();
            let v = g.value.expose();
            assert_eq!(v.chars().count(), 32);
            assert!(v
                .chars()
                .all(|c| c.is_ascii_alphanumeric() && !AMBIGUOUS.contains(c)));
            assert!(v.chars().any(|c| c.is_ascii_digit()));
            assert!(g.bits > 180.0);
        }
        let p = generate(&Recipe::Passphrase {
            words: 5,
            separator: ".".into(),
            capitalize: true,
            number: true,
        })
        .unwrap();
        let parts: Vec<&str> = p.value.expose().split('.').collect();
        assert_eq!(parts.len(), 5);
        assert!(parts
            .iter()
            .all(|w| w.starts_with(|c: char| c.is_ascii_uppercase())));
        assert_eq!(
            p.value
                .expose()
                .chars()
                .filter(char::is_ascii_digit)
                .count(),
            1
        );
        assert!((p.bits - (5.0 * 7776f64.log2() + 50f64.log2())).abs() < 1e-9);
        let pin = generate(&Recipe::Pin { length: 6 }).unwrap();
        assert!(
            pin.value.expose().len() == 6 && pin.value.expose().chars().all(|c| c.is_ascii_digit())
        );
        for bad in [
            Recipe::Random {
                length: 7,
                digits: true,
                symbols: true,
                avoid_ambiguous: false,
            },
            Recipe::Passphrase {
                words: 2,
                separator: "-".into(),
                capitalize: false,
                number: false,
            },
            Recipe::Passphrase {
                words: 4,
                separator: "----".into(),
                capitalize: false,
                number: false,
            },
            Recipe::Pin { length: 3 },
        ] {
            assert!(generate(&bad).is_err(), "{bad:?}");
        }
        let parsed: Recipe = serde_json::from_str(r#"{"kind":"passphrase","words":4}"#).unwrap();
        assert_eq!(
            parsed,
            Recipe::Passphrase {
                words: 4,
                separator: "-".into(),
                capitalize: false,
                number: false
            }
        );
    }

    #[test]
    fn people_patterns_rate_weak_and_random_strings_strong() {
        for weak in [
            "password",
            "Password123!",
            "p@ssw0rd2024",
            "qwerty123",
            "aaaaaaaaaaaa",
            "letmein!",
            "abc12345",
            "Dragon1990",
        ] {
            assert_eq!(
                rating(estimate_bits(weak)),
                "weak",
                "{weak}: {}",
                estimate_bits(weak)
            );
        }
        for strong in ["Xk9#mQ2$vL7!pR4&", "u7Gq!2zT#e9Lw$4Np@8K"] {
            assert_eq!(
                rating(estimate_bits(strong)),
                "strong",
                "{strong}: {}",
                estimate_bits(strong)
            );
        }
        let phrase = generate(&Recipe::Passphrase {
            words: 6,
            separator: "-".into(),
            capitalize: false,
            number: false,
        })
        .unwrap();
        assert!(estimate_bits(phrase.value.expose()) >= 60.0);
    }
}
