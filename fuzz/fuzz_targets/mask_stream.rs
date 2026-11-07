//! Masking does not depend on how a program's output is cut into reads, and no value
//! survives it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultos_core::mask::{Masker, MIN_LEN};

fn masked(values: &[String], text: &[u8], step: usize) -> Vec<u8> {
    let mut m = Masker::new(values.iter().map(String::as_str));
    let mut out = Vec::new();
    for chunk in text.chunks(step) {
        out.extend(m.push(chunk));
    }
    out.extend(m.finish());
    out
}

fuzz_target!(|data: &[u8]| {
    // The first byte gives the number of values and how to cut the text. Each value is a run
    // of digits: the mask has none, so a value left in the output is one the masker missed.
    let Some((&head, mut rest)) = data.split_first() else {
        return;
    };
    let mut values = Vec::new();
    for _ in 0..head % 4 {
        let Some((&len, tail)) = rest.split_first() else {
            return;
        };
        let len = MIN_LEN + usize::from(len % 12);
        if tail.len() < len {
            return;
        }
        values.push(
            tail[..len]
                .iter()
                .map(|b| char::from(b'0' + b % 10))
                .collect(),
        );
        rest = &tail[len..];
    }
    // Plenty of digits in the text, so values and near misses occur in it.
    let text: Vec<u8> = rest
        .iter()
        .map(|&b| if b % 3 == 0 { b'0' + b % 10 } else { b })
        .collect();
    let whole = masked(&values, &text, text.len().max(1));
    let step = usize::from(head / 4 % 7) + 1;
    assert_eq!(
        masked(&values, &text, step),
        whole,
        "masking depends on how the output is read"
    );
    for v in &values {
        assert!(
            !whole.windows(v.len()).any(|w| w == v.as_bytes()),
            "a value survived masking"
        );
    }
});
