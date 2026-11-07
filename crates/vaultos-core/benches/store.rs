//! Rough timings for the store's hot paths: `cargo bench -p vaultos-core`. Uses the KDF floor
//! so unlock time reflects the format, not Argon2id's cost setting.

use std::time::Instant;
use vaultos_core::{Fields, KdfParams, SecretString, Store};

fn time<R>(label: &str, runs: u32, mut f: impl FnMut() -> R) {
    let start = Instant::now();
    for _ in 0..runs {
        std::hint::black_box(f());
    }
    let each = start.elapsed() / runs;
    eprintln!("{label:<32} {each:>12.2?}");
}

fn main() -> vaultos_core::Result<()> {
    time("Argon2id default (256 MiB, t=3)", 3, || {
        vaultos_core::crypto::argon2id(b"synthetic-bench-password", &[7; 16], KdfParams::DEFAULT)
    });

    let dir = std::env::temp_dir().join(format!("vaultos-bench-{}", std::process::id()));
    let password = SecretString::new("synthetic-bench-password");
    let mut store = Store::new(&dir)?;
    store.create(&password, None, KdfParams::FLOOR)?;
    store.create_project("Bench", "human")?;
    store.batch(|s| {
        for i in 0..1000 {
            let fields = Fields {
                key: format!("KEY_{i}"),
                value: Some(SecretString::new(format!("value-{i}"))),
                ..Default::default()
            };
            s.set_item("Bench", &fields, "human")?;
        }
        Ok(())
    })?;

    time("unlock (1000 items, KDF floor)", 5, || {
        store.lock();
        store.unlock(&password, None)
    });
    time("list_items (1000)", 200, || {
        store.list_items("Bench").map(|v| v.len())
    });
    time("set_item (save included)", 20, || {
        let fields = Fields {
            key: "KEY_0".into(),
            value: Some(SecretString::new("changed")),
            ..Default::default()
        };
        store.set_item("Bench", &fields, "human")
    });
    time("reveal (audit append included)", 200, || {
        store
            .reveal("Bench", "KEY_500", "human")
            .map(|r| r.value.len())
    });

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
