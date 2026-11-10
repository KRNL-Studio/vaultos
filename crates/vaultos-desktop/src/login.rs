//! Optional "open at login" (`login-item.js`): a per-user LaunchAgent on macOS or an XDG
//! autostart entry on Linux that starts VaultOS with `--hidden`, so it waits locked in the
//! menu bar. Written only when the human turns the preference on, rewritten at each start
//! (the app may have moved) and removed when it is turned off.

use std::path::{Path, PathBuf};

const LABEL: &str = "org.vaultos.preview.desktop";

pub fn item_path() -> Option<PathBuf> {
    let home = PathBuf::from(std::env::var_os("HOME")?);
    if cfg!(target_os = "macos") {
        return Some(
            home.join("Library/LaunchAgents")
                .join(format!("{LABEL}.plist")),
        );
    }
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.join(".config"));
    Some(config.join("autostart").join(format!("{LABEL}.desktop")))
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Desktop Entry Exec quoting: every argument double-quoted, with \ " ` $ escaped.
fn exec_arg(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '\\' | '"' | '`' | '$' => {
                out.push('\\');
                out.push(c);
            }
            '%' => out.push_str("%%"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

fn content(command: &[String], data_dir: Option<&Path>) -> String {
    if cfg!(target_os = "macos") {
        let env = data_dir.map_or(String::new(), |d| {
            format!(
                "\n  <key>EnvironmentVariables</key>\n  <dict><key>VAULTOS_DATA_DIR</key><string>{}</string></dict>",
                xml(&d.to_string_lossy())
            )
        });
        let args: String = command
            .iter()
            .map(|a| format!("<string>{}</string>", xml(a)))
            .collect();
        return format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key><string>{LABEL}</string>\n  <key>ProgramArguments</key>\n  <array>{args}</array>\n  <key>RunAtLoad</key><true/>\n  <key>LimitLoadToSessionType</key><string>Aqua</string>\n  <key>ProcessType</key><string>Interactive</string>{env}\n</dict>\n</plist>\n"
        );
    }
    let mut words: Vec<String> = Vec::new();
    if let Some(d) = data_dir {
        words.push("env".into());
        words.push(format!("VAULTOS_DATA_DIR={}", d.to_string_lossy()));
    }
    words.extend(command.iter().cloned());
    let exec: Vec<String> = words.iter().map(|w| exec_arg(w)).collect();
    format!(
        "[Desktop Entry]\nType=Application\nName=VaultOS\nComment=Start VaultOS locked in the system tray\nExec={}\nTerminal=false\nX-GNOME-Autostart-enabled=true\n",
        exec.join(" ")
    )
}

/// One label serves every data folder, so an item is removed only by the vault it starts.
fn belongs_to(text: &str, data_dir: Option<&Path>) -> bool {
    match data_dir {
        None => !text.contains("VAULTOS_DATA_DIR"),
        Some(d) if cfg!(target_os = "macos") => {
            text.contains(&format!("<string>{}</string>", xml(&d.to_string_lossy())))
        }
        Some(d) => text.contains(&exec_arg(&format!(
            "VAULTOS_DATA_DIR={}",
            d.to_string_lossy()
        ))),
    }
}

fn safe_arg(a: &str) -> bool {
    !a.contains(['\0', '\n', '\r'])
}

pub fn set_enabled(on: bool, command: &[String], data_dir: Option<&Path>) -> Result<(), String> {
    let file = item_path().ok_or("Open at login is not supported on this platform")?;
    if let Some(d) = data_dir {
        if !d.is_absolute() || !safe_arg(&d.to_string_lossy()) {
            return Err("Invalid data directory for open at login".into());
        }
    }
    if !on {
        match std::fs::symlink_metadata(&file) {
            Ok(m) if m.is_file() && m.len() < 65_536 => {
                let text = std::fs::read_to_string(&file).unwrap_or_default();
                if belongs_to(&text, data_dir) {
                    std::fs::remove_file(&file).map_err(|e| e.to_string())?;
                }
            }
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.to_string()),
            _ => {}
        }
        return Ok(());
    }
    if command.is_empty() || !command.iter().all(|a| safe_arg(a)) {
        return Err("Invalid login command".into());
    }
    let dir = file.parent().ok_or("Invalid login item path")?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    if std::fs::symlink_metadata(&file).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("Refusing to replace a symbolic link".into());
    }
    let tmp = file.with_extension(format!("{}.tmp", std::process::id()));
    std::fs::write(&tmp, content(command, data_dir)).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &file).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn items_name_the_vault_they_start() {
        let d = Path::new("/tmp/vault one");
        let text = content(
            &[
                "/Applications/VaultOS.app/Contents/MacOS/vaultos-desktop".into(),
                "--hidden".into(),
            ],
            Some(d),
        );
        assert!(belongs_to(&text, Some(d)));
        assert!(!belongs_to(&text, None));
        assert!(!belongs_to(&text, Some(Path::new("/tmp/other"))));
    }

    #[test]
    fn quotes_desktop_entry_arguments() {
        assert_eq!(exec_arg("a \"b\" $c 100%"), "\"a \\\"b\\\" \\$c 100%%\"");
    }
}
