//! Where the vault lives, as `paths.js` decides it.

use crate::error::{Error, Result};
use std::path::PathBuf;

/// The folder name is kept from the preview so existing vaults are found where they are.
pub const APP_DIR: &str = "VaultOS-Preview";

/// `VAULTOS_DATA_DIR` (which must be absolute), else the platform's application-data folder.
pub fn default_data_dir() -> Result<PathBuf> {
    data_dir_from(
        std::env::var_os("VAULTOS_DATA_DIR").map(PathBuf::from),
        std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
        std::env::var_os("HOME").map(PathBuf::from),
        cfg!(target_os = "macos"),
    )
}

fn data_dir_from(
    explicit: Option<PathBuf>,
    xdg: Option<PathBuf>,
    home: Option<PathBuf>,
    macos: bool,
) -> Result<PathBuf> {
    if let Some(dir) = explicit.filter(|d| !d.as_os_str().is_empty()) {
        if !dir.is_absolute() {
            return Err(Error::invalid("VAULTOS_DATA_DIR must be absolute"));
        }
        return Ok(dir);
    }
    let home = home
        .filter(|h| h.is_absolute())
        .ok_or_else(|| Error::invalid("HOME is not set; set VAULTOS_DATA_DIR"))?;
    if macos {
        return Ok(home.join("Library/Application Support").join(APP_DIR));
    }
    // The XDG base directory specification says relative values must be ignored.
    let config = xdg
        .filter(|x| x.is_absolute())
        .unwrap_or_else(|| home.join(".config"));
    Ok(config.join(APP_DIR))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follows_paths_js() {
        let home = Some(PathBuf::from("/home/u"));
        let d = |e: Option<&str>, x: Option<&str>, mac| {
            data_dir_from(
                e.map(PathBuf::from),
                x.map(PathBuf::from),
                home.clone(),
                mac,
            )
        };
        assert_eq!(d(Some("/v"), None, true).ok(), Some(PathBuf::from("/v")));
        assert!(d(Some("rel"), None, false).is_err());
        assert_eq!(
            d(None, None, true).ok(),
            Some(PathBuf::from(
                "/home/u/Library/Application Support/VaultOS-Preview"
            ))
        );
        assert_eq!(
            d(None, Some("/x"), false).ok(),
            Some(PathBuf::from("/x/VaultOS-Preview"))
        );
        assert_eq!(
            d(None, Some("rel"), false).ok(),
            Some(PathBuf::from("/home/u/.config/VaultOS-Preview"))
        );
    }
}
