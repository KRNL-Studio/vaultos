//! Browser extensions paired with this vault. The extension asks to pair with a code it
//! shows, and the human confirms in the app only when the app shows the same code. The
//! extension then holds a key with which it can list the logins saved for the site it is
//! on, fill one there and save new ones, and nothing else. Pairings live in the vault's
//! sealed metadata, so another process of this user cannot add one, and are not synced.

use super::*;
use crate::crypto::ct_eq;
use crate::sites::{site, Site};
use crate::totp::Totp;

/// Where a saved login goes when the extension names no project.
pub const DEFAULT_PROJECT: &str = "Logins";
const MAX_BROWSERS: usize = 32;
/// Most logins offered for one page.
const MAX_MATCHES: usize = 50;

#[derive(Clone, Debug, Default, PartialEq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Browser {
    pub id: String,
    /// What the human called it (the browser's name, by default).
    pub name: String,
    /// The extension's origin (`chrome-extension://…/`), checked on every request.
    pub origin: String,
    pub key_hash: String,
    pub paired_at: String,
    #[serde(default)]
    pub last_seen_at: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A new pairing. The key is shown once, to the extension.
#[derive(Debug)]
pub struct Pairing {
    pub id: String,
    pub name: String,
    pub key: SecretString,
}

/// A login that may be filled on the page: no values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginMatch {
    pub project_id: String,
    pub project: String,
    pub item_id: String,
    pub name: String,
    pub username: String,
    pub url: String,
    /// The host of the saved address that fits the page, shown beside the login so a login
    /// for another part of the site is not taken for this one.
    pub host: String,
    pub has_password: bool,
    pub has_otp: bool,
}

/// What the extension types into the page.
#[derive(Debug)]
pub struct Filled {
    pub username: String,
    pub password: SecretString,
    /// The current one-time code, when the login has one.
    pub otp: Option<SecretString>,
}

fn page_site(page: &str) -> Result<Site> {
    let s = site(page).ok_or_else(|| Error::invalid("This page's address cannot hold logins"))?;
    if !s.secure {
        return Err(Error::Forbidden(
            "VaultOS fills logins only on HTTPS pages".into(),
        ));
    }
    Ok(s)
}

/// The addresses a login is saved for: its URL and its URL fields.
fn saved_sites(meta: &ItemMeta) -> impl Iterator<Item = Site> + '_ {
    std::iter::once(meta.url.as_str())
        .chain(
            meta.fields
                .iter()
                .filter(|f| f.kind == "url")
                .map(|f| f.value.as_str()),
        )
        .filter_map(site)
}

/// The host of the login's saved address that fits the page, preferring the page's own host;
/// `None` when the login is not offered on the page.
fn fitting_host(meta: &ItemMeta, page: &Site) -> Option<String> {
    if !meta.trashed_at.is_empty() || meta.archived || meta.kind() != "login" {
        return None;
    }
    let mut hosts = saved_sites(meta)
        .filter(|s| page.matches(s))
        .map(|s| s.host);
    let first = hosts.next()?;
    if first == page.host {
        return Some(first);
    }
    Some(hosts.find(|h| *h == page.host).unwrap_or(first))
}

fn fits(meta: &ItemMeta, page: &Site) -> bool {
    fitting_host(meta, page).is_some()
}

fn browser_actor(b: &Browser) -> String {
    format!("browser {} ({})", b.name, b.id)
}

impl Store {
    pub fn browsers(&self) -> Result<Vec<Browser>> {
        Ok(self.state()?.meta.browsers.clone())
    }

    /// Pairs an extension; call it only after the human confirmed the pairing code.
    pub fn pair_browser(&mut self, name: &str, origin: &str) -> Result<Pairing> {
        validate::text(name, "browser name", 100, false)?;
        validate::text(origin, "extension origin", 200, false)?;
        let key = crate::agents::new_token();
        let browser = Browser {
            id: random_id(),
            name: name.trim().to_owned(),
            origin: origin.to_owned(),
            key_hash: crate::agents::token_hash(key.expose()),
            paired_at: now_iso(),
            last_seen_at: None,
            extra: Map::new(),
        };
        let pairing = Pairing {
            id: browser.id.clone(),
            name: browser.name.clone(),
            key,
        };
        let detail = format!("{} ({})", browser.name, browser.origin);
        self.mutate(|_, st| {
            if st.meta.browsers.len() >= MAX_BROWSERS {
                return Err(Error::Conflict(format!(
                    "At most {MAX_BROWSERS} browsers can be paired; unpair one in Settings"
                )));
            }
            st.meta.browsers.push(browser);
            Ok(())
        })?;
        self.audit("browser-pair", &detail, HUMAN)?;
        Ok(pairing)
    }

    pub fn unpair_browser(&mut self, id: &str) -> Result<()> {
        let gone = self.mutate(|_, st| {
            let at = st
                .meta
                .browsers
                .iter()
                .position(|b| b.id == id)
                .ok_or_else(|| Error::not_found("Browser not found"))?;
            Ok(st.meta.browsers.remove(at))
        })?;
        self.audit(
            "browser-unpair",
            &format!("{} ({})", gone.name, gone.origin),
            HUMAN,
        )
    }

    /// The paired browser holding `key`, if it asks from the origin it was paired from.
    pub fn authenticate_browser(&self, key: &str, origin: &str) -> Result<Option<Browser>> {
        if key.is_empty() {
            return Ok(None);
        }
        let h = crate::agents::token_hash(key);
        Ok(self
            .state()?
            .meta
            .browsers
            .iter()
            .find(|b| ct_eq(b.key_hash.as_bytes(), h.as_bytes()) && b.origin == origin)
            .cloned())
    }

    /// Records when a browser last asked, in memory until the next save (as for agents).
    pub fn note_browser_seen(&mut self, id: &str) {
        let now = now_iso();
        let Some(open) = self.open.as_mut() else {
            return;
        };
        for st in std::iter::once(&mut open.state).chain(self.pending.as_mut()) {
            if let Some(b) = st.meta.browsers.iter_mut().find(|b| b.id == id) {
                b.last_seen_at = Some(now.clone());
            }
        }
    }

    /// The logins saved for the page's site, with no values: those saved for the page's own
    /// host first.
    pub fn logins_for(&self, page: &str) -> Result<Vec<LoginMatch>> {
        let page = page_site(page)?;
        let st = self.state()?;
        let mut out = Vec::new();
        for p in &st.projects {
            for i in &p.items {
                let Some(host) = fitting_host(&i.meta, &page) else {
                    continue;
                };
                out.push(LoginMatch {
                    project_id: p.id.clone(),
                    project: p.meta.name.clone(),
                    item_id: i.id.clone(),
                    name: i.meta.key.clone(),
                    username: i.meta.username.clone(),
                    url: i.meta.url.clone(),
                    host,
                    has_password: i.meta.has_password,
                    has_otp: i.meta.has_otp(),
                });
            }
        }
        out.sort_by_key(|m| m.host != page.host);
        out.truncate(MAX_MATCHES);
        Ok(out)
    }

    /// A login's username, password and current one-time code, for a page of its site.
    /// Recorded in the audit log with the page's host.
    pub fn fill_login(
        &mut self,
        page: &str,
        project_id: &str,
        item_id: &str,
        browser: &Browser,
    ) -> Result<Filled> {
        let page = page_site(page)?;
        let (filled, detail) = {
            let st = self.state()?;
            let keys = &self.open()?.keys;
            let p = &st.projects[st.project(project_id)?];
            let i = p
                .items
                .iter()
                .find(|i| i.id == item_id && fits(&i.meta, &page))
                .ok_or_else(|| Error::not_found("No login for this site has that id"))?;
            let secret = keys.open_secret(p, i)?;
            let otp = i
                .meta
                .fields
                .iter()
                .find(|f| f.kind == "otp" && f.has_value)
                .and_then(|f| secret.fields.iter().find(|s| s.id == f.id))
                .and_then(|s| Totp::parse(&s.value).ok())
                .map(|t| SecretString::new(t.code(Totp::now())));
            (
                Filled {
                    username: i.meta.username.clone(),
                    password: SecretString::new(secret.password.clone()),
                    otp,
                },
                format!("{}/{} on {}", p.meta.name, i.meta.key, page.host),
            )
        };
        self.audit("browser-fill", &detail, &browser_actor(browser))?;
        Ok(filled)
    }

    /// Saves a login from a page. With `target` (a project and item id), a new password for
    /// that login, which must be one for this site and username; without, a new password for
    /// the one login of this site and username, or a new item in [`DEFAULT_PROJECT`] (created
    /// when missing) when there is none. Several such logins and no target is a conflict, so
    /// VaultOS never picks one of them for the human. Returns the project's name, the item and
    /// whether an existing login was updated. The human clicked Save in the extension; the item
    /// is the human's.
    pub fn save_login(
        &mut self,
        page: &str,
        username: &str,
        password: &SecretString,
        target: Option<(&str, &str)>,
        browser: &Browser,
    ) -> Result<(String, Saved, bool)> {
        let page_site = page_site(page)?;
        validate::text(username, "username", 256, true)?;
        if password.expose().is_empty() {
            return Err(Error::invalid("There is no password to save"));
        }
        // (project id, project name, item id, item name) of each login for this site and user.
        let mut candidates: Vec<(String, String, String, String)> = Vec::new();
        for p in &self.state()?.projects {
            for i in &p.items {
                if fits(&i.meta, &page_site) && i.meta.username == username {
                    candidates.push((
                        p.id.clone(),
                        p.meta.name.clone(),
                        i.id.clone(),
                        i.meta.key.clone(),
                    ));
                }
            }
        }
        let existing = match target {
            Some((project_id, item_id)) => Some(
                candidates
                    .into_iter()
                    .find(|c| c.0 == project_id && c.2 == item_id)
                    .ok_or_else(|| {
                        Error::not_found("That login is not saved for this site and username")
                    })?,
            ),
            None if candidates.len() > 1 => return Err(Error::Conflict(
                "Several logins for this site use this username; change the password in VaultOS"
                    .into(),
            )),
            None => candidates.pop(),
        };
        let updated = existing.is_some();
        // An existing login keeps its address, fields and everything else but the password.
        let (project_id, name, key, url) = match existing {
            Some((id, name, _, key)) => (id, name, key, None),
            None => {
                let id = match self.find_project(DEFAULT_PROJECT)? {
                    Some((id, _)) => id,
                    None => self.create_project(DEFAULT_PROJECT, HUMAN)?.0,
                };
                let key = self.free_login_name(&id, &page_site.host, username)?;
                let origin = url::Url::parse(page)
                    .map(|u| u.origin().ascii_serialization())
                    .unwrap_or_else(|_| format!("https://{}", page_site.host));
                (id, DEFAULT_PROJECT.to_owned(), key, Some(origin))
            }
        };
        let fields = Fields {
            key,
            password: Some(password.clone()),
            username: Some(username.to_owned()),
            url,
            kind: Some("login".into()),
            ..Fields::default()
        };
        let saved = self.set_item(&project_id, &fields, HUMAN)?;
        self.audit(
            "browser-save",
            &format!("{name}/{} from {}", saved.key, page_site.host),
            &browser_actor(browser),
        )?;
        Ok((name, saved, updated))
    }

    /// `host`, or `host (username)`, or with a number, whichever is not taken.
    fn free_login_name(&self, project_id: &str, host: &str, username: &str) -> Result<String> {
        let st = self.state()?;
        let p = &st.projects[st.project(project_id)?];
        let taken = |k: &str| p.items.iter().any(|i| i.meta.key == k);
        let host = host.strip_prefix("www.").unwrap_or(host);
        let mut candidates = vec![host.to_owned()];
        if !username.is_empty() {
            candidates.push(format!("{host} ({username})"));
        }
        if let Some(free) = candidates.into_iter().find(|c| !taken(c)) {
            return Ok(free);
        }
        (2..1000)
            .map(|n| format!("{host} {n}"))
            .find(|c| !taken(c))
            .ok_or_else(|| Error::Conflict("Too many logins for this site".into()))
    }
}
