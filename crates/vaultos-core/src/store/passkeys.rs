//! Passkeys for the browser extension. A passkey lives in a login item as four fields in its
//! "Passkey" section: the credential ID, the relying party (the site's WebAuthn ID), the
//! site's user handle and the private key (concealed). Keeping them as fields keeps the
//! vault format, sync, history and export as they are. A page may use the passkeys of its own
//! relying party only: its host, or a parent domain that is not a public suffix.

use super::browser::{browser_actor, page_site, DEFAULT_PROJECT};
use super::*;
use crate::sites::Site;
use crate::webauthn::{self, b64url, Assertion, Registration};

pub const SECTION: &str = "Passkey";
const ID_FIELD: &str = "passkey-id";
const RP_FIELD: &str = "passkey-rp";
const USER_FIELD: &str = "passkey-user";
const KEY_FIELD: &str = "passkey-key";
const MAX_PASSKEYS: usize = 50;

/// A passkey the page may use: no key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyMatch {
    pub project_id: String,
    pub project: String,
    pub item_id: String,
    pub name: String,
    pub username: String,
    pub credential_id: String,
}

/// A new passkey, registered with the site.
#[derive(Debug)]
pub struct Created {
    pub project: String,
    pub name: String,
    pub registration: Registration,
}

/// A sign-in with a passkey.
#[derive(Debug)]
pub struct Used {
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub assertion: Assertion,
}

/// What a site asks for when it makes a passkey.
#[derive(Debug)]
pub struct NewPasskeyRequest<'a> {
    pub rp_id: &'a str,
    pub user_name: &'a str,
    pub user_handle: &'a [u8],
    pub challenge: &'a [u8],
    /// Credential IDs the site already has for this account.
    pub exclude: &'a [Vec<u8>],
    /// Whether the human was verified for this request (Touch ID), not only present.
    pub verified: bool,
}

/// A sign-in the human chose in the extension's window.
#[derive(Debug)]
pub struct PasskeyUse<'a> {
    pub rp_id: &'a str,
    pub project_id: &'a str,
    pub item_id: &'a str,
    /// The credential the window showed; the item must still hold it.
    pub credential_id: &'a [u8],
    pub challenge: &'a [u8],
    /// Whether the human was verified for this request (Touch ID), not only present.
    pub verified: bool,
}

fn value<'a>(meta: &'a ItemMeta, id: &str) -> &'a str {
    meta.fields
        .iter()
        .find(|f| f.id == id && !f.is_secret())
        .map_or("", |f| f.value.as_str())
}

fn has_passkey(meta: &ItemMeta) -> bool {
    meta.fields.iter().any(|f| f.id == KEY_FIELD)
}

/// The item's passkey's credential ID, when it has one for `rp_id` and is a login in use.
fn passkey_for(meta: &ItemMeta, rp_id: &str) -> Option<Vec<u8>> {
    if !meta.trashed_at.is_empty() || meta.archived || meta.kind() != "login" || !has_passkey(meta)
    {
        return None;
    }
    if value(meta, RP_FIELD) != rp_id {
        return None;
    }
    webauthn::unb64url(
        value(meta, ID_FIELD),
        "credential ID",
        webauthn::MAX_CREDENTIAL_ID,
    )
    .ok()
}

/// The page's site, if it may use passkeys for `rp_id`, and its origin for the client data.
fn page_for(page: &str, rp_id: &str) -> Result<(Site, String)> {
    let site = page_site(page)?;
    if !webauthn::rp_id_fits(rp_id, &site.host) {
        return Err(Error::Forbidden(format!(
            "This page cannot use passkeys for {rp_id}"
        )));
    }
    let origin = url::Url::parse(page)
        .map(|u| u.origin().ascii_serialization())
        .map_err(|_| Error::invalid("This page's address cannot hold logins"))?;
    Ok((site, origin))
}

impl Store {
    /// The passkeys a page may use for `rp_id`; with `allow`, only those credential IDs.
    pub fn passkeys_for(
        &self,
        page: &str,
        rp_id: &str,
        allow: &[Vec<u8>],
    ) -> Result<Vec<PasskeyMatch>> {
        page_for(page, rp_id)?;
        let st = self.state()?;
        let mut out = Vec::new();
        for p in &st.projects {
            for i in &p.items {
                let Some(id) = passkey_for(&i.meta, rp_id) else {
                    continue;
                };
                if !allow.is_empty() && !allow.contains(&id) {
                    continue;
                }
                out.push(PasskeyMatch {
                    project_id: p.id.clone(),
                    project: p.meta.name.clone(),
                    item_id: i.id.clone(),
                    name: i.meta.key.clone(),
                    username: i.meta.username.clone(),
                    credential_id: b64url(&id),
                });
            }
        }
        out.truncate(MAX_PASSKEYS);
        Ok(out)
    }

    /// Makes a passkey for the page's site and saves it: in the one login for this site and
    /// username that has none yet and that only the human controls (theirs, delegated to no
    /// agent), or in a new login of the human's in [`DEFAULT_PROJECT`]. The human chose to
    /// save it in the extension's window.
    pub fn create_passkey(
        &mut self,
        page: &str,
        req: &NewPasskeyRequest<'_>,
        browser: &Browser,
    ) -> Result<Created> {
        let (site, origin) = page_for(page, req.rp_id)?;
        validate::text(req.user_name, "username", 256, true)?;
        if req.user_handle.is_empty() || req.user_handle.len() > webauthn::MAX_USER_HANDLE {
            return Err(Error::invalid(
                "The site's user handle must be 1 to 64 bytes",
            ));
        }
        if req.challenge.len() < 16 {
            return Err(Error::invalid("The site's challenge is too short"));
        }
        let st = self.state()?;
        let excluded =
            st.projects.iter().flat_map(|p| &p.items).any(|i| {
                passkey_for(&i.meta, req.rp_id).is_some_and(|id| req.exclude.contains(&id))
            });
        if excluded {
            return Err(Error::Conflict(
                "VaultOS already has a passkey for this account".into(),
            ));
        }
        // (project id, project name, item name, its fields) of each login it could go in.
        let mut into: Vec<(String, String, String, Vec<validate::FieldInput>)> = Vec::new();
        for p in &st.projects {
            for i in &p.items {
                let fits = super::browser::fits(&i.meta, &site);
                let humans = i.meta.owner == HUMAN && i.meta.editable_by.is_empty();
                if fits && humans && i.meta.username == req.user_name && !has_passkey(&i.meta) {
                    let fields = i
                        .meta
                        .fields
                        .iter()
                        .map(|f| validate::FieldInput {
                            id: f.id.clone(),
                            section: f.section.clone(),
                            label: f.label.clone(),
                            kind: f.kind.clone(),
                            value: None,
                        })
                        .collect();
                    into.push((
                        p.id.clone(),
                        p.meta.name.clone(),
                        i.meta.key.clone(),
                        fields,
                    ));
                }
            }
        }
        let new = webauthn::new_passkey();
        let registration = webauthn::register(
            req.rp_id,
            &origin,
            req.challenge,
            &new.credential_id,
            &new.private_key,
            req.verified,
        )?;
        let (project_id, project, key, mut fields, url) = match into.len() {
            1 => {
                let (id, name, key, fields) = into.remove(0);
                (id, name, key, fields, None)
            }
            _ => {
                let id = match self.find_project(DEFAULT_PROJECT)? {
                    Some((id, _)) => id,
                    None => self.create_project(DEFAULT_PROJECT, HUMAN)?.0,
                };
                let key = self.free_login_name(&id, &site.host, req.user_name)?;
                (
                    id,
                    DEFAULT_PROJECT.to_owned(),
                    key,
                    Vec::new(),
                    Some(origin.clone()),
                )
            }
        };
        let field = |id: &str, label: &str, kind: &str, v: String| validate::FieldInput {
            id: id.into(),
            section: SECTION.into(),
            label: label.into(),
            kind: kind.into(),
            value: Some(SecretString::new(v)),
        };
        fields.extend([
            field(
                ID_FIELD,
                "Credential ID",
                "text",
                b64url(&new.credential_id),
            ),
            field(RP_FIELD, "Relying party", "text", req.rp_id.to_owned()),
            field(USER_FIELD, "User handle", "text", b64url(req.user_handle)),
            field(
                KEY_FIELD,
                "Private key",
                "concealed",
                new.private_key.to_string(),
            ),
        ]);
        // Audited before the save, which records the entry in the vault: a passkey is never
        // saved without its entry.
        self.audit(
            "browser-passkey-create",
            &format!("{project}/{key} for {} from {}", req.rp_id, site.host),
            &browser_actor(browser),
        )?;
        let saved = self.set_item(
            &project_id,
            &Fields {
                key,
                username: url.is_some().then(|| req.user_name.to_owned()),
                url,
                kind: Some("login".into()),
                fields: Some(fields),
                ..Fields::default()
            },
            HUMAN,
        )?;
        Ok(Created {
            project,
            name: saved.key,
            registration,
        })
    }

    /// Signs in to the page's site with a login's passkey for `rp_id`, if the login still
    /// holds the credential the human chose.
    pub fn use_passkey(
        &mut self,
        page: &str,
        u: &PasskeyUse<'_>,
        browser: &Browser,
    ) -> Result<Used> {
        let PasskeyUse {
            rp_id,
            project_id,
            item_id,
            challenge,
            ..
        } = *u;
        let (site, origin) = page_for(page, rp_id)?;
        if challenge.len() < 16 {
            return Err(Error::invalid("The site's challenge is too short"));
        }
        let (used, detail) = {
            let st = self.state()?;
            let keys = &self.open()?.keys;
            let p = &st.projects[st.project(project_id)?];
            let (i, credential_id) = p
                .items
                .iter()
                .find_map(|i| {
                    (i.id == item_id)
                        .then(|| passkey_for(&i.meta, rp_id))
                        .flatten()
                        .map(|c| (i, c))
                })
                .ok_or_else(|| Error::not_found("No passkey for this site has that id"))?;
            if credential_id != u.credential_id {
                return Err(Error::Conflict(
                    "This login's passkey changed while you were choosing it. Try again.".into(),
                ));
            }
            let secret = keys.open_secret(p, i)?;
            let key = secret
                .fields
                .iter()
                .find(|s| s.id == KEY_FIELD)
                .ok_or_else(|| Error::not_found("This passkey has no key"))?;
            let user_handle = webauthn::unb64url(
                value(&i.meta, USER_FIELD),
                "user handle",
                webauthn::MAX_USER_HANDLE,
            )?;
            (
                Used {
                    credential_id,
                    user_handle,
                    assertion: webauthn::assert(rp_id, &origin, challenge, &key.value, u.verified)?,
                },
                format!("{}/{} on {}", p.meta.name, i.meta.key, site.host),
            )
        };
        self.audit("browser-passkey", &detail, &browser_actor(browser))?;
        Ok(used)
    }
}
