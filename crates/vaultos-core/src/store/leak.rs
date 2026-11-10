//! The leak index: keyed hashes of every value in the vault, for `vaultos scan` and the
//! app's folder scan. See [`crate::leak`].

use super::*;
use crate::leak::{Index, Source};

/// What a hit's source is, by name, for someone who can open the vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Named {
    pub project: String,
    pub item: String,
    pub field: String,
}

impl Store {
    /// Indexes every value, password and secret field, archived and trashed items too: a
    /// value that leaked before it was retired still matters.
    pub fn leak_index(&mut self, actor: &str) -> Result<Index> {
        forbidden_unless_human(actor, "The leak scan")?;
        let vault_id = self.vault_id()?.to_owned();
        let index = {
            let st = self.state()?;
            let k = &self.open()?.keys;
            let mut index = Index::new(&vault_id);
            for p in &st.projects {
                for i in &p.items {
                    let s = k.open_secret(p, i)?;
                    let source = |field: &str| Source {
                        project_id: p.id.clone(),
                        item_id: i.id.clone(),
                        field: field.to_owned(),
                    };
                    index.add(&s.value, source("value"));
                    index.add(&s.password, source("password"));
                    for f in &s.fields {
                        index.add(&f.value, source(&f.id));
                    }
                }
            }
            index
        };
        self.audit("leak-index", &format!("{} values", index.len()), actor)?;
        Ok(index)
    }

    /// The names behind an index's sources, in order; `None` for one no longer in the vault.
    pub fn name_sources(&self, sources: &[Source]) -> Result<Vec<Option<Named>>> {
        let st = self.state()?;
        let mut out = Vec::new();
        for s in sources {
            let Some(p) = st.projects.iter().find(|p| p.id == s.project_id) else {
                out.push(None);
                continue;
            };
            let Some(i) = p.items.iter().find(|i| i.id == s.item_id) else {
                out.push(None);
                continue;
            };
            let field = match s.field.as_str() {
                "value" | "password" => s.field.clone(),
                id => i
                    .meta
                    .fields
                    .iter()
                    .find(|f| f.id == id)
                    .map_or_else(|| "field".to_owned(), |f| f.label.clone()),
            };
            out.push(Some(Named {
                project: p.meta.name.clone(),
                item: i.meta.key.clone(),
                field,
            }));
        }
        Ok(out)
    }
}
