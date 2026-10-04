//! Field selection that keeps the document's nesting, so a selected row has
//! the same shape as the stored document minus unselected members.
use crate::allocation;
use crate::scalar::{invalid, validate_pointer};
use kasumi_types::Result;
use serde::ser::{Serialize, SerializeMap, Serializer};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Selected object members, as a tree of decoded JSON Pointer tokens.
#[derive(Debug, Default)]
pub(crate) struct Selection {
    children: BTreeMap<String, Selection>,
    leaf: bool,
}

fn tokens(path: &str) -> Result<Vec<String>> {
    validate_pointer(path)?;
    if path.is_empty() {
        return Err(invalid(
            "select names fields; omit select to return whole documents",
        ));
    }
    Ok(path[1..]
        .split('/')
        .map(|token| token.replace("~1", "/").replace("~0", "~"))
        .collect())
}

impl Selection {
    /// Paths must not repeat or contain one another, so every output member
    /// has exactly one source.
    pub(crate) fn new(paths: &[String], what: &str) -> Result<Self> {
        let mut root = Selection::default();
        for path in paths {
            let mut node = &mut root;
            for token in tokens(path)? {
                if node.leaf {
                    return Err(invalid(format!("{what} paths overlap at {path}")));
                }
                node = node.children.entry(token).or_default();
            }
            if node.leaf || !node.children.is_empty() {
                return Err(invalid(format!("{what} paths overlap at {path}")));
            }
            node.leaf = true;
        }
        Ok(root)
    }

    fn present(&self, value: &Value) -> bool {
        let Value::Object(members) = value else {
            return false;
        };
        self.children.iter().any(|(key, child)| {
            members
                .get(key)
                .is_some_and(|value| child.leaf || child.present(value))
        })
    }

    /// Before-clone charge for `project`, using the same conservative model as
    /// whole-document clones. The walk borrows and allocates nothing.
    pub(crate) fn clone_bytes(&self, value: &Value) -> Result<u64> {
        let Value::Object(members) = value else {
            return Ok(0);
        };
        let mut bytes = 0;
        for (key, child) in &self.children {
            let Some(value) = members.get(key) else {
                continue;
            };
            let nested = if child.leaf {
                allocation::json_clone_bytes(value)?
            } else if child.present(value) {
                child.clone_bytes(value)?
            } else {
                continue;
            };
            bytes = allocation::add(bytes, allocation::object_entry_bytes()?)?;
            bytes = allocation::add(bytes, allocation::string_clone_bytes(key)?)?;
            bytes = allocation::add(bytes, nested)?;
        }
        Ok(bytes)
    }

    /// The selected members of `value`; an object even when nothing matched.
    pub(crate) fn project(&self, value: &Value) -> Value {
        let mut projected = Map::new();
        if let Value::Object(members) = value {
            for (key, child) in &self.children {
                let Some(value) = members.get(key) else {
                    continue;
                };
                if child.leaf {
                    projected.insert(key.clone(), value.clone());
                } else if child.present(value) {
                    projected.insert(key.clone(), child.project(value));
                }
            }
        }
        Value::Object(projected)
    }

    pub(crate) fn view<'a>(&'a self, value: &'a Value) -> View<'a> {
        View {
            selection: self,
            value,
        }
    }

    /// Insert `value` at `path` (a member of this selection) into `output`.
    pub(crate) fn insert(output: &mut Map<String, Value>, path: &str, value: Value) -> Result<()> {
        let tokens = tokens(path)?;
        let (last, parents) = tokens.split_last().expect("nonempty pointer");
        let mut target = output;
        for token in parents {
            target = match target
                .entry(token.clone())
                .or_insert_with(|| Value::Object(Map::new()))
            {
                Value::Object(members) => members,
                _ => return Err(invalid("group paths overlap")),
            };
        }
        target.insert(last.clone(), value);
        Ok(())
    }
}

/// Serializes `project(value)` without building it, for exact size checks.
pub(crate) struct View<'a> {
    selection: &'a Selection,
    value: &'a Value,
}

impl Serialize for View<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        if let Value::Object(members) = self.value {
            for (key, child) in &self.selection.children {
                let Some(value) = members.get(key) else {
                    continue;
                };
                if child.leaf {
                    map.serialize_entry(key, value)?;
                } else if child.present(value) {
                    map.serialize_entry(key, &child.view(value))?;
                }
            }
        }
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn select(paths: &[&str]) -> Result<Selection> {
        let paths: Vec<String> = paths.iter().map(|path| (*path).to_owned()).collect();
        Selection::new(&paths, "select")
    }

    #[test]
    fn projection_keeps_nesting_and_omits_absent_branches() {
        let document = json!({
            "amount": 12.5,
            "customer": {"name": "Ada", "email": "ada@example.com", "tier": {"level": 2}},
            "items": [{"sku": "a"}],
            "a/b": {"~": 1},
            "empty": {}
        });
        let selection = select(&[
            "/amount",
            "/customer/name",
            "/customer/tier/level",
            "/missing/deep",
            "/items/0/sku",
            "/a~1b/~0",
            "/empty/none",
        ])
        .unwrap();
        let projected = selection.project(&document);
        assert_eq!(
            projected,
            json!({
                "amount": 12.5,
                "customer": {"name": "Ada", "tier": {"level": 2}},
                "a/b": {"~": 1}
            })
        );
        assert_eq!(
            serde_json::to_value(selection.view(&document)).unwrap(),
            projected
        );
        assert!(
            selection.clone_bytes(&document).unwrap()
                >= allocation::json_clone_bytes(&projected).unwrap()
        );
        assert_eq!(select(&["/x"]).unwrap().project(&json!(5)), json!({}));
    }

    #[test]
    fn overlapping_or_empty_selections_are_rejected() {
        for paths in [
            &["/a", "/a"][..],
            &["/a", "/a/b"],
            &["/a/b", "/a"],
            &[""],
            &["a"],
        ] {
            assert!(select(paths).is_err(), "{paths:?}");
        }
        assert!(select(&["/a/b", "/a/c", "/b"]).is_ok());
    }
}
