//! Private indexes assembled from the ordered live documents of a snapshot.
use crate::{CollectionIndexes, QueryIndexes, TextResidency, invalid, validation};
use kasumi_types::{CollectionDefinition, CollectionState, Document, Result, validate_name};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};

/// A restore can validate and index a live body while it still owns the decode.
/// Collections with archives or secondary indexes use the replayable source.
#[derive(Clone, Default)]
pub struct SnapshotIndexBuilder {
    collections: BTreeMap<String, SnapshotCollection>,
    installed: bool,
    failed: bool,
}

#[derive(Clone)]
struct SnapshotCollection {
    definition: Arc<CollectionDefinition>,
    indexes: CollectionIndexes,
    sequence: Option<IdSequence>,
}

#[derive(Clone, Default)]
struct IdSequence {
    last: Option<String>,
    digest: Sha256,
}

impl IdSequence {
    fn hash(digest: &mut Sha256, id: &str, version: u64) {
        digest.update((id.len() as u64).to_be_bytes());
        digest.update(id.as_bytes());
        digest.update(version.to_be_bytes());
    }
}

impl SnapshotIndexBuilder {
    /// The authenticated restore appends canonical descriptors while validating
    /// the live documents. Keep only the ordered digest until both agree.
    #[doc(hidden)]
    pub fn for_installed_rows() -> Self {
        Self {
            installed: true,
            ..Self::default()
        }
    }

    fn begin(&mut self) -> Result<()> {
        if std::mem::replace(&mut self.failed, true) {
            return Err(invalid("snapshot index construction previously failed"));
        }
        Ok(())
    }

    pub fn add_collection(&mut self, definition: &Arc<CollectionDefinition>) -> Result<()> {
        self.begin()?;
        if !definition.indexes.is_empty() {
            return Err(invalid(
                "snapshot secondary indexes require a replayable collection",
            ));
        }
        let entry = self.collections.entry(definition.name.clone());
        let std::collections::btree_map::Entry::Vacant(entry) = entry else {
            return Err(invalid("duplicate snapshot index collection"));
        };
        entry.insert(SnapshotCollection {
            definition: definition.clone(),
            indexes: CollectionIndexes::empty(definition)?,
            sequence: self.installed.then(IdSequence::default),
        });
        self.failed = false;
        Ok(())
    }

    pub fn add_document(&mut self, collection: &str, document: &Document) -> Result<()> {
        self.begin()?;
        let entry = self
            .collections
            .get_mut(collection)
            .ok_or_else(|| invalid("snapshot document lacks its index collection"))?;
        validate_name(&document.id)?;
        let last = match &entry.sequence {
            Some(sequence) => sequence.last.as_deref(),
            None => entry.indexes.structured.ids.get_max().map(AsRef::as_ref),
        };
        if last.is_some_and(|last| last >= document.id.as_str()) {
            return Err(invalid("snapshot index documents are out of order"));
        }
        validation::validate_document_with_validator(
            &entry.definition,
            &document.body,
            &entry.indexes.validator,
        )?;
        if let Some(sequence) = &mut entry.sequence {
            IdSequence::hash(&mut sequence.digest, &document.id, document.version);
            sequence
                .last
                .get_or_insert_with(String::new)
                .clone_from(&document.id);
        } else {
            entry
                .indexes
                .structured
                .ids
                .insert(Arc::from(document.id.as_str()));
        }
        self.failed = false;
        Ok(())
    }

    pub fn finish(self, residency: TextResidency) -> Result<QueryIndexes> {
        if self.installed {
            return Err(invalid("snapshot collection rows are required"));
        }
        self.finish_collections(residency, None, || Ok(()))
    }

    #[doc(hidden)]
    pub fn finish_installed<E: From<kasumi_types::Error>>(
        self,
        residency: TextResidency,
        rows: &BTreeMap<String, CollectionState>,
        check: impl FnMut() -> std::result::Result<(), E>,
    ) -> std::result::Result<QueryIndexes, E> {
        if !self.installed || self.collections.len() != rows.len() {
            return Err(invalid("snapshot index collection set differs").into());
        }
        self.finish_collections(residency, Some(rows), check)
    }

    fn finish_collections<E: From<kasumi_types::Error>>(
        self,
        residency: TextResidency,
        rows: Option<&BTreeMap<String, CollectionState>>,
        mut check: impl FnMut() -> std::result::Result<(), E>,
    ) -> std::result::Result<QueryIndexes, E> {
        if self.failed {
            return Err(invalid("snapshot index construction previously failed").into());
        }
        let mut collections = BTreeMap::new();
        for (name, entry) in self.collections {
            let mut indexes = entry.indexes;
            if let Some(sequence) = entry.sequence {
                let collection = rows
                    .and_then(|all| all.get(&name))
                    .ok_or_else(|| invalid("snapshot index collection missing"))?;
                if !Arc::ptr_eq(&entry.definition, &collection.definition)
                    || !collection.archived_documents.is_empty()
                {
                    return Err(invalid("snapshot index collection owners differ").into());
                }
                let mut actual = Sha256::new();
                for (position, (id, slot)) in collection.documents.iter().enumerate() {
                    if position.is_multiple_of(256) {
                        check()?;
                    }
                    if slot.id() != id {
                        return Err(
                            invalid("snapshot index stored document identity differs").into()
                        );
                    }
                    IdSequence::hash(&mut actual, id, slot.version());
                }
                if actual.finalize() != sequence.digest.finalize() {
                    return Err(invalid("snapshot index document headers differ").into());
                }
                indexes.logical_ids = Some(crate::LogicalIds::rows(collection));
            }
            collections.insert(name, Arc::new(indexes));
        }
        Ok(QueryIndexes {
            collections,
            text_residency: residency,
            seek_projection: None,
            structured_layout: Default::default(),
        })
    }
}
