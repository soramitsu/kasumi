//! Private indexes assembled from the ordered live documents of a snapshot.
use crate::{CollectionIndexes, QueryIndexes, TextResidency, invalid, validation};
use kasumi_types::{CollectionDefinition, Document, Result, validate_name};
use std::{collections::BTreeMap, sync::Arc};

/// A restore can validate and index a live body while it still owns the decode.
/// Collections with archives or secondary indexes use the replayable source.
#[derive(Clone, Default)]
pub struct SnapshotIndexBuilder {
    collections: BTreeMap<String, (Arc<CollectionDefinition>, CollectionIndexes)>,
    failed: bool,
}

impl SnapshotIndexBuilder {
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
        entry.insert((definition.clone(), CollectionIndexes::empty(definition)?));
        self.failed = false;
        Ok(())
    }

    pub fn add_document(&mut self, collection: &str, document: &Document) -> Result<()> {
        self.begin()?;
        let (definition, indexes) = self
            .collections
            .get_mut(collection)
            .ok_or_else(|| invalid("snapshot document lacks its index collection"))?;
        validate_name(&document.id)?;
        if indexes
            .structured
            .ids
            .iter()
            .next_back()
            .is_some_and(|last| last.as_ref() >= document.id.as_str())
        {
            return Err(invalid("snapshot index documents are out of order"));
        }
        validation::validate_document_with_validator(
            definition,
            &document.body,
            &indexes.validator,
        )?;
        indexes
            .structured
            .ids
            .insert(Arc::from(document.id.as_str()));
        self.failed = false;
        Ok(())
    }

    pub fn finish(self, residency: TextResidency) -> Result<QueryIndexes> {
        if self.failed {
            return Err(invalid("snapshot index construction previously failed"));
        }
        Ok(QueryIndexes {
            collections: self
                .collections
                .into_iter()
                .map(|(name, (_, indexes))| (name, Arc::new(indexes)))
                .collect(),
            text_residency: residency,
            seek_projection: None,
            structured_layout: Default::default(),
        })
    }
}
