//! Logical document IDs of an installed collection without structured fields.
use crate::QueryIndexes;
use kasumi_types::{ArchivedDocument, CollectionState, DocumentSlot, Error, ErrorCode, Result};
use std::{collections::BTreeMap, fmt, ops::Bound, sync::Arc};

/// The exact selected physical header directory of a detached ordinary reader.
#[doc(hidden)]
pub trait PrimaryIdPages: fmt::Debug + Send + Sync {
    fn ids_after(&self, after: Option<&str>, limit: usize) -> Result<Vec<String>>;
}

#[derive(Clone, Debug)]
pub(crate) enum LogicalIds {
    Rows {
        live: imbl::OrdMap<String, Arc<DocumentSlot>>,
        archived: imbl::OrdMap<String, Arc<ArchivedDocument>>,
    },
    Directory(Arc<dyn PrimaryIdPages>),
}

impl LogicalIds {
    pub(crate) fn rows(collection: &CollectionState) -> Self {
        Self::Rows {
            live: collection.documents.clone(),
            archived: collection.archived_documents.clone(),
        }
    }

    fn matches(&self, collection: &CollectionState) -> bool {
        matches!(self, Self::Rows {live, archived} if live.ptr_eq(&collection.documents)
            && archived.ptr_eq(&collection.archived_documents))
    }

    pub(crate) fn page(&self, after: Option<&str>, limit: usize) -> Result<Vec<String>> {
        match self {
            Self::Directory(reader) => reader.ids_after(after, limit),
            Self::Rows { live, archived } => {
                let bounds = (
                    after.map_or(Bound::Unbounded, Bound::Excluded),
                    Bound::Unbounded,
                );
                let ids = ordered_union(
                    live.range::<_, str>(bounds).map(|(id, _)| id),
                    archived.range::<_, str>(bounds).map(|(id, _)| id),
                );
                Ok(ids.take(limit).cloned().collect())
            }
        }
    }

    pub(crate) fn visit_selected<S: crate::DocumentSource + ?Sized>(
        &self,
        source: &S,
        cancellation: &crate::QueryCancellation,
        mut lend: impl FnMut(&str) -> Result<()>,
    ) -> crate::ReadResult<(), S::Failure> {
        let mut visited = false;
        let available = source.visit_primary_ids(cancellation, |id| {
            visited = true;
            lend(id)
        })?;
        if !available {
            if visited {
                return Err(Error::new(ErrorCode::Corruption, "partial primary directory").into());
            }
            self.visit(lend)?;
        }
        Ok(())
    }

    pub(crate) fn visit(&self, mut lend: impl FnMut(&str) -> Result<()>) -> Result<()> {
        const ROWS: usize = 32;
        let mut after = None;
        loop {
            let page = self.page(after.as_deref(), ROWS)?;
            if page.len() > ROWS {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "oversized logical ID window",
                ));
            }
            let mut previous = after.as_deref();
            for id in &page {
                if previous.is_some_and(|prior: &str| prior >= id.as_str()) {
                    return Err(Error::new(
                        ErrorCode::Corruption,
                        "logical ID window is out of order",
                    ));
                }
                lend(id)?;
                previous = Some(id);
            }
            if page.len() < ROWS {
                return Ok(());
            }
            after = page.into_iter().next_back();
        }
    }
}

impl QueryIndexes {
    /// Install only the already-finalized row roots. A generation whose selected
    /// primary is stale still has an exact ordered fallback and a context-free
    /// caller can continue paging without creating another full ID set.
    #[doc(hidden)]
    pub fn with_collection_id_sources(
        &self,
        rows: &BTreeMap<String, CollectionState>,
    ) -> Option<Self> {
        if self.seek_projection.is_some() {
            return None;
        }
        let mut changed = None;
        for (name, collection) in rows {
            let Some(indexes) = self.collections.get(name) else {
                continue;
            };
            if !indexes.structured.fields.is_empty()
                || indexes
                    .logical_ids
                    .as_ref()
                    .is_some_and(|old| old.matches(collection))
            {
                continue;
            }
            let collections = changed.get_or_insert_with(|| self.collections.clone());
            let local = Arc::make_mut(
                collections
                    .get_mut(name)
                    .expect("selected collection index"),
            );
            local.structured.ids.clear();
            local.logical_ids = Some(LogicalIds::rows(collection));
        }
        changed.map(|collections| Self {
            collections,
            text_residency: self.text_residency,
            seek_projection: None,
            structured_layout: self.structured_layout.clone(),
        })
    }

    /// A bounded ordinary worker can release the canonical fallback maps
    /// after the selected directory has proved this generation's boundary.
    #[doc(hidden)]
    pub fn for_query_collection_with_primary(
        &self,
        name: &str,
        reader: impl FnOnce() -> Arc<dyn PrimaryIdPages>,
    ) -> Option<Self> {
        let mut scoped = self.for_query_collection(name)?;
        let index = scoped.collections.get_mut(name)?;
        if index.structured.fields.is_empty() {
            let local = Arc::make_mut(index);
            local.structured.ids.clear();
            local.logical_ids = Some(LogicalIds::Directory(reader()));
        }
        Some(scoped)
    }
}

/// Merge two strictly ordered key streams, yielding a shared key once.
pub fn ordered_union<T: Ord>(
    left: impl Iterator<Item = T>,
    right: impl Iterator<Item = T>,
) -> impl Iterator<Item = T> {
    let mut left = left.peekable();
    let mut right = right.peekable();
    std::iter::from_fn(move || match (left.peek(), right.peek()) {
        (Some(a), Some(b)) => match a.cmp(b) {
            std::cmp::Ordering::Less => left.next(),
            std::cmp::Ordering::Greater => right.next(),
            std::cmp::Ordering::Equal => {
                right.next();
                left.next()
            }
        },
        (Some(_), None) => left.next(),
        _ => right.next(),
    })
}
