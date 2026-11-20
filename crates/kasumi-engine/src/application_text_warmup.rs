//! One registered database monitor step opens at most one selected text shard.
//! A completed sweep holds neither a generation nor an open native reader.
use super::*;
use crate::Generation;
use std::sync::Weak;

#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TextWarmupState {
    #[default]
    Pending,
    Scanning,
    Complete,
    CapacityLimited,
    DirectoryUnavailable,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct TextWarmupStatus {
    pub state: TextWarmupState,
    pub revision: Option<u64>,
    pub visited_shards: u64,
    pub skipped_shards: u64,
    pub completed_sweeps: u64,
}

#[derive(Default)]
pub(crate) struct Warmup {
    generation: Weak<Generation>,
    /// Current collection if a shard position exists, otherwise the last completed collection.
    collection: Option<String>,
    after: Option<(u8, u64)>,
    repeat: bool,
    cache_epoch: u64,
    last_tree: Option<[u8; 16]>,
    checking_cache: bool,
    checked: Option<CacheKey>,
    denied: Option<u64>,
    pub(crate) status: TextWarmupStatus,
}

impl Warmup {
    fn begin_pass(&mut self) {
        self.checking_cache = self.last_tree.is_some();
        self.checked = None;
        self.collection = None;
        self.after = None;
        self.denied = None;
        self.repeat = false;
        self.status.state = TextWarmupState::Scanning;
        self.status.visited_shards = 0;
        self.status.skipped_shards = 0;
    }

    pub(crate) fn step(
        &mut self,
        generation: &Arc<Generation>,
        admission: &Arc<NodeAdmission>,
    ) -> Result<()> {
        let epoch = admission.text_shards.lock().unwrap().evictions;
        let changed =
            self.generation.as_ptr() != Arc::as_ptr(generation) || self.cache_epoch != epoch;
        self.generation = Arc::downgrade(generation);
        self.cache_epoch = epoch;
        self.status.revision = Some(generation.revision());
        match self.status.state {
            TextWarmupState::Scanning => self.repeat |= changed,
            TextWarmupState::Complete | TextWarmupState::DirectoryUnavailable if !changed => {
                return Ok(());
            }
            TextWarmupState::CapacityLimited if !changed => {
                let needed = self.denied.context("missing text warmup capacity quote")?;
                if admission.try_reserve_text_shard(needed)?.is_none() {
                    return Ok(());
                }
                self.begin_pass();
            }
            _ => self.begin_pass(),
        }

        // Reclaim at most one obsolete cached identity before opening another
        // shard. A concurrent user keeps its Arc and charge. Previous selections
        // remain independently readable through their pinned native roots.
        if self.checking_cache && self.check_cached(generation, admission)? {
            return Ok(());
        }
        self.checking_cache = false;
        self.checked = None;
        let collections = &generation.state.collections;
        let start = match self.collection.as_deref() {
            None => Bound::Unbounded,
            Some(name) if self.after.is_some() => Bound::Included(name),
            Some(name) => Bound::Excluded(name),
        };
        let Some((name, collection)) = collections
            .range::<str, _>((start, Bound::Unbounded))
            .next()
        else {
            self.status.completed_sweeps = self.status.completed_sweeps.saturating_add(1);
            if self.repeat {
                self.begin_pass();
            } else if self.denied.is_some() {
                self.status.state = TextWarmupState::CapacityLimited;
            } else {
                self.status.state = TextWarmupState::Complete;
            }
            return Ok(());
        };
        if self.collection.as_ref() != Some(name) {
            self.after = None;
        }
        // Commit the cursor only after the selected source has actually been served.
        if !collection
            .definition
            .indexes
            .iter()
            .any(|i| i.text.is_some())
        {
            self.collection = Some(name.clone());
            self.after = None;
            return Ok(());
        }
        let Some(selection) = generation.application_selection.get() else {
            self.status.state = TextWarmupState::DirectoryUnavailable;
            return Ok(());
        };
        // The native reader admits its own path and overflow buffers. Keep the
        // decoded descriptors, path copies and Tantivy schema construction in
        // the optional budget as well. No file is opened when this is denied.
        let layout_bytes = collection
            .definition
            .indexes
            .iter()
            .filter(|index| index.text.is_some())
            .flat_map(|index| &index.fields)
            .try_fold(4 * MAX_DESCRIPTOR_BYTES as u64, |sum, field| {
                sum.checked_add(4096 + 8 * field.path.len() as u64)
            })
            .context("text warmup layout quote overflow")?;
        let Some(_workspace) = admission.try_reserve_text_shard(layout_bytes)? else {
            self.denied = Some(layout_bytes);
            self.status.state = TextWarmupState::CapacityLimited;
            return Ok(());
        };
        let step = selection.with_text_records(
            None,
            &generation.state,
            |tree, source, manifest, owner| {
                ensure!(
                    Arc::ptr_eq(owner, admission),
                    "text warmup memory owner differs"
                );
                Self::visit(tree, source, manifest, collection, owner, self.after)
            },
        )?;
        if let Some((tree, position, denied)) = step {
            self.last_tree = Some(tree);
            if let Some(bytes) = denied {
                let bytes = bytes
                    .checked_add(layout_bytes)
                    .context("text warmup quote overflow")?;
                self.denied = Some(self.denied.map_or(bytes, |old| old.min(bytes)));
                self.status.skipped_shards = self.status.skipped_shards.saturating_add(1);
            }
            self.status.visited_shards = self
                .status
                .visited_shards
                .saturating_add(u64::from(position.is_some()));
            self.collection = Some(name.clone());
            self.after = position;
        } else {
            self.status.state = TextWarmupState::DirectoryUnavailable;
        }
        Ok(())
    }

    fn check_cached(
        &mut self,
        generation: &Generation,
        admission: &Arc<NodeAdmission>,
    ) -> Result<bool> {
        let Some(tree_id) = self.last_tree else {
            return Ok(false);
        };
        let Some(key) = admission.text_shards.lock().unwrap().next_in_tree(
            generation.tenant(),
            tree_id,
            self.checked.as_ref(),
        ) else {
            return Ok(false);
        };
        let Some(selection) = generation.application_selection.get() else {
            return Ok(false);
        };
        let valid =
            selection.with_text_records(None, &generation.state, |tree, _, manifest, _| {
                if manifest.records.tree != key.0.tree {
                    return Ok(false);
                }
                let descriptor: Option<ShardDescriptor> =
                    read(tree, &shard_key(&key.0.collection, key.0.seq))?;
                Ok(descriptor.is_some_and(|d| {
                    d.layout == key.0.layout
                        && d.contents_sha256
                            .or_else(|| tree.root().root.map(|p| p.sha256))
                            == Some(key.1)
                }))
            })?;
        if valid == Some(false) {
            admission.text_shards.lock().unwrap().entries.remove(&key);
        }
        self.checked = Some(key);
        Ok(true)
    }

    fn visit(
        tree: &TreeReader<'_>,
        source: &dyn PageSource,
        manifest: &TextManifest,
        collection: &CollectionState,
        admission: &Arc<NodeAdmission>,
        after: Option<(u8, u64)>,
    ) -> Result<WarmStep> {
        let name = collection.definition.name.as_str();
        let mut next = None;
        visit_levels(tree, name, after.unwrap_or((0, 0)), |level, seq| {
            let position = (level, seq);
            if Some(position) == after {
                return Ok(true);
            }
            next = Some(position);
            Ok(false)
        })?;
        let mut denied = None;
        if let Some((_, seq)) = next {
            let layout = TextShardLayout::for_definition(&collection.definition)
                .context("text warmup layout missing")?;
            let descriptor: CollectionDescriptor =
                read(tree, &collection_key(name))?.context("text warmup collection missing")?;
            ensure!(
                descriptor.layout == layout.sha256(),
                "selected text warmup layout differs"
            );
            let key = ShardAddress {
                tenant: manifest.tenant.clone(),
                tree: manifest.records.tree,
                collection: name.into(),
                seq,
                layout: descriptor.layout,
            };
            if let ShardLoad::Capacity(bytes) =
                load_selected_shard(tree, source, key, &layout, admission, false)?
            {
                denied = Some(bytes);
            }
        }
        Ok((manifest.records.tree, next, denied))
    }
}

type WarmStep = ([u8; 16], Option<(u8, u64)>, Option<u64>);
