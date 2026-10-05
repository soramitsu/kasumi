//! Bounded fresh unselected catalog construction. Direct manifest closure only;
//! this does not publish a selector or certify the full accepted projection.
use super::*;
use crate::primary_tree::Totals;
use records::{CatalogEntry, CatalogId, CatalogMember, Manifest, ManifestRef};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Appending,
    Verifying,
    Complete,
}
#[derive(Clone, Copy)]
pub(super) struct CatalogBuildState {
    inventory: Inventory,
    phase: Phase,
    cursor: u64,
    last: Option<CatalogMember>,
    totals: Totals,
    attempt: Option<Attempt>,
}
/// Physical evidence only. Construction is private; no serving authority.
#[derive(Debug)]
pub(crate) struct StagedCatalog {
    id: CatalogId,
    scope: [u8; 32],
    member_count: u64,
    totals: Totals,
}
impl StagedCatalog {
    pub(crate) fn id(&self) -> CatalogId {
        self.id
    }
    pub(crate) fn scope(&self) -> [u8; 32] {
        self.scope
    }
    pub(crate) fn member_count(&self) -> u64 {
        self.member_count
    }
    pub(crate) fn totals(&self) -> Totals {
        self.totals
    }
}
impl PrimaryStage<'_, '_> {
    pub(crate) fn begin_catalog(self) -> Result<Self> {
        let (stage, ()) = self.perform(PrimaryResources::begin_catalog)?;
        Ok(stage)
    }
    pub(crate) fn append_catalog(self, name: &str, manifest: ManifestRef) -> Result<Self> {
        let (stage, ()) = self.perform(|resources| resources.append_catalog(name, manifest))?;
        Ok(stage)
    }
    pub(crate) fn finish_catalog_step(
        self,
        max_members: usize,
    ) -> Result<(Self, Option<StagedCatalog>)> {
        self.perform(|resources| resources.finish_catalog_step(max_members.min(64)))
    }
}
impl PrimaryResources {
    pub(super) fn require_catalog_mutable(&self) -> Result<()> {
        ensure!(
            !self.cow_frozen,
            "primary accepted verification owns the source pin"
        );
        ensure!(
            self.active_catalog
                .is_none_or(|state| state.phase != Phase::Verifying),
            "primary catalog verification owns the source pin"
        );
        Ok(())
    }
    pub(super) fn metadata_shape(namespace: &str, key: usize, value: Option<usize>) -> bool {
        let fixed = |wanted_key, wanted_value| {
            key == wanted_key && value.is_none_or(|bytes| bytes == wanted_value)
        };
        namespace.len() <= 32
            && key <= MAX_KEY_BYTES
            && value.is_none_or(|n| n <= MAX_METADATA_BYTES)
            && match namespace {
                META => fixed(2, records::GC_BYTES) || fixed(8, records::SELECTOR_BYTES),
                EPOCHS => fixed(16, records::EPOCH_BYTES),
                ATTEMPTS => fixed(16, records::ATTEMPT_BYTES),
                INVENTORY => fixed(24, records::INVENTORY_BYTES),
                MANIFESTS => fixed(24, records::MANIFEST_BYTES),
                CATALOG => fixed(56, records::CATALOG_ENTRY_BYTES),
                MEMBERS => fixed(32, records::CATALOG_MEMBER_BYTES),
                RETIRES => fixed(24, records::RETIRE_BYTES),
                PAGES => key == 24 && value.is_none(),
                CHUNKS => key == 32 && value.is_none(),
                _ => false,
            }
    }
    fn catalog_attempt(&mut self) -> Result<Attempt> {
        let cached = self.attempt.context("primary attempt absent")?;
        let actual = self.read(ATTEMPTS, &cached.id, records::ATTEMPT_BYTES, |bytes| {
            codec(Attempt::decode(
                bytes.context("primary catalog owning attempt absent")?,
            ))
        })?;
        ensure!(
            actual == cached
                && actual.phase == AttemptPhase::Building
                && actual.scope == self.scope,
            "primary catalog owning attempt differs"
        );
        Ok(actual)
    }
    pub(super) fn require_catalog_inventory(inventory: Inventory) -> Result<()> {
        ensure!(
            inventory.kind == ResourceKind::Catalog
                && inventory.total_units == inventory.completed_units
                && inventory.total_units == inventory.catalog_dense_count,
            "primary catalog inventory counts differ"
        );
        Ok(())
    }
    fn read_catalog_inventory(&mut self, expected: Inventory) -> Result<Inventory> {
        let actual = self.read(
            INVENTORY,
            &object_key(expected.id),
            records::INVENTORY_BYTES,
            |bytes| {
                codec(Inventory::decode(
                    bytes.context("primary catalog inventory absent")?,
                ))
            },
        )?;
        Self::require_catalog_inventory(actual)?;
        ensure!(
            actual == expected
                && actual.scope == self.scope
                && actual.phase == InventoryPhase::Allocating
                && actual.cleanup_unit_cursor == 0,
            "primary catalog inventory differs"
        );
        Ok(actual)
    }
    fn catalog_member(&mut self, inventory: Inventory, ordinal: u64) -> Result<CatalogMember> {
        let id = CatalogId(inventory.id);
        self.read(
            MEMBERS,
            &CatalogMember::key(id, ordinal),
            records::CATALOG_MEMBER_BYTES,
            |bytes| {
                codec(CatalogMember::decode(
                    bytes.context("primary catalog member absent")?,
                    id,
                    inventory.scope,
                    ordinal,
                ))
            },
        )
    }
    fn catalog_mapping(&mut self, member: CatalogMember) -> Result<CatalogEntry> {
        self.read(
            CATALOG,
            &CatalogEntry::key(member.catalog, member.name_hash),
            records::CATALOG_ENTRY_BYTES,
            |bytes| {
                let entry = codec(CatalogEntry::decode(
                    bytes.context("primary catalog mapping absent")?,
                ))?;
                ensure!(
                    entry.catalog == member.catalog
                        && entry.scope == member.scope
                        && entry.name_hash == member.name_hash,
                    "primary catalog mapping context differs"
                );
                Ok(entry)
            },
        )
    }
    fn catalog_manifest(
        &mut self,
        catalog: ObjectId,
        attempt: Attempt,
        name_hash: [u8; 32],
        reference: ManifestRef,
    ) -> Result<Manifest> {
        ensure!(
            reference.id.attempt == attempt.id
                && reference.id.ordinal < attempt.next_object
                && reference.id != catalog,
            "primary catalog manifest ownership differs"
        );
        let inventory = self.read(
            INVENTORY,
            &object_key(reference.id),
            records::INVENTORY_BYTES,
            |bytes| {
                codec(Inventory::decode(
                    bytes.context("primary catalog manifest inventory absent")?,
                ))
            },
        )?;
        Self::require_complete_fixed(inventory)?;
        ensure!(
            inventory.kind == ResourceKind::CollectionManifest
                && inventory.id == reference.id
                && inventory.scope == self.scope
                && inventory.sha256 == reference.sha256
                && inventory.encoded_bytes == records::MANIFEST_BYTES as u64,
            "primary catalog manifest inventory differs"
        );
        self.read(
            MANIFESTS,
            &object_key(reference.id),
            records::MANIFEST_BYTES,
            |bytes| {
                let manifest = codec(Manifest::decode_referenced(
                    bytes.context("primary catalog manifest absent")?,
                    reference,
                ))?;
                ensure!(
                    manifest.scope == inventory.scope
                        && manifest.name_hash == name_hash
                        && manifest.tree_id == inventory.tree_id,
                    "primary catalog manifest context differs"
                );
                Ok(manifest)
            },
        )
    }
    fn begin_catalog(&mut self) -> Result<()> {
        self.require_catalog_mutable()?;
        ensure!(
            self.active_catalog
                .is_none_or(|state| state.phase == Phase::Complete),
            "primary catalog already active"
        );
        self.refresh()?;
        let mut attempt = self.catalog_attempt()?;
        let mut epoch = self.epoch.context("primary epoch absent")?;
        let id = ObjectId {
            attempt: attempt.id,
            ordinal: attempt.next_object,
        };
        let inventory = Inventory {
            kind: ResourceKind::Catalog,
            phase: InventoryPhase::Allocating,
            scope: self.scope,
            id,
            tree_id: [0; 16],
            encoded_bytes: 0,
            sha256: [0; 32],
            total_units: 0,
            completed_units: 0,
            cleanup_unit_cursor: 0,
            catalog_dense_count: 0,
        };
        attempt.next_object = attempt
            .next_object
            .checked_add(1)
            .context("primary object ordinal exhausted")?;
        attempt.live_resources = attempt
            .live_resources
            .checked_add(1)
            .context("primary attempt resource overflow")?;
        epoch.live_resources = epoch
            .live_resources
            .checked_add(1)
            .context("primary epoch resource overflow")?;
        let mut ib = [0; records::INVENTORY_BYTES];
        codec(inventory.encode(&mut ib))?;
        let mut ab = [0; records::ATTEMPT_BYTES];
        codec(attempt.encode(&mut ab))?;
        let mut eb = [0; records::EPOCH_BYTES];
        codec(epoch.encode(&mut eb))?;
        self.put(INVENTORY, &object_key(id), &ib)?;
        self.put(ATTEMPTS, &attempt.id, &ab)?;
        self.put(EPOCHS, &epoch.id, &eb)?;
        self.write()?;
        self.attempt = Some(attempt);
        self.epoch = Some(epoch);
        self.active_catalog = Some(CatalogBuildState {
            inventory,
            phase: Phase::Appending,
            cursor: 0,
            last: None,
            totals: Totals::default(),
            attempt: None,
        });
        Ok(())
    }
    fn append_catalog(&mut self, name: &str, reference: ManifestRef) -> Result<()> {
        let mut state = self.active_catalog.context("primary catalog absent")?;
        ensure!(
            state.phase == Phase::Appending,
            "primary catalog is not appending"
        );
        self.refresh()?;
        let attempt = self.catalog_attempt()?;
        let mut inventory = self.read_catalog_inventory(state.inventory)?;
        let k = inventory.total_units;
        let member = codec(CatalogMember::new(
            CatalogId(inventory.id),
            self.scope,
            k,
            name,
        ))?;
        if k > 0 {
            let previous = self.catalog_member(inventory, k - 1)?;
            ensure!(
                previous.name() < member.name(),
                "primary catalog names are not strictly ordered"
            );
        }
        self.read(
            MEMBERS,
            &CatalogMember::key(member.catalog, k),
            records::CATALOG_MEMBER_BYTES,
            |bytes| {
                ensure!(bytes.is_none(), "primary catalog member already exists");
                Ok(())
            },
        )?;
        self.read(
            CATALOG,
            &CatalogEntry::key(member.catalog, member.name_hash),
            records::CATALOG_ENTRY_BYTES,
            |bytes| {
                ensure!(bytes.is_none(), "primary catalog mapping already exists");
                Ok(())
            },
        )?;
        self.catalog_manifest(inventory.id, attempt, member.name_hash, reference)?;
        let entry = CatalogEntry {
            catalog: member.catalog,
            scope: self.scope,
            name_hash: member.name_hash,
            manifest: reference,
        };
        let next = k.checked_add(1).context("primary catalog count overflow")?;
        inventory.total_units = next;
        inventory.completed_units = next;
        inventory.catalog_dense_count = next;
        let mut cb = [0; records::CATALOG_ENTRY_BYTES];
        codec(entry.encode(&mut cb))?;
        let mut mb = [0; records::CATALOG_MEMBER_BYTES];
        codec(member.encode(&mut mb))?;
        let mut ib = [0; records::INVENTORY_BYTES];
        codec(inventory.encode(&mut ib))?;
        self.put(
            CATALOG,
            &CatalogEntry::key(member.catalog, member.name_hash),
            &cb,
        )?;
        self.put(MEMBERS, &CatalogMember::key(member.catalog, k), &mb)?;
        self.put(INVENTORY, &object_key(inventory.id), &ib)?;
        self.write()?;
        state.inventory = inventory;
        self.active_catalog = Some(state);
        Ok(())
    }
    fn finish_catalog_step(&mut self, max_members: usize) -> Result<Option<StagedCatalog>> {
        let mut state = self.active_catalog.context("primary catalog absent")?;
        ensure!(
            state.phase != Phase::Complete,
            "primary catalog already complete"
        );
        if max_members == 0 {
            return Ok(None);
        }
        if state.phase == Phase::Appending {
            self.refresh()?;
            let attempt = self.catalog_attempt()?;
            let inventory = self.read_catalog_inventory(state.inventory)?;
            // Bind actual same-pin records before any verifier progress escapes.
            state.inventory = inventory;
            state.attempt = Some(attempt);
            state.phase = Phase::Verifying;
            self.active_catalog = Some(state);
        }
        let inventory = state.inventory;
        for _ in 0..max_members {
            if state.cursor == inventory.total_units {
                break;
            }
            let member = self.catalog_member(inventory, state.cursor)?;
            ensure!(
                state.last.is_none_or(|last| last.name() < member.name()),
                "primary catalog names are not strictly ordered"
            );
            let mapping = self.catalog_mapping(member)?;
            let manifest = self.catalog_manifest(
                inventory.id,
                state.attempt.expect("bound attempt"),
                member.name_hash,
                mapping.manifest,
            )?;
            state.totals = codec(state.totals.add(manifest.totals))?;
            state.cursor = state
                .cursor
                .checked_add(1)
                .context("primary catalog cursor overflow")?;
            state.last = Some(member);
        }
        if state.cursor != inventory.total_units {
            self.active_catalog = Some(state);
            return Ok(None);
        }
        let complete = Inventory {
            phase: InventoryPhase::Complete,
            ..inventory
        };
        let mut ib = [0; records::INVENTORY_BYTES];
        codec(complete.encode(&mut ib))?;
        self.put(INVENTORY, &object_key(inventory.id), &ib)?;
        self.write()?;
        state.inventory = complete;
        state.phase = Phase::Complete;
        self.active_catalog = Some(state);
        Ok(Some(StagedCatalog {
            id: CatalogId(inventory.id),
            scope: self.scope,
            member_count: inventory.total_units,
            totals: state.totals,
        }))
    }
    pub(super) fn delete_catalog_member(&mut self, mut inventory: Inventory) -> Result<()> {
        Self::require_catalog_inventory(inventory)?;
        ensure!(
            inventory.cleanup_unit_cursor < inventory.completed_units,
            "primary catalog cleanup cursor exhausted"
        );
        let member = self.catalog_member(inventory, inventory.cleanup_unit_cursor)?;
        self.catalog_mapping(member)?; // Never chase independently owned manifests.
        inventory.cleanup_unit_cursor = inventory
            .cleanup_unit_cursor
            .checked_add(1)
            .context("primary catalog cleanup overflow")?;
        inventory.phase = InventoryPhase::Deleting;
        let mut ib = [0; records::INVENTORY_BYTES];
        codec(inventory.encode(&mut ib))?;
        self.delete(
            CATALOG,
            &CatalogEntry::key(member.catalog, member.name_hash),
        )?;
        self.delete(MEMBERS, &CatalogMember::key(member.catalog, member.ordinal))?;
        self.put(INVENTORY, &object_key(inventory.id), &ib)?;
        self.write()
    }
}
