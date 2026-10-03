//! Fixed unselected objects use one four-operation transaction with their exact
//! inventory and enclosing counters. This establishes physical custody only;
//! the later projection producer must prove reference and semantic closure.
use super::*;
use crate::primary_tree::{
    EncodedPage, Entry, ExpectedPage, KeyRange, PAGE_BYTES, PageRef, PageSpec, Totals,
};
use records::{Manifest, ManifestRef};

impl PrimaryStage<'_, '_> {
    pub(crate) fn stage_page(
        self,
        tree: [u8; 16],
        generation: u64,
        level: u8,
        entries: &[Entry<'_>],
    ) -> Result<(Self, EncodedPage)> {
        self.perform(|resources| resources.stage_page(tree, generation, level, entries))
    }

    pub(crate) fn stage_manifest(self, manifest: Manifest) -> Result<(Self, ManifestRef)> {
        self.perform(|resources| resources.stage_manifest(manifest))
    }
}

impl PrimaryResources {
    fn next_fixed_id(&self) -> Result<ObjectId> {
        self.require_catalog_mutable()?;
        let attempt = self.attempt.context("primary attempt absent")?;
        ensure!(
            attempt.phase == AttemptPhase::Building,
            "primary attempt does not accept objects"
        );
        Ok(ObjectId {
            attempt: attempt.id,
            ordinal: attempt.next_object,
        })
    }

    pub(super) fn stage_page(
        &mut self,
        tree: [u8; 16],
        generation: u64,
        level: u8,
        entries: &[Entry<'_>],
    ) -> Result<EncodedPage> {
        let id = self.next_fixed_id()?;
        // Reuse the existing admitted chunk allocation, including its capacity.
        // Entry names and descriptors are borrowed from the admitted caller.
        self.chunk.resize(PAGE_BYTES, 0);
        let page = codec(crate::primary_tree::encode(
            self.chunk
                .as_mut_slice()
                .try_into()
                .expect("fixed page length"),
            PageSpec {
                tree_id: tree,
                id,
                generation,
                level,
            },
            entries,
        ))?;
        let inventory = self.fixed_inventory(
            id,
            tree,
            ResourceKind::Page,
            PAGE_BYTES as u64,
            page.reference.sha256,
        );
        self.put_buffer(PAGES, &object_key(id))?;
        self.commit_fixed(inventory)?;
        Ok(page)
    }

    pub(super) fn stage_manifest(&mut self, manifest: Manifest) -> Result<ManifestRef> {
        ensure!(
            manifest.scope == self.scope,
            "primary manifest scope differs"
        );
        let id = self.next_fixed_id()?;
        let mut bytes = [0; records::MANIFEST_BYTES];
        codec(manifest.encode(&mut bytes))?;
        let reference = ManifestRef {
            id,
            sha256: Sha256::digest(bytes).into(),
        };
        let inventory = self.fixed_inventory(
            id,
            manifest.tree_id,
            ResourceKind::CollectionManifest,
            records::MANIFEST_BYTES as u64,
            reference.sha256,
        );
        self.put(MANIFESTS, &object_key(id), &bytes)?;
        self.commit_fixed(inventory)?;
        Ok(reference)
    }

    fn fixed_inventory(
        &self,
        id: ObjectId,
        tree_id: [u8; 16],
        kind: ResourceKind,
        encoded_bytes: u64,
        sha256: [u8; 32],
    ) -> Inventory {
        Inventory {
            kind,
            phase: InventoryPhase::Complete,
            scope: self.scope,
            id,
            tree_id,
            encoded_bytes,
            sha256,
            total_units: 1,
            completed_units: 1,
            cleanup_unit_cursor: 0,
            catalog_dense_count: 0,
        }
    }

    fn commit_fixed(&mut self, inventory: Inventory) -> Result<()> {
        let mut attempt = self.attempt.context("primary attempt absent")?;
        let mut epoch = self.epoch.context("primary epoch absent")?;
        ensure!(
            inventory.id == self.next_fixed_id()?,
            "primary object ordinal differs"
        );
        attempt.next_object = attempt
            .next_object
            .checked_add(1)
            .context("primary object ordinal exhausted")?;
        attempt.live_resources = attempt
            .live_resources
            .checked_add(1)
            .context("primary attempt resources overflow")?;
        epoch.live_resources = epoch
            .live_resources
            .checked_add(1)
            .context("primary epoch resources overflow")?;
        let mut ib = [0; records::INVENTORY_BYTES];
        codec(inventory.encode(&mut ib))?;
        let mut ab = [0; records::ATTEMPT_BYTES];
        codec(attempt.encode(&mut ab))?;
        let mut eb = [0; records::EPOCH_BYTES];
        codec(epoch.encode(&mut eb))?;
        self.put(INVENTORY, &object_key(inventory.id), &ib)?;
        self.put(ATTEMPTS, &attempt.id, &ab)?;
        self.put(EPOCHS, &epoch.id, &eb)?;
        self.write()?;
        self.attempt = Some(attempt);
        self.epoch = Some(epoch);
        Ok(())
    }

    pub(super) fn require_complete_fixed(inventory: Inventory) -> Result<()> {
        // Fixed publication and deletion each commit the object and inventory in
        // one transaction. No partial allocation/deletion state can be durable.
        ensure!(
            inventory.phase == InventoryPhase::Complete
                && inventory.total_units == 1
                && inventory.completed_units == 1
                && inventory.cleanup_unit_cursor == 0,
            "primary fixed inventory progress differs"
        );
        Ok(())
    }

    pub(super) fn delete_fixed(&mut self, inventory: Inventory) -> Result<()> {
        let namespace = match inventory.kind {
            ResourceKind::Page => PAGES,
            ResourceKind::CollectionManifest => MANIFESTS,
            _ => anyhow::bail!("primary resource is not fixed"),
        };
        Self::require_complete_fixed(inventory)?;
        self.read(
            namespace,
            &object_key(inventory.id),
            inventory.encoded_bytes as usize,
            |bytes| {
                let bytes = bytes.context("primary fixed abort object absent")?;
                ensure!(
                    bytes.len() as u64 == inventory.encoded_bytes
                        && <[u8; 32]>::from(Sha256::digest(bytes)) == inventory.sha256,
                    "primary fixed abort object digest differs"
                );
                // Authenticate and validate local framing before erasing the
                // inventory. This does not establish external reference closure.
                match inventory.kind {
                    ResourceKind::Page => {
                        ensure!(
                            bytes.len() == PAGE_BYTES,
                            "primary abort page length differs"
                        );
                        // Inventory binds tree, object ID and digest. Header-derived
                        // level/generation/totals ask the codec to check the page's
                        // internal shape without asserting any parent contract.
                        codec(crate::primary_tree::validate(
                            bytes,
                            ExpectedPage {
                                tree_id: inventory.tree_id,
                                reference: PageRef {
                                    id: inventory.id,
                                    sha256: inventory.sha256,
                                },
                                generation_ceiling: u64_at(bytes, 36),
                                level: bytes[19],
                                totals: Totals::read(&bytes[72..104]),
                                range: KeyRange::default(),
                            },
                        ))?;
                    }
                    ResourceKind::CollectionManifest => {
                        let manifest = codec(Manifest::decode(bytes))?;
                        ensure!(
                            manifest.scope == inventory.scope
                                && manifest.tree_id == inventory.tree_id,
                            "primary abort manifest identity differs"
                        );
                    }
                    _ => unreachable!("checked fixed kind"),
                }
                Ok(())
            },
        )?;
        self.delete(namespace, &object_key(inventory.id))
    }
}
