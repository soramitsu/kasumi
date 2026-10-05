//! Positive, uncommitted fresh-epoch cleanup only. Committed retirement and
//! catalog cleanup require the later real activation/editor integration.
use super::*;
impl<'guard, 'engine> PrimaryStage<'guard, 'engine> {
    pub(crate) fn resume_abort(
        authority: &'guard mut PrimaryApplyGuard<'engine>,
    ) -> Result<Option<Self>> {
        let (stage, pending) =
            Self::allocate(authority)?.perform(|resources| resources.load_uncommitted())?;
        if pending {
            Ok(Some(stage))
        } else {
            stage.close()?;
            Ok(None)
        }
    }
    /// Each unit performs at most one four-op transaction. The call cap bounds
    /// internal work, not accepted DTO/document size. Cancellation between calls
    /// leaves the exact durable progress cursor for a new installed owner.
    pub(crate) fn abort_step(self, units: usize) -> Result<(Self, bool)> {
        self.perform(|resources| resources.abort_step(units.min(64)))
    }
}
impl PrimaryResources {
    fn load_uncommitted(&mut self) -> Result<bool> {
        self.refresh()?;
        let gc = self
            .read(META, b"gc", records::GC_BYTES, |bytes| {
                bytes.map(|bytes| codec(GcState::decode(bytes))).transpose()
            })?
            .unwrap_or(GcState {
                current: None,
                building: None,
                retired: None,
            });
        let selector = self.read(META, b"selected", records::SELECTOR_BYTES, |bytes| {
            bytes
                .map(|bytes| codec(Selector::decode(bytes)))
                .transpose()
        })?;
        match selector {
            Some(selector) => ensure!(
                selector.scope == self.scope && gc.current == Some(selector.projection_epoch),
                "primary selected/current epoch differs"
            ),
            None => ensure!(
                gc.current.is_none(),
                "primary current epoch has no selector"
            ),
        }
        let Some(id) = gc.building else {
            self.gc = Some(gc);
            self.epoch = None;
            self.attempt = None;
            return Ok(false);
        };
        let epoch = self.read(EPOCHS, &id, records::EPOCH_BYTES, |bytes| {
            codec(Epoch::decode(
                bytes.context("primary building epoch absent")?,
            ))
        })?;
        ensure!(
            epoch.scope == self.scope && epoch.id == id,
            "primary building epoch identity differs"
        );
        let attempt_id = epoch
            .pending
            .context("primary building epoch pending attempt absent")?;
        ensure!(
            epoch.head == Some(attempt_id) && epoch.tail == Some(attempt_id),
            "primary building epoch is not this fresh-attempt shape"
        );
        let attempt = self.read(ATTEMPTS, &attempt_id, records::ATTEMPT_BYTES, |bytes| {
            codec(Attempt::decode(
                bytes.context("primary pending attempt absent")?,
            ))
        })?;
        ensure!(
            attempt.scope == self.scope && attempt.id == attempt_id && attempt.epoch == id,
            "primary pending attempt identity differs"
        );
        ensure!(
            attempt.previous.is_none()
                && attempt.next.is_none()
                && attempt.retire_count == 0
                && attempt.retire_cursor == 0
                && attempt.journal_erase_cursor == 0,
            "primary attempt needs general journal cleanup"
        );
        ensure!(
            matches!(
                attempt.phase,
                AttemptPhase::Building | AttemptPhase::Prepared | AttemptPhase::Aborting
            ),
            "primary attempt outcome is not positively uncommitted"
        );
        ensure!(
            selector.is_none_or(|selector| selector.activation_attempt != attempt_id
                && selector.projection_epoch != id),
            "primary selected attempt cannot abort"
        );
        ensure!(
            attempt.live_resources == epoch.live_resources,
            "primary fresh epoch resource counts differ"
        );
        self.gc = Some(gc);
        self.epoch = Some(epoch);
        self.attempt = Some(attempt);
        Ok(true)
    }
    fn abort_step(&mut self, units: usize) -> Result<bool> {
        if !self.load_uncommitted()? {
            return Ok(true);
        }
        if units == 0 {
            return Ok(false);
        }
        let mut attempt = self.attempt.expect("loaded attempt");
        let mut epoch = self.epoch.expect("loaded epoch");
        let mut left = units;
        if attempt.phase != AttemptPhase::Aborting {
            attempt.phase = AttemptPhase::Aborting;
            let mut bytes = [0; records::ATTEMPT_BYTES];
            codec(attempt.encode(&mut bytes))?;
            self.put(ATTEMPTS, &attempt.id, &bytes)?;
            self.write()?;
            self.attempt = Some(attempt);
            // Consume one bounded operation unit for the durable state change.
            left -= 1;
            if left == 0 {
                return Ok(false);
            }
        }
        // This pin predates only our serialized progress writes. Future object
        // inventories/chunks have not changed; each touched descriptor's new
        // state is retained locally until the next fresh step acquires a pin.
        while left > 0 && attempt.abort_object_cursor < attempt.next_object {
            left -= 1;
            let id = ObjectId {
                attempt: attempt.id,
                ordinal: attempt.abort_object_cursor,
            };
            let mut inventory = self.read(
                INVENTORY,
                &object_key(id),
                records::INVENTORY_BYTES,
                |bytes| {
                    codec(Inventory::decode(
                        bytes.context("primary live abort inventory absent")?,
                    ))
                },
            )?;
            ensure!(
                inventory.scope == self.scope && inventory.id == id,
                "primary abort inventory identity differs"
            );
            ensure!(
                matches!(
                    inventory.kind,
                    ResourceKind::Live
                        | ResourceKind::Archived
                        | ResourceKind::Definition
                        | ResourceKind::Page
                        | ResourceKind::CollectionManifest
                        | ResourceKind::Catalog
                ),
                "primary resource needs general cleanup"
            );
            ensure!(
                attempt.live_resources > 0 && epoch.live_resources > 0,
                "primary abort resource count underflow"
            );
            if inventory.kind == ResourceKind::Catalog {
                Self::require_catalog_inventory(inventory)?;
                if inventory.cleanup_unit_cursor < inventory.completed_units {
                    self.delete_catalog_member(inventory)?;
                    self.refresh()?;
                    // Even the last member uses its own three-op transaction.
                    // Inventory/counter retirement needs a separate work unit.
                    continue;
                }
            }
            let fixed = matches!(
                inventory.kind,
                ResourceKind::Page | ResourceKind::CollectionManifest
            );
            if fixed {
                // Validate before the generic completed-units shortcut: fixed
                // objects never persist an intermediate inventory phase/cursor.
                Self::require_complete_fixed(inventory)?;
            }
            let reference = OverflowRef {
                id,
                encoded_bytes: inventory.encoded_bytes,
                sha256: inventory.sha256,
            };
            if inventory.cleanup_unit_cursor < inventory.completed_units {
                if fixed {
                    self.delete_fixed(inventory)?;
                } else {
                    let ordinal = inventory.cleanup_unit_cursor;
                    let key = chunk::key(id, ordinal);
                    let scope = self.scope;
                    self.read(CHUNKS, &key, chunk::BYTES, |bytes| {
                        chunk::parse(
                            bytes.context("primary live abort chunk absent")?,
                            scope,
                            inventory.tree_id,
                            reference,
                            inventory.kind,
                            ordinal,
                        )?;
                        Ok(())
                    })?;
                    self.delete(CHUNKS, &key)?;
                }
                inventory.cleanup_unit_cursor = inventory
                    .cleanup_unit_cursor
                    .checked_add(1)
                    .context("primary abort cursor overflow")?;
                inventory.phase = InventoryPhase::Deleting;
            }
            if inventory.cleanup_unit_cursor == inventory.completed_units {
                attempt.live_resources = attempt
                    .live_resources
                    .checked_sub(1)
                    .context("primary attempt resource underflow")?;
                epoch.live_resources = epoch
                    .live_resources
                    .checked_sub(1)
                    .context("primary epoch resource underflow")?;
                attempt.abort_object_cursor = attempt
                    .abort_object_cursor
                    .checked_add(1)
                    .context("primary abort object cursor overflow")?;
                let mut ab = [0; records::ATTEMPT_BYTES];
                codec(attempt.encode(&mut ab))?;
                let mut eb = [0; records::EPOCH_BYTES];
                codec(epoch.encode(&mut eb))?;
                self.delete(INVENTORY, &object_key(id))?;
                self.put(ATTEMPTS, &attempt.id, &ab)?;
                self.put(EPOCHS, &epoch.id, &eb)?;
                self.write()?;
                self.attempt = Some(attempt);
                self.epoch = Some(epoch);
            } else {
                let mut ib = [0; records::INVENTORY_BYTES];
                codec(inventory.encode(&mut ib))?;
                self.put(INVENTORY, &object_key(id), &ib)?;
                self.write()?;
                // Re-reading this same resource through the prior pin would
                // repeat a deleted chunk. Refresh before consuming another unit.
                self.refresh()?;
            }
        }
        if attempt.abort_object_cursor != attempt.next_object || left == 0 {
            return Ok(false);
        }
        ensure!(
            attempt.live_resources == 0 && epoch.live_resources == 0,
            "primary exhausted inventory has live resources"
        );
        let mut gc = self.gc.expect("loaded gc");
        ensure!(
            gc.building == Some(epoch.id),
            "primary building epoch changed"
        );
        gc.building = None;
        let mut gb = [0; records::GC_BYTES];
        codec(gc.encode(&mut gb))?;
        // No retire rows exist in this fresh attempt. Each inventory descriptor
        // was erased with its resource and enclosing abort cursor. Three fixed
        // deletions/updates therefore complete the proven-empty linkage.
        self.delete(ATTEMPTS, &attempt.id)?;
        self.delete(EPOCHS, &epoch.id)?;
        self.put(META, b"gc", &gb)?;
        self.write()?;
        self.gc = Some(gc);
        self.epoch = None;
        self.attempt = None;
        Ok(true)
    }
}
