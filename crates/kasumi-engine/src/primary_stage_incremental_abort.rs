//! Current-epoch pending branch cleanup. It never follows retire targets or
//! erases a committed attempt. Every durable step is a separate <=4-op batch.
use super::*;
use records::Retire;

impl<'guard, 'engine> PrimaryStage<'guard, 'engine> {
    pub(crate) fn resume_incremental_abort(
        authority: &'guard mut PrimaryApplyGuard<'engine>,
    ) -> Result<Option<Self>> {
        let (stage, pending) =
            Self::allocate(authority)?.perform(PrimaryResources::load_incremental_abort)?;
        if pending {
            Ok(Some(stage))
        } else {
            stage.close()?;
            Ok(None)
        }
    }
    pub(crate) fn incremental_abort_step(self, units: usize) -> Result<(Self, bool)> {
        self.perform(|r| r.incremental_abort_step(units.min(64)))
    }
}
impl PrimaryResources {
    pub(super) fn read_epoch(&mut self, id: [u8; 16]) -> Result<Epoch> {
        self.read(EPOCHS, &id, records::EPOCH_BYTES, |bytes| {
            codec(Epoch::decode(bytes.context("primary epoch absent")?))
        })
    }
    pub(super) fn read_attempt(&mut self, id: [u8; 16]) -> Result<Attempt> {
        self.read(ATTEMPTS, &id, records::ATTEMPT_BYTES, |bytes| {
            codec(Attempt::decode(bytes.context("primary attempt absent")?))
        })
    }
    pub(super) fn read_inventory(&mut self, id: ObjectId) -> Result<Inventory> {
        self.read(
            INVENTORY,
            &object_key(id),
            records::INVENTORY_BYTES,
            |bytes| {
                codec(Inventory::decode(
                    bytes.context("primary inventory absent")?,
                ))
            },
        )
    }
    fn load_incremental_abort(&mut self) -> Result<bool> {
        self.refresh()?;
        let gc = self.read(META, b"gc", records::GC_BYTES, |bytes| {
            codec(GcState::decode(bytes.context("primary GC absent")?))
        })?;
        let selected = self.read(META, b"selected", records::SELECTOR_BYTES, |bytes| {
            codec(Selector::decode(bytes.context("primary selector absent")?))
        })?;
        ensure!(
            selected.bootstrap_sha256 == self.bootstrap,
            "primary incremental bootstrap differs"
        );
        ensure!(
            selected.scope == self.scope
                && gc.current == Some(selected.projection_epoch)
                && gc.building.is_none()
                && gc.retired.is_none(),
            "primary incremental GC/selector differs"
        );
        let epoch = self.read_epoch(selected.projection_epoch)?;
        ensure!(
            epoch.scope == self.scope && epoch.id == selected.projection_epoch,
            "primary incremental epoch identity differs"
        );
        let Some(id) = epoch.pending else {
            self.gc = Some(gc);
            self.epoch = Some(epoch);
            self.attempt = None;
            return Ok(false);
        };
        let pending = self.read_attempt(id)?;
        let tail_id = epoch.tail.context("primary committed tail absent")?;
        let tail = self.read_attempt(tail_id)?;
        ensure!(
            epoch.head.is_some()
                && tail_id != id
                && pending.previous == Some(tail_id)
                && pending.next.is_none()
                && pending.id == id
                && pending.epoch == epoch.id
                && pending.scope == self.scope
                && pending.retire_cursor == 0
                && tail.id == tail_id
                && tail.epoch == epoch.id
                && tail.scope == self.scope
                && tail.phase == AttemptPhase::Committed
                && tail.next.is_none()
                && selected.activation_attempt == tail_id,
            "primary incremental pending branch differs"
        );
        ensure!(
            matches!(
                pending.phase,
                AttemptPhase::Building | AttemptPhase::Prepared | AttemptPhase::Aborting
            ),
            "primary incremental outcome is not positively uncommitted"
        );
        ensure!(
            pending.live_resources <= epoch.live_resources
                && (pending.journal_erase_cursor == 0
                    || (pending.live_resources == 0
                        && pending.abort_object_cursor == pending.next_object
                        && pending.journal_erase_cursor >= pending.next_object)),
            "primary incremental resource/cursor differs"
        );
        self.gc = Some(gc);
        self.epoch = Some(epoch);
        self.attempt = Some(pending);
        Ok(true)
    }
    fn incremental_abort_step(&mut self, units: usize) -> Result<bool> {
        // Loading observes only; zero allowance never changes phase or settles.
        if !self.load_incremental_abort()? {
            return Ok(true);
        }
        if units == 0 {
            return Ok(false);
        }
        for _ in 0..units {
            // Current progress is obtained from the actual post-step pin.
            if !self.load_incremental_abort()? {
                return Ok(true);
            }
            let mut attempt = self.attempt.context("pending incremental attempt absent")?;
            let mut epoch = self.epoch.context("pending incremental epoch absent")?;
            if attempt.phase != AttemptPhase::Aborting {
                attempt.phase = AttemptPhase::Aborting;
                let mut bytes = [0; records::ATTEMPT_BYTES];
                codec(attempt.encode(&mut bytes))?;
                self.put(ATTEMPTS, &attempt.id, &bytes)?;
                self.write()?;
                continue;
            }
            if attempt.abort_object_cursor < attempt.next_object {
                let id = ObjectId {
                    attempt: attempt.id,
                    ordinal: attempt.abort_object_cursor,
                };
                let mut inventory = self.read_inventory(id)?;
                ensure!(
                    inventory.id == id
                        && inventory.scope == self.scope
                        && matches!(
                            inventory.kind,
                            ResourceKind::Live
                                | ResourceKind::Page
                                | ResourceKind::CollectionManifest
                        )
                        && attempt.live_resources > 0
                        && epoch.live_resources > 0,
                    "primary incremental abort inventory differs"
                );
                let fixed = matches!(
                    inventory.kind,
                    ResourceKind::Page | ResourceKind::CollectionManifest
                );
                if fixed {
                    Self::require_complete_fixed(inventory)?;
                }
                if inventory.cleanup_unit_cursor < inventory.completed_units {
                    if fixed {
                        self.delete_fixed(inventory)?;
                    } else {
                        let ordinal = inventory.cleanup_unit_cursor;
                        let key = chunk::key(id, ordinal);
                        let scope = self.scope;
                        self.read(CHUNKS, &key, chunk::BYTES, |bytes| {
                            chunk::parse(
                                bytes.context("incremental abort chunk absent")?,
                                scope,
                                inventory.tree_id,
                                OverflowRef {
                                    id,
                                    encoded_bytes: inventory.encoded_bytes,
                                    sha256: inventory.sha256,
                                },
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
                        .context("primary incremental cleanup overflow")?;
                    inventory.phase = InventoryPhase::Deleting;
                }
                if inventory.cleanup_unit_cursor == inventory.completed_units {
                    attempt.live_resources = attempt
                        .live_resources
                        .checked_sub(1)
                        .context("attempt underflow")?;
                    epoch.live_resources = epoch
                        .live_resources
                        .checked_sub(1)
                        .context("epoch underflow")?;
                    attempt.abort_object_cursor = attempt
                        .abort_object_cursor
                        .checked_add(1)
                        .context("abort cursor overflow")?;
                    let mut ab = [0; records::ATTEMPT_BYTES];
                    codec(attempt.encode(&mut ab))?;
                    let mut eb = [0; records::EPOCH_BYTES];
                    codec(epoch.encode(&mut eb))?;
                    self.delete(INVENTORY, &object_key(id))?;
                    self.put(ATTEMPTS, &attempt.id, &ab)?;
                    self.put(EPOCHS, &epoch.id, &eb)?;
                } else {
                    let mut ib = [0; records::INVENTORY_BYTES];
                    codec(inventory.encode(&mut ib))?;
                    self.put(INVENTORY, &object_key(id), &ib)?;
                }
                self.write()?;
                continue;
            }
            ensure!(
                attempt.live_resources == 0,
                "incremental erased objects remain live"
            );
            if attempt.journal_erase_cursor < attempt.next_object {
                ensure!(
                    attempt.journal_erase_cursor == 0,
                    "incremental journal cursor differs"
                );
                attempt.journal_erase_cursor = attempt.next_object;
                let mut ab = [0; records::ATTEMPT_BYTES];
                codec(attempt.encode(&mut ab))?;
                self.put(ATTEMPTS, &attempt.id, &ab)?;
                self.write()?;
                continue;
            }
            let end = attempt
                .next_object
                .checked_add(attempt.retire_count)
                .context("journal end overflow")?;
            if attempt.journal_erase_cursor < end {
                let ordinal = attempt.journal_erase_cursor - attempt.next_object;
                let key = object_key(ObjectId {
                    attempt: attempt.id,
                    ordinal,
                });
                self.read(RETIRES, &key, records::RETIRE_BYTES, |bytes| {
                    codec(Retire::decode(
                        bytes.context("incremental retire intention absent")?,
                    ))?;
                    Ok(())
                })?;
                attempt.journal_erase_cursor = attempt
                    .journal_erase_cursor
                    .checked_add(1)
                    .context("erase overflow")?;
                let mut ab = [0; records::ATTEMPT_BYTES];
                codec(attempt.encode(&mut ab))?;
                self.delete(RETIRES, &key)?;
                self.put(ATTEMPTS, &attempt.id, &ab)?;
                self.write()?;
                continue;
            }
            ensure!(
                attempt.journal_erase_cursor == end,
                "incremental journal end differs"
            );
            epoch.pending = None;
            let mut eb = [0; records::EPOCH_BYTES];
            codec(epoch.encode(&mut eb))?;
            self.put(EPOCHS, &epoch.id, &eb)?;
            self.delete(ATTEMPTS, &attempt.id)?;
            self.write()?;
            self.epoch = Some(epoch);
            self.attempt = None;
            return Ok(true);
        }
        Ok(false)
    }
}
