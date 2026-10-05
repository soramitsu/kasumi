//! One concrete prospective allocation recipe for Engine batch_changes only.
//! Keep this model aligned with the pinned std B=6 BTree implementation and the
//! real Engine producer. It accounts duplicate String temporaries too; no
//! serialized-byte multiplier, arbitrary caller byte allowance or new grant.
use super::{InputBindingError, allocation};
use kasumi_types::{Mutation, MutationBatch};
use sha2::{Digest, Sha256};
use std::{
    alloc::Layout,
    collections::BTreeSet,
    io,
    mem::size_of,
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct MutationChangeTreeRecipe {
    bytes: u64,
    targets: usize,
    transcript: [u8; 32],
}
fn add(left: u64, right: u64) -> io::Result<u64> {
    left.checked_add(right)
        .ok_or_else(|| io::ErrorKind::InvalidInput.into())
}
fn tree_node<K, V>() -> io::Result<u64> {
    // Same conservative model used by the concrete topology/query producers:
    // 11 keys/values, 12 edges plus four pointer widths for header/alignment.
    // One complete INTERNAL node per target bounds every nonempty allocated
    // node; String buffers are quoted independently. These concrete K/V are
    // pointer-aligned String and BTreeSet<String>, not arbitrary user codecs.
    let bytes = size_of::<K>()
        .checked_add(size_of::<V>())
        .and_then(|size| size.checked_mul(11))
        .and_then(|size| size.checked_add(16 * size_of::<usize>()))
        .ok_or(io::ErrorKind::InvalidInput)?;
    allocation(
        Layout::from_size_align(
            bytes,
            std::mem::align_of::<K>().max(std::mem::align_of::<V>()),
        )
        .map_err(|_| io::ErrorKind::InvalidInput)?,
    )
}
impl MutationChangeTreeRecipe {
    pub(super) fn prepare(batch: &MutationBatch) -> io::Result<Self> {
        let mut digest = Sha256::new();
        digest.update(b"kasumi mutation target-tree v1\0");
        digest.update(
            u64::try_from(batch.operations.len())
                .map_err(|_| io::ErrorKind::InvalidInput)?
                .to_le_bytes(),
        );
        let nodes = add(
            tree_node::<String, BTreeSet<String>>()?,
            tree_node::<String, ()>()?,
        )?;
        let mut bytes = 0;
        for mutation in &batch.operations {
            // Explicit variants force a recipe review for any new target mode.
            // Bodies/expected versions are covered by the invocation's unchanged
            // whole encoded bytes; this recipe pays only target-tree production.
            let mode = match mutation {
                Mutation::Put { .. } => 0u8,
                Mutation::Patch { .. } => 1,
                Mutation::Delete { .. } => 2,
            };
            digest.update([mode]);
            let (collection, id) = mutation.target();
            for target in [collection, id] {
                digest.update(
                    u64::try_from(target.len())
                        .map_err(|_| io::ErrorKind::InvalidInput)?
                        .to_le_bytes(),
                );
                digest.update(target.as_bytes());
                bytes = add(
                    bytes,
                    allocation(
                        Layout::array::<u8>(target.len())
                            .map_err(|_| io::ErrorKind::InvalidInput)?,
                    )?,
                )?;
            }
            // The existing builder constructs a collection String on EVERY
            // entry call and an ID String on EVERY insert, including duplicates.
            bytes = add(bytes, nodes)?;
        }
        Ok(Self {
            bytes,
            targets: batch.operations.len(),
            transcript: digest.finalize().into(),
        })
    }
    pub(super) fn request_bytes(self) -> u64 {
        self.bytes
    }
}

pub(super) struct MutationChangeTreeState {
    recipe: MutationChangeTreeRecipe,
    claimed: AtomicBool,
}
impl MutationChangeTreeState {
    pub(super) fn new(recipe: MutationChangeTreeRecipe) -> Self {
        Self {
            recipe,
            claimed: AtomicBool::new(false),
        }
    }
    pub(super) fn claim(&self, batch: &MutationBatch) -> Result<(), InputBindingError> {
        let recipe = MutationChangeTreeRecipe::prepare(batch)
            .map_err(|_| InputBindingError::Insufficient)?;
        if recipe != self.recipe {
            return Err(InputBindingError::Foreign);
        }
        self.claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| InputBindingError::Repeated)
    }
}
