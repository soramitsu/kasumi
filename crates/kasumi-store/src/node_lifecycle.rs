//! Fixed lifetime gate inside the original registered database allocation.
//!
//! Preparing blocks census disposal even before there is a public node facade.
//! A promoted node requires the original explicit shutdown path to observe its
//! actual task/native outcomes; facade counts and absent handles are not proof.
use std::sync::atomic::{AtomicU8, Ordering};

const PREPARING: u8 = 0;
const FAILED: u8 = 1;
const LIVE: u8 = 2;
const JOINING: u8 = 3;
const JOINED: u8 = 4;
const NOT_ENTERED: u8 = 0;
const ENTERED: u8 = 1;
const RETURNED: u8 = 2;

#[derive(Clone, Copy)]
pub(crate) enum NodeResource {
    Cache,
    Initializers,
    Native,
}

pub(crate) struct NodeLifecycle {
    state: AtomicU8,
    cache: AtomicU8,
    initializers: AtomicU8,
    native: AtomicU8,
}

impl NodeLifecycle {
    pub(crate) const fn preparing() -> Self {
        Self {
            state: AtomicU8::new(PREPARING),
            cache: AtomicU8::new(NOT_ENTERED),
            initializers: AtomicU8::new(NOT_ENTERED),
            native: AtomicU8::new(NOT_ENTERED),
        }
    }

    /// Only the synchronous original startup, after it recorded failure.
    pub(crate) fn failed_startup(&self) {
        assert_eq!(
            self.state
                .compare_exchange(PREPARING, FAILED, Ordering::AcqRel, Ordering::Acquire,),
            Ok(PREPARING)
        );
    }

    /// Only the original Ready handoff, before returning the first facade.
    pub(crate) fn promote(&self) {
        assert_eq!(
            self.state
                .compare_exchange(PREPARING, LIVE, Ordering::AcqRel, Ordering::Acquire,),
            Ok(PREPARING)
        );
    }

    pub(crate) fn begin_shutdown(&self) {
        // The original AsyncMutex shutdown gate serializes callers. Retrying an
        // interrupted join keeps the existing state; it never reconstructs jobs.
        match self
            .state
            .compare_exchange(LIVE, JOINING, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(LIVE) | Err(JOINING) | Err(JOINED) => {}
            other => panic!("node shutdown has no Ready origin: {other:?}"),
        }
    }

    fn resource(&self, resource: NodeResource) -> &AtomicU8 {
        match resource {
            NodeResource::Cache => &self.cache,
            NodeResource::Initializers => &self.initializers,
            NodeResource::Native => &self.native,
        }
    }

    /// The original shutdown mutex serializes these transitions. Entered stays
    /// sticky if its original await, report callback or disposal is interrupted.
    pub(crate) fn enter_resource(&self, resource: NodeResource) {
        match self.resource(resource).compare_exchange(
            NOT_ENTERED,
            ENTERED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(NOT_ENTERED) | Err(ENTERED) | Err(RETURNED) => {}
            other => panic!("unknown original node resource observation: {other:?}"),
        }
    }

    /// Called only at the trusted return boundary of the same original resource.
    /// A Retained drain, an absent handle, a missing locator or an unknown native
    /// disposal never enters this branch. The original error stays in its report.
    pub(crate) fn resource_returned(&self, resource: NodeResource) {
        match self.resource(resource).compare_exchange(
            ENTERED,
            RETURNED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(ENTERED) | Err(RETURNED) => {}
            other => panic!("node resource returned without its original entry: {other:?}"),
        }
    }

    pub(crate) fn finish_shutdown(&self) -> bool {
        if [
            NodeResource::Cache,
            NodeResource::Initializers,
            NodeResource::Native,
        ]
        .into_iter()
        .any(|resource| self.resource(resource).load(Ordering::Acquire) != RETURNED)
        {
            return false;
        }
        matches!(
            self.state
                .compare_exchange(JOINING, JOINED, Ordering::AcqRel, Ordering::Acquire),
            Ok(JOINING) | Err(JOINED)
        )
    }

    pub(crate) fn has_ready_origin(&self) -> bool {
        matches!(self.state.load(Ordering::Acquire), LIVE | JOINING | JOINED)
    }

    pub(crate) fn permits_drive(&self) -> bool {
        matches!(self.state.load(Ordering::Acquire), FAILED | JOINED)
    }
}
