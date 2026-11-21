//! A target may return a signed challenge only while the original Control
//! administrator is waiting for that particular physical writer.
use kasumi_engine::{Database, ResponseFence, TargetSigner};
use kasumi_types::{
    Action, Error, ErrorCode, LifecycleNode, RefreshTargetWriter, RequestContext, Result,
    SignedTargetWriterChallenge,
};
use std::{
    collections::{BTreeMap, btree_map::Entry},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};
use uuid::Uuid;

#[derive(Default)]
pub(crate) struct WriterCallbacks(Mutex<BTreeMap<Uuid, Arc<WriterCallback>>>);
pub(crate) struct WriterCallback {
    refresh: RefreshTargetWriter,
    node: LifecycleNode,
    original: RequestContext,
    fence: ResponseFence<'static>,
    active: AtomicBool,
    challenge: OnceLock<String>,
}
pub(crate) struct OpenCallback<'a> {
    owner: &'a WriterCallbacks,
    callback: Arc<WriterCallback>,
}
impl Drop for OpenCallback<'_> {
    fn drop(&mut self) {
        self.callback.active.store(false, Ordering::Release);
        self.owner
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.callback.refresh.nonce);
    }
}
impl WriterCallbacks {
    pub(crate) fn open<'a>(
        &'a self,
        refresh: &RefreshTargetWriter,
        node: &LifecycleNode,
        original: &RequestContext,
        database: &Arc<Database>,
    ) -> Result<OpenCallback<'a>> {
        let mut fence = database.admitted_response_fence(original)?;
        // One enrolled node, its request, a second context and the map/Arc
        // backing survive if an in-flight callback outlasts its dispatch.
        fence.retain_response_bytes(8192)?;
        let mut active = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if active.len() >= 64 {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "concurrent writer refresh bound",
            ));
        }
        let Entry::Vacant(slot) = active.entry(refresh.nonce) else {
            return Err(Error::new(
                ErrorCode::Conflict,
                "writer refresh already open",
            ));
        };
        let callback = Arc::new(WriterCallback {
            refresh: refresh.clone(),
            node: node.clone(),
            original: original.clone(),
            fence,
            active: AtomicBool::new(true),
            challenge: OnceLock::new(),
        });
        slot.insert(callback.clone());
        Ok(OpenCallback {
            owner: self,
            callback,
        })
    }

    pub(crate) fn resolve(
        &self,
        nonce: Uuid,
        reader: &RequestContext,
        peer: &[u8; 32],
        signed: &SignedTargetWriterChallenge,
        database: &Database,
    ) -> Result<Arc<WriterCallback>> {
        let active = self
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&nonce)
            .cloned()
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Unavailable,
                    "original writer refresh is not active on this Control member",
                )
            })?;
        if reader.principal != active.node.principal
            || hex::encode(peer) != active.node.certificate_sha256
            || signed.challenge.root != active.refresh.root
            || signed.challenge.verifier != active.refresh.verifier
            || signed.challenge.lifecycle_command.is_some()
        {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "writer callback differs from original target",
            ));
        }
        active.check(reader, database)?;
        TargetSigner::verify_writer_challenge(signed, &active.node).map_err(|error| {
            Error::new(
                ErrorCode::Forbidden,
                "writer callback attestation differs from its enrollment",
            )
            .with_physical_source(error)
        })?;
        let digest = kasumi_types::staged_digest(signed)?.0;
        if active.challenge.get_or_init(|| digest.clone()) != &digest {
            return Err(Error::new(
                ErrorCode::Conflict,
                "writer refresh already has a different challenge",
            ));
        }
        Ok(active)
    }
}
impl WriterCallback {
    pub(crate) fn original(&self) -> &RequestContext {
        &self.original
    }
    pub(crate) fn state_sha256(&self) -> &str {
        &self.refresh.state_sha256
    }
    pub(crate) fn check(&self, reader: &RequestContext, database: &Database) -> Result<()> {
        if !self.active.load(Ordering::Acquire) {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "original writer refresh closed",
            ));
        }
        if reader.scopes.len() != 1 || !reader.scopes.contains(&Action::Read) {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "read-scoped writer credential required",
            ));
        }
        database
            .engine()
            .authorize(reader, Some("target_journal_writers"), Action::Read)?;
        database
            .engine()
            .authorize(&self.original, None, Action::Admin)?;
        self.fence.check()
    }
}
