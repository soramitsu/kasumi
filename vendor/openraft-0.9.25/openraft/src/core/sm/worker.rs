use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::sync::Mutex;

use super::apply_batch::ApplyBatch;
use super::pending_apply::PendingApply;
use crate::async_runtime::AsyncOneshotSendExt;
use crate::core::notify::Notify;
use crate::core::raft_msg::ResultSender;
use crate::core::sm::handle::Handle;
use crate::core::sm::tasks::Task;
use crate::core::sm::tasks::TaskError;
use crate::core::sm::tasks::Tasks;
use crate::core::sm::Command;
use crate::core::sm::CommandPayload;
use crate::core::sm::CommandResult;
use crate::core::sm::CommandSeq;
use crate::core::sm::Response;
use crate::core::ApplyResult;
use crate::core::ApplyingEntry;
use crate::display_ext::DisplayOptionExt;
use crate::entry::RaftPayload;
use crate::storage::RaftStateMachine;
use crate::type_config::alias::JoinHandleOf;
use crate::AsyncRuntime;
use crate::RaftLogId;
use crate::RaftSnapshotBuilder;
use crate::RaftTypeConfig;
use crate::Snapshot;
use crate::StorageError;
use crate::{LogId, RaftLogReader, StorageIOError};

pub(crate) struct Worker<C, SM, LR>
where
    C: RaftTypeConfig,
    SM: RaftStateMachine<C>,
    LR: RaftLogReader<C>,
{
    state_machine: SM,
    log_reader: LR,
    max_entries: u64,
    apply_batch: Arc<ApplyBatch<C>>,

    snapshot: Arc<Mutex<Option<Task<C>>>>,

    cmd_rx: mpsc::UnboundedReceiver<Command<C>>,
    pending_apply: Arc<PendingApply<C>>,

    resp_tx: mpsc::UnboundedSender<Notify<C>>,
}

impl<C, SM, LR> Worker<C, SM, LR>
where
    C: RaftTypeConfig,
    SM: RaftStateMachine<C>,
    LR: RaftLogReader<C>,
{
    /// Spawn a new state machine worker, return a controlling handle.
    pub(crate) fn spawn(
        state_machine: SM,
        log_reader: LR,
        max_entries: u64,
        resp_tx: mpsc::UnboundedSender<Notify<C>>,
    ) -> (Handle<C>, Tasks<C>) {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let snapshot = Arc::new(Mutex::new(None));
        let apply_batch = ApplyBatch::new();
        let pending_apply = PendingApply::new();
        let worker = Worker {
            state_machine,
            log_reader,
            max_entries,
            apply_batch: apply_batch.clone(),
            snapshot: snapshot.clone(),
            cmd_rx,
            pending_apply: pending_apply.clone(),
            resp_tx,
        };
        let task = Arc::new(Mutex::new(Task::Running(worker.do_spawn())));
        let handle = Handle {
            cmd_tx,
            pending_apply,
            task: task.clone(),
        };
        (
            handle,
            Tasks {
                worker: task,
                snapshot,
                apply_batch,
            },
        )
    }

    fn do_spawn(mut self) -> JoinHandleOf<C, Result<(), TaskError<C>>> {
        C::AsyncRuntime::spawn(async move { self.worker_loop().await })
    }

    #[tracing::instrument(level = "debug", skip_all)]
    async fn worker_loop(&mut self) -> Result<(), TaskError<C>> {
        loop {
            let cmd = {
                let mut snapshot = self.snapshot.lock().await;
                let completed = async {
                    match snapshot.as_mut() {
                        Some(task) if task.is_running() => task.join().await,
                        _ => std::future::pending().await,
                    }
                };
                // Preserve completed-builder failure priority even under a
                // continuous stream of coalesced application work.
                let pending_apply = &self.pending_apply;
                let cmd_rx = &mut self.cmd_rx;
                let command = async {
                    match pending_apply.take_next(cmd_rx) {
                        Ok(command) => Some(command),
                        Err(mpsc::error::TryRecvError::Disconnected) => None,
                        Err(mpsc::error::TryRecvError::Empty) => match cmd_rx.recv().await {
                            Some(command) => Some(command),
                            None => pending_apply.take_next(cmd_rx).ok(),
                        },
                    }
                };
                tokio::select! {
                    biased;
                    outcome = completed => {
                        outcome?;
                        continue;
                    }
                    command = command => command,
                    _ = pending_apply.ready.notified() => continue,
                }
            };
            let cmd = match cmd {
                None => {
                    tracing::info!("{}: rx closed, state machine worker quit", func_name!());
                    return Ok(());
                }
                Some(x) => x,
            };

            tracing::debug!("{}: received command: {:?}", func_name!(), cmd);

            if let Some(range) = cmd.apply_before {
                self.apply_range(range.seq, range.since, range.upto).await?;
            }
            match cmd.payload {
                CommandPayload::BuildSnapshot => {
                    tracing::info!("{}: build snapshot", func_name!());

                    // It is a read operation and is spawned, and it responds in another task
                    self.build_snapshot(cmd.seq, self.resp_tx.clone()).await?;
                }
                CommandPayload::GetSnapshot { tx } => {
                    tracing::info!("{}: get snapshot", func_name!());

                    self.get_snapshot(tx).await?;
                    // GetSnapshot does not respond to RaftCore
                }
                CommandPayload::InstallFullSnapshot { snapshot } => {
                    tracing::info!("{}: install complete snapshot", func_name!());

                    let meta = snapshot.meta.clone();
                    self.state_machine.install_snapshot(&meta, snapshot.snapshot).await?;

                    tracing::info!("Done install complete snapshot, meta: {}", meta);

                    let res = CommandResult::new(cmd.seq, Ok(Response::InstallSnapshot(Some(meta))));
                    let _ = self.resp_tx.send(Notify::sm(res));
                }
                CommandPayload::BeginReceivingSnapshot { tx } => {
                    tracing::info!("{}: BeginReceivingSnapshot", func_name!());

                    let snapshot_data = self.state_machine.begin_receiving_snapshot().await?;

                    let _ = tx.send(Ok(snapshot_data));
                    // No response to RaftCore
                }
                CommandPayload::Apply { since, upto } => {
                    self.apply_range(cmd.seq, since, upto).await?;
                }
                CommandPayload::Stop => return Ok(()),
            };
        }
    }
    async fn apply_range(
        &mut self,
        seq: CommandSeq,
        mut since: u64,
        upto: LogId<C::NodeId>,
    ) -> Result<(), StorageError<C::NodeId>> {
        let invalid = || {
            StorageIOError::apply(
                upto.clone(),
                anyerror::AnyError::error("committed apply range has a missing, unordered or mismatched log entry"),
            )
        };
        let end = upto.index.checked_add(1).ok_or_else(&invalid)?;
        if self.max_entries == 0 || since > end {
            return Err(invalid().into());
        }
        while since < end {
            let requested_end = end.min(since.saturating_add(self.max_entries));
            let entries = self.log_reader.limited_get_log_entries(since, requested_end).await?;
            if entries.is_empty() {
                return Err(invalid().into());
            }
            let mut next = since;
            for entry in &entries {
                if entry.get_log_id().index != next || next >= requested_end {
                    return Err(invalid().into());
                }
                next = next.checked_add(1).ok_or_else(&invalid)?;
            }
            let final_batch = next == end;
            if final_batch && entries.last().unwrap().get_log_id() != &upto {
                return Err(invalid().into());
            }
            let response = self.apply(entries).await?;
            self.apply_batch.publish(response);
            // Validate response cardinality only after actual opaque replies have
            // entered their fixed retained cell, including a violating backend.
            self.apply_batch.progress()?;
            let (consumed, consumed_rx) = C::AsyncRuntime::oneshot();
            let response = Response::Apply {
                batch: self.apply_batch.clone(),
                final_batch,
                consumed,
            };
            self.resp_tx.send(Notify::sm(CommandResult::new(seq, Ok(response)))).map_err(|_| {
                StorageIOError::apply(
                    upto.clone(),
                    anyerror::AnyError::error("core closed before applied response delivery"),
                )
            })?;
            consumed_rx.await.map_err(|_| {
                StorageIOError::apply(
                    upto.clone(),
                    anyerror::AnyError::error("core did not complete applied response consumption"),
                )
            })?;
            if self.apply_batch.retained().is_some() {
                return Err(invalid().into());
            }
            since = next;
        }
        Ok(())
    }
    #[tracing::instrument(level = "debug", skip_all)]
    async fn apply(&mut self, entries: Vec<C::Entry>) -> Result<ApplyResult<C>, StorageError<C::NodeId>> {
        // TODO: prepare response before apply,
        //       so that an Entry does not need to be Clone,
        //       and no references will be used by apply

        let since = entries.first().map(|x| x.get_log_id().index).unwrap();
        let end = entries.last().map(|x| x.get_log_id().index + 1).unwrap();
        let last_applied = entries.last().map(|x| x.get_log_id().clone()).unwrap();

        // Fake complain: avoid using `collect()` when not needed
        #[allow(clippy::needless_collect)]
        let applying_entries = entries
            .iter()
            .map(|e| ApplyingEntry::new(e.get_log_id().clone(), e.get_membership().cloned()))
            .collect::<Vec<_>>();

        let apply_results = self.state_machine.apply(entries).await?;

        let resp = ApplyResult {
            since,
            end,
            last_applied,
            applying_entries,
            apply_results,
        };

        Ok(resp)
    }

    /// Build a snapshot from the state machine.
    ///
    /// Building snapshot is a read-only operation, so it can be run in another task in parallel.
    /// This parallelization depends on the [`RaftSnapshotBuilder`] implementation returned  by
    /// [`get_snapshot_builder()`](`RaftStateMachine::get_snapshot_builder()`): The builder must:
    /// - hold a consistent view of the state machine that won't be affected by further writes such
    ///   as applying a log entry,
    /// - or it must be able to acquire a lock that prevents any write operations.
    #[tracing::instrument(level = "info", skip_all)]
    async fn build_snapshot(
        &mut self,
        seq: CommandSeq,
        resp_tx: mpsc::UnboundedSender<Notify<C>>,
    ) -> Result<(), TaskError<C>> {
        let mut snapshot = self.snapshot.lock().await;
        if let Some(previous) = snapshot.as_mut() {
            // A notification can reach the core before the child has actually
            // exited. Join it before reusing the one fixed builder slot.
            previous.join().await?;
        }
        let mut builder = self.state_machine.get_snapshot_builder().await;
        let handle = C::AsyncRuntime::spawn(async move {
            let built = builder.build_snapshot().await.map_err(TaskError::<C>::from)?;
            let cmd_res = CommandResult::new(seq, Ok(Response::BuildSnapshot(built.meta)));
            let _ = resp_tx.send(Notify::sm(cmd_res));
            Ok(())
        });
        // Publish the handle synchronously; neither the worker nor a shutdown
        // caller can abandon an unregistered spawned snapshot child.
        *snapshot = Some(Task::Running(handle));
        Ok(())
    }

    #[tracing::instrument(level = "info", skip_all)]
    async fn get_snapshot(&mut self, tx: ResultSender<C, Option<Snapshot<C>>>) -> Result<(), StorageError<C::NodeId>> {
        tracing::info!("{}", func_name!());

        let snapshot = self.state_machine.get_current_snapshot().await?;

        tracing::info!(
            "sending back snapshot: meta: {}",
            snapshot.as_ref().map(|s| &s.meta).display()
        );
        let _ = tx.send(Ok(snapshot));
        Ok(())
    }
}
