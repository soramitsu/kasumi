use crate::{BasicNode, Raft, TypeConfig};
use anyhow::{Result, bail};
use async_trait::async_trait;
use openraft::{
    RaftNetwork, RaftNetworkFactory,
    error::{InstallSnapshotError, RPCError, RaftError, RemoteError, Unreachable},
    network::{Backoff, RPCOption},
    raft::{
        AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest,
        InstallSnapshotResponse, VoteRequest, VoteResponse,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, RwLock},
    time::Duration,
};

/// The transport must authenticate the source node and isolate `group` routing.
/// Implementations must not route by unverified client-supplied tenant/node IDs.
#[async_trait]
pub trait RaftTransport: Send + Sync + 'static {
    async fn send(
        &self,
        group: &str,
        source: u64,
        target: u64,
        node: &BasicNode,
        request: RpcRequest,
    ) -> Result<RpcResponse>;
}

/// A transport byte limit that can be satisfied by sending fewer log entries.
/// Network adapters return this through anyhow; the Raft adapter translates it
/// into OpenRaft's immediate, adaptive append retry rather than unreachability.
#[derive(Clone, Debug)]
pub struct RpcPayloadTooLarge {
    pub max_entries: u64,
}

impl std::fmt::Display for RpcPayloadTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "raft append exceeds transport limit; retry at most {} entries",
            self.max_entries
        )
    }
}
impl std::error::Error for RpcPayloadTooLarge {}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "rpc", content = "payload", rename_all = "snake_case")]
pub enum RpcRequest {
    Append(AppendEntriesRequest<TypeConfig>),
    Vote(VoteRequest<u64>),
    Snapshot(InstallSnapshotRequest<TypeConfig>),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "rpc", content = "payload", rename_all = "snake_case")]
pub enum RpcResponse {
    Append(Result<AppendEntriesResponse<u64>, RaftError<u64>>),
    Vote(Result<VoteResponse<u64>, RaftError<u64>>),
    Snapshot(Result<InstallSnapshotResponse<u64>, RaftError<u64, InstallSnapshotError>>),
}

/// Call only after transport authentication and group/node authorization.
pub async fn dispatch_rpc(raft: &Raft, request: RpcRequest) -> RpcResponse {
    match request {
        RpcRequest::Append(request) => RpcResponse::Append(raft.append_entries(request).await),
        RpcRequest::Vote(request) => RpcResponse::Vote(raft.vote(request).await),
        RpcRequest::Snapshot(request) => {
            RpcResponse::Snapshot(raft.install_snapshot(request).await)
        }
    }
}

pub(crate) struct NetworkFactory {
    source: u64,
    group: String,
    transport: Arc<dyn RaftTransport>,
}

impl NetworkFactory {
    pub fn new(source: u64, group: String, transport: Arc<dyn RaftTransport>) -> Self {
        Self {
            source,
            group,
            transport,
        }
    }
}

pub(crate) struct Network {
    source: u64,
    target: u64,
    group: String,
    node: BasicNode,
    transport: Arc<dyn RaftTransport>,
}

impl RaftNetworkFactory<TypeConfig> for NetworkFactory {
    type Network = Network;
    async fn new_client(&mut self, target: u64, node: &BasicNode) -> Network {
        Network {
            source: self.source,
            target,
            group: self.group.clone(),
            node: node.clone(),
            transport: self.transport.clone(),
        }
    }
}

impl Network {
    async fn send(&self, request: RpcRequest, option: RPCOption) -> Result<RpcResponse> {
        // OpenRaft uses hard_ttl as the RPC deadline. soft_ttl is the point
        // where a transport may begin graceful cancellation, not permission to
        // fail a still-live authenticated RPC before OpenRaft's own deadline.
        tokio::time::timeout(
            option.hard_ttl(),
            self.transport
                .send(&self.group, self.source, self.target, &self.node, request),
        )
        .await?
    }

    fn unavailable<E: std::error::Error>(
        &self,
        message: impl std::fmt::Display,
    ) -> RPCError<u64, BasicNode, E> {
        RPCError::Unreachable(Unreachable::new(&std::io::Error::other(
            message.to_string(),
        )))
    }
}

impl RaftNetwork<TypeConfig> for Network {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        let entries = rpc.entries.len() as u64;
        let result = self
            .send(RpcRequest::Append(rpc), option)
            .await
            .map_err(|error| {
                if let Some(hint) = error.downcast_ref::<RpcPayloadTooLarge>() {
                    let hint = hint
                        .max_entries
                        .max(1)
                        .min(entries.saturating_sub(1).max(1));
                    RPCError::PayloadTooLarge(openraft::error::PayloadTooLarge::new_entries_hint(
                        hint,
                    ))
                } else {
                    self.unavailable(error)
                }
            })?;
        match result {
            RpcResponse::Append(response) => response.map_err(|error| {
                RPCError::RemoteError(RemoteError::new_with_node(
                    self.target,
                    self.node.clone(),
                    error,
                ))
            }),
            _ => Err(self.unavailable("unexpected raft RPC response")),
        }
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<u64>,
        option: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        match self
            .send(RpcRequest::Vote(rpc), option)
            .await
            .map_err(|error| self.unavailable(error))?
        {
            RpcResponse::Vote(response) => response.map_err(|error| {
                RPCError::RemoteError(RemoteError::new_with_node(
                    self.target,
                    self.node.clone(),
                    error,
                ))
            }),
            _ => Err(self.unavailable("unexpected raft RPC response")),
        }
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<u64>,
        RPCError<u64, BasicNode, RaftError<u64, InstallSnapshotError>>,
    > {
        match self
            .send(RpcRequest::Snapshot(rpc), option)
            .await
            .map_err(|error| self.unavailable(error))?
        {
            RpcResponse::Snapshot(response) => response.map_err(|error| {
                RPCError::RemoteError(RemoteError::new_with_node(
                    self.target,
                    self.node.clone(),
                    error,
                ))
            }),
            _ => Err(self.unavailable("unexpected raft RPC response")),
        }
    }

    fn backoff(&self) -> Backoff {
        Backoff::new(std::iter::repeat(Duration::from_millis(100)))
    }
}

/// Real Raft RPC routing with controllable network cuts, for local deployment and tests.
/// This is not a consensus simulator: it delivers requests to actual OpenRaft instances.
#[derive(Default)]
pub struct InProcessRouter {
    nodes: RwLock<BTreeMap<(String, u64), Raft>>,
    blocked: RwLock<BTreeSet<(String, u64, u64)>>,
}

impl InProcessRouter {
    pub fn register(&self, group: String, id: u64, raft: Raft) {
        self.nodes
            .write()
            .expect("router lock poisoned")
            .insert((group, id), raft);
    }

    pub fn unregister(&self, group: &str, id: u64) {
        self.nodes
            .write()
            .expect("router lock poisoned")
            .remove(&(group.into(), id));
    }

    pub fn block(&self, group: &str, source: u64, target: u64, blocked: bool) {
        let key = (group.into(), source, target);
        let mut cuts = self.blocked.write().expect("router lock poisoned");
        if blocked {
            cuts.insert(key);
        } else {
            cuts.remove(&key);
        }
    }

    pub fn isolate(&self, group: &str, id: u64, isolated: bool) {
        let peers = self
            .nodes
            .read()
            .expect("router lock poisoned")
            .keys()
            .filter(|(name, _)| name == group)
            .map(|(_, id)| *id)
            .collect::<Vec<_>>();
        for peer in peers {
            if peer != id {
                self.block(group, id, peer, isolated);
                self.block(group, peer, id, isolated);
            }
        }
    }
}

#[async_trait]
impl RaftTransport for InProcessRouter {
    async fn send(
        &self,
        group: &str,
        source: u64,
        target: u64,
        _node: &BasicNode,
        request: RpcRequest,
    ) -> Result<RpcResponse> {
        if self
            .blocked
            .read()
            .map_err(|_| anyhow::anyhow!("router lock poisoned"))?
            .contains(&(group.into(), source, target))
        {
            bail!("raft link partitioned");
        }
        let target = self
            .nodes
            .read()
            .map_err(|_| anyhow::anyhow!("router lock poisoned"))?
            .get(&(group.into(), target))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("raft peer unavailable"))?;
        Ok(dispatch_rpc(&target, request).await)
    }
}
