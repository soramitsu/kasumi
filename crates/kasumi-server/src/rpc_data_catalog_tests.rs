//! The two independent three-member groups in the protected admin fixture use
//! their real installed databases as the owners of physical catalog reads.
use super::*;
use crate::data_member_catalog::{DataCatalogSource, DataCatalogSources, InstalledReader};
use kasumi_raft::{BasicNode, RaftTransport, RpcRequest, RpcResponse};
use std::sync::{RwLock, Weak};

#[derive(Default)]
pub(super) struct Groups {
    raft: kasumi_raft::InProcessRouter,
    members: RwLock<BTreeMap<(String, u64), Weak<Database>>>,
}
impl Groups {
    pub(super) fn register(&self, group: String, id: u64, database: &Arc<Database>) {
        self.members
            .write()
            .unwrap()
            .insert((group.clone(), id), Arc::downgrade(database));
        self.raft
            .register(group, id, database.raft_group().raft().clone());
    }
}
#[async_trait::async_trait]
impl RaftTransport for Groups {
    async fn send(
        &self,
        group: &str,
        source: u64,
        target: u64,
        node: &BasicNode,
        request: RpcRequest,
    ) -> anyhow::Result<RpcResponse> {
        let RpcRequest::MemberCatalog(input) = request else {
            return self.raft.send(group, source, target, node, request).await;
        };
        anyhow::ensure!(
            input.leader == source,
            "catalog caller differs from Raft source"
        );
        let database = self
            .members
            .read()
            .unwrap()
            .get(&(group.to_owned(), target))
            .and_then(Weak::upgrade)
            .unwrap();
        let result = database.member_key_catalog((*input).clone()).await?;
        let bytes = serde_json::to_vec(result.as_ref())?;
        database
            .check_member_catalog_release(&result, &input)
            .await?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}
pub(super) type Journal = (
    Arc<kasumi_engine::TargetJournal>,
    Arc<TenantStore>,
    kasumi_store::NodeStore,
);

struct EmptyCheckpoints;
impl kasumi_engine::TargetCheckpointInventory for EmptyCheckpoints {
    fn source(
        &self,
        _: Uuid,
        _: &FullBackupCheckpoint,
    ) -> anyhow::Result<Option<kasumi_engine::TargetCheckpointSource>> {
        anyhow::bail!("fresh Data journal unexpectedly contains a permanent checkpoint")
    }
}

pub(super) async fn open_data_journal(
    base: &Path,
    disks: &kasumi_engine::test_utils::FixtureStorage,
    db: &Arc<Database>,
    root: &ControlSigningRoot,
) -> Journal {
    let app = db.stores().application();
    let kasumi_store::StoragePurpose::Serving { identity, .. } = app.storage_access().purpose()
    else {
        panic!("fixture expected a Data member")
    };
    let verifier = &identity.node.verifier;
    let id =
        kasumi_store::node_store_ids::target_journal(root.control_incarnation, verifier).unwrap();
    let file = disks
        .create_new(base.join("persistent/target-journal.kv"), id)
        .unwrap();
    let owner = TenantStore::initialize_catalog(
        file.clone(),
        format!(
            "kasumi.target.{}.{}",
            root.control_incarnation, verifier.node_id
        ),
        Arc::new(LocalKeyProvider::new([64 + verifier.node_id as u8; 32])),
        StorageAccess::target_journal(root, &identity.node).unwrap(),
    )
    .await
    .unwrap();
    let (cache, destination) = app.installed_tenant_audit_placement().unwrap().unwrap();
    assert_eq!(cache, destination);
    let placement = crate::audit_destination::TenantAuditPlacementConfig::LocalReplicaOnly
        .canonical_binding()
        .unwrap();
    let journal = kasumi_engine::TargetJournal::create_new(
        owner.clone(),
        kasumi_engine::TargetJournalInstallation {
            root: root.clone(),
            node: identity.node.clone(),
            audit_placement_bindings: BTreeMap::from([(identity.tenant.clone(), placement)]),
            source_key_bindings_sha256: None,
        },
        TargetJournalLimits {
            max_metadata_bytes: 4 << 20,
        },
        disks.admission.clone(),
    )
    .unwrap();
    db.install_data_target_inventory(&journal, root, Arc::new(EmptyCheckpoints))
        .unwrap();
    (journal, owner, file)
}

pub(super) struct Installation<'a> {
    pub ids: &'a Identities,
    pub routes: BTreeMap<u64, AuthorityEndpoint>,
    pub token_path: &'a Path,
    pub reader_token: &'a str,
    pub denied_token: &'a str,
    pub control: &'a Arc<Database>,
    pub operator: &'a RequestContext,
    pub topology: &'a kasumi_engine::control::ControlTopology,
    pub root: Uuid,
    pub admission: &'a Arc<kasumi_engine::admission::NodeAdmission>,
    pub tenant: &'a str,
    pub incarnation: Uuid,
    pub source: u64,
    pub journals: &'a [Journal],
    pub control_bootstrap: &'a ReplicatedBootstrap,
    pub control_members: &'a [Arc<Database>],
    pub database_ids: &'a [Uuid],
    pub signers: &'a [Arc<TenantStore>],
    pub audits: &'a [Arc<kasumi_engine::SecurityAudit>],
}
impl Installation<'_> {
    fn enroll_dedicated_control(
        &self,
        sources: &DataCatalogSources,
        remote: &kasumi_engine::control::ControlTopology,
    ) {
        let ReplicatedGenesis::Control(genesis) = &self.control_bootstrap.genesis else {
            panic!("missing Control genesis")
        };
        let kasumi_engine::ControlLifecycleGenesis::Installed {
            command_id,
            installation,
        } = &genesis.lifecycle
        else {
            panic!("missing installed Control lifecycle")
        };
        for db in self.control_members {
            let id = db.raft_group().node_id();
            let i = (id - 1) as usize;
            let mut config = crate::runtime::example_config(
                kasumi_store::DirectoryPolicy::fixture(),
                kasumi_store::FileAllocationPolicy::fixture(),
            )
            .unwrap();
            config.database_id = self.database_ids[i];
            config.tenants.clear();
            config.target_recovery = None;
            config.remote_control = None;
            let verifier = kasumi_serving::test_utils::fixture_verifier(id);
            config.signer_verifier.as_mut().unwrap().identity = verifier.clone();
            let hosted = config.control.as_mut().unwrap();
            hosted.incarnation = Some(self.root.to_string());
            hosted.remote_data = Some(remote.clone());
            hosted.catalog_sources = Some(sources.clone());
            hosted.lifecycle = Some(crate::lifecycle_runtime::LifecycleRuntimeConfig {
                command_id: *command_id,
                installation: installation.clone(),
                signing_key: "/fixture/control-root".into(),
                recovery: None,
            });
            let replica = config.replication.as_mut().unwrap();
            replica.node_id = id;
            replica.initial_voters = self.control_bootstrap.voters.keys().copied().collect();
            replica.peers = self
                .control_bootstrap
                .voters
                .iter()
                .map(|(&node_id, placement)| crate::runtime::ReplicaConfig {
                    node_id,
                    endpoint: placement.address.clone(),
                    failure_domain: placement.failure_domain.clone(),
                    certificate_pins: vec![self.ids.pin(node_id as usize)],
                })
                .collect();
            crate::control_genesis::dedicated_topology(&config, remote).unwrap();
            let store = self.audits[i].store();
            let input = crate::node_enrollment::Input::Data {
                configuration: Box::new(config),
            };
            let enrollment = crate::node_enrollment::Enrollment::begin(store, &input).unwrap();
            enrollment
                .record_genesis_tenant(
                    store,
                    crate::runtime::CONTROL_TENANT,
                    self.root,
                    crate::runtime::persisted_replicated_bootstrap_fingerprint(db.stores())
                        .unwrap(),
                )
                .unwrap();
            enrollment.complete(store).unwrap();
            let proof = crate::node_enrollment::target_journal_exclusion(
                self.database_ids[i],
                self.audits[i].admission(),
            );
            let token = kasumi_query::QueryCancellation::default();
            proof(store, &verifier, &installation.root, &token).unwrap();
            let mut wrong = verifier.clone();
            wrong.installation_id = Uuid::new_v4();
            assert!(proof(store, &wrong, &installation.root, &token).is_err());
            db.install_target_journal_exclusion(proof).unwrap();
        }
    }
}
pub(super) async fn assert_cross_group_reads(f: Installation<'_>) {
    let mut remote = f.topology.clone();
    remote.nodes.retain(|id, _| *id <= 3);
    let members = f
        .routes
        .iter()
        .map(|(&id, route)| {
            (
                id,
                DataCatalogSource {
                    verifier: kasumi_serving::test_utils::fixture_verifier(id),
                    admin: route.clone(),
                },
            )
        })
        .collect();
    let sources = DataCatalogSources {
        target_journals: true,
        tls: f.ids.files[11].clone(),
        server_ca: f.ids.ca.clone(),
        principal: "catalog-reader".into(),
        bearer_file: f.token_path.display().to_string(),
        client_certificate_pins: BTreeSet::from([f.ids.pin(11)]),
        members,
        groups: BTreeMap::from([(
            f.tenant.into(),
            DataCatalogGroup {
                incarnation: f.incarnation,
                members: BTreeSet::from([1, 2, 3]),
            },
        )]),
    };
    sources.validate(&remote, None).unwrap();
    f.enroll_dedicated_control(&sources, &remote);
    let mut expanded = remote.clone();
    expanded.nodes.insert(
        12,
        kasumi_engine::control::ControlNode {
            endpoint: "https://spare-data.example".into(),
            failure_domain: "extra-zone".into(),
            certificate_pins: BTreeSet::from(["fa".repeat(32)]),
        },
    );
    sources.validate(&expanded, None).unwrap();
    let mut replacement = sources.clone();
    replacement.members.get_mut(&1).unwrap().verifier.node_id = 2;
    assert!(replacement.validate(&remote, None).is_err());
    f.control
        .install_remote_data_catalog_reader(InstalledReader::open(&sources, f.admission).unwrap())
        .unwrap();
    let mut client = KasumiAdminClient::connect(
        &crate::installed_clients::connections(&f.routes, &f.ids.files[11], &f.ids.ca).unwrap()
            [&f.source],
    )
    .await
    .unwrap();
    let read = DataMemberCatalogRead {
        tenant: f.tenant.into(),
        incarnation: f.incarnation,
        verifier: kasumi_serving::test_utils::fixture_verifier(f.source),
        service: DataMemberService::Signer,
        nonce: Uuid::new_v4(),
        from_identity: None,
        after: None,
        limit: 1,
    };
    let first = client
        .read_data_member_catalog(f.reader_token, &read)
        .await
        .unwrap();
    assert_eq!(first.membership.members, BTreeSet::from([1, 2, 3]));
    assert_eq!(first.membership.leader, f.source);
    let voters = BTreeSet::from([1, 2, 3]);
    let confirmed = f
        .control
        .confirm_data_membership(f.operator, f.tenant, f.incarnation, &voters)
        .await
        .unwrap();
    assert_eq!(hex::encode(confirmed), first.membership.membership_sha256);
    assert!(
        f.control
            .confirm_data_membership(f.operator, f.tenant, Uuid::new_v4(), &voters)
            .await
            .is_err()
    );
    assert!(
        f.control
            .confirm_data_membership(
                f.operator,
                f.tenant,
                f.incarnation,
                &BTreeSet::from([1, 2, 12])
            )
            .await
            .is_err()
    );
    // The Control route can still name a prior voter set after Data has
    // completed its Raft transition. Exercise the actual versioned write.
    let plane = kasumi_engine::control::ControlPlane::new(f.control.clone()).unwrap();
    let original = plane.topology(f.operator).await.unwrap().unwrap();
    let mut previous_topology = original.topology.clone();
    previous_topology
        .nodes
        .insert(12, expanded.nodes[&12].clone());
    let previous = BTreeSet::from([1, 2, 12]);
    previous_topology.tenants.get_mut(f.tenant).unwrap().voters = previous.clone();
    plane
        .replace_topology(
            f.operator.clone(),
            previous_topology,
            Precondition::Version(original.version),
            "catalog-fixture-previous-route".into(),
        )
        .await
        .unwrap();
    let before = plane.topology(f.operator).await.unwrap().unwrap().version;
    let publish = crate::administration::publish_data_voters;
    assert!(
        publish(
            f.control,
            f.operator,
            f.tenant,
            f.incarnation,
            &BTreeSet::from([1, 3, 12]),
            &voters
        )
        .await
        .is_err()
    );
    // A Control administrator still needs the independent Data observations.
    write_token(f.token_path, f.denied_token);
    assert!(
        publish(
            f.control,
            f.operator,
            f.tenant,
            f.incarnation,
            &previous,
            &voters
        )
        .await
        .is_err()
    );
    assert_eq!(
        plane.topology(f.operator).await.unwrap().unwrap().version,
        before
    );
    write_token(f.token_path, f.reader_token);
    publish(
        f.control,
        f.operator,
        f.tenant,
        f.incarnation,
        &previous,
        &voters,
    )
    .await
    .unwrap();
    let published = plane.topology(f.operator).await.unwrap().unwrap();
    assert!(published.version > before);
    assert_eq!(published.topology.tenants[f.tenant].voters, voters);
    publish(
        f.control,
        f.operator,
        f.tenant,
        f.incarnation,
        &previous,
        &voters,
    )
    .await
    .unwrap();
    assert_eq!(
        plane.topology(f.operator).await.unwrap().unwrap().version,
        published.version
    );
    plane
        .replace_topology(
            f.operator.clone(),
            original.topology,
            Precondition::Version(published.version),
            "catalog-fixture-original-topology".into(),
        )
        .await
        .unwrap();
    assert_eq!(
        client
            .read_data_member_catalog(f.denied_token, &read)
            .await
            .unwrap_err()
            .code(),
        Some(ErrorCode::Forbidden)
    );
    let mut wrong_peer = KasumiAdminClient::connect(
        &crate::installed_clients::connections(&f.routes, &f.ids.files[0], &f.ids.ca).unwrap()
            [&f.source],
    )
    .await
    .unwrap();
    assert_eq!(
        wrong_peer
            .read_data_member_catalog(f.reader_token, &read)
            .await
            .unwrap_err()
            .code(),
        Some(ErrorCode::Forbidden)
    );
    let mut wrong_verifier = read.clone();
    wrong_verifier.verifier.installation_id = Uuid::new_v4();
    assert!(
        client
            .read_data_member_catalog(f.reader_token, &wrong_verifier)
            .await
            .is_err()
    );
    let mut journal_request = read.clone();
    journal_request.service = DataMemberService::TargetJournal;
    let follower = (1..=3).find(|id| *id != f.source).unwrap();
    journal_request.verifier = kasumi_serving::test_utils::fixture_verifier(follower);
    let journal_page = client
        .read_data_member_catalog(f.reader_token, &journal_request)
        .await
        .unwrap();
    assert!(
        matches!(journal_page.contents, DataCatalogContents::TargetJournal { ref unreadable_targets, truncated:false, .. } if unreadable_targets.is_empty())
    );
    let owner = &f.journals[follower as usize - 1].1;
    owner
        .visit_wrapping_identities(|catalog, _, _, _| {
            assert_eq!(journal_page.catalog, catalog);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        client
            .read_data_member_catalog(f.denied_token, &journal_request)
            .await
            .unwrap_err()
            .code(),
        Some(ErrorCode::Forbidden)
    );

    let mut other = read;
    other.incarnation = f.root;
    assert_eq!(
        client
            .read_data_member_catalog(f.reader_token, &other)
            .await
            .unwrap_err()
            .code(),
        Some(ErrorCode::Forbidden)
    );
    for scope in [
        KeyRetentionScope::Signer {},
        KeyRetentionScope::SecurityAudit {},
        KeyRetentionScope::TargetJournal {},
    ] {
        let mut request = ReadKeyRetentionRequest {
            scope: scope.clone(),
            cursor: None,
            limit: 2,
        };
        let mut entries = BTreeSet::new();
        loop {
            let page = f
                .control
                .read_key_retention(f.operator, request.clone())
                .await
                .unwrap();
            if matches!(scope, KeyRetentionScope::TargetJournal {}) {
                assert!(
                    matches!(page.coverage, KeyRetentionCoverage::Complete { .. }),
                    "journal coverage with authentic role exclusions: {:?}",
                    page.coverage
                );
            }
            if let KeyRetentionCoverage::Incomplete { missing, .. } = &page.coverage {
                let present = if matches!(scope, KeyRetentionScope::TargetJournal {}) {
                    1..=3
                } else {
                    1..=6
                };
                assert!(
                    missing.iter().all(|m| !matches!(
                        m,
                        MissingKeyDependency::MemberUnreported { node_id } if present.contains(node_id)
                    )),
                    "missing enrolled members {missing:?}"
                );
            }
            for entry in &page.entries {
                assert!(entries.insert(entry.clone()));
            }
            request.cursor = page.next_cursor.clone();
            if request.cursor.is_none() {
                break;
            }
        }
        let count = if matches!(scope, KeyRetentionScope::TargetJournal {}) {
            3
        } else {
            6
        };
        for node in 1..=count {
            let (store, domain) = if matches!(scope, KeyRetentionScope::TargetJournal {}) {
                (&f.journals[node - 1].1, KeyCatalogDomain::TargetJournal)
            } else if matches!(scope, KeyRetentionScope::Signer {}) {
                (&f.signers[node - 1], KeyCatalogDomain::LiveSignerTrust)
            } else {
                (f.audits[node - 1].store(), KeyCatalogDomain::SecurityAudit)
            };
            store.visit_wrapping_identities(|catalog,provider,key_ref,version|{
                assert!(entries.iter().any(|row|row.key.provider==provider && row.key.key_ref==key_ref && row.key.version==version &&
                      matches!(row.reference,KeyReference::Catalog{node_id,catalog_id,domain:d} if node_id==node as u64 && catalog_id==catalog && d==domain)));
                Ok(())
            }).unwrap();
        }
    }
    let control_follower = f
        .control_members
        .iter()
        .find(|db| db.raft_group().node_id() != f.control.raft_group().node_id())
        .unwrap()
        .raft_group()
        .node_id();
    let encrypted = f.audits[control_follower as usize - 1].store();
    let original = encrypted
        .get_bounded("node.enrollment", b"head", 4096)
        .unwrap()
        .unwrap();
    encrypted
        .write_batch(&[kasumi_store::WriteOp::delete("node.enrollment", b"head")])
        .unwrap();
    let missing_original = f
        .control
        .read_key_retention(
            f.operator,
            ReadKeyRetentionRequest {
                scope: KeyRetentionScope::TargetJournal {},
                cursor: None,
                limit: 2,
            },
        )
        .await;
    encrypted
        .write_batch(&[kasumi_store::WriteOp::put(
            "node.enrollment",
            b"head",
            original.to_vec(),
        )])
        .unwrap();
    let missing_original = missing_original.unwrap();
    assert!(
        matches!(&missing_original.coverage,KeyRetentionCoverage::Incomplete{missing,..}
        if missing.contains(&MissingKeyDependency::MemberUnreported{node_id:control_follower}))
    );
    // Replacing the dedicated reader with a valid backup writer leaves all
    // three physical Data nodes explicit in the Control coverage.
    write_token(f.token_path, f.denied_token);
    let page = f
        .control
        .read_key_retention(
            f.operator,
            ReadKeyRetentionRequest {
                scope: KeyRetentionScope::SecurityAudit {},
                cursor: None,
                limit: 4,
            },
        )
        .await
        .unwrap();
    let KeyRetentionCoverage::Incomplete { missing, .. } = &page.coverage else {
        panic!("writer acquired global inventory coverage")
    };
    for id in 1..=3 {
        assert!(missing.contains(&MissingKeyDependency::MemberUnreported { node_id: id }));
    }
    write_token(f.token_path, f.reader_token);
}
