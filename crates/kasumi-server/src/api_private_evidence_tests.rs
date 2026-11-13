include!("api_private_evidence_retry_tests.rs");

struct PrivateEvidenceTransportFixture {
    fixture: Fixture,
    context: RequestContext,
    profile: kasumi_client::ClientProfile,
    profile_path: std::path::PathBuf,
    binding: kasumi_private_evidence::InstalledProfileBinding,
    stop: tokio::sync::watch::Sender<bool>,
    serving: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl PrivateEvidenceTransportFixture {
    async fn close(self) {
        self.stop.send(true).unwrap();
        self.serving.await.unwrap().unwrap();
        self.fixture.close().await;
    }
}

async fn private_evidence_transport_fixture() -> PrivateEvidenceTransportFixture {
    private_evidence_transport_fixture_with_router(std::convert::identity).await
}

async fn private_evidence_transport_fixture_with_router(
    configure: impl FnOnce(Router) -> Router,
) -> PrivateEvidenceTransportFixture {
    private_evidence_transport_fixture_with_admission(Default::default(), configure).await
}

async fn private_evidence_transport_fixture_with_admission(
    admission: kasumi_engine::admission::AdmissionConfig,
    configure: impl FnOnce(Router) -> Router,
) -> PrivateEvidenceTransportFixture {
    use kasumi_client::{ClientProfile, ProfileAuthorityEndpoint, ProfileTlsFiles};
    use kasumi_private_evidence::{
        CHUNK_BYTES, InstalledProfileBinding, collection_definition_sha256, collection_definitions,
        verify_installed_collection_definitions,
    };
    use kasumi_transport::{ClientAuthentication, TlsIdentity};
    use sha2::{Digest, Sha256};
    use std::{collections::BTreeMap, os::unix::fs::PermissionsExt};

    let fixture = Fixture::new_with_admission(admission).await;
    let context = RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        principal: "person".into(),
        tenant: "tenant-a".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
        request_id: "private-evidence-schema".into(),
    };
    for definition in collection_definitions("evidence_manifests", "evidence_chunks").unwrap() {
        fixture
            .db
            .administer(context.clone(), Operation::CreateCollection(definition))
            .await
            .unwrap();
    }

    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let key = rcgen::KeyPair::generate().unwrap();
    let certificate = ca.self_signed(&key).unwrap();
    let issuer = rcgen::Issuer::new(ca, key);
    let identity = || {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        ];
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = params.signed_by(&key, &issuer).unwrap();
        (certificate.pem(), key.serialize_pem())
    };
    let (server_certificate, server_key) = identity();
    let server =
        TlsIdentity::from_pem(server_certificate.as_bytes(), server_key.as_bytes()).unwrap();
    let (client_certificate, client_key) = identity();
    let trusted = certificate.pem().into_bytes();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let pin = hex::encode(server.certificate_pin());
    let write_private = |name: &str, bytes: &[u8]| {
        let path = fixture._dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    };
    let token = fixture.token("person", "tenant-a", "kasumi:read kasumi:write");
    let bearer = token.strip_prefix("Bearer ").unwrap();
    let family_id = uuid::Uuid::new_v4();
    let profile = ClientProfile {
        format: 2,
        family_id,
        tenant: "tenant-a".into(),
        principal: "person".into(),
        resource: kasumi_types::CredentialResource::Database {
            incarnation: fixture.incarnation,
        },
        native_endpoint: endpoint.clone(),
        administrative_members: BTreeMap::from([(
            1,
            ProfileAuthorityEndpoint {
                endpoint: endpoint.clone(),
                certificate_pins: BTreeSet::from([pin.clone()]),
            },
        )]),
        mcp_endpoint: format!("{endpoint}/mcp"),
        identity: ProfileTlsFiles {
            certificate: write_private("client.crt", client_certificate.as_bytes()),
            private_key: write_private("client.key", client_key.as_bytes()),
        },
        server_ca: write_private("ca.crt", &trusted),
        native_certificate_pin: pin,
        bearer_file: write_private("bearer", bearer.as_bytes()),
    };
    let bytes = serde_json::to_vec(&profile).unwrap();
    let profile_path = write_private("profile.json", &bytes);
    let [manifest_definition_sha256, chunk_definition_sha256] =
        collection_definition_sha256("evidence_manifests", "evidence_chunks").unwrap();
    let binding = InstalledProfileBinding {
        profile_sha256: hex::encode(Sha256::digest(&bytes)),
        tenant: profile.tenant.clone(),
        incarnation: fixture.incarnation,
        principal: profile.principal.clone(),
        family_id,
        manifest_collection: "evidence_manifests".into(),
        chunk_collection: "evidence_chunks".into(),
        manifest_definition_sha256,
        chunk_definition_sha256,
        max_component_bytes: 4 * CHUNK_BYTES,
    };
    let schema = fixture
        .db
        .read_schema(
            &context,
            kasumi_types::ReadSchema::Named {
                collections: BTreeSet::from([
                    binding.manifest_collection.clone(),
                    binding.chunk_collection.clone(),
                ]),
            },
        )
        .await
        .unwrap();
    verify_installed_collection_definitions(&schema, &binding).unwrap();
    let tls = kasumi_transport::server_config(
        &server,
        ClientAuthentication::Required {
            trusted_ca_pem: &trusted,
        },
    )
    .unwrap();
    let diagnostics = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let admission = fixture.physical.admission.clone();
    let router = configure(tonic::service::Routes::new(fixture.data().service()).into_axum_router())
        .layer(axum::middleware::from_fn(move |request: HttpRequest<Body>, next: axum::middleware::Next| {
            let diagnostics = diagnostics.clone();
            let admission = admission.clone();
            async move {
                let path = request.uri().path().to_owned();
                let response = next.run(request).await;
                if let Some(status) = response.headers().get("grpc-status")
                    && status == "8"
                    && path == "/kasumi.v1.KasumiData/ReadSnapshot"
                    && diagnostics.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 8
                {
                    eprintln!("fixture native RPC {path} rejected: status={status:?}, message={:?}, admission={:?}, policy={:?}", response.headers().get("grpc-message"), admission.snapshot(), admission.policy());
                }
                response
            }
        }));
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(crate::tls::serve_tls(
        listener,
        tls,
        router,
        crate::tls::ListenerLimits::default(),
        fixture.audit.clone(),
        shutdown,
    ));

    PrivateEvidenceTransportFixture {
        fixture,
        context,
        profile,
        profile_path,
        binding,
        stop,
        serving,
    }
}

#[tokio::test]
async fn private_evidence_four_full_chunks_roundtrip_through_secure_native_transport() {
    use kasumi_private_evidence::{
        AppendOutcome, CHUNK_BYTES, EvidenceIdentity, PrivateEvidenceCustody,
    };
    use sha2::{Digest, Sha256};
    use std::time::Duration;

    let transport = private_evidence_transport_fixture().await;
    let PrivateEvidenceTransportFixture {
        fixture,
        profile,
        profile_path,
        binding,
        ..
    } = &transport;
    let token = fixture.token("person", "tenant-a", "kasumi:read kasumi:write");
    let bearer = token.strip_prefix("Bearer ").unwrap();
    let payload = (0..4 * CHUNK_BYTES)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let evidence = EvidenceIdentity::new(
        kasumi_types::MutationReceiptScope {
            tenant: binding.tenant.clone(),
            incarnation: binding.incarnation.to_string(),
            principal: binding.principal.clone(),
        },
        hex::encode(Sha256::digest(b"secure native full read-group boundary")),
        "native_boundary".into(),
    )
    .unwrap();
    let mut custody =
        PrivateEvidenceCustody::from_installed_profile(profile_path, binding).unwrap();
    let timeout = Duration::from_secs(60);
    assert_eq!(
        custody.append(&evidence, &payload, timeout).await.unwrap(),
        AppendOutcome::Committed
    );
    let retained = custody.read(&evidence, timeout).await.unwrap().unwrap();
    assert_eq!(retained.identity, evidence);
    assert_eq!(retained.sha256, hex::encode(Sha256::digest(&payload)));
    assert_eq!(retained.bytes, payload);
    assert_eq!(
        custody.append(&evidence, &payload, timeout).await.unwrap(),
        AppendOutcome::AlreadyPresent
    );

    // The original 12 MiB budget rejects these exact native rows, demonstrating
    // that this test exercises the real decoder capacity rather than a mock.
    let mut client = kasumi_client::KasumiClient::connect(&profile.connection(false).unwrap())
        .await
        .unwrap();
    let request = kasumi_types::ReadSnapshotRequest {
        documents: (0..4)
            .map(|index| kasumi_types::DocumentKey {
                collection: binding.chunk_collection.clone(),
                id: format!("private-evidence/{}/chunk-{index:04}", evidence.evidence_id),
            })
            .collect(),
        queries: vec![],
        time_bounds: None,
    };
    let options = kasumi_client::SnapshotReadOptions {
        resources: kasumi_client::ClientResources::new(128 << 20, 2).unwrap(),
        limits: kasumi_client::ClientDecodeLimits {
            max_request_bytes: 128 << 10,
            max_wire_bytes: 8 << 20,
            max_json_bytes: 8 << 20,
            max_depth: 32,
            max_nodes: 100_000,
            max_string_bytes: 1 << 20,
            max_number_bytes: 128,
            max_rows: 4,
            max_decoded_bytes: 12 << 20,
        },
        deadline: tokio::time::Instant::now() + timeout,
        expected_incarnation: fixture.incarnation,
    };
    assert!(matches!(
        client.read_snapshot(bearer, &request, &options).await,
        Err(kasumi_client::ClientError::DecodeRejected {
            code: Code::ResourceExhausted,
            ..
        })
    ));
    drop(client);
    drop(custody);
    transport.close().await;
}

/// Record logical mutation originals without replacing transport,
/// authentication, receipts, storage or readback. As Core does, only a typed
/// server capacity refusal can resend the same immutable RPC input.
struct RecordingPrivateEvidenceBackend {
    native: kasumi_private_evidence::KasumiBackend,
    submitted: Arc<std::sync::Mutex<Vec<MutationBatch>>>,
    reads: usize,
    schedule: Arc<PrivateEvidenceRpcSchedule>,
}

/// Core bounds native reads independently of its 100 concurrent user workflows.
/// This fixture likewise schedules individual RPCs, not complete custody work.
/// The engine's unchanged default admits 64 operations; a native RPC also owns
/// response-fence and audited-read work. Keep at most 32 RPCs in flight.
struct PrivateEvidenceRpcSchedule {
    slots: Arc<tokio::sync::Semaphore>,
    active: std::sync::atomic::AtomicUsize,
    peak: std::sync::atomic::AtomicUsize,
    capacity_retries: std::sync::atomic::AtomicUsize,
}

struct PrivateEvidenceRpcPermit {
    _slot: tokio::sync::OwnedSemaphorePermit,
    schedule: Arc<PrivateEvidenceRpcSchedule>,
}

impl Drop for PrivateEvidenceRpcPermit {
    fn drop(&mut self) {
        self.schedule
            .active
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl PrivateEvidenceRpcSchedule {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            slots: Arc::new(tokio::sync::Semaphore::new(32)),
            active: std::sync::atomic::AtomicUsize::new(0),
            peak: std::sync::atomic::AtomicUsize::new(0),
            capacity_retries: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    async fn admit(
        self: &Arc<Self>,
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<(PrivateEvidenceRpcPermit, std::time::Duration)> {
        let slot = tokio::time::timeout_at(deadline, self.slots.clone().acquire_owned()).await??;
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        anyhow::ensure!(
            !remaining.is_zero(),
            "native RPC deadline elapsed while queued"
        );
        let active = self
            .active
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        self.peak
            .fetch_max(active, std::sync::atomic::Ordering::SeqCst);
        Ok((
            PrivateEvidenceRpcPermit {
                _slot: slot,
                schedule: self.clone(),
            },
            remaining,
        ))
    }

    async fn retry_capacity(
        &self,
        error: &anyhow::Error,
        attempt: &mut usize,
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<bool> {
        // From Core core_native_data_session.rs::read_error_is_capacity and
        // CAPACITY_PAUSES. Require the server's closed ResourceExhausted code;
        // unlike Core's broader decoder handling, this fixture never retries
        // local admission/decode failures or terminal QuotaExceeded receipts.
        let capacity = error
            .downcast_ref::<kasumi_client::ClientError>()
            .is_some_and(|error| match error {
                kasumi_client::ClientError::DecodeRejected { code, database, .. } => {
                    *code == tonic::Code::ResourceExhausted
                        && *database == Some(kasumi_types::ErrorCode::ResourceExhausted)
                }
                kasumi_client::ClientError::Transport(status) => {
                    status.code() == tonic::Code::ResourceExhausted
                        && error.code() == Some(kasumi_types::ErrorCode::ResourceExhausted)
                }
                _ => false,
            });
        if !capacity {
            return Ok(false);
        }
        let pauses = [10, 25, 50, 100];
        let pause = std::time::Duration::from_millis(pauses[(*attempt).min(pauses.len() - 1)]);
        tokio::time::timeout_at(deadline, tokio::time::sleep(pause)).await?;
        *attempt += 1;
        self.capacity_retries
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(true)
    }
}

#[async_trait::async_trait]
impl kasumi_private_evidence::CustodyBackend for RecordingPrivateEvidenceBackend {
    async fn mutate(
        &mut self,
        batch: &MutationBatch,
        timeout: std::time::Duration,
    ) -> anyhow::Result<WriteReceipt> {
        let deadline = tokio::time::Instant::now() + timeout;
        self.submitted.lock().unwrap().push(batch.clone());
        let mut attempt = 0;
        loop {
            let (permit, remaining) = self.schedule.admit(deadline).await?;
            let result =
                kasumi_private_evidence::CustodyBackend::mutate(&mut self.native, batch, remaining)
                    .await;
            drop(permit);
            if let Err(error) = &result
                && self
                    .schedule
                    .retry_capacity(error, &mut attempt, deadline)
                    .await?
            {
                continue;
            }
            return result;
        }
    }

    async fn resolve(
        &mut self,
        scope: &kasumi_types::MutationReceiptScope,
        original: &MutationBatch,
        timeout: std::time::Duration,
    ) -> anyhow::Result<Option<kasumi_types::MutationReceipt>> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut attempt = 0;
        loop {
            let (permit, remaining) = self.schedule.admit(deadline).await?;
            let result = kasumi_private_evidence::CustodyBackend::resolve(
                &mut self.native,
                scope,
                original,
                remaining,
            )
            .await;
            drop(permit);
            if let Err(error) = &result
                && self
                    .schedule
                    .retry_capacity(error, &mut attempt, deadline)
                    .await?
            {
                continue;
            }
            return result;
        }
    }

    async fn read_records(
        &mut self,
        collection: &str,
        ids: &[String],
        timeout: std::time::Duration,
    ) -> anyhow::Result<Vec<Option<kasumi_types::Document>>> {
        let deadline = tokio::time::Instant::now() + timeout;
        self.reads += 1;
        let mut attempt = 0;
        loop {
            let (permit, remaining) = self.schedule.admit(deadline).await?;
            let result = kasumi_private_evidence::CustodyBackend::read_records(
                &mut self.native,
                collection,
                ids,
                remaining,
            )
            .await;
            drop(permit);
            if let Err(error) = &result {
                if self
                    .schedule
                    .retry_capacity(error, &mut attempt, deadline)
                    .await?
                {
                    continue;
                }
                eprintln!(
                    "real custody read {} failed for {collection} {ids:?}: {error:#}",
                    self.reads
                );
            }
            return result;
        }
    }
}

fn recording_private_evidence_custody(
    profile: &std::path::Path,
    binding: &kasumi_private_evidence::InstalledProfileBinding,
    scope: kasumi_types::MutationReceiptScope,
    schedule: Arc<PrivateEvidenceRpcSchedule>,
) -> (
    kasumi_private_evidence::PrivateEvidenceCustody<RecordingPrivateEvidenceBackend>,
    Arc<std::sync::Mutex<Vec<MutationBatch>>>,
) {
    let submitted = Arc::new(std::sync::Mutex::new(Vec::new()));
    let native =
        kasumi_private_evidence::KasumiBackend::from_installed_profile(profile, binding).unwrap();
    let custody = kasumi_private_evidence::PrivateEvidenceCustody::new(
        RecordingPrivateEvidenceBackend {
            native,
            submitted: submitted.clone(),
            reads: 0,
            schedule,
        },
        binding.manifest_collection.clone(),
        binding.chunk_collection.clone(),
        scope,
        binding.max_component_bytes,
    )
    .unwrap();
    (custody, submitted)
}

async fn append_private_evidence_fixture<B: kasumi_private_evidence::CustodyBackend>(
    custody: &mut kasumi_private_evidence::PrivateEvidenceCustody<B>,
    evidence: &kasumi_private_evidence::EvidenceIdentity,
    payload: &[u8],
    use_batch: bool,
    timeout: std::time::Duration,
) -> kasumi_private_evidence::Result<kasumi_private_evidence::AppendOutcome> {
    if use_batch {
        let outcomes = custody
            .append_many(&[(evidence.clone(), payload)], timeout)
            .await?;
        assert_eq!(outcomes.len(), 1);
        Ok(outcomes[0])
    } else {
        custody.append(evidence, payload, timeout).await
    }
}

// This measures the actual custody subworkflow, not mobile enrollment, hardware
// admission, finality verification or the complete retail activation deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    debug_assertions,
    ignore = "release qualification: cargo test --release -p kasumi-server --lib api::tests::hundred_private_evidence_workflows_recover_retained_quota_refusals_over_native_tls -- --exact --nocapture"
)]
async fn hundred_private_evidence_workflows_recover_retained_quota_refusals_over_native_tls() {
    private_evidence_quota_recovery_workflows(100).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_private_evidence_workflows_recover_retained_quota_refusals_over_native_tls() {
    private_evidence_quota_recovery_workflows(4).await;
}

async fn private_evidence_quota_recovery_workflows(workflows: usize) {
    use kasumi_private_evidence::{
        AppendOutcome, CustodyBackend, CustodyError, EvidenceIdentity, KasumiBackend,
    };
    use sha2::{Digest, Sha256};
    use std::time::Duration;

    // The hundred-workflow release qualification keeps its 30-second budget.
    // The debug suite runs four workflows beside the rest of the suite, where
    // a loaded machine takes many times longer; their budget only bounds a hang.
    let deadline_budget = if workflows == 100 {
        Duration::from_secs(30)
    } else {
        4 * crate::runtime_storage_fixtures::LIVENESS
    };
    // BPNG's installed admission floor is 12 GiB, selected by
    // png2-deploy/scripts/sogeri-poc/deploy/kasumi-storage.py:69. The generic
    // 512-MiB fixture reached 569 MB of its 588-MB metadata-inclusive limit at
    // only 48/64 operations. Use deployed workload headroom for this capacity
    // test; the fixture adds its exact disk metadata charges as usual.
    let transport = private_evidence_transport_fixture_with_admission(
        kasumi_engine::admission::AdmissionConfig {
            max_inflight_bytes: (workflows == 100).then_some(12 << 30),
            ..Default::default()
        },
        std::convert::identity,
    )
    .await;
    assert_eq!(
        transport
            .fixture
            .physical
            .admission
            .policy()
            .max_inflight_operations,
        64
    );
    let limits = transport
        .fixture
        .db
        .engine()
        .generation()
        .unwrap()
        .limits()
        .clone();
    let mut exhausted = limits.clone();
    // Keep schema, receipts, audit and document limits intact. Only the tenant's
    // logical value quota refuses these otherwise admissible original bytes.
    exhausted.max_logical_bytes = 1 << 10;
    transport
        .fixture
        .db
        .administer(transport.context.clone(), Operation::SetLimits(exhausted))
        .await
        .unwrap();
    let scope = kasumi_types::MutationReceiptScope {
        tenant: transport.binding.tenant.clone(),
        incarnation: transport.binding.incarnation.to_string(),
        principal: transport.binding.principal.clone(),
    };
    let mut originals = Vec::new();
    let schedule = PrivateEvidenceRpcSchedule::new();
    let barrier = Arc::new(tokio::sync::Barrier::new(workflows + 1));
    let mut rejected = tokio::task::JoinSet::new();
    for owner in 0..workflows {
        // Core uses one authenticated custody principal for distinct owners.
        // Each workflow retains its own immutable subject, bytes and receipts.
        let evidence = EvidenceIdentity::new(
            scope.clone(),
            hex::encode(Sha256::digest(format!("quota-recovery-owner-{owner}"))),
            "quota_recovery".into(),
        )
        .unwrap();
        let payload = (0..4096)
            .map(|index| ((index + owner) % 251) as u8)
            .collect::<Vec<_>>();
        let use_batch = owner % 2 == 0;
        let profile = transport.profile_path.clone();
        let binding = transport.binding.clone();
        let barrier = barrier.clone();
        let schedule = schedule.clone();
        rejected.spawn(async move {
            let (mut custody, submitted) = recording_private_evidence_custody(
                &profile,
                &binding,
                evidence.scope.clone(),
                schedule.clone(),
            );
            barrier.wait().await;
            let refusal = append_private_evidence_fixture(
                &mut custody,
                &evidence,
                &payload,
                use_batch,
                deadline_budget,
            )
            .await;
            assert!(
                matches!(refusal, Err(CustodyError::Rejected)),
                "owner {owner}: {refusal:?}"
            );
            assert_eq!(
                submitted.lock().unwrap().len(),
                1,
                "one new refusal per invocation"
            );
            // Both single and grouped append must stop after one new refusal.
            // Recreate the client, then preserve a second terminal refusal for
            // two owners to exercise traversal across more than one receipt.
            if owner < 2 {
                drop(custody);
                let (mut next, dispatched) = recording_private_evidence_custody(
                    &profile,
                    &binding,
                    evidence.scope.clone(),
                    schedule,
                );
                let refusal = append_private_evidence_fixture(
                    &mut next, &evidence, &payload, use_batch, deadline_budget,
                )
                .await;
                assert!(
                    matches!(refusal, Err(CustodyError::Rejected)),
                    "second refusal for owner {owner}: {refusal:?}"
                );
                assert_eq!(dispatched.lock().unwrap().len(), 1);
                submitted
                    .lock()
                    .unwrap()
                    .extend(dispatched.lock().unwrap().iter().cloned());
                assert!(next.read(&evidence, deadline_budget).await.unwrap().is_none());
            } else {
                assert!(custody.read(&evidence, deadline_budget).await.unwrap().is_none());
            }
            let batches = submitted.lock().unwrap().clone();
            (evidence, payload, use_batch, batches)
        });
    }
    barrier.wait().await;
    while let Some(result) = rejected.join_next().await {
        originals.push(result.unwrap());
    }
    assert_eq!(originals.len(), workflows);
    assert_eq!(
        transport
            .fixture
            .db
            .engine()
            .generation()
            .unwrap()
            .document_count(),
        0
    );

    // Inspect retained receipts only after all workflow clients have dropped.
    // A second inspector per in-flight owner would test 200 connections against
    // the listener's 128-connection bound, not the required 100 workflows.
    let mut native =
        KasumiBackend::from_installed_profile(&transport.profile_path, &transport.binding).unwrap();
    let mut refused = Vec::new();
    for (evidence, payload, use_batch, batches) in originals {
        let mut receipts = Vec::new();
        for batch in &batches {
            let receipt = native
                .resolve(&evidence.scope, batch, deadline_budget)
                .await
                .unwrap()
                .expect("original refusal must be durable");
            assert_eq!(receipt.request_digest, batch.digest().unwrap());
            assert_eq!(
                receipt.outcome.as_ref().unwrap_err().code,
                kasumi_types::ErrorCode::QuotaExceeded
            );
            receipts.push(receipt);
        }
        refused.push((evidence, payload, use_batch, batches, receipts));
    }
    drop(native);

    // Authorized quota repair changes no evidence, owner identity or receipt.
    transport
        .fixture
        .db
        .administer(transport.context.clone(), Operation::SetLimits(limits))
        .await
        .unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(workflows + 1));
    let mut recovered = tokio::task::JoinSet::new();
    assert_eq!(schedule.active.load(std::sync::atomic::Ordering::SeqCst), 0);
    schedule.peak.store(0, std::sync::atomic::Ordering::SeqCst);
    schedule
        .capacity_retries
        .store(0, std::sync::atomic::Ordering::SeqCst);
    let deadline = tokio::time::Instant::now() + deadline_budget;
    for (evidence, payload, use_batch, batches, receipts) in refused {
        let profile = transport.profile_path.clone();
        let binding = transport.binding.clone();
        let barrier = barrier.clone();
        let schedule = schedule.clone();
        recovered.spawn(async move {
            // No in-memory attempt state survives: choose the successor solely
            // from the authenticated, matching persisted rejection receipts.
            let (mut custody, submitted) = recording_private_evidence_custody(
                &profile,
                &binding,
                evidence.scope.clone(),
                schedule,
            );
            barrier.wait().await;
            let remaining = || deadline.saturating_duration_since(tokio::time::Instant::now());
            assert_eq!(
                append_private_evidence_fixture(
                    &mut custody,
                    &evidence,
                    &payload,
                    use_batch,
                    remaining()
                )
                .await
                .unwrap(),
                AppendOutcome::Recovered,
            );
            let retained = custody.read(&evidence, remaining()).await.unwrap().unwrap();
            assert_eq!(retained.identity, evidence);
            assert_eq!(retained.sha256, hex::encode(Sha256::digest(&payload)));
            assert_eq!(retained.bytes, payload);
            assert_eq!(
                append_private_evidence_fixture(
                    &mut custody,
                    &evidence,
                    &payload,
                    use_batch,
                    remaining()
                )
                .await
                .unwrap(),
                AppendOutcome::AlreadyPresent,
            );
            let sent = submitted.lock().unwrap().clone();
            assert_eq!(sent.len(), if use_batch { 1 } else { 2 });
            assert_ne!(sent[0].idempotency_key, batches[0].idempotency_key);
            assert_eq!(sent[0].operations, batches[0].operations);
            assert_eq!(sent[0].read_set, batches[0].read_set);
            drop(custody);
            (evidence, batches, receipts)
        });
    }
    let began = tokio::time::Instant::now();
    barrier.wait().await;
    let originals = tokio::time::timeout_at(deadline, async {
        let mut completed = Vec::new();
        while let Some(result) = recovered.join_next().await {
            completed.push(result.unwrap());
        }
        completed
    })
    .await
    .unwrap_or_else(|_| {
        panic!("all independent native recovery workflows must finish within {deadline_budget:?}")
    });
    assert_eq!(originals.len(), workflows);
    assert_eq!(
        transport
            .fixture
            .db
            .engine()
            .generation()
            .unwrap()
            .document_count(),
        (2 * workflows) as u64
    );
    let peak_rpcs = schedule.peak.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        (2..=32).contains(&peak_rpcs),
        "RPCs must overlap within the admitted bound"
    );
    assert_eq!(schedule.active.load(std::sync::atomic::Ordering::SeqCst), 0);
    eprintln!(
        "{workflows} real native TLS quota-recovery workflows: {:?}; peak native RPCs: {peak_rpcs}/32; typed server capacity retries: {}",
        began.elapsed(),
        schedule
            .capacity_retries
            .load(std::sync::atomic::Ordering::SeqCst),
    );

    let mut native =
        KasumiBackend::from_installed_profile(&transport.profile_path, &transport.binding).unwrap();
    for (evidence, batches, receipts) in originals {
        for (batch, before) in batches.iter().zip(receipts) {
            assert_eq!(
                native
                    .resolve(&evidence.scope, batch, deadline_budget)
                    .await
                    .unwrap(),
                Some(before),
                "successful recovery must preserve the original terminal refusal",
            );
        }
    }
    drop(native);
    transport.close().await;
}
