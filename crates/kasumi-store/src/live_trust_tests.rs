use super::*;
use kasumi_serving::{
    AuthorityManifest, AuthorityPartition, AuthorityTrust, GenerationSigner,
    InstallationSigningRoot, LeaseClaims, LiveGenerationSigner, NodeIdentity, ServingBoot,
    ServingGate, ServingIdentity, SignedLease, SignerTrustAction, SignerTrustCommand,
};
use kasumi_types::{Action, CredentialResource, RequestAuthorization, RequestContext};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

struct Clock(AtomicU64);
impl LeaseClock for Clock {
    fn now(&self) -> Duration {
        Duration::from_millis(self.0.load(Ordering::SeqCst))
    }
}
struct Administrator {
    allowed: AtomicBool,
    resource: CredentialResource,
}
impl LiveTrustAdministrator for Administrator {
    fn authorize(&self, context: &RequestContext) -> Result<()> {
        ensure!(
            self.allowed.load(Ordering::SeqCst)
                && context.principal == "operator"
                && context.scopes.contains(&Action::Admin)
                && context.authorization.resource() == Some(&self.resource),
            "current administrator and exact resource required"
        );
        Ok(())
    }
}
struct Fixture {
    directory: tempfile::TempDir,
    store: Arc<TenantStore>,
    verifier: TrustVerifierIdentity,
    domain: SigningDomain,
    manifest: AuthorityManifest,
    root: InstallationSigningRoot,
    clock: Arc<Clock>,
    administrator: Arc<Administrator>,
    keys: Vec<rcgen::KeyPair>,
    signers: Vec<GenerationSigner>,
}
impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let manifest = AuthorityManifest {
            authority_id: Uuid::new_v4(),
            partitions: BTreeMap::from([(
                0,
                AuthorityPartition {
                    group: "signing-authority".into(),
                    public_key: hex::encode(root.public_key_raw()),
                },
            )]),
            lifecycle_controls: BTreeMap::new(),
            max_lease_ms: 1000,
            clock_rate_error_ppm: 0,
        };
        let domain = manifest.signing_domain(0).unwrap();
        let root =
            InstallationSigningRoot::from_pkcs8(domain.clone(), &root.serialize_der()).unwrap();
        let keys: Vec<_> = (0..3)
            .map(|_| rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap())
            .collect();
        let signers = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                GenerationSigner::from_pkcs8(
                    root.certify(index as u64 + 1, hex::encode(key.public_key_raw()))
                        .unwrap(),
                    &key.serialize_der(),
                )
                .unwrap()
            })
            .collect();
        let verifier = TrustVerifierIdentity {
            installation_id: Uuid::new_v4(),
            node_id: 1,
        };
        let clock = Arc::new(Clock(AtomicU64::new(0)));
        let store = TenantStore::initialize_catalog_fixture_with_clock_and_access(
            NodeStore::create_new(
                directory.path().join("trust.redb"),
                crate::test_utils::NODE_STORE_ID,
                crate::ScratchDisk::fixture(),
            )
            .unwrap(),
            verifier.tenant(),
            Arc::new(test_utils::LocalKeyProvider::new([51; 32])),
            clock.clone(),
            StorageAccess::live_signer_trust(verifier.clone()).unwrap(),
        )
        .await
        .unwrap();
        let administrator = Arc::new(Administrator {
            allowed: AtomicBool::new(true),
            resource: CredentialResource::Authority {
                authority_id: domain.authority_id,
                partition: 0,
            },
        });
        Self {
            directory,
            store,
            verifier,
            domain,
            manifest,
            root,
            clock,
            administrator,
            keys,
            signers,
        }
    }
    fn context(&self) -> RequestContext {
        let clock = kasumi_clock::EpochClock::system().unwrap();
        RequestContext {
            tenant: self.verifier.tenant(),
            principal: "operator".into(),
            request_id: Uuid::new_v4().to_string(),
            scopes: BTreeSet::from([Action::Admin]),
            authorization: RequestAuthorization::from_verified_credential(
                clock.now_ms().unwrap() + 120_000,
                &clock.observe().unwrap(),
                self.administrator.resource.clone(),
            )
            .unwrap(),
        }
    }
    fn initialize(&self) -> Arc<LiveSignerTrust> {
        self.store
            .initialize_live_signer_trust(
                &self.verifier,
                self.signers[0].certificate().clone(),
                self.administrator.clone(),
            )
            .unwrap()
    }
    fn open(&self) -> Arc<LiveSignerTrust> {
        self.store
            .open_live_signer_trust(
                &self.verifier,
                self.domain.clone(),
                self.administrator.clone(),
            )
            .unwrap()
    }
    fn command(&self, trust: &LiveSignerTrust, action: SignerTrustAction) -> SignerTrustCommand {
        SignerTrustCommand {
            operation_id: Uuid::new_v4(),
            expected_revision: trust.current().unwrap().revision,
            not_after_ms: u64::MAX,
            action,
        }
    }
    fn stage(&self, trust: &LiveSignerTrust) -> SignerTrustCommand {
        let command = self.command(
            trust,
            SignerTrustAction::Stage {
                certificate: self.signers[1].certificate().clone(),
            },
        );
        trust.administer(&self.context(), command.clone()).unwrap();
        command
    }
    fn activation(
        &self,
        trust: &LiveSignerTrust,
        stage: &SignerTrustCommand,
    ) -> SignerTrustCommand {
        self.command(
            trust,
            SignerTrustAction::Activate {
                staged_operation_id: stage.operation_id,
                certificate_sha256: self.signers[1].certificate().digest().unwrap(),
            },
        )
    }
    async fn reopen(&mut self) {
        self.store.shutdown().await;
        // The closed old owner may remain referenced. Its capability can never
        // become live when the new store installs its own fresh clock witness.
        self.store = TenantStore::open_existing_fixture_with_clock_and_access(
            self.store.node.clone(),
            self.verifier.tenant(),
            Arc::new(test_utils::LocalKeyProvider::new([51; 32])),
            self.clock.clone(),
            StorageAccess::live_signer_trust(self.verifier.clone()).unwrap(),
        )
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn exact_live_generation_rejects_historical_and_reused_key_forgery() {
    let f = Fixture::new().await;
    let trust = f.initialize();
    assert!(Arc::ptr_eq(&trust, &f.open()));
    assert!(
        f.store
            .initialize_live_signer_trust(
                &f.verifier,
                f.signers[0].certificate().clone(),
                f.administrator.clone()
            )
            .is_err()
    );
    let old = f.signers[0].sign("lease", &"original-attempt").unwrap();
    let old_fence = trust
        .verify_live("lease", &"original-attempt", &old)
        .unwrap();
    let before_stage = trust.observe().unwrap();
    let mut notices = old_fence.notifications();
    let stage = f.stage(&trust);
    assert!(before_stage.check().is_err());
    old_fence.check().unwrap();
    assert!(!notices.has_changed().unwrap());
    let mut signature_alias = f.signers[1].certificate().clone();
    signature_alias.root_signature = signature_alias.root_signature.to_ascii_uppercase();
    assert!(signature_alias.verify(&f.domain).is_err());
    let next = f.signers[1].sign("lease", &"next-attempt").unwrap();
    trust
        .historical()
        .verify("lease", &"next-attempt", &next)
        .unwrap();
    assert!(trust.verify_live("lease", &"next-attempt", &next).is_err());
    let activation = f.activation(&trust, &stage);
    // A valid old signature over an activation command cannot authorize its
    // administrative mutation. Current credential/resource policy remains required.
    let forged_activation = f.signers[0].sign("activate", &activation).unwrap();
    trust
        .historical()
        .verify("activate", &activation, &forged_activation)
        .unwrap();
    f.administrator.allowed.store(false, Ordering::SeqCst);
    assert!(trust.administer(&f.context(), activation.clone()).is_err());
    assert_eq!(trust.current().unwrap().active.identity.generation, 1);
    f.administrator.allowed.store(true, Ordering::SeqCst);
    let receipt = trust.administer(&f.context(), activation.clone()).unwrap();
    let observed = trust.observe().unwrap();
    assert_eq!(observed.record().revision, receipt.revision);
    observed.check().unwrap();
    notices.changed().await.unwrap();
    assert_eq!(*notices.borrow_and_update(), 2);
    assert!(old_fence.check().is_err());
    assert!(
        trust
            .verify_live("lease", &"original-attempt", &old)
            .is_err()
    );
    trust
        .historical()
        .verify("lease", &"original-attempt", &old)
        .unwrap();
    trust
        .verify_live("lease", &"next-attempt", &next)
        .unwrap()
        .check()
        .unwrap();
    assert_eq!(
        trust.administer(&f.context(), activation.clone()).unwrap(),
        receipt
    );
    let mut changed = activation.clone();
    changed.expected_revision += 1;
    assert!(trust.administer(&f.context(), changed).is_err());
    f.clock.0.store(1000, Ordering::SeqCst);
    let complete = f.command(
        &trust,
        SignerTrustAction::CompleteRetirement {
            activation_operation_id: activation.operation_id,
        },
    );
    trust.administer(&f.context(), complete).unwrap();
    assert!(observed.check().is_err());
    let reused = f
        .root
        .certify(3, hex::encode(f.keys[0].public_key_raw()))
        .unwrap();
    assert!(
        f.root
            .certify(
                3,
                hex::encode(f.keys[0].public_key_raw()).to_ascii_uppercase()
            )
            .is_err()
    );
    let compromised =
        GenerationSigner::from_pkcs8(reused.clone(), &f.keys[0].serialize_der()).unwrap();
    let forged = compromised.sign("lease", &"fresh-forgery").unwrap();
    trust
        .historical()
        .verify("lease", &"fresh-forgery", &forged)
        .unwrap();
    assert!(
        trust
            .verify_live("lease", &"fresh-forgery", &forged)
            .is_err()
    );
    let stage_reused = f.command(
        &trust,
        SignerTrustAction::Stage {
            certificate: reused,
        },
    );
    assert!(trust.administer(&f.context(), stage_reused).is_err());
    assert!(old_fence.check().is_err());
    f.store.shutdown().await;
    let raw = std::fs::read(f.directory.path().join("trust.redb")).unwrap();
    assert!(
        !raw.windows(f.domain.manifest_sha256.len())
            .any(|bytes| bytes == f.domain.manifest_sha256.as_bytes())
    );
}

#[tokio::test]
async fn encrypted_restart_and_clock_regression_restart_the_complete_retirement_drain() {
    let mut f = Fixture::new().await;
    let trust = f.initialize();
    let stage = f.stage(&trust);
    let activation = f.activation(&trust, &stage);
    trust.administer(&f.context(), activation.clone()).unwrap();
    let signature = f.signers[1].sign("lease", &"current").unwrap();
    let held = trust.verify_live("lease", &"current", &signature).unwrap();
    f.clock.0.store(900, Ordering::SeqCst);
    f.reopen().await;
    assert!(held.check().is_err());
    let fresh = f.open();
    assert!(!Arc::ptr_eq(&trust, &fresh));
    let completion = f.command(
        &fresh,
        SignerTrustAction::CompleteRetirement {
            activation_operation_id: activation.operation_id,
        },
    );
    f.clock.0.store(1899, Ordering::SeqCst);
    assert!(fresh.administer(&f.context(), completion.clone()).is_err());
    f.clock.0.store(1800, Ordering::SeqCst);
    assert!(fresh.administer(&f.context(), completion.clone()).is_err());
    assert!(fresh.is_closed());
    let restarted = f.open();
    f.clock.0.store(2799, Ordering::SeqCst);
    assert!(
        restarted
            .administer(&f.context(), completion.clone())
            .is_err()
    );
    f.clock.0.store(2800, Ordering::SeqCst);
    let receipt = restarted
        .administer(&f.context(), completion.clone())
        .unwrap();
    assert!(!receipt.retirement_pending);
    assert!(held.check().is_err());
    f.reopen().await;
    let reopened = f.open();
    assert_eq!(
        reopened
            .status(&f.context(), completion.operation_id)
            .unwrap(),
        Some(receipt)
    );
    assert_eq!(reopened.current().unwrap().active.identity.generation, 2);
    assert!(
        reopened
            .verify_live("lease", &"current", &signature)
            .is_ok()
    );
    f.store.shutdown().await;
}

struct LostReply {
    persistence: EncryptedTrust,
    lose: AtomicBool,
}
impl LiveTrustPersistence for LostReply {
    fn check_access(&self) -> Result<()> {
        self.persistence.check_access()
    }
    fn load(&self) -> Result<LocalSignerTrustRecord> {
        self.persistence.load()
    }
    fn receipt(&self, id: Uuid) -> Result<Option<SignerTrustReceipt>> {
        self.persistence.receipt(id)
    }
    fn key_use(&self, key: &str) -> Result<Option<SignerKeyUse>> {
        self.persistence.key_use(key)
    }
    fn commit(
        &self,
        previous: &LocalSignerTrustRecord,
        next: &LocalSignerTrustRecord,
        receipt: &SignerTrustReceipt,
    ) -> Result<()> {
        self.persistence.commit(previous, next, receipt)?;
        ensure!(
            !self.lose.swap(false, Ordering::SeqCst),
            "injected reply loss after durable publication"
        );
        Ok(())
    }
}

#[tokio::test]
async fn uncertain_activation_closes_old_owner_and_exact_receipt_recovers_from_encrypted_state() {
    let f = Fixture::new().await;
    let initialized = f.initialize();
    let stage = f.stage(&initialized);
    let activation = f.activation(&initialized, &stage);
    initialized.close();
    let persistence = Arc::new(LostReply {
        persistence: f.store.trust_persistence(&f.verifier, &f.domain).unwrap(),
        lose: AtomicBool::new(true),
    });
    let trust = LiveSignerTrust::open(
        &f.verifier,
        f.domain.clone(),
        persistence,
        f.administrator.clone(),
        f.clock.clone(),
    )
    .unwrap();
    let old = f.signers[0].sign("lease", &"old").unwrap();
    let held = trust.verify_live("lease", &"old", &old).unwrap();
    assert!(trust.administer(&f.context(), activation.clone()).is_err());
    assert!(trust.is_closed());
    assert!(held.check().is_err());
    assert!(trust.verify_live("lease", &"old", &old).is_err());
    let reopened = f.open();
    assert_eq!(reopened.current().unwrap().active.identity.generation, 2);
    let exact = reopened
        .administer(&f.context(), activation.clone())
        .unwrap();
    assert_eq!(exact.command, activation);
    assert_eq!(exact.active_generation, 2);
    assert!(exact.retirement_pending);
    assert!(held.check().is_err());
    f.administrator.allowed.store(false, Ordering::SeqCst);
    assert!(
        reopened
            .status(&f.context(), activation.operation_id)
            .is_err()
    );
    f.store.shutdown().await;
}

#[tokio::test]
async fn stopped_stage_and_new_admin_requests_preserve_original_identity_and_reject_format_fallback()
 {
    let f = Fixture::new().await;
    let trust = f.initialize();
    let stage = f.stage(&trust);
    let stop = f.command(
        &trust,
        SignerTrustAction::StopStage {
            staged_operation_id: stage.operation_id,
        },
    );
    let stopped = trust.administer(&f.context(), stop.clone()).unwrap();
    assert!(trust.current().unwrap().staged.is_none());
    assert_eq!(trust.administer(&f.context(), stop).unwrap(), stopped);
    let stage_again = f.command(
        &trust,
        SignerTrustAction::Stage {
            certificate: f.signers[1].certificate().clone(),
        },
    );
    trust.administer(&f.context(), stage_again.clone()).unwrap();
    assert!(
        trust
            .administer(&f.context(), f.activation(&trust, &stage))
            .is_err()
    );
    let mut bad_context = f.context();
    bad_context.authorization = RequestAuthorization::service_identity();
    assert!(
        trust
            .administer(&bad_context, f.activation(&trust, &stage_again))
            .is_err()
    );
    assert!(
        f.store
            .open_live_signer_trust(
                &f.verifier,
                f.domain.clone(),
                Arc::new(Administrator {
                    allowed: AtomicBool::new(true),
                    resource: f.administrator.resource.clone(),
                })
            )
            .is_err()
    );
    trust.close();
    let key = f.domain.digest().unwrap();
    let bytes = f.store.get(NS, key.as_bytes()).unwrap().unwrap();
    let mut bad: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    bad["format"] = serde_json::json!(0);
    f.store
        .write_batch(&[WriteOp::put(
            NS,
            key.as_bytes(),
            serde_json::to_vec(&bad).unwrap(),
        )])
        .unwrap();
    assert!(
        f.store
            .open_live_signer_trust(&f.verifier, f.domain.clone(), f.administrator.clone())
            .is_err()
    );
    f.store
        .write_batch(&[WriteOp::put(NS, key.as_bytes(), bytes)])
        .unwrap();
    assert_eq!(f.open().current().unwrap().revision, 3);
    f.store.shutdown().await;
}

#[tokio::test]
async fn complete_file_reopen_retains_exact_trust_and_permanent_key_bindings() {
    let f = Fixture::new().await;
    let trust = f.initialize();
    let stage = f.stage(&trust);
    let activation = f.activation(&trust, &stage);
    let expected = trust.administer(&f.context(), activation.clone()).unwrap();
    let context = f.context();
    let Fixture {
        directory,
        store,
        verifier,
        domain,
        administrator,
        ..
    } = f;
    trust.close();
    drop(trust);
    store.shutdown().await;
    drop(store);
    let reopened = TenantStore::open_existing(
        NodeStore::open_existing(
            directory.path().join("trust.redb"),
            crate::test_utils::NODE_STORE_ID,
            crate::ScratchDisk::fixture(),
        )
        .unwrap(),
        verifier.tenant(),
        Arc::new(test_utils::LocalKeyProvider::new([51; 32])),
        StorageAccess::live_signer_trust(verifier.clone()).unwrap(),
    )
    .await
    .unwrap();
    let trust = reopened
        .open_live_signer_trust(&verifier, domain, administrator)
        .unwrap();
    assert_eq!(trust.administer(&context, activation).unwrap(), expected);
    assert_eq!(trust.current().unwrap().active.identity.generation, 2);
    assert!(trust.current().unwrap().retirement.is_some());
    assert!(
        reopened
            .open_live_signer_trust(
                &TrustVerifierIdentity {
                    installation_id: verifier.installation_id,
                    node_id: 2
                },
                trust.historical().domain().clone(),
                Arc::new(Administrator {
                    allowed: AtomicBool::new(true),
                    resource: context.authorization.resource().unwrap().clone(),
                }),
            )
            .is_err()
    );
    reopened.shutdown().await;
}

#[tokio::test]
async fn issuance_and_encoded_response_require_the_exact_active_signer_owner() {
    let f = Fixture::new().await;
    let trust = f.initialize();
    let signer = |index: usize, trust: Arc<LiveSignerTrust>| {
        LiveGenerationSigner::install(
            GenerationSigner::from_pkcs8(
                f.signers[index].certificate().clone(),
                &f.keys[index].serialize_der(),
            )
            .unwrap(),
            trust,
        )
    };
    assert!(signer(1, trust.clone()).is_err());
    let old = signer(0, trust.clone()).unwrap();
    let pending = old.sign("lease", &"original-attempt").unwrap();
    pending.check().unwrap();
    trust
        .historical()
        .verify("lease", &"original-attempt", pending.signature())
        .unwrap();
    let stage = f.stage(&trust);
    assert!(signer(1, trust.clone()).is_err());
    old.sign("lease", &"still-current")
        .unwrap()
        .check()
        .unwrap();
    let activation = f.activation(&trust, &stage);
    trust.administer(&f.context(), activation.clone()).unwrap();
    assert!(old.check().is_err());
    assert!(old.sign("lease", &"retired-forgery").is_err());
    assert!(pending.check().is_err());
    // The same bytes can still verify a retained proof, never a new live reply.
    trust
        .historical()
        .verify("lease", &"original-attempt", pending.signature())
        .unwrap();
    let current = signer(1, trust.clone()).unwrap();
    let new_pending = current.sign("lease", &"new-attempt").unwrap();
    trust.administer(&f.context(), activation).unwrap();
    new_pending.check().unwrap();
    assert!(pending.check().is_err());
    trust.close();
    assert!(new_pending.check().is_err());
    assert!(current.sign("lease", &"closed-owner").is_err());
    let reopened = f.open();
    let fresh = signer(1, reopened.clone()).unwrap();
    fresh
        .sign("lease", &"fresh-owner")
        .unwrap()
        .check()
        .unwrap();
    assert!(signer(0, reopened).is_err());
    assert!(new_pending.check().is_err());
    assert!(current.check().is_err());
    f.store.shutdown().await;
    assert!(fresh.sign("lease", &"closed-storage").is_err());
}

#[tokio::test]
async fn encrypted_current_generation_fences_lease_admission_and_retained_responses() {
    let mut f = Fixture::new().await;
    let owner = f.initialize();
    let historical = AuthorityTrust::install(f.manifest.clone()).unwrap();
    let identity = ServingIdentity {
        tenant: "city".into(),
        incarnation: Uuid::new_v4(),
        authority_epoch: 1,
        node: NodeIdentity {
            node_id: 1,
            verifier: f.verifier.clone(),
            principal: "data-1".into(),
            certificate_sha256: "ab".repeat(32),
        },
    };
    // A correctly installed root and root-certified key are historical trust only.
    assert!(
        ServingBoot::with_test_clock(historical.clone(), identity.clone(), f.clock.clone())
            .is_err()
    );
    let installed = historical
        .with_live_verifiers(BTreeMap::from([(0, owner.clone())]))
        .unwrap();
    let boot = ServingBoot::with_test_clock(installed, identity.clone(), f.clock.clone()).unwrap();
    let signed = |generation: usize, attempt: &kasumi_serving::LeaseAttempt| {
        let claims = LeaseClaims {
            request: attempt.request().clone(),
            authority_id: f.manifest.authority_id,
            partition: 0,
            authority_term: 1,
            authority_revision: 1,
            lifetime_ms: 1000,
            credential_lifetime_ms: 1000,
            activation_digest: "cd".repeat(32),
            recovery_checkpoint: None,
        };
        SignedLease {
            signature: f.signers[generation]
                .sign("kasumi.serving-lease.v1", &claims)
                .unwrap(),
            claims,
        }
    };
    let original = boot.begin_acquisition().unwrap();
    let wire = signed(0, &original);
    let lease = original.verify(wire.clone()).unwrap();
    let gate = ServingGate::new(lease.clone()).unwrap();
    let response = gate.capture().unwrap();
    let stage = f.stage(&owner);
    assert!(original.verify(signed(1, &original)).is_err());
    original.verify(wire.clone()).unwrap();
    f.clock.0.store(500, Ordering::SeqCst);
    let activation = f.activation(&owner, &stage);
    owner.administer(&f.context(), activation).unwrap();
    assert!(lease.check().is_err());
    assert!(response.check().is_err());
    assert!(original.verify(wire.clone()).is_err());
    owner
        .historical()
        .verify("kasumi.serving-lease.v1", &wire.claims, &wire.signature)
        .unwrap();
    let attempt = boot.begin_acquisition().unwrap();
    // A retired private key cannot mint a new nonce or boot into live admission.
    assert!(attempt.verify(signed(0, &attempt)).is_err());
    let next_wire = signed(1, &attempt);
    let next = attempt.verify(next_wire.clone()).unwrap();
    assert_eq!(next.remaining().unwrap(), Duration::from_millis(1000));
    assert!(gate.renew(next.clone()).is_err());
    let fresh_gate = ServingGate::new(next).unwrap();
    let mut old_format = serde_json::to_value(next_wire).unwrap();
    old_format["signature"] = serde_json::Value::String("00".repeat(64));
    assert!(serde_json::from_value::<SignedLease>(old_format).is_err());
    f.clock.0.store(1500, Ordering::SeqCst);
    assert!(fresh_gate.check().is_err());
    assert!(attempt.verify(signed(1, &attempt)).is_err());
    f.reopen().await;
    let reopened = f.open();
    assert_eq!(reopened.current().unwrap().active.identity.generation, 2);
    assert!(owner.current().is_err());
    assert!(response.check().is_err());
    f.store.shutdown().await;
}
