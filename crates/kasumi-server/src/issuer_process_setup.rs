//! Isolated installation builder for the physical issuer-crash component.
use super::*;
use anyhow::Context;
use base64::Engine;
use serde_json::json;
use std::{net::TcpListener, path::Path};

fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    private_files::create(path, &serde_json::to_vec_pretty(value)?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native issuer process fixture; requires an owner-only evidence directory"]
async fn provision_original_member_identities() -> Result<()> {
    let directory =
        std::env::var_os("KASUMI_ISSUER_CRASH_DIRECTORY").context("fixture directory missing")?;
    let root = Path::new(&directory);
    private_files::directory_identity(root)?;
    let base = Fixture::with_lease(8000).await?;
    let mut ca = rcgen::CertificateParams::new(vec!["localhost".into()])?;
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let root_key = rcgen::KeyPair::generate()?;
    let root_cert = ca.self_signed(&root_key)?;
    let ca_path = root.join("cluster-ca.pem");
    private_files::create(&ca_path, root_cert.pem().as_bytes())?;
    let issuer = rcgen::Issuer::new(ca, root_key);
    let tls = |name: &str| -> Result<TlsFiles> {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()])?;
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let key = rcgen::KeyPair::generate()?;
        let cert = params.signed_by(&key, &issuer)?;
        let files = TlsFiles {
            certificate: root.join(format!("{name}.pem")),
            private_key: root.join(format!("{name}.key")),
        };
        private_files::create(&files.certificate, cert.pem().as_bytes())?;
        private_files::create(&files.private_key, key.serialize_pem().as_bytes())?;
        Ok(files)
    };
    let member_tls: Vec<_> = (1..=3)
        .map(|id| tls(&format!("member-{id}")))
        .collect::<Result<_>>()?;
    let _provider = tls("jwks")?;
    let listeners: Vec<_> = (0..7)
        .map(|_| TcpListener::bind("127.0.0.1:0"))
        .collect::<std::io::Result<_>>()?;
    let addresses: Vec<_> = listeners
        .iter()
        .map(TcpListener::local_addr)
        .collect::<std::io::Result<_>>()?;
    let jwks_endpoint = format!("https://localhost:{}/jwks", addresses[6].port());
    let jwt = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let public = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(jwt.public_key_raw());
    write_json(
        &root.join("jwks.json"),
        &json!({"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","kid":"physical-issuer","x":public}]}),
    )?;
    let installation = &base.config.installation;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let claims = json!({"sub":"operator","tenant":installation.tenant(),"scope":"kasumi:admin kasumi:read",
        "exp":now+3600,"iat":now,"nbf":now-1,"iss":base.config.auth.issuer,"aud":base.config.auth.audience,
        "kasumi_resource":kasumi_types::CredentialResource::Authority{authority_id:installation.manifest.authority_id,partition:0}});
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    header.kid = Some("physical-issuer".into());
    header.typ = Some("at+jwt".into());
    let token = jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_ed_pem(jwt.serialize_pem().as_bytes())?,
    )?;
    private_files::create(&root.join("operator.jwt"), token.as_bytes())?;
    let first = OperationalSignerConfig::load(
        &base.config.operational_signer_file,
        &installation.manifest.signing_domain(0)?,
    )?;
    let copied = OperationalSignerConfig {
        certificate: first.certificate,
        key_file: root.join("operational.pk8"),
    };
    private_files::create(
        &copied.key_file,
        &private_files::read_trusted(&first.key_file, 4096)?,
    )?;
    write_json(&root.join("operational.json"), &copied)?;
    let peers: Vec<_> = member_tls
        .iter()
        .enumerate()
        .map(|(index, tls)| {
            Ok(ReplicaConfig {
                node_id: (index + 1) as u64,
                endpoint: format!("https://localhost:{}", addresses[index].port()),
                failure_domain: format!("fixture-host-local-{}", index + 1),
                certificate_pins: vec![hex::encode(tls.load()?.certificate_pin())],
            })
        })
        .collect::<Result<_>>()?;
    let voters: BTreeSet<_> = peers.iter().map(|peer| peer.node_id).collect();
    let members: BTreeMap<_, _> = peers
        .iter()
        .map(|peer| {
            (
                peer.node_id,
                AuthorityMember {
                    verifier: base.config.installed_verifiers[&peer.node_id].clone(),
                    endpoint: peer.endpoint.clone(),
                    failure_domain: peer.failure_domain.clone(),
                    certificate_pins: peer.certificate_pins.iter().cloned().collect(),
                },
            )
        })
        .collect();
    let nodes: BTreeSet<_> = peers
        .iter()
        .map(|peer| kasumi_types::NodeIdentity {
            node_id: peer.node_id,
            verifier: base.config.installed_verifiers[&peer.node_id].clone(),
            principal: format!("node-{}", peer.node_id),
            certificate_sha256: peer.certificate_pins[0].clone(),
        })
        .collect();
    let source = Uuid::new_v4();
    let target = kasumi_types::RecoveryTarget {
        incarnation: Uuid::new_v4(),
        nodes: nodes.clone(),
        checkpoint: kasumi_types::FullBackupCheckpoint {
            tenant: "city".into(),
            source_incarnation: source.to_string(),
            revision: 1,
            resident_sha256: "a".repeat(64),
            backup_id: Uuid::new_v4(),
            manifest_ciphertext_sha256: "b".repeat(64),
            key_lineage_digest: "c".repeat(64),
        },
    };
    let command = |action| kasumi_types::AuthorityCommand {
        tenant: "city".into(),
        command_id: Uuid::new_v4(),
        expected_policy_epoch: 1,
        not_after_ms: (now + 3600) * 1000,
        action,
    };
    let enroll = command(kasumi_types::AuthorityAction::Enroll {
        incarnation: source,
        nodes,
    });
    let stop = command(kasumi_types::AuthorityAction::StopTarget {
        source_incarnation: source,
        source_epoch: 1,
        target: target.clone(),
    });
    write_json(
        &root.join("plan.json"),
        &json!({"jwks_port":addresses[6].port(),"enroll":enroll,"stop":stop,"query":kasumi_types::IssuerStopQuery{tenant:"city".into(),command_id:stop.command_id,target_incarnation:target.incarnation},"drain_ms":installation.manifest.drain_ms()?}),
    )?;
    for (index, identity) in member_tls.into_iter().enumerate() {
        let node_id = (index + 1) as u64;
        let member = root.join(format!("node-{node_id}"));
        private_files::create_directory(&member)?;
        let key = |name: &str| -> Result<KeyProviderSettings> {
            let path = member.join(format!("{name}.json"));
            kasumi_store::FileKeyProvider::initialize(&path, name)?;
            Ok(KeyProviderSettings::File { path })
        };
        let mut config = base.config.clone();
        config.database_path = member.join("data/authority.kv");
        config.database_id = Uuid::new_v4();
        config.persistent_disk = crate::persistent_disk::fixture_config(&member.join("data"));
        config.scratch_disk.directory = member.join("scratch");
        config.keys = key("application")?;
        config.custody_keys = key("custody")?;
        config.security_audit.keys = key("security")?;
        config.operational_signer_file = root.join("operational.json");
        config.signer_verifier = SignerVerifierConfig {
            identity: config.installed_verifiers[&node_id].clone(),
            database_path: member.join("data/verifier.kv"),
            keys: key("verifier")?,
            max_background_workers: 64,
        };
        config.replication = ReplicationConfig {
            node_id,
            initial_voters: voters.clone(),
            listener: MutualTlsEndpoint {
                listen: addresses[index],
                tls: identity.clone(),
                client_ca: ca_path.clone(),
                client_certificate_pins: None,
            },
            peers: peers.clone(),
        };
        config.native = MutualTlsEndpoint {
            listen: addresses[3 + index],
            tls: identity,
            client_ca: ca_path.clone(),
            client_certificate_pins: None,
        };
        config.bootstrap.membership = AuthorityMembership {
            voters: voters.clone(),
            members: members.clone(),
        };
        config.auth.source = AuthKeySource::ExternalOAuth {
            jwks_uri: jwks_endpoint.clone(),
            trusted_ca_pem: Some(root_cert.pem()),
        };
        config.validate()?;
        let storage = crate::runtime_memory::RuntimeStorage::isolated_fixture(
            Default::default(),
            &config.persistent_disk,
            &config.scratch_disk,
        )?;
        config.admission = storage.policy().clone();
        InitializeSignerVerifier {
            admission: config.admission.clone(),
            persistent_disk: config.persistent_disk.clone(),
            scratch_disk: config.scratch_disk.clone(),
            verifier: config.signer_verifier.clone(),
            initial_certificates: vec![copied.certificate.clone()],
        }
        .initialize_with_storage(storage)
        .await?;
        write_json(&root.join(format!("member-{node_id}.json")), &config)?;
    }
    Ok(())
}
