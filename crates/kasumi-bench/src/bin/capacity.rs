//! Bounded native corpus loading and exhaustive verification against an installed
//! production service. Original commands are journaled before dispatch; failures
//! stop the run without automatic mutation retry or a fabricated success.
use anyhow::{Context, Result, ensure};
use kasumi_client::proto;
use kasumi_transport::{
    TlsIdentity,
    credentials::{CredentialSource, FileCredentialSource, token},
    grpc_channel,
};
use kasumi_types::{Mutation, MutationBatch, Precondition};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_BATCH_BYTES: usize = 4 << 20;
const MAX_DOCUMENT_BYTES: usize = 1 << 20;
const MAX_BATCH_DOCUMENTS: usize = 256;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    endpoint: String,
    ca_pem: PathBuf,
    client_certificate_pem: PathBuf,
    client_private_key_pem: PathBuf,
    server_certificate_sha256: String,
    token_file: PathBuf,
    timeout_ms: u64,
    corpus: Corpus,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    run_id: Uuid,
    /// Public deterministic corpus seed, not an authentication secret.
    seed_sha256: String,
    collection: String,
    documents: u64,
    document_bytes: usize,
    batch_documents: usize,
}

impl Corpus {
    fn validate(&self) -> Result<u64> {
        kasumi_types::validate_name(&self.collection)?;
        kasumi_types::validate_sha256(&self.seed_sha256)?;
        ensure!(!self.run_id.is_nil(), "corpus run identity is required");
        ensure!(self.documents > 0, "corpus is empty");
        ensure!(
            (128..=MAX_DOCUMENT_BYTES).contains(&self.document_bytes),
            "document size outside work limit"
        );
        ensure!(
            (1..=MAX_BATCH_DOCUMENTS).contains(&self.batch_documents),
            "batch count outside work limit"
        );
        // Reserve per-operation framing including the maximum ordinal/ID widths.
        ensure!(
            self.document_bytes
                .checked_add(2048)
                .and_then(|n| n.checked_mul(self.batch_documents))
                .is_some_and(|n| n <= MAX_BATCH_BYTES),
            "batch exceeds bounded workspace"
        );
        self.documents
            .checked_mul(self.document_bytes as u64)
            .context("corpus aggregate byte count overflows u64")
    }

    fn id(&self, ordinal: u64) -> String {
        format!("capacity-{}-{ordinal}", self.run_id.simple())
    }

    fn document(&self, ordinal: u64) -> Result<Value> {
        ensure!(ordinal < self.documents, "corpus ordinal out of range");
        let mut value = json!({"ordinal":ordinal,"payload":"","version":0});
        let overhead = serde_json::to_vec(&value)?.len();
        let length = self
            .document_bytes
            .checked_sub(overhead)
            .context("document framing exceeds configured size")?;
        // Uniform rejection sampling over all printable ASCII except JSON's
        // quote and backslash. There is no repeated compressible filler and no
        // entropy claim beyond this precisely reported generator.
        let alphabet = (b'!'..=b'~')
            .filter(|c| !matches!(c, b'"' | b'\\'))
            .collect::<Vec<_>>();
        let seed = hex::decode(&self.seed_sha256)?;
        let mut payload = String::with_capacity(length);
        let mut counter = 0u64;
        while payload.len() < length {
            let mut hash = Sha256::new();
            hash.update(b"kasumi-capacity-corpus-v1\0");
            hash.update(&seed);
            hash.update(ordinal.to_be_bytes());
            hash.update(counter.to_be_bytes());
            counter = counter
                .checked_add(1)
                .context("corpus block counter overflow")?;
            for byte in hash.finalize() {
                if byte < 184 {
                    payload.push(alphabet[usize::from(byte) % 92] as char);
                    if payload.len() == length {
                        break;
                    }
                }
            }
        }
        value["payload"] = Value::String(payload);
        ensure!(
            serde_json::to_vec(&value)?.len() == self.document_bytes,
            "generated document length differs"
        );
        Ok(value)
    }

    fn batch(&self, first: u64) -> Result<(MutationBatch, u64)> {
        ensure!(first < self.documents, "batch starts after corpus end");
        let count = (self.documents - first).min(self.batch_documents as u64);
        let mut operations = Vec::with_capacity(count as usize);
        for ordinal in first..first + count {
            operations.push(Mutation::Put {
                collection: self.collection.clone(),
                id: self.id(ordinal),
                body: self.document(ordinal)?,
                expected: Precondition::Absent,
            });
        }
        let batch = MutationBatch {
            idempotency_key: format!("capacity-{}-{first}", self.run_id.simple()),
            operations,
            read_set: vec![],
        };
        ensure!(
            serde_json::to_vec(&batch)?.len() <= MAX_BATCH_BYTES,
            "encoded batch exceeds request work limit"
        );
        Ok((batch, count))
    }
}

fn bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() <= maximum as u64,
        "input file exceeds limit or is not regular"
    );
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= maximum, "input file grew beyond limit");
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn validate_receipt(
    corpus: &Corpus,
    first: u64,
    count: u64,
    receipt: &proto::WriteReceipt,
) -> Result<()> {
    let collection = corpus.collection.replace('~', "~0").replace('/', "~1");
    ensure!(
        receipt.revision > 0
            && receipt.versions.len() == count as usize
            && (first..first + count).all(|ordinal| receipt
                .versions
                .get(&format!("/{collection}/{}", corpus.id(ordinal)))
                == Some(&receipt.revision)),
        "native receipt differs from the exact original batch documents"
    );
    Ok(())
}

fn resolve(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.into()
    } else {
        root.join(path)
    }
}

fn request<T>(
    value: T,
    credentials: &FileCredentialSource,
    timeout: Duration,
) -> Result<tonic::Request<T>> {
    // Anchor the deadline before reading a renewable file. Reading a new token
    // can affect the next invocation only; no retry extends this one.
    let started = Instant::now();
    let bearer = token(credentials)?;
    let authorization = Zeroizing::new(format!("Bearer {}", bearer.as_str()));
    let mut request = tonic::Request::new(value);
    request.metadata_mut().insert(
        "authorization",
        authorization.parse().context("invalid bearer header")?,
    );
    let remaining = timeout
        .checked_sub(started.elapsed())
        .context("credential read consumed request deadline")?;
    request.set_timeout(remaining);
    Ok(request)
}

struct Journal {
    directory: PathBuf,
    events: File,
}
impl Journal {
    fn create(
        directory: &Path,
        config: &Configuration,
        config_sha256: &str,
        mode: &str,
        total: u64,
    ) -> Result<Self> {
        ensure!(
            directory.is_absolute(),
            "evidence directory must be absolute"
        );
        std::fs::DirBuilder::new().mode(0o700).create(directory)?;
        File::open(
            directory
                .parent()
                .context("evidence directory has no parent")?,
        )?
        .sync_all()?;
        let events = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("events.jsonl"))?;
        let mut journal = Self {
            directory: directory.into(),
            events,
        };
        let mut executable = File::open(std::env::current_exe()?)?;
        let mut hash = Sha256::new();
        std::io::copy(&mut executable, &mut hash)?;
        journal.event(json!({"event":"started","format":1,"mode":mode,"configuration_sha256":config_sha256,
            "corpus":config.corpus,"expected_canonical_bytes":total,"endpoint":config.endpoint,
            "executable_sha256":hex::encode(hash.finalize()),"os":std::env::consts::OS,
            "architecture":std::env::consts::ARCH,"generator":"SHA256 counter; uniform 92-character printable ASCII payload; exact canonical JSON lengths",
            "scope":"Installed native service load and individual point-read integrity; not a coherent concurrent snapshot, node capacity certificate, latency benchmark or compressibility measurement. No automatic retries."}))?;
        File::open(directory)?.sync_all()?;
        Ok(journal)
    }
    fn event(&mut self, value: Value) -> Result<()> {
        serde_json::to_writer(&mut self.events, &value)?;
        self.events.write_all(b"\n")?;
        self.events.sync_all()?;
        Ok(())
    }
    fn pending(&self, bytes: &[u8]) -> Result<()> {
        // A single bounded exact request remains available if its response or
        // local result publication is lost. The journal names its original key.
        let mut staged = tempfile::NamedTempFile::new_in(&self.directory)?;
        staged.write_all(bytes)?;
        staged.as_file().sync_all()?;
        staged.persist(self.directory.join("last-original-batch.json"))?;
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}

async fn run(
    config: &Configuration,
    root: &Path,
    config_sha256: &str,
    mode: &str,
    original: Option<&str>,
    journal: &mut Journal,
) -> Result<()> {
    let credentials = FileCredentialSource::new(resolve(root, &config.token_file))?;
    let key = FileCredentialSource::new(resolve(root, &config.client_private_key_pem))?.load()?;
    let identity = TlsIdentity::from_pem(
        &bounded(&resolve(root, &config.client_certificate_pem), 1 << 20)?,
        key.as_bytes(),
    )?;
    let pin: [u8; 32] = hex::decode(&config.server_certificate_sha256)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid certificate pin"))?;
    let ca = bounded(&resolve(root, &config.ca_pem), 1 << 20)?;
    let channel = grpc_channel(&config.endpoint, &identity, &ca, BTreeSet::from([pin])).await?;
    let mut client = proto::kasumi_data_client::KasumiDataClient::new(channel)
        .max_encoding_message_size(MAX_BATCH_BYTES + (64 << 10))
        .max_decoding_message_size(MAX_DOCUMENT_BYTES + (64 << 10));
    let timeout = Duration::from_millis(config.timeout_ms);
    if let Some(original) = original {
        let original = Path::new(original);
        ensure!(
            original.is_absolute(),
            "original evidence directory must be absolute"
        );
        let events = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(original.join("events.jsonl"))?;
        ensure!(
            events.metadata()?.is_file(),
            "original journal must be regular"
        );
        let mut first_event = Vec::new();
        BufReader::new(events.take(128 << 10)).read_until(b'\n', &mut first_event)?;
        ensure!(
            first_event.last() == Some(&b'\n'),
            "original journal header exceeds limit or is incomplete"
        );
        let header: Value = serde_json::from_slice(&first_event)?;
        ensure!(
            header["event"] == "started"
                && header["mode"] == "load"
                && header["configuration_sha256"] == config_sha256,
            "original connection and corpus configuration differ"
        );
        let bytes = bounded(&original.join("last-original-batch.json"), MAX_BATCH_BYTES)?;
        let batch: MutationBatch = serde_json::from_slice(&bytes)?;
        let first: u64 = batch
            .idempotency_key
            .rsplit('-')
            .next()
            .context("original batch key absent")?
            .parse()?;
        let (expected, count) = config.corpus.batch(first)?;
        ensure!(
            serde_json::to_vec(&expected)? == bytes,
            "original batch differs from the exact configured corpus"
        );
        let response = client
            .receipt(request(
                proto::ReceiptRequest {
                    idempotency_key: batch.idempotency_key.clone(),
                },
                &credentials,
                timeout,
            )?)
            .await?
            .into_inner();
        let outcome = match response.outcome {
            Some(proto::receipt_response::Outcome::Committed(receipt)) => {
                validate_receipt(&config.corpus, first, count, &receipt)?;
                json!({"kind":"committed","revision":receipt.revision,"versions":receipt.versions})
            }
            Some(proto::receipt_response::Outcome::Rejected(error)) => {
                json!({"kind":"rejected","code":error.code})
            }
            None => {
                json!({"kind":"unknown","message":"No retained original receipt. This is not proof that the mutation never committed."})
            }
        };
        journal.event(
            json!({"event":"original_receipt_observed","idempotency_key":batch.idempotency_key,
            "batch_sha256":digest(&bytes),"outcome":outcome}),
        )?;
        return Ok(());
    }
    if mode == "load" {
        let mut first = 0u64;
        while first < config.corpus.documents {
            let (batch, count) = config.corpus.batch(first)?;
            let bytes = serde_json::to_vec(&batch)?;
            let key = batch.idempotency_key.clone();
            journal.pending(&bytes)?;
            journal.event(
                json!({"event":"prepared","first":first,"count":count,"idempotency_key":key,
                "batch_sha256":digest(&bytes),"batch_bytes":bytes.len()}),
            )?;
            let started = Instant::now();
            let receipt = client
                .mutate(request(
                    proto::MutateRequest { batch_json: bytes },
                    &credentials,
                    timeout,
                )?)
                .await?
                .into_inner();
            validate_receipt(&config.corpus, first, count, &receipt)?;
            journal.event(json!({"event":"committed","first":first,"count":count,"idempotency_key":key,
                "revision":receipt.revision,"versions":receipt.versions,"seconds":started.elapsed().as_secs_f64()}))?;
            first = first.checked_add(count).context("load progress overflow")?;
        }
        journal.event(json!({"event":"load_completed","documents":config.corpus.documents}))?;
    }
    let mut expected = Sha256::new();
    let mut observed = Sha256::new();
    let mut total = 0u64;
    for ordinal in 0..config.corpus.documents {
        let id = config.corpus.id(ordinal);
        let response = client
            .get(request(
                proto::GetRequest {
                    collection: config.corpus.collection.clone(),
                    id: id.clone(),
                },
                &credentials,
                timeout,
            )?)
            .await?
            .into_inner();
        ensure!(
            response.id == id && response.version > 0,
            "native document identity differs"
        );
        let actual: Value = serde_json::from_slice(&response.body_json)?;
        let wanted = config.corpus.document(ordinal)?;
        ensure!(
            actual == wanted,
            "corpus integrity mismatch at ordinal {ordinal}"
        );
        let actual = serde_json::to_vec(&actual)?;
        let wanted = serde_json::to_vec(&wanted)?;
        for (hasher, bytes) in [(&mut expected, &wanted), (&mut observed, &actual)] {
            hasher.update(ordinal.to_be_bytes());
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        }
        total = total
            .checked_add(actual.len() as u64)
            .context("verified byte count overflow")?;
        if (ordinal + 1).is_multiple_of(config.corpus.batch_documents as u64)
            || ordinal + 1 == config.corpus.documents
        {
            journal.event(
                json!({"event":"verified_prefix","documents":ordinal+1,"canonical_bytes":total}),
            )?;
        }
    }
    let expected = hex::encode(expected.finalize());
    let observed = hex::encode(observed.finalize());
    ensure!(
        expected == observed && total == config.corpus.validate()?,
        "verified corpus aggregate differs"
    );
    journal.event(
        json!({"event":"passed","documents":config.corpus.documents,"canonical_bytes":total,
        "expected_sha256":expected,"observed_sha256":observed}),
    )?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let [configuration, mode, output, flags @ ..] = args.as_slice() else {
        anyhow::bail!(
            "usage: kasumi-bench-capacity <config.json> load|verify|resolve <new-absolute-evidence-directory> [--allow-writes | original-evidence-directory]"
        );
    };
    ensure!(
        (mode == "load" && flags == ["--allow-writes"])
            || (mode == "verify" && flags.is_empty())
            || (mode == "resolve" && flags.len() == 1),
        "load requires --allow-writes; verify accepts no flags; resolve requires the original evidence directory"
    );
    let path = Path::new(configuration).canonicalize()?;
    let bytes = bounded(&path, 128 << 10)?;
    let config: Configuration = serde_json::from_slice(&bytes)?;
    let total = config.corpus.validate()?;
    ensure!(
        (1..=30_000).contains(&config.timeout_ms),
        "request timeout must be in 1..30000 milliseconds"
    );
    kasumi_types::validate_sha256(&config.server_certificate_sha256)?;
    let config_sha256 = digest(&bytes);
    let mut journal = Journal::create(Path::new(output), &config, &config_sha256, mode, total)?;
    let original = (mode == "resolve").then(|| flags[0].as_str());
    let result = run(
        &config,
        path.parent().context("configuration parent missing")?,
        &config_sha256,
        mode,
        original,
        &mut journal,
    )
    .await;
    if let Err(error) = &result {
        let code = error
            .downcast_ref::<tonic::Status>()
            .map(|s| format!("{:?}", s.code()));
        // Transport/provider diagnostics can include request values. Retain a
        // bounded structural failure marker and the exact original request file.
        journal.event(json!({"event":"failed","transport_code":code,"message":"Run stopped; retain the last original batch and inspect its original receipt before considering another mutation. Uncompleted work is not a success."}))?;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn corpus() -> Corpus {
        Corpus {
            run_id: Uuid::from_u128(1),
            seed_sha256: "12".repeat(32),
            collection: "capacity".into(),
            documents: 3 << 20,
            document_bytes: 1024,
            batch_documents: 128,
        }
    }
    #[test]
    fn aggregate_exceeds_two_gib_without_allocating_a_tenant_buffer() {
        let corpus = corpus();
        assert_eq!(corpus.validate().unwrap(), 3 << 30);
        for ordinal in [0, 9, 10, 999, corpus.documents - 1] {
            let bytes = serde_json::to_vec(&corpus.document(ordinal).unwrap()).unwrap();
            assert_eq!(bytes.len(), 1024);
            assert_eq!(
                bytes,
                serde_json::to_vec(&corpus.document(ordinal).unwrap()).unwrap()
            );
        }
        assert_ne!(corpus.document(0).unwrap(), corpus.document(1).unwrap());
    }
    #[test]
    fn batch_identity_is_exact_and_limits_fail_before_allocating() {
        let mut corpus = corpus();
        corpus.documents = 129;
        let (first, n) = corpus.batch(0).unwrap();
        let (last, m) = corpus.batch(128).unwrap();
        assert_eq!((n, m), (128, 1));
        assert_ne!(first.idempotency_key, last.idempotency_key);
        assert!(last.operations.iter().all(|op| matches!(
            op,
            Mutation::Put {
                expected: Precondition::Absent,
                ..
            }
        )));
        corpus.documents = u64::MAX;
        assert!(corpus.validate().is_err());
        corpus.documents = 1;
        corpus.document_bytes = MAX_DOCUMENT_BYTES;
        assert!(corpus.validate().is_err());
    }
    #[test]
    fn receipt_count_alone_cannot_substitute_a_different_document() {
        let corpus = corpus();
        let mut receipt = proto::WriteReceipt {
            revision: 7,
            versions: std::collections::HashMap::from([(format!("/capacity/{}", corpus.id(0)), 7)]),
        };
        validate_receipt(&corpus, 0, 1, &receipt).unwrap();
        assert!(validate_receipt(&corpus, 1, 1, &receipt).is_err());
        *receipt.versions.values_mut().next().unwrap() = 6;
        assert!(validate_receipt(&corpus, 0, 1, &receipt).is_err());
    }
}
