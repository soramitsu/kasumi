//! Managed S3 objects use single-object PUTs and immutable conditional control
//! publication. Cleanup never accepts a destination key from a caller or response.
use super::*;
use crate::{
    BackupSessionObject, BackupSessionObjectPage, BackupSessionSlot, MAX_SESSION_GC_OBJECTS,
    MAX_SESSION_RECORD_BYTES, VerifiedBackupAbort,
};

const MAX_VERSION_ID_BYTES: usize = 1024;
const MAX_VERSION_RECORD_BYTES: usize = 16 << 10;

fn validate_version_id(version_id: &str) -> Result<()> {
    ensure!(
        !version_id.is_empty() && version_id.len() <= MAX_VERSION_ID_BYTES,
        "invalid S3 object version ID"
    );
    Ok(())
}

pub(super) fn canonical_query(url: &Url) -> String {
    fn encode(value: &str) -> String {
        let mut result = String::new();
        for byte in value.bytes() {
            if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                result.push(char::from(byte));
            } else {
                use std::fmt::Write;
                write!(result, "%{byte:02X}").expect("string write");
            }
        }
        result
    }
    let mut pairs = url
        .query_pairs()
        .map(|(key, value)| (encode(&key), encode(&value)))
        .collect::<Vec<_>>();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}
async fn bounded(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    ensure!(
        response.content_length().is_none_or(|n| n <= limit as u64),
        "S3 session response exceeds limit"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("reading S3 session response")?
    {
        ensure!(
            chunk.len() <= limit.saturating_sub(bytes.len()),
            "S3 session response exceeds limit"
        );
        bytes.extend(chunk);
    }
    Ok(bytes)
}
impl S3BackupDestination {
    fn managed_key(&self, session: Uuid, slot: BackupSessionSlot) -> Result<String> {
        let relative = slot.relative(session)?;
        Ok(if self.prefix.is_empty() {
            relative
        } else {
            format!("{}/{relative}", self.prefix)
        })
    }
    fn managed_url(&self, session: Uuid, slot: BackupSessionSlot) -> Result<Url> {
        Ok(self.endpoint.join(&format!(
            "{}/{}",
            self.bucket,
            self.managed_key(session, slot)?
        ))?)
    }
    pub(super) async fn managed_put(
        &self,
        session: Uuid,
        slot: BackupSessionSlot,
        encrypted: BackupUpload,
    ) -> Result<()> {
        ensure!(
            encrypted.len() <= self.max_bytes,
            "backup exceeds destination byte limit"
        );
        let url = self.managed_url(session, slot)?;
        let headers =
            self.signed_headers("PUT", &url, &encrypted, time::OffsetDateTime::now_utc())?;
        let response = self
            .client
            .put(url)
            .headers(headers)
            .body(encrypted.into_http_body())
            .send()
            .await
            .map_err(|_| {
                anyhow::anyhow!("S3 session publication uncertain; resolve outcome before cleanup")
            })?;
        ensure!(
            response.status().is_success(),
            "S3 rejected create-only session publication (HTTP {})",
            response.status().as_u16()
        );
        Ok(())
    }
    pub(super) async fn managed_get(
        &self,
        session: Uuid,
        slot: BackupSessionSlot,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>> {
        let url = self.managed_url(session, slot)?;
        let headers = self.signed_headers("GET", &url, &[], time::OffsetDateTime::now_utc())?;
        let response = self
            .client
            .get(url)
            .headers(headers)
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("S3 session read unavailable"))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        ensure!(
            response.status().is_success(),
            "S3 rejected session read (HTTP {})",
            response.status().as_u16()
        );
        Ok(Some(
            bounded(response, self.max_bytes.min(max_bytes)).await?,
        ))
    }
    async fn check_aborted(&self, proof: &VerifiedBackupAbort) -> Result<()> {
        proof.matches_outcome(
            &self
                .managed_get(
                    proof.session_id(),
                    BackupSessionSlot::Outcome,
                    MAX_SESSION_RECORD_BYTES + HEADER_LIMIT + 84,
                )
                .await?
                .context("backup abort outcome missing")?,
        )
    }
    pub(super) async fn managed_list(
        &self,
        proof: &VerifiedBackupAbort,
        limit: usize,
    ) -> Result<BackupSessionObjectPage> {
        ensure!(
            (1..=MAX_SESSION_GC_OBJECTS).contains(&limit),
            "invalid backup cleanup page limit"
        );
        self.check_aborted(proof).await?;
        let prefix = format!(
            "{}objects/",
            self.managed_key(proof.session_id(), BackupSessionSlot::Intent)?
                .strip_suffix("intent.kasumi")
                .context("session key suffix")?
        );
        let mut url = self.endpoint.join(&self.bucket)?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs
                .append_pair("versions", "")
                .append_pair("max-keys", &limit.to_string())
                .append_pair("prefix", &prefix);
        }
        let headers = self.signed_headers("GET", &url, &[], time::OffsetDateTime::now_utc())?;
        let response = self
            .client
            .get(url)
            .headers(headers)
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("S3 session enumeration unavailable"))?;
        ensure!(
            response.status().is_success(),
            "S3 rejected session enumeration (HTTP {})",
            response.status().as_u16()
        );
        let bytes = bounded(response, 64 * 1024 + limit * MAX_VERSION_RECORD_BYTES).await?;
        let page = parse_page(&bytes, &prefix, limit)?;
        self.check_aborted(proof).await?;
        Ok(page)
    }
    pub(super) async fn managed_delete(
        &self,
        proof: &VerifiedBackupAbort,
        objects: &[BackupSessionObject],
    ) -> Result<()> {
        ensure!(
            objects.len() <= MAX_SESSION_GC_OBJECTS,
            "backup cleanup deletion exceeds page limit"
        );
        // Validate all selectors before any mutation. A bare object key is never
        // a deletion request: it would create a marker and retain the data.
        let mut seen = std::collections::BTreeSet::new();
        for object in objects {
            let BackupSessionObject::S3Version { id, version_id } = object else {
                anyhow::bail!("S3 cleanup requires exact version selectors");
            };
            validate_version_id(version_id)?;
            ensure!(
                !id.is_nil() && seen.insert((*id, version_id.as_str())),
                "invalid or duplicate S3 cleanup selector"
            );
        }
        self.check_aborted(proof).await?;
        for object in objects {
            let BackupSessionObject::S3Version { id, version_id } = object else {
                unreachable!("validated version selector")
            };
            proof.check()?;
            let mut url = self.managed_url(proof.session_id(), BackupSessionSlot::Object(*id))?;
            url.query_pairs_mut().append_pair("versionId", version_id);
            let headers =
                self.signed_headers("DELETE", &url, &[], time::OffsetDateTime::now_utc())?;
            let response = self
                .client
                .delete(url)
                .headers(headers)
                .send()
                .await
                .map_err(|_| anyhow::anyhow!("S3 session deletion uncertain; repeat cleanup"))?;
            ensure!(
                response.status().is_success()
                    || response.status() == reqwest::StatusCode::NOT_FOUND,
                "S3 rejected session deletion (HTTP {})",
                response.status().as_u16()
            );
        }
        proof.check()?;
        Ok(())
    }
}
fn parse_page(bytes: &[u8], prefix: &str, limit: usize) -> Result<BackupSessionObjectPage> {
    use quick_xml::{Reader, events::Event};
    ensure!(
        (1..=MAX_SESSION_GC_OBJECTS).contains(&limit),
        "invalid S3 page limit"
    );
    let mut reader = Reader::from_reader(bytes);
    // Version IDs are opaque. Do not trim or normalize them, including when a
    // service encodes their characters as XML references.
    let mut stack: Vec<String> = Vec::new();
    let mut root = false;
    let mut root_closed = false;
    let mut objects = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut previous_id = None;
    let mut truncated = None;
    let mut actual_prefix = None;
    let mut current_key = None;
    let mut current_version = None;
    let mut record_start = None;
    let mut text = String::new();
    loop {
        let position = reader.buffer_position();
        let event = reader.read_event()?;
        if let Some(start) = record_start {
            ensure!(
                reader.buffer_position() - start <= MAX_VERSION_RECORD_BYTES as u64,
                "S3 object version record exceeds limit"
            );
        }
        match event {
            Event::Start(event) => {
                ensure!(
                    !root_closed && stack.len() < 8,
                    "invalid S3 session XML nesting"
                );
                ensure!(
                    stack.last().is_none_or(|tag| !matches!(
                        tag.as_str(),
                        "Key" | "VersionId" | "Prefix" | "IsTruncated"
                    )),
                    "nested S3 selector text"
                );
                let tag = event.name().as_ref().to_owned();
                if stack.is_empty() {
                    ensure!(
                        !root && tag == "ListVersionsResult",
                        "invalid S3 session XML root"
                    );
                    root = true;
                }
                match tag.as_str() {
                    "Version" | "DeleteMarker" => {
                        ensure!(
                            stack.len() == 1 && record_start.is_none(),
                            "invalid S3 version nesting"
                        );
                        current_key = None;
                        current_version = None;
                        record_start = Some(position);
                    }
                    "Key" | "VersionId" => {
                        ensure!(
                            stack.len() == 2
                                && matches!(stack[1].as_str(), "Version" | "DeleteMarker"),
                            "invalid S3 version selector nesting"
                        );
                    }
                    "Prefix" | "IsTruncated" => ensure!(stack.len() == 1, "nested S3 page state"),
                    "CommonPrefixes" | "Contents" => {
                        anyhow::bail!("unexpected grouped S3 enumeration")
                    }
                    _ => {}
                }
                stack.push(tag);
                text.clear();
            }
            Event::Text(value) => {
                ensure!(
                    text.len() + value.len() <= 4096,
                    "S3 session XML text exceeds limit"
                );
                ensure!(
                    !stack.is_empty() || value.trim().is_empty(),
                    "text outside S3 XML root"
                );
                text.push_str(&value);
            }
            Event::GeneralRef(value) => {
                ensure!(!stack.is_empty(), "reference outside S3 XML root");
                if let Some(character) = value.resolve_char_ref()? {
                    text.push(character);
                } else {
                    text.push_str(
                        quick_xml::escape::resolve_predefined_entity(&value)
                            .context("unsupported S3 XML entity")?,
                    );
                }
                ensure!(text.len() <= 4096, "S3 session XML text exceeds limit");
            }
            Event::End(event) => {
                let tag = stack.pop().context("unexpected S3 XML close")?;
                ensure!(tag == event.name().as_ref(), "S3 XML close differs");
                match tag.as_str() {
                    "Key" => ensure!(
                        current_key.replace(text.clone()).is_none(),
                        "duplicate S3 object key"
                    ),
                    "VersionId" => {
                        validate_version_id(&text)?;
                        ensure!(
                            current_version.replace(text.clone()).is_none(),
                            "duplicate S3 version ID"
                        );
                    }
                    "Version" | "DeleteMarker" => {
                        let key = current_key.take().context("S3 object key absent")?;
                        let version_id = current_version.take().context("S3 version ID absent")?;
                        let value = key
                            .strip_prefix(prefix)
                            .and_then(|key| key.strip_suffix(".kasumi"))
                            .context("S3 enumeration escaped aborted namespace")?;
                        let id = Uuid::parse_str(value)?;
                        ensure!(
                            !id.is_nil()
                                && key == format!("{prefix}{id}.kasumi")
                                && previous_id.is_none_or(|previous| previous <= id),
                            "S3 object order or scope differs"
                        );
                        ensure!(
                            seen.insert((id, version_id.clone())),
                            "duplicate S3 version selector"
                        );
                        previous_id = Some(id);
                        objects.push(BackupSessionObject::S3Version { id, version_id });
                        ensure!(
                            objects.len() <= limit,
                            "S3 enumeration exceeds requested page limit"
                        );
                        record_start = None;
                    }
                    "IsTruncated" => {
                        ensure!(truncated.is_none(), "duplicate S3 page state");
                        truncated = Some(match text.as_str() {
                            "true" => true,
                            "false" => false,
                            _ => anyhow::bail!("invalid S3 page state"),
                        });
                    }
                    "Prefix" => ensure!(
                        actual_prefix.replace(text.clone()).is_none(),
                        "duplicate S3 prefix"
                    ),
                    "ListVersionsResult" => {
                        root_closed = true;
                    }
                    _ => {}
                }
                text.clear();
            }
            Event::Empty(event) => {
                ensure!(
                    !stack.is_empty()
                        && !root_closed
                        && !matches!(
                            event.name().as_ref(),
                            "Version"
                                | "DeleteMarker"
                                | "Key"
                                | "VersionId"
                                | "Prefix"
                                | "IsTruncated"
                                | "CommonPrefixes"
                                | "Contents"
                        ),
                    "invalid empty S3 XML record"
                );
                ensure!(
                    stack.last().is_none_or(|tag| !matches!(
                        tag.as_str(),
                        "Key" | "VersionId" | "Prefix" | "IsTruncated"
                    )),
                    "nested S3 selector text"
                );
            }
            Event::Decl(_) if !root => {}
            Event::Eof => break,
            Event::Comment(_) => {}
            _ => anyhow::bail!("unsupported S3 session XML content"),
        }
    }
    ensure!(
        root_closed && stack.is_empty() && actual_prefix.as_deref() == Some(prefix),
        "S3 enumeration scope or framing differs"
    );
    let more = truncated.context("S3 page completion missing")?;
    ensure!(!more || !objects.is_empty(), "truncated S3 page is empty");
    Ok(BackupSessionObjectPage { objects, more })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_query_uses_aws_encoding_and_sorting() {
        let url =
            Url::parse("https://example/bucket?z=two+words&prefix=a%2Fb&list-type=2&a=~&a=%2B")
                .unwrap();
        assert_eq!(
            canonical_query(&url),
            "a=%2B&a=~&list-type=2&prefix=a%2Fb&z=two%20words"
        );
    }
    fn version(id: u128, version_id: &str) -> BackupSessionObject {
        BackupSessionObject::S3Version {
            id: Uuid::from_u128(id),
            version_id: version_id.into(),
        }
    }
    #[test]
    fn bounded_s3_versions_preserve_exact_ids_and_service_order() {
        let prefix = "backup/sessions/session/objects/";
        let bytes = format!("<ListVersionsResult><Prefix>{prefix}</Prefix><KeyMarker/><VersionIdMarker/>
            <DeleteMarker><Key>{prefix}{}.kasumi</Key><VersionId>z/+&amp;&#61;</VersionId></DeleteMarker>
            <Version><Key>{prefix}{}.kasumi</Key><VersionId>a</VersionId><Owner><ID>owner</ID></Owner></Version>
            <Version><Key>{prefix}{}.kasumi</Key><VersionId>null</VersionId></Version>
            <IsTruncated>true</IsTruncated></ListVersionsResult>",
            Uuid::from_u128(1), Uuid::from_u128(1), Uuid::from_u128(2));
        let page = parse_page(bytes.as_bytes(), prefix, 3).unwrap();
        assert_eq!(
            page.objects,
            vec![version(1, "z/+&="), version(1, "a"), version(2, "null")]
        );
        assert!(page.more);
        assert!(parse_page(bytes.as_bytes(), prefix, 2).is_err());
    }
    #[test]
    fn bounded_s3_versions_reject_malformed_scope_duplicates_and_oversized_records() {
        let prefix = "backup/sessions/session/objects/";
        let make = |body: &str| {
            format!("<ListVersionsResult><Prefix>{prefix}</Prefix>{body}</ListVersionsResult>")
        };
        let key = |id| format!("<Key>{prefix}{}.kasumi</Key>", Uuid::from_u128(id));
        let record = |id, version: &str| {
            format!(
                "<Version>{}<VersionId>{version}</VersionId></Version>",
                key(id)
            )
        };
        let valid = make(&format!(
            "{}<IsTruncated>false</IsTruncated>",
            record(1, "null")
        ));
        assert_eq!(
            parse_page(valid.as_bytes(), prefix, 2).unwrap().objects,
            vec![version(1, "null")]
        );
        for body in [
            format!("{}{}<IsTruncated>false</IsTruncated>", record(2, "v"), record(1, "v")),
            format!("{}<DeleteMarker>{}<VersionId>v</VersionId></DeleteMarker><IsTruncated>false</IsTruncated>", record(1, "v"), key(1)),
            "<Version><Key>outside/key.kasumi</Key><VersionId>v</VersionId></Version><IsTruncated>false</IsTruncated>".into(),
            format!("{}<IsTruncated>false</IsTruncated>", record(0, "v")),
            "<IsTruncated>true</IsTruncated>".into(),
            format!("{}<IsTruncated>false</IsTruncated><IsTruncated>false</IsTruncated>", record(1, "v")),
            format!("{}<IsTruncated>false</IsTruncated>", record(1, "&secret;")),
            format!("{}<IsTruncated>false</IsTruncated>", record(1, "<Bad/>v")),
            format!("{}<IsTruncated>false</IsTruncated>", record(1, "")),
            format!("{}<IsTruncated>false</IsTruncated>", record(1, &"x".repeat(1025))),
            format!("<Version>{}</Version><IsTruncated>false</IsTruncated>", key(1)),
            format!("<Version>{}<VersionId/><VersionId>v</VersionId></Version><IsTruncated>false</IsTruncated>", key(1)),
            format!("<Version>{}<VersionId>v</VersionId><VersionId>w</VersionId></Version><IsTruncated>false</IsTruncated>", key(1)),
            format!("<Version>{}{}<VersionId>v</VersionId></Version><IsTruncated>false</IsTruncated>", key(1), key(1)),
            "<CommonPrefixes/><IsTruncated>false</IsTruncated>".into(),
            format!("<Version>{}<VersionId>v</VersionId>{}</Version><IsTruncated>false</IsTruncated>", key(1), "<Metadata>opaque</Metadata>".repeat(1000)),
        ] {
            assert!(parse_page(make(&body).as_bytes(), prefix, 2).is_err(), "{body}");
        }
        assert!(parse_page(&valid.as_bytes()[..valid.len() - 1], prefix, 2).is_err());
        assert!(
            parse_page(
                valid
                    .replace("ListVersionsResult", "ListBucketResult")
                    .as_bytes(),
                prefix,
                2
            )
            .is_err()
        );
    }
}
