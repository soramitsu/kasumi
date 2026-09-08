//! Managed S3 objects use single-object PUTs and immutable conditional control
//! publication. Cleanup never accepts a destination key from a caller or response.
use super::*;
use crate::{
    BackupSessionObjectPage, BackupSessionSlot, MAX_SESSION_GC_OBJECTS, MAX_SESSION_RECORD_BYTES,
    VerifiedBackupAbort,
};

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
        encrypted: Vec<u8>,
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
            .body(encrypted)
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
                .append_pair("list-type", "2")
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
        let bytes = bounded(response, 64 * 1024 + limit * 4096).await?;
        let page = parse_page(&bytes, &prefix, limit)?;
        self.check_aborted(proof).await?;
        Ok(page)
    }
    pub(super) async fn managed_delete(
        &self,
        proof: &VerifiedBackupAbort,
        ids: &[Uuid],
    ) -> Result<()> {
        ensure!(
            ids.len() <= MAX_SESSION_GC_OBJECTS,
            "backup cleanup deletion exceeds page limit"
        );
        self.check_aborted(proof).await?;
        for id in ids {
            proof.check()?;
            let url = self.managed_url(proof.session_id(), BackupSessionSlot::Object(*id))?;
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
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    let mut stack: Vec<String> = Vec::new();
    let mut root = false;
    let mut root_closed = false;
    let mut keys = Vec::new();
    let mut truncated = None;
    let mut actual_prefix = None;
    let mut current_key = None;
    let mut text = String::new();
    loop {
        match reader.read_event()? {
            Event::Start(event) => {
                ensure!(
                    !root_closed && stack.len() < 8,
                    "invalid S3 session XML nesting"
                );
                let tag = event.name().as_ref().to_owned();
                if stack.is_empty() {
                    ensure!(
                        !root && tag == "ListBucketResult",
                        "invalid S3 session XML root"
                    );
                    root = true;
                }
                if tag == "Contents" {
                    ensure!(stack.len() == 1, "invalid S3 Contents nesting");
                    current_key = None;
                }
                if tag == "Key" {
                    ensure!(
                        stack.len() == 2 && stack[1] == "Contents" && current_key.is_none(),
                        "invalid or duplicate S3 object key"
                    );
                }
                stack.push(tag);
                text.clear();
            }
            Event::Text(value) => {
                ensure!(
                    text.len() + value.len() <= 4096,
                    "S3 session XML text exceeds limit"
                );
                ensure!(!stack.is_empty(), "text outside S3 XML root");
                text.push_str(&value);
            }
            Event::End(event) => {
                let tag = stack.pop().context("unexpected S3 XML close")?;
                ensure!(tag == event.name().as_ref(), "S3 XML close differs");
                match tag.as_str() {
                    "Key" => {
                        ensure!(
                            current_key.replace(text.clone()).is_none(),
                            "duplicate S3 object key"
                        );
                    }
                    "Contents" => {
                        let key = current_key.take().context("S3 object key absent")?;
                        let value = key
                            .strip_prefix(prefix)
                            .and_then(|key| key.strip_suffix(".kasumi"))
                            .context("S3 enumeration escaped aborted namespace")?;
                        let id = Uuid::parse_str(value)?;
                        ensure!(
                            !id.is_nil()
                                && key == format!("{prefix}{id}.kasumi")
                                && keys.last().is_none_or(|previous| previous < &id),
                            "S3 object order or scope differs"
                        );
                        keys.push(id);
                        ensure!(
                            keys.len() <= limit,
                            "S3 enumeration exceeds requested page limit"
                        );
                    }
                    "IsTruncated" => {
                        ensure!(
                            stack.len() == 1 && truncated.is_none(),
                            "duplicate or nested S3 page state"
                        );
                        truncated = Some(match text.as_str() {
                            "true" => true,
                            "false" => false,
                            _ => anyhow::bail!("invalid S3 page state"),
                        });
                    }
                    "Prefix" => {
                        ensure!(
                            stack.len() == 1 && actual_prefix.replace(text.clone()).is_none(),
                            "duplicate or nested S3 prefix"
                        );
                    }
                    "ListBucketResult" => {
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
                        && event.name().as_ref() != "Contents"
                        && event.name().as_ref() != "Key",
                    "invalid empty S3 XML record"
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
    ensure!(!more || !keys.is_empty(), "truncated S3 page is empty");
    Ok(BackupSessionObjectPage {
        objects: keys,
        more,
    })
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
    #[test]
    fn bounded_s3_xml_rejects_wrong_scope_order_truncation_and_entities() {
        let prefix = "backup/sessions/session/objects/";
        let make = |body: &str| {
            format!("<ListBucketResult><Prefix>{prefix}</Prefix>{body}</ListBucketResult>")
        };
        let key = |id| {
            format!(
                "<Contents><Key>{prefix}{}.kasumi</Key></Contents>",
                Uuid::from_u128(id)
            )
        };
        let valid = make(&format!(
            "{}{}<IsTruncated>true</IsTruncated>",
            key(1),
            key(2)
        ));
        let page = parse_page(valid.as_bytes(), prefix, 2).unwrap();
        assert_eq!(page.objects, vec![Uuid::from_u128(1), Uuid::from_u128(2)]);
        assert!(page.more);
        assert!(parse_page(valid.as_bytes(), prefix, 1).is_err());
        for body in [
            format!("{}{}<IsTruncated>false</IsTruncated>", key(2), key(1)),
            "<Contents><Key>outside/key.kasumi</Key></Contents><IsTruncated>false</IsTruncated>"
                .into(),
            "<IsTruncated>true</IsTruncated>".into(),
            format!(
                "{}<IsTruncated>false</IsTruncated><IsTruncated>false</IsTruncated>",
                key(1)
            ),
            "<Contents><Key>&secret;</Key></Contents><IsTruncated>false</IsTruncated>".into(),
        ] {
            assert!(
                parse_page(make(&body).as_bytes(), prefix, 2).is_err(),
                "{body}"
            );
        }
        assert!(parse_page(&valid.as_bytes()[..valid.len() - 1], prefix, 2).is_err());
    }
}
