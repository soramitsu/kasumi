/// Capture the actual bounded TLS reply in the original libtest output on an
/// explicit evidence run. Only public response metadata and its body leave
/// the fixture. Client request headers and private test credentials stay local.
pub(crate) async fn observed_reply(label: &str, mut response: reqwest::Response) -> Vec<u8> {
    let status = response.status().as_u16();
    let header = |name| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let cache = header("cache-control");
    let media = header("content-type");
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.unwrap() {
        assert!(
            body.len() + chunk.len() <= 1 << 20,
            "protected reply exceeds its response bound"
        );
        body.extend_from_slice(&chunk);
    }
    if std::env::var("KASUMI_CAPTURE_PROTECTED_RESPONSES").as_deref() == Ok("1") {
        println!(
            "kasumi-protected-response {}",
            serde_json::json!({
                "id": label, "status": status, "cache_control": cache, "content_type": media,
                "body": std::str::from_utf8(&body).unwrap()
            })
        );
    }
    body
}

/// Emit only the independently read public identifiers and outcomes.
pub(crate) fn native_observation(label: &str, fields: serde_json::Value) {
    if std::env::var("KASUMI_CAPTURE_PROTECTED_RESPONSES").as_deref() == Ok("1") {
        println!(
            "kasumi-native-observation {}",
            serde_json::json!({"id":label, "fields":fields})
        );
    }
}
