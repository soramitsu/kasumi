//! `kasumictl` data commands as another program runs them: whatever the
//! arguments, standard output is one JSON document and the exit status is its
//! class's, with nothing connecting for these local mistakes.
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    io::Write,
    os::unix::ffi::OsStringExt,
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

const PROFILE: &str = "/nonexistent/kasumi-profile.json";

fn document(output: &Output) -> Value {
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1,
        "one line: {output:?}"
    );
    assert!(output.stdout.ends_with(b"\n"), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

fn kasumictl(arguments: &[OsString], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kasumictl"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

fn words(text: &str) -> Vec<OsString> {
    text.split(' ').map(OsString::from).collect()
}

fn class(output: &Output) -> (Option<i32>, Value) {
    (
        output.status.code(),
        document(output)["error"]["class"].clone(),
    )
}

#[test]
fn every_data_command_line_prints_one_document_and_its_class_status() {
    // An argument that is not UTF-8 is a request mistake, not a panic.
    let mut arguments = words(&format!("--profile {PROFILE} get docs"));
    arguments.push(OsString::from_vec(vec![0xff, b'a']));
    let output = kasumictl(&arguments, b"");
    assert_eq!(class(&output), (Some(2), json!("invalid_request")));
    assert_eq!(
        document(&output)["error"]["message"],
        json!("arguments must be UTF-8")
    );

    // Data options select the data command line in any order, and its
    // mistakes are documents too.
    for (line, status, expected) in [
        ("--profile", 2, "invalid_request"),
        ("--timeout-ms 5000 get docs a", 2, "invalid_request"),
        (
            &format!("--timeout-ms 5000 --profile {PROFILE} get docs a"),
            3,
            "profile_rejected",
        ),
        (
            &format!(
                "--expect-profile-sha256 {} --profile {PROFILE} collections",
                "a".repeat(64)
            ),
            3,
            "profile_rejected",
        ),
    ] {
        let output = kasumictl(&words(line), b"");
        assert_eq!(class(&output), (Some(status), json!(expected)), "{line}");
        assert!(output.stderr.is_empty(), "{line}: {output:?}");
    }

    // A write refused before it is sent still reports its key.
    let output = kasumictl(
        &words(&format!("--profile {PROFILE} put docs a {{}} --key k-1")),
        b"",
    );
    assert_eq!(class(&output), (Some(3), json!("profile_rejected")));
    assert_eq!(document(&output)["error"]["idempotency_key"], json!("k-1"));

    // Standard input supplies one JSON argument at most.
    let batch =
        br#"{"idempotency_key":"k-2","operations":[{"op":"delete","collection":"docs","id":"a"}]}"#;
    let output = kasumictl(
        &words(&format!("--profile {PROFILE} resolve-mutation - --scope -")),
        batch,
    );
    assert_eq!(class(&output), (Some(2), json!("invalid_request")));
    let message = document(&output)["error"]["message"].to_string();
    assert!(message.contains("only one JSON argument"), "{message}");

    // Administrative command lines keep their own reporting on stderr.
    let output = kasumictl(&words("--config"), b"");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "{output:?}");
}

#[test]
fn a_session_whose_profile_is_rejected_answers_once_without_connecting() {
    let output = kasumictl(
        &words(&format!("--profile {PROFILE} session")),
        br#"{"id":1,"argv":["get","docs","a"]}"#,
    );
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let reply = document(&output);
    assert_eq!(reply["id"], Value::Null);
    assert_eq!(reply["status"], json!(3));
    assert_eq!(
        reply["document"]["error"]["class"],
        json!("profile_rejected")
    );
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn standard_input_left_open_ends_at_the_deadline() {
    let started = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_kasumictl"))
        .args(words(&format!(
            "--profile {PROFILE} --timeout-ms 500 mutate -"
        )))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Keep standard input open, unlike a well-behaved caller.
    let _held = child.stdin.take().unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(started.elapsed() < Duration::from_secs(20), "{output:?}");
    assert_eq!(class(&output), (Some(2), json!("invalid_request")));
    let message = document(&output)["error"]["message"].to_string();
    assert!(message.contains("standard input"), "{message}");
}
