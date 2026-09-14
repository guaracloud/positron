use super::*;
use positron_api::policy::{MAX_TEST_REQUEST_BYTES, PolicyPreviewTransport};

#[test]
fn policy_validate_defaults_to_tls_and_rejects_ambiguous_transport_options() {
    let policy = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let command = |transport: &str| {
        format!(
            "validate --endpoint 127.0.0.1:8080 --credential-stdin --policy-file {} {transport}",
            policy
        )
    };
    assert!(matches!(
        parse(
            command("--server-name policy.example --trust-file policy-ca.pem")
                .split_whitespace()
                .map(ToOwned::to_owned)
        ),
        Ok((PolicyPreviewTransport::Tls { .. }, _))
    ));
    assert!(matches!(
        parse(
            command("--allow-plaintext")
                .split_whitespace()
                .map(ToOwned::to_owned)
        ),
        Ok((PolicyPreviewTransport::PlaintextOptOut { .. }, _))
    ));
    assert!(
        parse(
            command("--allow-plaintext --server-name ignored")
                .split_whitespace()
                .map(ToOwned::to_owned)
        )
        .is_err()
    );
}

#[test]
fn policy_validate_reports_only_safe_client_failures() {
    assert_eq!(
        preview_failure(PolicyPreviewServiceClientFailure::InvalidRequest),
        "invalid policy candidate; correct the request before retrying"
    );
    assert_eq!(
        preview_failure(PolicyPreviewServiceClientFailure::AuthenticationRejected),
        "authentication rejected"
    );
}

#[test]
fn policy_test_diff_explain_and_activate_accept_their_bounded_file_inputs() {
    let policy = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    for command in [
        format!(
            "test --endpoint 127.0.0.1:8080 --credential-stdin --policy-file {policy} --candidate-file {policy} --allow-plaintext"
        ),
        format!(
            "diff --endpoint 127.0.0.1:8080 --credential-stdin --before-policy-file {policy} --after-policy-file {policy} --allow-plaintext"
        ),
        format!(
            "explain --endpoint 127.0.0.1:8080 --credential-stdin --policy-file {policy} --candidate-file {policy} --allow-plaintext"
        ),
        format!(
            "activate --endpoint 127.0.0.1:8080 --credential-stdin --policy-file {policy} --expected-generation 1 --idempotency-key 01010101-0101-0101-0101-010101010101 --allow-plaintext"
        ),
    ] {
        assert!(
            parse(command.split_whitespace().map(ToOwned::to_owned)).is_ok(),
            "{command}"
        );
    }
}

#[test]
fn policy_commands_use_checked_generated_clients_against_local_loopback()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    let policy = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let digest = "a".repeat(64);
    let cases = [
        (
            "test",
            format!("--policy-file {policy} --candidate-file {policy}"),
            "/v1/policies:test",
            format!(
                r#"{{"policy_generation":1,"policy_digest":"{digest}","accepted":true,"applied_rule_count":1}}"#
            ),
        ),
        (
            "diff",
            format!("--before-policy-file {policy} --after-policy-file {policy}"),
            "/v1/policies:diff",
            format!(
                r#"{{"before_policy_generation":1,"before_policy_digest":"{digest}","after_policy_generation":2,"after_policy_digest":"{digest}","semantic_changes":["rule_added"]}}"#
            ),
        ),
        (
            "explain",
            format!("--policy-file {policy} --candidate-file {policy}"),
            "/v1/policies:explain",
            format!(
                r#"{{"policy_generation":1,"policy_digest":"{digest}","outcome":"accepted","explanation":"redacted summary"}}"#
            ),
        ),
        (
            "activate",
            format!(
                "--policy-file {policy} --expected-generation 1 --idempotency-key 01010101-0101-0101-0101-010101010101"
            ),
            "/v1/policies:activate",
            format!(r#"{{"resource_generation":2,"policy_digest":"{digest}","audit_position":7}}"#),
        ),
    ];
    for (command, files, path, body) in cases {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = listener.local_addr()?;
        let server = thread::spawn(move || -> Result<(), std::io::Error> {
            let (mut stream, _) = listener.accept()?;
            let mut bytes = [0_u8; 8192];
            let read = stream.read(&mut bytes)?;
            let request = String::from_utf8_lossy(&bytes[..read]);
            assert!(request.starts_with(&format!("POST {path} HTTP/1.1\r\n")));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("authorization: bearer key-material\r\n")
            );
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("content-type: application/json\r\n")
            );
            stream.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )?;
            Ok(())
        });
        let command_line =
            format!("{command} --endpoint {endpoint} --credential-stdin {files} --allow-plaintext");
        let (transport, request) = parse(command_line.split_whitespace().map(ToOwned::to_owned))?;
        match request {
            PolicyCommand::Test(request) => {
                PolicyTestServiceClient::new(transport)?.test("key-material", &request)?;
            },
            PolicyCommand::Diff(request) => {
                PolicyDiffServiceClient::new(transport)?.diff("key-material", &request)?;
            },
            PolicyCommand::Explain(request) => {
                PolicyExplainServiceClient::new(transport)?.explain("key-material", &request)?;
            },
            PolicyCommand::Activate(request) => {
                PolicyActivateServiceClient::new(transport)?.activate("key-material", &request)?;
            },
            PolicyCommand::Validate(_) => panic!("test case selects a non-validation command"),
        }
        server.join().map_err(|_| "loopback server panicked")??;
    }
    Ok(())
}

#[test]
fn policy_commands_reject_unbounded_or_inapplicable_inputs()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    let policy = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let oversized = std::env::temp_dir().join(format!(
        "positron-policy-cli-oversized-{}",
        std::process::id()
    ));
    let mut file = std::fs::File::create(&oversized)?;
    file.write_all(&vec![b'x'; MAX_TEST_REQUEST_BYTES + 1])?;
    drop(file);
    let oversized_command = format!(
        "test --endpoint 127.0.0.1:8080 --credential-stdin --policy-file {} --candidate-file {policy} --allow-plaintext",
        oversized.display()
    );
    assert!(parse(oversized_command.split_whitespace().map(ToOwned::to_owned)).is_err());
    std::fs::remove_file(&oversized)?;

    for command in [
        format!(
            "test --endpoint 127.0.0.1:8080 --credential-stdin --policy-file {policy} --candidate-file {policy} --allow-plaintext --trust-file ignored.pem"
        ),
        format!(
            "diff --endpoint 127.0.0.1:8080 --credential-stdin --before-policy-file {policy} --after-policy-file {policy} --candidate-file {policy} --allow-plaintext"
        ),
        format!(
            "activate --endpoint 127.0.0.1:8080 --credential-stdin --policy-file {policy} --expected-generation 0 --idempotency-key invalid --allow-plaintext"
        ),
    ] {
        assert!(
            parse(command.split_whitespace().map(ToOwned::to_owned)).is_err(),
            "{command}"
        );
    }
    Ok(())
}

#[test]
fn policy_new_command_failures_remain_redacted() {
    assert_eq!(
        test_failure(PolicyTestServiceClientFailure::AuthenticationRejected),
        "authentication rejected"
    );
    assert_eq!(
        diff_failure(PolicyDiffServiceClientFailure::Transport),
        "API transport unavailable; inspect state before retrying"
    );
    assert_eq!(
        explain_failure(PolicyExplainServiceClientFailure::InvalidRequest),
        "invalid policy or candidate input"
    );
    assert_eq!(
        activate_failure(PolicyActivateServiceClientFailure::StaleGeneration {
            resource_generation: 2,
            semantic_diff: "redacted".to_owned(),
        }),
        "stale policy generation; inspect current state before retrying"
    );
}

#[test]
fn policy_cli_reads_credential_and_files_then_uses_tls_with_checked_name_and_trust()
-> Result<(), Box<dyn std::error::Error>> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    use rustls::{ServerConfig, ServerConnection, StreamOwned};
    use std::io::{Cursor, Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;

    let certificate = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../positron-runtime/tests/native_transport/fixtures/api-test-cert.pem"
    );
    let private_key = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../positron-runtime/tests/native_transport/fixtures/api-test-key.pem"
    );
    let certificates =
        CertificateDer::pem_file_iter(certificate)?.collect::<Result<Vec<_>, _>>()?;
    let private_key = PrivateKeyDer::from_pem_slice(&std::fs::read(private_key)?)?;
    let configuration = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?;
    let server = thread::spawn(move || -> Result<(), std::io::Error> {
        let (stream, _) = listener.accept()?;
        let connection =
            ServerConnection::new(Arc::new(configuration)).map_err(std::io::Error::other)?;
        let mut stream = StreamOwned::new(connection, stream);
        let mut bytes = [0_u8; 8192];
        let read = stream.read(&mut bytes)?;
        let request = String::from_utf8_lossy(&bytes[..read]);
        assert!(request.starts_with("POST /v1/policies:test HTTP/1.1\r\n"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer key-material\r\n")
        );
        let body = format!(
            r#"{{"policy_generation":1,"policy_digest":"{}","accepted":true,"applied_rule_count":1}}"#,
            "a".repeat(64)
        );
        stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )?;
        Ok(())
    });
    let policy = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let command = format!(
        "test --endpoint {endpoint} --credential-stdin --policy-file {policy} --candidate-file {policy} --server-name localhost --trust-file {certificate}"
    );
    let mut credential = Cursor::new(b"key-material\n".to_vec());
    execute_with_input(
        command.split_whitespace().map(ToOwned::to_owned),
        &mut credential,
    )?;
    server
        .join()
        .map_err(|_| "TLS loopback server panicked")??;

    let wrong_name = format!(
        "test --endpoint {endpoint} --credential-stdin --policy-file {policy} --candidate-file {policy} --server-name 127.0.0.2 --trust-file {certificate}"
    );
    let (transport, _) = parse(wrong_name.split_whitespace().map(ToOwned::to_owned))?;
    assert!(matches!(
        PolicyTestServiceClient::new(transport),
        Err(PolicyTestServiceClientFailure::Transport)
    ));
    Ok(())
}
