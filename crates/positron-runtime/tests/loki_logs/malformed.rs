use std::error::Error;

use positron_runtime::ListenerRole;

use super::support;

#[test]
fn malformed_compression_payloads_and_headers_have_stable_statuses() -> Result<(), Box<dyn Error>> {
    let harness = support::LiveLokiHarness::start("malformed")?;
    let bearer = format!("Bearer {}", harness.bearer());

    for (content_type, content_encoding, body, status) in [
        ("application/json", None, b"{not-json}".as_slice(), 400),
        (
            "application/json",
            Some("gzip"),
            [0xff, 0xff].as_slice(),
            400,
        ),
        (
            "application/json",
            Some("deflate"),
            [0xff, 0xff].as_slice(),
            400,
        ),
        (
            "application/x-protobuf",
            Some("snappy"),
            [0xff, 0xff].as_slice(),
            400,
        ),
        ("text/plain", None, b"secret body".as_slice(), 415),
    ] {
        let mut headers = vec![
            ("Authorization", bearer.as_str()),
            ("Content-Type", content_type),
        ];
        if let Some(content_encoding) = content_encoding {
            headers.push(("Content-Encoding", content_encoding));
        }
        let response = harness.http(
            ListenerRole::LokiPush,
            "POST",
            "/loki/api/v1/push",
            &headers,
            body,
        )?;
        support::assert_status(response.clone(), status);
        assert!(!response.contains("secret body"));
    }

    support::assert_status(
        harness.http(
            ListenerRole::LokiPush,
            "POST",
            "/loki/api/v1/push",
            &[
                ("Authorization", bearer.as_str()),
                ("Content-Type", "application/json"),
                ("X-Scope-OrgID", "tenant"),
                ("X-Scope-OrgID", "tenant"),
            ],
            br#"{"streams":[]}"#,
        )?,
        400,
    );
    support::assert_status(
        harness.http_with_advertised_length(
            ListenerRole::LokiPush,
            "POST",
            "/loki/api/v1/push",
            &[
                ("Authorization", bearer.as_str()),
                ("Content-Type", "application/json"),
            ],
            64,
        )?,
        400,
    );
    support::assert_status(
        harness.http(
            ListenerRole::LokiPush,
            "POST",
            "/loki/api/v1/push",
            &[
                ("Authorization", bearer.as_str()),
                ("Content-Type", "application/json"),
            ],
            br#"{"streams":[]}"#,
        )?,
        204,
    );
    Ok(())
}

#[test]
fn invalid_label_sets_fail_without_storage_and_valid_follow_up_succeeds()
-> Result<(), Box<dyn Error>> {
    let harness = support::LiveLokiHarness::start("il")?;
    let bearer = format!("Bearer {}", harness.bearer());
    let headers = [
        ("Authorization", bearer.as_str()),
        ("Content-Type", "application/json"),
    ];

    for body in [
        br#"{"streams":[{"stream":{},"values":[["1","empty-labels"]]}]}"#.as_slice(),
        br#"{"streams":[{"stream":{"dup":"one","dup":"two"},"values":[["2","duplicate-label"]]}]}"#
            .as_slice(),
        br#"{"streams":[{"stream":{"1bad":"value"},"values":[["3","invalid-name"]]}]}"#.as_slice(),
    ] {
        support::assert_status(
            harness.http(
                ListenerRole::LokiPush,
                "POST",
                "/loki/api/v1/push",
                &headers,
                body,
            )?,
            400,
        );
    }
    let query = "logs | range query_time 0 100 | limit 16";
    assert!(harness.query_log_bodies(query)?.is_empty());

    support::assert_status(
        harness.http(
            ListenerRole::LokiPush,
            "POST",
            "/loki/api/v1/push",
            &headers,
            br#"{"streams":[{"stream":{"app":"api"},"values":[["4","follow-up"]]}]}"#,
        )?,
        204,
    );
    assert_eq!(harness.query_log_bodies(query)?, vec!["follow-up"]);
    Ok(())
}
