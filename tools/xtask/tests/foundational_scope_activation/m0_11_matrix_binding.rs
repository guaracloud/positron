#[test]
fn parent_rejects_matrix_binding_field_root_order_and_cardinality_tampering() -> TestResult {
    let fixture = create_matrix_fixture()?;
    let result: TestResult = (|| {
        let baseline = matrix_quality_output(&fixture, "pr")?;
        if !baseline.status.success() {
            return Err(std::io::Error::other(
                "matrix binding-tamper baseline failed",
            )
            .into());
        }
        let evidence_path = fixture.latest_evidence_path()?;
        let original_evidence = fs::read(&evidence_path)?;
        for variant in [
            "target-id",
            "registry-digest",
            "plan-digest",
            "binding-root",
            "order",
            "extra",
            "missing",
        ] {
            fs::write(&evidence_path, &original_evidence)?;
            tamper_matrix_binding_evidence(&evidence_path, variant)?;
            let verified = matrix_quality_output(&fixture, "pr")?;
            assert_rejected_output(&verified, "EG-MATRIX")?;
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

fn tamper_matrix_binding_evidence(path: &Path, variant: &str) -> TestResult {
    let mut evidence = fs::read_to_string(path)?;
    let gate_start = evidence
        .find("\"gate_id\": \"EG-MATRIX\"")
        .ok_or_else(|| std::io::Error::other("EG-MATRIX evidence is missing"))?;
    match variant {
        "target-id" | "registry-digest" | "plan-digest" => {
            let field = "env.POSITRON_MATRIX_BINDING_DIGEST=\\\"";
            let gate = evidence
                .get(gate_start..)
                .ok_or_else(|| std::io::Error::other("matrix gate range is invalid"))?;
            let relative = gate
                .find(field)
                .ok_or_else(|| std::io::Error::other("matrix binding digest is missing"))?;
            let digest_start = gate_start + relative + field.len();
            let digest_end = digest_start
                .checked_add(71)
                .ok_or_else(|| std::io::Error::other("binding digest range overflowed"))?;
            evidence.replace_range(
                digest_start..digest_end,
                &format!("sha256:{:x}", Sha256::digest(variant.as_bytes())),
            );
        },
        "binding-root" => {
            let field = "binding-root=";
            let gate = evidence
                .get(gate_start..)
                .ok_or_else(|| std::io::Error::other("matrix gate range is invalid"))?;
            let relative = gate
                .find(field)
                .ok_or_else(|| std::io::Error::other("matrix binding root is missing"))?;
            let digest_start = gate_start + relative + field.len();
            let digest_end = digest_start
                .checked_add(71)
                .ok_or_else(|| std::io::Error::other("binding root range overflowed"))?;
            evidence.replace_range(
                digest_start..digest_end,
                &format!("sha256:{:x}", Sha256::digest(variant.as_bytes())),
            );
        },
        "order" | "extra" | "missing" => {
            let (steps, array_end) = matrix_step_ranges(&evidence, gate_start)?;
            let first_range = steps
                .first()
                .ok_or_else(|| std::io::Error::other("first matrix step is missing"))?;
            let second_range = steps
                .get(1)
                .ok_or_else(|| std::io::Error::other("second matrix step is missing"))?;
            let first = evidence
                .get(first_range.clone())
                .ok_or_else(|| std::io::Error::other("first matrix step range is invalid"))?
                .to_owned();
            match variant {
                "order" => {
                    let second = evidence
                        .get(second_range.clone())
                        .ok_or_else(|| {
                            std::io::Error::other("second matrix step range is invalid")
                        })?
                        .to_owned();
                    evidence.replace_range(second_range.clone(), &first);
                    evidence.replace_range(first_range.clone(), &second);
                },
                "extra" => evidence.insert_str(array_end, &format!(",{first}")),
                "missing" => {
                    evidence.replace_range(first_range.start..second_range.start, "");
                },
                _ => {
                    return Err(std::io::Error::other(
                        "matrix binding cardinality variant is not closed",
                    )
                    .into());
                },
            }
        },
        _ => {
            return Err(
                std::io::Error::other("matrix binding tamper variant is not closed").into(),
            );
        },
    }
    fs::write(path, evidence)?;
    Ok(())
}

fn matrix_step_ranges(
    evidence: &str,
    gate_start: usize,
) -> TestResult<(Vec<std::ops::Range<usize>>, usize)> {
    let marker = "\"controlled_steps\":[";
    let gate = evidence
        .get(gate_start..)
        .ok_or_else(|| std::io::Error::other("matrix gate range is invalid"))?;
    let relative = gate
        .find(marker)
        .ok_or_else(|| std::io::Error::other("matrix controlled step array is missing"))?;
    let array_start = gate_start + relative + marker.len();
    let bytes = evidence.as_bytes();
    let mut ranges = Vec::new();
    let mut depth = 0_usize;
    let mut start = None;
    let mut in_string = false;
    let mut escaped = false;
    let mut cursor = array_start;
    while cursor < bytes.len() {
        let byte = *bytes
            .get(cursor)
            .ok_or_else(|| std::io::Error::other("matrix step cursor is invalid"))?;
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else {
            match byte {
                b'"' => in_string = true,
                b'{' => {
                    if depth == 0 {
                        start = Some(cursor);
                    }
                    depth = depth
                        .checked_add(1)
                        .ok_or_else(|| std::io::Error::other("matrix step depth overflowed"))?;
                },
                b'}' => {
                    depth = depth.checked_sub(1).ok_or_else(|| {
                        std::io::Error::other("matrix step braces are unbalanced")
                    })?;
                    if depth == 0 {
                        let object_start = start.take().ok_or_else(|| {
                            std::io::Error::other("matrix step start is missing")
                        })?;
                        ranges.push(object_start..cursor + 1);
                    }
                },
                b']' if depth == 0 => {
                    if ranges.len() < 2 {
                        return Err(std::io::Error::other(
                            "matrix evidence has fewer than two controlled steps",
                        )
                        .into());
                    }
                    return Ok((ranges, cursor));
                },
                _ => {},
            }
        }
        cursor = cursor
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("matrix step cursor overflowed"))?;
    }
    Err(std::io::Error::other("matrix controlled step array is unterminated").into())
}
