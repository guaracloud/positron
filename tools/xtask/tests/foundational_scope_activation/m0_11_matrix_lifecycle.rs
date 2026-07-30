#[test]
fn quality_qual_does_not_execute_diagnostic_matrix_targets_or_claim_qualification() -> TestResult {
    let fixture = create_matrix_fixture()?;
    let result = (|| {
        let marker = fixture
            .root
            .join("target/quality-tools/matrix-qual-must-not-run");
        fs::write(&marker, "matrix target must remain unexecuted\n")?;
        install_matrix_cargo_fault(
            &fixture,
            "qual",
            "rm target/quality-tools/matrix-qual-must-not-run\n    exit 73",
        )?;
        let output = matrix_quality_output(&fixture, "qual")?;
        if output.status.success() {
            return Err(std::io::Error::other(
                "QUAL must remain rejected until exact-artifact qualification is authorized",
            )
            .into());
        }
        if !marker.is_file() {
            return Err(
                std::io::Error::other("QUAL executed an M0 diagnostic matrix target").into(),
            );
        }
        let evidence = fixture.latest_evidence()?;
        let gate = gate_record(&evidence, "EG-MATRIX")?;
        if !gate.contains(
            "exact-targets=0; binding-root=not-applicable; product-outcome=missing",
        )
            || !gate.contains("\"controlled_steps\":[]")
        {
            return Err(std::io::Error::other(
                "QUAL matrix evidence did not retain its no-qualification boundary",
            )
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn matrix_fixture_suppresses_nested_output_and_retains_structured_evidence() -> TestResult {
    let fixture = create_matrix_fixture()?;
    let result = (|| {
        let output = matrix_quality_output(&fixture, "pr")?;
        if !output.status.success() {
            return Err(std::io::Error::other(
                "matrix output-capture fixture failed; inspect retained structured evidence",
            )
            .into());
        }
        let matrix_console_bytes = String::from_utf8_lossy(&output.stdout)
            .lines()
            .chain(String::from_utf8_lossy(&output.stderr).lines())
            .filter(|line| line.contains("EG-MATRIX"))
            .map(str::len)
            .sum::<usize>();
        if matrix_console_bytes > MAXIMUM_MATRIX_CONSOLE_BYTES {
            return Err(std::io::Error::other(format!(
                "matrix-attributable console output exceeds the {MAXIMUM_MATRIX_CONSOLE_BYTES}-byte limit"
            ))
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        let gate = gate_record(&evidence, "EG-MATRIX")?;
        if !gate.contains("exact-targets=14")
            || gate.contains("target=rust-host-1;kind=compile;mode=runner-capability")
        {
            return Err(
                std::io::Error::other("EG-MATRIX evidence summary is not constant-sized").into(),
            );
        }
        let report = fs::read_to_string(exact_raw_report_path(
            &fixture.root,
            &evidence,
            "EG-MATRIX",
        )?)?;
        let controlled_steps = report.contains("\"controlled_steps\"");
        let resolved_programs = report.matches("\"resolved_program\"").count();
        let detail = matrix_public_detail(gate)?;
        if !controlled_steps
            || resolved_programs != 28
            || !report.contains(&format!("\"detail\": \"{detail}\""))
        {
            return Err(std::io::Error::other(format!(
                "nested matrix runner did not retain structured controlled evidence: steps={controlled_steps}; resolved-programs={resolved_programs}"
            ))
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn matrix_failure_console_is_bounded_and_points_to_retained_evidence() -> TestResult {
    let fixture = create_matrix_fixture()?;
    let result: TestResult = (|| {
        install_matrix_cargo_fault(
            &fixture,
            "console-failure",
            "printf '%s\\n' 'matrix fixture failure' >&2\n    exit 73",
        )?;
        let output = matrix_quality_output(&fixture, "pr")?;
        assert_rejected_output(&output, "[EG-MATRIX] failed")?;
        let evidence_path = fixture.latest_evidence_path()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.contains("Evidence:")
            || !stdout.contains(evidence_path.to_string_lossy().as_ref())
        {
            return Err(std::io::Error::other(
                "bounded matrix failure console output did not point to retained evidence",
            )
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn quality_ext_executes_all_diagnostic_targets_without_reusing_product_qualification() -> TestResult {
    let fixture = create_matrix_fixture()?;
    let result = (|| {
        install_product_target(&fixture)?;
        let output = matrix_quality_output(&fixture, "ext")?;
        if !output.status.success() {
            return Err(std::io::Error::other(
                "EXT must execute the registered diagnostic runner-capability targets",
            )
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        let gate = gate_record(&evidence, "EG-MATRIX")?;
        let detail = matrix_public_detail(gate)?;
        if !detail.contains("exact-targets=14")
            || !detail.contains("product-outcome=inactive")
            || !detail.contains("qualification=no-product-qualification")
        {
            return Err(std::io::Error::other(
                "EXT matrix evidence reused a product target or qualification outcome",
            )
            .into());
        }
        let report = fs::read_to_string(exact_raw_report_path(
            &fixture.root,
            &evidence,
            "EG-MATRIX",
        )?)?;
        if gate.matches("\"resolved_program\":").count() != 14
            || report.matches("\"resolved_program\":").count() != 28
            || report.contains("ProductTargetDiagnostic")
        {
            return Err(std::io::Error::other(
                "EXT did not retain exactly fourteen independent diagnostic target steps",
            )
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn matrix_product_target_is_not_applicable_when_its_artifact_scope_is_inactive() -> TestResult {
    let fixture = Fixture::create()?;
    install_product_target(&fixture)?;
    fixture.build_fixture_xtask()?;
    let result = (|| {
        let output = matrix_quality_output(&fixture, "pr")?;
        if !output.status.success() {
            return Err(std::io::Error::other(
                "inactive product matrix scope must retain a diagnostic-only outcome",
            )
            .into());
        }
        let evidence = fixture.latest_evidence()?;
        let gate = gate_record(&evidence, "EG-MATRIX")?;
        let detail = matrix_public_detail(gate)?;
        if !detail.contains("product-outcome=inactive")
            || detail.contains("identity=")
            || detail.len() > MAXIMUM_MATRIX_CONSOLE_BYTES
        {
            return Err(std::io::Error::other(
                "inactive product matrix summary is not the bounded typed public form",
            )
            .into());
        }
        let report = fs::read_to_string(exact_raw_report_path(
            &fixture.root,
            &evidence,
            "EG-MATRIX",
        )?)?;
        if !report.contains(detail)
            || !report.contains("qualification=no-product-qualification")
        {
            return Err(std::io::Error::other(
                "inactive product target raw report did not cross-reference its typed diagnostic outcome",
            )
            .into());
        }
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

#[test]
fn matrix_registries_enforce_exact_and_max_plus_one_source_boundaries() -> TestResult {
    for (name, path, bytes, expected) in [
        (
            "required-exact",
            TARGETS,
            MAXIMUM_MATRIX_REGISTRY_BYTES,
            "exact target registry header does not match",
        ),
        (
            "required-max-plus-one",
            TARGETS,
            MAXIMUM_MATRIX_REGISTRY_BYTES + 1,
            "exact target registry exceeds 16384 bytes",
        ),
        (
            "optional-exact",
            "qualification/engineering/matrix-product-targets.tsv",
            MAXIMUM_MATRIX_REGISTRY_BYTES,
            "matrix product target registry header does not match",
        ),
        (
            "optional-max-plus-one",
            "qualification/engineering/matrix-product-targets.tsv",
            MAXIMUM_MATRIX_REGISTRY_BYTES + 1,
            "matrix product target registry exceeds 16384 bytes",
        ),
    ] {
        let fixture = create_matrix_fixture()?;
        let result: TestResult = (|| {
            fs::write(fixture.root.join(path), vec![b'x'; bytes])?;
            let output = matrix_quality_output(&fixture, "pr")?;
            assert_rejected_output(&output, expected).map_err(|error| {
                std::io::Error::other(format!("{name} boundary failed: {error}")).into()
            })
        })();
        let cleanup = fixture.remove();
        cleanup?;
        result?;
    }
    Ok(())
}
