use super::*;

const TOOLCHAINS: &str = "qualification/engineering/toolchains.tsv";

#[test]
fn quality_rejects_missing_disabled_or_quarantined_coverage_detector_descriptors_without_fallback()
-> TestResult {
    let fixture = Fixture::create()?;
    let result = (|| {
        fixture.build_fixture_xtask()?;
        let path = fixture.root.join(TOOLCHAINS);
        let original = fs::read_to_string(&path)?;
        let missing = original
            .lines()
            .filter(|line| !line.starts_with("cargo-llvm-cov\t"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&path, format!("{missing}\n"))?;
        let output = fixture.quality_output_from_built_fixture("ext")?;
        assert_rejected_output(&output, "missing required detector `cargo-llvm-cov`")?;
        assert_failed_coverage_evidence(&fixture)?;

        for state in ["disabled", "quarantined"] {
            let stateful = original
                .replacen("required_profiles\n", "required_profiles\tstate\n", 1)
                .lines()
                .map(|line| {
                    if line.starts_with("cargo-llvm-cov\t") {
                        format!("{line}\t{state}")
                    } else {
                        line.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            fs::write(&path, format!("{stateful}\n"))?;
            let output = fixture.quality_output_from_built_fixture("ext")?;
            assert_rejected_output(&output, "headers are")?;
            assert_rejected_output(&output, "required_profiles, state")?;
            if String::from_utf8_lossy(&output.stdout).contains("$ cargo llvm-cov") {
                return Err(std::io::Error::other(format!(
                    "the unsupported `{state}` detector state reached a coverage command"
                ))
                .into());
            }
        }
        fs::write(path, original)?;
        Ok(())
    })();
    let cleanup = fixture.remove();
    cleanup?;
    result
}

fn assert_failed_coverage_evidence(fixture: &Fixture) -> TestResult {
    let evidence = fixture.latest_evidence()?;
    let gate = gate_record(&evidence, "EG-COVERAGE")?;
    if gate.contains("\"result\": \"failed\"") {
        return Ok(());
    }
    Err(std::io::Error::other(
        "missing coverage detector did not retain a failed EG-COVERAGE evidence record",
    )
    .into())
}
