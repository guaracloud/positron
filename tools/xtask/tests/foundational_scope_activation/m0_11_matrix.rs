use super::*;

include!("m0_11_matrix_execution.rs");
include!("m0_11_matrix_lifecycle.rs");
include!("m0_11_matrix_policy.rs");

const MAXIMUM_MATRIX_CONSOLE_BYTES: usize = 512;
const MAXIMUM_M0_11_CONSOLE_BYTES: usize = 4_096;
const MAXIMUM_M0_11_CONSOLE_LINES: usize = 8;
fn matrix_quality_output(fixture: &Fixture, profile: &str) -> TestResult<std::process::Output> {
    let controlled_path = std::env::join_paths([
        fixture.root.join("target/quality-tools/bin"),
        std::path::PathBuf::from("/usr/bin"),
        std::path::PathBuf::from("/bin"),
        std::path::PathBuf::from("/usr/sbin"),
        std::path::PathBuf::from("/sbin"),
    ])?;
    let output = Command::new(fixture.root.join("target/debug/xtask"))
        .current_dir(&fixture.root)
        .args(["quality", "--profile", profile])
        .env("PATH", controlled_path)
        .output()?;
    if profile == "pr" {
        assert_m0_11_console_budget(&output)?;
    }
    Ok(output)
}

fn assert_m0_11_console_budget(output: &std::process::Output) -> TestResult {
    let (bytes, lines) = m0_11_console_footprint(&output.stdout, &output.stderr)?;
    if bytes > MAXIMUM_M0_11_CONSOLE_BYTES || lines > MAXIMUM_M0_11_CONSOLE_LINES {
        return Err(std::io::Error::other(format!(
            "M0-11-owned console is {bytes} bytes across {lines} lines, exceeding the {MAXIMUM_M0_11_CONSOLE_BYTES}-byte/{MAXIMUM_M0_11_CONSOLE_LINES}-line budget"
        ))
        .into());
    }
    Ok(())
}

fn m0_11_console_footprint(stdout: &[u8], stderr: &[u8]) -> TestResult<(usize, usize)> {
    let mut bytes = 0_usize;
    let mut lines = 0_usize;
    for line in String::from_utf8_lossy(stdout)
        .lines()
        .chain(String::from_utf8_lossy(stderr).lines())
    {
        if line.contains("[EG-MATRIX]")
            || line.contains("[EG-SECURITY]")
            || line.contains("security-policy=")
            || line.starts_with("Evidence:")
        {
            bytes = bytes
                .checked_add(line.len())
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| std::io::Error::other("M0-11 console byte count overflowed"))?;
            lines = lines
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("M0-11 console line count overflowed"))?;
        }
    }
    Ok((bytes, lines))
}

#[test]
fn m0_11_console_budget_excludes_unrelated_gate_noise() -> TestResult {
    let unrelated = "x".repeat(20 * 1024);
    let (bytes, lines) = m0_11_console_footprint(
        format!("[EG-SECURITY] passed\n[EG-MATRIX] passed\nEvidence: retained.json\n{unrelated}\n")
            .as_bytes(),
        b"",
    )?;
    if bytes > MAXIMUM_M0_11_CONSOLE_BYTES || lines > MAXIMUM_M0_11_CONSOLE_LINES {
        return Err(
            std::io::Error::other("unrelated gate noise changed M0-11 console accounting").into(),
        );
    }
    let oversized = format!("[EG-MATRIX] {}\n", "x".repeat(MAXIMUM_M0_11_CONSOLE_BYTES));
    let (bytes, lines) = m0_11_console_footprint(oversized.as_bytes(), b"")?;
    if bytes <= MAXIMUM_M0_11_CONSOLE_BYTES && lines <= MAXIMUM_M0_11_CONSOLE_LINES {
        return Err(std::io::Error::other("oversized M0-11 console line was not accounted").into());
    }
    Ok(())
}

fn matrix_public_detail(gate: &str) -> TestResult<&str> {
    let (_, detail) = gate
        .rsplit_once("\"detail\": \"")
        .ok_or_else(|| std::io::Error::other("EG-MATRIX evidence omitted its public detail"))?;
    detail
        .split_once("\"\n")
        .map(|(detail, _)| detail)
        .ok_or_else(|| std::io::Error::other("EG-MATRIX public detail was not terminated"))
        .map_err(Into::into)
}

fn create_matrix_fixture() -> TestResult<Fixture> {
    let fixture = Fixture::create_current_registry()?;
    fixture.build_fixture_xtask()?;
    Ok(fixture)
}

fn install_matrix_cargo_fault(fixture: &Fixture, name: &str, body: &str) -> TestResult {
    let marker = format!("target/quality-tools/matrix-fault-{name}");
    let cargo = fixture.root.join("target/quality-tools/bin/cargo");
    let insertion = format!(
        "if [ -n \"${{POSITRON_MATRIX_TARGET_ID:-}}\" ] && [ -f {marker} ]; then\n  {body}\nfi\ncase \"$command\" in"
    );
    replace_once(&cargo, "case \"$command\" in", &insertion)?;
    fs::write(fixture.root.join(marker), "trigger\n")?;
    Ok(())
}

fn replace_once_after(path: &Path, marker: &str, before: &str, after: &str) -> TestResult {
    let content = fs::read_to_string(path)?;
    let (prefix, tail) = content
        .split_once(marker)
        .ok_or_else(|| std::io::Error::other("matrix evidence gate marker is missing"))?;
    let (head, suffix) = tail.split_once(before).ok_or_else(|| {
        std::io::Error::other(format!(
            "matrix evidence target field `{before}` is missing"
        ))
    })?;
    fs::write(path, format!("{prefix}{marker}{head}{after}{suffix}"))?;
    Ok(())
}
