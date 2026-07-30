use super::*;

include!("m0_11_matrix_execution.rs");
include!("m0_11_matrix_lifecycle.rs");
include!("m0_11_matrix_policy.rs");

const MAXIMUM_NESTED_MATRIX_OUTPUT_BYTES: usize = 8_192;
const MAXIMUM_MATRIX_CONSOLE_BYTES: usize = 512;
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
    let bytes = output
        .stdout
        .len()
        .checked_add(output.stderr.len())
        .ok_or_else(|| std::io::Error::other("nested matrix output byte count overflowed"))?;
    if profile == "pr" && bytes > MAXIMUM_NESTED_MATRIX_OUTPUT_BYTES {
        return Err(std::io::Error::other(format!(
            "nested matrix runner output exceeds the {MAXIMUM_NESTED_MATRIX_OUTPUT_BYTES}-byte fixture suppression budget"
        ))
        .into());
    }
    Ok(output)
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
