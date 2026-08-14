//! Native Positron composition root.

#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    positron::run_native(std::env::args().skip(1), std::env::vars())
}
