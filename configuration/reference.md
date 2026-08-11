<!-- Keep synchronized with `crates/positron-config/src/contract.rs`. -->

# Positron Configuration Contract v1

Precedence: compiled defaults, TOML file, non-secret POSITRON__ overrides, then non-secret CLI overrides.

| Setting | Type | Default | Domain | Secrecy | Provenance | Mutability |
| --- | --- | --- | --- | --- | --- | --- |
| `schema_version` | integer | `1` | exactly `1` | public | compiled default, configuration file | immutable after initialization |
| `diagnostics.log_level` | string | `info` | `error`, `warn`, `info`, `debug` | public | compiled default, configuration file, environment, command line | live-reloadable |
| `runtime.shutdown_grace_seconds` | integer | `30` | `1..=3600` | public | compiled default, configuration file, environment, command line | restart-required |
| `listener.control_bind_address` | string | `127.0.0.1:4317` | loopback socket address; at most 256 bytes | public | compiled default, configuration file, environment, command line | drain-and-reload |
| `storage.data_directory` | string | `/var/lib/positron` | absolute path; at most 256 bytes | public | compiled default, configuration file | immutable after initialization |
| `storage.secrets_directory` | string | `/var/lib/positron-secrets` | absolute path; at most 256 bytes | public | compiled default, configuration file | immutable after initialization |
| `security.local_key_file` | string | `<redacted protected-file reference>` | protected absolute path; at most 256 bytes | secret-bearing (redacted) | compiled default, protected configuration-file reference | immutable after initialization |
