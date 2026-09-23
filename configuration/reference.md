<!-- Keep synchronized with `crates/positron-config/src/contract.rs`. -->

# Positron Configuration Contract v1

Precedence: compiled defaults, TOML file, non-secret POSITRON__ overrides, then non-secret CLI overrides.

| Setting | Type | Default | Domain | Secrecy | Provenance | Mutability |
| --- | --- | --- | --- | --- | --- | --- |
| `schema_version` | integer | `1` | exactly `1` | public | compiled default, configuration file | immutable after initialization |
| `diagnostics.log_level` | string | `info` | `error`, `warn`, `info`, `debug` | public | compiled default, configuration file, environment, command line | live-reloadable |
| `runtime.shutdown_grace_seconds` | integer | `30` | `1..=3600` | public | compiled default, configuration file, environment, command line | restart-required |
| `runtime.max_registered_tenants` | integer | `2` | `1..=1024`; maximum tenant quotas simultaneously registered in the live Resource Governor, including the default tenant and a pending non-admittable tenant-creation reservation | public | compiled default, configuration file, environment, command line | restart-required |
| `listener.control_path` | string | `/var/run/positron/control.sock` | absolute path; at most 256 bytes | public | compiled default, configuration file, environment, command line | drain-and-reload |
| `listener.operations_bind_address` | string | `127.0.0.1:13133` | loopback socket address; at most 256 bytes | public | compiled default, configuration file, environment, command line | drain-and-reload |
| `listener.api_bind_address` | string | `127.0.0.1:8080` | socket address; at most 256 bytes; non-loopback requires TLS or the explicit plaintext opt-out | public | compiled default, configuration file, environment, command line | drain-and-reload |
| `listener.api_transport` | string | `tls` | `tls`, `plaintext`; plaintext emits a configuration warning, persistent ready health warning, and one redacted governance audit record | public | compiled default, configuration file | drain-and-reload |
| `listener.api_tls_certificate_file` | string | `<redacted protected-file reference>` | protected absolute path; at most 256 bytes | secret-bearing (redacted) | compiled default, protected configuration-file reference | drain-and-reload |
| `listener.api_tls_private_key_file` | string | `<redacted protected-file reference>` | protected absolute path; at most 256 bytes | secret-bearing (redacted) | compiled default, protected configuration-file reference | drain-and-reload |
| `listener.otlp_grpc_bind_address` | string | `127.0.0.1:4317` | loopback socket address; at most 256 bytes | public | compiled default, configuration file, environment, command line | drain-and-reload |
| `listener.otlp_http_bind_address` | string | `127.0.0.1:4318` | loopback socket address; at most 256 bytes | public | compiled default, configuration file, environment, command line | drain-and-reload |
| `listener.loki_push_bind_address` | string | `127.0.0.1:3100` | loopback socket address; at most 256 bytes | public | compiled default, configuration file, environment, command line | drain-and-reload |
| `storage.data_directory` | string | `/var/lib/positron` | absolute path; at most 256 bytes | public | compiled default, configuration file | immutable after initialization |
| `storage.secrets_directory` | string | `/var/lib/positron-secrets` | absolute path; at most 256 bytes | public | compiled default, configuration file | immutable after initialization |
| `security.local_key_file` | string | `<redacted protected-file reference>` | protected absolute path under `storage.secrets_directory`, named `local-root-key.v1`; at most 256 bytes | secret-bearing (redacted) | compiled default, protected configuration-file reference | immutable after initialization |
| `export.destination` | array of tables | disabled | at most 8 named destinations; each has a lowercase `name` of at most 63 bytes, a nonzero 16-byte lowercase hexadecimal `identity`, and one to 8 unique canonical `allowed_tenants` | public | compiled default, configuration file | immutable after initialization |

## Durable export destinations

Durable export is disabled unless the selected TOML file includes one or more
`[[export.destination]]` entries. Environment and command-line overrides are
rejected. A destination may be selected only by an authenticated tenant named
in its `allowed_tenants`; its opaque `identity` is passed internally to the
protected Kernel output directory and is not supplied by an API caller.

```toml
[[export.destination]]
name = "regulated-archive"
identity = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
allowed_tenants = ["11111111-1111-1111-1111-111111111111"]
```

Destination names and identities must be unique. The complete candidate is
validated before publication; changing this immutable setting requires the
explicit initialization or restore workflow rather than live reload.

## Operator commands

The native binary resolves this same contract without starting the database:

```console
positron config validate [--config PATH] [--set PATH=VALUE]
positron config explain [--setting PATH]
positron config effective --redacted [--config PATH] [--set PATH=VALUE]
positron config diff --current PATH --candidate PATH
positron config migrate --config PATH
```

`validate` resolves the complete candidate and reports only its schema version
and warning count. `explain` reports each setting's canonical type, redacted
default where required, value domain, secrecy, provenance policy, and
mutability. `effective --redacted` renders the complete redacted effective
state followed by the source of every setting. `diff` resolves both canonical
documents without environment or command-line overrides, reports only redacted
semantic values and provenance, and derives one no-mutation lifecycle plan.

The current contract supports schema version 1 only. `migrate` therefore
performs a strict version-compatibility preflight and reports `changed=false`
for version 1; unsupported versions are rejected without coercion or an
invented transformation.
