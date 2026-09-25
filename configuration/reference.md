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
| `listener.operations_bind_address` | string | `127.0.0.1:13133` | socket address; at most 256 bytes | public | compiled default, configuration file, environment, command line | drain-and-reload |
| `listener.operations_transport` | string | `tls` | `tls`, `mtls`, `plaintext` | public | compiled default, configuration file | drain-and-reload |
| `listener.operations_accepted_socket_limit` | integer | `128` | `1..=4096`; maximum accepted sockets awaiting authentication for this listener role | public | compiled default, configuration file | drain-and-reload |
| `listener.operations_per_address_accepted_socket_limit` | integer | `16` | `1..=4096`; maximum accepted sockets awaiting authentication from one immediate peer address; cannot exceed this role's accepted-socket limit | public | compiled default, configuration file | drain-and-reload |
| `listener.operations_tls_handshake_limit` | integer | `16` | `1..=128`; maximum concurrent TLS handshakes for this listener role before authentication | public | compiled default, configuration file | drain-and-reload |
| `listener.operations_tls_handshake_deadline_seconds` | integer | `2` | `1..=300` seconds; deadline for each TLS handshake before authentication | public | compiled default, configuration file | drain-and-reload |
| `listener.operations_header_deadline_seconds` | integer | `2` | `1..=300` seconds; deadline for receiving one request header block | public | compiled default, configuration file | drain-and-reload |
| `listener.operations_body_deadline_seconds` | integer | `2` | `1..=300` seconds; deadline for receiving one request body | public | compiled default, configuration file | drain-and-reload |
| `listener.operations_request_deadline_seconds` | integer | `30` | `1..=300` seconds; deadline for handling one request | public | compiled default, configuration file | drain-and-reload |
| `listener.operations_idle_deadline_seconds` | integer | `30` | `1..=300` seconds; maximum idle connection duration | public | compiled default, configuration file | drain-and-reload |
| `listener.operations_tls_certificate_file` | string | `<redacted protected-file reference>` | protected absolute path; at most 256 bytes | secret-bearing (redacted) | compiled default, protected configuration-file reference | drain-and-reload |
| `listener.operations_tls_private_key_file` | string | `<redacted protected-file reference>` | protected absolute path; at most 256 bytes | secret-bearing (redacted) | compiled default, protected configuration-file reference | drain-and-reload |
| `listener.operations_tls_client_ca_file` | string | `<redacted protected-file reference>` | protected absolute path; at most 256 bytes | secret-bearing (redacted) | compiled default, protected configuration-file reference | drain-and-reload |
| `listener.operations.trusted_proxy_cidrs` | array | disabled | at most 16 literal IPv4 or IPv6 CIDRs, each at most 64 bytes; forwarded headers remain ignored unless this list and the matching nonzero fixed hop count are both configured | public | compiled default, configuration file | drain-and-reload |
| `listener.operations.forwarded_hops` | integer | `0` | `0..=255` | public | compiled default, configuration file | drain-and-reload |
| `listener.api_bind_address` | string | `127.0.0.1:8080` | socket address; at most 256 bytes; non-loopback requires TLS or the explicit plaintext opt-out | public | compiled default, configuration file, environment, command line | drain-and-reload |
| `listener.api_transport` | string | `tls` | `tls`, `mtls`, `plaintext`; plaintext emits a configuration warning, persistent ready health warning, and one redacted governance audit record | public | compiled default, configuration file | drain-and-reload |
| `listener.api_accepted_socket_limit` | integer | `128` | `1..=4096`; maximum accepted sockets awaiting authentication for this listener role | public | compiled default, configuration file | drain-and-reload |
| `listener.api_per_address_accepted_socket_limit` | integer | `16` | `1..=4096`; maximum accepted sockets awaiting authentication from one immediate peer address; cannot exceed this role's accepted-socket limit | public | compiled default, configuration file | drain-and-reload |
| `listener.api_tls_handshake_limit` | integer | `16` | `1..=128`; maximum concurrent TLS handshakes for this listener role before authentication | public | compiled default, configuration file | drain-and-reload |
| `listener.api_tls_handshake_deadline_seconds` | integer | `2` | `1..=300` seconds; deadline for each TLS handshake before authentication | public | compiled default, configuration file | drain-and-reload |
| `listener.api_header_deadline_seconds` | integer | `2` | `1..=300` seconds; deadline for receiving one request header block | public | compiled default, configuration file | drain-and-reload |
| `listener.api_body_deadline_seconds` | integer | `2` | `1..=300` seconds; deadline for receiving one request body | public | compiled default, configuration file | drain-and-reload |
| `listener.api_request_deadline_seconds` | integer | `30` | `1..=300` seconds; deadline for handling one request | public | compiled default, configuration file | drain-and-reload |
| `listener.api_idle_deadline_seconds` | integer | `30` | `1..=300` seconds; maximum idle connection duration | public | compiled default, configuration file | drain-and-reload |
| `listener.api.trusted_proxy_cidrs` | array | disabled | at most 16 literal IPv4 or IPv6 CIDRs, each at most 64 bytes; forwarded headers remain ignored unless this list and the matching nonzero fixed hop count are both configured | public | compiled default, configuration file | drain-and-reload |
| `listener.api.forwarded_hops` | integer | `0` | `0..=255` | public | compiled default, configuration file | drain-and-reload |
| `listener.api_tls_certificate_file` | string | `<redacted protected-file reference>` | protected absolute path; at most 256 bytes | secret-bearing (redacted) | compiled default, protected configuration-file reference | drain-and-reload |
| `listener.api_tls_private_key_file` | string | `<redacted protected-file reference>` | protected absolute path; at most 256 bytes | secret-bearing (redacted) | compiled default, protected configuration-file reference | drain-and-reload |
| `listener.api_tls_client_ca_file` | string | `<redacted protected-file reference>` | protected absolute path; at most 256 bytes | secret-bearing (redacted) | compiled default, protected configuration-file reference | drain-and-reload |
| `listener.otlp_grpc_bind_address` | string | `127.0.0.1:4317` | socket address; at most 256 bytes | public | compiled default, configuration file, environment, command line | drain-and-reload |
| `listener.otlp_grpc_transport` | string | `tls` | `tls`, `mtls`, `plaintext` | public | compiled default, configuration file | drain-and-reload |
| `listener.otlp_grpc_accepted_socket_limit` | integer | `128` | `1..=4096`; maximum accepted sockets awaiting authentication for this listener role | public | compiled default, configuration file | drain-and-reload |
| `listener.otlp_grpc_per_address_accepted_socket_limit` | integer | `16` | `1..=4096`; maximum accepted sockets awaiting authentication from one immediate peer address; cannot exceed this role's accepted-socket limit | public | compiled default, configuration file | drain-and-reload |
| `listener.otlp_grpc_tls_handshake_limit` | integer | `16` | `1..=128`; maximum concurrent TLS handshakes for this listener role before authentication | public | compiled default, configuration file | drain-and-reload |
| `listener.otlp_grpc_tls_handshake_deadline_seconds` | integer | `2` | `1..=300` seconds; deadline for each TLS handshake before authentication | public | compiled default, configuration file | drain-and-reload |
| `listener.otlp_grpc_header_deadline_seconds` | integer | `2` | `1..=300` seconds; deadline for receiving one request header block | public | compiled default, configuration file | drain-and-reload |
| `listener.otlp_grpc_body_deadline_seconds` | integer | `2` | `1..=300` seconds; deadline for receiving one request body | public | compiled default, configuration file | drain-and-reload |
| `listener.otlp_grpc_request_deadline_seconds` | integer | `30` | `1..=300` seconds; deadline for handling one request | public | compiled default, configuration file | drain-and-reload |
| `listener.otlp_grpc_idle_deadline_seconds` | integer | `30` | `1..=300` seconds; maximum idle connection duration | public | compiled default, configuration file | drain-and-reload |
| `listener.otlp_grpc_tls_certificate_file` | string | `<redacted protected-file reference>` | protected absolute path; at most 256 bytes | secret-bearing (redacted) | compiled default, protected configuration-file reference | drain-and-reload |
| `listener.otlp_grpc_tls_private_key_file` | string | `<redacted protected-file reference>` | protected absolute path; at most 256 bytes | secret-bearing (redacted) | compiled default, protected configuration-file reference | drain-and-reload |
| `listener.otlp_grpc_tls_client_ca_file` | string | `<redacted protected-file reference>` | protected absolute path; at most 256 bytes | secret-bearing (redacted) | compiled default, protected configuration-file reference | drain-and-reload |
| `listener.otlp_grpc.trusted_proxy_cidrs` | array | disabled | at most 16 literal IPv4 or IPv6 CIDRs, each at most 64 bytes; forwarded headers remain ignored unless this list and the matching nonzero fixed hop count are both configured | public | compiled default, configuration file | drain-and-reload |
| `listener.otlp_grpc.forwarded_hops` | integer | `0` | `0..=255` | public | compiled default, configuration file | drain-and-reload |
| `listener.otlp_http_bind_address` | string | `127.0.0.1:4318` | socket address; at most 256 bytes | public | compiled default, configuration file, environment, command line | drain-and-reload |
| `listener.otlp_http_transport` | string | `tls` | `tls`, `mtls`, `plaintext` | public | compiled default, configuration file | drain-and-reload |
| `listener.otlp_http_accepted_socket_limit` | integer | `128` | `1..=4096`; maximum accepted sockets awaiting authentication for this listener role | public | compiled default, configuration file | drain-and-reload |
| `listener.otlp_http_per_address_accepted_socket_limit` | integer | `16` | `1..=4096`; maximum accepted sockets awaiting authentication from one immediate peer address; cannot exceed this role's accepted-socket limit | public | compiled default, configuration file | drain-and-reload |
| `listener.otlp_http_tls_handshake_limit` | integer | `16` | `1..=128`; maximum concurrent TLS handshakes for this listener role before authentication | public | compiled default, configuration file | drain-and-reload |
| `listener.otlp_http_tls_handshake_deadline_seconds` | integer | `2` | `1..=300` seconds; deadline for each TLS handshake before authentication | public | compiled default, configuration file | drain-and-reload |
| `listener.otlp_http_header_deadline_seconds` | integer | `2` | `1..=300` seconds; deadline for receiving one request header block | public | compiled default, configuration file | drain-and-reload |
| `listener.otlp_http_body_deadline_seconds` | integer | `2` | `1..=300` seconds; deadline for receiving one request body | public | compiled default, configuration file | drain-and-reload |
| `listener.otlp_http_request_deadline_seconds` | integer | `30` | `1..=300` seconds; deadline for handling one request | public | compiled default, configuration file | drain-and-reload |
| `listener.otlp_http_idle_deadline_seconds` | integer | `30` | `1..=300` seconds; maximum idle connection duration | public | compiled default, configuration file | drain-and-reload |
| `listener.otlp_http_tls_certificate_file` | string | `<redacted protected-file reference>` | protected absolute path; at most 256 bytes | secret-bearing (redacted) | compiled default, protected configuration-file reference | drain-and-reload |
| `listener.otlp_http_tls_private_key_file` | string | `<redacted protected-file reference>` | protected absolute path; at most 256 bytes | secret-bearing (redacted) | compiled default, protected configuration-file reference | drain-and-reload |
| `listener.otlp_http_tls_client_ca_file` | string | `<redacted protected-file reference>` | protected absolute path; at most 256 bytes | secret-bearing (redacted) | compiled default, protected configuration-file reference | drain-and-reload |
| `listener.otlp_http.trusted_proxy_cidrs` | array | disabled | at most 16 literal IPv4 or IPv6 CIDRs, each at most 64 bytes; forwarded headers remain ignored unless this list and the matching nonzero fixed hop count are both configured | public | compiled default, configuration file | drain-and-reload |
| `listener.otlp_http.forwarded_hops` | integer | `0` | `0..=255` | public | compiled default, configuration file | drain-and-reload |
| `listener.loki_push_bind_address` | string | `127.0.0.1:3100` | socket address; at most 256 bytes | public | compiled default, configuration file, environment, command line | drain-and-reload |
| `listener.loki_push_transport` | string | `tls` | `tls`, `mtls`, `plaintext` | public | compiled default, configuration file | drain-and-reload |
| `listener.loki_push_accepted_socket_limit` | integer | `128` | `1..=4096`; maximum accepted sockets awaiting authentication for this listener role | public | compiled default, configuration file | drain-and-reload |
| `listener.loki_push_per_address_accepted_socket_limit` | integer | `16` | `1..=4096`; maximum accepted sockets awaiting authentication from one immediate peer address; cannot exceed this role's accepted-socket limit | public | compiled default, configuration file | drain-and-reload |
| `listener.loki_push_tls_handshake_limit` | integer | `16` | `1..=128`; maximum concurrent TLS handshakes for this listener role before authentication | public | compiled default, configuration file | drain-and-reload |
| `listener.loki_push_tls_handshake_deadline_seconds` | integer | `2` | `1..=300` seconds; deadline for each TLS handshake before authentication | public | compiled default, configuration file | drain-and-reload |
| `listener.loki_push_header_deadline_seconds` | integer | `2` | `1..=300` seconds; deadline for receiving one request header block | public | compiled default, configuration file | drain-and-reload |
| `listener.loki_push_body_deadline_seconds` | integer | `2` | `1..=300` seconds; deadline for receiving one request body | public | compiled default, configuration file | drain-and-reload |
| `listener.loki_push_request_deadline_seconds` | integer | `30` | `1..=300` seconds; deadline for handling one request | public | compiled default, configuration file | drain-and-reload |
| `listener.loki_push_idle_deadline_seconds` | integer | `30` | `1..=300` seconds; maximum idle connection duration | public | compiled default, configuration file | drain-and-reload |
| `listener.loki_push_tls_certificate_file` | string | `<redacted protected-file reference>` | protected absolute path; at most 256 bytes | secret-bearing (redacted) | compiled default, protected configuration-file reference | drain-and-reload |
| `listener.loki_push_tls_private_key_file` | string | `<redacted protected-file reference>` | protected absolute path; at most 256 bytes | secret-bearing (redacted) | compiled default, protected configuration-file reference | drain-and-reload |
| `listener.loki_push_tls_client_ca_file` | string | `<redacted protected-file reference>` | protected absolute path; at most 256 bytes | secret-bearing (redacted) | compiled default, protected configuration-file reference | drain-and-reload |
| `listener.loki_push.trusted_proxy_cidrs` | array | disabled | at most 16 literal IPv4 or IPv6 CIDRs, each at most 64 bytes; forwarded headers remain ignored unless this list and the matching nonzero fixed hop count are both configured | public | compiled default, configuration file | drain-and-reload |
| `listener.loki_push.forwarded_hops` | integer | `0` | `0..=255` | public | compiled default, configuration file | drain-and-reload |
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
positron config migrate --config PATH --output PATH
```

`validate` resolves the complete candidate and reports only its schema version
and warning count. `explain` reports each setting's canonical type, redacted
default where required, value domain, secrecy, provenance policy, and
mutability. `effective --redacted` renders the complete redacted effective
state followed by the source of every setting. `diff` resolves both canonical
documents without environment or command-line overrides, reports only redacted
semantic values and provenance, and derives one no-mutation lifecycle plan.

The current contract supports schema version 1 only. `migrate` validates its
source without environment or command-line overrides, then writes the validated
source bytes to the explicitly named output candidate. The output is created
with restrictive permissions and is never overwritten. This preserves protected
file references and avoids materializing defaults or overrides. The command
reports the deterministic zero semantic diff for version 1; unsupported
versions are rejected without coercion or an invented transformation.
