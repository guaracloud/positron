# Make the OCI image the primary portable runtime

Docker is Positron's primary portable runtime. Release 1 publishes one signed
OCI image for `linux/amd64` and `linux/arm64`, and the same image runs under
Docker, Docker Compose, and Kubernetes while containing both the server and
complete CLI. It runs in the foreground as a non-root arbitrary UID, supports a
read-only root filesystem, writes only to explicit data, configuration,
temporary, and key mounts, emits structured standard-stream logs, observes
cgroup limits, exposes liveness and readiness, and drains and durably closes on
`SIGTERM`. Docker and Helm examples persist data and automatically managed
local-key material in separate volumes. The minimal image contains current CA
roots but no shell, package manager, language runtime, or debug tools.
Integration tests cover install, initialize, ingest, query, restart, backup,
restore, key management, and upgrade behavior for the image.
