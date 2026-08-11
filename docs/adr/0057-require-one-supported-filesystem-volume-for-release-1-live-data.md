# Require one supported filesystem volume for Release 1 live data

Release 1 keeps all live segments, catalogs, kernel metadata, compaction
output, and upgrade staging on one Primary Data Volume with database-safe
filesystem semantics. Local filesystems, Docker volumes, and filesystem-mode
Kubernetes PVCs use the same contract. Before recovery, Positron verifies
durable file and directory synchronization, atomic same-filesystem
publication, safe truncation, stable reopen behavior, error propagation, and
reliable exclusive locking through a bounded Storage Capability Probe, then
holds a process-lifetime Storage Ownership Lock. Missing semantics fail closed
and cannot be bypassed by weakening acknowledged durability. Network-backed
storage is supported only for an explicitly tested provider, version, mount,
and StorageClass combination. Object storage remains a Backup Repository; raw
block and primary multi-writer storage are follow-on work. The separate
secrets root must independently meet the Local Root Key File contract.
Integration and fuzz tests cover recovery across crashes, torn tails, full
disks, remounts, volume reattachment, and duplicate-writer attempts.
