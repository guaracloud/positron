# Descriptor-authoritative local-key ACL custody

**Snapshot:** 2026-08-12
**Issue:** [#27 — M1-03 hardened local key bootstrap](https://github.com/guaracloud/positron/issues/27)
**Status:** Implemented with an approved, private macOS FFI leaf; native target evidence remains required by the issue acceptance gates.

## Conclusion

Positron can enforce owner-only ACL custody for the Release 1 local root key on both Linux and macOS without weakening descriptor authority. The earlier conclusion that the property is impossible in safe Rust is too broad:

- Linux already has a suitable safe descriptor API in the workspace's `rustix` dependency: `fgetxattr` can reject a POSIX access ACL on the exact opened object.
- macOS has the necessary descriptor API, `acl_get_fd_np(fd, ACL_TYPE_EXTENDED)`. Positron now owns a private, narrowly scoped workspace leaf that exposes only a safe borrowed-descriptor presence query and isolates the reviewed FFI.

The implementation therefore does not depend on a path-based ACL query, `/dev/fd` indirection, `F_GETPATH`, post-query identity checks, advisory locks, or an unreleased third-party wrapper. Those alternatives would reopen a time-of-check/time-of-use gap.

The approved boundary is the private `positron-darwin-acl` leaf. Its safe API accepts `BorrowedFd`; its platform implementation alone contains the reviewed `acl_get_fd_np`/`acl_free` calls; and its crate-level lint denies unsafe code everywhere except that documented native module. The open `exacl` pull request described below remains feasibility evidence, not a dependency.

## Binding product contract

The accepted contract is stronger than checking Unix mode bits:

- [The Release 1 product contract](../../project-positron.md#192-encryption-at-rest) requires exclusive, no-follow, owner-only key creation, durable synchronization, and startup verification of a regular single-link file with expected ownership, permissions, version, and fingerprint. A filesystem that cannot enforce these controls must be rejected.
- [ADR-0045](../adr/0045-harden-the-automatically-generated-local-root-key-file.md) requires rejection of unsafe permissions, unexpected ownership, symbolic links, hard links, and filesystems unable to enforce the controls.
- [ADR-0032](../adr/0032-use-envelope-encryption-with-local-and-external-key-providers.md) and [ADR-0035](../adr/0035-make-encryption-mandatory-and-bootstrap-a-local-key.md) make the protected local key-file provider part of Release 1 bootstrap.
- The distribution matrix includes native Linux and native macOS. The product contract says removing a required Release 1 capability requires a superseding ADR.

Consequently, a typed unsupported result is correct for a particular filesystem that cannot provide the necessary guarantee. Treating the entire macOS local provider as unsupported would change accepted Release 1 scope and would require a superseding ADR.

The attainable guarantee is point-in-time custody of the exact opened object: at inspection, no ACL grants access beyond the owner-only mode and ownership policy. No discretionary-access-control check can promise permanent immutability against a privileged process or the owning user after the check.

## Platform result

| Platform | Exact-object mechanism | Safe Rust availability | Result |
|---|---|---|---|
| Linux | Query `system.posix_acl_access` with descriptor-based `fgetxattr`; also reject access/default ACLs on the security directory | Released safe API in [`rustix::fs::fgetxattr`](https://docs.rs/rustix/1.1.4/rustix/fs/fn.fgetxattr.html) | Implementable now |
| macOS | Call `acl_get_fd_np(fd, ACL_TYPE_EXTENDED)` on the retained descriptor | Private owned safe wrapper in `positron-darwin-acl` | Implemented; retain native Intel and Apple Silicon evidence |

### Linux

Linux POSIX access ACLs are stored in the `system.posix_acl_access` extended attribute; directory inheritance uses `system.posix_acl_default`. The [Linux ACL specification](https://man7.org/linux/man-pages/man5/acl.5.html) describes the relationship between access ACLs and file permission bits, while the kernel's [ext4 attribute documentation](https://www.kernel.org/doc/html/latest/filesystems/ext4/attributes.html) identifies the storage names. Extended-attribute operations are atomic for an individual attribute according to [`xattr(7)`](https://man7.org/linux/man-pages/man7/xattr.7.html).

For issue #27, a conservative rule is simpler and stronger than decoding the ACL:

1. Retain the already validated file descriptor.
2. Query `system.posix_acl_access` through `rustix::fs::fgetxattr`.
3. Accept only the platform's no-data result. Any returned value or buffer-too-small result proves presence and must be rejected; unsupported or unexpected errors fail closed.
4. Apply the same access-ACL rule to the opened security directory and additionally reject its `system.posix_acl_default` attribute, because it can affect newly created children.

This rejects even ACLs equivalent to the mode bits. That is conservative, easy to audit, and consistent with the owner-only contract. The Linux ACL project's [`acl_extended_fd`](https://man7.org/linux/man-pages/man3/acl_extended_fd.3.html) could distinguish an extended ACL from a mode-equivalent minimal ACL, but Positron does not need that extra complexity.

### macOS

The current Apple SDK declares `acl_get_fd_np(int, acl_type_t)` and `ACL_TYPE_EXTENDED`. Unlike the POSIX `acl_get_fd` form, the `_np` overload accepts the ACL type required for macOS extended ACLs. It queries the object referred to by the file descriptor and returns an allocated ACL object that must be released exactly once with `acl_free`.

Ordinary mode validation is insufficient on macOS. A local reproduction created a file, set mode `0600`, added an `everyone allow read` ACL, and set mode `0600` again. `stat` still reported mode `0600`, the expected owner, and one link, while `ls -le` still showed the allow entry. Apple also documents ACLs as a permission mechanism in addition to BSD mode bits in the [File System Programming Guide](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html). The XNU `fchmod` implementation changes `va_mode`; ACL handling is separate in [`vfs_syscalls.c`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/vfs/vfs_syscalls.c#L8187-L8297).

The correct macOS check is therefore an `acl_get_fd_np` query on the retained descriptor. Absence is acceptable; an ACL object is rejected after it is freed; unsupported and unexpected errors fail closed. The security directory must be checked as well as the key file, including inherited entries relevant to child creation.

## Rust ecosystem audit

| Candidate | Finding | Suitability |
|---|---|---|
| [`rustix` 1.1.4](https://docs.rs/rustix/1.1.4/rustix/fs/fn.fgetxattr.html) | Safe `AsFd`-based `fgetxattr`; already a Positron dependency. Does not wrap Apple's ACL API. | Use for Linux; insufficient alone for macOS |
| [`exacl` 0.13.0](https://docs.rs/exacl/0.13.0/exacl/) | Maintained cross-platform crate, but the released public API is pathname-based. | Released version is unsuitable |
| [`exacl` PR #286](https://github.com/byllyfish/exacl/pull/286) | Adds a safe macOS `BorrowedFd` ACL-presence query around `acl_get_fd_np`. At the snapshot it is open, merge-conflicted, unreleased, and requested by the maintainer to be generalized. | Feasibility evidence only; not dependency-ready |
| [`acl-rs` 0.1.1](https://docs.rs/acl-rs/0.1.1/acl_rs/struct.Acl.html) | Exposes `for_fd(i32)` over POSIX `acl_get_fd`, not the typed macOS extended ACL query; its documentation also identifies a potentially unsound entry-construction operation. LGPL-2.1-only. | Reject |
| [`posix-acl` 1.2.0](https://docs.rs/posix-acl/1.2.0/posix_acl/) | Linux-only and pathname-based; explicitly does not support macOS. | Reject |
| [`acl-sys` 1.2.2](https://docs.rs/acl-sys/1.2.2/acl_sys/) | Raw unsafe bindings; no safe exact-object abstraction and no required `_np` API found. LGPL-2.1. | Reject |
| `nix` | No safe descriptor ACL API or suitable extended-attribute API found. | Reject |

No crate named `acl` with a relevant current release was found.

## Why the apparent path alternatives fail

### `F_GETPATH` plus pathname ACL query

`F_GETPATH` returns a pathname string for a descriptor; it does not turn the name into a stable handle. A later ACL call resolves that name again. An attacker who can mutate the parent namespace can replace the name between the identity check and the ACL query.

Pre-query and post-query `(device, inode)` comparisons do not close this gap. The name can point to object A for the first check, object B for the ACL query, and object A again for the last check. Retaining A open makes this ABA sequence possible without inode reuse.

### `/dev/fd/<n>`

Apple's descriptor filesystem uses synthetic descriptor vnodes and special open behavior; it is not specified as a pathname alias suitable for metadata queries. The relevant XNU paths are [`devfs_fdesc_support.c`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/miscfs/devfs/devfs_fdesc_support.c#L298-L399) and [`kern_descrip.c`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_descrip.c#L1876-L1904).

A local probe confirmed the distinction: direct `acl_get_fd_np` on an opened ACL-bearing file reported an ACL, while `acl_get_file("/dev/fd/<n>", ACL_TYPE_EXTENDED)` returned no ACL. The result remained the same after replacing the original pathname. `/dev/fd` therefore cannot stand in for the fd-native ACL call.

### Advisory locks

Advisory file locks coordinate cooperating callers. They do not pin a pathname, prevent rename/unlink, or prohibit another process from changing mode or ACL metadata. They do not make a pathname ACL query descriptor-authoritative.

## Safe dependency boundary

The repository uses `unsafe_code = "forbid"` by default for owned crates. The approved `positron-darwin-acl` leaf is an explicit exception: it independently denies unsafe code at crate level, permits it only in the documented native module, and denies unsafe operations in unsafe functions. The product crate depends on the leaf only for macOS and remains safe Rust.

The implemented macOS dependency surface exposes only a safe borrowed-descriptor query and keeps all unsafe operations private. Its continuing review requirements are:

- a private, non-published workspace leaf recorded in `Cargo.lock`;
- a target-specific dependency edge from the kernel and no extra runtime dependencies;
- audit of the exact unsafe implementation: ABI declarations and constants, borrowed-fd lifetime, null/error/`errno` handling, allocation ownership, and exactly-once `acl_free` on every successful allocation;
- no pointer dereference or ACL mutation merely to determine presence;
- native macOS Intel and Apple Silicon tests for absence, allow and deny entries, inherited entries, invalid descriptors, unsupported filesystems, and pathname replacement while the descriptor remains open;
- Linux cross-target coverage for the descriptor-xattr path;
- the dependency, advisory, SBOM, and license handling already required by [CONTRIBUTING.md](../../CONTRIBUTING.md) and the product supply-chain contract.

The current `exacl` pull request is close to the desired API shape, but adopting an open, conflicted fork would transfer a larger maintenance and security surface to Positron. The owned leaf keeps that surface to the two required native calls and one safe operation while making the exception explicit and independently testable.

## Recommendation

1. Retain the implemented Linux descriptor-xattr rule using the existing safe `rustix` API.
2. Retain the macOS descriptor-authoritative rule through the private owned leaf.
3. Keep the FFI surface isolated to `acl_get_fd_np` and exactly-once `acl_free`; do not add pathname fallbacks.
4. Do not treat the open `exacl` pull request as shipped functionality or as a Positron dependency.
5. Return typed unsupported only when the opened filesystem reports that it cannot enforce the control. If the project instead chooses to omit local bootstrap on macOS, record that product change in a superseding ADR before implementation.

This resolves the architectural question and the dependency decision. Issue #27 still requires its native cross-architecture evidence before completion.
