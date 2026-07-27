# Make tenancy a physical kernel boundary

Every ingest, query, store block, and segment is scoped to one authenticated tenant, and segments may contain data from only one tenant and one signal store. Tenant identity is part of the kernel-managed envelope and of identifier resolution, enabling independent retention, quotas, deletion, and encryption without rewriting another tenant's data. This accepts additional fragmentation for small tenants in exchange for enforceable isolation; even standalone deployments use an explicit default tenant.
