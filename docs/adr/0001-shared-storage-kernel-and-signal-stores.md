# Share one storage kernel across signal-specific stores

Positron uses one storage kernel for durability, metadata, lifecycle, replication, and query infrastructure while giving each telemetry signal its own signal store. A uniform physical model would weaken signal-specific optimization, while independent engines would duplicate infrastructure and undermine the single-system operational model.
