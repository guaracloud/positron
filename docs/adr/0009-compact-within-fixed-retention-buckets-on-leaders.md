# Compact within fixed retention buckets on leaders

Compaction atomically replaces sealed segments only when they belong to the same tenant, signal store, and fixed ingest-time retention bucket; active segments are never inputs. It may change store blocks, indexes, encodings, and physical order but must preserve logical telemetry, isolation, durability, retention, and query semantics. In HA mode the shard leader produces and replicates the physical output, avoiding divergent follower layouts, while old segments remain available to existing query snapshots until reclamation is safe.
