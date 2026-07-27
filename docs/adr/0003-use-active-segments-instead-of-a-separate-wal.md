# Use active segments instead of a separate WAL

Signal stores encode telemetry directly into canonical, checksummed store blocks, and the storage kernel appends those blocks to an active segment. Sealing publishes the same bytes as an immutable segment without copying, re-encoding, or replaying a separate WAL; recovery instead validates the active segment and truncates an incomplete tail. This avoids a second durable representation and its write amplification, at the cost of making every signal store's canonical block format part of the recovery contract.
