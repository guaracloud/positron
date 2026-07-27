# Query committed active segments through leaders

Acknowledged store blocks become queryable immediately from active segments rather than waiting for segment sealing. A query snapshots the committed high-water mark of each involved signal store at its start; cross-signal queries do not claim a transactionally atomic boundary across stores. In the first clustered release, HA queries are leader-served and followers are reserved for replication and failover, trading follower read scaling for an unambiguous read-after-acknowledgment guarantee.
