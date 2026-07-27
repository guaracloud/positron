# Tie ingest acknowledgment to deployment durability

In standalone mode, Positron acknowledges ingestion only after the store blocks are durably flushed to the local active segment. In three-replica high-availability mode, acknowledgment requires durable append by a two-replica majority. Release 1 and the first clustered release provide no memory-only acknowledgment and do not allow requests or tenants to weaken the deployment's guarantee, preventing a successful response from concealing an immediate crash-loss window.
