use super::TailSession;

impl Drop for TailSession<'_, '_, '_, '_> {
    fn drop(&mut self) {
        if self.cursor_observed.get() || self.terminal_emitted {
            if self._lease.as_ref().is_some_and(|lease| {
                self.state
                    .source_binding(lease.snapshot().scope().shard_id())
                    .is_some()
            }) {
                self.lease_owner.retain();
            }
            self.source_lease_owners.retain();
        }
    }
}
