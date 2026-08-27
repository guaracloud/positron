use super::TailSession;

impl Drop for TailSession<'_, '_, '_, '_> {
    fn drop(&mut self) {
        if self.cursor_observed.get() {
            if self
                .state
                .source_binding(self._lease.snapshot().scope().shard_id())
                .is_some()
            {
                self.lease_owner.retain();
            }
            self.source_lease_owners.retain();
        }
    }
}
