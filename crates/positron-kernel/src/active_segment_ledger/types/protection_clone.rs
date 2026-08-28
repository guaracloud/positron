use super::SegmentProtectionKey;
use crate::data_protection::SecretKeyBytes;

impl Clone for SegmentProtectionKey {
    fn clone(&self) -> Self {
        Self {
            key: SecretKeyBytes::from_owned(Box::new(*self.key.expose_to_backend())),
            route: self.route,
        }
    }
}
