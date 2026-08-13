use zeroize::Zeroizing;

use crate::catalog::InstanceId;
use crate::data_protection::{
    DataProtection, FrameFormatEpoch, FrameObjectContext, FrameObjectId, KeyEpoch, ObjectDataKey,
    SecretKeyBytes, SecretKeyInput, SystemObjectKind, WrappedKeyContext,
};
use positron_domain::identity::TenantId;

use super::{BootstrapKeyCustody, BootstrapKeyFailure, BootstrapObjectPurpose, map_frame};

const DERIVATION_DOMAIN: &[u8] = b"positron-instance-bootstrap-hierarchy-v2\0";

impl BootstrapKeyCustody {
    pub fn routed_instance(
        purpose: BootstrapObjectPurpose,
        encoded: &[u8],
    ) -> Result<InstanceId, BootstrapKeyFailure> {
        if encoded.get(..8) != Some(super::ENVELOPE_MAGIC.as_slice())
            || encoded.get(8).copied() != Some(purpose.tag())
        {
            return Err(BootstrapKeyFailure::Authentication);
        }
        let instance = encoded
            .get(9..25)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(BootstrapKeyFailure::Authentication)?;
        InstanceId::new(instance).map_err(|_| BootstrapKeyFailure::InvalidInput)
    }

    pub(super) fn object_key(
        &self,
        system: &SecretKeyBytes,
        instance: InstanceId,
        purpose: BootstrapObjectPurpose,
        object_id: [u8; 16],
    ) -> Result<ObjectDataKey, BootstrapKeyFailure> {
        let mut context = [0_u8; 17];
        context[0] = purpose.tag();
        context[1..].copy_from_slice(&object_id);
        Ok(ObjectDataKey::import(
            SecretKeyInput::from_owned(derive_child(
                system,
                instance,
                b"bootstrap-object-dek",
                &context,
            )?),
            object_context(object_id)?,
        ))
    }

    pub(super) fn system_kek(
        &self,
        instance: InstanceId,
    ) -> Result<SecretKeyBytes, BootstrapKeyFailure> {
        derive_child(&self.key.root_key.0, instance, b"system-kek", &[])
            .map(SecretKeyBytes::from_owned)
    }
}

pub(super) fn derive_child(
    parent: &SecretKeyBytes,
    instance: InstanceId,
    purpose: &[u8],
    context: &[u8],
) -> Result<Box<[u8; 32]>, BootstrapKeyFailure> {
    let mut input = Zeroizing::new(Vec::with_capacity(
        DERIVATION_DOMAIN.len() + 16 + purpose.len() + context.len(),
    ));
    input.extend_from_slice(DERIVATION_DOMAIN);
    input.extend_from_slice(&instance.to_bytes());
    input.extend_from_slice(purpose);
    input.extend_from_slice(context);
    DataProtection::authenticate(parent, &input)
        .map(Box::new)
        .map_err(map_frame)
}

pub(super) fn wrapped_context(
    instance: InstanceId,
    purpose: BootstrapObjectPurpose,
    object_id: [u8; 16],
) -> Result<WrappedKeyContext, BootstrapKeyFailure> {
    let mut encoding = Vec::with_capacity(64);
    encoding.extend_from_slice(b"positron-bootstrap-envelope-context-v2\0");
    encoding.push(purpose.tag());
    encoding.extend_from_slice(&instance.to_bytes());
    encoding.extend_from_slice(&object_id);
    let digest = DataProtection::hash(&encoding).map_err(map_frame)?;
    let mut key_id = Vec::with_capacity(56);
    key_id.extend_from_slice(b"positron-bootstrap-dek-identity-v2\0");
    key_id.extend_from_slice(&object_id);
    WrappedKeyContext::system(
        instance.to_bytes(),
        SystemObjectKind::InstanceBootstrap,
        DataProtection::hash(&key_id).map_err(map_frame)?,
        1,
        digest,
    )
    .map_err(map_frame)
}

pub(super) fn tenant_object_id(tenant: TenantId) -> Result<[u8; 16], BootstrapKeyFailure> {
    let mut encoding = Vec::with_capacity(48);
    encoding.extend_from_slice(b"positron-tenant-kek-identity-v1\0");
    encoding.extend_from_slice(&tenant.to_bytes());
    DataProtection::hash(&encoding)
        .map_err(map_frame)?
        .get(..16)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(BootstrapKeyFailure::InvalidInput)
}

pub(super) fn object_context(
    object_id: [u8; 16],
) -> Result<FrameObjectContext, BootstrapKeyFailure> {
    Ok(FrameObjectContext::system(
        SystemObjectKind::InstanceBootstrap,
        FrameObjectId::new(object_id).map_err(map_frame)?,
        KeyEpoch::new(1),
        FrameFormatEpoch::new(1).map_err(map_frame)?,
    ))
}
