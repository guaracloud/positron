//! Typed, bounded decoding for committed governance audit intents.

use super::*;

impl GovernanceAuditEntry {
    pub(crate) fn decode_fields(
        position: u64,
        transaction_id: [u8; 16],
        intent: &[u8],
    ) -> Result<Self, IdentityFailure> {
        if intent.starts_with(MAGIC_V1.as_slice()) || intent.starts_with(MAGIC_V2.as_slice()) {
            return InitializationAuditEntry::decode_intent(position, intent)
                .map(Self::Initialization);
        }
        if intent.starts_with(ROOT_ROTATION_MAGIC) {
            return CatalogRootRotationAuditEntry::decode_intent(position, transaction_id, intent)
                .map(Self::CatalogRootRotation);
        }
        if intent.starts_with(&POLICY_ACTIVATION_MAGIC) {
            let mut cursor = Cursor::new(intent);
            if cursor.take_array::<8>()? != POLICY_ACTIVATION_MAGIC {
                return Err(IdentityFailure);
            }
            let idempotency_key = AdministrativeIdempotencyKey::new(cursor.take_array()?)
                .map_err(|_| IdentityFailure)?;
            if idempotency_key.to_bytes() != transaction_id {
                return Err(IdentityFailure);
            }
            let principal =
                PrincipalId::from_bytes(cursor.take_array()?).map_err(|_| IdentityFailure)?;
            let tenant = TenantId::from_bytes(cursor.take_array()?).map_err(|_| IdentityFailure)?;
            let expected_generation =
                ResourceGeneration::new(cursor.take_u64()?).map_err(|_| IdentityFailure)?;
            let generation =
                ResourceGeneration::new(cursor.take_u64()?).map_err(|_| IdentityFailure)?;
            let digest = cursor.take_array()?;
            let request_digest = cursor.take_array()?;
            if expected_generation.get().checked_add(1) != Some(generation.get())
                || digest.iter().all(|byte| *byte == 0)
                || request_digest.iter().all(|byte| *byte == 0)
                || !cursor.is_empty()
            {
                return Err(IdentityFailure);
            }
            return Ok(Self::IngestPolicyActivation(
                IngestPolicyActivationAuditEntry {
                    position,
                    idempotency_key,
                    principal,
                    tenant,
                    expected_generation,
                    generation,
                    digest,
                    request_digest,
                },
            ));
        }
        if intent.starts_with(&TENANT_QUOTA_MAGIC) {
            let mut cursor = Cursor::new(intent);
            if cursor.take_array::<8>()? != TENANT_QUOTA_MAGIC {
                return Err(IdentityFailure);
            }
            let idempotency_key = AdministrativeIdempotencyKey::new(cursor.take_array()?)
                .map_err(|_| IdentityFailure)?;
            if idempotency_key.to_bytes() != transaction_id {
                return Err(IdentityFailure);
            }
            let principal =
                PrincipalId::from_bytes(cursor.take_array()?).map_err(|_| IdentityFailure)?;
            let tenant = TenantId::from_bytes(cursor.take_array()?).map_err(|_| IdentityFailure)?;
            let expected_generation =
                ResourceGeneration::new(cursor.take_u64()?).map_err(|_| IdentityFailure)?;
            let generation =
                ResourceGeneration::new(cursor.take_u64()?).map_err(|_| IdentityFailure)?;
            let weight = u32::from_be_bytes(cursor.take_array::<4>()?);
            let mut resources = [0_u64; 11];
            for resource in &mut resources {
                *resource = cursor.take_u64()?;
            }
            let request_digest = cursor.take_array::<32>()?;
            if expected_generation.get().checked_add(1) != Some(generation.get())
                || weight == 0
                || weight > u32::from(u16::MAX)
                || resources.contains(&0)
                || request_digest.iter().all(|byte| *byte == 0)
                || !cursor.is_empty()
            {
                return Err(IdentityFailure);
            }
            return Ok(Self::TenantQuotaUpdate(TenantQuotaUpdateAuditEntry {
                position,
                idempotency_key,
                principal,
                tenant,
                expected_generation,
                generation,
                weight,
                resources,
                request_digest,
            }));
        }
        if intent.starts_with(&TENANT_DISPLAY_MAGIC) {
            let mut cursor = Cursor::new(intent);
            if cursor.take_array::<8>()? != TENANT_DISPLAY_MAGIC {
                return Err(IdentityFailure);
            }
            let idempotency_key = AdministrativeIdempotencyKey::new(cursor.take_array()?)
                .map_err(|_| IdentityFailure)?;
            if idempotency_key.to_bytes() != transaction_id {
                return Err(IdentityFailure);
            }
            let principal =
                PrincipalId::from_bytes(cursor.take_array()?).map_err(|_| IdentityFailure)?;
            let tenant = TenantId::from_bytes(cursor.take_array()?).map_err(|_| IdentityFailure)?;
            let expected_generation =
                ResourceGeneration::new(cursor.take_u64()?).map_err(|_| IdentityFailure)?;
            let generation =
                ResourceGeneration::new(cursor.take_u64()?).map_err(|_| IdentityFailure)?;
            let request_digest = cursor.take_array()?;
            if expected_generation.get().checked_add(1) != Some(generation.get())
                || request_digest.iter().all(|byte| *byte == 0)
                || !cursor.is_empty()
            {
                return Err(IdentityFailure);
            }
            return Ok(Self::TenantDisplayNameUpdate(
                TenantDisplayNameUpdateAuditEntry {
                    position,
                    idempotency_key,
                    principal,
                    tenant,
                    expected_generation,
                    generation,
                    request_digest,
                },
            ));
        }
        if intent.starts_with(&schema_checkpoint::MAGIC) {
            return SchemaCheckpointAuditEntry::decode_intent(position, transaction_id, intent)
                .map(Self::SchemaCheckpoint);
        }
        if intent.starts_with(&LISTENER_TRANSPORT_V2_MAGIC) {
            let mut cursor = Cursor::new(intent);
            if cursor.take_array::<8>()? != LISTENER_TRANSPORT_V2_MAGIC {
                return Err(IdentityFailure);
            }
            let instance = cursor.take_array()?;
            let listener_target = decode_listener_target(&mut cursor)?;
            let configuration_provenance =
                ListenerTransportConfigurationProvenance::from_code(cursor.take_u8()?)?;
            let request_id = cursor.take_array()?;
            let request_digest = cursor.take_array()?;
            let request = ListenerTransportAuditRequest::configuration_file(listener_target);
            if request.configuration_provenance() != configuration_provenance {
                return Err(IdentityFailure);
            }
            if request_id != transaction_id
                || request_id != request.transaction_id_for(instance)
                || request_digest != request.digest_for(instance)
                || !cursor.is_empty()
            {
                return Err(IdentityFailure);
            }
            return Ok(Self::ListenerTransport(ListenerTransportAuditEntry::bound(
                position,
                instance,
                listener_target,
                configuration_provenance,
                request_id,
                request_digest,
            )));
        }
        if intent.starts_with(&LISTENER_TRANSPORT_MAGIC) {
            if intent.len() != LISTENER_TRANSPORT_MAGIC.len() + 16
                || intent.get(..8) != Some(LISTENER_TRANSPORT_MAGIC.as_slice())
                || intent.get(8..) != Some(transaction_id.as_slice())
                || transaction_id.iter().all(|byte| *byte == 0)
            {
                return Err(IdentityFailure);
            }
            return Ok(Self::ListenerTransport(ListenerTransportAuditEntry::new(
                position,
                transaction_id,
            )));
        }
        if intent.starts_with(&KEY_LIFECYCLE_MAGIC)
            || intent.starts_with(&KEY_LIFECYCLE_V2_MAGIC)
            || intent.starts_with(&KEY_LIFECYCLE_V3_MAGIC)
        {
            let version_two = intent.starts_with(&KEY_LIFECYCLE_V2_MAGIC);
            let version_three = intent.starts_with(&KEY_LIFECYCLE_V3_MAGIC);
            let fields = 9;
            let action = match *intent.get(8).ok_or(IdentityFailure)? {
                1 => ApiKeyLifecycleAction::Create,
                2 => ApiKeyLifecycleAction::Rotate,
                3 => ApiKeyLifecycleAction::Revoke,
                _ => return Err(IdentityFailure),
            };
            let request_digest_end =
                fields + 89 + if version_two || version_three { 32 } else { 0 };
            let tenant = if version_three {
                match *intent.get(request_digest_end).ok_or(IdentityFailure)? {
                    0 => None,
                    1 => Some(
                        TenantId::from_bytes(
                            intent
                                .get(request_digest_end + 1..request_digest_end + 17)
                                .and_then(|bytes| bytes.try_into().ok())
                                .ok_or(IdentityFailure)?,
                        )
                        .map_err(|_| IdentityFailure)?,
                    ),
                    _ => return Err(IdentityFailure),
                }
            } else {
                None
            };
            let expected_length = request_digest_end
                + if version_three {
                    1 + tenant.map_or(0, |_| 16)
                } else {
                    0
                };
            if intent.len() != expected_length
                || intent.get(..8)
                    != Some(if version_three {
                        KEY_LIFECYCLE_V3_MAGIC.as_slice()
                    } else if version_two {
                        KEY_LIFECYCLE_V2_MAGIC.as_slice()
                    } else {
                        KEY_LIFECYCLE_MAGIC.as_slice()
                    })
                || intent.get(fields + 73..fields + 89) != Some(transaction_id.as_slice())
            {
                return Err(IdentityFailure);
            }
            let actor = PrincipalId::from_bytes(
                intent
                    .get(fields..fields + 16)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(IdentityFailure)?,
            )
            .map_err(|_| IdentityFailure)?;
            let principal = PrincipalId::from_bytes(
                intent
                    .get(fields + 16..fields + 32)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(IdentityFailure)?,
            )
            .map_err(|_| IdentityFailure)?;
            let target = PrincipalId::from_bytes(
                intent
                    .get(fields + 32..fields + 48)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(IdentityFailure)?,
            )
            .map_err(|_| IdentityFailure)?;
            let scope = match *intent.get(fields + 48).ok_or(IdentityFailure)? {
                1 => Scope::Ingest,
                2 => Scope::Query,
                3 => Scope::TenantAdministration,
                _ => return Err(IdentityFailure),
            };
            let expires_at_unix_seconds = match intent
                .get(fields + 49..fields + 57)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u64::from_be_bytes)
                .ok_or(IdentityFailure)?
            {
                0 => None,
                value => Some(value),
            };
            let expected_generation = ResourceGeneration::new(
                intent
                    .get(fields + 57..fields + 65)
                    .and_then(|bytes| bytes.try_into().ok())
                    .map(u64::from_be_bytes)
                    .ok_or(IdentityFailure)?,
            )
            .map_err(|_| IdentityFailure)?;
            let generation = ResourceGeneration::new(
                intent
                    .get(fields + 65..fields + 73)
                    .and_then(|bytes| bytes.try_into().ok())
                    .map(u64::from_be_bytes)
                    .ok_or(IdentityFailure)?,
            )
            .map_err(|_| IdentityFailure)?;
            let request_digest = (version_two || version_three)
                .then(|| intent.get(fields + 89..fields + 121))
                .flatten()
                .map(|bytes| bytes.try_into().map_err(|_| IdentityFailure))
                .transpose()?;
            if expected_generation.get().checked_add(1) != Some(generation.get())
                || request_digest
                    .is_some_and(|digest: [u8; 32]| digest.iter().all(|byte| *byte == 0))
            {
                return Err(IdentityFailure);
            }
            return Ok(Self::ApiKeyLifecycle(ApiKeyLifecycleAuditEntry {
                position,
                action,
                actor,
                principal,
                target,
                scope,
                expires_at_unix_seconds,
                expected_generation,
                generation,
                idempotency_key: AdministrativeIdempotencyKey::new(transaction_id)
                    .map_err(|_| IdentityFailure)?,
                request_digest,
                tenant,
            }));
        }
        if intent.starts_with(&TENANT_CREATION_MAGIC) {
            let mut cursor = Cursor::new(intent);
            if cursor.take_array::<8>()? != TENANT_CREATION_MAGIC {
                return Err(IdentityFailure);
            }
            let idempotency_key = AdministrativeIdempotencyKey::new(cursor.take_array()?)
                .map_err(|_| IdentityFailure)?;
            if idempotency_key.to_bytes() != transaction_id {
                return Err(IdentityFailure);
            }
            let actor =
                PrincipalId::from_bytes(cursor.take_array()?).map_err(|_| IdentityFailure)?;
            let tenant = TenantId::from_bytes(cursor.take_array()?).map_err(|_| IdentityFailure)?;
            let expected_generation =
                ResourceGeneration::new(cursor.take_u64()?).map_err(|_| IdentityFailure)?;
            let generation =
                ResourceGeneration::new(cursor.take_u64()?).map_err(|_| IdentityFailure)?;
            let request_digest = cursor.take_array()?;
            if expected_generation.get().checked_add(1) != Some(generation.get())
                || request_digest.iter().all(|byte| *byte == 0)
                || !cursor.is_empty()
            {
                return Err(IdentityFailure);
            }
            return Ok(Self::TenantCreation(TenantCreationAuditEntry {
                position,
                idempotency_key,
                actor,
                tenant,
                expected_generation,
                generation,
                request_digest,
            }));
        }
        if intent.starts_with(&FORMAT_MIGRATION_MAGIC) {
            let mut cursor = Cursor::new(intent);
            if cursor.take_array::<8>()? != FORMAT_MIGRATION_MAGIC {
                return Err(IdentityFailure);
            }
            let idempotency_key = AdministrativeIdempotencyKey::new(cursor.take_array()?)
                .map_err(|_| IdentityFailure)?;
            if idempotency_key.to_bytes() != transaction_id {
                return Err(IdentityFailure);
            }
            let actor =
                PrincipalId::from_bytes(cursor.take_array()?).map_err(|_| IdentityFailure)?;
            let from = u32::from_be_bytes(cursor.take_array()?);
            let to = u32::from_be_bytes(cursor.take_array()?);
            if from != 1 || to != 2 || !cursor.is_empty() {
                return Err(IdentityFailure);
            }
            return Ok(Self::CatalogFormatMigration(
                CatalogFormatMigrationAuditEntry {
                    position,
                    idempotency_key,
                    actor,
                    from,
                    to,
                },
            ));
        }
        if intent.starts_with(&TENANT_LIFECYCLE_MAGIC)
            || intent.starts_with(&TENANT_LIFECYCLE_V2_MAGIC)
        {
            let version_two = intent.starts_with(&TENANT_LIFECYCLE_V2_MAGIC);
            let mut cursor = Cursor::new(intent);
            if cursor.take_array::<8>()?
                != if version_two {
                    TENANT_LIFECYCLE_V2_MAGIC
                } else {
                    TENANT_LIFECYCLE_MAGIC
                }
            {
                return Err(IdentityFailure);
            }
            let ingest_time_unix_seconds = cursor.take_u64()?;
            if ingest_time_unix_seconds == 0 {
                return Err(IdentityFailure);
            }
            let idempotency_key = AdministrativeIdempotencyKey::new(cursor.take_array()?)
                .map_err(|_| IdentityFailure)?;
            if idempotency_key.to_bytes() != transaction_id {
                return Err(IdentityFailure);
            }
            let actor =
                PrincipalId::from_bytes(cursor.take_array()?).map_err(|_| IdentityFailure)?;
            let tenant = TenantId::from_bytes(cursor.take_array()?).map_err(|_| IdentityFailure)?;
            let from = lifecycle_state(cursor.take_u8()?)?;
            let to = lifecycle_state(cursor.take_u8()?)?;
            let expected_generation =
                ResourceGeneration::new(cursor.take_u64()?).map_err(|_| IdentityFailure)?;
            let generation =
                ResourceGeneration::new(cursor.take_u64()?).map_err(|_| IdentityFailure)?;
            let request_digest = if version_two {
                Some(cursor.take_array()?)
            } else {
                None
            };
            if expected_generation.get().checked_add(1) != Some(generation.get())
                || request_digest
                    .is_some_and(|digest: [u8; 32]| digest.iter().all(|byte| *byte == 0))
                || !cursor.is_empty()
            {
                return Err(IdentityFailure);
            }
            return Ok(Self::TenantLifecycle(TenantLifecycleAuditEntry {
                position,
                ingest_time_unix_seconds,
                actor,
                tenant,
                from,
                to,
                expected_generation,
                generation,
                idempotency_key,
                request_digest,
            }));
        }
        if intent.starts_with(&TENANT_RETENTION_MAGIC) {
            let mut cursor = Cursor::new(intent);
            if cursor.take_array::<8>()? != TENANT_RETENTION_MAGIC {
                return Err(IdentityFailure);
            }
            let ingest_time_unix_seconds = cursor.take_u64()?;
            let idempotency_key = AdministrativeIdempotencyKey::new(cursor.take_array()?)
                .map_err(|_| IdentityFailure)?;
            if ingest_time_unix_seconds == 0 || idempotency_key.to_bytes() != transaction_id {
                return Err(IdentityFailure);
            }
            let actor =
                PrincipalId::from_bytes(cursor.take_array()?).map_err(|_| IdentityFailure)?;
            let tenant = TenantId::from_bytes(cursor.take_array()?).map_err(|_| IdentityFailure)?;
            let expected_generation =
                ResourceGeneration::new(cursor.take_u64()?).map_err(|_| IdentityFailure)?;
            let generation =
                ResourceGeneration::new(cursor.take_u64()?).map_err(|_| IdentityFailure)?;
            let _proposed_retention_seconds = cursor.take_u64()?;
            let request_digest = cursor.take_array()?;
            if expected_generation.get().checked_add(1) != Some(generation.get())
                || request_digest.iter().all(|byte| *byte == 0)
                || !cursor.is_empty()
            {
                return Err(IdentityFailure);
            }
            return Ok(Self::TenantRetentionUpdate(
                TenantRetentionUpdateAuditEntry {
                    position,
                    ingest_time_unix_seconds,
                    actor,
                    tenant,
                    expected_generation,
                    generation,
                    request_digest,
                    idempotency_key,
                },
            ));
        }
        if intent.starts_with(&SYSTEM_AUDIT_RETENTION_MAGIC) {
            let mut cursor = Cursor::new(intent);
            if cursor.take_array::<8>()? != SYSTEM_AUDIT_RETENTION_MAGIC {
                return Err(IdentityFailure);
            }
            let ingest_time_unix_seconds = cursor.take_u64()?;
            let idempotency_key = AdministrativeIdempotencyKey::new(cursor.take_array()?)
                .map_err(|_| IdentityFailure)?;
            let actor =
                PrincipalId::from_bytes(cursor.take_array()?).map_err(|_| IdentityFailure)?;
            let expected_generation =
                ResourceGeneration::new(cursor.take_u64()?).map_err(|_| IdentityFailure)?;
            let generation =
                ResourceGeneration::new(cursor.take_u64()?).map_err(|_| IdentityFailure)?;
            let retained_record_limit = cursor.take_u64()?;
            let request_digest = cursor.take_array()?;
            if ingest_time_unix_seconds == 0
                || idempotency_key.to_bytes() != transaction_id
                || expected_generation.get().checked_add(1) != Some(generation.get())
                || retained_record_limit == 0
                || request_digest.iter().all(|byte| *byte == 0)
                || !cursor.is_empty()
            {
                return Err(IdentityFailure);
            }
            return Ok(Self::SystemAuditRetentionUpdate(
                SystemAuditRetentionUpdateAuditEntry {
                    position,
                    ingest_time_unix_seconds,
                    actor,
                    expected_generation,
                    generation,
                    retained_record_limit,
                    request_digest,
                    idempotency_key,
                },
            ));
        }
        if intent.starts_with(&TENANT_ALIAS_MAGIC) {
            let mut cursor = Cursor::new(intent);
            if cursor.take_array::<8>()? != TENANT_ALIAS_MAGIC {
                return Err(IdentityFailure);
            }
            let ingest_time_unix_seconds = cursor.take_u64()?;
            let idempotency_key = AdministrativeIdempotencyKey::new(cursor.take_array()?)
                .map_err(|_| IdentityFailure)?;
            if ingest_time_unix_seconds == 0 || idempotency_key.to_bytes() != transaction_id {
                return Err(IdentityFailure);
            }
            let actor =
                PrincipalId::from_bytes(cursor.take_array()?).map_err(|_| IdentityFailure)?;
            let tenant = TenantId::from_bytes(cursor.take_array()?).map_err(|_| IdentityFailure)?;
            let expected_generation =
                ResourceGeneration::new(cursor.take_u64()?).map_err(|_| IdentityFailure)?;
            let generation =
                ResourceGeneration::new(cursor.take_u64()?).map_err(|_| IdentityFailure)?;
            let request_digest = cursor.take_array()?;
            if expected_generation.get().checked_add(1) != Some(generation.get())
                || request_digest.iter().all(|byte| *byte == 0)
                || !cursor.is_empty()
            {
                return Err(IdentityFailure);
            }
            return Ok(Self::TenantAliasBinding(TenantAliasBindingAuditEntry {
                position,
                ingest_time_unix_seconds,
                actor,
                tenant,
                expected_generation,
                generation,
                request_digest,
                idempotency_key,
            }));
        }
        Err(IdentityFailure)
    }
}
