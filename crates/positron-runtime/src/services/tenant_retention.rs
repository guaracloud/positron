use std::num::NonZeroU64;

use positron_api::tenant_retention::{
    MAX_PREVIEW_PAGE_ITEMS, RetentionReclamation, RetentionScopeImpact,
    TenantRetentionPreviewRequest, TenantRetentionPreviewResponse, TenantRetentionUpdateRequest,
    TenantRetentionUpdateResponse,
};
use positron_domain::identity::{PrincipalId, TenantId};
use positron_domain::routing::SignalKind;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};
use positron_kernel::RetentionReclamationEstimate;

use crate::instance_bootstrap::TenantRetentionImpactPreview;
use crate::{BootstrapFailure, BootstrapFailureCode, ServiceHandle};

pub(crate) enum TenantRetentionHttpFailure {
    Code(u16, &'static str),
    StaleGeneration {
        generation: u64,
        semantic_diff: &'static str,
    },
}

impl ServiceHandle {
    /// Authenticates the tenant-administration bearer before accepting a
    /// bounded preview body. The returned evidence comes only from the
    /// current committed ledgers and is never caller supplied.
    pub(crate) fn preview_tenant_retention(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<TenantRetentionPreviewResponse, TenantRetentionHttpFailure> {
        let actor = actor(self, bearer)?;
        let request = TenantRetentionPreviewRequest::decode(body)
            .map_err(|_| TenantRetentionHttpFailure::Code(400, "invalid_request"))?;
        let tenant = tenant(request.tenant())?;
        let proposed = seconds(request.proposed_retention_seconds())?;
        let preview = self
            .instance
            .inspect_tenant_retention_impact(actor, tenant, proposed)
            .map_err(map_failure)?;
        preview_response(preview, request.continuation())
    }

    /// Recomputes a supplied opaque confirmation at the runtime boundary
    /// before publishing. It never deserializes caller-authored impact data.
    pub(crate) fn update_tenant_retention_service(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<TenantRetentionUpdateResponse, TenantRetentionHttpFailure> {
        let actor = actor(self, bearer)?;
        let request = TenantRetentionUpdateRequest::decode(body)
            .map_err(|_| TenantRetentionHttpFailure::Code(400, "invalid_request"))?;
        let tenant = tenant(request.tenant())?;
        let proposed = seconds(request.proposed_retention_seconds())?;
        let expected = ResourceGeneration::new(request.expected_generation())
            .map_err(|_| TenantRetentionHttpFailure::Code(400, "invalid_request"))?;
        let idempotency = PrincipalId::parse_canonical(request.idempotency_key())
            .map_err(|_| TenantRetentionHttpFailure::Code(400, "invalid_request"))?;
        let confirmation_digest = request
            .confirmation_digest()
            .map(parse_confirmation_digest)
            .transpose()?;
        let update = self
            .instance
            .update_tenant_retention_with_confirmation_digest(
                actor,
                tenant,
                proposed,
                expected,
                confirmation_digest,
                AdministrativeIdempotencyKey::new(idempotency.to_bytes())
                    .map_err(|_| TenantRetentionHttpFailure::Code(400, "invalid_request"))?,
            )
            .map_err(map_failure)?;
        Ok(TenantRetentionUpdateResponse {
            tenant: update.tenant_id().to_canonical_text(),
            retention_generation: update.retention_generation().get(),
            audit_position: update.audit_position(),
            audit_ingest_time_unix_seconds: update.audit_ingest_time_unix_seconds(),
        })
    }
}

fn actor(
    services: &ServiceHandle,
    bearer: &str,
) -> Result<positron_governance::AuthorizedContext, TenantRetentionHttpFailure> {
    services
        .instance
        .attribute(
            PresentedCredential::parse(bearer)
                .map_err(|_| TenantRetentionHttpFailure::Code(401, "authentication_rejected"))?,
            RequestedIntent::TenantAdministration,
            CompatibilityHints::none(),
        )
        .map_err(|_| TenantRetentionHttpFailure::Code(401, "authentication_rejected"))
}

fn tenant(value: &str) -> Result<TenantId, TenantRetentionHttpFailure> {
    TenantId::parse_canonical(value)
        .map_err(|_| TenantRetentionHttpFailure::Code(400, "invalid_request"))
}
fn seconds(value: u64) -> Result<NonZeroU64, TenantRetentionHttpFailure> {
    NonZeroU64::new(value).ok_or(TenantRetentionHttpFailure::Code(400, "invalid_request"))
}

fn parse_confirmation_digest(value: &str) -> Result<[u8; 32], TenantRetentionHttpFailure> {
    if value.len() != 64 {
        return Err(TenantRetentionHttpFailure::Code(400, "invalid_request"));
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high =
            hex_value(pair[0]).ok_or(TenantRetentionHttpFailure::Code(400, "invalid_request"))?;
        let low =
            hex_value(pair[1]).ok_or(TenantRetentionHttpFailure::Code(400, "invalid_request"))?;
        digest[index] = (high << 4) | low;
    }
    Ok(digest)
}

const fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn preview_response(
    preview: TenantRetentionImpactPreview,
    continuation: Option<&str>,
) -> Result<TenantRetentionPreviewResponse, TenantRetentionHttpFailure> {
    let start = match continuation {
        None => 0,
        Some(value) => {
            let token = parse_preview_continuation(value)?;
            if token.get(..16) != Some(preview.tenant().to_bytes().as_slice())
                || token.get(16..24)
                    != Some(
                        preview
                            .proposed_retention_seconds()
                            .get()
                            .to_be_bytes()
                            .as_slice(),
                    )
                || token.get(24..56) != Some(preview.catalog_identity().to_bytes().as_slice())
                || token.get(56..64) != Some(preview.catalog_generation().to_be_bytes().as_slice())
                || token.get(64..96) != Some(preview.confirmation_digest().as_slice())
            {
                return Err(TenantRetentionHttpFailure::Code(409, "stale_continuation"));
            }
            usize::from(u16::from_be_bytes(
                token
                    .get(96..98)
                    .ok_or(TenantRetentionHttpFailure::Code(400, "invalid_request"))?
                    .try_into()
                    .map_err(|_| TenantRetentionHttpFailure::Code(400, "invalid_request"))?,
            ))
        },
    };
    if start > preview.scopes().len() {
        return Err(TenantRetentionHttpFailure::Code(400, "invalid_request"));
    }
    let end = start
        .checked_add(MAX_PREVIEW_PAGE_ITEMS)
        .map(|end| end.min(preview.scopes().len()))
        .ok_or(TenantRetentionHttpFailure::Code(
            503,
            "administration_unavailable",
        ))?;
    let continuation = if end < preview.scopes().len() {
        Some(format_preview_continuation(&preview, end)?)
    } else {
        None
    };
    Ok(TenantRetentionPreviewResponse {
        tenant: preview.tenant().to_canonical_text(),
        retention_generation: preview.retention_generation().get(),
        proposed_retention_seconds: preview.proposed_retention_seconds().get(),
        catalog_identity: hex(preview.catalog_identity().to_bytes()),
        catalog_generation: preview.catalog_generation(),
        confirmation_digest: hex(preview.confirmation_digest()),
        scopes: preview.scopes()[start..end]
            .iter()
            .copied()
            .map(|scope| {
                let range = scope.affected_time_range();
                let (earliest_reclamation, earliest_reclamation_unix_nanos) =
                    reclamation(scope.earliest_reclamation());
                RetentionScopeImpact {
                    signal: match scope.scope().signal_kind() {
                        SignalKind::Logs => "logs",
                        SignalKind::Traces => "traces",
                    }
                    .to_owned(),
                    shard: scope.scope().shard_id().value(),
                    catalog_identity: hex(scope.catalog_identity().to_bytes()),
                    catalog_generation: scope.catalog_generation(),
                    evaluated_at_unix_nanos: scope.evaluated_at().value(),
                    affected_start_unix_nanos: range.map(|value| value.earliest().value()),
                    affected_end_unix_nanos: range.map(|value| value.latest().value()),
                    affected_bytes: scope.approximate_affected_bytes(),
                    immediately_reclaimable_bytes: scope
                        .approximate_immediately_reclaimable_bytes(),
                    deferred_active_segment_bytes: scope.deferred_active_segment_bytes(),
                    deferred_mixed_sealed_segment_bytes: scope
                        .deferred_mixed_sealed_segment_bytes(),
                    earliest_reclamation,
                    earliest_reclamation_unix_nanos,
                }
            })
            .collect(),
        continuation,
    })
}

fn parse_preview_continuation(value: &str) -> Result<[u8; 98], TenantRetentionHttpFailure> {
    if value.len() != 196 {
        return Err(TenantRetentionHttpFailure::Code(400, "invalid_request"));
    }
    let mut bytes = [0_u8; 98];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = pair
            .first()
            .and_then(|byte| hex_value(*byte))
            .ok_or(TenantRetentionHttpFailure::Code(400, "invalid_request"))?;
        let low = pair
            .get(1)
            .and_then(|byte| hex_value(*byte))
            .ok_or(TenantRetentionHttpFailure::Code(400, "invalid_request"))?;
        *bytes
            .get_mut(index)
            .ok_or(TenantRetentionHttpFailure::Code(400, "invalid_request"))? = (high << 4) | low;
    }
    Ok(bytes)
}

fn format_preview_continuation(
    preview: &TenantRetentionImpactPreview,
    index: usize,
) -> Result<String, TenantRetentionHttpFailure> {
    let index = u16::try_from(index)
        .map_err(|_| TenantRetentionHttpFailure::Code(503, "administration_unavailable"))?;
    let mut bytes = [0_u8; 98];
    bytes[..16].copy_from_slice(&preview.tenant().to_bytes());
    bytes[16..24].copy_from_slice(&preview.proposed_retention_seconds().get().to_be_bytes());
    bytes[24..56].copy_from_slice(&preview.catalog_identity().to_bytes());
    bytes[56..64].copy_from_slice(&preview.catalog_generation().to_be_bytes());
    bytes[64..96].copy_from_slice(&preview.confirmation_digest());
    bytes[96..].copy_from_slice(&index.to_be_bytes());
    let mut text = String::with_capacity(196);
    for byte in bytes {
        text.push(hex_digit(byte >> 4));
        text.push(hex_digit(byte & 0x0f));
    }
    Ok(text)
}

fn reclamation(value: RetentionReclamationEstimate) -> (RetentionReclamation, Option<i64>) {
    match value {
        RetentionReclamationEstimate::None => (RetentionReclamation::None, None),
        RetentionReclamationEstimate::At(time) => (RetentionReclamation::At, Some(time.value())),
        RetentionReclamationEstimate::BlockedByDurableLease(time) => (
            RetentionReclamation::BlockedByDurableLease,
            Some(time.value()),
        ),
        RetentionReclamationEstimate::BlockedByInProcessSnapshot => {
            (RetentionReclamation::BlockedByInProcessSnapshot, None)
        },
    }
}

fn hex(bytes: [u8; 32]) -> String {
    let mut value = String::with_capacity(64);
    for byte in bytes {
        value.push(hex_digit(byte >> 4));
        value.push(hex_digit(byte & 0x0f));
    }
    value
}

const fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => '0',
    }
}

fn map_failure(failure: BootstrapFailure) -> TenantRetentionHttpFailure {
    match failure.code() {
        BootstrapFailureCode::TenantRetentionUnauthorized
        | BootstrapFailureCode::ApiKeyUnauthorized => {
            TenantRetentionHttpFailure::Code(401, "authentication_rejected")
        },
        BootstrapFailureCode::TenantRetentionUnknownTenant => {
            TenantRetentionHttpFailure::Code(404, "tenant_unavailable")
        },
        BootstrapFailureCode::TenantRetentionInvalidConfirmation => {
            TenantRetentionHttpFailure::Code(409, "invalid_confirmation")
        },
        BootstrapFailureCode::TenantRetentionStaleGeneration => failure
            .retention_generation_conflict()
            .map(|conflict| TenantRetentionHttpFailure::StaleGeneration {
                generation: conflict.current_generation().get(),
                semantic_diff: conflict.semantic_diff(),
            })
            .unwrap_or(TenantRetentionHttpFailure::Code(
                503,
                "administration_unavailable",
            )),
        BootstrapFailureCode::TenantRetentionIdempotencyConflict => {
            TenantRetentionHttpFailure::Code(409, "idempotency_conflict")
        },
        _ => TenantRetentionHttpFailure::Code(503, "administration_unavailable"),
    }
}
