use crate::{ResourceGeneration, TenantAdministration, TenantAdministrationFailure};
use positron_domain::{
    identity::{ExternalTenantAlias, TenantId},
    lifecycle::TenantLifecycleState,
};

const TENANT_RECORD_V1_MAGIC: [u8; 8] = *b"POSTNR01";
pub(crate) const TENANT_RECORD_V2_MAGIC: [u8; 8] = *b"POSTNR02";
pub(crate) const TENANT_RECORD_V3_MAGIC: [u8; 8] = *b"POSTNR03";
pub(crate) const TENANT_RECORD_V4_MAGIC: [u8; 8] = *b"POSTNR04";
const RESOURCE_COUNT: usize = 11;
const RESOURCE_BYTES: usize = RESOURCE_COUNT * std::mem::size_of::<u64>();

/// The mutable quota fields carried by one durable secondary-tenant record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TenantQuotaState {
    pub(crate) generation: ResourceGeneration,
    pub(crate) weight: u32,
    pub(crate) resources: [u64; 11],
}

/// The lifecycle fields of a canonical secondary-tenant record. Lifecycle
/// generation is deliberately independent from quota and policy generations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TenantLifecycleRecord {
    pub(crate) generation: ResourceGeneration,
    pub(crate) state: TenantLifecycleState,
}

/// The display and retention resources carried by one tenant's canonical
/// authority. They deliberately retain separate optimistic generations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TenantProfileState {
    pub(crate) display_name: String,
    pub(crate) display_generation: ResourceGeneration,
    pub(crate) retention_seconds: u64,
    pub(crate) retention_generation: ResourceGeneration,
}

/// The immutable external compatibility alias and its one-time bind generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TenantAliasRecord {
    pub(crate) generation: ResourceGeneration,
    pub(crate) alias: Option<ExternalTenantAlias>,
}

/// The immutable fields that other governance workflows read from a canonical
/// secondary-tenant record.
pub(crate) struct TenantRecordMetadata {
    pub(crate) tenant: TenantId,
    pub(crate) slug: String,
    pub(crate) display_name: String,
    pub(crate) display_generation: ResourceGeneration,
    pub(crate) retention_seconds: u64,
    pub(crate) retention_generation: ResourceGeneration,
    pub(crate) resources: [u64; 11],
    pub(crate) weight: u32,
    pub(crate) lifecycle: TenantLifecycleState,
    pub(crate) envelope: Vec<u8>,
}

pub(super) struct RecordLayout {
    pub(super) tenant: TenantId,
    pub(super) slug: String,
    pub(super) display_name: String,
    pub(super) envelope: Vec<u8>,
    pub(super) quota_start: usize,
    pub(super) display_length_at: usize,
    pub(super) display_end: usize,
    pub(super) retention_at: usize,
    pub(super) state: TenantQuotaState,
    pub(super) lifecycle: TenantLifecycleState,
    pub(super) lifecycle_generation: ResourceGeneration,
    pub(super) display_generation: ResourceGeneration,
    pub(super) retention_seconds: u64,
    pub(super) retention_generation: ResourceGeneration,
    pub(super) alias_generation: ResourceGeneration,
    pub(super) external_alias: Option<ExternalTenantAlias>,
    pub(super) lifecycle_at: usize,
    pub(super) lifecycle_generation_at: Option<usize>,
    pub(super) display_generation_at: Option<usize>,
    pub(super) retention_generation_at: Option<usize>,
    pub(super) alias_at: usize,
    pub(super) policy_at: usize,
}

#[path = "tenant_quota_record_facade.rs"]
mod tenant_quota_record_facade;
#[path = "tenant_quota_record_layout.rs"]
mod tenant_quota_record_layout;

pub(crate) use tenant_quota_record_facade::{
    replace_tenant_alias_record, replace_tenant_lifecycle_record, replace_tenant_profile_record,
    replace_tenant_quota_record, tenant_alias_record, tenant_lifecycle_record,
    tenant_profile_state, tenant_quota_state, tenant_record_metadata,
};
pub(crate) use tenant_quota_record_layout::is_tenant_record;
use tenant_quota_record_layout::*;

#[cfg(test)]
mod tests {
    use super::*;
    use positron_domain::lifecycle::TenantLifecycleState;

    #[test]
    fn metadata_decodes_every_persisted_lifecycle_and_rejects_unknown_codes() {
        let tenant = TenantId::from_bytes([2; 16]).expect("tenant");
        for (code, lifecycle) in [
            (1, TenantLifecycleState::Active),
            (2, TenantLifecycleState::ReadOnly),
            (3, TenantLifecycleState::Suspended),
            (4, TenantLifecycleState::Purging),
            (5, TenantLifecycleState::Purged),
        ] {
            let record = tenant_record_with_lifecycle(tenant, [1; 11], code);
            assert_eq!(
                tenant_record_metadata(&record)
                    .expect("valid lifecycle record")
                    .lifecycle,
                lifecycle
            );
        }
        for code in [0, 6, u8::MAX] {
            let record = tenant_record_with_lifecycle(tenant, [1; 11], code);
            assert!(
                tenant_record_metadata(&record).is_err(),
                "lifecycle code {code} must fail closed"
            );
        }
    }

    #[test]
    fn quota_replacement_preserves_every_non_quota_secondary_tenant_field() {
        let tenant = TenantId::from_bytes([2; 16]).expect("tenant");
        let original = tenant_record(tenant, [1; 11]);
        let successor = TenantQuotaState {
            generation: ResourceGeneration::new(2).expect("generation"),
            weight: 7,
            resources: [3; 11],
        };

        let replacement = replace_record_quota(&original, tenant, successor)
            .expect("replace canonical tenant quota");

        assert_eq!(
            quota_from_record(&replacement, tenant).expect("read replacement"),
            successor
        );
        assert_eq!(
            &replacement[..quota_start(&original).expect("quota offset")],
            &original[..quota_start(&original).expect("quota offset")]
        );
        assert_eq!(
            &replacement[quota_end(&original).expect("quota end")..],
            &original[quota_end(&original).expect("quota end")..]
        );
    }

    #[test]
    fn legacy_lifecycle_successor_upgrades_only_the_distinct_lifecycle_generation() {
        let tenant = TenantId::from_bytes([4; 16]).expect("tenant");
        let original = tenant_record(tenant, [1; 11]);
        let original_layout = record_layout(&original).expect("legacy layout");
        let original_policy_at = original_layout.policy_at;
        let original_envelope = original_layout.envelope.clone();
        let replacement = rewrite_lifecycle(
            &original,
            original_layout,
            TenantLifecycleRecord {
                generation: ResourceGeneration::new(2).expect("generation"),
                state: TenantLifecycleState::ReadOnly,
            },
        )
        .expect("lifecycle successor");
        let replacement_layout = record_layout(&replacement).expect("version two layout");

        assert!(replacement.starts_with(&TENANT_RECORD_V2_MAGIC));
        assert_eq!(replacement_layout.lifecycle, TenantLifecycleState::ReadOnly);
        assert_eq!(replacement_layout.lifecycle_generation.get(), 2);
        assert_eq!(
            &replacement[replacement_layout.policy_at..replacement_layout.policy_at + 8],
            &original[original_policy_at..original_policy_at + 8],
            "the existing policy generation remains independent"
        );
        assert_eq!(replacement_layout.envelope, original_envelope);
        assert_eq!(
            &replacement[replacement_layout.policy_at + 16..],
            &original[original_policy_at + 8..],
            "the envelope-length framing and opaque envelope remain byte-for-byte intact"
        );
    }

    #[test]
    fn quota_replacement_preserves_version_two_lifecycle_generation() {
        let tenant = TenantId::from_bytes([5; 16]).expect("tenant");
        let legacy = tenant_record(tenant, [1; 11]);
        let version_two = rewrite_lifecycle(
            &legacy,
            record_layout(&legacy).expect("legacy layout"),
            TenantLifecycleRecord {
                generation: ResourceGeneration::new(2).expect("generation"),
                state: TenantLifecycleState::ReadOnly,
            },
        )
        .expect("version two lifecycle successor");
        let replacement = replace_record_quota(
            &version_two,
            tenant,
            TenantQuotaState {
                generation: ResourceGeneration::new(2).expect("quota generation"),
                weight: 2,
                resources: [3; 11],
            },
        )
        .expect("quota successor");
        let layout = record_layout(&replacement).expect("replacement layout");

        assert_eq!(layout.lifecycle, TenantLifecycleState::ReadOnly);
        assert_eq!(layout.lifecycle_generation.get(), 2);
        assert_eq!(
            tenant_record_metadata(&replacement)
                .expect("metadata")
                .envelope,
            tenant_record_metadata(&version_two)
                .expect("original metadata")
                .envelope
        );
    }

    #[test]
    fn legacy_profile_successor_upgrades_independent_display_and_retention_generations() {
        let tenant = TenantId::from_bytes([8; 16]).expect("tenant");
        let original = tenant_record(tenant, [1; 11]);
        let original_layout = record_layout(&original).expect("legacy layout");
        let original_envelope = original_layout.envelope.clone();
        let successor = TenantProfileState {
            display_name: "Renamed tenant".to_owned(),
            display_generation: ResourceGeneration::new(2).expect("display generation"),
            retention_seconds: 86_400,
            retention_generation: ResourceGeneration::new(2).expect("retention generation"),
        };

        let replacement =
            rewrite_profile(&original, original_layout, &successor).expect("profile successor");
        let metadata = tenant_record_metadata(&replacement).expect("profile metadata");

        assert!(replacement.starts_with(&TENANT_RECORD_V3_MAGIC));
        assert_eq!(metadata.display_name, "Renamed tenant");
        assert_eq!(metadata.display_generation.get(), 2);
        assert_eq!(metadata.retention_seconds, 86_400);
        assert_eq!(metadata.retention_generation.get(), 2);
        assert_eq!(metadata.lifecycle, TenantLifecycleState::Active);
        assert_eq!(metadata.resources, [1; 11]);
        assert_eq!(metadata.envelope, original_envelope);
    }

    #[test]
    fn profile_record_alias_successor_upgrades_without_rewriting_other_authority() {
        let tenant = TenantId::from_bytes([0x81; 16]).expect("tenant");
        let legacy = tenant_record(tenant, [1; 11]);
        let profile = rewrite_profile(
            &legacy,
            record_layout(&legacy).expect("legacy layout"),
            &TenantProfileState {
                display_name: "Profile tenant".to_owned(),
                display_generation: ResourceGeneration::new(2).expect("display generation"),
                retention_seconds: 86_400,
                retention_generation: ResourceGeneration::new(2).expect("retention generation"),
            },
        )
        .expect("profile successor");
        let profile_layout = record_layout(&profile).expect("profile layout");
        let envelope = profile_layout.envelope.clone();

        let successor = rewrite_alias(
            &profile,
            profile_layout,
            TenantAliasRecord {
                generation: ResourceGeneration::new(2).expect("alias generation"),
                alias: Some(ExternalTenantAlias::parse("tenant-alias").expect("alias")),
            },
        )
        .expect("alias successor");
        let metadata = tenant_record_metadata(&successor).expect("metadata");

        assert!(successor.starts_with(&TENANT_RECORD_V4_MAGIC));
        assert_eq!(metadata.display_name, "Profile tenant");
        assert_eq!(metadata.display_generation.get(), 2);
        assert_eq!(metadata.retention_seconds, 86_400);
        assert_eq!(metadata.retention_generation.get(), 2);
        assert_eq!(
            record_layout(&successor)
                .expect("alias layout")
                .alias_generation
                .get(),
            2
        );
        assert_eq!(
            record_layout(&successor)
                .expect("alias layout")
                .external_alias
                .as_ref()
                .map(ExternalTenantAlias::as_str),
            Some("tenant-alias")
        );
        assert_eq!(metadata.envelope, envelope);
    }

    #[test]
    fn version_two_zero_lifecycle_generation_fails_closed() {
        let tenant = TenantId::from_bytes([6; 16]).expect("tenant");
        let legacy = tenant_record(tenant, [1; 11]);
        let mut version_two = rewrite_lifecycle(
            &legacy,
            record_layout(&legacy).expect("legacy layout"),
            TenantLifecycleRecord {
                generation: ResourceGeneration::new(2).expect("generation"),
                state: TenantLifecycleState::ReadOnly,
            },
        )
        .expect("version two lifecycle successor");
        let layout = record_layout(&version_two).expect("version two layout");
        let generation_at = layout
            .lifecycle_generation_at
            .expect("version two generation");
        version_two[generation_at..generation_at + 8].copy_from_slice(&0_u64.to_be_bytes());
        assert!(tenant_record_metadata(&version_two).is_err());
    }

    #[test]
    fn version_two_tenant_record_rejects_every_truncation() {
        let tenant = TenantId::from_bytes([7; 16]).expect("tenant");
        let legacy = tenant_record(tenant, [1; 11]);
        let version_two = rewrite_lifecycle(
            &legacy,
            record_layout(&legacy).expect("legacy layout"),
            TenantLifecycleRecord {
                generation: ResourceGeneration::new(2).expect("generation"),
                state: TenantLifecycleState::Suspended,
            },
        )
        .expect("version two lifecycle successor");
        for length in 0..version_two.len() {
            assert!(
                tenant_record_metadata(&version_two[..length]).is_err(),
                "version two truncation at {length} must fail closed"
            );
        }
    }

    #[test]
    fn quota_record_rejects_unknown_tenant_and_every_truncation() {
        let tenant = TenantId::from_bytes([2; 16]).expect("tenant");
        let record = tenant_record(tenant, [1; 11]);
        let other = TenantId::from_bytes([3; 16]).expect("other tenant");
        assert!(replace_record_quota(&record, other, quota_state()).is_err());
        for length in 0..record.len() {
            assert!(
                replace_record_quota(&record[..length], tenant, quota_state()).is_err(),
                "truncation at {length} must fail closed"
            );
        }
    }

    fn quota_state() -> TenantQuotaState {
        TenantQuotaState {
            generation: ResourceGeneration::new(2).expect("generation"),
            weight: 7,
            resources: [3; 11],
        }
    }

    fn tenant_record(tenant: TenantId, resources: [u64; 11]) -> Vec<u8> {
        tenant_record_with_lifecycle(tenant, resources, 1)
    }

    fn tenant_record_with_lifecycle(
        tenant: TenantId,
        resources: [u64; 11],
        lifecycle: u8,
    ) -> Vec<u8> {
        let slug = b"tenant";
        let display = b"Tenant display";
        let envelope = b"POSKE01:opaque-envelope";
        let mut record = Vec::new();
        record.extend_from_slice(b"POSTNR01");
        record.extend_from_slice(&[1; 16]);
        record.extend_from_slice(&tenant.to_bytes());
        record.push(u8::try_from(slug.len()).expect("slug bound"));
        record.extend_from_slice(slug);
        record.push(u8::try_from(display.len()).expect("display bound"));
        record.extend_from_slice(display);
        record.extend_from_slice(&2_592_000_u64.to_be_bytes());
        record.extend_from_slice(&1_u64.to_be_bytes());
        record.extend_from_slice(&1_u32.to_be_bytes());
        for resource in resources {
            record.extend_from_slice(&resource.to_be_bytes());
        }
        record.push(lifecycle);
        record.extend_from_slice(&1_u64.to_be_bytes());
        record.extend_from_slice(
            &u16::try_from(envelope.len())
                .expect("envelope bound")
                .to_be_bytes(),
        );
        record.extend_from_slice(envelope);
        record
    }
}
