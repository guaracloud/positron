//! Tenant, principal, scope, and attribution values.

use std::fmt::{Display, Formatter};

use crate::outcome::{DomainFailure, FailureSource};

/// An immutable, random, authoritative tenant identity.
///
/// A `TenantId` is exactly 16 non-zero bytes. Its stable textual form is 32
/// lowercase hexadecimal digits with RFC 4122-style hyphen positions. This
/// formatting is a native domain serialization promise, not a wire or durable
/// storage format. The all-zero sentinel is rejected so a default value cannot
/// cross an authorization, storage, or destructive-operation boundary as a
/// valid tenant.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TenantId([u8; 16]);

impl TenantId {
    /// Builds a tenant identity from exactly 16 random bytes.
    ///
    /// Random generation remains outside this crate so Domain Types does not
    /// reach for ambient entropy or runtime authority.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, DomainFailure> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(DomainFailure::invalid_identifier(FailureSource::TenantId));
        }
        Ok(Self(bytes))
    }

    /// Parses the canonical native textual representation of a tenant ID.
    pub fn parse_canonical(source: &str) -> Result<Self, DomainFailure> {
        parse_identifier(source, FailureSource::TenantId).and_then(Self::from_bytes)
    }

    /// Returns the 16-byte identity for a caller-owned canonical encoding.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }

    /// Returns the canonical lowercase textual domain representation.
    #[must_use]
    pub fn to_canonical_text(self) -> String {
        canonical_identifier_text(self.0)
    }
}

impl Display for TenantId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.to_canonical_text())
    }
}

/// An immutable random identity for one authenticated principal.
///
/// `PrincipalId` uses the same canonical 16-byte lowercase native text as
/// `TenantId` but remains a distinct Rust type. A principal can therefore not
/// be passed accidentally where tenant authority is required. It makes no wire
/// or durable serialization promise.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PrincipalId([u8; 16]);

impl PrincipalId {
    /// Builds a principal identity from exactly 16 random bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, DomainFailure> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(DomainFailure::invalid_identifier(
                FailureSource::PrincipalId,
            ));
        }
        Ok(Self(bytes))
    }

    /// Parses the canonical native textual representation of a principal ID.
    pub fn parse_canonical(source: &str) -> Result<Self, DomainFailure> {
        parse_identifier(source, FailureSource::PrincipalId).and_then(Self::from_bytes)
    }

    /// Returns the 16-byte identity for a caller-owned canonical encoding.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }

    /// Returns the canonical lowercase textual domain representation.
    #[must_use]
    pub fn to_canonical_text(self) -> String {
        canonical_identifier_text(self.0)
    }
}

/// The largest permitted byte length of a canonical native tenant slug.
///
/// This bounds the shared human-facing locator only. It does not limit display
/// names, protocol aliases, or tenant telemetry.
pub const MAX_TENANT_SLUG_BYTES: usize = 63;

/// An immutable, human-facing, non-reusable tenant locator.
///
/// A `TenantSlug` is one to 63 ASCII lowercase letters, digits, or internal
/// hyphens. It cannot start or end with a hyphen. Its canonical text is its
/// native representation and it never substitutes for `TenantId` in authority,
/// storage, encryption, cursor, or destructive-operation paths.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TenantSlug(String);

impl TenantSlug {
    /// Parses a checked, canonical tenant locator.
    pub fn parse_canonical(source: &str) -> Result<Self, DomainFailure> {
        if source.is_empty() || source.len() > MAX_TENANT_SLUG_BYTES {
            return Err(DomainFailure::invalid_identifier(FailureSource::TenantSlug));
        }
        let valid_boundaries = !source.starts_with('-') && !source.ends_with('-');
        let valid_characters = source.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        });
        if !valid_boundaries || !valid_characters {
            return Err(DomainFailure::invalid_identifier(FailureSource::TenantSlug));
        }
        Ok(Self(source.to_owned()))
    }

    /// Returns the immutable canonical locator text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A fixed authorization capability granted to one principal.
///
/// The variants are a closed native taxonomy. They are not wire values and no
/// custom role or string permission may be substituted for them.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Scope {
    /// Allows tenant-scoped telemetry ingestion.
    Ingest,
    /// Allows tenant-scoped query and tail traffic.
    Query,
    /// Allows tenant-scoped administration.
    TenantAdministration,
    /// Allows instance administration but never tenant data-plane impersonation.
    SystemAdministration,
}

impl Scope {
    /// Returns whether this scope is valid in a tenant attribution.
    #[must_use]
    pub const fn is_tenant_scoped(self) -> bool {
        matches!(
            self,
            Self::Ingest | Self::Query | Self::TenantAdministration
        )
    }
}

/// The checked binding of one principal, tenant scope, and exact tenant.
///
/// This post-authentication type is required before payload decoding or
/// resource admission. It has no public unchecked constructor and makes no
/// wire or persistence serialization promise.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantAttribution {
    principal_id: PrincipalId,
    scope: Scope,
    tenant_id: TenantId,
}

impl TenantAttribution {
    /// Builds an attribution only for a tenant-scoped capability.
    pub fn new(
        principal_id: PrincipalId,
        scope: Scope,
        tenant_id: TenantId,
    ) -> Result<Self, DomainFailure> {
        if !scope.is_tenant_scoped() {
            return Err(DomainFailure::invalid_attribution());
        }
        Ok(Self {
            principal_id,
            scope,
            tenant_id,
        })
    }

    /// Returns the authenticated principal without widening authority.
    #[must_use]
    pub const fn principal_id(self) -> PrincipalId {
        self.principal_id
    }

    /// Returns the fixed capability established during attribution.
    #[must_use]
    pub const fn scope(self) -> Scope {
        self.scope
    }

    /// Returns the exact tenant selected before payload handling.
    #[must_use]
    pub const fn tenant_id(self) -> TenantId {
        self.tenant_id
    }
}

fn canonical_identifier_text(bytes: [u8; 16]) -> String {
    let mut text = String::with_capacity(36);
    for (index, byte) in bytes.into_iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            text.push('-');
        }
        text.push(hex_character(byte >> 4));
        text.push(hex_character(byte & 0x0f));
    }
    text
}

fn parse_identifier(
    source: &str,
    failure_source: FailureSource,
) -> Result<[u8; 16], DomainFailure> {
    let source: [u8; 36] = source
        .as_bytes()
        .try_into()
        .map_err(|_| DomainFailure::invalid_identifier(failure_source))?;
    let [
        digit_00,
        digit_01,
        digit_02,
        digit_03,
        digit_04,
        digit_05,
        digit_06,
        digit_07,
        separator_00,
        digit_08,
        digit_09,
        digit_10,
        digit_11,
        separator_01,
        digit_12,
        digit_13,
        digit_14,
        digit_15,
        separator_02,
        digit_16,
        digit_17,
        digit_18,
        digit_19,
        separator_03,
        digit_20,
        digit_21,
        digit_22,
        digit_23,
        digit_24,
        digit_25,
        digit_26,
        digit_27,
        digit_28,
        digit_29,
        digit_30,
        digit_31,
    ] = source;
    let separators = [separator_00, separator_01, separator_02, separator_03];
    let digits = [
        digit_00, digit_01, digit_02, digit_03, digit_04, digit_05, digit_06, digit_07, digit_08,
        digit_09, digit_10, digit_11, digit_12, digit_13, digit_14, digit_15, digit_16, digit_17,
        digit_18, digit_19, digit_20, digit_21, digit_22, digit_23, digit_24, digit_25, digit_26,
        digit_27, digit_28, digit_29, digit_30, digit_31,
    ];
    if separators.into_iter().any(|separator| separator != b'-')
        || !digits.into_iter().all(is_canonical_hex)
    {
        return Err(DomainFailure::invalid_identifier(failure_source));
    }

    Ok([
        decode_hex_pair(digit_00, digit_01),
        decode_hex_pair(digit_02, digit_03),
        decode_hex_pair(digit_04, digit_05),
        decode_hex_pair(digit_06, digit_07),
        decode_hex_pair(digit_08, digit_09),
        decode_hex_pair(digit_10, digit_11),
        decode_hex_pair(digit_12, digit_13),
        decode_hex_pair(digit_14, digit_15),
        decode_hex_pair(digit_16, digit_17),
        decode_hex_pair(digit_18, digit_19),
        decode_hex_pair(digit_20, digit_21),
        decode_hex_pair(digit_22, digit_23),
        decode_hex_pair(digit_24, digit_25),
        decode_hex_pair(digit_26, digit_27),
        decode_hex_pair(digit_28, digit_29),
        decode_hex_pair(digit_30, digit_31),
    ])
}

const fn hex_character(value: u8) -> char {
    if value < 10 {
        b'0'.saturating_add(value) as char
    } else {
        b'a'.saturating_add(value.saturating_sub(10)) as char
    }
}

const fn is_canonical_hex(character: u8) -> bool {
    character.is_ascii_digit() || matches!(character, b'a'..=b'f')
}

const fn decode_hex_pair(high: u8, low: u8) -> u8 {
    (decode_hex_character(high) << 4) | decode_hex_character(low)
}

const fn decode_hex_character(character: u8) -> u8 {
    if character.is_ascii_digit() {
        character.saturating_sub(b'0')
    } else {
        character.saturating_sub(b'a').saturating_add(10)
    }
}
