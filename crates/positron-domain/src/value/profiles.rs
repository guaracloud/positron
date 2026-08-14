/// Checked native dynamic-value bounds in one Value Limit Profile.
///
/// This type has no wire or durable serialization promise. It is applied by
/// bounded native-value construction; path and key share the one contractually
/// singular ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DynamicValueLimits {
    individual_value_bytes: ByteLimit,
    attributes_per_namespace: CollectionLimit,
    key_path_bytes: ByteLimit,
    nesting_depth: NestingLimit,
    array_entries: CollectionLimit,
    key_value_list_entries: CollectionLimit,
}

impl DynamicValueLimits {
    /// Groups all individual-value, namespace, key/path, and collection bounds.
    #[must_use]
    pub const fn new(
        individual_value_bytes: ByteLimit,
        attributes_per_namespace: CollectionLimit,
        key_path_bytes: ByteLimit,
        nesting_depth: NestingLimit,
        array_entries: CollectionLimit,
        key_value_list_entries: CollectionLimit,
    ) -> Self {
        Self {
            individual_value_bytes,
            attributes_per_namespace,
            key_path_bytes,
            nesting_depth,
            array_entries,
            key_value_list_entries,
        }
    }

    /// Returns the maximum bytes in one individual dynamic value.
    #[must_use]
    pub const fn individual_value_bytes(self) -> ByteLimit {
        self.individual_value_bytes
    }

    /// Returns the maximum attributes in one native namespace.
    #[must_use]
    pub const fn attributes_per_namespace(self) -> CollectionLimit {
        self.attributes_per_namespace
    }

    /// Returns the shared maximum bytes in one attribute key or path.
    #[must_use]
    pub const fn key_path_bytes(self) -> ByteLimit {
        self.key_path_bytes
    }

    /// Returns the maximum permitted nested collection depth.
    #[must_use]
    pub const fn nesting_depth(self) -> NestingLimit {
        self.nesting_depth
    }

    /// Returns the maximum entries in one dynamic array.
    #[must_use]
    pub const fn array_entries(self) -> CollectionLimit {
        self.array_entries
    }

    /// Returns the maximum entries in one ordered dynamic key/value list.
    #[must_use]
    pub const fn key_value_list_entries(self) -> CollectionLimit {
        self.key_value_list_entries
    }

    const fn exceeds(self, system: Self) -> bool {
        self.individual_value_bytes.value() > system.individual_value_bytes.value()
            || self.attributes_per_namespace.value() > system.attributes_per_namespace.value()
            || self.key_path_bytes.value() > system.key_path_bytes.value()
            || self.nesting_depth.value() > system.nesting_depth.value()
            || self.array_entries.value() > system.array_entries.value()
            || self.key_value_list_entries.value() > system.key_value_list_entries.value()
    }
}

/// One complete set of typed Value Limit Profile dimensions.
///
/// It combines explicit request, record, and dynamic-value groups. No omitted
/// dimension receives an implicit or future default, and it makes no wire or
/// durable serialization promise.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValueLimitSet {
    request: RequestLimits,
    record: RecordLimits,
    dynamic_value: DynamicValueLimits,
}

impl ValueLimitSet {
    /// Combines the checked request, record, and dynamic-value limit groups.
    #[must_use]
    pub const fn new(
        request: RequestLimits,
        record: RecordLimits,
        dynamic_value: DynamicValueLimits,
    ) -> Self {
        Self {
            request,
            record,
            dynamic_value,
        }
    }

    /// Returns all transport and aggregate request bounds.
    #[must_use]
    pub const fn request(self) -> RequestLimits {
        self.request
    }

    /// Returns all encoded, decoded, and log-body record bounds.
    #[must_use]
    pub const fn record(self) -> RecordLimits {
        self.record
    }

    /// Returns all native dynamic-value bounds.
    #[must_use]
    pub const fn dynamic_value(self) -> DynamicValueLimits {
        self.dynamic_value
    }

    const fn exceeds(self, system: Self) -> bool {
        self.request.exceeds(system.request)
            || self.record.exceeds(system.record)
            || self.dynamic_value.exceeds(system.dynamic_value)
    }
}

/// A pre-validation system and optional tenant value-limit profile.
///
/// This is deliberately a pre-validation state: it can represent an invalid
/// tenant increase so configuration and policy owners must call `validate`
/// before passing limits to any native value construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValueLimitProfileCandidate {
    system: ValueLimitSet,
    tenant: Option<ValueLimitSet>,
}

impl ValueLimitProfileCandidate {
    /// Builds a candidate profile that still requires system-ceiling validation.
    #[must_use]
    pub const fn new(system: ValueLimitSet, tenant: Option<ValueLimitSet>) -> Self {
        Self { system, tenant }
    }

    /// Produces the post-validation profile only when tenant values do not raise ceilings.
    pub fn validate(self) -> Result<ValueLimitProfile, DomainFailure> {
        if self
            .system
            .exceeds(ValueLimitProfile::release_1_system_maximum().system)
            || self
                .tenant
                .is_some_and(|tenant| tenant.exceeds(self.system))
        {
            return Err(DomainFailure::limit_exceeds_system());
        }
        Ok(ValueLimitProfile {
            system: self.system,
            tenant: self.tenant,
        })
    }
}

/// A system-ceiling-respecting profile safe for native value validation.
///
/// There is no public unchecked constructor. The only transition from a
/// candidate is `ValueLimitProfileCandidate::validate`, which preserves every
/// system ceiling and allows tenant settings only to lower effective bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValueLimitProfile {
    system: ValueLimitSet,
    tenant: Option<ValueLimitSet>,
}

impl ValueLimitProfile {
    /// Returns the compiled Release 1 safe maxima for every profile dimension.
    #[must_use]
    pub const fn release_1_system_maximum() -> Self {
        let request = RequestLimits::new(
            ByteLimit(1_048_576),
            ByteLimit(1_048_576),
            CollectionLimit(1_024),
            CollectionLimit(4_096),
        );
        let record = RecordLimits::new(
            ByteLimit(1_048_576),
            ByteLimit(1_048_576),
            ByteLimit(262_144),
        );
        let dynamic_value = DynamicValueLimits::new(
            ByteLimit(65_536),
            CollectionLimit(1_024),
            ByteLimit(65_536),
            NestingLimit(128),
            CollectionLimit(1_024),
            CollectionLimit(1_024),
        );
        Self {
            system: ValueLimitSet::new(request, record, dynamic_value),
            tenant: None,
        }
    }

    /// Returns the complete configured system-ceiling limit set.
    #[must_use]
    pub const fn system_limits(self) -> ValueLimitSet {
        self.system
    }

    /// Returns the optional tenant-lowered limit set.
    #[must_use]
    pub const fn tenant_limits(self) -> Option<ValueLimitSet> {
        self.tenant
    }

    /// Returns the effective limit set after applying the tenant lowering.
    #[must_use]
    pub const fn effective_limits(self) -> ValueLimitSet {
        match self.tenant {
            Some(tenant) => tenant,
            None => self.system,
        }
    }
}
