pub(crate) struct MethodSpec {
    pub(crate) name: &'static str,
    pub(crate) input: &'static str,
    pub(crate) output: &'static str,
}

pub(crate) struct ServiceSpec {
    pub(crate) name: &'static str,
    pub(crate) methods: &'static [MethodSpec],
}

const API_KEY_METHODS: &[MethodSpec] = &[MethodSpec {
    name: "Manage",
    input: ".positron.v1.ApiKeyRequest",
    output: ".positron.v1.ApiKeyResponse",
}];
const TENANT_QUOTA_METHODS: &[MethodSpec] = &[MethodSpec {
    name: "Update",
    input: ".positron.v1.TenantQuotaUpdateRequest",
    output: ".positron.v1.TenantQuotaUpdateResponse",
}];
const TENANT_LIFECYCLE_METHODS: &[MethodSpec] = &[MethodSpec {
    name: "Transition",
    input: ".positron.v1.TenantLifecycleTransitionRequest",
    output: ".positron.v1.TenantLifecycleTransitionResponse",
}];
const TENANT_RETENTION_METHODS: &[MethodSpec] = &[
    MethodSpec {
        name: "Preview",
        input: ".positron.v1.TenantRetentionPreviewRequest",
        output: ".positron.v1.TenantRetentionPreviewResponse",
    },
    MethodSpec {
        name: "Update",
        input: ".positron.v1.TenantRetentionUpdateRequest",
        output: ".positron.v1.TenantRetentionUpdateResponse",
    },
];
const TENANT_METHODS: &[MethodSpec] = &[
    MethodSpec {
        name: "Create",
        input: ".positron.v1.TenantCreateRequest",
        output: ".positron.v1.TenantCreateResponse",
    },
    MethodSpec {
        name: "Inspect",
        input: ".positron.v1.TenantInspectRequest",
        output: ".positron.v1.TenantInspectResponse",
    },
    MethodSpec {
        name: "List",
        input: ".positron.v1.TenantListRequest",
        output: ".positron.v1.TenantListResponse",
    },
    MethodSpec {
        name: "UpdateDisplayName",
        input: ".positron.v1.TenantDisplayNameUpdateRequest",
        output: ".positron.v1.TenantDisplayNameUpdateResponse",
    },
];
const TENANT_ALIAS_METHODS: &[MethodSpec] = &[MethodSpec {
    name: "Bind",
    input: ".positron.v1.TenantAliasBindRequest",
    output: ".positron.v1.TenantAliasBindResponse",
}];
const POLICY_METHODS: &[MethodSpec] = &[
    MethodSpec {
        name: "Validate",
        input: ".positron.v1.PolicyPreviewRequest",
        output: ".positron.v1.PolicyValidateResponse",
    },
    MethodSpec {
        name: "Test",
        input: ".positron.v1.PolicyTestRequest",
        output: ".positron.v1.PolicyTestResponse",
    },
    MethodSpec {
        name: "Diff",
        input: ".positron.v1.PolicyDiffRequest",
        output: ".positron.v1.PolicyDiffResponse",
    },
    MethodSpec {
        name: "Explain",
        input: ".positron.v1.PolicyExplainRequest",
        output: ".positron.v1.PolicyExplainResponse",
    },
    MethodSpec {
        name: "Activate",
        input: ".positron.v1.PolicyActivateRequest",
        output: ".positron.v1.PolicyActivateResponse",
    },
];

pub(crate) const SERVICES: &[ServiceSpec] = &[
    ServiceSpec {
        name: "ApiKeyService",
        methods: API_KEY_METHODS,
    },
    ServiceSpec {
        name: "TenantQuotaService",
        methods: TENANT_QUOTA_METHODS,
    },
    ServiceSpec {
        name: "TenantLifecycleService",
        methods: TENANT_LIFECYCLE_METHODS,
    },
    ServiceSpec {
        name: "TenantRetentionService",
        methods: TENANT_RETENTION_METHODS,
    },
    ServiceSpec {
        name: "TenantService",
        methods: TENANT_METHODS,
    },
    ServiceSpec {
        name: "TenantAliasService",
        methods: TENANT_ALIAS_METHODS,
    },
    ServiceSpec {
        name: "PolicyService",
        methods: POLICY_METHODS,
    },
];
