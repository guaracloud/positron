use positron_domain::value::AttributeNamespace;

use crate::{ScanCancellation, ScanObserver};

use super::{LogicalSpan, SamplingDecision, TraceStoreFailure};

/// The authenticated identity state of one service endpoint field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceServiceIdentity<'span> {
    Missing,
    Exact(&'span str),
    Ambiguous,
    Transformed,
    Invalid,
}

impl<'span> TraceServiceIdentity<'span> {
    const fn exact(self) -> Option<&'span str> {
        if let Self::Exact(value) = self {
            Some(value)
        } else {
            None
        }
    }

    const fn is_present_and_not_exact(self) -> bool {
        !matches!(self, Self::Missing | Self::Exact(_))
    }
}

/// One direct parent-to-child service edge visible in an authenticated trace snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceServiceRelationship<'span> {
    parent_span_id: [u8; 8],
    child_span_id: [u8; 8],
    parent_service: Option<&'span str>,
    child_service: Option<&'span str>,
    parent_service_namespace: Option<&'span str>,
    child_service_namespace: Option<&'span str>,
    parent_sampling: SamplingDecision,
    child_sampling: SamplingDecision,
    parent_identity: TraceServiceIdentity<'span>,
    child_identity: TraceServiceIdentity<'span>,
    parent_namespace_identity: TraceServiceIdentity<'span>,
    child_namespace_identity: TraceServiceIdentity<'span>,
}

impl TraceServiceRelationship<'_> {
    #[must_use]
    pub const fn parent_span_id(&self) -> [u8; 8] {
        self.parent_span_id
    }
    #[must_use]
    pub const fn child_span_id(&self) -> [u8; 8] {
        self.child_span_id
    }
    #[must_use]
    pub const fn parent_service(&self) -> Option<&str> {
        self.parent_service
    }
    #[must_use]
    pub const fn child_service(&self) -> Option<&str> {
        self.child_service
    }
    #[must_use]
    pub const fn parent_service_namespace(&self) -> Option<&str> {
        self.parent_service_namespace
    }
    #[must_use]
    pub const fn child_service_namespace(&self) -> Option<&str> {
        self.child_service_namespace
    }
    #[must_use]
    pub const fn parent_sampling(&self) -> SamplingDecision {
        self.parent_sampling
    }
    #[must_use]
    pub const fn child_sampling(&self) -> SamplingDecision {
        self.child_sampling
    }
    #[must_use]
    pub const fn parent_identity(&self) -> TraceServiceIdentity<'_> {
        self.parent_identity
    }
    #[must_use]
    pub const fn child_identity(&self) -> TraceServiceIdentity<'_> {
        self.child_identity
    }
    #[must_use]
    pub const fn parent_service_namespace_identity(&self) -> TraceServiceIdentity<'_> {
        self.parent_namespace_identity
    }
    #[must_use]
    pub const fn child_service_namespace_identity(&self) -> TraceServiceIdentity<'_> {
        self.child_namespace_identity
    }
}

/// Direct service edges and whether their identities and structural evidence are complete.
#[derive(Debug)]
pub struct TraceServiceRelationships<'span> {
    edges: Vec<TraceServiceRelationship<'span>>,
    complete: bool,
}

impl<'span> TraceServiceRelationships<'span> {
    #[must_use]
    pub fn edges(&self) -> &[TraceServiceRelationship<'span>] {
        &self.edges
    }
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }
}

pub(super) fn collect<'span>(
    spans: &'span [LogicalSpan],
    parent_indexes: &[Option<usize>],
    structurally_complete: bool,
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<TraceServiceRelationships<'span>, TraceStoreFailure> {
    if parent_indexes.len() != spans.len() {
        return Err(TraceStoreFailure::invalid_input());
    }
    let mut edges = Vec::new();
    edges
        .try_reserve_exact(spans.len())
        .map_err(|_| TraceStoreFailure::resource_exhausted())?;
    let mut complete = structurally_complete;
    for (child_index, child) in spans.iter().enumerate() {
        observe(cancellation, observer)?;
        let Some(parent_index) = parent_indexes
            .get(child_index)
            .copied()
            .ok_or_else(TraceStoreFailure::invalid_input)?
        else {
            continue;
        };
        let parent = spans
            .get(parent_index)
            .ok_or_else(TraceStoreFailure::invalid_input)?;
        let parent_observation = representative(parent)?;
        let child_observation = representative(child)?;
        let parent_identity =
            resource_identity(parent_observation, "service.name", cancellation, observer)?;
        let child_identity =
            resource_identity(child_observation, "service.name", cancellation, observer)?;
        let parent_namespace_identity = resource_identity(
            parent_observation,
            "service.namespace",
            cancellation,
            observer,
        )?;
        let child_namespace_identity = resource_identity(
            child_observation,
            "service.namespace",
            cancellation,
            observer,
        )?;
        if parent_identity.exact().is_none()
            || child_identity.exact().is_none()
            || parent_namespace_identity.is_present_and_not_exact()
            || child_namespace_identity.is_present_and_not_exact()
            || parent_observation.sampling() != SamplingDecision::Sampled
            || child_observation.sampling() != SamplingDecision::Sampled
        {
            complete = false;
        }
        edges.push(TraceServiceRelationship {
            parent_span_id: parent.span_id(),
            child_span_id: child.span_id(),
            parent_service: parent_identity.exact(),
            child_service: child_identity.exact(),
            parent_service_namespace: parent_namespace_identity.exact(),
            child_service_namespace: child_namespace_identity.exact(),
            parent_sampling: parent_observation.sampling(),
            child_sampling: child_observation.sampling(),
            parent_identity,
            child_identity,
            parent_namespace_identity,
            child_namespace_identity,
        });
    }
    Ok(TraceServiceRelationships { edges, complete })
}

fn resource_identity<'span>(
    observation: &'span super::SpanObservation,
    key: &str,
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<TraceServiceIdentity<'span>, TraceStoreFailure> {
    let mut result = TraceServiceIdentity::Missing;
    for attribute in observation.attributes() {
        observe(cancellation, observer)?;
        if attribute.namespace() != AttributeNamespace::Resource || attribute.key() != key {
            continue;
        }
        if !matches!(result, TraceServiceIdentity::Missing) || attribute.len() != 1 {
            return Ok(TraceServiceIdentity::Ambiguous);
        }
        let Some(value) = attribute.occurrence(0) else {
            return Ok(TraceServiceIdentity::Invalid);
        };
        if value.is_marker() || value.truncation_action().is_some() {
            return Ok(TraceServiceIdentity::Transformed);
        }
        let Some(value) = value.as_str() else {
            return Ok(TraceServiceIdentity::Invalid);
        };
        result = TraceServiceIdentity::Exact(value);
    }
    Ok(result)
}

fn representative(span: &LogicalSpan) -> Result<&super::SpanObservation, TraceStoreFailure> {
    span.structural_representative()
        .map(|representative| representative.observation())
        .ok_or_else(TraceStoreFailure::invalid_input)
}

fn observe(
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<(), TraceStoreFailure> {
    super::scan::check_cancel(cancellation)?;
    observer
        .observe_work(1)
        .map_err(TraceStoreFailure::observation)?;
    super::scan::check_cancel(cancellation)
}
