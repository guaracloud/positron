use crate::LogicalPlan;
use crate::QueryFailure;

pub(super) fn scan_predicates<'plan>(
    plan: &'plan LogicalPlan,
    schema: Option<&positron_signals::SchemaCatalog>,
) -> Result<
    (
        Option<&'plan positron_signals::SchemaQuery>,
        bool,
        Option<positron_signals::TextSearchCandidate>,
        bool,
    ),
    QueryFailure,
> {
    let schema_query = plan.schema_query();
    let schema_filter_used = schema.zip(schema_query).is_some();
    let text_candidate = if plan.transform().is_some() {
        None
    } else {
        plan.text_search_candidate()?
    };
    let text_filter_used = schema.zip(text_candidate.as_ref()).is_some();
    Ok((
        schema_query,
        schema_filter_used,
        text_candidate,
        text_filter_used,
    ))
}
