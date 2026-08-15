use std::error::Error;
use std::sync::Arc;

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_ingest::SchemaDiscoveryRequest;
use prost::Message;

use super::super::{ServiceFailure, ServiceHandle};
use super::schema_maintenance::Fixture;

#[test]
fn authorized_schema_discovery_is_bounded_paginated_and_restart_stable()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request(&["zeta", "alpha"]).encode_to_vec())?
            .accepted_records(),
        1
    );
    let context = initialized.attribute(
        PresentedCredential::parse(&administrator)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let first =
        services.discover_log_schema(context, SchemaDiscoveryRequest::page(0, 1, 2)?, None)?;
    assert_eq!(first.discovery().top_paths().len(), 1);
    assert_eq!(first.discovery().sampled_path_digests().len(), 2);
    let cursor = first.next_cursor().ok_or("next page")?;
    assert_eq!(cursor.snapshot(), first.operation_id());
    let second = services.discover_log_schema(
        context,
        SchemaDiscoveryRequest::page(usize::from(cursor.next_offset()), 1, 2)?,
        Some(cursor),
    )?;
    assert_eq!(second.operation_id(), first.operation_id());
    assert_eq!(second.discovery().top_paths().len(), 1);
    assert!(second.next_cursor().is_none());

    services.prepare_shutdown_schema_checkpoint()?;
    services.publish_prepared_shutdown_schema_checkpoint()?;
    drop(services);
    let reopened = ServiceHandle::new(Arc::clone(&initialized))?;
    let restarted =
        reopened.discover_log_schema(context, SchemaDiscoveryRequest::page(0, 1, 2)?, None)?;
    assert_eq!(restarted.operation_id(), first.operation_id());
    Ok(())
}

#[test]
fn schema_discovery_rejects_unauthorized_or_stale_page_cursors() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.ingest_otlp_logs(&ingest, request(&["first", "second"]).encode_to_vec())?;
    let context = initialized.attribute(
        PresentedCredential::parse(&administrator)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let first =
        services.discover_log_schema(context, SchemaDiscoveryRequest::page(0, 1, 0)?, None)?;
    let cursor = first.next_cursor().ok_or("cursor")?;
    services.ingest_otlp_logs(&ingest, request(&["third"]).encode_to_vec())?;
    assert!(matches!(
        services.discover_log_schema(
            context,
            SchemaDiscoveryRequest::page(1, 1, 0)?,
            Some(cursor),
        ),
        Err(ServiceFailure::InvalidRequest)
    ));
    let query_context = initialized.attribute(
        PresentedCredential::parse(&query)?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    assert!(matches!(
        services.discover_log_schema(query_context, SchemaDiscoveryRequest::page(0, 1, 0)?, None,),
        Err(ServiceFailure::Unauthorized)
    ));
    Ok(())
}

fn request(keys: &[&str]) -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    time_unix_nano: 42,
                    body: Some(text("body")),
                    attributes: keys
                        .iter()
                        .map(|key| KeyValue {
                            key: (*key).to_owned(),
                            value: Some(text("value")),
                            ..KeyValue::default()
                        })
                        .collect(),
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    }
}

fn text(value: &str) -> AnyValue {
    AnyValue {
        value: Some(any_value::Value::StringValue(value.to_owned())),
    }
}
