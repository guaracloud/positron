use super::{TailEvent, TailStats, TailTerminal, TerminalKind, take_terminal_value};
use crate::{QueryBudget, QueryFailureCode};

fn stats() -> TailStats {
    TailStats {
        scanned_bytes: 0,
        decoded_records: 0,
        emitted_records: 0,
        emitted_bytes: 0,
        memory_peak_bytes: 0,
        cpu_work_units: 0,
        elapsed_seconds: 0,
        last_sequence: None,
        result_digest: [0; 32],
        cumulative_budget: QueryBudget::new(1, 1, 1, 1, 1, 1).expect("test budget"),
        resume_count: 0,
        repeated_batch_count: 0,
        reduced_pruning: false,
        limiting_budget: None,
    }
}

#[test]
fn failure_terminals_and_terminal_emission_are_exhaustive() {
    assert!(matches!(
        super::super::admission::terminal_for_failure(
            QueryFailureCode::BudgetExhausted,
            None,
            stats()
        ),
        TailTerminal::BudgetExhausted { cursor: None, .. }
    ));
    assert!(matches!(
        super::super::admission::terminal_for_failure(QueryFailureCode::Cancelled, None, stats()),
        TailTerminal::Cancelled { cursor: None, .. }
    ));
    assert!(matches!(
        super::super::admission::terminal_for_failure(
            QueryFailureCode::SnapshotExpired,
            None,
            stats()
        ),
        TailTerminal::Expired { cursor: None, .. }
    ));
    assert!(matches!(
        super::super::admission::terminal_for_failure(
            QueryFailureCode::AuthorizationChanged,
            None,
            stats()
        ),
        TailTerminal::AuthorizationChanged { cursor: None, .. }
    ));
    assert!(matches!(
        super::super::admission::terminal_for_failure(QueryFailureCode::Internal, None, stats()),
        TailTerminal::StoreUnavailable { cursor: None, .. }
    ));

    let mut terminal = Some(TailTerminal::Cancelled {
        cursor: None,
        stats: stats(),
    });
    let mut emitted = false;
    assert!(matches!(
        take_terminal_value(&mut terminal, &mut emitted),
        Some(TailEvent::Terminal(TailTerminal::Cancelled {
            cursor: None,
            ..
        }))
    ));
    assert!(emitted);
    assert!(take_terminal_value(&mut terminal, &mut emitted).is_none());
}

#[test]
fn terminal_kind_builds_the_store_failure_variant() {
    assert!(matches!(
        TerminalKind::StoreUnavailable.build(None, stats()),
        TailTerminal::StoreUnavailable { cursor: None, .. }
    ));
}

#[test]
fn tail_stats_exposes_the_cumulative_runtime_fields() {
    let stats = TailStats {
        scanned_bytes: 1,
        decoded_records: 2,
        emitted_records: 3,
        emitted_bytes: 4,
        memory_peak_bytes: 5,
        cpu_work_units: 6,
        elapsed_seconds: 7,
        last_sequence: Some(8),
        result_digest: [9; 32],
        cumulative_budget: QueryBudget::new(10, 11, 12, 13, 14, 15)
            .expect("test budget")
            .with_cpu_work_units(16)
            .expect("test CPU budget"),
        resume_count: 17,
        repeated_batch_count: 18,
        reduced_pruning: true,
        limiting_budget: Some(crate::QueryBudgetDimension::MemoryBytes),
    };
    assert_eq!(stats.scanned_bytes(), 1);
    assert_eq!(stats.decoded_records(), 2);
    assert_eq!(stats.emitted_records(), 3);
    assert_eq!(stats.emitted_bytes(), 4);
    assert_eq!(stats.memory_peak_bytes(), 5);
    assert_eq!(stats.cpu_work_units(), 6);
    assert_eq!(stats.elapsed_seconds(), 7);
    assert_eq!(stats.last_sequence(), Some(8));
    assert_eq!(stats.result_digest(), [9; 32]);
    assert_eq!(stats.cumulative_budget().output_rows(), 12);
    assert_eq!(stats.resume_count(), 17);
    assert_eq!(stats.repeated_batch_count(), 18);
    assert!(stats.reduced_pruning());
    assert_eq!(
        stats.limiting_budget(),
        Some(crate::QueryBudgetDimension::MemoryBytes)
    );
}
