use std::error::Error;

use positron_query::{QueryBudget, TailEvent, TailStart, TailTerminal};

use super::terminal_and_bounds::QueryFixture;

#[test]
fn tail_reads_acknowledged_history_then_stays_idle_until_disconnect() -> Result<(), Box<dyn Error>>
{
    let fixture = QueryFixture::new("tail-history")?;
    fixture.kernel.append_log("one", 1, 1)?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 4, 1_048_576, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 4",
        budget,
    )?;
    let mut tail = service.tail(query, TailStart::Historical { max_rows: 4 })?;
    assert!(matches!(tail.poll(), Some(TailEvent::Header(_))));
    assert!(matches!(tail.poll(), Some(TailEvent::Batch(_))));
    assert!(matches!(tail.poll(), Some(TailEvent::Idle)));
    tail.disconnect();
    assert!(matches!(
        tail.poll(),
        Some(TailEvent::Terminal(TailTerminal::Disconnected(_)))
    ));
    assert!(tail.poll().is_none());
    Ok(())
}

#[test]
fn tail_cursor_tamper_fails_closed_on_resume() -> Result<(), Box<dyn Error>> {
    let fixture = QueryFixture::new("tail-resume")?;
    let service = fixture.service(16)?;
    let budget = QueryBudget::new(1_048_576, 16, 1, 1, 1_048_576, 60)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
        budget,
    )?;
    let tail = service.tail(query, TailStart::Now)?;
    let mut bytes = tail.cursor().as_bytes().to_vec();
    let slot = bytes.get_mut(24).ok_or("tail cursor body is bounded")?;
    *slot ^= 1;
    let tampered = positron_query::TailCursor::from_bytes(&bytes)?;
    let query = service.plan_pipeline(
        fixture.context,
        "pipeline:v1 logs | range query_time -100 100 | limit 1",
        budget,
    )?;
    assert!(service.resume_tail(query, &tampered).is_err());
    Ok(())
}
