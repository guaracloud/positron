use crate::plan::{AggregateSpec, FilterPredicate, OrderDirection, OrderSpec, ProjectionColumn};
use crate::sql_lexer::tokenize;
use crate::sql_selection::{Selection, parse_body_predicate, parse_transform, push_column};
use crate::{LogicalPlan, QueryFailure, QueryFailureCode, TemporalAxis, TemporalRange};
use std::borrow::Cow;

pub(crate) fn parse(
    source: &str,
    memory: &crate::planning_memory::PlanningMemory,
) -> Result<LogicalPlan, QueryFailure> {
    let mut parser = Parser {
        tokens: tokenize(source, memory)?,
        index: 0,
        memory: memory.clone(),
    };
    parser.query()
}

struct Parser<'source> {
    tokens: crate::planning_memory::PlanningVec<&'source str>,
    index: usize,
    memory: crate::planning_memory::PlanningMemory,
}

impl<'source> Parser<'source> {
    fn query(&mut self) -> Result<LogicalPlan, QueryFailure> {
        self.keyword("select")?;
        let selection = self.selection()?;
        self.keyword("from")?;
        self.keyword("logs")?;
        self.keyword("where")?;
        let axis = self.identifier()?;
        if self.take()? != ">=" {
            return Err(unsupported());
        }
        let start = self.take()?;
        self.keyword("and")?;
        if !self.identifier()?.eq_ignore_ascii_case(axis) || self.take()? != "<" {
            return Err(unsupported());
        }
        let end = self.take()?;
        let filter = self.when("and", |parser| parser.predicate())?;
        let groups = self.when("group", |parser| {
            parser.keyword("by")?;
            parser.columns()
        })?;
        let ordering = self.when("order", |parser| {
            parser.keyword("by")?;
            parser.ordering(axis)
        })?;
        let aggregate_selection = matches!(&selection, Selection::Count | Selection::CountBy(_));
        if ordering.is_none() && !aggregate_selection {
            return Err(unsupported());
        }
        self.keyword("limit")?;
        let limit = parse_limit(self.take()?)?;
        if self.index != self.tokens.len() {
            return Err(unsupported());
        }

        let mut plan = plan(axis, start, end, limit, &self.memory)?;
        if let Some(filter) = filter {
            plan = plan.with_filter(filter);
        }
        if aggregate_selection && ordering.is_some() {
            return Err(unsupported());
        }
        match selection {
            Selection::Projection {
                projection,
                transform,
            } => {
                if groups.is_some() {
                    return Err(unsupported());
                }
                plan = plan.with_projection(projection.into_vec());
                if let Some(transform) = transform {
                    plan = plan.with_transform(transform);
                }
            },
            Selection::Count => {
                plan = plan.with_aggregate(groups.map_or_else(AggregateSpec::count, |columns| {
                    AggregateSpec::count_by(columns.into_vec())
                }));
            },
            Selection::CountBy(columns) => {
                if groups.as_ref() != Some(&columns) {
                    return Err(unsupported());
                }
                plan = plan.with_aggregate(AggregateSpec::count_by(columns.into_vec()));
            },
        }
        let default_ordering = OrderSpec::ascending(plan.temporal_axis());
        Ok(plan.with_ordering(ordering.unwrap_or(default_ordering)))
    }

    fn selection(&mut self) -> Result<Selection, QueryFailure> {
        let mut columns = crate::planning_memory::PlanningVec::with_capacity(&self.memory, 5)?;
        let mut count = false;
        let mut transform = None;
        loop {
            if self.count_marker() {
                if count {
                    return Err(unsupported());
                }
                count = true;
            } else {
                let token = self.take()?;
                if token == "*" {
                    return Err(unsupported());
                }
                if let Some(value) = parse_transform(token)? {
                    if transform.replace(value).is_some() {
                        return Err(unsupported());
                    }
                    push_column(
                        &mut columns,
                        "body",
                        crate::sql_selection::IdentifierCase::Insensitive,
                    )?;
                } else {
                    push_column(
                        &mut columns,
                        token,
                        crate::sql_selection::IdentifierCase::Insensitive,
                    )?;
                }
            }
            if !self.comma() {
                break;
            }
        }
        if count {
            if transform.is_some() {
                return Err(unsupported());
            }
            return Ok(if columns.is_empty() {
                Selection::Count
            } else {
                Selection::CountBy(columns)
            });
        }
        Ok(Selection::Projection {
            projection: columns,
            transform,
        })
    }

    fn columns(
        &mut self,
    ) -> Result<crate::planning_memory::PlanningVec<ProjectionColumn>, QueryFailure> {
        let mut columns = crate::planning_memory::PlanningVec::with_capacity(&self.memory, 5)?;
        let first = self.take()?;
        if first == "*" {
            return Err(unsupported());
        }
        push_column(
            &mut columns,
            first,
            crate::sql_selection::IdentifierCase::Insensitive,
        )?;
        while self.comma() {
            let token = self.take()?;
            push_column(
                &mut columns,
                token,
                crate::sql_selection::IdentifierCase::Insensitive,
            )?;
        }
        Ok(columns)
    }

    fn predicate(&mut self) -> Result<FilterPredicate, QueryFailure> {
        let left = self.take()?;
        let operator = self.take()?;
        let literal = self.take()?;
        if left.eq_ignore_ascii_case("body") {
            if self.peek().is_some_and(|token| !clause(token)) {
                return Err(unsupported());
            }
            return parse_body_predicate(operator, literal, &self.memory);
        }

        let value = self.take()?;
        if self.peek().is_some_and(|token| !clause(token)) {
            return Err(unsupported());
        }
        let selector = if operator.eq_ignore_ascii_case("any") {
            Cow::Borrowed("any")
        } else if operator.eq_ignore_ascii_case("all") {
            Cow::Borrowed("all")
        } else if operator
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("index("))
            && operator.ends_with(')')
        {
            let suffix = operator.get(6..).ok_or_else(unsupported)?;
            let mut selector = String::new();
            let selector_reservation = self.memory.reserve(
                u64::try_from(6_usize.checked_add(suffix.len()).ok_or_else(unsupported)?)
                    .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?,
            )?;
            selector
                .try_reserve_exact(6 + suffix.len())
                .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
            selector.push_str("index(");
            selector.push_str(suffix);
            drop(selector_reservation);
            Cow::Owned(selector)
        } else {
            return Err(unsupported());
        };
        if literal != "=" && literal != "==" {
            return Err(unsupported());
        }
        let mut source = String::new();
        let source_reservation = self.memory.reserve(
            u64::try_from(
                left.len()
                    .checked_add(selector.len())
                    .and_then(|length| length.checked_add(value.len()))
                    .and_then(|length| length.checked_add(8))
                    .ok_or_else(unsupported)?,
            )
            .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?,
        )?;
        source
            .try_reserve_exact(left.len() + selector.len() + value.len() + 8)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        source.push_str(left);
        source.push(' ');
        source.push_str(&selector);
        source.push_str(" == ");
        source.push_str(value);
        let predicate = crate::attribute_syntax::parse_predicate(&source, &self.memory)?;
        drop(source_reservation);
        Ok(FilterPredicate::AttributeEquals(predicate))
    }

    fn ordering(&mut self, axis: &str) -> Result<OrderSpec, QueryFailure> {
        let primary = self.identifier()?;
        if !primary.eq_ignore_ascii_case(axis) {
            return Err(unsupported());
        }
        let primary_direction = self.direction();
        if !self.comma() {
            return Err(unsupported());
        }
        let commit = self.identifier()?;
        if !commit.eq_ignore_ascii_case("commit_position") {
            return Err(unsupported());
        }
        Ok(OrderSpec::new(primary_direction, self.direction()))
    }

    fn direction(&mut self) -> OrderDirection {
        match self.peek() {
            Some(value) if value.eq_ignore_ascii_case("asc") => {
                self.index += 1;
                OrderDirection::Ascending
            },
            Some(value) if value.eq_ignore_ascii_case("desc") => {
                self.index += 1;
                OrderDirection::Descending
            },
            _ => OrderDirection::Ascending,
        }
    }

    fn count_marker(&mut self) -> bool {
        if self
            .peek()
            .is_some_and(|value| value.eq_ignore_ascii_case("count(*)"))
        {
            self.index += 1;
            return true;
        }
        if self
            .peek()
            .is_some_and(|value| value.eq_ignore_ascii_case("count"))
            && self
                .tokens
                .get(self.index + 1)
                .is_some_and(|value| *value == "( * )")
        {
            self.index += 2;
            return true;
        }
        false
    }

    fn when<T>(
        &mut self,
        keyword: &str,
        parse: impl FnOnce(&mut Self) -> Result<T, QueryFailure>,
    ) -> Result<Option<T>, QueryFailure> {
        if self
            .peek()
            .is_some_and(|value| value.eq_ignore_ascii_case(keyword))
        {
            self.index += 1;
            parse(self).map(Some)
        } else {
            Ok(None)
        }
    }

    fn keyword(&mut self, expected: &str) -> Result<(), QueryFailure> {
        if self.take()?.eq_ignore_ascii_case(expected) {
            Ok(())
        } else {
            Err(unsupported())
        }
    }

    fn identifier(&mut self) -> Result<&'source str, QueryFailure> {
        let value = self.take()?;
        if value.is_empty()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        {
            return Err(unsupported());
        }
        Ok(value)
    }

    fn comma(&mut self) -> bool {
        if self.peek() == Some(",") {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn take(&mut self) -> Result<&'source str, QueryFailure> {
        let value = self
            .tokens
            .get(self.index)
            .copied()
            .ok_or_else(unsupported)?;
        self.index += 1;
        Ok(value)
    }

    fn peek(&self) -> Option<&'source str> {
        self.tokens.get(self.index).copied()
    }
}

pub(crate) fn plan(
    axis: &str,
    start: &str,
    end: &str,
    limit: u16,
    memory: &crate::planning_memory::PlanningMemory,
) -> Result<LogicalPlan, QueryFailure> {
    let axis = if axis.eq_ignore_ascii_case("query_time") {
        TemporalAxis::QueryTime
    } else if axis.eq_ignore_ascii_case("event_time") {
        TemporalAxis::EventTime
    } else if axis.eq_ignore_ascii_case("ingest_time") {
        TemporalAxis::IngestTime
    } else {
        return Err(unsupported());
    };
    let range = TemporalRange::new(parse_timestamp(start)?, parse_timestamp(end)?)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidBudget))?;
    LogicalPlan::logs_with_memory(axis, range, limit, memory)
}

pub(crate) fn parse_limit(source: &str) -> Result<u16, QueryFailure> {
    if source.starts_with('0') && source.len() > 1 {
        return Err(unsupported());
    }
    source.parse().map_err(|_| unsupported())
}

fn parse_timestamp(source: &str) -> Result<i64, QueryFailure> {
    if source.starts_with('+')
        || (source.starts_with('0') && source.len() > 1)
        || (source.starts_with("-0") && source.len() > 2)
    {
        return Err(unsupported());
    }
    source.parse().map_err(|_| unsupported())
}

fn clause(token: &str) -> bool {
    ["group", "order", "limit"]
        .iter()
        .any(|value| token.eq_ignore_ascii_case(value))
}

fn unsupported() -> QueryFailure {
    QueryFailure::new(QueryFailureCode::UnsupportedQuery)
}
