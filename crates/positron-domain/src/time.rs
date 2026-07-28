//! Exact source, observed, ingest, and selected query times.

use crate::outcome::DomainFailure;

/// A fixed-width count of nanoseconds from the Unix epoch.
///
/// Every `i64` value is representable so a source timestamp can remain exact,
/// including values that a later signal-specific policy may classify as an
/// outlier. This unit type makes no wire or durable serialization promise.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UnixNanoseconds(i64);

impl UnixNanoseconds {
    /// Creates an exact, representable Unix-nanoseconds value without changing it.
    #[must_use]
    pub const fn new(value: i64) -> Self {
        Self(value)
    }

    /// Returns the exact received or kernel-assigned nanoseconds value.
    #[must_use]
    pub const fn value(self) -> i64 {
        self.0
    }
}

/// The usability annotation attached to one exact received source time.
///
/// The annotation never rewrites the original timestamp. It is a native domain
/// value; API and signal-store owners define any wire or durable encoding.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SourceTimeQuality {
    /// A present source time is usable for its signal's Query Time selection.
    Usable,
    /// The source did not supply a timestamp.
    Missing,
    /// The source supplied the zero timestamp, preserved but not usable.
    Zero,
    /// A representable source time that requires a bounded outlier path.
    Outlier,
    /// A source time contradicting another signal-defined source value.
    Contradictory,
}

/// A producer-supplied Event Time with a preserved usability annotation.
///
/// `EventTime` stays distinct from signal-defined observed time and
/// kernel-assigned Ingest Time. Its checked constructor requires a zero-quality
/// value to retain the exact zero timestamp.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventTime {
    instant: Option<UnixNanoseconds>,
    quality: SourceTimeQuality,
}

impl EventTime {
    /// Represents a source that supplied no Event Time without fabricating one.
    #[must_use]
    pub const fn missing() -> Self {
        Self {
            instant: None,
            quality: SourceTimeQuality::Missing,
        }
    }

    /// Preserves a present source timestamp and its explicit quality annotation.
    pub fn received(
        instant: UnixNanoseconds,
        quality: SourceTimeQuality,
    ) -> Result<Self, DomainFailure> {
        validate_present_source_time(instant, quality)?;
        Ok(Self {
            instant: Some(instant),
            quality,
        })
    }

    /// Returns the exact producer-supplied timestamp.
    #[must_use]
    pub const fn instant(self) -> Option<UnixNanoseconds> {
        self.instant
    }

    /// Returns the source-time usability annotation without changing the value.
    #[must_use]
    pub const fn quality(self) -> SourceTimeQuality {
        self.quality
    }

    const fn is_usable(self) -> bool {
        matches!(
            self.quality,
            SourceTimeQuality::Usable | SourceTimeQuality::Outlier
        )
    }

    const fn usable_instant(self) -> Option<UnixNanoseconds> {
        if self.is_usable() { self.instant } else { None }
    }
}

/// A signal-defined observed timestamp distinct from producer Event Time.
///
/// It has the same exact-value and explicit-quality rules as `EventTime`, but
/// a different Rust type prevents callers from silently exchanging meanings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedTime {
    instant: UnixNanoseconds,
    quality: SourceTimeQuality,
}

impl ObservedTime {
    /// Preserves a present observed timestamp and its explicit quality annotation.
    pub fn received(
        instant: UnixNanoseconds,
        quality: SourceTimeQuality,
    ) -> Result<Self, DomainFailure> {
        validate_present_source_time(instant, quality)?;
        Ok(Self { instant, quality })
    }

    /// Returns the exact observed timestamp.
    #[must_use]
    pub const fn instant(self) -> Option<UnixNanoseconds> {
        Some(self.instant)
    }

    /// Returns the observed-time usability annotation without changing the value.
    #[must_use]
    pub const fn quality(self) -> SourceTimeQuality {
        self.quality
    }

    const fn is_usable(self) -> bool {
        matches!(self.quality, SourceTimeQuality::Usable)
    }

    const fn usable_instant(self) -> Option<UnixNanoseconds> {
        if self.is_usable() {
            Some(self.instant)
        } else {
            None
        }
    }
}

/// A Storage Kernel-assigned time for one accepted record.
///
/// `IngestTime` is distinct from Event, Observed, and Query Time. It wraps only
/// an exact kernel value and makes no wire or durable serialization promise.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IngestTime(UnixNanoseconds);

impl IngestTime {
    /// Wraps the exact timestamp assigned by the Storage Kernel.
    #[must_use]
    pub const fn new(instant: UnixNanoseconds) -> Self {
        Self(instant)
    }

    /// Returns the exact kernel-assigned timestamp.
    #[must_use]
    pub const fn instant(self) -> UnixNanoseconds {
        self.0
    }
}

/// The source selected for a signal's Query Time.
///
/// This closed taxonomy makes the fallback source observable without
/// fabricating or changing a retained Event or Observed Time.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum QueryTimeProvenance {
    /// Query Time came from a usable producer Event Time.
    Event,
    /// Query Time came from a usable signal-defined Observed Time.
    Observed,
    /// Query Time fell back to Storage Kernel Ingest Time.
    Ingest,
}

/// A selected Query Time and the provenance that made it valid.
///
/// Logs select usable Event Time, then usable Observed Time, then Ingest Time.
/// The fields are private, so callers cannot fabricate a provenance claim. API
/// and storage owners, not this type, define serialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryTime {
    instant: UnixNanoseconds,
    provenance: QueryTimeProvenance,
}

impl QueryTime {
    /// Selects Query Time for a log using the frozen source fallback order.
    #[must_use]
    pub fn for_log(
        event_time: &EventTime,
        observed_time: Option<&ObservedTime>,
        ingest_time: IngestTime,
    ) -> Self {
        if let Some(instant) = event_time.usable_instant() {
            return Self {
                instant,
                provenance: QueryTimeProvenance::Event,
            };
        }
        if let Some(instant) =
            observed_time.and_then(|observed_time| observed_time.usable_instant())
        {
            return Self {
                instant,
                provenance: QueryTimeProvenance::Observed,
            };
        }
        Self {
            instant: ingest_time.instant(),
            provenance: QueryTimeProvenance::Ingest,
        }
    }

    /// Selects Query Time for a span from usable start time or Ingest Time.
    #[must_use]
    pub fn for_span(start_time: &EventTime, ingest_time: IngestTime) -> Self {
        if let Some(instant) = start_time.usable_instant() {
            return Self {
                instant,
                provenance: QueryTimeProvenance::Event,
            };
        }
        Self {
            instant: ingest_time.instant(),
            provenance: QueryTimeProvenance::Ingest,
        }
    }

    /// Returns the selected exact timestamp.
    #[must_use]
    pub const fn instant(self) -> UnixNanoseconds {
        self.instant
    }

    /// Returns which source supplied the selected timestamp.
    #[must_use]
    pub const fn provenance(self) -> QueryTimeProvenance {
        self.provenance
    }
}

fn validate_present_source_time(
    instant: UnixNanoseconds,
    quality: SourceTimeQuality,
) -> Result<(), DomainFailure> {
    let is_zero = instant.value() == 0;
    let has_zero_annotation = matches!(quality, SourceTimeQuality::Zero);
    if matches!(quality, SourceTimeQuality::Missing) || is_zero != has_zero_annotation {
        return Err(DomainFailure::invalid_time_annotation());
    }
    Ok(())
}
