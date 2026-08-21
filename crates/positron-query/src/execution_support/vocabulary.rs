pub(super) const fn query_time_provenance_tag(
    provenance: positron_domain::time::QueryTimeProvenance,
) -> u8 {
    match provenance {
        positron_domain::time::QueryTimeProvenance::Event => 0,
        positron_domain::time::QueryTimeProvenance::Observed => 1,
        positron_domain::time::QueryTimeProvenance::Ingest => 2,
    }
}

pub(super) const fn source_time_quality_tag(
    quality: positron_domain::time::SourceTimeQuality,
) -> u8 {
    match quality {
        positron_domain::time::SourceTimeQuality::Usable => 0,
        positron_domain::time::SourceTimeQuality::Missing => 1,
        positron_domain::time::SourceTimeQuality::Zero => 2,
        positron_domain::time::SourceTimeQuality::Outlier => 3,
        positron_domain::time::SourceTimeQuality::Contradictory => 4,
    }
}
