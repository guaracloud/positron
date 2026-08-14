use positron_kernel::ResourceAmounts;

pub(super) const fn group_work_amounts(record_count: u64) -> ResourceAmounts {
    ResourceAmounts::new([
        1_048_576,
        1,
        1,
        1_048_576,
        record_count,
        0,
        1,
        1,
        1,
        4,
        1_048_576,
    ])
}
