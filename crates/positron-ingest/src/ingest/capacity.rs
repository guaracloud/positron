use positron_kernel::ResourceAmounts;
use positron_policy::PolicyBudget;

pub(super) fn group_work_amounts(
    record_count: u64,
    policy: PolicyBudget,
) -> Option<ResourceAmounts> {
    let per_record = policy.reserved_memory_bytes()?;
    let policy_memory = per_record.checked_mul(record_count)?;
    let memory = 1_048_576_u64.checked_add(policy_memory)?;
    Some(ResourceAmounts::new([
        memory,
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
    ]))
}

#[cfg(test)]
mod tests {
    use positron_kernel::ResourceDimension;
    use positron_policy::IngestPolicy;

    use super::group_work_amounts;

    #[test]
    fn policy_memory_is_reserved_per_record_at_the_exact_boundary() {
        let policy = IngestPolicy::preserving(1).expect("policy");
        let one = group_work_amounts(1, policy.budget()).expect("one record");
        let two = group_work_amounts(2, policy.budget()).expect("two records");
        let per_record = policy
            .budget()
            .reserved_memory_bytes()
            .expect("bounded memory");
        assert_eq!(
            one.get(ResourceDimension::MemoryBytes),
            1_048_576 + per_record
        );
        assert_eq!(
            two.get(ResourceDimension::MemoryBytes),
            1_048_576 + 2 * per_record
        );
        assert!(group_work_amounts(u64::MAX, policy.budget()).is_none());
    }
}
