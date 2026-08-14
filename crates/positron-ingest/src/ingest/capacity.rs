use positron_kernel::ResourceAmounts;
use positron_policy::PolicyBudget;

// Resource Governor CPU units are coarse concurrent-work reservations; policy
// steps remain byte-exact and are rounded up to one 64 Ki-step work quantum.
const POLICY_EVALUATION_STEPS_PER_CPU_WORK_UNIT: u64 = 65_536;

pub(super) fn group_work_amounts(
    record_count: u64,
    policy: PolicyBudget,
) -> Option<ResourceAmounts> {
    let evaluation_work = policy
        .evaluation_steps()
        .checked_add(POLICY_EVALUATION_STEPS_PER_CPU_WORK_UNIT - 1)?
        / POLICY_EVALUATION_STEPS_PER_CPU_WORK_UNIT;
    let cpu_work = evaluation_work.checked_mul(record_count)?.checked_add(1)?;
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
        cpu_work,
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

    #[test]
    fn policy_evaluation_work_is_reserved_per_record_at_the_exact_boundary() {
        let exact = IngestPolicy::reject_exact_text_body(1, "exact", &"a".repeat(65_535))
            .expect("exact work-unit policy");
        assert_eq!(exact.budget().evaluation_steps(), 65_536);
        let exact_two = group_work_amounts(2, exact.budget()).expect("two records");
        assert_eq!(exact_two.get(ResourceDimension::CpuWorkUnits), 3);

        let over = IngestPolicy::reject_exact_text_body(1, "over", &"a".repeat(65_536))
            .expect("over work-unit policy");
        assert_eq!(over.budget().evaluation_steps(), 65_537);
        let over_two = group_work_amounts(2, over.budget()).expect("two records");
        assert_eq!(over_two.get(ResourceDimension::CpuWorkUnits), 5);
        assert!(group_work_amounts(u64::MAX, over.budget()).is_none());
    }
}
