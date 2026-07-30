#![forbid(unsafe_code)]

//! Bounded deterministic properties for public Domain Types behavior.

use positron_domain::identity::TenantId;
use positron_domain::outcome::DomainFailure;

const GENERATED_CASES: usize = 256;

#[test]
fn tenant_identifier_canonical_round_trip_holds_for_bounded_generated_cases()
-> Result<(), DomainFailure> {
    let mut generator = DeterministicBytes::from_dynamic_inputs();
    for _case in 0..GENERATED_CASES {
        let mut bytes = generator.next_identifier();
        let [first, ..] = &mut bytes;
        *first |= 1;
        let identifier = TenantId::from_bytes(bytes)?;
        let canonical = identifier.to_string();
        let reparsed = TenantId::parse_canonical(&canonical)?;
        assert_eq!(reparsed, identifier);
    }
    Ok(())
}

struct DeterministicBytes {
    state: u64,
}

impl DeterministicBytes {
    fn from_dynamic_inputs() -> Self {
        let inputs = [
            dynamic_input("POSITRON_DYNAMIC_CORPUS_ID", "domain-value-boundaries-v1"),
            dynamic_input("POSITRON_DYNAMIC_SEED", "seed-domain-properties-v1"),
            dynamic_input("POSITRON_DYNAMIC_SCHEDULE", "proptest-sequence-v1"),
            dynamic_input(
                "POSITRON_DYNAMIC_MINIMIZED_FAILURE_ID",
                "domain-value-minimized-v1",
            ),
        ];
        let mut state = 0xcbf2_9ce4_8422_2325_u64;
        for input in inputs {
            for byte in input.bytes() {
                state ^= u64::from(byte);
                state = state.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        Self { state }
    }

    fn next_identifier(&mut self) -> [u8; 16] {
        let mut bytes = [0_u8; 16];
        for byte in &mut bytes {
            self.state ^= self.state << 13;
            self.state ^= self.state >> 7;
            self.state ^= self.state << 17;
            let [least_significant, ..] = self.state.to_le_bytes();
            *byte = least_significant;
        }
        bytes
    }
}

fn dynamic_input(name: &str, default: &str) -> String {
    match std::env::var(name) {
        Ok(value) => value,
        Err(_) => default.to_owned(),
    }
}
