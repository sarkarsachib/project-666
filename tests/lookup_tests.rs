use project_666::dht::{xor_distance, LookupContext, LookupType};
use project_666::Address;

fn test_address(byte: u8) -> Address {
    Address::new([byte; 16])
}

#[test]
fn test_lookup_convergence_closest_k() {
    let target = Address::new([0xAB; 16]);
    let mut ctx = LookupContext::new(target, LookupType::FindNode);

    for i in 0..20u8 {
        ctx.add_candidate(
            test_address(i),
            xor_distance(&target, &test_address(i)),
            "127.0.0.1:1234".parse().unwrap(),
        );
    }

    let closest = ctx.get_closest_k(20);
    assert_eq!(closest.len(), 20);

    // The closest candidate should be among the ones queried first.
    let next = ctx.get_next_candidates(3);
    assert_eq!(next.len(), 3);
}

#[test]
fn test_lookup_timeout() {
    let target = Address::new([0xCC; 16]);
    let mut ctx = LookupContext::new(target, LookupType::FindNode);
    ctx.timeout_ms = 0;
    assert!(ctx.is_expired());
}
