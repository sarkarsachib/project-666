use criterion::{black_box, criterion_group, criterion_main, Criterion};
use project_666::crypto::ed25519;
use project_666::dht::DHTNode;
use project_666::types::SystemDescriptor;
use project_666::Address;
use std::net::SocketAddr;

fn test_node() -> DHTNode {
    let seed = [7u8; 32];
    let (sk, pk) = ed25519::generate_keypair(&seed);
    let id = SystemDescriptor::address_from_public_key(&pk);
    DHTNode::new(id, (sk, pk), 20)
}

fn bench_put_get(c: &mut Criterion) {
    let mut node = test_node();
    let key = Address::new([0x42; 16]);
    let value = vec![0xAA; 1024];

    c.bench_function("dht_put", |b| {
        b.iter(|| {
            node.put(black_box(key), black_box(value.clone()), 60).unwrap();
        })
    });

    c.bench_function("dht_get", |b| {
        b.iter(|| {
            let _ = node.get(black_box(&key)).unwrap();
        })
    });
}

fn bench_bucket_ops(c: &mut Criterion) {
    let mut node = test_node();
    let socket: SocketAddr = "127.0.0.1:1234".parse().unwrap();

    c.bench_function("dht_add_peer", |b| {
        b.iter(|| {
            let peer = Address::new([black_box(1u8); 16]);
            let _ = node.add_peer(peer, socket);
        })
    });
}

criterion_group!(dht_benches, bench_put_get, bench_bucket_ops);
criterion_main!(dht_benches);
