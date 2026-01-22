use crate::dht::routing::{compare_distance, xor_distance};
use crate::dht::now_ms;
use crate::types::Address;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashSet};
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupType {
    FindNode,
    FindValue,
}

#[derive(Debug, Clone)]
pub struct CandidateNode {
    pub address: Address,
    pub distance: [u8; 16],
    pub socket: SocketAddr,
    pub queried: bool,
}

impl Ord for CandidateNode {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering so the BinaryHeap pops the closest node first.
        match compare_distance(&self.distance, &other.distance) {
            Ordering::Less => Ordering::Greater,
            Ordering::Greater => Ordering::Less,
            Ordering::Equal => self.address.cmp(&other.address).reverse(),
        }
    }
}

impl PartialOrd for CandidateNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for CandidateNode {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address && self.distance == other.distance
    }
}

impl Eq for CandidateNode {}

#[derive(Debug, Clone)]
pub struct LookupContext {
    pub target: Address,
    pub lookup_type: LookupType,
    pub visited: HashSet<Address>,
    pub candidates: BinaryHeap<CandidateNode>,
    pub replies: Vec<Address>,
    pub value: Option<Vec<u8>>,
    pub alpha: usize,
    pub started_at: u64,
    pub timeout_ms: u64,

    inflight: Vec<CandidateNode>,
    known: HashSet<Address>,
}

impl LookupContext {
    pub fn new(target: Address, lookup_type: LookupType) -> Self {
        Self {
            target,
            lookup_type,
            visited: HashSet::new(),
            candidates: BinaryHeap::new(),
            replies: Vec::new(),
            value: None,
            alpha: 3,
            started_at: now_ms(),
            timeout_ms: 1_000,
            inflight: Vec::new(),
            known: HashSet::new(),
        }
    }

    pub fn add_candidate(&mut self, address: Address, distance: [u8; 16], socket: SocketAddr) {
        if self.visited.contains(&address) || self.known.contains(&address) {
            return;
        }

        self.known.insert(address);
        self.candidates.push(CandidateNode {
            address,
            distance,
            socket,
            queried: false,
        });
    }

    pub fn get_next_candidates(&mut self, count: usize) -> Vec<&CandidateNode> {
        self.inflight.clear();
        while self.inflight.len() < count {
            let Some(mut next) = self.candidates.pop() else {
                break;
            };

            if self.visited.contains(&next.address) {
                continue;
            }

            next.queried = true;
            self.visited.insert(next.address);
            self.inflight.push(next);
        }

        self.inflight.iter().collect()
    }

    pub fn mark_queried(&mut self, address: &Address) {
        self.visited.insert(*address);
    }

    pub fn add_reply(&mut self, addresses: Vec<Address>) {
        self.replies.extend(addresses);
    }

    pub fn set_value(&mut self, value: Vec<u8>) {
        self.value = Some(value);
    }

    pub fn is_complete(&self, k: usize) -> bool {
        match self.lookup_type {
            LookupType::FindValue => self.value.is_some() || self.candidates.is_empty(),
            LookupType::FindNode => self.replies.len() >= k || self.candidates.is_empty(),
        }
    }

    pub fn is_expired(&self) -> bool {
        now_ms().saturating_sub(self.started_at) >= self.timeout_ms
    }

    pub fn get_closest_k(&self, k: usize) -> Vec<Address> {
        let mut all = Vec::new();
        for c in self.candidates.iter() {
            all.push(c.address);
        }
        for c in &self.inflight {
            all.push(c.address);
        }
        for a in &self.replies {
            all.push(*a);
        }

        all.sort();
        all.dedup();

        all.sort_by(|a, b| {
            let da = xor_distance(a, &self.target);
            let db = xor_distance(b, &self.target);
            compare_distance(&da, &db)
        });

        all.truncate(k);
        all
    }
}
