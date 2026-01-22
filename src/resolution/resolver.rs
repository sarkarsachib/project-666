use crate::dht::error::{DHTError, Result};
use crate::dht::now_secs;
use crate::dht::DHTNode;
use crate::resolution::cache::DescriptorCache;
use crate::resolution::descriptor::DescriptorValidator;
use crate::types::{Address, Permission, SystemDescriptor};
use std::collections::HashMap;

#[derive(Debug)]
pub struct Resolver {
    dht: DHTNode,
    descriptor_cache: DescriptorCache,
    local_descriptors: HashMap<Address, SystemDescriptor>,
    validator: DescriptorValidator,
}

#[derive(Debug, Clone)]
pub struct ResolutionRequest {
    pub address: Address,
    pub capability_filter: Option<Vec<Permission>>,
}

#[derive(Debug, Clone)]
pub struct ResolutionResult {
    pub descriptor: SystemDescriptor,
    pub resolved_at: u64,
    pub resolver_address: Address,
    pub confidence: f32,
}

impl Resolver {
    pub fn new(dht: DHTNode) -> Self {
        Self {
            dht,
            descriptor_cache: DescriptorCache::new(300, 1024),
            local_descriptors: HashMap::new(),
            validator: DescriptorValidator::new(),
        }
    }

    pub fn resolve(&mut self, req: &ResolutionRequest) -> Result<ResolutionResult> {
        if let Some(local) = self.local_descriptors.get(&req.address) {
            return Ok(ResolutionResult {
                descriptor: local.clone(),
                resolved_at: now_secs(),
                resolver_address: self.dht.node_id,
                confidence: 1.0,
            });
        }

        if let Some(cached) = self.descriptor_cache.get(&req.address) {
            return Ok(ResolutionResult {
                descriptor: cached.descriptor.clone(),
                resolved_at: now_secs(),
                resolver_address: self.dht.node_id,
                confidence: cached.replica_count as f32,
            });
        }

        let Some(bytes) = self.dht.find_value(&req.address)? else {
            return Err(DHTError::Descriptor("descriptor not found"));
        };

        let descriptor = SystemDescriptor::from_bytes(&bytes).map_err(DHTError::Descriptor)?;
        self.verify_descriptor(&descriptor)?;

        // Optionally enforce a capability filter (Phase 5 will expand this).
        if let Some(filter) = &req.capability_filter {
            let ok = filter.iter().all(|p| descriptor.capabilities.contains(p));
            if !ok {
                return Err(DHTError::Descriptor("capability filter mismatch"));
            }
        }

        self.descriptor_cache
            .insert(descriptor.address, descriptor.clone(), self.dht.node_id);

        Ok(ResolutionResult {
            descriptor,
            resolved_at: now_secs(),
            resolver_address: self.dht.node_id,
            confidence: 1.0,
        })
    }

    pub fn register_descriptor(&mut self, descriptor: SystemDescriptor) -> Result<()> {
        self.verify_descriptor(&descriptor)?;
        let ttl = descriptor.expires_at.saturating_sub(now_secs());
        self.dht
            .put(descriptor.address, descriptor.to_bytes(), ttl)?;
        self.local_descriptors.insert(descriptor.address, descriptor);
        Ok(())
    }

    pub fn unregister_descriptor(&mut self, address: &Address) -> Result<()> {
        self.local_descriptors.remove(address);
        self.descriptor_cache.invalidate(address);
        self.dht.delete(address)?;
        Ok(())
    }

    pub fn update_descriptor(&mut self, descriptor: SystemDescriptor) -> Result<()> {
        self.register_descriptor(descriptor)
    }

    pub fn verify_descriptor(&self, descriptor: &SystemDescriptor) -> Result<()> {
        let report = self.validator.validate(descriptor)?;
        if report.valid {
            Ok(())
        } else {
            Err(DHTError::Descriptor("descriptor validation failed"))
        }
    }

    pub fn check_cache(&self, address: &Address) -> Option<ResolutionResult> {
        let cached = self.descriptor_cache.get(address)?;
        Some(ResolutionResult {
            descriptor: cached.descriptor.clone(),
            resolved_at: cached.cached_at,
            resolver_address: self.dht.node_id,
            confidence: cached.replica_count as f32,
        })
    }

    pub fn dht(&self) -> &DHTNode {
        &self.dht
    }

    pub fn dht_mut(&mut self) -> &mut DHTNode {
        &mut self.dht
    }
}
