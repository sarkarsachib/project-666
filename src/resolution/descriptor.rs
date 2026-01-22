use crate::dht::error::{DHTError, Result};
use crate::types::{Address, Permission, SystemDescriptor};
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct DescriptorValidator {
    trusted_signers: HashSet<Address>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    pub valid: bool,
    pub signature_valid: bool,
    pub capabilities_valid: bool,
    pub resource_limits_valid: bool,
    pub warnings: Vec<String>,
}

impl DescriptorValidator {
    pub fn new() -> Self {
        Self {
            trusted_signers: HashSet::new(),
        }
    }

    pub fn validate(&self, descriptor: &SystemDescriptor) -> Result<ValidationReport> {
        let signature_valid = self.check_signature(descriptor).is_ok();
        let capabilities_valid = self.check_capabilities(descriptor).is_ok();
        let resource_limits_valid = self.check_resource_limits(descriptor).is_ok();

        let mut warnings = Vec::new();
        if !self.trusted_signers.is_empty() && !self.trusted_signers.contains(&descriptor.address) {
            warnings.push("descriptor signer not in trusted set".to_string());
        }

        let valid = signature_valid && capabilities_valid && resource_limits_valid;
        Ok(ValidationReport {
            valid,
            signature_valid,
            capabilities_valid,
            resource_limits_valid,
            warnings,
        })
    }

    pub fn check_signature(&self, descriptor: &SystemDescriptor) -> Result<()> {
        if descriptor.verify() {
            Ok(())
        } else {
            Err(DHTError::Descriptor("invalid signature"))
        }
    }

    pub fn check_capabilities(&self, descriptor: &SystemDescriptor) -> Result<()> {
        let _filter: Option<Vec<Permission>> = None;
        let _ = _filter;
        let _ = descriptor;
        Ok(())
    }

    pub fn check_resource_limits(&self, descriptor: &SystemDescriptor) -> Result<()> {
        if descriptor.resources.max_storage_bytes == 0 {
            return Err(DHTError::Descriptor("max_storage_bytes must be > 0"));
        }
        if descriptor.resources.max_bandwidth_bytes_per_sec == 0 {
            return Err(DHTError::Descriptor(
                "max_bandwidth_bytes_per_sec must be > 0",
            ));
        }
        Ok(())
    }

    pub fn add_trusted_signer(&mut self, address: Address) {
        self.trusted_signers.insert(address);
    }

    pub fn remove_trusted_signer(&mut self, address: &Address) {
        self.trusted_signers.remove(address);
    }
}
