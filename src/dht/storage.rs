use crate::aead;
use crate::dht::error::{DHTError, Result};
use crate::dht::now_secs;
use crate::sha256;
use crate::types::Address;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct EncryptedStorage {
    entries: HashMap<Address, StorageEntry>,
    storage_key: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct StorageEntry {
    pub key: Address,
    pub encrypted_value: Vec<u8>,
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
    pub created_at: u64,
    pub expires_at: u64,
    pub replication_count: u8,
}

impl EncryptedStorage {
    pub fn new(storage_key: [u8; 32]) -> Self {
        Self {
            entries: HashMap::new(),
            storage_key,
        }
    }

    pub fn insert(&mut self, key: Address, value: Vec<u8>, ttl: u64) -> Result<()> {
        let created_at = now_secs();
        let expires_at = created_at.saturating_add(ttl);

        let nonce = derive_nonce(&self.storage_key, &key, created_at);
        let (ciphertext, tag) = aead::encrypt(&self.storage_key, &nonce, key.as_bytes(), &value);

        let entry = StorageEntry {
            key,
            encrypted_value: ciphertext,
            nonce,
            tag,
            created_at,
            expires_at,
            replication_count: 0,
        };

        self.entries.insert(key, entry);
        Ok(())
    }

    pub fn get(&self, key: &Address) -> Result<Option<Vec<u8>>> {
        let Some(entry) = self.entries.get(key) else {
            return Ok(None);
        };

        if now_secs() >= entry.expires_at {
            return Ok(None);
        }

        let decrypted = aead::decrypt(
            &self.storage_key,
            &entry.nonce,
            key.as_bytes(),
            &entry.encrypted_value,
            &entry.tag,
        )
        .map_err(DHTError::Crypto)?;

        Ok(Some(decrypted))
    }

    pub fn delete(&mut self, key: &Address) -> Result<()> {
        self.entries.remove(key);
        Ok(())
    }

    pub fn contains(&self, key: &Address) -> bool {
        self.entries.contains_key(key)
    }

    pub fn prune_expired(&mut self) -> usize {
        let now = now_secs();
        let before = self.entries.len();
        self.entries.retain(|_, v| now < v.expires_at);
        before.saturating_sub(self.entries.len())
    }

    pub fn get_all_entries(&self) -> Vec<&StorageEntry> {
        self.entries.values().collect()
    }

    pub fn size(&self) -> usize {
        self.entries.len()
    }

    pub fn estimated_size_bytes(&self) -> usize {
        self.entries
            .values()
            .map(|e| {
                16 + e.encrypted_value.len() + 12 + 16 + 8 + 8 + 1
            })
            .sum()
    }
}

fn derive_nonce(storage_key: &[u8; 32], key: &Address, created_at: u64) -> [u8; 12] {
    let mut data = Vec::new();
    data.extend_from_slice(b"dht-storage-nonce");
    data.extend_from_slice(storage_key);
    data.extend_from_slice(key.as_bytes());
    data.extend_from_slice(&created_at.to_be_bytes());

    let digest = sha256::digest(&data);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&digest[..12]);
    nonce
}
