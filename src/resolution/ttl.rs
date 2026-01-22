use crate::dht::now_secs;

pub fn is_expired(expires_at: u64) -> bool {
    now_secs() >= expires_at
}
