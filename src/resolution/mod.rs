//! Address resolution layer.
//!
//! Resolves `.666` addresses into signed `SystemDescriptor`s via the DHT.

pub mod cache;
pub mod descriptor;
pub mod resolver;
pub mod ttl;

pub use cache::{CachedDescriptor, DescriptorCache};
pub use descriptor::{DescriptorValidator, ValidationReport};
pub use resolver::{ResolutionRequest, ResolutionResult, Resolver};
