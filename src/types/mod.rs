//! Common protocol types.

mod address;
mod descriptor;

pub use address::Address;
pub use descriptor::{Permission, ResourceLimits, SystemDescriptor};
