pub mod error;
pub mod mnemonic;
pub mod utils;
pub mod seed;
pub mod hd_key;

// Re-export commonly used types
pub use error::{KeyManagerError, Result};
pub use hd_key::ExtendedKey;
pub use seed::mnemonic_to_seed;

// Unit tests are in a separate module
#[cfg(test)]
mod tests;
