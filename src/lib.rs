pub mod error;
pub mod mnemonic;
pub mod utils;

pub use error::{KeyManagerError, Result};

// Unit tests are in a separate module
#[cfg(test)]
mod tests;
