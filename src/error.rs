use std::fmt;

/// Result type for key manager operations
pub type Result<T> = std::result::Result<T, KeyManagerError>;

/// Errors that can occur during key management operations
#[derive(Debug)]
pub enum KeyManagerError {
    InvalidMnemonic,
    InvalidWordCount(usize),
    InvalidWord(String),



    /// Invalid seed length (must be 16-64 bytes)
    InvalidSeedLength,
    
    /// Error during key generation
    KeyGenerationError(String),
    EncodingError(String),
    IoError(std::io::Error),
    /// Invalid derivation path format
    InvalidDerivationPath(String),
    
    /// HMAC operation failed
    HmacError(String),
    
    /// Secp256k1 operation failed
    Secp256k1Error(String),

}

impl fmt::Display for KeyManagerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {

             KeyManagerError::InvalidMnemonic => write!(f, "Invalid mnemonic phrase"),
              KeyManagerError::InvalidWordCount(count) => {
                write!(f, "Invalid word count: {}", count)
              }
               KeyManagerError::InvalidWord(word) => {
                write!(f, "Invalid word in mnemonic: {}", word)
               }
               KeyManagerError::EncodingError(msg) => write!(f, "Encoding error: {}", msg),
               KeyManagerError::IoError(err) => write!(f, "IO error: {}", err),

            KeyManagerError::InvalidSeedLength => {
                write!(f, "Invalid seed length. Expected 16-64 bytes.")
            }
            KeyManagerError::KeyGenerationError(msg) => {
                write!(f, "Key generation error: {}", msg)
            }
            KeyManagerError::InvalidDerivationPath(msg) => {
                write!(f, "Invalid derivation path: {}", msg)
            }
            KeyManagerError::HmacError(msg) => {
                write!(f, "HMAC operation failed: {}", msg)
            }
            KeyManagerError::Secp256k1Error(msg) => {
                write!(f, "Secp256k1 operation failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for KeyManagerError {}

// Convenience conversions
impl From<String> for KeyManagerError {
    fn from(msg: String) -> Self {
        KeyManagerError::KeyGenerationError(msg)
    }
}
impl From<std::io::Error> for KeyManagerError {
    fn from(err: std::io::Error) -> Self {
        KeyManagerError::IoError(err)
    }
}

impl From<&str> for KeyManagerError {
    fn from(msg: &str) -> Self {
        KeyManagerError::KeyGenerationError(msg.to_string())
    }
}