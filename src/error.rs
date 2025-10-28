use std::fmt;

#[derive(Debug)]
pub enum KeyManagerError {
    InvalidMnemonic,
    InvalidWordCount(usize),
    InvalidWord(String),
    InvalidDerivationPath(String),
    KeyGenerationError(String),
    EncodingError(String),
    IoError(std::io::Error),
}

impl fmt::Display for KeyManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyManagerError::InvalidMnemonic => write!(f, "Invalid mnemonic phrase"),
            KeyManagerError::InvalidWordCount(count) => {
                write!(f, "Invalid word count: {}", count)
            }
            KeyManagerError::InvalidWord(word) => {
                write!(f, "Invalid word in mnemonic: {}", word)
            }
            KeyManagerError::InvalidDerivationPath(msg) => {
                write!(f, "Invalid derivation path: {}", msg)
            }
            KeyManagerError::KeyGenerationError(msg) => {
                write!(f, "Key generation failed: {}", msg)
            }
            KeyManagerError::EncodingError(msg) => write!(f, "Encoding error: {}", msg),
            KeyManagerError::IoError(err) => write!(f, "IO error: {}", err),
        }
    }
}

impl std::error::Error for KeyManagerError {}

impl From<std::io::Error> for KeyManagerError {
    fn from(err: std::io::Error) -> Self {
        KeyManagerError::IoError(err)
    }
}

pub type Result<T> = std::result::Result<T, KeyManagerError>;
