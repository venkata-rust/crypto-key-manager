use crate::error::{KeyManagerError, Result};

/// Validates that word count is one of the standard BIP39 counts
pub fn validate_word_count(count: usize) -> Result<()> {
    match count {
        12 | 15 | 18 | 21 | 24 => Ok(()),
        _ => Err(KeyManagerError::InvalidWordCount(count)),
    }
}

/// Validates that a derivation path starts with 'm'
pub fn validate_derivation_path_format(path: &str) -> Result<()> {
    if !path.starts_with('m') {
        return Err(KeyManagerError::InvalidDerivationPath(
            "Path must start with 'm'".to_string(),
        ));
    }
    Ok(())
}

/// Converts hex string to bytes
pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>> {
    let cleaned = hex_str.trim_start_matches("0x");

    if cleaned.len() % 2 != 0 {
        return Err(KeyManagerError::EncodingError(
            "Hex string must have even length".to_string(),
        ));
    }

    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i..i + 2], 16)
                .map_err(|e| KeyManagerError::EncodingError(e.to_string()))
        })
        .collect()
}

/// Converts bytes to hex string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
