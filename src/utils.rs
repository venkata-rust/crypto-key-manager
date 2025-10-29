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

/// Validate if string is valid hex (0-9a-fA-F)
pub fn validate_hex_string(hex: &str) -> Result<()> {
    if hex.is_empty() {
        return Err(KeyManagerError::EncodingError("Empty hex string".to_string()));
    }
    
    let hex_clean = hex.strip_prefix("0x").unwrap_or(hex);
    
    if hex_clean.len() % 2 != 0 {
        return Err(KeyManagerError::EncodingError("Odd length hex".to_string()));
    }
    
    if !hex_clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(KeyManagerError::EncodingError("Invalid hex characters".to_string()));
    }
    
    Ok(())
}

/// Get human-readable word count description
pub fn word_count_description(count: usize) -> String {
    match count {
        12 => "12-word (128-bit entropy)".to_string(),
        15 => "15-word (160-bit entropy)".to_string(),
        18 => "18-word (192-bit entropy)".to_string(),
        21 => "21-word (224-bit entropy)".to_string(),
        24 => "24-word (256-bit entropy)".to_string(),
        _ => format!("{}-word (invalid)", count),
    }
}