use crate::error::{KeyManagerError, Result};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha512;

/// BIP39 seed generation from mnemonic
/// 
/// Takes a BIP39 mnemonic phrase and optional passphrase,
/// returns a 64-byte seed suitable for BIP32 key generation
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Result<[u8; 64]> {
    // Normalize the mnemonic (remove extra whitespace, lowercase)
    let mnemonic = normalize_mnemonic(mnemonic)?;
    
    // Prepare password and salt
    let password = mnemonic.as_bytes();
    let salt = format!("mnemonic{}", passphrase);
    let salt_bytes = salt.as_bytes();
    
    // PBKDF2-HMAC-SHA512 with 2048 iterations
    // This matches BIP39 specification exactly
    let mut seed = [0u8; 64];
    pbkdf2::<Hmac<Sha512>>(password, salt_bytes, 2048, &mut seed);
    
    Ok(seed)
}

/// Validate and normalize BIP39 mnemonic
/// 
/// Validates that the mnemonic has valid word count (12, 15, 18, 21, or 24)
/// Normalizes whitespace and validates it's not empty
fn normalize_mnemonic(mnemonic: &str) -> Result<String> {
    let mnemonic = mnemonic.trim();
    
    // Check not empty
    if mnemonic.is_empty() {
        return Err(KeyManagerError::InvalidSeedLength);
    }
    
    // Split into words and filter empty strings (handles multiple spaces)
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    
    // Validate word count (BIP39 valid counts: 12, 15, 18, 21, 24)
    match words.len() {
        12 | 15 | 18 | 21 | 24 => {},
        _ => return Err(KeyManagerError::KeyGenerationError(
            format!("Invalid mnemonic word count: {}. Must be 12, 15, 18, 21, or 24.", words.len())
        )),
    }
    
    // Validate each word is not empty and alphanumeric
    for (i, word) in words.iter().enumerate() {
        if word.is_empty() {
            return Err(KeyManagerError::KeyGenerationError(
                format!("Empty word at position {}", i)
            ));
        }
        
        // Words should only contain lowercase letters
        if !word.chars().all(|c| c.is_ascii_lowercase()) {
            return Err(KeyManagerError::KeyGenerationError(
                format!("Invalid character in word {}: '{}'. Only lowercase letters allowed.", i, word)
            ));
        }
    }
    
    // Return normalized mnemonic (with single spaces between words)
    Ok(words.join(" "))
}

/// Convenience function: Generate BIP32 master key directly from mnemonic
/// 
/// This combines mnemonic_to_seed() with ExtendedKey::from_seed()
/// 
/// # Usage
/// ```ignore
/// let master_key = generate_master_key_from_mnemonic(
///     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
///     ""
/// )?;
/// ```
pub fn generate_master_key_from_mnemonic(
    mnemonic: &str, 
    passphrase: &str
) -> Result<crate::hd_key::ExtendedKey> {
    let seed = mnemonic_to_seed(mnemonic, passphrase)?;
    crate::hd_key::ExtendedKey::from_seed(&seed)
}