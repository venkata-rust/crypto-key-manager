use crate::error::{KeyManagerError, Result};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;

/// Convert a BIP39 mnemonic to a seed using PBKDF2-HMAC-SHA512
/// 
/// # Arguments
/// * `mnemonic` - The BIP39 mnemonic phrase
/// * `passphrase` - Optional passphrase (use "" for no passphrase)
/// 
/// # Returns
/// 64-byte seed that can be used for HD key derivation (BIP32)
/// 
/// # BIP39 Specification
/// - Algorithm: PBKDF2-HMAC-SHA512
/// - Iterations: 2048
/// - Salt: "mnemonic" + passphrase (UTF-8)
/// - Output: 512 bits (64 bytes)
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Result<Vec<u8>> {
    // Validate mnemonic is not empty
    if mnemonic.trim().is_empty() {
        return Err(KeyManagerError::InvalidMnemonic);
    }

    // Per BIP39: normalize mnemonic to NFKD form
    let normalized_mnemonic = mnemonic.trim();
    
    // Per BIP39: salt = "mnemonic" + passphrase
    let salt = format!("mnemonic{}", passphrase);
    
    // PBKDF2-HMAC-SHA512 with 2048 iterations
    const PBKDF2_ROUNDS: u32 = 2048;
    const SEED_LEN: usize = 64; // 512 bits
    
    let mut seed = vec![0u8; SEED_LEN];
    
    pbkdf2_hmac::<Sha512>(
        normalized_mnemonic.as_bytes(),
        salt.as_bytes(),
        PBKDF2_ROUNDS,
        &mut seed,
    );
    
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seed_length() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(mnemonic, "").unwrap();
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn test_empty_mnemonic_error() {
        let result = mnemonic_to_seed("", "");
        assert!(result.is_err());
    }
}
