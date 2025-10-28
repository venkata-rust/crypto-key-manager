use crate::error::{KeyManagerError, Result};
use crate::utils;

// BIP39 English wordlist (2048 words)
const WORDLIST: [&str; 2048] = include!("wordlist.txt");

/// Generate a BIP39 mnemonic phrase with the specified word count
/// Now uses proper SHA256 checksums
pub fn generate_mnemonic(word_count: usize) -> Result<String> {
    // Validate word count
    utils::validate_word_count(word_count)?;

    // Calculate entropy size in bytes
    let entropy_bits = match word_count {
        12 => 128,
        15 => 160,
        18 => 192,
        21 => 224,
        24 => 256,
        _ => return Err(KeyManagerError::InvalidWordCount(word_count)),
    };
    let entropy_bytes = entropy_bits / 8;

    // Generate random entropy
    let entropy = generate_entropy(entropy_bytes)?;

    // Convert entropy to mnemonic with proper SHA256 checksum
    entropy_to_mnemonic_checked(&entropy)
}

/// Validate a BIP39 mnemonic phrase
/// Now includes proper SHA256 checksum validation
pub fn validate_mnemonic(mnemonic: &str) -> Result<()> {
    let words: Vec<&str> = mnemonic.trim().split_whitespace().collect();
    let word_count = words.len();

    // Check word count is valid
    utils::validate_word_count(word_count)?;

    // Check all words are in wordlist
    for word in &words {
        if !is_valid_word(word) {
            return Err(KeyManagerError::InvalidMnemonic);
        }
    }

    // Validate SHA256 checksum
    validate_mnemonic_checksum(mnemonic)?;

    Ok(())
}

/// Convert entropy to mnemonic with SHA256 checksum (BIP39 compliant)
pub fn entropy_to_mnemonic_checked(entropy: &[u8]) -> Result<String> {
    // Validate entropy length
    let entropy_bits = entropy.len() * 8;
    if ![128, 160, 192, 224, 256].contains(&entropy_bits) {
        return Err(KeyManagerError::EncodingError(
            format!("Invalid entropy length: {} bits", entropy_bits)
        ));
    }

    // Calculate SHA256 checksum
    let checksum = calculate_sha256_checksum(entropy);
    let checksum_bits = entropy_bits / 32;

    // Combine entropy and checksum into bits
    let mut bits = Vec::new();
    
    // Add entropy bits
    for byte in entropy {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1);
        }
    }
    
    // Add checksum bits (first checksum_bits of the hash - MSB first)
    // For 128-bit entropy: take bits 7,6,5,4 of checksum[0] (top 4 bits)
    for i in 0..checksum_bits {
        bits.push((checksum[0] >> (7 - i)) & 1);
    }

    // Convert 11-bit chunks to words
    let mut words = Vec::new();
    for chunk in bits.chunks(11) {
        if chunk.len() == 11 {
            let mut index = 0u16;
            for (i, &bit) in chunk.iter().enumerate() {
                index |= (bit as u16) << (10 - i);
            }
            if (index as usize) < WORDLIST.len() {
                words.push(WORDLIST[index as usize]);
            }
        }
    }

    Ok(words.join(" "))
}

/// Convert mnemonic to entropy (reverse operation)
pub fn mnemonic_to_entropy(mnemonic: &str) -> Result<Vec<u8>> {
    let words: Vec<&str> = mnemonic.trim().split_whitespace().collect();
    
    // Validate word count
    utils::validate_word_count(words.len())?;

    // Convert words to indices
    let mut bits = Vec::new();
    for word in &words {
        let index = WORDLIST
            .binary_search(word)
            .map_err(|_| KeyManagerError::InvalidMnemonic)?;
        
        // Convert index to 11 bits
        for i in (0..11).rev() {
            bits.push(((index >> i) & 1) as u8);
        }
    }

    // Calculate sizes
    let total_bits = bits.len();
    let checksum_bits = total_bits / 33;
    let entropy_bits = total_bits - checksum_bits;

    // Extract entropy bits
    let entropy_bits_slice = &bits[..entropy_bits];
    
    // Convert bits to bytes
    let mut entropy = Vec::new();
    for chunk in entropy_bits_slice.chunks(8) {
        let mut byte = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            byte |= bit << (7 - i);
        }
        entropy.push(byte);
    }

    // Verify checksum
    let calculated_checksum = calculate_sha256_checksum(&entropy);
    
    // Extract actual checksum from bits (MSB first)
    let mut actual_checksum = 0u8;
    for (i, &bit) in bits[entropy_bits..].iter().enumerate() {
        if i < checksum_bits {
            actual_checksum |= bit << (7 - i);
        }
    }

    // Compare the first checksum_bits of both
    let shift = 8 - checksum_bits;
    if (calculated_checksum[0] >> shift) != (actual_checksum >> shift) {
        return Err(KeyManagerError::InvalidMnemonic);
    }

    Ok(entropy)
}

/// Validate mnemonic SHA256 checksum
pub fn validate_mnemonic_checksum(mnemonic: &str) -> Result<()> {
    let words: Vec<&str> = mnemonic.trim().split_whitespace().collect();
    
    // Validate word count
    utils::validate_word_count(words.len())?;

    // Convert to entropy (which validates checksum internally)
    mnemonic_to_entropy(mnemonic)?;
    
    Ok(())
}

/// Check if a word is in the BIP39 wordlist
pub fn is_valid_word(word: &str) -> bool {
    WORDLIST.binary_search(&word).is_ok()
}

/// Check if a word is in the BIP39 wordlist (alias for compatibility)
pub fn is_valid_bip39_word(word: &str) -> bool {
    is_valid_word(word)
}

/// Get word count from mnemonic phrase
pub fn get_word_count(mnemonic: &str) -> usize {
    mnemonic.trim().split_whitespace().count()
}

/// Get the size of the BIP39 wordlist
pub fn wordlist_size() -> usize {
    WORDLIST.len()
}

// ============================================================================
// Internal helper functions
// ============================================================================

/// Generate cryptographically secure random entropy
fn generate_entropy(bytes: usize) -> Result<Vec<u8>> {
    use std::fs::File;
    use std::io::Read;

    let mut entropy = vec![0u8; bytes];
    let mut file = File::open("/dev/urandom")
        .map_err(|e| KeyManagerError::KeyGenerationError(e.to_string()))?;
    file.read_exact(&mut entropy)
        .map_err(|e| KeyManagerError::KeyGenerationError(e.to_string()))?;

    Ok(entropy)
}

/// Calculate SHA256 checksum of entropy (BIP39 compliant)
fn calculate_sha256_checksum(entropy: &[u8]) -> Vec<u8> {
    use sha2::{Sha256, Digest};
    
    let mut hasher = Sha256::new();
    hasher.update(entropy);
    hasher.finalize().to_vec()
}
