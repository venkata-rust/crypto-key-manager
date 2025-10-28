// Unit tests for crypto-key-manager
// All PASS_TO_PASS tests for base commit functionality

use crate::mnemonic;
use crate::utils::*;

// ============================================================================
// PASS_TO_PASS: Utils Module Tests
// ============================================================================

#[test]
fn test_validate_word_count_valid() {
    assert!(validate_word_count(12).is_ok());
    assert!(validate_word_count(15).is_ok());
    assert!(validate_word_count(18).is_ok());
    assert!(validate_word_count(21).is_ok());
    assert!(validate_word_count(24).is_ok());
}

#[test]
fn test_validate_word_count_invalid() {
    assert!(validate_word_count(11).is_err());
    assert!(validate_word_count(13).is_err());
    assert!(validate_word_count(25).is_err());
    assert!(validate_word_count(0).is_err());
}

#[test]
fn test_validate_derivation_path_format_valid() {
    assert!(validate_derivation_path_format("m").is_ok());
    assert!(validate_derivation_path_format("m/44'/60'/0'/0/0").is_ok());
}

#[test]
fn test_validate_derivation_path_format_invalid() {
    assert!(validate_derivation_path_format("").is_err());
    assert!(validate_derivation_path_format("44'/60'/0'/0/0").is_err());
    assert!(validate_derivation_path_format("M/44'/60'/0'/0/0").is_err());
}

#[test]
fn test_hex_conversion_roundtrip() {
    let original = vec![0x01, 0x02, 0x03, 0xff];
    let hex = bytes_to_hex(&original);
    let decoded = hex_to_bytes(&hex).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn test_hex_to_bytes_with_0x_prefix() {
    let result = hex_to_bytes("0x0102").unwrap();
    assert_eq!(result, vec![0x01, 0x02]);
}

#[test]
fn test_hex_to_bytes_without_prefix() {
    let result = hex_to_bytes("0102").unwrap();
    assert_eq!(result, vec![0x01, 0x02]);
}

#[test]
fn test_bytes_to_hex_lowercase() {
    let bytes = vec![0xde, 0xad, 0xbe, 0xef];
    let hex = bytes_to_hex(&bytes);
    assert_eq!(hex, "deadbeef");
}

#[test]
fn test_hex_to_bytes_invalid() {
    assert!(hex_to_bytes("xyz").is_err());
    assert!(hex_to_bytes("123").is_err()); // Odd length
}

// ============================================================================
// PASS_TO_PASS: Basic Mnemonic Tests
// ============================================================================

#[test]
fn test_generate_mnemonic_12_words() {
    let mnemonic = mnemonic::generate_mnemonic(12).unwrap();
    assert_eq!(mnemonic.split_whitespace().count(), 12);
}

#[test]
fn test_generate_mnemonic_24_words() {
    let mnemonic = mnemonic::generate_mnemonic(24).unwrap();
    assert_eq!(mnemonic.split_whitespace().count(), 24);
}

#[test]
fn test_generate_mnemonic_valid_words() {
    let mnemonic = mnemonic::generate_mnemonic(12).unwrap();
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    
    for word in words {
        assert!(mnemonic::is_valid_word(word));
    }
}

#[test]
fn test_generate_mnemonic_invalid_count() {
    assert!(mnemonic::generate_mnemonic(11).is_err());
    assert!(mnemonic::generate_mnemonic(13).is_err());
}

#[test]
fn test_is_valid_word() {
    assert!(mnemonic::is_valid_word("abandon"));
    assert!(mnemonic::is_valid_word("ability"));
    assert!(!mnemonic::is_valid_word("notaword"));
    assert!(!mnemonic::is_valid_word(""));
}

#[test]
fn test_validate_mnemonic_valid() {
    let mnemonic = "abandon ability able about above absent absorb abstract absurd abuse access accident";
    assert!(mnemonic::validate_mnemonic(mnemonic).is_ok());
}

#[test]
fn test_validate_mnemonic_invalid_word() {
    let mnemonic = "abandon ability invalid about above absent absorb abstract absurd abuse access accident";
    assert!(mnemonic::validate_mnemonic(mnemonic).is_err());
}

#[test]
fn test_validate_mnemonic_invalid_count() {
    let mnemonic = "abandon ability able";  // Only 3 words
    assert!(mnemonic::validate_mnemonic(mnemonic).is_err());
}

#[test]
fn test_wordlist_size() {
    assert!(mnemonic::wordlist_size() > 0);
}

// ============================================================================
// Future PR Tests will be added below with FAIL_TO_PASS markers
// ============================================================================

// PR #1: BIP39 Checksum Validation
// FAIL_TO_PASS tests will be added here

// PR #2: Seed Generation
// FAIL_TO_PASS tests will be added here

// PR #3: HD Key Derivation
// FAIL_TO_PASS tests will be added here
