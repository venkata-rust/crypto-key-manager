// Unit tests for crypto-key-manager
// All PASS_TO_PASS tests for base commit functionality

use crate::mnemonic;
use crate::utils::*;
use crate::seed;

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
    // Official BIP39 test vector with valid SHA256 checksum
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
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
// FAIL_TO_PASS: Test entropy to mnemonic conversion with proper checksum
#[test]
fn test_entropy_to_mnemonic_with_checksum() {
    // Test vector from BIP39 spec
    let entropy = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let expected = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let result = mnemonic::entropy_to_mnemonic_checked(&entropy).unwrap();
    assert_eq!(result, expected);
}

// FAIL_TO_PASS: Test mnemonic to entropy reverse operation
#[test]
fn test_mnemonic_to_entropy() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let entropy = mnemonic::mnemonic_to_entropy(mnemonic).unwrap();
    assert_eq!(entropy.len(), 16); // 128 bits = 16 bytes
    assert_eq!(entropy, vec![0u8; 16]); // All zeros
}

// FAIL_TO_PASS: Test roundtrip entropy -> mnemonic -> entropy
#[test]
fn test_entropy_mnemonic_roundtrip() {
    let original_entropy = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10];
    
    let mnemonic = mnemonic::entropy_to_mnemonic_checked(&original_entropy).unwrap();
    let recovered_entropy = mnemonic::mnemonic_to_entropy(&mnemonic).unwrap();
    
    assert_eq!(original_entropy, recovered_entropy);
}

// FAIL_TO_PASS: Test valid checksum validation
#[test]
fn test_validate_checksum_valid() {
    // Known valid BIP39 mnemonic with correct SHA256 checksum
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    assert!(mnemonic::validate_mnemonic_checksum(mnemonic).is_ok());
}

// FAIL_TO_PASS: Test invalid checksum detection
#[test]
fn test_validate_checksum_invalid() {
    // Valid words but last word gives invalid checksum
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    assert!(mnemonic::validate_mnemonic_checksum(mnemonic).is_err());
}

// FAIL_TO_PASS: Test another BIP39 test vector
#[test]
fn test_bip39_test_vector_2() {
    // Test vector 2 from BIP39 spec
    let entropy = vec![0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
                       0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f];
    let expected = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    let result = mnemonic::entropy_to_mnemonic_checked(&entropy).unwrap();
    assert_eq!(result, expected);
}

// FAIL_TO_PASS: Test 24-word mnemonic with checksum
#[test]
fn test_24_word_mnemonic_checksum() {
    // Test vector for 24 words (256 bits entropy)
    let entropy = vec![0x00; 32]; // 32 bytes = 256 bits
    let mnemonic = mnemonic::entropy_to_mnemonic_checked(&entropy).unwrap();
    
    // Should be 24 words
    assert_eq!(mnemonic.split_whitespace().count(), 24);
    
    // Should validate correctly
    assert!(mnemonic::validate_mnemonic_checksum(&mnemonic).is_ok());
}

// FAIL_TO_PASS: Test generated mnemonics have valid checksums
#[test]
fn test_generated_mnemonic_has_valid_checksum() {
    let mnemonic = mnemonic::generate_mnemonic(12).unwrap();
    
    // Should pass checksum validation
    assert!(mnemonic::validate_mnemonic_checksum(&mnemonic).is_ok());
}

// FAIL_TO_PASS: Test checksum with different entropy sizes
#[test]
fn test_checksum_various_entropy_sizes() {
    // 12 words (128 bits)
    let entropy_12 = vec![0xaa; 16];
    let mnemonic_12 = mnemonic::entropy_to_mnemonic_checked(&entropy_12).unwrap();
    assert_eq!(mnemonic_12.split_whitespace().count(), 12);
    assert!(mnemonic::validate_mnemonic_checksum(&mnemonic_12).is_ok());
    
    // 15 words (160 bits)
    let entropy_15 = vec![0xbb; 20];
    let mnemonic_15 = mnemonic::entropy_to_mnemonic_checked(&entropy_15).unwrap();
    assert_eq!(mnemonic_15.split_whitespace().count(), 15);
    assert!(mnemonic::validate_mnemonic_checksum(&mnemonic_15).is_ok());
    
    // 24 words (256 bits)
    let entropy_24 = vec![0xcc; 32];
    let mnemonic_24 = mnemonic::entropy_to_mnemonic_checked(&entropy_24).unwrap();
    assert_eq!(mnemonic_24.split_whitespace().count(), 24);
    assert!(mnemonic::validate_mnemonic_checksum(&mnemonic_24).is_ok());
}

// FAIL_TO_PASS: Test that modified mnemonic fails checksum
#[test]
fn test_modified_mnemonic_fails_checksum() {
    // Start with valid mnemonic
    let valid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    assert!(mnemonic::validate_mnemonic_checksum(valid).is_ok());
    
    // Change one word in the middle (not checksum word)
    let invalid = "abandon abandon ability abandon abandon abandon abandon abandon abandon abandon abandon about";
    assert!(mnemonic::validate_mnemonic_checksum(invalid).is_err());
}

// PR #2: Seed Generation
// FAIL_TO_PASS tests will be added here
// ============================================================================
// PR #2: BIP39 Seed Generation (PBKDF2) - FAIL_TO_PASS Tests
// Add these tests to src/tests.rs AFTER PR #1 tests
// These tests will FAIL until you implement src/seed.rs
// ============================================================================

// FAIL_TO_PASS: Test basic mnemonic to seed conversion (no passphrase)
#[test]
fn test_mnemonic_to_seed_no_passphrase() {
    // BIP39 test vector
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = seed::mnemonic_to_seed(mnemonic, "").unwrap();
    
    // Expected seed (64 bytes) from BIP39 test vectors
    let expected_hex = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
    let expected = hex::decode(expected_hex).unwrap();
    
    assert_eq!(seed.len(), 64); // BIP39 seeds are always 64 bytes
    // ✅ FIXED: Compare as slices instead of [u8; 64] vs Vec<u8>
    assert_eq!(&seed[..], &expected[..]);
}

// FAIL_TO_PASS: Test mnemonic to seed with passphrase
#[test]
fn test_mnemonic_to_seed_with_passphrase() {
    // BIP39 test vector with passphrase "TREZOR"
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = seed::mnemonic_to_seed(mnemonic, "TREZOR").unwrap();
    
    // Expected seed with passphrase from BIP39 test vectors
    let expected_hex = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
    let expected = hex::decode(expected_hex).unwrap();
    
    assert_eq!(seed.len(), 64);
    // ✅ FIXED: Compare as slices instead of [u8; 64] vs Vec<u8>
    assert_eq!(&seed[..], &expected[..]);
}

// FAIL_TO_PASS: Test seed determinism (same input = same output)
#[test]
fn test_seed_determinism() {
    let mnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    
    // Generate seed twice
    let seed1 = seed::mnemonic_to_seed(mnemonic, "").unwrap();
    let seed2 = seed::mnemonic_to_seed(mnemonic, "").unwrap();
    
    // Should be identical
    assert_eq!(seed1, seed2);
    assert_eq!(seed1.len(), 64);
}


// ============================================================================
// PR #3: BIP32 HD Key Derivation - FAIL_TO_PASS Tests
// Add these tests to src/tests.rs AFTER PR #2 tests
// These tests will FAIL until you implement src/hd_key.rs
// ============================================================================

use crate::hd_key;

// FAIL_TO_PASS: Test master key generation from seed
#[test]
fn test_master_key_generation() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let master = seed::generate_master_key_from_mnemonic(mnemonic, "")
            .expect("Failed to create master key");
        
        // Master key should have depth 0
        let _xprv = master.to_string();
        assert!(!_xprv.is_empty());
    }

// FAIL_TO_PASS: Test child key derivation with path
#[test]
fn test_child_key_derivation() {
    // BIP32 test vector 1
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master_key = hd_key::master_key_from_seed(&seed).unwrap();
    
    // Derive key at path m/0'/1/2'/2
    let derived = master_key.derive_path("m/0'/1/2'/2").unwrap();
    
    // Expected derived key from BIP32 test vectors
    let expected_xprv = "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334";
    
    assert_eq!(derived.to_string(), expected_xprv);
}

#[test]
fn test_seed_generation() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed1 = seed::mnemonic_to_seed(mnemonic, "")
            .expect("Failed to generate seed");
        
        assert_eq!(seed1.len(), 64);
        
        // Same mnemonic + same passphrase = same seed
        let seed2 = seed::mnemonic_to_seed(mnemonic, "")
            .expect("Failed to generate seed again");
        assert_eq!(seed1, seed2);
        
        // Different passphrase = different seed
        let seed3 = seed::mnemonic_to_seed(mnemonic, "different")
            .expect("Failed to generate seed with passphrase");
        assert_ne!(seed1, seed3);
    }
    // PR #4: Additional FAIL_TO_PASS tests will be added here

#[test]

fn test_validate_hex_string_valid() {
    assert!(validate_hex_string("deadbeef").is_ok());
    assert!(validate_hex_string("0xdeadbeef").is_ok());
}

#[test]
fn test_validate_hex_string_invalid() {
    assert!(validate_hex_string("xyz").is_err());
    assert!(validate_hex_string("").is_err());
    assert!(validate_hex_string("0x123").is_err()); // odd length
}
