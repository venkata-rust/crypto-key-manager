use crate::error::{KeyManagerError, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use ripemd::Ripemd160;
use num_bigint::BigUint;
use num_traits::Num;
use num_traits::ToPrimitive;
use secp256k1::{Secp256k1, SecretKey, PublicKey};

type HmacSha512 = Hmac<Sha512>;

const HARDENED_OFFSET: u32 = 0x80000000; // 2^31
const CURVE_ORDER_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Extended Key structure for BIP32 hierarchical deterministic keys
#[derive(Clone, Debug)]
pub struct ExtendedKey {
    /// 32-byte private key
    private_key: [u8; 32],
    /// 32-byte chain code
    chain_code: [u8; 32],
    /// Depth in the derivation tree (0 for master)
    depth: u8,
    /// Parent key fingerprint (4 bytes)
    parent_fingerprint: [u8; 4],
    /// Child index
    child_index: u32,
}

impl ExtendedKey {
    /// Generate master key from seed (BIP32)
    ///
    /// # Arguments
    /// * `seed` - Seed bytes (typically 64 bytes from BIP39)
    ///
    /// # Returns
    /// Master extended private key
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        // Validate seed length (recommended: 128-512 bits)
        if seed.len() < 16 || seed.len() > 64 {
            return Err(KeyManagerError::InvalidSeedLength);
        }

        // BIP32: I = HMAC-SHA512(Key = "Bitcoin seed", Data = seed)
        let mut hmac = HmacSha512::new_from_slice(b"Bitcoin seed")
            .map_err(|_| KeyManagerError::KeyGenerationError("HMAC init failed".to_string()))?;
        hmac.update(seed);
        let result = hmac.finalize().into_bytes();

        // Split into key and chain code
        let mut private_key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        private_key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);

        // Validate private key is valid (not zero, less than curve order)
        Self::validate_private_key(&private_key)?;

        Ok(ExtendedKey {
            private_key,
            chain_code,
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_index: 0,
        })
    }

    /// Validate that private key is within valid range for secp256k1
    fn validate_private_key(private_key: &[u8; 32]) -> Result<()> {
        // Check if all bytes are zero
        if private_key.iter().all(|&b| b == 0) {
            return Err(KeyManagerError::KeyGenerationError(
                "Invalid private key: all zeros".to_string(),
            ));
        }

        // Check if key is less than curve order n
        let key_num = BigUint::from_bytes_be(private_key);
        let curve_order = BigUint::from_str_radix(CURVE_ORDER_HEX, 16)
            .map_err(|_| KeyManagerError::KeyGenerationError("Invalid curve order".to_string()))?;

        if key_num >= curve_order {
            return Err(KeyManagerError::KeyGenerationError(
                "Private key exceeds curve order".to_string(),
            ));
        }

        Ok(())
    }

    /// Add two keys with modular arithmetic (mod curve order)
    fn add_keys_modulo(key1: &[u8], key2: &[u8]) -> Result<[u8; 32]> {
        let num1 = BigUint::from_bytes_be(key1);
        let num2 = BigUint::from_bytes_be(key2);
        let curve_order = BigUint::from_str_radix(CURVE_ORDER_HEX, 16)
            .map_err(|_| KeyManagerError::KeyGenerationError("Invalid curve order".to_string()))?;

        let sum = (num1 + num2) % &curve_order;
        let sum_bytes = sum.to_bytes_be();

        // Pad to 32 bytes if necessary
        let mut result = [0u8; 32];
        if sum_bytes.len() > 32 {
            return Err(KeyManagerError::KeyGenerationError(
                "Key sum overflow".to_string(),
            ));
        }

        let offset = 32 - sum_bytes.len();
        result[offset..].copy_from_slice(&sum_bytes);
        Ok(result)
    }

    /// Derive a child key at the specified index
    ///
    /// # Arguments
    /// * `index` - Child index (use index >= 2^31 for hardened derivation)
    fn derive_child(&self, index: u32) -> Result<Self> {
        let hardened = index >= HARDENED_OFFSET;

        // Prepare data for HMAC
        let mut data = Vec::new();

        if hardened {
            // Hardened child: data = 0x00 || ser256(private_key) || ser32(index)
            data.push(0x00);
            data.extend_from_slice(&self.private_key);
        } else {
            // Non-hardened child: data = serP(public_key) || ser32(index)
            let public_key = self.get_public_key()?;
            data.extend_from_slice(&public_key);
        }

        data.extend_from_slice(&index.to_be_bytes());

        // I = HMAC-SHA512(Key = chain_code, Data = data)
        let mut hmac = HmacSha512::new_from_slice(&self.chain_code)
            .map_err(|_| KeyManagerError::KeyGenerationError("HMAC init failed".to_string()))?;
        hmac.update(&data);
        let result = hmac.finalize().into_bytes();

        // Split result
        let il = &result[..32];
        let ir = &result[32..];

        // Child private key = (parse256(IL) + parent_private_key) mod n
        let child_key = Self::add_keys_modulo(il, &self.private_key)?;

        // Validate child key
        Self::validate_private_key(&child_key)?;

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(ir);

        // Compute parent fingerprint (first 4 bytes of Hash160 of parent public key)
        let parent_pub = self.get_public_key()?;
        let parent_fingerprint = Self::fingerprint_from_public(&parent_pub);

        Ok(ExtendedKey {
            private_key: child_key,
            chain_code,
            depth: self.depth + 1,
            parent_fingerprint,
            child_index: index,
        })
    }

    /// Derive key using a BIP32 path (e.g., "m/44'/0'/0'/0/0")
    ///
    /// # Arguments
    /// * `path` - Derivation path string
    ///
    /// # Returns
    /// Derived extended key
    pub fn derive_path(&self, path: &str) -> Result<Self> {
        let path = path.trim();

        // Check if path starts with "m" or "M"
        if !path.starts_with('m') && !path.starts_with('M') {
            return Err(KeyManagerError::InvalidDerivationPath(
                "Path must start with 'm' or 'M'".to_string(),
            ));
        }

        // Remove "m/" or "M/" prefix
        let path = if path.len() > 2 && &path[1..2] == "/" {
            &path[2..]
        } else if path.len() == 1 {
            return Ok(self.clone()); // Just "m" returns master key
        } else {
            return Err(KeyManagerError::InvalidDerivationPath(
                "Invalid path format".to_string(),
            ));
        };

        // If empty after "m/", return master key
        if path.is_empty() {
            return Ok(self.clone());
        }

        // Parse path components
        let mut current = self.clone();
        for component in path.split('/') {
            if component.is_empty() {
                continue;
            }

            // Check for hardened derivation (ends with ' or h)
            let (index_str, hardened) = if component.ends_with('\'') || component.ends_with('h') {
                (&component[..component.len() - 1], true)
            } else {
                (component, false)
            };

            // Parse index
            let index: u32 = index_str
                .parse()
                .map_err(|_| KeyManagerError::InvalidDerivationPath(
                    format!("Invalid index: {}", index_str)
                ))?;

            // Apply hardened offset if needed
            let final_index = if hardened {
                index.checked_add(HARDENED_OFFSET)
                    .ok_or_else(|| KeyManagerError::InvalidDerivationPath(
                        "Index overflow".to_string()
                    ))?
            } else {
                index
            };

            // Derive child
            current = current.derive_child(final_index)?;
        }

        Ok(current)
    }

    /// Get compressed public key from private key using secp256k1
    fn get_public_key(&self) -> Result<Vec<u8>> {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&self.private_key)
            .map_err(|e| KeyManagerError::KeyGenerationError(
                format!("Invalid private key: {}", e)
            ))?;
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        // serialize() returns 33-byte compressed public key [u8; 33]
        Ok(public_key.serialize().to_vec())
    }

    /// Calculate fingerprint from public key using Hash160
    /// Hash160 = RIPEMD160(SHA256(public_key))
    fn fingerprint_from_public(public_key: &[u8]) -> [u8; 4] {
        // Step 1: SHA256(public_key)
        let sha256_hash = Sha256::digest(public_key);

        // Step 2: RIPEMD160(SHA256 result)
        let mut hasher = Ripemd160::new();
        hasher.update(&sha256_hash);
        let hash160 = hasher.finalize();

        // Take first 4 bytes as fingerprint
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&hash160[..4]);
        fingerprint
    }

    /// Serialize to xprv format (Base58Check encoded)
    pub fn to_string(&self) -> String {
        // BIP32 serialization format
        let mut data = Vec::new();

        // Version bytes (4 bytes) - mainnet private key
        data.extend_from_slice(&[0x04, 0x88, 0xAD, 0xE4]);

        // Depth (1 byte)
        data.push(self.depth);

        // Parent fingerprint (4 bytes)
        data.extend_from_slice(&self.parent_fingerprint);

        // Child index (4 bytes)
        data.extend_from_slice(&self.child_index.to_be_bytes());

        // Chain code (32 bytes)
        data.extend_from_slice(&self.chain_code);

        // Private key (33 bytes: 0x00 + 32 bytes)
        data.push(0x00);
        data.extend_from_slice(&self.private_key);

        // Base58Check encode
        base58_check_encode(&data)
    }
}

/// Generate master key from seed (convenience function)
pub fn master_key_from_seed(seed: &[u8]) -> Result<ExtendedKey> {
    ExtendedKey::from_seed(seed)
}

// ============================================================================
// Base58Check encoding (Bitcoin standard)
// ============================================================================

fn base58_check_encode(data: &[u8]) -> String {
    // Calculate checksum: first 4 bytes of SHA256(SHA256(data))
    let hash1 = Sha256::digest(data);
    let hash2 = Sha256::digest(&hash1);
    let checksum = &hash2[..4];

    // Append checksum
    let mut payload = data.to_vec();
    payload.extend_from_slice(checksum);

    // Convert to base58
    let mut num = BigUint::from_bytes_be(&payload);
    let mut encoded = String::new();
    let base = BigUint::from(58u32);
    let zero = BigUint::from(0u32);

    while num > zero {
        let remainder = &num % &base;
        // Convert remainder to usize (always < 58, so safe)
        let digit: usize = remainder.to_u64().unwrap_or(0) as usize;
        encoded.insert(0, BASE58_ALPHABET[digit] as char);
        num = num / &base;
    }

    // Add leading '1's for leading zero bytes
    for &byte in payload.iter() {
        if byte == 0 {
            encoded.insert(0, '1');
        } else {
            break;
        }
    }

    encoded
}