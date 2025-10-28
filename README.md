# crypto-key-manager
Secure CLI for generating HD wallets, deriving addresses across different paths (BIP44/49/84), signing messages, with encrypted local storage.
A CLI tool for managing cryptocurrency keys and mnemonics, built with Rust following Test-Driven Development practices.

## Features (Planned)

- 🔐 Generate secure BIP39 mnemonic phrases (12/15/18/21/24 words)
- 🔑 Derive keys using BIP32/BIP44 derivation paths
- ✅ Validate mnemonic phrases
- 💾 Secure key storage with encryption
- 🌐 Support for multiple cryptocurrencies (Ethereum, Bitcoin, etc.)
- 📊 Display key information in various formats

## Development Philosophy: Test-Driven Development

This project follows a strict TDD approach with two types of tests:

### Test Categories

#### 1. **PASS_TO_PASS Tests** (Regression Tests)
- These tests validate existing functionality
- **Must pass in the base commit** (before any PR)
- Must continue to pass after the PR is merged
- Ensure we don't break existing features
- Found in every module's test section

#### 2. **FAIL_TO_PASS Tests** (Feature Tests)
- These tests validate NEW functionality being added
- **Should fail or miss in the base commit** (test the feature that doesn't exist yet)
- Must pass after the PR is merged
- Drive the implementation of new features
- Added as part of each feature PR

### PR Workflow

1. **Before Starting a Feature:**
   ```bash
   # Ensure all existing tests pass
   cargo test
   ```

2. **During Feature Development:**
   - Write FAIL_TO_PASS tests first (they should fail)
   - Implement the feature
   - Ensure FAIL_TO_PASS tests now pass
   - Ensure all PASS_TO_PASS tests still pass

3. **PR Checklist:**
   - [ ] All PASS_TO_PASS tests pass
   - [ ] New FAIL_TO_PASS tests added for the feature
   - [ ] New FAIL_TO_PASS tests pass
   - [ ] Code is documented
   - [ ] No compiler warnings

### Test Naming Convention

```rust
#[cfg(test)]
mod tests {
    // PASS_TO_PASS: Description of what this validates
    #[test]
    fn test_existing_feature() {
        // Tests for existing functionality
    }
    
    // FAIL_TO_PASS: Description of new feature
    #[test]
    fn test_new_feature() {
        // Tests for new functionality (in feature PR)
    }
}
```

## Project Structure

```
crypto-key-manager/
├── src/
│   ├── main.rs              # CLI entry point
│   ├── lib.rs               # Library root
│   ├── error.rs             # Error types
│   ├── utils.rs             # Utility functions (with base tests)
│   ├── mnemonic.rs          # Mnemonic generation/validation (TODO)
│   ├── key_derivation.rs    # BIP32/BIP44 derivation (TODO)
│   └── wallet.rs            # Wallet management (TODO)
├── tests/                   # Integration tests (future)
└── Cargo.toml
```

## Installation

```bash
cargo build --release
```

## Usage

```bash
# Generate a 12-word mnemonic
cargo run -- generate

# Generate a 24-word mnemonic
cargo run -- generate --words 24

# Validate a mnemonic
cargo run -- validate "your mnemonic phrase here"

# Derive a key
cargo run -- derive --mnemonic "your mnemonic" --path "m/44'/60'/0'/0/0"
```

## Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run tests for a specific module
cargo test utils::tests

# Run a specific test
cargo test test_validate_word_count_valid
```

## Current Status

**Base Commit Features:**
- ✅ Project structure
- ✅ Error handling framework
- ✅ Basic utility functions with tests
- ✅ CLI skeleton
- ✅ Module stubs

**Next PRs (Planned):**
1. **PR #1: Mnemonic Generation**
   - FAIL_TO_PASS: Generate valid BIP39 mnemonics
   - FAIL_TO_PASS: Support different word counts
   - PASS_TO_PASS: Utility functions still work

2. **PR #2: Mnemonic Validation**
   - FAIL_TO_PASS: Validate mnemonic checksums
   - FAIL_TO_PASS: Detect invalid words
   - PASS_TO_PASS: Generation + utilities work

3. **PR #3: Key Derivation**
   - FAIL_TO_PASS: Derive keys from mnemonic
   - FAIL_TO_PASS: Support BIP44 paths
   - PASS_TO_PASS: All previous features work

## Dependencies

- `clap` - CLI argument parsing
- `bip39` - BIP39 mnemonic implementation
- `secp256k1` - Elliptic curve cryptography
- `sha2`, `ripemd` - Hashing functions
- `hex`, `bs58` - Encoding utilities
- `serde` - Serialization

## Contributing

1. Write FAIL_TO_PASS tests for your feature
2. Implement the feature
3. Ensure all tests pass
4. Submit PR with test breakdown

## License

MIT

## Security Warning

⚠️ **This is a learning/development project. DO NOT use for production or real funds without thorough security audit.**

