# Crypto Key Manager

A CLI tool for managing cryptocurrency keys and mnemonics, built with Rust following Test-Driven Development practices.

## Features

### ✅ Base Commit (Current)
- 🔐 Generate BIP39 mnemonic phrases (12/15/18/21/24 words)
- ✅ Basic validation (word count, wordlist verification)
- 💻 Working CLI interface
- 🧪 18 passing tests (all PASS_TO_PASS)

### 📋 Future PRs (Planned via TDD)
- **PR #1:** BIP39 checksum validation (6 new tests)
- **PR #2:** Seed generation via PBKDF2 (6 new tests)
- **PR #3:** HD key derivation BIP32/BIP44 (8 new tests)

## Quick Start

```bash
# Generate a 12-word mnemonic
cargo run -- generate

# Generate a 24-word mnemonic
cargo run -- generate --words 24

# Validate a mnemonic
cargo run -- validate "abandon ability able about above absent absorb abstract absurd abuse access accident"

# Show help
cargo run -- help
```

## Development Philosophy: Test-Driven Development

This project follows strict TDD with two types of tests:

### Test Categories

#### PASS_TO_PASS Tests (Regression Tests)
- Validate existing functionality
- **Must pass in base commit and all future PRs**
- Ensure no regressions
- Currently: 18 tests in `src/tests.rs`

#### FAIL_TO_PASS Tests (Feature Tests)
- Validate NEW functionality being added in a PR
- **Should fail in base commit** (feature doesn't exist yet)
- Must pass after PR implementation
- Drive new feature development

### TDD Workflow Example

```bash
# Before PR #1:
cargo test  # 18 tests pass (base commit)

# Add FAIL_TO_PASS tests for checksum validation:
# - test_mnemonic_checksum_valid
# - test_entropy_to_mnemonic_12_words
# etc. (6 new tests)

cargo test  # 18 pass, 6 fail ❌ (expected!)

# Implement checksum validation feature

cargo test  # All 24 tests pass ✅

# Merge PR #1, repeat for PR #2, etc.
```

## Project Structure

```
crypto-key-manager/
├── src/
│   ├── main.rs          # CLI entry point
│   ├── lib.rs           # Library root
│   ├── error.rs         # Error types
│   ├── utils.rs         # Utility functions
│   ├── mnemonic.rs      # ✅ Basic mnemonic generation/validation
│   └── tests.rs         # ALL 18 unit tests
├── tests/               # Integration tests (future)
├── PR1_CHECKSUM_VALIDATION.md  # Issue template for PR #1
├── PR2_SEED_GENERATION.md      # Issue template for PR #2
├── PR3_HD_KEY_DERIVATION.md    # Issue template for PR #3
└── Cargo.toml
```

## Current Status

### Base Commit Features
- ✅ Basic mnemonic generation (pseudo-random, no checksum yet)
- ✅ Word validation (checks against BIP39 wordlist)
- ✅ Word count validation (12/15/18/21/24)
- ✅ Working CLI
- ✅ 18 PASS_TO_PASS tests

### Limitations (By Design - Fixed in Future PRs)
- ⚠️ **No checksum validation** (PR #1 will add this)
- ⚠️ **Not cryptographically secure entropy** (PR #1 will fix)
- ⚠️ **No seed generation** (PR #2 will add)
- ⚠️ **No key derivation** (PR #3 will add)

## Installation & Build

```bash
# Clone repository
git clone <your-repo>
cd crypto-key-manager

# Run tests
cargo test

# Build release
cargo build --release

# Run
./target/release/crypto-key-manager help
```

## Usage

```bash
# Generate mnemonic (default 12 words)
crypto-key-manager generate

# Generate 24-word mnemonic
crypto-key-manager generate --words 24

# Validate mnemonic (basic validation)
crypto-key-manager validate "abandon ability able about above absent absorb abstract absurd abuse access accident"
```

## Running Tests

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_generate_mnemonic_12_words

# Run quietly
cargo test --quiet
```

## Future Development

### PR #1: BIP39 Checksum Validation
**Goal:** Add proper entropy-to-mnemonic with SHA256 checksum

**New Features:**
- Entropy to mnemonic conversion
- Checksum calculation and validation
- Cryptographically secure entropy generation
- BIP39 test vector compliance

**Tests:** 18 → 24 (6 new FAIL_TO_PASS tests)

See: `PR1_CHECKSUM_VALIDATION.md`

### PR #2: Seed Generation  
**Goal:** Convert mnemonics to seeds via PBKDF2

**New Features:**
- PBKDF2-HMAC-SHA512 implementation
- Passphrase support ("25th word")
- 64-byte seed generation
- BIP39 seed test vectors

**Tests:** 24 → 30 (6 new FAIL_TO_PASS tests)

See: `PR2_SEED_GENERATION.md`

### PR #3: HD Key Derivation
**Goal:** Implement BIP32/BIP44 hierarchical key derivation

**New Features:**
- Master key derivation from seed
- Child key derivation (normal & hardened)
- Derivation path parsing (m/44'/60'/0'/0/0)
- Ethereum address generation
- Bitcoin address generation

**Tests:** 30 → 38 (8 new FAIL_TO_PASS tests)

See: `PR3_HD_KEY_DERIVATION.md`

## Dependencies

### Base Commit
- **std library only** - No external dependencies

### Future PRs Will Add:
- `sha2` - SHA256 hashing (PR #1)
- `pbkdf2`, `hmac` - Key derivation (PR #2)
- `secp256k1`, `ripemd`, `keccak` - Address generation (PR #3)

## Contributing

1. Pick a PR from the templates (PR1, PR2, or PR3)
2. Write FAIL_TO_PASS tests first (verify they fail)
3. Implement the feature
4. Ensure all tests pass (old PASS_TO_PASS + new FAIL_TO_PASS)
5. Submit PR with test breakdown

## Security Warning

⚠️ **This is a learning/development project.**

**Current Base Commit:**
- Uses pseudo-random generation (NOT cryptographically secure)
- No checksum validation (can't detect typos)
- Suitable for learning, NOT for production

**After PR #1-3:**
- Will use proper cryptographic primitives
- BIP39/BIP32/BIP44 compliant
- Still recommend professional audit before real use

**DO NOT use for real funds without thorough security review!**

## Test Summary

| Stage | Tests | Description |
|-------|-------|-------------|
| Base  | 18    | Basic mnemonic + utils |
| PR #1 | 24    | + Checksum validation |
| PR #2 | 30    | + Seed generation |
| PR #3 | 38    | + HD key derivation |

## License

MIT

## Acknowledgments

- [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) - Mnemonic standard
- [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) - HD wallet standard
- [BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) - Multi-account hierarchy
