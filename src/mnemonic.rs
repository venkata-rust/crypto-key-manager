use crate::error::{KeyManagerError, Result};
use crate::utils::validate_word_count;
use std::time::{SystemTime, UNIX_EPOCH};

// BIP39 English wordlist (first 2048 words)
// For demo purposes, including a subset. In production, use full list.
const WORDLIST: &[&str] = &[
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
    "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
    "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
    "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
    "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact",
    "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
    "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
    "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis",
    "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball",
    "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base",
    "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become",
    "beef", "before", "begin", "behave", "behind", "believe", "below", "belt",
    "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle",
    "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black",
    "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood",
    "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
    "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring",
    "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain",
    "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief",
    "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother",
    "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
    "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus",
    "business", "busy", "butter", "buyer", "buzz", // ... (256 words for demo)
];

/// Generate a mnemonic phrase with the specified word count
/// NOTE: This is a basic implementation without BIP39 checksum validation
/// Checksum validation will be added in PR #1
pub fn generate_mnemonic(word_count: usize) -> Result<String> {
    validate_word_count(word_count)?;
    
    // Simple pseudo-random selection using system time
    // In production, use cryptographically secure randomness
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    
    let mut words = Vec::new();
    let wordlist_len = WORDLIST.len();
    
    for i in 0..word_count {
        // Simple pseudo-random index generation (NOT cryptographically secure)
        let index = ((seed.wrapping_mul(i as u128 + 1)) % wordlist_len as u128) as usize;
        words.push(WORDLIST[index]);
    }
    
    Ok(words.join(" "))
}

/// Check if a word is in the BIP39 wordlist
pub fn is_valid_word(word: &str) -> bool {
    WORDLIST.contains(&word)
}

/// Validate a mnemonic phrase (basic validation only)
/// NOTE: This does NOT validate BIP39 checksum (PR #1 will add that)
pub fn validate_mnemonic(phrase: &str) -> Result<()> {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    
    // Check word count
    validate_word_count(words.len())?;
    
    // Check each word is in the wordlist
    for word in &words {
        if !is_valid_word(word) {
            return Err(KeyManagerError::InvalidWord(word.to_string()));
        }
    }
    
    // NOTE: Checksum validation will be added in PR #1
    Ok(())
}

/// Get the wordlist size
pub fn wordlist_size() -> usize {
    WORDLIST.len()
}
