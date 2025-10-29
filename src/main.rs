use crypto_key_manager::{mnemonic, Result};
use std::env;


fn print_usage() {
    println!("Crypto Key Manager - A CLI tool for managing cryptocurrency keys and mnemonics");
    println!("\nUsage:");
    println!("  crypto-key-manager <command> [options]");
    println!("\nCommands:");
    println!("  generate [--words <12|15|18|21|24>]  Generate a new mnemonic phrase");
    println!("  validate <mnemonic>                   Validate a mnemonic phrase");
    println!("  help                                  Show this help message");
    println!("\nExamples:");
    println!("  crypto-key-manager generate --words 24");
    println!("  crypto-key-manager validate \"abandon ability able about above absent absorb abstract absurd abuse access accident\"");
    println!("\nNote: Current implementation uses basic validation.");
    println!("  seed <mnemonic> [passphrase]      Generate seed from mnemonic");
    println!("  derive <mnemonic> <path> [pass]   Derive key at BIP32 path (m/44'/0'/0'/0/0)");
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    match args[1].as_str() {
        "generate" => {
            let mut words = 12;

            // Parse --words flag if present
            if args.len() > 3 && args[2] == "--words" {
                words = args[3].parse().unwrap_or(12);
            }

            match mnemonic::generate_mnemonic(words) {
                Ok(mnemonic_phrase) => {
                    println!("\nGenerated {}-word mnemonic:", words);
                    println!("{}", mnemonic_phrase);
                    println!("\n⚠️  IMPORTANT: Write this down and store it securely!");
                    println!("    This is a demo - use proper entropy in production.\n");
                }
                Err(e) => {
                    eprintln!("Error generating mnemonic: {}", e);
                    std::process::exit(1);
                }
            }
            Ok(())
        }
        "validate" => {
            if args.len() < 3 {
                println!("Error: Mnemonic phrase required");
                print_usage();
                return Ok(());
            }

            let mnemonic_phrase = &args[2];
            
            match mnemonic::validate_mnemonic(mnemonic_phrase) {
                Ok(()) => {
                    println!("✓ Mnemonic is valid!");
                    println!("  Word count: {} words", mnemonic_phrase.split_whitespace().count());
                    println!("\nNote: Checksum validation will be added in PR #1");
                }
                Err(e) => {
                    eprintln!("✗ Invalid mnemonic: {}", e);
                    std::process::exit(1);
                }
            }
            Ok(())
        }
        // After the existing commands, add these:

"seed" => {
    if args.len() < 3 {
        println!("Error: Mnemonic required");
        return Ok(());
    }
    let mnemonic_phrase = &args[2];
    let passphrase = args.get(3).map(|s| s.as_str()).unwrap_or("");
    
    match crypto_key_manager::seed::mnemonic_to_seed(mnemonic_phrase, passphrase) {
        Ok(seed) => {
            println!("Seed (hex): {}", hex::encode(seed));
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
    Ok(())
}

"derive" => {
    if args.len() < 4 {
        println!("Usage: crypto-key-manager derive <mnemonic> <path> [passphrase]");
        return Ok(());
    }
    let mnemonic = &args[2];
    let path = &args[3];
    let passphrase = args.get(4).map(|s| s.as_str()).unwrap_or("");
    
    match crypto_key_manager::seed::generate_master_key_from_mnemonic(mnemonic, passphrase)
        .and_then(|master| master.derive_path(path)) 
    {
        Ok(key) => println!("xprv: {}", key.to_string()),
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
        Ok(())
    }
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        _ => {
            println!("Unknown command: {}", args[1]);
            print_usage();
            Ok(())
        }
    }
}
