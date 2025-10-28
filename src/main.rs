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
    println!("      BIP39 checksum validation will be added in a future update.");
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
