use protocol::crypto::Identity;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: cargo run --bin keygen <username>");
        return;
    }

    let username = &args[1];
    println!("Generating keys for {}", username);

    let identity = Identity::generate();

    if let Err(e) = identity.save(username) {
        eprintln!("Failed to save private key: {}", e);
        return;
    }

    if let Err(e) = identity.save_public(username) {
        eprintln!("Failed to save public key: {}", e);
        return;
    }

    println!("Keys saved to:");
    println!("  keys/{}.key (PRIVATE - DO NOT SHARE)", username);
    println!(
        "  keys/{}.pub (PUBLIC - DO WHATEVER YOU WANT WITH IT)",
        username
    );
}
