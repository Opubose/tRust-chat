mod input;
mod network;
mod state;

use tokio::net::TcpStream;
use tokio::io::AsyncReadExt;
use protocol::{Packet, MessageType};
use protocol::crypto::{Identity, Handshake, SymmetricKey};
use std::env;
use std::fs;

use crate::input::spawn_line_reader;
use crate::network::send_packet;
use crate::state::ClientState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let my_name = args.get(1).expect("Usage: cargo run --bin client -- <name>").clone();

    println!("[{}] Loading my private key", my_name);
    let identity = Identity::load(&my_name).expect("Failed to load keys! Run keygen first.");

    let relay_addr = "127.0.0.1:8080";
    println!("[{}] Connecting to relay at {}...", my_name, relay_addr);
    
    let socket = match TcpStream::connect(relay_addr).await {
        Ok(s) => s,
        Err(_) => {
            println!("[{}] Failed to connect to relay. Are you sure it's running?", my_name);
            return Ok(());
        }
    };
    let (mut reader, mut writer) = socket.into_split();

    println!("[{}] Starting registration protocol", my_name);

    let reg_packet = {
        let msg = MessageType::Registration {
            sender: my_name.clone(),
            timestamp: 0.0,
        };

        println!("[{}] Signing registration request with my private key", my_name);
        let mut p = Packet { msg, signature: vec![] };
        p.signature = identity.sign(&p.as_signable_bytes()?);
        p
    };

    println!("[{}] Sending registration request to relay", my_name);
    send_packet(&mut writer, &reg_packet).await?;
    println!("[{}] Registration complete\n", my_name);

    let mut state = ClientState::new();
    let mut input_rx = spawn_line_reader();

    println!("[{}] Waiting for session establishment request", my_name);

    loop {
        let mut len_buf = [0u8; 4];

        tokio::select! {
            Some(line) = input_rx.recv() => {
                let line = line.trim();
                if line.is_empty() { continue; }

                if line.to_lowercase() == "exit chat" {
                    println!("[{}] Leaving so soon? Good bye :( ...", my_name);
                    break;
                }

                if let Some(target) = line.strip_prefix("connect ") {
                    println!("[{}] Starting session establishment with {}", my_name, target);

                    println!("[{}] Generating my DH private key", my_name);
                    let handshake = Handshake::new();

                    println!("[{}] Computed my DH public key g^a mod p = 0x{}", my_name, hex::encode(handshake.public_key.as_bytes()));
                    
                    let msg = MessageType::Handshake {
                        sender: my_name.clone(),
                        recipient: target.to_string(),
                        pubkey: handshake.public_key.to_bytes(),
                    };
                    
                    println!("[{}] Signing my DH public key with my private key", my_name);
                    let mut pkt = Packet { msg, signature: vec![] };
                    pkt.signature = identity.sign(&pkt.as_signable_bytes()?);
                    
                    println!("[{}] Sending authenticated DH public key to {}", my_name, target);
                    send_packet(&mut writer, &pkt).await?;

                    println!("[{}] Waiting for {}'s DH public key...", my_name, target);
                    
                    // Update State
                    state.pending_handshake = Some(handshake);
                    state.peer_target = Some(target.to_string());
                } 
                else if let Some(target) = &state.peer_target {
                    // Send Message
                    if let Some(key) = &state.session_key {
                        let ciphertext = key.encrypt(line.as_bytes())?;
                        let msg = MessageType::Message {
                            sender: my_name.clone(),
                            recipient: target.clone(),
                            content: ciphertext,
                        };
                        let mut pkt = Packet { msg, signature: vec![] };
                        pkt.signature = identity.sign(&pkt.as_signable_bytes()?);
                        
                        if let Err(e) = send_packet(&mut writer, &pkt).await {
                            println!("[{}] Error encountered while sending message: {}", my_name, e);
                        }
                        println!("[Me]: {}", line);
                    } else {
                        println!("[{}] Error: no session key established yet!", my_name);
                    }
                } else {
                    println!("[{}] Type 'connect <user>' to start chatting.", my_name);
                }
            }

            result = reader.read_exact(&mut len_buf) => {
                if result.is_err() {
                    println!("[{}] ERROR: Connection lost.", my_name);
                    println!("[{}] Terminating session.", my_name);
                    break;
                }
                
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut buf = vec![0u8; len];
                reader.read_exact(&mut buf).await?;
                
                let packet: Packet = match bincode::deserialize(&buf) {
                    Ok(p) => p,
                    Err(e) => {
                        println!("[{}] ERROR: Invalid Bincode received: {}", my_name, e);
                        break;
                    }
                };
                
                let sender = match &packet.msg {
                    MessageType::Registration { sender, .. } => sender,
                    MessageType::Message { sender, .. } => sender,
                    MessageType::Handshake { sender, .. } => sender,
                };

                if let Some(pubkey) = load_public_key(sender) {
                    if Identity::verify(&pubkey, &packet.as_signable_bytes()?, &packet.signature).is_err() {
                        println!("[{}] Warning!!! {}'s signature verification failed!", my_name, sender);
                        println!("[{}] Potential MITM attack detected.", my_name);
                        println!("[{}] Terminating this chat immediately for security. Sorry about that.", my_name);
                        continue;
                    }
                } else {
                    println!("[{}] Error loading public key for {}", my_name, sender);
                    continue;
                }

                match packet.msg {
                    MessageType::Handshake { sender, pubkey, .. } => {
                        println!("[{}] Handshake received from {}", my_name, sender);
                        
                        if state.pending_handshake.is_some() {
                            // We are Alice (Completing the handshake)
                            println!("[{}] Received {}'s public key = 0x{}", my_name, sender, hex::encode(pubkey));
                            let handshake = state.pending_handshake.take().unwrap();

                            println!("[{}] Computing shared session key", my_name);
                            let secret = handshake.derive_shared_key(x25519_dalek::PublicKey::from(pubkey));
                            state.session_key = Some(SymmetricKey::new(secret));

                            println!("[{}] Session key established: 0x{}", my_name, hex::encode(secret));
                            println!("[{}] Secure session established with {}", my_name, sender);
                            println!("[{}] Enter your messages below :D, or type \"exit chat\" to quit :(\n", my_name);
                        } else {
                            // We are Bob (Responding)
                            println!("[{}] Received connection request from {} with DH public key 0x{}", my_name, sender, hex::encode(pubkey));
                            println!("[{}] Generating my DH private key", my_name);

                            let handshake = Handshake::new();
                            println!("[{}] Computed my DH public key g^b mod p = 0x{}", my_name, hex::encode(handshake.public_key.as_bytes()));
                            let my_pubkey_bytes = handshake.public_key.to_bytes();

                            println!("[{}] Computing shared session key from DH", my_name);
                            let secret = handshake.derive_shared_key(x25519_dalek::PublicKey::from(pubkey));
                            state.session_key = Some(SymmetricKey::new(secret));

                            println!("[{}] Session key established: 0x{}\n", my_name, hex::encode(secret));
                            
                            // Send reply
                            let msg = MessageType::Handshake {
                                sender: my_name.clone(),
                                recipient: sender.clone(),
                                pubkey: my_pubkey_bytes,
                            };

                            println!("[{}] Signing my DH public key with my private key", my_name);
                            let mut pkt = Packet { msg, signature: vec![] };
                            pkt.signature = identity.sign(&pkt.as_signable_bytes()?);
                            
                            println!("[{}] Sending authenticated DH public key to {}", my_name, sender);
                            send_packet(&mut writer, &pkt).await?;
                            state.peer_target = Some(sender.clone());

                            println!("[{}] Secure session established with {}", my_name, sender);
                            println!("[{}] Enter your messages below :D, or type \"exit chat\" to quit :(\n", my_name);
                        }
                    }
                    MessageType::Message { sender, content, .. } => {
                        if let Some(key) = &state.session_key {
                            match key.decrypt(&content) {
                                Ok(pt) => println!("[{}]: {}", sender, String::from_utf8_lossy(&pt)),
                                Err(_) => {
                                    eprintln!("[{}] Warning!!! MAC integrity check failed from {}!", my_name, sender);
                                    eprintln!("[{}] Terminating this chat immediately for security. Sorry about that.", my_name);
                                    break;
                                }
                            }
                        } else {
                            println!("[{}] Error: Received encrypted message but no session key!", my_name);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}


fn load_public_key(username: &str) -> Option<[u8; 32]> {
    let path = format!("keys/{}.pub", username);
    let hex = fs::read_to_string(path).ok()?;
    let bytes = hex::decode(hex.trim()).ok()?;
    bytes.try_into().ok()
}
