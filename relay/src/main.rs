use protocol::{MessageType, Packet};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::sync::mpsc;

type SharedState = Arc<RwLock<HashMap<String, mpsc::UnboundedSender<Packet>>>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("[relay] Loading private key");
    println!("[relay] Loading clients' public keys");

    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("[relay] Server listening on 127.0.0.1:8080...");

    let state: SharedState = Arc::new(RwLock::new(HashMap::new()));

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("[relay] New connection from {}", addr);

        let state = state.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, state).await {
                eprintln!("[relay] ERROR: Connection lost: {}", e);
            }
        });
    }
}

async fn handle_connection(
    socket: TcpStream,
    state: SharedState,
) -> Result<(), Box<dyn std::error::Error>> {
    let (tx, mut rx) = mpsc::unbounded_channel::<Packet>();
    let (mut reader, mut writer) = socket.into_split();
    let mut my_username: Option<String> = None;

    loop {
        let mut length_buf = [0u8; 4];

        tokio::select! {
            // Case A (network read): for when the owner of the connection sends a message (either to the relay or to someone else)
            result = reader.read_exact(&mut length_buf) => {
                if result.is_err() { break; }

                let len = u32::from_be_bytes(length_buf) as usize;
                let mut buf = vec![0u8; len];

                reader.read_exact(&mut buf).await?;

                let packet: Packet = bincode::deserialize(&buf)?;

                match packet.msg {
                    MessageType::Registration { ref sender, .. } => {
                        println!("[relay] Receiving registration request");
                        println!("[relay] Registration request from client: {}", sender);

                        let mut map = state.write().await;
                        map.insert(sender.clone(), tx.clone());

                        my_username = Some(sender.clone());
                        println!("[relay] Client {} authenticated", sender);
                        println!("[relay] Sending authentication response to {}", sender);
                        println!("[relay] Client {} registration complete\n", sender);

                        // TODO: verify signature
                        // TODO: reply with confirmation
                    }
                    MessageType::Message { ref recipient, .. } | MessageType::Handshake { ref recipient, .. } => {
                        let sender = match &packet.msg {
                            MessageType::Message { sender, .. } => sender,
                            MessageType::Handshake { sender, .. } => sender,
                            _ => "unknown",
                        };

                        println!("[relay] Relaying message: {} -> {}", sender, recipient);

                        let map = state.read().await;
                        if let Some(recipient_tx) = map.get(recipient) {
                            let _ = recipient_tx.send(packet);
                        } else {
                            println!("[relay] Warning: {} is not connected but {} is trying to send them a message! Rejecting...", recipient, sender);
                        }
                    }
                }
            }

            // Case B (channel recv): for when someone else sends a message to the owner of this connection
            Some(packet) = rx.recv() => {
                let bytes = bincode::serialize(&packet)?;
                let len_header = (bytes.len() as u32).to_be_bytes();

                writer.write_all(&len_header).await?;
                writer.write_all(&bytes).await?;
            }
        }
    }

    if let Some(name) = my_username {
        let mut map = state.write().await;
        map.remove(&name);
        println!("[relay] Client {} closed the connection.\n", name);
    }

    Ok(())
}
