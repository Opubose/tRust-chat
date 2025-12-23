use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use protocol::{Packet, MessageType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("[relay] Server listening on 127.0.0.1:8080...");

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("[relay] New connection from {}", addr);

        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket).await {
                eprintln!("[relay] Error handling {}: {}", addr, e);
            }
        });
    }
}

async fn handle_connection(mut socket: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let mut length_buf = [0u8; 4];
        if socket.read_exact(&mut length_buf).await.is_err() {
            return Ok(());
        }

        let len = u32::from_be_bytes(length_buf) as usize;

        let mut buf = vec![0u8; len];

        socket.read_exact(&mut buf).await?;

        let packet: Packet = bincode::deserialize(&buf)?;

        println!("[relay] Received binary packet: {:?}", packet);

        match packet.msg {
            MessageType::Handshake { sender, .. } => {
                println!("[relay] {} registered!", sender);
            }
            _ => {
                println!("[relay] Unrecognized packet");
            }
        }
    }
}
