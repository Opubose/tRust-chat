use protocol::Packet;
use std::error::Error;
use tokio::io::AsyncWriteExt;

/// Serializes and sends a packet with a 4-byte length header.
pub async fn send_packet(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    packet: &Packet,
) -> Result<(), Box<dyn Error>> {
    let bytes = bincode::serialize(packet)?;
    let len_header = (bytes.len() as u32).to_be_bytes();

    writer.write_all(&len_header).await?;
    writer.write_all(&bytes).await?;

    Ok(())
}
