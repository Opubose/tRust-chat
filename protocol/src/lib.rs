pub mod crypto;
pub mod error;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Packet {
    pub msg: MessageType,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum MessageType {
    Registration {
        sender: String,
        timestamp: f64,
    },
    Message {
        sender: String,
        recipient: String,
        content: Vec<u8>,
    },
    Handshake {
        sender: String,
        recipient: String,
        pubkey: [u8; 32],
    },
}

impl Packet {
    pub fn as_signable_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(&self.msg)
    }
}
