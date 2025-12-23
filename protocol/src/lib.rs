use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Packet {
    #[serde(flatten)]
    pub msg: MessageType,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", content = "payload", rename_all = "lowercase")]
pub enum MessageType {
    Registration {
        sender: String,
        timestamp: f64
    },
    Message {
        sender: String,
        recipient: String,
        ciphertext: String,
        mac: String
    },
    Handshake {
        sender: String,
        pubkey: u64
    }
}
