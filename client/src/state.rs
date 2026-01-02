use protocol::crypto::{Handshake, SymmetricKey};

pub struct ClientState {
    pub peer_target: Option<String>, // Who are we currently talking to?
    pub session_key: Option<SymmetricKey>, // The encryption key for the current session
    pub pending_handshake: Option<Handshake>, // If we started a handshake, we hold the secret here until they reply
}

impl ClientState {
    pub fn new() -> Self {
        Self {
            peer_target: None,
            session_key: None,
            pending_handshake: None,
        }
    }
}
