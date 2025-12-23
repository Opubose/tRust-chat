use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce
};
use rand::{rngs::OsRng, RngCore};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use crate::error::ProtocolError;

const NONCE_LEN: usize = 12;

pub struct Handshake {
    secret: EphemeralSecret,
    pub public_key: PublicKey,
}

impl Handshake {
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret);
        Self { secret, public_key }
    }

    pub fn derive_shared_key(self, peer_public: PublicKey) -> [u8; 32] {
        let shared_secret = self.secret.diffie_hellman(&peer_public);
        *shared_secret.as_bytes()
    }
}
