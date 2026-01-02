use rand::{RngCore, rngs::OsRng};
use x25519_dalek::{EphemeralSecret, PublicKey};
use crate::error::ProtocolError;
use serde::{Serialize, Deserialize};
use std::fs;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey, Signature, Verifier};
use chacha20poly1305::{
    ChaCha20Poly1305, ChaChaPoly1305, Nonce, aead::{Aead, KeyInit}
};

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


#[derive(Serialize, Deserialize)]
pub struct Identity {
    signing_key: SigningKey,
    public_key: VerifyingKey,
}

impl Identity {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let public_key = VerifyingKey::from(&signing_key);

        Self { signing_key, public_key }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }

    pub fn load(name: &str) -> Result<Self, ProtocolError> {
        let filename = format!("keys/{}.key", name);
        let data = fs::read_to_string(&filename)
            .map_err(|_| ProtocolError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Key file not found! {}", filename)
            )))?;

        let bytes = hex::decode(data.trim()).map_err(|_| ProtocolError::CryptoError)?;
        bincode::deserialize(&bytes).map_err(ProtocolError::Serialization)
    }

    pub fn save(&self, name: &str) -> Result<(), ProtocolError> {
        let _ = fs::create_dir("keys");

        let bytes = bincode::serialize(&self)?;
        let hex_string = hex::encode(bytes);

        fs::write(format!("keys/{}.key", name), hex_string)?;

        Ok(())
    }

    pub fn save_public(&self, name: &str) -> Result<(), ProtocolError> {
        let _ = fs::create_dir("keys");
        let bytes = self.public_key.to_bytes();
        let hex_string = hex::encode(bytes);

        fs::write(format!("keys/{}.pub", name), hex_string)?;
        
        Ok(())
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature: Signature = self.signing_key.sign(message);
        signature.to_vec()
    }

    pub fn verify(peer_public_key_bytes: &[u8; 32], message: &[u8], signature_bytes: &[u8]) -> Result<(), ProtocolError> {
        let peer_key = VerifyingKey::from_bytes(peer_public_key_bytes).map_err(|_| ProtocolError::CryptoError)?;
        let signature = Signature::from_slice(signature_bytes).map_err(|_| ProtocolError::CryptoError)?;

        peer_key.verify(message, &signature).map_err(|_| ProtocolError::InvalidSignature)
    }
}


pub struct SymmetricKey {
    cipher: ChaCha20Poly1305,
}

impl SymmetricKey {
    pub fn new(key_bytes: [u8; 32]) -> Self {
        Self {
            cipher: ChaChaPoly1305::new(&key_bytes.into()),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut ciphertext = self.cipher.encrypt(nonce, plaintext).map_err(|_| ProtocolError::CryptoError)?;

        let mut packet = nonce_bytes.to_vec();
        packet.append(&mut ciphertext);

        Ok(packet)
    }

    pub fn decrypt(&self, packet: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        if packet.len() < NONCE_LEN {
            return Err(ProtocolError::CryptoError);
        }

        let nonce = Nonce::from_slice(&packet[..NONCE_LEN]);
        let ciphertext = &packet[NONCE_LEN..];
        
        self.cipher.decrypt(nonce, ciphertext).map_err(|_| ProtocolError::CryptoError)
    }
}
