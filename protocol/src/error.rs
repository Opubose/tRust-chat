use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Cryptographic error")]
    CryptoError,

    #[error("Signature verification failed")]
    InvalidSignature,

    #[error("Unknown error")]
    Unknown,
}
