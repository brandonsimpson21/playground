use std::{array::TryFromSliceError, env::VarError, io};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PlaygroundError {
    #[error("io error")]
    IoError(#[from] io::Error),
    #[error("Try from slice error")]
    TryFromSliceError(#[from] TryFromSliceError),
    #[error("Network error {0}")]
    NetworkError(String),
    #[error("rustls error {0}")]
    RustlsError(#[from] rustls::Error),
    #[error("join error")]
    JoinError(#[from] tokio::task::JoinError),
    #[error("Internal Error {0}")]
    InternalError(String),
    #[error("Var Error")]
    VarError(#[from] VarError),
    #[error("unknown error")]
    Unknown,
}

impl From<Box<dyn std::error::Error>> for PlaygroundError {
    fn from(error: Box<dyn std::error::Error>) -> Self {
        PlaygroundError::InternalError(format!("Boxed Error: {}", error))
    }
}