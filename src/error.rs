use thiserror::Error;
use std::{io, env::VarError, array::TryFromSliceError};

#[derive(Error, Debug)]
pub enum PlaygroundError {
    #[error("io error")]
    IoError(#[from] io::Error),
    #[error("Try from slice error")]
    TryFromSliceError(#[from] TryFromSliceError),
    #[error("Commitment error")]
    CommitmentError(#[from] ark_poly_commit::Error),
    #[error("Internal Error {0}")]
    InternalError(String),
    #[error("unknown error")]
    Unknown,
}


impl From<VarError> for PlaygroundError {
    fn from(error: VarError) -> Self {
        PlaygroundError::InternalError(format!("VarError: {}", error))
    }
}

impl From<Box<dyn std::error::Error>> for PlaygroundError {
    fn from(error: Box<dyn std::error::Error>) -> Self {
        PlaygroundError::InternalError(format!("Boxed Error: {}", error))
    }
}