use thiserror::Error;
use std::{io, env::VarError};

#[derive(Error, Debug)]
pub enum PlaygroundError {
    #[error("io error")]
    IoError(#[from] io::Error),
    #[error("Internal Error {0}")]
    InternalError(String),
    #[error("unknown data store error")]
    Unknown,
}


impl From<VarError> for PlaygroundError {
    fn from(error: VarError) -> Self {
        PlaygroundError::InternalError(format!("VarError: {}", error))
    }
}