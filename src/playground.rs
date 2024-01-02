use std::{
    collections::{HashMap, HashSet, LinkedList, VecDeque},
    fs::{self, File},
    io::{self, BufRead, BufReader, Write},
    net::{TcpListener, TcpStream, ToSocketAddrs},
    os::unix::net::SocketAddr,
    path::Path,
    pin::Pin,
    sync::{
        atomic::{AtomicPtr, AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
    time::{Duration, Instant},
};

use futures::{
    future::{self, BoxFuture, Either},
    stream::{self, StreamExt},
    task::{Context, Poll},
    FutureExt,
};


use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener as TokioTcpListener,
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};

use tokio_stream::wrappers::{SignalStream, TcpListenerStream, WatchStream};

use crate::error::PlaygroundError;

use itertools::*;
use rayon::prelude::*;
use s2n_quic::{
    self as quic,
    provider::{
        self,
        event::{ConnectionInfo, ConnectionMeta, Meta, Timestamp},
    },
    Client, Connection, Server,
};
use std::future::Future;
use tracing::{debug, error, info, instrument, Instrument};


#[instrument]
async fn playground() -> Result<(), PlaygroundError> {

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_play() {
        playground().await.unwrap();
    }
}
