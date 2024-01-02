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
    time::{Duration, Instant}, num::NonZeroU64,
};

use futures::{
    future::{self, BoxFuture, Either},
    stream::{self, StreamExt},
    task::{Context, Poll},
    FutureExt,
};

use quic::{client::Connect, stream::BidirectionalStream};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener as TokioTcpListener,
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};

use tokio_stream::wrappers::{SignalStream, TcpListenerStream, WatchStream};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::PlaygroundError;

use itertools::*;
use rayon::prelude::*;
use s2n_quic::{
    self as quic,
    provider::{
        self,
        event::{ConnectionInfo, ConnectionMeta, Meta, Timestamp, supervisor, Subscriber},
    },
    Client, Connection, Server,
};
use std::future::Future;
use tracing::{debug, error, info, instrument, Instrument};

#[derive(Debug, Clone)]
pub struct ConnectionContext{
    pub last_update: Timestamp,
    pub key_bytes: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Default)]
pub struct ConnectionSupervisor;

impl provider::event::Subscriber for ConnectionSupervisor {
    type ConnectionContext = ConnectionContext;

    fn create_connection_context(
        &mut self,
        meta: &ConnectionMeta,
        info: &ConnectionInfo,
    ) -> Self::ConnectionContext {
        ConnectionContext {
            last_update: *meta.timestamp(),
            key_bytes: Vec::new(),
            data: Vec::new(),
        }
    }

    fn supervisor_timeout(
        &mut self,
        conn_context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        context: &provider::event::supervisor::Context,
    ) -> Option<Duration> {
        Some(Duration::from_secs(5))
    }

    fn on_supervisor_timeout(
        &mut self,
        conn_context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        context: &provider::event::supervisor::Context,
    ) -> provider::event::supervisor::Outcome {
        provider::event::supervisor::Outcome::default()
    }

    fn on_application_protocol_information(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::ApplicationProtocolInformation,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_server_name_information(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::ServerNameInformation,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_packet_skipped(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::PacketSkipped,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_packet_sent(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::PacketSent,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_packet_received(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::PacketReceived,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_active_path_updated(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::ActivePathUpdated,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_path_created(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::PathCreated,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_frame_sent(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::FrameSent,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_frame_received(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::FrameReceived,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_packet_lost(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::PacketLost,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_recovery_metrics(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::RecoveryMetrics,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_congestion(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::Congestion,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_rx_ack_range_dropped(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::RxAckRangeDropped,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_ack_range_received(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::AckRangeReceived,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_ack_range_sent(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::AckRangeSent,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_packet_dropped(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::PacketDropped,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_key_update(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::KeyUpdate,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_key_space_discarded(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::KeySpaceDiscarded,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_connection_started(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::ConnectionStarted,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_connection_closed(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::ConnectionClosed,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_duplicate_packet(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::DuplicatePacket,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_transport_parameters_received(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::TransportParametersReceived,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_datagram_sent(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::DatagramSent,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_datagram_received(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::DatagramReceived,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_datagram_dropped(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::DatagramDropped,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_connection_id_updated(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::ConnectionIdUpdated,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_ecn_state_changed(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::EcnStateChanged,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_connection_migration_denied(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::ConnectionMigrationDenied,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_handshake_status_updated(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::HandshakeStatusUpdated,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_tls_exporter_ready(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::TlsExporterReady,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_path_challenge_updated(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::PathChallengeUpdated,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_tls_client_hello(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::TlsClientHello,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_tls_server_hello(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::TlsServerHello,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_rx_stream_progress(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::RxStreamProgress,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_tx_stream_progress(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::TxStreamProgress,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_keep_alive_timer_expired(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::KeepAliveTimerExpired,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_mtu_updated(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::MtuUpdated,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_slow_start_exited(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::SlowStartExited,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_delivery_rate_sampled(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::DeliveryRateSampled,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_pacing_rate_updated(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::PacingRateUpdated,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_bbr_state_changed(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &provider::event::events::BbrStateChanged,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }

    fn on_version_information(
        &mut self,
        meta: &provider::event::events::EndpointMeta,
        event: &provider::event::events::VersionInformation,
    ) {
        let _ = meta;
        let _ = event;
    }

    fn on_endpoint_packet_sent(
        &mut self,
        meta: &provider::event::events::EndpointMeta,
        event: &provider::event::events::EndpointPacketSent,
    ) {
        let _ = meta;
        let _ = event;
    }

    fn on_endpoint_packet_received(
        &mut self,
        meta: &provider::event::events::EndpointMeta,
        event: &provider::event::events::EndpointPacketReceived,
    ) {
        let _ = meta;
        let _ = event;
    }

    fn on_endpoint_datagram_sent(
        &mut self,
        meta: &provider::event::events::EndpointMeta,
        event: &provider::event::events::EndpointDatagramSent,
    ) {
        let _ = meta;
        let _ = event;
    }

    fn on_endpoint_datagram_received(
        &mut self,
        meta: &provider::event::events::EndpointMeta,
        event: &provider::event::events::EndpointDatagramReceived,
    ) {
        let _ = meta;
        let _ = event;
    }

    fn on_endpoint_datagram_dropped(
        &mut self,
        meta: &provider::event::events::EndpointMeta,
        event: &provider::event::events::EndpointDatagramDropped,
    ) {
        let _ = meta;
        let _ = event;
    }

    fn on_endpoint_connection_attempt_failed(
        &mut self,
        meta: &provider::event::events::EndpointMeta,
        event: &provider::event::events::EndpointConnectionAttemptFailed,
    ) {
        let _ = meta;
        let _ = event;
    }

    fn on_platform_tx(
        &mut self,
        meta: &provider::event::events::EndpointMeta,
        event: &provider::event::events::PlatformTx,
    ) {
        let _ = meta;
        let _ = event;
    }

    fn on_platform_tx_error(
        &mut self,
        meta: &provider::event::events::EndpointMeta,
        event: &provider::event::events::PlatformTxError,
    ) {
        let _ = meta;
        let _ = event;
    }

    fn on_platform_rx(
        &mut self,
        meta: &provider::event::events::EndpointMeta,
        event: &provider::event::events::PlatformRx,
    ) {
        let _ = meta;
        let _ = event;
    }

    fn on_platform_rx_error(
        &mut self,
        meta: &provider::event::events::EndpointMeta,
        event: &provider::event::events::PlatformRxError,
    ) {
        let _ = meta;
        let _ = event;
    }

    fn on_platform_feature_configured(
        &mut self,
        meta: &provider::event::events::EndpointMeta,
        event: &provider::event::events::PlatformFeatureConfigured,
    ) {
        let _ = meta;
        let _ = event;
    }

    fn on_platform_event_loop_wakeup(
        &mut self,
        meta: &provider::event::events::EndpointMeta,
        event: &provider::event::events::PlatformEventLoopWakeup,
    ) {
        let _ = meta;
        let _ = event;
    }

    fn on_platform_event_loop_sleep(
        &mut self,
        meta: &provider::event::events::EndpointMeta,
        event: &provider::event::events::PlatformEventLoopSleep,
    ) {
        let _ = meta;
        let _ = event;
    }

    fn on_event<M: Meta, E: provider::event::Event>(&mut self, meta: &M, event: &E) {
        let _ = meta;
        let _ = event;
    }

    fn on_connection_event<E: provider::event::Event>(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &E,
    ) {
        let _ = context;
        let _ = meta;
        let _ = event;
    }
}
