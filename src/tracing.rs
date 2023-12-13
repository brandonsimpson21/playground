use tracing_opentelemetry;
use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt};
use tracing_subscriber::EnvFilter;
use opentelemetry::trace::{Tracer, TracerProvider as _};

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("playground"));
    let fmt_layer = tracing_subscriber::fmt::layer();
    let subscriber = tracing_subscriber::Registry::default().with(filter).with(fmt_layer);
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}