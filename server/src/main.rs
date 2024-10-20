use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use server::run_server;

const TRACING_FILTER: &str = "DEBUG";

const SERVER_HOST: &str = "0.0.0.0";
const SERVER_PORT: u16 = 9816;

/// Make sure this is the same on the prover side
const SESSION_ID: &str = "interactive-verifier";

#[tokio::main]
async fn main() -> Result<(), eyre::ErrReport> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| TRACING_FILTER.into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    run_server(
        SERVER_HOST,
        SERVER_PORT,
        SESSION_ID,
    )
    .await?;

    Ok(())
}