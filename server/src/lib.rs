use std::str;
use axum::{
    extract::{Query, Request, State},
    response::IntoResponse,
    routing::get,
    routing::post,
    body::to_bytes,
    Router,
};
use chrono;
use std::fs;
use std::io::{Read, Write};
use axum_websocket::{WebSocket, WebSocketUpgrade};
use eyre::eyre;
use http_body_util;
use hyper;
use hyper::{body, server::conn::http1, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json;
use std::collections::HashMap;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tlsn_core::Direction;
use tlsn_prover::tls::{state::Prove, Prover, ProverConfig};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tower_service::Service;
use tracing::{debug, error, info};
use ws_stream_tungstenite::WsStream;

mod axum_websocket;

const OPENAI_API_KEY_FILE: &str = "/tmp/openai_api.key";

/// Global data that needs to be shared with the axum handlers
#[derive(Clone, Debug)]
struct VerifierGlobals {
    pub session_id: String,
}

pub async fn run_server(
    server_host: &str,
    server_port: u16,
    verification_session_id: &str,
) -> Result<(), eyre::ErrReport> {
    let server_address = SocketAddr::new(
        IpAddr::V4(server_host.parse().map_err(|err| {
            eyre!("Failed to parse verifer host address from server config: {err}")
        })?),
        server_port,
    );
    let listener = TcpListener::bind(server_address)
        .await
        .map_err(|err| eyre!("Failed to bind server address to tcp listener: {err}"))?;

    info!("Listening for TCP traffic at {}", server_address);

    let protocol = Arc::new(http1::Builder::new());
    let router = Router::new()
        .route("/completions", get(ws_handler))
        .route("/openai_key", post(openai_key_handler))
        .with_state(VerifierGlobals {
            session_id: verification_session_id.to_string(),
        });

    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(err) => {
                error!("Failed to connect to prover: {err}");
                continue;
            }
        };
        debug!("Received a verifyer TCP connection");

        let tower_service = router.clone();
        let protocol = protocol.clone();

        tokio::spawn(async move {
            info!("Accepted verifyer TCP connection",);
            // Reference: https://github.com/tokio-rs/axum/blob/5201798d4e4d4759c208ef83e30ce85820c07baa/examples/low-level-rustls/src/main.rs#L67-L80
            let io = TokioIo::new(stream);
            let hyper_service =
                hyper::service::service_fn(move |request: Request<body::Incoming>| {
                    tower_service.clone().call(request)
                });
            // Serve different requests using the same hyper protocol and axum router
            let _ = protocol
                .serve_connection(io, hyper_service)
                // use with_upgrades to upgrade connection to websocket for websocket clients
                // and to extract tcp connection for tcp clients
                .with_upgrades()
                .await;
        });
    }
}
async fn openai_key_handler(
    req: Request,
) -> impl IntoResponse {
    // Allow connection only form localhost

    let api_key = to_bytes(req.into_body(), 1024 * 1024)
        .await
        .map_err(|err| eyre!("Failed to read request body: {err}"))
        .unwrap();

    let mut file = fs::File::create(OPENAI_API_KEY_FILE).expect("Unable to create API key file");
    file.write_all(&api_key)
        .expect("Unable to write API key to file");

    debug!("Received OpenAI API key: {:?}", api_key);

    "OK".into_response()
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(verifier_globals): State<VerifierGlobals>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    info!("Received websocket request with params: {:?}", params);

    let model = params
        .get("model")
        .cloned()
        .unwrap_or_else(|| "gpt-3.5-turbo".to_string());
    let temperature = params
        .get("temperature")
        .cloned()
        .unwrap_or_else(|| "1.0".to_string());
    let content = params
        .get("content")
        .cloned()
        .unwrap_or_else(|| "".to_string());

    ws.on_upgrade(move |socket| {
        handle_socket(socket, verifier_globals, model, temperature, content)
    })
}

async fn handle_socket(
    socket: WebSocket,
    verifier_globals: VerifierGlobals,
    model: String,
    temperature: String,
    content: String,
) {
    debug!("Upgraded to websocket connection");
    let stream = WsStream::new(socket.into_inner());

    let id = &verifier_globals.session_id;

    if let Err(err) = prover(stream, id, &model, &temperature, &content).await {
        error!("Proving failed: {err}");
    } else {
        info!("Proving is successful!");
    }
}

async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    verifier_socket: T,
    id: &str,
    model: &str,
    temperature: &str,
    content: &str,
) -> Result<(), eyre::ErrReport> {
    debug!("Starting proving...");

    let server_domain = "api.openai.com";
    let server_port = 443;

    // Create prover and connect to verifier.
    let prover = Prover::new(
        ProverConfig::builder()
            .id(id)
            .server_dns(server_domain)
            .build()
            .unwrap(),
    )
    .setup(verifier_socket.compat())
    .await
    .unwrap();

    // Connect to TLS Server.
    info!("Connecting to OpenAI API Server");
    let tls_client_socket = tokio::net::TcpStream::connect((server_domain, server_port))
        .await
        .unwrap();
    let (mpc_tls_connection, prover_fut) =
        prover.connect(tls_client_socket.compat()).await.unwrap();
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());
    let prover_task = tokio::spawn(prover_fut);

    // MPC-TLS Handshake.
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection)
            .await
            .unwrap();

    tokio::spawn(connection);

    // MPC-TLS: Send Request and wait for Response.
    info!("Sending Request to OpenAI API and waiting for Response");

    // Build the OpenAI API request body
    let mut file = fs::File::open(OPENAI_API_KEY_FILE).expect("Unable to open API key file");
    let mut api_key = String::new();
    file.read_to_string(&mut api_key).expect("Unable to read API key file");
   
    let request_body = serde_json::json!({
        "model": model,
        "temperature": temperature.parse::<f32>().unwrap_or(1.0),
        "messages": [{"role": "user", "content": content}]
    });

    let request = Request::builder()
        .uri("https://api.openai.com/v1/chat/completions")
        .header("Host", server_domain)
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .header("Connection", "close")
        .method("POST")
        .body(http_body_util::Full::<body::Bytes>::from(
            request_body.to_string(),
        ))
        .unwrap();

    let response = request_sender.send_request(request).await.unwrap();

    debug!("OpenAI API response: {:?}", response);
    assert!(response.status() == StatusCode::OK);

    // Create proof for the Verifier.
    info!("Creating proof for the Verifier");
    let mut prover = prover_task.await.unwrap().unwrap().start_prove();
    redact_and_reveal_sent_data(&mut prover);
    redact_and_reveal_received_data(&mut prover);
    prover.prove().await.unwrap();

    // Finalize.
    info!("Finalizing prover");
    prover.finalize().await.unwrap();

    Ok(())
}


/// Redacts and reveals received data to the verifier.
fn redact_and_reveal_received_data(prover: &mut Prover<Prove>) {
    // Get the received data as bytes
    let data = prover.recv_transcript().data().to_vec();
    let data_len = data.len();

    // Find the end of the headers (\r\n\r\n)
    let header_end = data
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|pos| pos + 4)
        .unwrap_or(data_len);

    let headers_to_redact = vec!["set-cookie", "openai-organization"]; // Add headers to redact here

    let mut pos = 0;
    let mut reveal_start = 0;

    while pos < header_end {
        // Find the end of the current line (\r\n)
        let line_end = data[pos..header_end]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|pos_inner| pos + pos_inner)
            .unwrap_or(header_end);

        let line = &data[pos..line_end];

        // Check if the line contains a colon, indicating a header
        if let Some(colon_pos) = line.iter().position(|&b| b == b':') {
            // Extract the header name and convert it to lowercase
            let header_name_bytes = &line[0..colon_pos];
            let header_name = str::from_utf8(header_name_bytes)
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();

            if headers_to_redact.contains(&header_name.as_str()) {
                // Reveal data before the redacted header
                if reveal_start < pos {
                    _ = prover.reveal(reveal_start..pos, Direction::Received);
                }
                // Skip revealing this header
                reveal_start = line_end + 2; // Move past the header line
            }
        }

        pos = line_end + 2; // Move to the start of the next line
    }

    // Reveal any remaining data after the headers
    if reveal_start < data_len {
        _ = prover.reveal(reveal_start..data_len, Direction::Received);
    }
}

/// Redacts and reveals sent data to the verifier.
fn redact_and_reveal_sent_data(prover: &mut Prover<Prove>) {
    let sent_transcript_len = prover.sent_transcript().data().len();

    let sent_string = String::from_utf8(prover.sent_transcript().data().to_vec()).unwrap();
    debug!("Sent data: {}", sent_string);

    // Redact the Authorization header (API key)
    let secret_start = sent_string.find("authorization: Bearer").unwrap();
    let secret_end = sent_string[secret_start..].find("\r\n").unwrap() + secret_start;

    // Reveal everything except for the API key
    _ = prover.reveal(0..secret_start, Direction::Sent);
    _ = prover.reveal(secret_end..sent_transcript_len, Direction::Sent);
}
