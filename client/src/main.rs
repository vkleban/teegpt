use async_tungstenite::{tokio::client_async_with_config, tungstenite::protocol::WebSocketConfig};
use remote_attestation_verifier::parse_verify_with;
use eyre::eyre;
use std::io::Write;
use hex;
use rand::Rng;
use base64::{engine::general_purpose::STANDARD, Engine};
use rustls_pki_types::ServerName;
use rustls_pki_types::TrustAnchor;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tlsn_verifier::tls::{Verifier, VerifierConfig};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{debug, error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use urlencoding;
use webpki_roots;
use ws_stream_tungstenite::WsStream;
use serde_json::{json, Value};

const TRACING_FILTER: &str = "DEBUG";

const SERVER_HOST: &'static str = "tlsnotary.hosts.name";
const SERVER_PORT: u16 = 443;

/// Make sure this is the same on the verifier side
const VERIFICATION_SESSION_ID: &str = "interactive-verifier";

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| TRACING_FILTER.into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let mut messages = Vec::new();

    loop {
        print!("You: ");
        std::io::stdout().flush().unwrap(); 
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        let input = input.trim();
        if input.eq_ignore_ascii_case("exit") {
            break;
        }

        // Append user's message to the conversation history
        messages.push(json!({"role": "user", "content": input}));

        match run_verifier(SERVER_HOST, SERVER_PORT, VERIFICATION_SESSION_ID, &messages).await {
            Ok(received) => {
                // get body from response devide by \r\n\r\n{
                let body = received.split("\r\n\r\n").last().unwrap();
                // Parse the received data as JSON
                let json_response: Value = serde_json::from_str(&body).unwrap();
                // Extract the content
                debug!("Received JSON: {}", json_response);
                let content = json_response["choices"][0]["message"]["content"].as_str().unwrap();

                println!("AI: {}", content);
                // Append AI's response to the conversation history
                messages.push(json!({"role": "ai", "content": content}));
            },
            Err(err) => eprintln!("Verfication error: {}", err),
        }
    }
}

fn generate_nonce() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 20] = rng.gen();
    hex::encode(bytes)
}

async fn perform_attestation(
    tls_stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
) -> Result<(), eyre::ErrReport> {
    use std::collections::HashMap;

    info!("Performing attestation...");

    // Send HTTP GET request using HTTP/1.1 and no Connection header
    let nonce = generate_nonce();
    let request = format!(
        "GET /enclave/attestation?nonce={} HTTP/1.1\r\nHost: {}\r\n\r\n",
        nonce, SERVER_HOST
    );

    tls_stream.write_all(request.as_bytes()).await?;
    info!("Sent HTTP request for attestation.");

    // Read headers until "\r\n\r\n" is found
    let mut headers = Vec::new();
    let mut buf = [0u8; 1];
    let mut headers_end = false;

    while !headers_end {
        let n = tls_stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        headers.push(buf[0]);

        if headers.len() >= 4 && &headers[headers.len() - 4..] == b"\r\n\r\n" {
            headers_end = true;
        }
    }

    let headers_str = String::from_utf8_lossy(&headers);
    //info!("Received headers: {}", headers_str);

    // Parse headers into a HashMap
    let mut headers_map = HashMap::new();
    for line in headers_str.lines().skip(1) { // Skip the status line
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(": ") {
            headers_map.insert(key.to_lowercase(), value.to_string());
        }
    }

    // Determine how to read the body
    let mut body = Vec::new();
    if let Some(content_length) = headers_map.get("content-length") {
        // Read exact number of bytes
        let content_length: usize = content_length.parse()?;
        let mut buf = vec![0u8; content_length];
        tls_stream.read_exact(&mut buf).await?;
        body.extend_from_slice(&buf);
    } else if let Some(transfer_encoding) = headers_map.get("transfer-encoding") {
        if transfer_encoding.eq_ignore_ascii_case("chunked") {
            // Read chunked encoding
            loop {
                // Read chunk size line
                let mut chunk_size_line = Vec::new();
                loop {
                    let n = tls_stream.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    chunk_size_line.push(buf[0]);
                    if chunk_size_line.len() >= 2 && &chunk_size_line[chunk_size_line.len() - 2..] == b"\r\n" {
                        break;
                    }
                }
                let chunk_size_str = String::from_utf8_lossy(&chunk_size_line);
                let chunk_size = usize::from_str_radix(chunk_size_str.trim_end().trim_end_matches("\r\n"), 16)?;
                if chunk_size == 0 {
                    // Read and discard the trailing "\r\n"
                    let mut trailing = [0u8; 2];
                    tls_stream.read_exact(&mut trailing).await?;
                    break;
                }
                // Read chunk data
                let mut chunk_data = vec![0u8; chunk_size];
                tls_stream.read_exact(&mut chunk_data).await?;
                body.extend_from_slice(&chunk_data);
                // Read and discard the trailing "\r\n"
                let mut trailing = [0u8; 2];
                tls_stream.read_exact(&mut trailing).await?;
            }
        } else {
            return Err(eyre!("Unsupported transfer encoding"));
        }
    } else {
        // No Content-Length or Transfer-Encoding, read until EOF
        let mut buf = [0u8; 1024];
        loop {
            let n = tls_stream.read(&mut buf).await?;
            if n == 0 {
                break; // EOF reached
            }
            body.extend_from_slice(&buf[..n]);
        }
    }

    let body_str = String::from_utf8_lossy(&body.trim_ascii_end());
    //info!("Received body: {}", body_str);

    // get current unix time
    let unix_time= chrono::Utc::now().timestamp();
    let mut pcrs = vec![vec![0; 48]; 16];

    // pcr2 = 366e4e622db5f087dcdea544bc817785e171be53f6b7d646f6f25ccdfcee131940cb3edcbefe93b1df617befe8b126c6 
    pcrs.insert(
        2,
        vec![
            0x36, 0x6e, 0x4e, 0x62, 0x2d, 0xb5, 0xf0, 0x87, 0xdc, 0xde, 0xa5, 0x44, 0xbc, 0x81, 0x77, 0x85,
            0xe1, 0x71, 0xbe, 0x53, 0xf6, 0xb7, 0xd6, 0x46, 0xf6, 0xf2, 0x5c, 0xcd, 0xfc, 0xee, 0x13, 0x19,
            0x40, 0xcb, 0x3e, 0xdc, 0xbe, 0xfe, 0x93, 0xb1, 0xdf, 0x61, 0x7b, 0xef, 0xe8, 0xb1, 0x26, 0xc6,
        ]
        .to_vec(),
    );

    //debug!("Verifying attestation response...: {:?}", body_str.as_bytes());
    let document_data  = STANDARD.decode(body_str.as_bytes())
        .expect("Failed to decode base64 data");

    // convert nonce to vec<u8>
    let nonce = hex::decode(nonce).unwrap();

    match parse_verify_with(document_data, nonce, pcrs, unix_time as u64) {
        Ok(_) => (),
        Err(e) => panic!("parse_verify_with failed: {:?}", e.to_string()),
    }

    info!("Attestation response verified successfully.");

    Ok(())
}

async fn verifier<T: AsyncWrite + AsyncReadExt + Send + Unpin + 'static>(
    socket: T,
    verification_session_id: &str,
) -> Result<String, eyre::ErrReport> {
    debug!("Starting verification...");

    // Setup Verifier.
    let verifier_config = VerifierConfig::builder()
        .id(verification_session_id)
        .build()?;
    let verifier = Verifier::new(verifier_config);

    // Verify MPC-TLS and wait for (redacted) data.
    debug!("Starting MPC-TLS verification...");
    let (sent, received, session_info) = verifier
        .verify(socket.compat())
        .await
        .map_err(|err| eyre!("Verification failed: {err}"))?;

    // Check sent data: check host and path.
    debug!("Starting sent data verification...");
    let sent_data = String::from_utf8(sent.data().to_vec())
        .map_err(|err| eyre!("Failed to parse sent data: {err}"))?;
    debug!("Sent data: {}", sent_data);

    sent_data
        .find("api.openai.com")
        .ok_or_else(|| eyre!("Verification failed: Expected host api.openai.com"))?;

    sent_data
        .find("/v1/chat/completions")
        .ok_or_else(|| eyre!("Verification failed: Expected path /v1/chat/completions"))?;

    // Check received data: check for expected JSON structure.
    debug!("Starting received data verification...");
    let response = String::from_utf8(received.data().to_vec())
        .map_err(|err| eyre!("Failed to parse received data: {err}"))?;
    debug!("Received data: {:?}", response);

    // Verify that the response contains expected fields
    response
        .find("\"choices\"")
        .ok_or_else(|| eyre!("Verification failed: missing 'choices' in received data"))?;

    // Parse the received data as JSON
    // Find \r\n\r\n in response to extract the JSON part
    let response = response
        .split("\r\n\r\n")
        .last()
        .ok_or_else(|| eyre!("Failed to extract JSON response"))?;

    let json_response: Value = serde_json::from_str(&response)
        .map_err(|err| eyre!("Failed to parse JSON response: {err}"))?;

    // Extract the content
    if let Some(content) = json_response["choices"][0]["message"]["content"].as_str() {
        println!("Response: {}", content);
    } else {
        return Err(eyre!("Failed to extract response content"));
    }

    // Check Session info: server name.
    if session_info.server_name.as_str() != "api.openai.com" {
        return Err(eyre!(
            "Verification failed: server name mismatches (expected api.openai.com)"
        ));
    }

    let sent_string = bytes_to_redacted_string(sent.data())?;
    let received_string = bytes_to_redacted_string(received.data())?;

    info!("Verification successful!");
    info!("Verified sent data:\n{}", sent_string);
    info!("Verified received data:\n{}", received_string);

    Ok(received_string)
}

async fn get_tls_fingerprint(
    tls_stream: &tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
) -> Option<String> {
    let certificates = tls_stream.get_ref().1.peer_certificates().unwrap();
    let cert = certificates.get(0).unwrap();
    let fingerprint = Sha256::digest(cert.as_ref());
    let fingerprint_hex = hex::encode(fingerprint);
    Some(fingerprint_hex)
}

async fn run_verifier(
    server_host: &'static str,
    server_port: u16,
    verification_session_id: &str,
    messages: &Vec<Value>,
) -> Result<String, eyre::ErrReport> {
    // Establish a TCP connection to the server.
    let addr = format!("{}:{}", server_host, server_port);
    let tcp_stream = TcpStream::connect(&addr).await.unwrap();

    // Set up TLS configuration.
    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| TrustAnchor {
        subject: ta.subject.clone(),
        subject_public_key_info: ta.subject_public_key_info.clone(),
        name_constraints: ta.name_constraints.clone(),
    }));

    let config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    // Establish a TLS connection.
    let tls_connector = TlsConnector::from(Arc::new(config));

    let domain = ServerName::try_from(server_host).map_err(|_| eyre!("Invalid server name"))?;

    let mut tls_stream = tls_connector.connect(domain, tcp_stream).await?;

    info!("TLS connection established.");

    // Get TLS certificate fingerprint.
    let fingerprint_hex = get_tls_fingerprint(&tls_stream).await.unwrap();
    info!(
        "TLS certificate fingerprint (SHA-256): {}",
        &fingerprint_hex
    );

    // Send an HTTP GET request to the attestation enclave using the endpoint `/enclave/attestation?nonce=xxxx` and retrieve the response text.
    debug!("Sending attestation request...");
    // Call the separate function to perform attestation
    perform_attestation(&mut tls_stream).await?;

    info!("Sending websocket request...");

    // Define the query parameters
    let model = "gpt-3.5-turbo";
    let temperature = "1.0";
    // Serialize the messages to JSON
    let messages_json = serde_json::to_string(messages)
        .map_err(|err| eyre!("Failed to serialize messages: {err}"))?;


    let query = format!(
        "?model={}&temperature={}&content={}",
        urlencoding::encode(model),
        urlencoding::encode(temperature),
        urlencoding::encode(&messages_json)
    );

    let ws_request = http::Request::builder()
        .uri(format!(
            "wss://{}:{}/completions{}",
            server_host, server_port, query
        ))
        .header("Host", server_host)
        .header("Sec-WebSocket-Key", uuid::Uuid::new_v4().to_string())
        .header("Sec-WebSocket-Version", "13")
        .header("Connection", "Upgrade")
        .header("Upgrade", "Websocket")
        .body(())
        .unwrap();

    // Use client_async_with_config to perform the WebSocket handshake over the existing TLS stream
    let (prover_ws_stream, _) =
        client_async_with_config(ws_request, tls_stream, Some(WebSocketConfig::default())).await?;

    info!("Websocket connection established!");
    let prover_ws_socket = WsStream::new(prover_ws_stream);

    match verifier(prover_ws_socket, verification_session_id).await {
        Ok(received) => {
            info!("Verification successful!");
            Ok(received)
        },
        Err(err) => {
            error!("Verification failed: {err}");
            Err(err)
        }
    }


}

fn bytes_to_redacted_string(bytes: &[u8]) -> Result<String, eyre::ErrReport> {
    Ok(String::from_utf8(bytes.to_vec())
        .map_err(|err| eyre!("Failed to parse bytes to redacted string: {err}"))?
        .replace('\0', "🙈"))
}
