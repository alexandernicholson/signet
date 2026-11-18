//! Minimal HTTP health endpoints for Kubernetes probes.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

/// Upper bound on one probe exchange; matches the manifest's `timeoutSeconds`.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(2);

const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n";
const NOT_READY: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 10\r\nConnection: close\r\n\r\nnot ready\n";
const NOT_FOUND: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 10\r\nConnection: close\r\n\r\nnot found\n";

/// Serves liveness and watch-initialization readiness until shutdown.
///
/// Each connection is handled in its own task and bounded by a short deadline,
/// so an idle or slow client cannot block other probes.
///
/// # Errors
///
/// Returns an I/O error when accepting a connection fails.
pub async fn serve<F>(
    listener: TcpListener,
    ready: Arc<AtomicBool>,
    shutdown: F,
) -> std::io::Result<()>
where
    F: Future<Output = ()>,
{
    serve_with_timeout(listener, ready, shutdown, EXCHANGE_TIMEOUT).await
}

/// Like [`serve`] with an explicit per-connection deadline.
///
/// # Errors
///
/// Returns an I/O error when accepting a connection fails.
pub async fn serve_with_timeout<F>(
    listener: TcpListener,
    ready: Arc<AtomicBool>,
    shutdown: F,
    exchange_timeout: Duration,
) -> std::io::Result<()>
where
    F: Future<Output = ()>,
{
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => return Ok(()),
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let ready = ready.load(Ordering::Acquire);
                tokio::spawn(async move {
                    // Per-connection failures and timeouts only drop that connection.
                    let _ = tokio::time::timeout(exchange_timeout, respond(stream, ready)).await;
                });
            }
        }
    }
}

async fn respond(mut stream: TcpStream, ready: bool) -> std::io::Result<()> {
    let mut request = [0_u8; 1024];
    let mut read = 0;
    // A probe may arrive in several segments; decide only on complete headers.
    loop {
        let received = stream.read(&mut request[read..]).await?;
        read += received;
        if received == 0 || read == request.len() || request[..read].ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let response = if request[..read].starts_with(b"GET /healthz ") {
        OK
    } else if request[..read].starts_with(b"GET /readyz ") {
        if ready { OK } else { NOT_READY }
    } else {
        NOT_FOUND
    };
    stream.write_all(response).await?;
    stream.shutdown().await
}
