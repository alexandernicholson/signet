//! Minimal HTTP health endpoints for Kubernetes probes.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n";
const NOT_READY: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 10\r\nConnection: close\r\n\r\nnot ready\n";
const NOT_FOUND: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 10\r\nConnection: close\r\n\r\nnot found\n";

/// Serves liveness and watch-initialization readiness until shutdown.
///
/// # Errors
///
/// Returns an I/O error when accepting a connection or serving a probe fails.
pub async fn serve<F>(
    listener: TcpListener,
    ready: Arc<AtomicBool>,
    shutdown: F,
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
                respond(stream, ready.load(Ordering::Acquire)).await?;
            }
        }
    }
}

async fn respond(mut stream: TcpStream, ready: bool) -> std::io::Result<()> {
    let mut request = [0_u8; 1024];
    let read = stream.read(&mut request).await?;
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
