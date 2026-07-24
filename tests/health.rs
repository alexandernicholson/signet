#![allow(clippy::expect_used)]

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use signet::health;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

async fn request(address: std::net::SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(address)
        .await
        .expect("connect health server");
    stream
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
        .await
        .expect("write request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .expect("read response");
    response
}

#[tokio::test]
async fn liveness_is_immediate_and_readiness_tracks_watch_initialization() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind health server");
    let address = listener.local_addr().expect("listener address");
    let ready = Arc::new(AtomicBool::new(false));
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(health::serve(listener, Arc::clone(&ready), async {
        let _ = stopped.await;
    }));

    assert!(
        request(address, "/healthz")
            .await
            .starts_with("HTTP/1.1 200")
    );
    assert!(
        request(address, "/readyz")
            .await
            .starts_with("HTTP/1.1 503")
    );
    ready.store(true, Ordering::Release);
    assert!(
        request(address, "/readyz")
            .await
            .starts_with("HTTP/1.1 200")
    );
    assert!(request(address, "/other").await.starts_with("HTTP/1.1 404"));

    shutdown.send(()).expect("stop health server");
    task.await.expect("server task").expect("graceful shutdown");
}
