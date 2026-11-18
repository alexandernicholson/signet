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
#[ntest_timeout::timeout(2_000)]
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

#[tokio::test]
#[ntest_timeout::timeout(2_000)]
async fn idle_connections_neither_block_probes_nor_outlive_the_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind health server");
    let address = listener.local_addr().expect("listener address");
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(health::serve_with_timeout(
        listener,
        Arc::new(AtomicBool::new(true)),
        async {
            let _ = stopped.await;
        },
        std::time::Duration::from_millis(200),
    ));

    let mut idle = TcpStream::connect(address).await.expect("connect idle");
    assert!(
        request(address, "/healthz")
            .await
            .starts_with("HTTP/1.1 200")
    );

    let mut remainder = Vec::new();
    idle.read_to_end(&mut remainder)
        .await
        .expect("server closes idle connection at its deadline");
    assert_eq!(remainder, [] as [u8; 0]);
    assert!(
        request(address, "/readyz")
            .await
            .starts_with("HTTP/1.1 200")
    );

    shutdown.send(()).expect("stop health server");
    task.await.expect("server task").expect("graceful shutdown");
}

#[tokio::test]
#[ntest_timeout::timeout(2_000)]
async fn probes_split_across_segments_are_answered_from_the_full_request() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind health server");
    let address = listener.local_addr().expect("listener address");
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(health::serve(
        listener,
        Arc::new(AtomicBool::new(true)),
        async {
            let _ = stopped.await;
        },
    ));

    let mut stream = TcpStream::connect(address).await.expect("connect");
    stream.set_nodelay(true).expect("disable Nagle");
    stream.write_all(b"GET /hea").await.expect("first segment");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    stream
        .write_all(b"lthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("second segment");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .expect("read response");
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");

    shutdown.send(()).expect("stop health server");
    task.await.expect("server task").expect("graceful shutdown");
}
