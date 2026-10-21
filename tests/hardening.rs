//! Resilience against silent, vanishing and misbehaving peers.

mod common;

use std::time::Duration;

use renfield::client;
use renfield::proto::Request;
use renfield::server::ServerOptions;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

fn short_timeout() -> ServerOptions {
    ServerOptions {
        first_contact_timeout: Some(Duration::from_millis(300)),
        ..ServerOptions::default()
    }
}

fn running(pattern: &str) -> bool {
    let out = std::process::Command::new("pgrep")
        .args(["-f", pattern])
        .output()
        .unwrap();
    !out.stdout.is_empty()
}

#[tokio::test]
async fn silent_tcp_connection_is_dropped_after_the_handshake_timeout() {
    let env = common::start_with(short_timeout()).await;
    let mut tcp = TcpStream::connect(env.addr).await.unwrap();
    let mut buf = [0u8; 16];
    let outcome = timeout(Duration::from_secs(3), tcp.read(&mut buf)).await;
    assert!(outcome.is_ok(), "the server kept a silent connection open");
}

#[tokio::test]
async fn silent_authenticated_connection_is_dropped_after_the_request_timeout() {
    let env = common::start_with(short_timeout()).await;
    let mut conn = client::connect(env.client_dir.path(), "srv").await.unwrap();
    let outcome = timeout(Duration::from_secs(3), conn.recv_response()).await;
    assert!(
        outcome.is_ok(),
        "the server waited forever for a first request"
    );
}

#[tokio::test]
async fn source_disconnect_kills_the_running_command() {
    let env = common::start().await;
    let mut conn = client::connect(env.client_dir.path(), "srv").await.unwrap();
    conn.send_request(&Request::Exec {
        command: "sleep 41; true".into(),
        args: Vec::new(),
        shell: None,
        cwd: None,
        timeout_secs: None,
    })
    .await
    .unwrap();
    sleep(Duration::from_millis(600)).await;
    assert!(
        running("sleep 41"),
        "the command should be running before the disconnect"
    );
    drop(conn);
    for _ in 0..100 {
        if !running("sleep 41") {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("the command kept running after the source disconnected");
}

#[tokio::test]
async fn connection_dropped_before_any_answer_is_reported_as_not_authorized() {
    use renfield::error::RenfieldError;
    use renfield::identity::Identity;
    use renfield::server::FilePolicy;
    use renfield::tls;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    // A dest that completes the handshake and then hangs up, as a rejecting dest does when the
    // client sends its request after the connection was already closed.
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::load_or_create(dir.path()).unwrap();
    let policy = std::sync::Arc::new(FilePolicy::new(dir.path()));
    policy.set_pairing(true);
    let acceptor = TlsAcceptor::from(tls::server_config(&id, policy).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            drop(acceptor.accept(tcp).await);
        }
    });

    let client_dir = tempfile::tempdir().unwrap();
    let client_id = Identity::load_or_create(client_dir.path()).unwrap();
    let mut conn =
        client::connect_addr(&client_id, "srv", &addr.to_string(), Some(id.fingerprint()))
            .await
            .unwrap();
    let outcome = async {
        conn.send_request(&Request::Exec {
            command: "true".into(),
            args: Vec::new(),
            shell: None,
            cwd: None,
            timeout_secs: None,
        })
        .await?;
        conn.recv_response().await
    }
    .await;
    let err = outcome.expect_err("a closed connection cannot answer");
    assert!(matches!(err, RenfieldError::NotAuthorized(_)), "{err:?}");
}
