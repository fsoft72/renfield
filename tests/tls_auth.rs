//! Mutual TLS pinning tests over loopback.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use renfield::error::RenfieldError;
use renfield::identity::Identity;
use renfield::proto::{self, Frame, MAX_FRAME};
use renfield::tls::{self, PeerPolicy};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

struct Policy {
    allowed: Mutex<HashSet<String>>,
    pairing: AtomicBool,
}

impl PeerPolicy for Policy {
    fn is_authorized(&self, fp: &str) -> bool {
        self.allowed.lock().unwrap().contains(fp)
    }
    fn pairing_open(&self) -> bool {
        self.pairing.load(Ordering::SeqCst)
    }
}

fn ident() -> Identity {
    let dir = tempfile::tempdir().unwrap();
    Identity::load_or_create(dir.path()).unwrap()
}

fn policy(allowed: &[&str], pairing: bool) -> Arc<Policy> {
    Arc::new(Policy {
        allowed: Mutex::new(allowed.iter().map(|s| s.to_string()).collect()),
        pairing: AtomicBool::new(pairing),
    })
}

/// Starts an echo server: every JSON frame received is sent back.
async fn echo_server(id: &Identity, policy: Arc<Policy>) -> SocketAddr {
    let cfg = tls::server_config(id, policy).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = TlsAcceptor::from(cfg.clone());
            tokio::spawn(async move {
                let Ok(mut s) = acceptor.accept(tcp).await else {
                    return;
                };
                while let Ok(Some(v)) = proto::recv::<_, serde_json::Value>(&mut s).await {
                    if proto::send(&mut s, &v).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn authorized_client_connects_and_echoes_frame() {
    let (server, client) = (ident(), ident());
    let addr = echo_server(&server, policy(&[&client.fingerprint()], false)).await;
    let cfg = tls::client_config(&client, Some(server.fingerprint())).unwrap();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut s = TlsConnector::from(cfg)
        .connect(tls::server_name(), tcp)
        .await
        .unwrap();
    proto::send(&mut s, &serde_json::json!({"hello": 1}))
        .await
        .unwrap();
    let back: serde_json::Value = proto::recv(&mut s).await.unwrap().unwrap();
    assert_eq!(back, serde_json::json!({"hello": 1}));
    assert_eq!(
        tls::peer_fingerprint(s.get_ref().1),
        Some(server.fingerprint())
    );
}

#[tokio::test]
async fn unauthorized_client_is_rejected_with_not_authorized_error() {
    let (server, client) = (ident(), ident());
    let addr = echo_server(&server, policy(&[], false)).await;
    let cfg = tls::client_config(&client, Some(server.fingerprint())).unwrap();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let outcome = async {
        let mut s = TlsConnector::from(cfg)
            .connect(tls::server_name(), tcp)
            .await?;
        proto::send(&mut s, &serde_json::json!({"x": 1})).await?;
        proto::recv::<_, serde_json::Value>(&mut s).await
    }
    .await;
    let err = outcome.expect_err("an unauthorized client must not get an answer");
    assert!(
        matches!(
            tls::map_io_error("srv", &err),
            RenfieldError::NotAuthorized(_)
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn wrong_server_fingerprint_is_rejected_with_key_mismatch_error() {
    let (server, client) = (ident(), ident());
    let addr = echo_server(&server, policy(&[&client.fingerprint()], false)).await;
    let cfg = tls::client_config(&client, Some("00".repeat(32))).unwrap();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let err = TlsConnector::from(cfg)
        .connect(tls::server_name(), tcp)
        .await
        .expect_err("must fail");
    assert!(
        matches!(
            tls::map_io_error("srv", &err),
            RenfieldError::KeyMismatch(_)
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn unknown_client_allowed_when_pairing_open() {
    let (server, client) = (ident(), ident());
    let addr = echo_server(&server, policy(&[], true)).await;
    let cfg = tls::client_config(&client, None).unwrap();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut s = TlsConnector::from(cfg)
        .connect(tls::server_name(), tcp)
        .await
        .unwrap();
    proto::send(&mut s, &serde_json::json!(7)).await.unwrap();
    let back: serde_json::Value = proto::recv(&mut s).await.unwrap().unwrap();
    assert_eq!(back, serde_json::json!(7));
}

#[tokio::test]
async fn frame_roundtrip_json_and_data() {
    let (mut a, mut b) = tokio::io::duplex(1024);
    proto::write_frame(&mut a, &Frame::Json(b"{\"a\":1}".to_vec()))
        .await
        .unwrap();
    proto::write_frame(&mut a, &Frame::Data(vec![0, 1, 2, 255]))
        .await
        .unwrap();
    drop(a);
    assert_eq!(
        proto::read_frame(&mut b).await.unwrap(),
        Some(Frame::Json(b"{\"a\":1}".to_vec()))
    );
    assert_eq!(
        proto::read_frame(&mut b).await.unwrap(),
        Some(Frame::Data(vec![0, 1, 2, 255]))
    );
    assert_eq!(proto::read_frame(&mut b).await.unwrap(), None);
}

#[tokio::test]
async fn oversized_frame_is_rejected() {
    let (mut a, mut b) = tokio::io::duplex(1024);
    let header = ((MAX_FRAME + 1) as u32).to_be_bytes();
    tokio::io::AsyncWriteExt::write_all(&mut a, &header)
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut a, &[0u8])
        .await
        .unwrap();
    let err = proto::read_frame(&mut b).await.expect_err("must reject");
    assert!(err.to_string().contains("too large"), "{err}");
}
