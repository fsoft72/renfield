//! Shared helpers: an in-process dest and a paired client configuration.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use renfield::identity::Identity;
use renfield::server::{self, FilePolicy, ServerOptions};
use renfield::store::{Authorized, Entry, Registry};
use tempfile::TempDir;
use tokio::net::TcpListener;

/// A running dest plus the directories of both sides.
pub struct Env {
    pub client_dir: TempDir,
    pub server_dir: TempDir,
    pub addr: SocketAddr,
    pub policy: Arc<FilePolicy>,
}

/// Starts a dest on loopback that already authorizes the client; the client registry knows it as "srv".
pub async fn start() -> Env {
    start_with(ServerOptions::default()).await
}

/// Same as [`start`] with explicit server options.
pub async fn start_with(opts: ServerOptions) -> Env {
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();
    let sid = Identity::load_or_create(server_dir.path()).unwrap();
    let cid = Identity::load_or_create(client_dir.path()).unwrap();
    let mut auth = Authorized::default();
    auth.add(&cid.fingerprint(), "client");
    auth.save(server_dir.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut reg = Registry::default();
    reg.add(
        Entry {
            name: "srv".into(),
            addr: addr.to_string(),
            fingerprint: sid.fingerprint(),
        },
        false,
    )
    .unwrap();
    reg.save(client_dir.path()).unwrap();
    let policy = Arc::new(FilePolicy::new(server_dir.path()));
    tokio::spawn(server::serve(listener, sid, policy.clone(), opts));
    Env {
        client_dir,
        server_dir,
        addr,
        policy,
    }
}
