//! Pairing tests: two phase exchange between an in-process dest and source.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use renfield::client::{self, ExecArgs};
use renfield::error::RenfieldError;
use renfield::identity::Identity;
use renfield::pairing::{PairParams, Prompt, source_flow};
use renfield::server::{self, FilePolicy, ServerOptions};
use renfield::store::{Authorized, Entry, Registry};
use tempfile::TempDir;
use tokio::net::TcpListener;

/// A prompt that answers from a script and records every question.
struct Script {
    answers: Mutex<VecDeque<bool>>,
    texts: Mutex<Vec<String>>,
}

impl Script {
    fn new(answers: &[bool]) -> Arc<Script> {
        Arc::new(Script {
            answers: Mutex::new(answers.iter().copied().collect()),
            texts: Mutex::new(Vec::new()),
        })
    }
    fn asked(&self) -> Vec<String> {
        self.texts.lock().unwrap().clone()
    }
}

impl Prompt for Script {
    fn confirm(&self, text: &str) -> bool {
        self.texts.lock().unwrap().push(text.to_string());
        self.answers.lock().unwrap().pop_front().unwrap_or(false)
    }
}

/// A prompt that blocks until the test releases it.
struct Gated {
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<bool>>,
}

impl Prompt for Gated {
    fn confirm(&self, _text: &str) -> bool {
        let _ = self.entered.send(());
        self.release.lock().unwrap().recv().unwrap_or(false)
    }
}

/// A running dest with its directory, identity and address.
struct Dest {
    dir: TempDir,
    id: Identity,
    addr: SocketAddr,
    policy: Arc<FilePolicy>,
}

/// Starts a dest; `window_open` tells whether the pairing window starts open.
async fn start_dest(prompt: Option<Arc<dyn Prompt>>, window_open: bool) -> Dest {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::load_or_create(dir.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let policy = Arc::new(FilePolicy::new(dir.path()));
    policy.set_pairing(window_open);
    let opts = ServerOptions {
        prompt,
        ..ServerOptions::default()
    };
    tokio::spawn(server::serve(listener, id.clone(), policy.clone(), opts));
    Dest {
        dir,
        id,
        addr,
        policy,
    }
}

fn params(dir: &Path, addr: SocketAddr) -> PairParams {
    PairParams {
        dir: dir.to_path_buf(),
        name: "win".into(),
        addr: addr.to_string(),
        own_name: "laptop".into(),
        both: false,
        listen_port: None,
        force: false,
    }
}

fn new_source() -> (TempDir, Identity) {
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::load_or_create(dir.path()).unwrap();
    (dir, id)
}

fn authorized_len(dir: &Path) -> usize {
    Authorized::load(dir).unwrap().key.len()
}

#[tokio::test]
async fn pairing_accepted_both_sides_stores_keys() {
    let dest_prompt = Script::new(&[true]);
    let dest = start_dest(Some(dest_prompt.clone()), true).await;
    let (src_dir, src_id) = new_source();
    source_flow(params(src_dir.path(), dest.addr), Script::new(&[true]))
        .await
        .unwrap();
    assert!(
        Authorized::load(dest.dir.path())
            .unwrap()
            .contains(&src_id.fingerprint())
    );
    let reg = Registry::load(src_dir.path()).unwrap();
    assert_eq!(
        reg.get("win").unwrap().fingerprint,
        dest.id.fingerprint(),
        "source must pin dest's key"
    );
    // End to end: the new pairing really works.
    let mut conn = client::connect(src_dir.path(), "win").await.unwrap();
    let args = ExecArgs {
        command: "exit 5".into(),
        ..ExecArgs::default()
    };
    assert_eq!(conn.exec(args, |_, _| {}).await.unwrap().exit_code, Some(5));
}

#[tokio::test]
async fn prompt_text_shows_both_fingerprints_labelled() {
    let dest_prompt = Script::new(&[true]);
    let dest = start_dest(Some(dest_prompt.clone()), true).await;
    let (src_dir, src_id) = new_source();
    let src_prompt = Script::new(&[true]);
    source_flow(params(src_dir.path(), dest.addr), src_prompt.clone())
        .await
        .unwrap();
    let (d, s) = (dest.id.fingerprint(), src_id.fingerprint());
    for text in dest_prompt.asked().iter().chain(src_prompt.asked().iter()) {
        assert!(text.contains(&d) && text.contains(&s), "{text}");
        assert!(text.contains("This machine") && text.contains("Other machine"));
    }
    let on_dest = &dest_prompt.asked()[0];
    assert!(
        on_dest.contains(&format!("This machine's key:   {d}")),
        "{on_dest}"
    );
    assert!(
        on_dest.contains(&format!("Other machine's key:  {s}")),
        "{on_dest}"
    );
}

#[tokio::test]
async fn dest_rejects_nothing_stored() {
    let dest = start_dest(Some(Script::new(&[false])), true).await;
    let (src_dir, _) = new_source();
    let err = source_flow(params(src_dir.path(), dest.addr), Script::new(&[true]))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("rejected"), "{err}");
    assert_eq!(authorized_len(dest.dir.path()), 0);
    assert!(Registry::load(src_dir.path()).unwrap().machine.is_empty());
}

#[tokio::test]
async fn source_rejects_after_dest_accepts_rolls_back() {
    let dest = start_dest(Some(Script::new(&[true])), true).await;
    let (src_dir, _) = new_source();
    let err = source_flow(params(src_dir.path(), dest.addr), Script::new(&[false]))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("nothing was saved"), "{err}");
    assert_eq!(authorized_len(dest.dir.path()), 0);
    assert!(Registry::load(src_dir.path()).unwrap().machine.is_empty());
}

#[tokio::test]
async fn pairing_window_timeout_closes() {
    let dest = start_dest(Some(Script::new(&[true])), false).await;
    dest.policy.open_pairing_for(Duration::from_millis(200));
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (src_dir, _) = new_source();
    let err = source_flow(params(src_dir.path(), dest.addr), Script::new(&[true]))
        .await
        .unwrap_err();
    assert!(matches!(err, RenfieldError::NotAuthorized(_)), "{err:?}");
    assert_eq!(authorized_len(dest.dir.path()), 0);
}

#[tokio::test]
async fn second_concurrent_pairing_is_refused_with_pairing_in_progress() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let gated = Arc::new(Gated {
        entered: entered_tx,
        release: Mutex::new(release_rx),
    });
    let dest = start_dest(Some(gated), true).await;
    let (dir1, _) = new_source();
    let (dir2, _) = new_source();
    let first = tokio::spawn(source_flow(
        params(dir1.path(), dest.addr),
        Script::new(&[true]),
    ));
    tokio::task::spawn_blocking(move || entered_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let err = source_flow(params(dir2.path(), dest.addr), Script::new(&[true]))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("pairing in progress"), "{err}");
    release_tx.send(true).unwrap();
    first.await.unwrap().unwrap();
    assert_eq!(authorized_len(dest.dir.path()), 1);
}

#[tokio::test]
async fn duplicate_name_without_force_fails_before_prompting() {
    let dest_prompt = Script::new(&[true]);
    let dest = start_dest(Some(dest_prompt.clone()), true).await;
    let (src_dir, _) = new_source();
    let mut reg = Registry::default();
    reg.add(
        Entry {
            name: "win".into(),
            addr: "10.0.0.9:1".into(),
            fingerprint: "aa".repeat(32),
        },
        false,
    )
    .unwrap();
    reg.save(src_dir.path()).unwrap();
    let src_prompt = Script::new(&[true]);
    let err = source_flow(params(src_dir.path(), dest.addr), src_prompt.clone())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("already registered"), "{err}");
    assert!(dest_prompt.asked().is_empty() && src_prompt.asked().is_empty());
}

/// Starts the source machine's own listener, so it can be commanded in the reverse direction.
async fn start_listener_on(dir: &Path) -> SocketAddr {
    let id = Identity::load_or_create(dir).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let policy = Arc::new(FilePolicy::new(dir));
    tokio::spawn(server::serve(
        listener,
        id,
        policy,
        ServerOptions::default(),
    ));
    addr
}

#[tokio::test]
async fn both_makes_reverse_direction_work() {
    let dest = start_dest(Some(Script::new(&[true])), true).await;
    let (src_dir, src_id) = new_source();
    let src_addr = start_listener_on(src_dir.path()).await;
    let mut p = params(src_dir.path(), dest.addr);
    p.both = true;
    p.listen_port = Some(src_addr.port());
    source_flow(p, Script::new(&[true])).await.unwrap();
    let reg = Registry::load(dest.dir.path()).unwrap();
    let entry = reg
        .get("laptop")
        .expect("dest must know the source by name");
    assert_eq!(entry.addr, format!("127.0.0.1:{}", src_addr.port()));
    assert_eq!(entry.fingerprint, src_id.fingerprint());
    let mut conn = client::connect(dest.dir.path(), "laptop").await.unwrap();
    let args = ExecArgs {
        command: "echo back".into(),
        ..ExecArgs::default()
    };
    let mut out = Vec::new();
    conn.exec(args, |_, b| out.extend_from_slice(b))
        .await
        .unwrap();
    assert_eq!(out, b"back\n");
}

#[tokio::test]
async fn without_both_reverse_direction_is_refused() {
    let dest = start_dest(Some(Script::new(&[true])), true).await;
    let (src_dir, src_id) = new_source();
    let src_addr = start_listener_on(src_dir.path()).await;
    source_flow(params(src_dir.path(), dest.addr), Script::new(&[true]))
        .await
        .unwrap();
    assert!(Registry::load(dest.dir.path()).unwrap().machine.is_empty());
    assert_eq!(authorized_len(src_dir.path()), 0);
    let mut conn = client::connect_addr(
        &dest.id,
        "laptop",
        &src_addr.to_string(),
        Some(src_id.fingerprint()),
    )
    .await
    .unwrap();
    let args = ExecArgs {
        command: "true".into(),
        ..ExecArgs::default()
    };
    let err = conn.exec(args, |_, _| {}).await.unwrap_err();
    assert!(matches!(err, RenfieldError::NotAuthorized(_)), "{err:?}");
}

#[tokio::test]
async fn normal_mode_dest_rejects_unknown_key() {
    let dest = start_dest(Some(Script::new(&[true])), false).await;
    let (src_dir, src_id) = new_source();
    let mut conn = client::connect_addr(
        &src_id,
        "win",
        &dest.addr.to_string(),
        Some(dest.id.fingerprint()),
    )
    .await
    .unwrap();
    let args = ExecArgs {
        command: "true".into(),
        ..ExecArgs::default()
    };
    let err = conn.exec(args, |_, _| {}).await.unwrap_err();
    assert!(matches!(err, RenfieldError::NotAuthorized(_)), "{err:?}");
    assert_eq!(authorized_len(dest.dir.path()), 0);
    drop(src_dir);
}
