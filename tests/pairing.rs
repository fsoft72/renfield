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

#[tokio::test]
async fn hostile_source_name_is_refused_before_any_prompt() {
    let dest_prompt = Script::new(&[true]);
    let dest = start_dest(Some(dest_prompt.clone()), true).await;
    let (src_dir, src_id) = new_source();
    let mut conn = client::connect_addr(&src_id, "x", &dest.addr.to_string(), None)
        .await
        .unwrap();
    let hostile =
        "laptop\n  This machine's key:   aa\n  Other machine's key:  bb\n\u{1b}[2J".to_string();
    conn.send_request(&renfield::proto::Request::PairOffer {
        source_name: hostile,
        both: true,
        source_listen_port: None,
    })
    .await
    .unwrap();
    let answer = conn.recv_response().await.unwrap();
    assert!(format!("{answer:?}").contains("invalid"), "{answer:?}");
    assert!(
        dest_prompt.asked().is_empty(),
        "the human must never see a hostile name"
    );
    assert_eq!(authorized_len(dest.dir.path()), 0);
    // The refusal must not burn the pairing window: a legitimate source still pairs.
    source_flow(params(src_dir.path(), dest.addr), Script::new(&[true]))
        .await
        .unwrap();
    assert_eq!(authorized_len(dest.dir.path()), 1);
}

#[test]
fn clean_name_keeps_safe_names_and_neutralises_the_rest() {
    use renfield::pairing::{clean_name, is_valid_name};
    assert_eq!(clean_name("fabio-office.local"), "fabio-office.local");
    assert_eq!(clean_name("my laptop\n\u{1b}[2J"), "my-laptop---2J");
    assert_eq!(clean_name(&"x".repeat(200)).len(), 64);
    assert_eq!(clean_name(""), "renfield-host");
    assert!(is_valid_name("srv_1.test"));
    assert!(!is_valid_name("a b"));
    assert!(!is_valid_name("a\nb"));
    assert!(!is_valid_name(""));
    assert!(!is_valid_name(&"x".repeat(65)));
}

#[tokio::test]
async fn unknown_key_cannot_exec_while_the_pairing_window_is_open() {
    let dest = start_dest(Some(Script::new(&[true])), true).await;
    let (_dir, id) = new_source();
    let mut conn = client::connect_addr(
        &id,
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
    assert_eq!(err.exit_code(), 202);
}

#[tokio::test]
async fn prompts_say_when_both_directions_are_granted() {
    let dest_prompt = Script::new(&[true, true]);
    let dest = start_dest(Some(dest_prompt.clone()), true).await;
    let (src_dir, _) = new_source();
    let src_prompt = Script::new(&[true]);
    let mut p = params(src_dir.path(), dest.addr);
    p.both = true;
    p.listen_port = Some(4242);
    source_flow(p, src_prompt.clone()).await.unwrap();
    let on_dest = &dest_prompt.asked()[0];
    assert!(
        on_dest.contains("--both") && on_dest.contains("will also be able to command 'laptop'"),
        "{on_dest}"
    );
    let on_source = &src_prompt.asked()[0];
    assert!(
        on_source.contains("--both")
            && on_source.contains("'win' will also be able to command this machine"),
        "{on_source}"
    );

    // A plain pairing mentions nothing of the kind.
    let dest2_prompt = Script::new(&[true]);
    let dest2 = start_dest(Some(dest2_prompt.clone()), true).await;
    let (src2_dir, _) = new_source();
    let src2_prompt = Script::new(&[true]);
    source_flow(params(src2_dir.path(), dest2.addr), src2_prompt.clone())
        .await
        .unwrap();
    assert!(!dest2_prompt.asked()[0].contains("--both"));
    assert!(!src2_prompt.asked()[0].contains("--both"));
}

#[cfg(target_os = "linux")]
#[test]
fn os_hostname_matches_the_kernel_hostname() {
    let kernel = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap();
    assert_eq!(
        renfield::pairing::os_hostname().as_deref(),
        Some(kernel.trim())
    );
}

#[test]
fn local_name_is_always_a_valid_pairing_name() {
    assert!(renfield::pairing::is_valid_name(
        &renfield::pairing::local_name()
    ));
}

#[tokio::test]
async fn peer_vanishing_during_the_prompt_frees_the_slot_and_keeps_the_window_open() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let gated = Arc::new(Gated {
        entered: entered_tx,
        release: Mutex::new(release_rx),
    });
    let dest = start_dest(Some(gated), true).await;
    let (_dir, id) = new_source();
    let mut conn = client::connect_addr(&id, "x", &dest.addr.to_string(), None)
        .await
        .unwrap();
    conn.send_request(&renfield::proto::Request::PairOffer {
        source_name: "laptop".into(),
        both: false,
        source_listen_port: None,
    })
    .await
    .unwrap();
    tokio::task::spawn_blocking(move || entered_rx.recv())
        .await
        .unwrap()
        .unwrap();
    drop(conn);
    // The human has not answered yet, but the source is gone: a legitimate source must be able to retry.
    let mut freed = false;
    for _ in 0..30 {
        if dest.policy.try_begin_pairing() {
            freed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    release_tx.send(false).ok();
    assert!(
        freed,
        "the pairing slot stayed taken by a prompt nobody is waiting for"
    );
}
