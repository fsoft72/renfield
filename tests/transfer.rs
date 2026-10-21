//! Single file transfer tests.

mod common;

use std::path::Path;

use renfield::client;
use renfield::proto::{self, Frame, TransferTrailer};
use renfield::transfer::{Incoming, TransferError};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

/// Writes `len` pseudo random bytes to a file.
fn write_random(path: &Path, len: usize) {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut data = Vec::with_capacity(len);
    while data.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        data.extend_from_slice(&state.to_le_bytes());
    }
    data.truncate(len);
    std::fs::write(path, data).unwrap();
}

fn sha_of(path: &Path) -> String {
    hex::encode(Sha256::digest(std::fs::read(path).unwrap()))
}

fn no_progress() -> impl FnMut(u64, u64) {
    |_, _| {}
}

#[tokio::test]
async fn put_then_get_roundtrip_is_identical() {
    let env = common::start().await;
    let work = tempfile::tempdir().unwrap();
    let (src, remote, back) = (
        work.path().join("src.bin"),
        work.path().join("remote.bin"),
        work.path().join("back.bin"),
    );
    let size = 50 * 1024 * 1024;
    write_random(&src, size);
    let mut conn = client::connect(env.client_dir.path(), "srv").await.unwrap();
    let mut last = (0, 0);
    let sent = conn
        .put_file(&src, &remote.to_string_lossy(), &mut |d, t| last = (d, t))
        .await
        .unwrap();
    assert_eq!(sent, size as u64);
    assert_eq!(last, (size as u64, size as u64));
    assert_eq!(sha_of(&src), sha_of(&remote));
    let got = conn
        .get_file(&remote.to_string_lossy(), &back, &mut no_progress())
        .await
        .unwrap();
    assert_eq!(got, size as u64);
    assert_eq!(sha_of(&src), sha_of(&back));
}

#[tokio::test]
async fn zero_byte_file() {
    let env = common::start().await;
    let work = tempfile::tempdir().unwrap();
    let (src, remote, back) = (
        work.path().join("e"),
        work.path().join("r"),
        work.path().join("b"),
    );
    std::fs::write(&src, b"").unwrap();
    let mut conn = client::connect(env.client_dir.path(), "srv").await.unwrap();
    assert_eq!(
        conn.put_file(&src, &remote.to_string_lossy(), &mut no_progress())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        conn.get_file(&remote.to_string_lossy(), &back, &mut no_progress())
            .await
            .unwrap(),
        0
    );
    assert!(back.exists() && std::fs::metadata(&back).unwrap().len() == 0);
}

#[tokio::test]
async fn filename_with_spaces_and_unicode() {
    let env = common::start().await;
    let work = tempfile::tempdir().unwrap();
    let src = work.path().join("caffè è.bin");
    write_random(&src, 70_000);
    let remote = work.path().join("dir x/nuovo caffè.bin");
    let back = work.path().join("indietro è.bin");
    let mut conn = client::connect(env.client_dir.path(), "srv").await.unwrap();
    conn.put_file(&src, &remote.to_string_lossy(), &mut no_progress())
        .await
        .unwrap();
    conn.get_file(&remote.to_string_lossy(), &back, &mut no_progress())
        .await
        .unwrap();
    assert_eq!(sha_of(&src), sha_of(&back));
}

#[tokio::test]
async fn get_missing_file_gives_clear_error() {
    let env = common::start().await;
    let work = tempfile::tempdir().unwrap();
    let mut conn = client::connect(env.client_dir.path(), "srv").await.unwrap();
    let missing = work.path().join("nope.bin");
    let back = work.path().join("back.bin");
    let err = conn
        .get_file(&missing.to_string_lossy(), &back, &mut no_progress())
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("nope.bin"), "{err}");
    assert!(!back.exists());
    // The connection is still usable.
    assert!(
        conn.list_dir(&work.path().to_string_lossy(), false)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn put_missing_local_file_fails_before_sending() {
    let env = common::start().await;
    let work = tempfile::tempdir().unwrap();
    let mut conn = client::connect(env.client_dir.path(), "srv").await.unwrap();
    let err = conn
        .put_file(
            &work.path().join("absent"),
            &work.path().join("r").to_string_lossy(),
            &mut no_progress(),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("absent"), "{err}");
}

#[tokio::test]
async fn hash_mismatch_leaves_no_target_file() {
    let work = tempfile::tempdir().unwrap();
    let target = work.path().join("out.bin");
    let (mut tx, mut rx) = tokio::io::duplex(1 << 20);
    let incoming = Incoming::create(&target).await.unwrap();
    proto::write_frame(&mut tx, &Frame::Data(vec![1, 2, 3, 4]))
        .await
        .unwrap();
    proto::send(
        &mut tx,
        &TransferTrailer {
            sha256: "00".repeat(32),
        },
    )
    .await
    .unwrap();
    let err = incoming.receive(&mut rx, 4, &mut |_| {}).await.unwrap_err();
    assert!(matches!(err, TransferError::Checksum), "{err:?}");
    assert!(
        std::fs::read_dir(work.path()).unwrap().next().is_none(),
        "files left behind"
    );
}

#[tokio::test]
async fn connection_drop_mid_transfer_leaves_no_partial() {
    let work = tempfile::tempdir().unwrap();
    let target = work.path().join("out.bin");
    let (mut tx, mut rx) = tokio::io::duplex(1 << 20);
    let incoming = Incoming::create(&target).await.unwrap();
    proto::write_frame(&mut tx, &Frame::Data(vec![7; 1000]))
        .await
        .unwrap();
    tx.shutdown().await.unwrap();
    drop(tx);
    let err = incoming
        .receive(&mut rx, 5000, &mut |_| {})
        .await
        .unwrap_err();
    assert!(err.to_string().contains("connection"), "{err}");
    assert!(
        std::fs::read_dir(work.path()).unwrap().next().is_none(),
        "files left behind"
    );
}

#[tokio::test]
async fn failed_final_rename_leaves_no_part_file() {
    let work = tempfile::tempdir().unwrap();
    let target = work.path().join("occupied");
    std::fs::create_dir(&target).unwrap();
    let (mut tx, mut rx) = tokio::io::duplex(1 << 20);
    let incoming = Incoming::create(&target).await.unwrap();
    let data = vec![1u8, 2, 3];
    proto::write_frame(&mut tx, &Frame::Data(data.clone()))
        .await
        .unwrap();
    let trailer = TransferTrailer {
        sha256: hex::encode(Sha256::digest(&data)),
    };
    proto::send(&mut tx, &trailer).await.unwrap();
    let err = incoming.receive(&mut rx, 3, &mut |_| {}).await.unwrap_err();
    assert!(matches!(err, TransferError::Local(_)), "{err:?}");
    let names: Vec<_> = std::fs::read_dir(work.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        names.len(),
        1,
        "a verified part file was left behind: {names:?}"
    );
}
