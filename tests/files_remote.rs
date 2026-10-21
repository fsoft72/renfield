//! Remote file operations through a real connection.

mod common;

use renfield::client;
use renfield::error::RenfieldError;

#[tokio::test]
async fn remote_roundtrip_write_read_edit() {
    let env = common::start().await;
    let work = tempfile::tempdir().unwrap();
    let file = work
        .path()
        .join("src/main.rs")
        .to_string_lossy()
        .into_owned();
    let mut conn = client::connect(env.client_dir.path(), "srv").await.unwrap();

    let bytes = conn
        .write_file(&file, "fn main() {\n    old();\n}\n")
        .await
        .unwrap();
    assert_eq!(bytes, 25);
    let read = conn.read_file(&file, None, None).await.unwrap();
    assert_eq!(read.total_lines, 3);
    assert_eq!(read.text, "fn main() {\n    old();\n}");
    assert_eq!(
        conn.edit_file(&file, "old()", "new()", false)
            .await
            .unwrap(),
        1
    );
    let again = conn.read_file(&file, Some(2), Some(1)).await.unwrap();
    assert_eq!(again.text, "    new();");
    let listing = conn
        .list_dir(&work.path().to_string_lossy(), true)
        .await
        .unwrap();
    assert!(
        listing
            .entries
            .iter()
            .any(|e| e.name == "src/main.rs" && e.kind == "file")
    );
}

#[tokio::test]
async fn remote_edit_failure_is_a_clear_remote_error() {
    let env = common::start().await;
    let work = tempfile::tempdir().unwrap();
    let file = work.path().join("a.txt").to_string_lossy().into_owned();
    let mut conn = client::connect(env.client_dir.path(), "srv").await.unwrap();
    conn.write_file(&file, "hello\n").await.unwrap();
    let err = conn
        .edit_file(&file, "absent", "x", false)
        .await
        .unwrap_err();
    assert!(matches!(err, RenfieldError::Remote(_)), "{err:?}");
    assert!(err.to_string().contains("not found"), "{err}");
    // The connection stays usable after a failed request.
    assert_eq!(
        conn.read_file(&file, None, None).await.unwrap().text,
        "hello"
    );
}

#[tokio::test]
async fn write_file_over_8mib_suggests_put() {
    let env = common::start().await;
    let mut conn = client::connect(env.client_dir.path(), "srv").await.unwrap();
    let big = "x".repeat(9 * 1024 * 1024);
    let err = conn
        .write_file("/tmp/never-written", &big)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("put"), "{err}");
}
