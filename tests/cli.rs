//! End to end tests of the real binary against an in-process dest.

mod common;

use std::path::Path;

use renfield::store::Registry;

/// Runs the renfield binary with the given config dir; returns (exit code, stdout, stderr).
async fn run(home: &Path, args: &[&str]) -> (i32, String, String) {
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_renfield"))
        .env("RENFIELD_HOME", home)
        .args(args)
        .output()
        .await
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[tokio::test]
async fn exec_on_unknown_name_exits_201_with_hint_to_pair() {
    let home = tempfile::tempdir().unwrap();
    let (code, _, err) = run(home.path(), &["exec", "ghost", "--", "true"]).await;
    assert_eq!(code, 201, "{err}");
    assert!(err.contains("renfield pair ghost"), "{err}");
}

#[tokio::test]
async fn exec_to_closed_port_exits_200_naming_machine_and_address() {
    let env = common::start().await;
    let mut reg = Registry::load(env.client_dir.path()).unwrap();
    reg.machine[0].addr = "127.0.0.1:1".into();
    reg.save(env.client_dir.path()).unwrap();
    let (code, _, err) = run(env.client_dir.path(), &["exec", "srv", "--", "true"]).await;
    assert_eq!(code, 200, "{err}");
    assert!(
        err.contains("'srv'") && err.contains("127.0.0.1:1"),
        "{err}"
    );
}

#[tokio::test]
async fn exec_not_authorized_exits_202() {
    let env = common::start().await;
    std::fs::remove_file(env.server_dir.path().join("authorized.toml")).unwrap();
    let (code, _, err) = run(env.client_dir.path(), &["exec", "srv", "--", "true"]).await;
    assert_eq!(code, 202, "{err}");
    assert!(
        err.contains("not authorized") && err.contains("--accept-key"),
        "{err}"
    );
}

#[tokio::test]
async fn key_mismatch_exits_203() {
    let env = common::start().await;
    let mut reg = Registry::load(env.client_dir.path()).unwrap();
    reg.machine[0].fingerprint = "00".repeat(32);
    reg.save(env.client_dir.path()).unwrap();
    let (code, _, err) = run(env.client_dir.path(), &["exec", "srv", "--", "true"]).await;
    assert_eq!(code, 203, "{err}");
    assert!(err.contains("renfield remove srv"), "{err}");
}

#[tokio::test]
async fn exec_timeout_exits_204() {
    let env = common::start().await;
    let (code, _, err) = run(
        env.client_dir.path(),
        &["exec", "srv", "--timeout", "1", "--", "sleep", "20"],
    )
    .await;
    assert_eq!(code, 204, "{err}");
}

#[tokio::test]
async fn remote_exit_code_is_passed_through_and_output_mirrored() {
    let env = common::start().await;
    let (code, out, err) = run(
        env.client_dir.path(),
        &["exec", "srv", "--", "echo hi; echo bad 1>&2; exit 42"],
    )
    .await;
    assert_eq!(code, 42);
    assert_eq!(out, "hi\n");
    assert_eq!(err, "bad\n");
}

#[tokio::test]
async fn list_remove_roundtrip() {
    let env = common::start().await;
    let (code, out, _) = run(env.client_dir.path(), &["list"]).await;
    assert_eq!(code, 0);
    assert!(
        out.contains("srv") && out.contains(&env.addr.to_string()),
        "{out}"
    );
    assert_eq!(run(env.client_dir.path(), &["remove", "srv"]).await.0, 0);
    let (_, out, _) = run(env.client_dir.path(), &["list"]).await;
    assert!(!out.contains("127.0.0.1"), "{out}");
    assert!(
        out.contains("renfield pair"),
        "an empty list should say how to pair: {out}"
    );
    let (code, _, err) = run(env.client_dir.path(), &["remove", "srv"]).await;
    assert_eq!(code, 201, "{err}");
}

#[tokio::test]
async fn authorized_revoke_blocks_next_connection() {
    let env = common::start().await;
    assert_eq!(
        run(env.client_dir.path(), &["exec", "srv", "--", "true"])
            .await
            .0,
        0
    );
    let (code, out, _) = run(env.server_dir.path(), &["authorized", "list"]).await;
    assert_eq!(code, 0);
    assert!(out.contains("client"), "{out}");
    assert_eq!(
        run(env.server_dir.path(), &["authorized", "revoke", "client"])
            .await
            .0,
        0
    );
    let (code, _, err) = run(env.client_dir.path(), &["exec", "srv", "--", "true"]).await;
    assert_eq!(code, 202, "{err}");
    let (code, _, err) = run(env.server_dir.path(), &["authorized", "revoke", "client"]).await;
    assert_eq!(
        code, 206,
        "revoking something unknown is a usage error: {err}"
    );
}
