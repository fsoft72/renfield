//! Remote command execution tests (unix shells).

mod common;

use std::time::{Duration, Instant};

use renfield::client::{self, ExecArgs, ExecOutcome};
use renfield::proto::Stream;

/// Runs a command on the test dest, returning the outcome and the collected stdout and stderr.
async fn run(env: &common::Env, args: ExecArgs) -> (ExecOutcome, Vec<u8>, Vec<u8>) {
    let mut conn = client::connect(env.client_dir.path(), "srv").await.unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let outcome = conn
        .exec(args, |s, b| match s {
            Stream::Stdout => out.extend_from_slice(b),
            Stream::Stderr => err.extend_from_slice(b),
        })
        .await
        .unwrap();
    (outcome, out, err)
}

fn cmd(c: &str) -> ExecArgs {
    ExecArgs {
        command: c.into(),
        ..ExecArgs::default()
    }
}

#[tokio::test]
async fn exec_returns_exit_code() {
    let env = common::start().await;
    let (o, _, _) = run(&env, cmd("exit 3")).await;
    assert_eq!(o.exit_code, Some(3));
    assert!(!o.timed_out);
}

#[tokio::test]
async fn exec_streams_stdout_and_stderr_separately() {
    let env = common::start().await;
    let (o, out, err) = run(&env, cmd("echo out; echo err 1>&2")).await;
    assert_eq!(o.exit_code, Some(0));
    assert_eq!(out, b"out\n");
    assert_eq!(err, b"err\n");
}

#[tokio::test]
async fn exec_streams_before_command_ends() {
    let env = common::start().await;
    let mut conn = client::connect(env.client_dir.path(), "srv").await.unwrap();
    let start = Instant::now();
    let mut first_at = None;
    conn.exec(cmd("echo first; sleep 1; echo second"), |_, _| {
        first_at.get_or_insert(start.elapsed());
    })
    .await
    .unwrap();
    assert!(
        first_at.unwrap() < Duration::from_millis(700),
        "{first_at:?}"
    );
    assert!(start.elapsed() >= Duration::from_secs(1));
}

#[tokio::test]
async fn exec_timeout_kills_and_flags() {
    let env = common::start().await;
    let start = Instant::now();
    let args = ExecArgs {
        command: "sleep 37".into(),
        timeout_secs: Some(1),
        ..ExecArgs::default()
    };
    let (o, _, _) = run(&env, args).await;
    assert!(o.timed_out);
    assert!(start.elapsed() < Duration::from_secs(5));
    let left = std::process::Command::new("pgrep")
        .args(["-f", "sleep 37"])
        .output()
        .unwrap();
    assert!(left.stdout.is_empty(), "a child survived the timeout");
}

#[tokio::test]
async fn exec_cwd_is_honoured() {
    let env = common::start().await;
    let dir = tempfile::tempdir().unwrap();
    let args = ExecArgs {
        command: "pwd".into(),
        cwd: Some(dir.path().to_string_lossy().into_owned()),
        ..ExecArgs::default()
    };
    let (_, out, _) = run(&env, args).await;
    assert_eq!(
        String::from_utf8_lossy(&out).trim(),
        dir.path().to_string_lossy()
    );
}

#[tokio::test]
async fn exec_no_output_still_returns_code() {
    let env = common::start().await;
    let (o, out, err) = run(&env, cmd("true")).await;
    assert_eq!(o.exit_code, Some(0));
    assert!(out.is_empty() && err.is_empty());
}

#[tokio::test]
async fn exec_non_utf8_output_does_not_panic() {
    let env = common::start().await;
    let (o, out, _) = run(&env, cmd("printf '\\377\\376'")).await;
    assert_eq!(o.exit_code, Some(0));
    assert_eq!(out, vec![0xff, 0xfe]);
}

#[tokio::test]
async fn exec_bad_cwd_reports_clear_error() {
    let env = common::start().await;
    let mut conn = client::connect(env.client_dir.path(), "srv").await.unwrap();
    let args = ExecArgs {
        command: "true".into(),
        cwd: Some("/definitely/not/here".into()),
        ..ExecArgs::default()
    };
    let err = conn.exec(args, |_, _| {}).await.unwrap_err().to_string();
    assert!(err.contains("/definitely/not/here"), "{err}");
}

#[tokio::test]
async fn exec_args_keep_spaces_quotes_and_metacharacters() {
    let env = common::start().await;
    let args = ExecArgs {
        command: "printf".into(),
        args: ["%s\n", "x;y", "$HOME", "a  b", "it's"]
            .map(String::from)
            .to_vec(),
        ..ExecArgs::default()
    };
    let (o, out, _) = run(&env, args).await;
    assert_eq!(o.exit_code, Some(0));
    assert_eq!(String::from_utf8_lossy(&out), "x;y\n$HOME\na  b\nit's\n");
}
