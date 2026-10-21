//! MCP server tests: the handler is driven directly and over an in-memory pipe.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use renfield::mcp::{self, DEFAULT_EXEC_TIMEOUT_SECS, Server};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

fn server_for(env: &common::Env) -> Server {
    Server::new(env.client_dir.path().to_path_buf())
}

async fn call(server: &Server, tool: &str, args: Value) -> Value {
    let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}});
    server
        .handle(request)
        .await
        .expect("a request must get an answer")
}

fn text(response: &Value) -> String {
    response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

fn is_error(response: &Value) -> bool {
    response["result"]["isError"].as_bool().unwrap_or(false)
}

#[tokio::test]
async fn tools_list_has_all_seven_tools() {
    let env = common::start().await;
    let response = server_for(&env)
        .handle(json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list"}))
        .await
        .unwrap();
    assert_eq!(response["id"], 7);
    let mut names: Vec<String> = response["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "remote_edit",
            "remote_exec",
            "remote_get",
            "remote_list",
            "remote_put",
            "remote_read",
            "remote_write"
        ]
    );
    for tool in response["result"]["tools"].as_array().unwrap() {
        assert!(
            tool["inputSchema"]["properties"]["machine"].is_object(),
            "{tool}"
        );
        assert!(tool["description"].as_str().unwrap().len() > 20);
    }
}

#[tokio::test]
async fn exec_tool_returns_exit_code_and_output() {
    let env = common::start().await;
    let response = call(
        &server_for(&env),
        "remote_exec",
        json!({"machine": "srv", "command": "echo out; echo err 1>&2; exit 3"}),
    )
    .await;
    let t = text(&response);
    assert!(t.contains("exit code: 3"), "{t}");
    assert!(t.contains("out") && t.contains("err"), "{t}");
    assert!(!is_error(&response));
}

#[test]
fn default_exec_timeout_is_120_seconds() {
    assert_eq!(DEFAULT_EXEC_TIMEOUT_SECS, 120);
    assert_eq!(
        Server::new(std::path::PathBuf::from(".")).default_timeout(),
        120
    );
}

#[tokio::test]
async fn exec_tool_default_timeout_flags_timed_out() {
    let env = common::start().await;
    let server = server_for(&env).with_default_timeout(1);
    let started = Instant::now();
    let response = call(
        &server,
        "remote_exec",
        json!({"machine": "srv", "command": "sleep 30"}),
    )
    .await;
    assert!(started.elapsed() < Duration::from_secs(6));
    assert!(text(&response).contains("timed out"), "{}", text(&response));
    assert!(is_error(&response));
}

#[tokio::test]
async fn exec_tool_truncates_to_1mib_keeping_tail() {
    let env = common::start().await;
    let response = call(
        &server_for(&env),
        "remote_exec",
        json!({"machine": "srv", "command": "seq 1 400000"}),
    )
    .await;
    let t = text(&response);
    assert!(t.contains("truncated"), "output was not flagged");
    assert!(t.trim_end().ends_with("400000"), "the tail must be kept");
    assert!(!t.contains("\n1\n2\n"), "the head must be dropped");
    assert!(t.len() < 1024 * 1024 + 1024, "{} bytes", t.len());
}

#[tokio::test]
async fn edit_tool_error_is_iserror_not_rpc_error() {
    let env = common::start().await;
    let server = server_for(&env);
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("a.txt").to_string_lossy().into_owned();
    let wrote = call(
        &server,
        "remote_write",
        json!({"machine": "srv", "path": file, "content": "hello\n"}),
    )
    .await;
    assert!(!is_error(&wrote), "{}", text(&wrote));
    let response = call(
        &server,
        "remote_edit",
        json!({"machine": "srv", "path": file, "old_string": "absent", "new_string": "x"}),
    )
    .await;
    assert!(response.get("error").is_none());
    assert!(is_error(&response));
    assert!(text(&response).contains("not found"), "{}", text(&response));
}

#[tokio::test]
async fn read_tool_numbers_lines_and_reports_range() {
    let env = common::start().await;
    let server = server_for(&env);
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("n.txt").to_string_lossy().into_owned();
    call(
        &server,
        "remote_write",
        json!({"machine": "srv", "path": file, "content": "alpha\nbeta\ngamma\n"}),
    )
    .await;
    let response = call(
        &server,
        "remote_read",
        json!({"machine": "srv", "path": file, "offset": 2, "limit": 1}),
    )
    .await;
    let t = text(&response);
    assert!(t.contains("     2\tbeta"), "{t}");
    assert!(!t.contains("alpha") && !t.contains("gamma"), "{t}");
    assert!(t.contains("lines 2-2 of 3"), "{t}");
}

#[tokio::test]
async fn list_tool_shows_kind_size_and_name() {
    let env = common::start().await;
    let server = server_for(&env);
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("f.txt"), "12345").unwrap();
    std::fs::create_dir(dir.path().join("d")).unwrap();
    let response = call(
        &server,
        "remote_list",
        json!({"machine": "srv", "path": dir.path().to_string_lossy()}),
    )
    .await;
    let t = text(&response);
    assert!(
        t.lines()
            .any(|l| l.contains("file") && l.contains("5") && l.ends_with("f.txt")),
        "{t}"
    );
    assert!(
        t.lines().any(|l| l.contains("dir") && l.ends_with("d/")),
        "{t}"
    );
}

#[tokio::test]
async fn put_and_get_tools_copy_files() {
    let env = common::start().await;
    let server = server_for(&env);
    let dir = tempfile::tempdir().unwrap();
    let (local, remote, back) = (
        dir.path().join("l.bin"),
        dir.path().join("r.bin"),
        dir.path().join("b.bin"),
    );
    std::fs::write(&local, b"payload").unwrap();
    let put = call(
        &server,
        "remote_put",
        json!({"machine": "srv", "local_path": local, "remote_path": remote}),
    )
    .await;
    assert!(!is_error(&put), "{}", text(&put));
    let get = call(
        &server,
        "remote_get",
        json!({"machine": "srv", "remote_path": remote, "local_path": back}),
    )
    .await;
    assert!(!is_error(&get), "{}", text(&get));
    assert_eq!(std::fs::read(&back).unwrap(), b"payload");
}

#[tokio::test]
async fn unknown_machine_error_is_clear() {
    let env = common::start().await;
    let response = call(
        &server_for(&env),
        "remote_exec",
        json!({"machine": "ghost", "command": "true"}),
    )
    .await;
    assert!(is_error(&response));
    assert!(
        text(&response).contains("not paired"),
        "{}",
        text(&response)
    );
}

#[tokio::test]
async fn bad_arguments_are_a_tool_error_naming_the_problem() {
    let env = common::start().await;
    let response = call(&server_for(&env), "remote_exec", json!({"machine": "srv"})).await;
    assert!(is_error(&response));
    assert!(text(&response).contains("command"), "{}", text(&response));
}

#[tokio::test]
async fn unknown_method_returns_rpc_error() {
    let env = common::start().await;
    let response = server_for(&env)
        .handle(json!({"jsonrpc": "2.0", "id": 3, "method": "no/such"}))
        .await
        .unwrap();
    assert_eq!(response["error"]["code"], -32601);
    assert_eq!(response["id"], 3);
}

#[tokio::test]
async fn unknown_tool_returns_invalid_params() {
    let env = common::start().await;
    let request = json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "nope", "arguments": {}}});
    let response = server_for(&env).handle(request).await.unwrap();
    assert_eq!(response["error"]["code"], -32602);
}

#[tokio::test]
async fn parallel_calls_run_concurrently() {
    let env = common::start().await;
    let server = server_for(&env);
    let started = Instant::now();
    let args = json!({"machine": "srv", "command": "sleep 1"});
    let (a, b) = tokio::join!(
        call(&server, "remote_exec", args.clone()),
        call(&server, "remote_exec", args)
    );
    assert!(text(&a).contains("exit code: 0") && text(&b).contains("exit code: 0"));
    assert!(
        started.elapsed() < Duration::from_millis(1800),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn stdio_framing_initialize_notification_and_garbage() {
    let env = common::start().await;
    let server = Arc::new(server_for(&env));
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let (server_read, server_write) = tokio::io::split(server_side);
    let handle = tokio::spawn(mcp::serve_io(
        server,
        BufReader::new(server_read),
        server_write,
    ));
    let (client_read, mut client_write) = tokio::io::split(client_side);
    let mut lines = BufReader::new(client_read).lines();

    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}});
    client_write
        .write_all(format!("{init}\n").as_bytes())
        .await
        .unwrap();
    let first: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(first["result"]["serverInfo"]["name"], "renfield");
    assert!(first["result"]["capabilities"]["tools"].is_object());

    client_write
        .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
        .await
        .unwrap();
    client_write.write_all(b"this is not json\n").await.unwrap();
    let second: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(
        second["error"]["code"], -32700,
        "the notification must not be answered, the garbage must"
    );

    client_write.shutdown().await.unwrap();
    handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn responses_from_the_client_are_ignored_but_garbage_is_not() {
    let env = common::start().await;
    let server = server_for(&env);
    let result = json!({"jsonrpc": "2.0", "id": 9, "result": {}});
    assert!(
        server.handle(result).await.is_none(),
        "a client response must not be answered"
    );
    let error = json!({"jsonrpc": "2.0", "id": 9, "error": {"code": -1, "message": "no"}});
    assert!(server.handle(error).await.is_none());
    let neither = server
        .handle(json!({"jsonrpc": "2.0", "id": 10}))
        .await
        .unwrap();
    assert_eq!(neither["error"]["code"], -32600);
}

#[tokio::test]
async fn edit_tool_description_warns_about_mixed_line_endings() {
    let env = common::start().await;
    let response = server_for(&env)
        .handle(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
        .await
        .unwrap();
    let tools = response["result"]["tools"].as_array().unwrap();
    let edit = tools.iter().find(|t| t["name"] == "remote_edit").unwrap();
    let description = edit["description"].as_str().unwrap();
    assert!(description.contains("mixed"), "{description}");
}

#[tokio::test]
async fn timeout_message_reports_the_limit_dest_actually_applied() {
    let env = common::start_with(renfield::server::ServerOptions {
        max_timeout_secs: Some(1),
        ..renfield::server::ServerOptions::default()
    })
    .await;
    let args = json!({"machine": "srv", "command": "sleep 30", "timeout_secs": 30});
    let started = Instant::now();
    let response = call(&server_for(&env), "remote_exec", args).await;
    assert!(started.elapsed() < Duration::from_secs(6));
    let t = text(&response);
    assert!(t.contains("killed after 1s"), "{t}");
}
