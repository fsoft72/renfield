//! Two phase pairing: dest accepts an offered key, source confirms, and only then both sides store it.

use std::io::{BufRead, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::client::{self, Conn};
use crate::config::DEFAULT_PORT;
use crate::error::RenfieldError;
use crate::identity::Identity;
use crate::proto::{self, Request, Response};
use crate::server::FilePolicy;
use crate::store::{Authorized, Entry, Registry};
use crate::tls::PeerPolicy;

/// How long each side waits for the other (and its human) during the exchange.
const STEP_TIMEOUT: Duration = Duration::from_secs(300);
/// Shown when dest is not in pairing mode.
const NOT_PAIRING: &str =
    "this machine is not accepting new keys. Start it with: renfield listen --accept-key";

/// Asks a human a yes/no question.
pub trait Prompt: Send + Sync {
    /// Shows `text` and returns true only when the human answers yes.
    fn confirm(&self, text: &str) -> bool;
}

/// Prompt that talks to the terminal: prints the text and reads a line from stdin.
pub struct TerminalPrompt;

impl Prompt for TerminalPrompt {
    fn confirm(&self, text: &str) -> bool {
        print!("{text} ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        if std::io::stdin().lock().read_line(&mut line).is_err() {
            return false;
        }
        matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
    }
}

/// Longest machine name accepted in a pairing.
pub const MAX_NAME_LEN: usize = 64;
/// Name used when the host name is empty or unusable.
const FALLBACK_NAME: &str = "renfield-host";

/// Tells whether a name is safe to show to a human and to store: letters, digits, `.`, `_`, `-`.
pub fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Turns any text into a valid name: unsafe characters become `-`, the length is capped.
pub fn clean_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .take(MAX_NAME_LEN)
        .collect();
    if cleaned.is_empty() {
        FALLBACK_NAME.to_string()
    } else {
        cleaned
    }
}

/// Returns the name this machine gives itself in pairings (its host name, made safe).
pub fn local_name() -> String {
    let from_env = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME"));
    let name = from_env
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok());
    clean_name(name.as_deref().map(str::trim).unwrap_or_default())
}

/// Builds the question shown on both machines: the same two keys, with the labels swapped.
fn prompt_text(headline: &str, own_fp: &str, other_fp: &str, question: &str) -> String {
    format!(
        "{headline}\n  This machine's key:   {own_fp}\n  Other machine's key:  {other_fp}\n\
         The same two keys must appear on the other machine, with the labels swapped.\n{question} [y/N]"
    )
}

/// Runs the blocking prompt on a thread that does not stall the async runtime.
async fn ask(prompt: Arc<dyn Prompt>, text: String) -> bool {
    tokio::task::spawn_blocking(move || prompt.confirm(&text))
        .await
        .unwrap_or(false)
}

/// What the source asked for.
pub struct Offer {
    pub source_name: String,
    pub both: bool,
    pub source_listen_port: Option<u16>,
}

/// What dest knows while handling an offer.
pub struct DestContext<'a> {
    pub policy: &'a FilePolicy,
    pub own_fingerprint: &'a str,
    pub peer_fingerprint: &'a str,
    pub peer_addr: SocketAddr,
    pub prompt: Option<Arc<dyn Prompt>>,
}

/// Releases the single pairing slot (and closes the window) however the exchange ends.
struct Slot<'a>(&'a FilePolicy);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.finish_pairing();
    }
}

/// Sends an error answer.
async fn refuse<S: AsyncWrite + Unpin>(stream: &mut S, message: &str) -> std::io::Result<()> {
    proto::send(
        stream,
        &Response::Error {
            message: message.to_string(),
        },
    )
    .await
}

/// Dest side of the exchange: confirm with the human, wait for the source's commit, then store.
pub async fn dest_handle_offer<S>(
    stream: &mut S,
    ctx: &DestContext<'_>,
    offer: Offer,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(prompt) = ctx.prompt.clone() else {
        return refuse(stream, NOT_PAIRING).await;
    };
    if !ctx.policy.pairing_open() {
        return refuse(stream, NOT_PAIRING).await;
    }
    if !is_valid_name(&offer.source_name) {
        let message = format!(
            "invalid source name: use only letters, digits, '.', '_' and '-' (at most {MAX_NAME_LEN} characters)"
        );
        return refuse(stream, &message).await;
    }
    if !ctx.policy.try_begin_pairing() {
        return refuse(stream, "pairing in progress, try again later").await;
    }
    let _slot = Slot(ctx.policy);
    let headline = format!(
        "Pairing request from '{}' at {}.",
        offer.source_name, ctx.peer_addr
    );
    let text = prompt_text(
        &headline,
        ctx.own_fingerprint,
        ctx.peer_fingerprint,
        "Accept this key?",
    );
    if !ask(prompt, text).await {
        return refuse(stream, "pairing rejected on the other machine").await;
    }
    proto::send(
        stream,
        &Response::PairOffered {
            dest_name: local_name(),
        },
    )
    .await?;
    let next = tokio::time::timeout(STEP_TIMEOUT, proto::recv::<_, Request>(stream)).await;
    match next {
        Ok(Ok(Some(Request::PairCommit))) => match store_pairing(ctx, &offer) {
            Ok(()) => proto::send(stream, &Response::PairDone).await,
            Err(e) => refuse(stream, &format!("cannot store the pairing: {e:#}")).await,
        },
        Ok(Ok(Some(Request::PairAbort))) => {
            refuse(stream, "pairing aborted by the source, nothing was saved").await
        }
        _ => Ok(()),
    }
}

/// Writes the source's key into the authorized list (and the registry for `--both`).
fn store_pairing(ctx: &DestContext<'_>, offer: &Offer) -> anyhow::Result<()> {
    let dir = ctx.policy.dir();
    if offer.both {
        let port = offer.source_listen_port.unwrap_or(DEFAULT_PORT);
        let entry = Entry {
            name: offer.source_name.clone(),
            addr: SocketAddr::new(ctx.peer_addr.ip(), port).to_string(),
            fingerprint: ctx.peer_fingerprint.to_string(),
        };
        let mut registry = Registry::load(dir)?;
        registry.add(entry, true)?;
        registry.save(dir)?;
    }
    let mut authorized = Authorized::load(dir)?;
    authorized.add(ctx.peer_fingerprint, &offer.source_name);
    authorized.save(dir)
}

/// Parameters of the source side of a pairing.
pub struct PairParams {
    /// This machine's configuration directory.
    pub dir: PathBuf,
    /// Name to register dest under.
    pub name: String,
    /// Dest's address (host:port).
    pub addr: String,
    /// Name this machine presents to dest.
    pub own_name: String,
    /// Also let dest command this machine.
    pub both: bool,
    /// Port this machine listens on (only with `both`).
    pub listen_port: Option<u16>,
    /// Replace an existing registry entry of the same name.
    pub force: bool,
}

/// Converts a refusal or unexpected answer from dest into an error.
fn unexpected(machine: &str, response: Response) -> RenfieldError {
    match response {
        Response::Error { message } => {
            RenfieldError::Remote(format!("'{machine}' reported: {message}"))
        }
        other => RenfieldError::Protocol(format!("unexpected answer during pairing: {other:?}")),
    }
}

/// Waits for the next answer within the step timeout.
async fn next_response(conn: &mut Conn) -> Result<Response, RenfieldError> {
    let machine = conn.machine().to_string();
    tokio::time::timeout(STEP_TIMEOUT, conn.recv_response())
        .await
        .map_err(|_| RenfieldError::Timeout(format!("'{machine}' did not answer during pairing")))?
}

/// Source side of the exchange; nothing is saved unless both humans confirm.
pub async fn source_flow(p: PairParams, prompt: Arc<dyn Prompt>) -> Result<(), RenfieldError> {
    let io = |e: anyhow::Error| RenfieldError::Io(format!("{e:#}"));
    let mut registry = Registry::load(&p.dir).map_err(io)?;
    if !p.force && registry.get(&p.name).is_some() {
        return Err(RenfieldError::Usage(format!(
            "machine '{}' is already registered, use --force to replace it or choose another name",
            p.name
        )));
    }
    let id = Identity::load_or_create(&p.dir).map_err(io)?;
    let mut conn = client::connect_addr(&id, &p.name, &p.addr, None).await?;
    let dest_fp = conn
        .peer_fingerprint()
        .ok_or_else(|| RenfieldError::Protocol("dest presented no certificate".into()))?;
    conn.send_request(&Request::PairOffer {
        source_name: clean_name(&p.own_name),
        both: p.both,
        source_listen_port: p.listen_port,
    })
    .await?;
    match next_response(&mut conn).await? {
        Response::PairOffered { .. } => {}
        other => return Err(unexpected(&p.name, other)),
    }
    let headline = format!("Pairing with '{}' at {}.", p.name, p.addr);
    let text = prompt_text(
        &headline,
        &id.fingerprint(),
        &dest_fp,
        "Trust this machine?",
    );
    if !ask(prompt, text).await {
        conn.send_request(&Request::PairAbort).await?;
        let _ = next_response(&mut conn).await;
        return Err(RenfieldError::Usage(
            "pairing cancelled, nothing was saved".into(),
        ));
    }
    conn.send_request(&Request::PairCommit).await?;
    match next_response(&mut conn).await? {
        Response::PairDone => {}
        other => return Err(unexpected(&p.name, other)),
    }
    registry
        .add(
            Entry {
                name: p.name.clone(),
                addr: p.addr.clone(),
                fingerprint: dest_fp.clone(),
            },
            p.force,
        )
        .map_err(io)?;
    registry.save(&p.dir).map_err(io)?;
    if p.both {
        let mut authorized = Authorized::load(&p.dir).map_err(io)?;
        authorized.add(&dest_fp, &p.name);
        authorized.save(&p.dir).map_err(io)?;
    }
    Ok(())
}
