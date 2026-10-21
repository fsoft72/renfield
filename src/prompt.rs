//! Asking a human a yes/no question, with a time limit and without stale prompts piling up.

use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// How long a human has to answer a pairing question.
pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(300);
/// How often a waiting prompt checks whether a newer question replaced it.
const TICK: Duration = Duration::from_millis(100);

/// Asks a human a yes/no question.
pub trait Prompt: Send + Sync {
    /// Shows `text` and returns true only when the human answers yes.
    fn confirm(&self, text: &str) -> bool;
}

/// Tells whether a typed line means yes.
fn is_yes(line: &str) -> bool {
    matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}

/// A prompt fed by a channel of typed lines. It gives up after a timeout, and a newer question
/// replaces a pending older one (which answers "no"), so an abandoned question never keeps the
/// human's answers to itself.
pub struct LinePrompt {
    lines: Mutex<Receiver<String>>,
    out: Mutex<Box<dyn Write + Send>>,
    generation: AtomicU64,
    timeout: Duration,
}

impl LinePrompt {
    /// Creates a prompt reading answers from `lines` and printing questions to `out`.
    pub fn new(
        lines: Receiver<String>,
        out: Box<dyn Write + Send>,
        timeout: Duration,
    ) -> LinePrompt {
        LinePrompt {
            lines: Mutex::new(lines),
            out: Mutex::new(out),
            generation: AtomicU64::new(0),
            timeout,
        }
    }
}

impl Prompt for LinePrompt {
    fn confirm(&self, text: &str) -> bool {
        let mine = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        // An older question still waiting notices the new generation within one tick and leaves.
        let Ok(lines) = self.lines.lock() else {
            return false;
        };
        if let Ok(mut out) = self.out.lock() {
            let _ = write!(out, "{text} ");
            let _ = out.flush();
        }
        let deadline = Instant::now() + self.timeout;
        loop {
            if self.generation.load(Ordering::SeqCst) != mine {
                return false;
            }
            match lines.recv_timeout(TICK) {
                Ok(line) => return is_yes(&line),
                Err(RecvTimeoutError::Disconnected) => return false,
                Err(RecvTimeoutError::Timeout) if Instant::now() >= deadline => {
                    if let Ok(mut out) = self.out.lock() {
                        let _ = writeln!(out, "\n(no answer in time, taken as no)");
                    }
                    return false;
                }
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }
}

/// The prompt used by the command line tool: questions on stdout, answers from stdin.
pub struct TerminalPrompt;

/// The one reader of stdin, started the first time a question is asked.
fn terminal() -> &'static LinePrompt {
    static TERMINAL: OnceLock<LinePrompt> = OnceLock::new();
    TERMINAL.get_or_init(|| {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            loop {
                let mut line = String::new();
                match stdin.lock().read_line(&mut line) {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {
                        if tx.send(line).is_err() {
                            return;
                        }
                    }
                }
            }
        });
        LinePrompt::new(rx, Box::new(std::io::stdout()), PROMPT_TIMEOUT)
    })
}

impl Prompt for TerminalPrompt {
    fn confirm(&self, text: &str) -> bool {
        terminal().confirm(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A writer whose content can be read back.
    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn prompt(timeout: Duration) -> (Arc<LinePrompt>, mpsc::Sender<String>, Shared) {
        let (tx, rx) = mpsc::channel();
        let out = Shared::default();
        (
            Arc::new(LinePrompt::new(rx, Box::new(out.clone()), timeout)),
            tx,
            out,
        )
    }

    #[test]
    fn yes_and_no_answers() {
        let (p, tx, out) = prompt(Duration::from_secs(5));
        for (typed, expected) in [
            ("y\n", true),
            ("Yes\n", true),
            ("n\n", false),
            ("\n", false),
            ("maybe\n", false),
        ] {
            tx.send(typed.to_string()).unwrap();
            assert_eq!(p.confirm("Accept?"), expected, "{typed:?}");
        }
        assert!(String::from_utf8_lossy(&out.0.lock().unwrap()).contains("Accept? "));
    }

    #[test]
    fn closed_input_means_no() {
        let (p, tx, _) = prompt(Duration::from_secs(5));
        drop(tx);
        assert!(!p.confirm("Accept?"));
    }

    #[test]
    fn no_answer_in_time_means_no() {
        let (p, _tx, out) = prompt(Duration::from_millis(300));
        let started = Instant::now();
        assert!(!p.confirm("Accept?"));
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(String::from_utf8_lossy(&out.0.lock().unwrap()).contains("no answer in time"));
    }

    #[test]
    fn a_newer_question_replaces_the_pending_one_and_gets_the_answer() {
        let (p, tx, _) = prompt(Duration::from_secs(30));
        let older = {
            let p = p.clone();
            std::thread::spawn(move || p.confirm("old question"))
        };
        std::thread::sleep(Duration::from_millis(300));
        let newer = {
            let p = p.clone();
            std::thread::spawn(move || p.confirm("new question"))
        };
        std::thread::sleep(Duration::from_millis(500));
        tx.send("y\n".to_string()).unwrap();
        assert!(
            newer.join().unwrap(),
            "the answer must go to the newer question"
        );
        assert!(
            !older.join().unwrap(),
            "the replaced question must answer no"
        );
    }
}
