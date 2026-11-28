//! The status console. Port of console.go.
//!
//! One thread owns stderr. Status messages go through a bounded queue of 16 and are dropped when
//! it is full, so a stalled terminal or a full pipe never holds up saving a winner. Closing cannot
//! cancel a blocked write: a blocked writer may outlive `run`, as in Go.
//!
//! Basis: the example rewrite's `Console` (bounded queue with `try_send`, 2 s close), renamed to
//! Go's `status` and `close`; the closed state and the write-error handling follow Go.

use std::io::Write;
use std::sync::Mutex;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::thread;
use std::time::Duration;

/// Go's `make(chan string, 16)`.
const QUEUE_LEN: usize = 16;

/// How long `run` waits for the writer at the end (Go's default `consoleTimeout`).
pub(crate) const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

struct State {
    /// `None` once closed.
    messages: Option<SyncSender<Vec<u8>>>,
    /// Signalled when the writer thread has drained the queue; taken by the first `close`.
    done: Option<Receiver<()>>,
}

pub(crate) struct Console {
    state: Mutex<State>,
}

impl Console {
    /// Starts the writer thread. Only this thread writes to `writer`; its errors are ignored.
    pub(crate) fn new<W: Write + Send + 'static>(mut writer: W) -> std::io::Result<Console> {
        let (messages, queue) = mpsc::sync_channel::<Vec<u8>>(QUEUE_LEN);
        let (finished, done) = mpsc::channel::<()>();
        thread::Builder::new()
            .name("console".to_owned())
            .spawn(move || {
                for message in queue {
                    let _ = writer.write_all(&message);
                }
                // The receiver may have given up already.
                let _ = finished.send(());
            })?;
        Ok(Console {
            state: Mutex::new(State {
                messages: Some(messages),
                done: Some(done),
            }),
        })
    }

    /// Queues `message` (a complete line with its newline) and never blocks. A full queue or a
    /// closed console drops it.
    pub(crate) fn status(&self, message: Vec<u8>) {
        let Ok(state) = self.state.lock() else { return };
        if let Some(messages) = &state.messages {
            match messages.try_send(message) {
                Ok(()) | Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {}
            }
        }
    }

    /// Closes the queue and waits for the writer at most `timeout`. Closing twice is harmless; the
    /// second call returns at once.
    pub(crate) fn close(&self, timeout: Duration) {
        let done = {
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            if state.messages.take().is_none() {
                return;
            }
            state.done.take()
        };
        if let Some(done) = done {
            // A timeout and a disconnected writer both end the wait.
            let _: Result<(), RecvTimeoutError> = done.recv_timeout(timeout);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, mpsc::Sender};
    use std::time::Instant;

    /// Blocks its first write until the test lets go (Go: `blockedWriter`), and records what it got.
    struct BlockedWriter {
        entered: Sender<()>,
        release: Receiver<()>,
        written: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl Write for BlockedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let _ = self.entered.send(());
            // Returns an error once the test drops the sender: every later write goes through.
            let _ = self.release.recv();
            self.written.lock().expect("lock").push(buf.to_vec());
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn delivered(written: &Arc<Mutex<Vec<Vec<u8>>>>, want: usize) -> usize {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let n = written.lock().expect("lock").len();
            if n >= want || Instant::now() > deadline {
                // Give a wrongly queued extra message time to show up.
                thread::sleep(Duration::from_millis(100));
                return written.lock().expect("lock").len();
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    // Go: TestConsoleBoundedQueueAndClose
    #[test]
    fn a_blocked_writer_holds_at_most_sixteen_queued_messages_and_close_returns() {
        let (entered_tx, entered) = mpsc::channel();
        let (release_tx, release) = mpsc::channel::<()>();
        let written = Arc::new(Mutex::new(Vec::new()));
        let console = Console::new(BlockedWriter {
            entered: entered_tx,
            release,
            written: Arc::clone(&written),
        })
        .expect("thread starts");
        console.status(b"first\n".to_vec());
        entered.recv().expect("the writer took the first message");
        for _ in 0..100 {
            console.status(b"dropped when full\n".to_vec());
        }
        let start = Instant::now();
        console.close(Duration::from_millis(1));
        assert!(start.elapsed() < Duration::from_secs(1), "close blocked");
        // Let the writer go: the one in flight and the sixteen queued ones arrive, nothing else.
        drop(release_tx);
        assert_eq!(delivered(&written, 17), 17, "queue bound");
        let written = written.lock().expect("lock");
        assert_eq!(written[0], b"first\n");
        assert!(written[1..].iter().all(|m| m == b"dropped when full\n"));
    }

    #[test]
    fn status_after_close_is_dropped_and_a_second_close_returns_at_once() {
        let written = Arc::new(Mutex::new(Vec::new()));
        struct Collect(Arc<Mutex<Vec<Vec<u8>>>>);
        impl Write for Collect {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("lock").push(buf.to_vec());
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let console = Console::new(Collect(Arc::clone(&written))).expect("thread starts");
        console.status(b"one\n".to_vec());
        console.close(Duration::from_secs(5));
        console.status(b"late\n".to_vec());
        let start = Instant::now();
        console.close(Duration::from_secs(5));
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(*written.lock().expect("lock"), vec![b"one\n".to_vec()]);
    }

    #[test]
    fn write_errors_are_ignored_and_later_messages_still_flow() {
        struct FailFirst(Arc<Mutex<Vec<Vec<u8>>>>, bool);
        impl Write for FailFirst {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if !self.1 {
                    self.1 = true;
                    return Err(std::io::ErrorKind::BrokenPipe.into());
                }
                self.0.lock().expect("lock").push(buf.to_vec());
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let written = Arc::new(Mutex::new(Vec::new()));
        let console = Console::new(FailFirst(Arc::clone(&written), false)).expect("thread starts");
        console.status(b"lost\n".to_vec());
        console.status(b"kept\n".to_vec());
        console.close(Duration::from_secs(5));
        assert_eq!(*written.lock().expect("lock"), vec![b"kept\n".to_vec()]);
    }
}
