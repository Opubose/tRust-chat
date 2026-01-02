use tokio::sync::mpsc;
use std::thread;
use std::io::{self, BufRead};

/// Spawns a background thread to read stdin line-by-line.
/// Returns a channel receiver for those lines.
pub fn spawn_line_reader() -> mpsc::UnboundedReceiver<String> {
    let (tx, rx) = mpsc::unbounded_channel();
    
    thread::spawn(move || {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            if let Ok(l) = line {
                // If the receiver dropped (main ended), stop the thread
                if tx.send(l).is_err() { break; }
            }
        }
    });

    rx
}
