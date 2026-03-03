use notify::{EventKind, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::engine::signature::SignatureEngine;

pub fn start_rules_watcher(sig_engine: Arc<SignatureEngine>, rules_dir: PathBuf) {
    thread::spawn(move || {
        let (tx, rx) = std::sync::mpsc::channel();

        // Create a watcher object, delivering debounced events.
        // We use a basic recommended watcher matching the current platform.
        let mut watcher = notify::recommended_watcher(tx).unwrap();

        // Check if rules_dir exists so we can watch it.
        if rules_dir.exists() {
            watcher
                .watch(&rules_dir, RecursiveMode::NonRecursive)
                .unwrap();
            println!("Hot-reloading watcher started for {:?}", rules_dir);
        } else {
            println!("Cannot watch {:?} because it does not exist.", rules_dir);
            return;
        }

        loop {
            match rx.recv() {
                Ok(Ok(event)) => {
                    // Only react to file modifications or creations
                    match event.kind {
                        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {
                            // Give the file a moment to be fully written
                            thread::sleep(Duration::from_millis(100));
                            sig_engine.reload_rules(&rules_dir);
                        }
                        _ => {}
                    }
                }
                Ok(Err(e)) => println!("Watcher error: {:?}", e),
                Err(e) => {
                    println!("Watcher channel disconnected: {:?}", e);
                    break;
                }
            }
        }
    });
}
