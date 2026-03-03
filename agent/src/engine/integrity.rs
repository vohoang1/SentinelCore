use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

pub static INTEGRITY_COMPROMISED: AtomicBool = AtomicBool::new(false);

pub fn start_integrity_monitor() {
    let current_exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Failed to get current executable path: {}", e);
            return;
        }
    };

    let baseline_hash = match calculate_hash(&current_exe) {
        Ok(hash) => {
            println!("Baseline SentinelCore Hash: {}", hash);
            hash
        }
        Err(e) => {
            eprintln!("Failed to calculate baseline hash: {}", e);
            return;
        }
    };

    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(30));

            match calculate_hash(&current_exe) {
                Ok(current_hash) => {
                    if current_hash != baseline_hash {
                        eprintln!(
                            "🚨 CRITICAL: Binary integrity compromised! Hash mismatch on {:?}",
                            current_exe
                        );
                        INTEGRITY_COMPROMISED.store(true, Ordering::Relaxed);
                        // In production, we would alert the central console,
                        // attempt to self-heal by pulling a clean binary from the cloud,
                        // or panic to let the Guard restore us.
                    }
                }
                Err(e) => {
                    eprintln!(
                        "🚨 Warning: Could not read binary for integrity check: {}",
                        e
                    );
                    // This often happens if the binary is locked for modification by malware.
                }
            }
        }
    });
}

fn calculate_hash(path: &PathBuf) -> std::io::Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}
