use std::process::Command;
use std::thread;
use std::time::Duration;

fn main() {
    println!("Starting Sentinel Guard Watchdog...");

    loop {
        println!("Guard: Spawning SentinelCore...");

        let exe_path = if cfg!(debug_assertions) {
            "target/debug/core.exe"
        } else {
            "target/release/core.exe"
        };

        let child_result = Command::new(exe_path).arg("--service").spawn();

        match child_result {
            Ok(mut child) => {
                println!("Guard: Child process started with PID: {}", child.id());

                // Monitor the child process handle
                // child.wait() uses WaitForSingleObject under the hood on Windows
                match child.wait() {
                    Ok(status) => {
                        println!("Guard: Child process exited with status: {}", status);
                        println!("Guard: Restarting in 500ms...");
                        thread::sleep(Duration::from_millis(500));
                    }
                    Err(e) => {
                        eprintln!("Guard: Error waiting on child: {}", e);
                        thread::sleep(Duration::from_millis(500));
                    }
                }
            }
            Err(e) => {
                eprintln!("Guard: Failed to spawn child process: {}", e);
                println!("Guard: Retrying in 5 seconds...");
                thread::sleep(Duration::from_secs(5));
            }
        }
    }
}
