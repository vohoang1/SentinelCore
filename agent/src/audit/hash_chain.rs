use std::sync::Mutex;
use std::sync::OnceLock;

static LAST_HASH: OnceLock<Mutex<String>> = OnceLock::new();

fn get_hash_mutex() -> &'static Mutex<String> {
    LAST_HASH.get_or_init(|| {
        // Initial genesis hash (can be anything, zeroed hex used here for genesis)
        let genesis =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        Mutex::new(genesis)
    })
}

pub fn get_previous_hash() -> String {
    let mutex = get_hash_mutex();
    let lock = mutex.lock().unwrap();
    lock.clone()
}

pub fn update_hash_chain(new_hash: String) {
    let mutex = get_hash_mutex();
    let mut lock = mutex.lock().unwrap();
    *lock = new_hash;
}
