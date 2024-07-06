use notify::{RecommendedWatcher, RecursiveMode, Watcher, Event, Config as NotifyConfig};
use serde::{Deserialize, Serialize};
use ssh2::Session;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::fs::File;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::{mpsc::channel, Arc, Mutex};
use std::time::{Duration, Instant};
use log::{info, error};
use rayon::prelude::*;

#[derive(Serialize, Deserialize, Clone)]
struct Config {
    source_directory: String,
    remote_server: String,
    remote_path: String,
    username: String,
}

#[derive(Serialize, Deserialize)]
struct Metadata {
    synced_files: HashSet<String>,
}

fn load_config() -> Config {
    let config_data = fs::read_to_string("config.json").expect("Unable to read config file");
    serde_json::from_str(&config_data).expect("Unable to parse config file")
}

fn load_metadata() -> Metadata {
    let metadata_data = fs::read_to_string("metadata.json").unwrap_or_else(|_| "{\"synced_files\": []}".to_string());
    serde_json::from_str(&metadata_data).unwrap_or_else(|_| Metadata { synced_files: HashSet::new() })
}

fn save_metadata(metadata: &Metadata) {
    let metadata_data = serde_json::to_string(metadata).expect("Unable to serialize metadata");
    fs::write("metadata.json", metadata_data).expect("Unable to write metadata file")
}

fn should_omit_file(path: &PathBuf) -> bool {
    if let Some(file_name) = path.file_name() {
        if let Some(file_name_str) = file_name.to_str() {
            return file_name_str == ".DS_Store";
        }
    }
    false
}

fn sync_file(path: PathBuf, config: &Config, metadata: &Arc<Mutex<Metadata>>) {
    if should_omit_file(&path) {
        info!("Omitting file: {:?}", path);
        return;
    }

    if path.is_dir() {
        info!("Skipping directory: {:?}", path);
        return;
    }

    info!("Syncing file: {:?}", path);

    let tcp = match TcpStream::connect(format!("{}:22", config.remote_server)) {
        Ok(tcp) => tcp,
        Err(e) => {
            error!("Failed to connect to remote server: {:?}", e);
            return;
        }
    };
    let mut sess = Session::new().unwrap();
    sess.set_tcp_stream(tcp);
    if let Err(e) = sess.handshake() {
        error!("SSH handshake failed: {:?}", e);
        return;
    }

    let home_dir = std::env::var("HOME").unwrap();
    let private_key_path = format!("{}/.ssh/id_rsa", home_dir);
    let public_key_path = format!("{}/.ssh/id_rsa.pub", home_dir);

    if let Err(e) = sess.userauth_pubkey_file(
        &config.username, 
        Some(Path::new(&public_key_path)), 
        Path::new(&private_key_path), 
        None,
    ) {
        error!("SSH public key authentication failed: {:?}", e);
        return;
    }

    if sess.authenticated() {
        let remote_path = format!("{}/{}", config.remote_path, path.file_name().unwrap().to_str().unwrap());
        let mut remote_file = match sess.scp_send(
            Path::new(&remote_path), 
            0o644, 
            path.metadata().unwrap().len(), 
            None
        ) {
            Ok(file) => file,
            Err(e) => {
                error!("Failed to open remote file for writing: {:?}", e);
                return;
            }
        };

        let mut local_file = match File::open(&path) {
            Ok(file) => file,
            Err(e) => {
                error!("Failed to open local file for reading: {:?}", e);
                return;
            }
        };
        if let Err(e) = std::io::copy(&mut local_file, &mut remote_file) {
            error!("Failed to copy file to remote server: {:?}", e);
            return;
        }

        let mut metadata = metadata.lock().unwrap();
        metadata.synced_files.insert(path.to_str().unwrap().to_string());
        save_metadata(&metadata);
        info!("File synced successfully: {:?}", path);
    } else {
        error!("Authentication failed");
    }
}

fn initial_scan(config: &Config, metadata: &Arc<Mutex<Metadata>>) {
    fn scan_directory(path: &PathBuf, config: &Config, metadata: &Arc<Mutex<Metadata>>) {
        if path.is_dir() {
            match fs::read_dir(path) {
                Ok(entries) => {
                    let entries: Vec<_> = entries.filter_map(Result::ok).collect();
                    entries.par_iter().for_each(|entry| {
                        let entry_path = entry.path();
                        if entry_path.is_file() {
                            let mut metadata = metadata.lock().unwrap();
                            metadata.synced_files.insert(entry_path.to_str().unwrap().to_string());
                        }
                        scan_directory(&entry_path, config, metadata);
                    });
                },
                Err(e) => error!("Failed to read directory {:?}: {:?}", path, e),
            }
        }
    }

    let source_path = PathBuf::from(&config.source_directory);
    scan_directory(&source_path, config, metadata);
}

fn main() {
    env_logger::init();
    info!("Starting file sync service");

    let config = load_config();
    let metadata = Arc::new(Mutex::new(load_metadata()));
    let mut last_processed = HashMap::new();
    let debounce_duration = Duration::from_secs(2);

    let metadata_exists = Path::new("metadata.json").exists();

    if !metadata_exists {
        initial_scan(&config, &metadata);
        save_metadata(&metadata.lock().unwrap());
    }

    let (tx, rx) = channel();
    let mut watcher = RecommendedWatcher::new(tx, NotifyConfig::default()).unwrap();
    watcher.watch(Path::new(&config.source_directory), RecursiveMode::Recursive).unwrap();

    info!("Watching directory: {}", config.source_directory);

    for event in rx {
        match event.unwrap() {
            Event { kind: notify::EventKind::Create(_) | notify::EventKind::Modify(_), paths, .. } => {
                for path in paths {
                    let now = Instant::now();
                    let should_process = match last_processed.get(&path) {
                        Some(&last_time) => now.duration_since(last_time) > debounce_duration,
                        None => true,
                    };

                    if should_process {
                        let config = config.clone();
                        let metadata = Arc::clone(&metadata);
                        let path_clone = path.clone();  // Clone the path before moving
                        rayon::spawn(move || {
                            sync_file(path_clone, &config, &metadata);
                        });
                        last_processed.insert(path, now);
                    }
                }
            },
            _ => {},
        }
    }
}
