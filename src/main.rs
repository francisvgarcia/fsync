use notify::{RecommendedWatcher, RecursiveMode, Watcher, Event, Config as NotifyConfig};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use ssh2::Session;
use std::collections::HashMap;
use std::fs;
use std::fs::{File, read_dir};
use std::io::{self, Read};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::time::{Duration, Instant};
use chrono::Utc;
use log::{info, warn, error};

#[derive(Serialize, Deserialize)]
struct Config {
    source_directory: String,
    remote_server: String,
    remote_path: String,
    username: String,
}

#[derive(Serialize, Deserialize)]
struct FileMetadata {
    path: String,
    checksum: Option<String>,
    last_synced: String,
}

#[derive(Serialize, Deserialize)]
struct Metadata {
    synced_files: Vec<FileMetadata>,
}

fn load_config() -> Config {
    let config_data = fs::read_to_string("config.json").expect("Unable to read config file");
    serde_json::from_str(&config_data).expect("Unable to parse config file")
}

fn load_metadata() -> Metadata {
    let metadata_data = fs::read_to_string("metadata.json").unwrap_or_else(|_| "{\"synced_files\": []}".to_string());
    serde_json::from_str(&metadata_data).expect("Unable to parse metadata file")
}

fn save_metadata(metadata: &Metadata) {
    let metadata_data = serde_json::to_string(metadata).expect("Unable to serialize metadata");
    fs::write("metadata.json", metadata_data).expect("Unable to write metadata file")
}

fn calculate_checksum(path: &PathBuf) -> Result<String, io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    hasher.update(buffer);
    Ok(format!("{:x}", hasher.finalize()))
}

fn is_already_synced(path: &PathBuf, checksum: &Option<String>, metadata: &Metadata) -> bool {
    metadata.synced_files.iter().any(|f| {
        f.path == path.to_str().unwrap() && f.checksum == *checksum
    })
}

fn sync_path(path: PathBuf, config: &Config, metadata: &mut Metadata) {
    if path.is_dir() {
        // Sync directory
        let checksum = None;
        if is_already_synced(&path, &checksum, metadata) {
            info!("Directory already synced: {:?}", path);
            return;
        }

        // Create remote directory
        let remote_path = format!("{}/{}", config.remote_path, path.strip_prefix(&config.source_directory).unwrap().display());
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

        // Public key authentication
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
            let sftp = sess.sftp().unwrap();
            match sftp.mkdir(Path::new(&remote_path), 0o755) {
                Ok(_) => {
                    let dir_metadata = FileMetadata {
                        path: path.to_str().unwrap().to_string(),
                        checksum: None,
                        last_synced: Utc::now().to_rfc3339(),
                    };
                    metadata.synced_files.push(dir_metadata);
                    save_metadata(metadata);
                    info!("Directory synced successfully: {:?}", path);
                },
                Err(e) => error!("Failed to create remote directory: {:?}", e),
            }
        } else {
            error!("Authentication failed");
        }

        // Process directory contents
        match read_dir(&path) {
            Ok(entries) => {
                for entry in entries {
                    if let Ok(entry) = entry {
                        sync_path(entry.path(), config, metadata);
                    }
                }
            },
            Err(e) => error!("Failed to read directory {:?}: {:?}", path, e),
        }
    } else {
        // Sync file
        let checksum = match calculate_checksum(&path) {
            Ok(checksum) => Some(checksum),
            Err(e) => {
                error!("Failed to calculate checksum for {:?}: {:?}", path, e);
                return;
            }
        };

        if is_already_synced(&path, &checksum, metadata) {
            info!("File already synced with the same content: {:?}", path);
            return; // File already synced with the same content
        }

        // Establish SSH connection
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

        // Public key authentication
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
            // Use SCP to copy file
            let remote_path = format!("{}/{}", config.remote_path, path.strip_prefix(&config.source_directory).unwrap().display());
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

            // Update metadata
            let file_metadata = FileMetadata {
                path: path.to_str().unwrap().to_string(),
                checksum,
                last_synced: Utc::now().to_rfc3339(),
            };
            metadata.synced_files.push(file_metadata);
            save_metadata(metadata);
            info!("File synced successfully: {:?}", path);
        } else {
            error!("Authentication failed");
        }
    }
}

fn initial_scan(config: &Config, metadata: &mut Metadata) {
    fn scan_directory(path: &PathBuf, config: &Config, metadata: &mut Metadata) {
        if path.is_dir() {
            // Process directory contents
            match read_dir(path) {
                Ok(entries) => {
                    for entry in entries {
                        if let Ok(entry) = entry {
                            let entry_path = entry.path();
                            sync_path(entry_path.clone(), config, metadata);
                            scan_directory(&entry_path, config, metadata);
                        }
                    }
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
    let mut metadata = load_metadata();
    let mut last_processed = HashMap::new();
    let debounce_duration = Duration::from_secs(2);

    // Initial scan of the source directory
    initial_scan(&config, &mut metadata);

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
                        sync_path(path.clone(), &config, &mut metadata);
                        last_processed.insert(path, now);
                    }
                }
            },
            _ => {},
        }
    }
}
