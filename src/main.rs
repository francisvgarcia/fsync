use notify::{RecommendedWatcher, RecursiveMode, Watcher, Event, Config as NotifyConfig};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use ssh2::Session;
use std::fs;
use std::fs::File;
use std::io::{self, Read};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::time::Duration;
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
    checksum: String,
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

fn sync_file(path: PathBuf, config: &Config, metadata: &mut Metadata) {
    if path.is_dir() {
        info!("Skipping directory: {:?}", path);
        return;
    }

    info!("Syncing file: {:?}", path);
    let checksum = match calculate_checksum(&path) {
        Ok(checksum) => checksum,
        Err(e) => {
            error!("Failed to calculate checksum for {:?}: {:?}", path, e);
            return;
        }
    };

    if metadata.synced_files.iter().any(|f| f.path == path.to_str().unwrap() && f.checksum == checksum) {
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

fn main() {
    env_logger::init();
    info!("Starting file sync service");

    let config = load_config();
    let mut metadata = load_metadata();

    let (tx, rx) = channel();
    let mut watcher = RecommendedWatcher::new(tx, NotifyConfig::default()).unwrap();
    watcher.watch(Path::new(&config.source_directory), RecursiveMode::Recursive).unwrap();

    info!("Watching directory: {}", config.source_directory);

    for event in rx {
        match event.unwrap() {
            Event { kind: notify::EventKind::Create(_), paths, .. } | 
            Event { kind: notify::EventKind::Modify(_), paths, .. } => {
                for path in paths {
                    sync_file(path, &config, &mut metadata);
                }
            },
            _ => {},
        }
    }
}
