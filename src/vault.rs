use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use std::path::PathBuf;
use std::time::SystemTime;
use tokio::fs;
use tokio::sync::OnceCell;

const LOCK_SMITH_DIR: &str = ".lock-smith";
const VAULT_FILE_NAME: &str = "vault.enc";

static VAULT_FILE_PATH: OnceCell<PathBuf> = OnceCell::const_new();

pub async fn init_vault_file() -> &'static PathBuf {
    VAULT_FILE_PATH
        .get_or_init(|| async {
            get_vault_file_path()
                .await
                .inspect_err(|e| eprintln!("{e}"))
                .expect("error reading account store file")
        })
        .await
}

async fn get_vault_file_path() -> Result<PathBuf> {
    let home_dir = env::home_dir().with_context(|| "Home directory not found")?;
    let vault_dir = home_dir.join(LOCK_SMITH_DIR);
    fs::create_dir_all(&vault_dir)
        .await
        .with_context(|| format!("Failed to create lock-smith dir {:?}", vault_dir))?;
    let vault_file = vault_dir.join(VAULT_FILE_NAME);
    if !vault_file.is_file() {
        fs::OpenOptions::new()
            .mode(0o600)
            .write(true)
            .create_new(true)
            .open(&vault_file)
            .await
            .with_context(|| format!("Failed to open or create file: {:?}", vault_file))?;
    }
    Ok(vault_dir)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    pub(crate) salt: Vec<u8>,
    pub(crate) nonce: Vec<u8>,
    pub(crate) entries: BTreeMap<String, PasswordEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordEntry {
    id: String,
    username: Option<String>,
    password: String,
    url: Option<String>,
    created_at: SystemTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_at: Option<SystemTime>,
}

impl Vault {
    fn new() -> Result<Self> {
        Ok(Self {
            salt: Vec::new(),
            nonce: Vec::new(),
            entries: BTreeMap::new(),
        })
    }

    pub async fn load() -> Result<Self> {
        let filename = init_vault_file().await;
        let data = fs::read_to_string(&**filename)
            .await
            .with_context(|| "failed to read vault data file")?;
        if data.trim().is_empty() {
            Self::new()
        } else {
            serde_json::from_str(&data).with_context(|| "failed to decode vault data file")
        }
    }
}
