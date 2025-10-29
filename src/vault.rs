use crate::entry::PasswordEntry;
use crate::password::{SECRET_KEY, derive_secret_key};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit};
use anyhow::{Context, Result, anyhow, bail};
use clap::builder::TypedValueParser;
use rand::{Rng, rng};
use secrecy::ExposeSecret;
use secrecy::SecretBox;
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

pub async fn init_vault_file() -> Result<&'static PathBuf> {
    VAULT_FILE_PATH
        .get_or_try_init(|| async { get_vault_file_path().await })
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
    pub(crate) salt: [u8; 32],
    /// Nonce for AES-256-GCM is 96 bit
    pub(crate) nonce: [u8; 12],
    pub(crate) entries: BTreeMap<String, PasswordEntry>,
}

impl Vault {
    fn new() -> Result<Self> {
        let mut rng = rng();
        Ok(Self {
            salt: rng.random(),
            nonce: rng.random(),
            entries: BTreeMap::new(),
        })
    }

    fn from_nonce_and_salt(nonce: &[u8], salt: &[u8]) -> Result<Self> {
        Ok(Self {
            salt: salt.try_into()?,
            nonce: nonce.try_into()?,
            entries: BTreeMap::new(),
        })
    }

    pub async fn load() -> Result<Self> {
        let filename = init_vault_file().await?;
        let data = fs::read(filename)
            .await
            .with_context(|| "failed to read vault data file")?;
        if data.is_empty() {
            Self::new()
        } else {
            Self::from_encrypted(data).await
        }
    }

    pub async fn save(self) -> Result<()> {
        let filename = init_vault_file().await?;
        fs::write(filename, self.encrypt().await?).await;
        Ok(())
    }

    async fn from_encrypted(data: Vec<u8>) -> Result<Self> {
        if data.len() < 32 + 12 {
            bail!("encrypted data is too short");
        }
        let salt = &data[0..32];
        let nonce = &data[32..32 + 12];
        let mut vault = Vault::from_nonce_and_salt(nonce, salt)?;
        let cipher = {
            let key = vault.get_secret_key().await?;
            let gcm_key = Key::<Aes256Gcm>::from_iter(key.expose_secret().iter().copied());
            Aes256Gcm::new(&gcm_key)
        };
        let plaintext = cipher
            .decrypt(nonce.into(), &data[32 + 12..])
            .map_err(|_| anyhow!("decryption failed"))?;
        vault.entries = serde_json::from_slice(&plaintext)?;
        Ok(vault)
    }

    async fn encrypt(self) -> Result<Vec<u8>> {
        let cipher = {
            let key = self.get_secret_key().await?;
            let gcm_key = Key::<Aes256Gcm>::from_iter(key.expose_secret().iter().copied());
            Aes256Gcm::new(&gcm_key)
        };
        let plaintext = serde_json::to_vec(&self)?;
        let ciphertext = cipher
            .encrypt((&self.nonce).into(), plaintext.as_slice())
            .map_err(|_| anyhow!("encryption failed"))?;
        let mut result = Vec::with_capacity(self.salt.len() + self.nonce.len() + ciphertext.len());
        result.extend(self.salt);
        result.extend(self.nonce);
        result.extend(ciphertext);
        Ok(result)
    }

    pub async fn get_secret_key(&self) -> Result<&SecretBox<[u8; 32]>> {
        SECRET_KEY
            .get_or_try_init(|| async { derive_secret_key(self.salt.as_slice()) })
            .await
    }

    pub fn list(&self, verbose: bool) -> Result<()> {
        self.entries.values().for_each(|entry| {});
        Ok(())
    }

    pub fn remove(&mut self, id: &str) -> Result<()> {
        self.entries
            .remove(id)
            .map(|_| println!("Password entry with id '{}' deleted successfully", id))
            .ok_or_else(|| anyhow!("Entry with id '{}' not found", id))
    }
}
