use anyhow::{Result, anyhow};
use argon2::Argon2;
use rpassword::prompt_password;
use secrecy::ExposeSecret;
use secrecy::SecretBox;
use tokio::sync::OnceCell;

pub(crate) static SECRET_KEY: OnceCell<SecretBox<[u8; 32]>> = OnceCell::const_new();

fn get_master_password() -> Result<SecretBox<String>> {
    Ok(SecretBox::new(Box::new(prompt_password(
        "Please enter your master password: ",
    )?)))
}

pub fn derive_secret_key(salt: &[u8]) -> Result<SecretBox<[u8; 32]>> {
    let master_password = get_master_password()?;
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(master_password.expose_secret().as_bytes(), salt, &mut key)
        .map_err(|_| anyhow!("error hashing master password"))?;
    Ok(SecretBox::new(Box::new(key)))
}
