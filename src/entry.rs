use anyhow::Result;
use arboard::Clipboard;
use chrono::{DateTime, Utc};
use rpassword::prompt_password;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize, Serializer};
use tabled::Tabled;

#[derive(Debug, Serialize, Deserialize, Tabled)]
pub struct PasswordEntry {
    pub(crate) id: String,
    #[tabled(format("{}", self.username.as_deref().unwrap_or("")))]
    username: Option<String>,
    #[tabled(skip)]
    #[serde(serialize_with = "expose_secret")]
    password: SecretBox<String>,
    #[tabled(format("{}", self.url.as_deref().unwrap_or("")))]
    url: Option<String>,
    #[tabled(format("{}", self.description.as_deref().unwrap_or("")))]
    description: Option<String>,
    pub(crate) created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(format("{}", self.updated_at.unwrap_or(self.created_at)))]
    pub(crate) updated_at: Option<DateTime<Utc>>,
}

impl PasswordEntry {
    pub fn new(
        id: String,
        username: Option<String>,
        url: Option<String>,
        description: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            id,
            username,
            url,
            created_at: Utc::now(),
            updated_at: None,
            password: SecretBox::new(Box::new(prompt_password("Please enter the password: ")?)),
            description,
        })
    }

    pub fn show(&self) {
        println!(
            "id: {}\nusername: {}\npassword: {}",
            self.id,
            self.username.as_deref().unwrap_or(""),
            self.password.expose_secret()
        );
    }

    pub fn copy(&self) -> Result<()> {
        let mut clipboard = Clipboard::new()?;
        clipboard.set_text(self.password.expose_secret())?;
        Ok(())
    }
}

fn expose_secret<S>(secret: &SecretBox<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(secret.expose_secret().as_str())
}
