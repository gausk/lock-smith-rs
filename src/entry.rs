use serde::{Deserialize, Serialize};
use std::time::SystemTime;

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
