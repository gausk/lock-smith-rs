use crate::command::{Arg, Command};
use crate::vault::Vault;
use anyhow::Result;
use clap::Parser;

mod command;
mod entry;
mod password;
mod vault;

#[tokio::main]
async fn main() -> Result<()> {
    let mut vault = Vault::load().await?;
    let arg = Arg::try_parse()?;
    let update = matches!(arg.command, Command::Add { .. } | Command::Remove { .. });
    match arg.command {
        Command::Add {
            id,
            username,
            url,
            description,
        } => {
            vault.add(id, username, url, description)?;
        }
        Command::List { verbose } => {
            vault.list(verbose)?;
        }
        Command::Get { id, copy, show: _ } => {
            vault.get(&id, copy)?;
        }
        Command::Remove { ref id } => {
            vault.remove(id)?;
        }
    }
    if update {
        vault.save().await?;
    }
    Ok(())
}
