#![allow(unused)]
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
    let arg = Arg::try_parse()?;
    let mut vault = Vault::load().await?;
    match arg.command {
        Command::Add { .. } => {}
        Command::List { verbose } => {}
        Command::Get { .. } => {}
        Command::Remove { id } => {
            vault.remove(&id)?;
        }
    }
    vault.save().await?;
    Ok(())
}
