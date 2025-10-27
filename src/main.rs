#![allow(unused)]
use crate::command::Arg;
use crate::vault::Vault;
use anyhow::Result;
use clap::Parser;

mod command;
mod vault;

#[tokio::main]
async fn main() -> Result<()> {
    let arg = Arg::try_parse()?;
    let vault = Vault::load().await?;
    Ok(())
}
