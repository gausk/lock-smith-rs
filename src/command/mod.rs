use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
pub struct Arg {
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Add,
}
