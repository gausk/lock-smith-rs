use clap::{Parser, Subcommand};
use secrecy::SecretBox;

#[derive(Debug, Parser)]
pub struct Arg {
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "Add or update a new password entry")]
    Add {
        #[arg(long, help = "Unique ID or label for the password entry")]
        id: String,
        #[arg(short, long, help = "Username or email")]
        username: Option<String>,
        #[arg(short, long)]
        description: Option<String>,
        #[arg(long)]
        url: Option<String>,
    },
    #[command(about = "Print or copy particular credentials")]
    Get {
        #[arg(long, help = "The password entry id")]
        id: String,
        #[arg(
            short,
            long,
            help = "Copy password to the clipboard instead of displaying"
        )]
        copy: bool,
        #[arg(short, long, help = "Display the password in plaintext")]
        show: bool,
    },
    #[command(about = "Delete a password entry")]
    Remove {
        #[arg(long, help = "The password entry id")]
        id: String,
    },
    #[command(about = "List all password entries")]
    List {
        #[arg(long, short)]
        verbose: bool,
    },
}
