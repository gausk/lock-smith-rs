# lock-smith-rs

A secure, fast, and user-friendly CLI password manager built with Rust.

## Features

- **Strong Encryption**: AES-256-GCM authenticated encryption
- **Secure Key Derivation**: Argon2 password-based key derivation
- **Clipboard Integration**: Copy passwords securely to clipboard
- **Organized Storage**: Store passwords with metadata (username, URL, description)
- **Easy Retrieval**: List and search through your password entries
- **Local Storage**: All data stored locally in encrypted format
- **Memory Safety**: Sensitive data protection using Rust's `secrecy` crate

## Installation

### From Source

```bash
git clone https://github.com/gausk/lock-smith-rs.git
cd lock-smith-rs
cargo build --release
```

The binary will be available at `target/release/lock-smith`.

### Using Cargo

```bash
cargo install --path .
```

## Usage

### Adding a Password Entry

```bash
lock-smith add --id "github" --username "your-username" --url "https://github.com" --description "GitHub account"
```

### Listing All Entries

```bash
# Basic list
lock-smith list

# Verbose list with all details
lock-smith list --verbose
```

### Retrieving a Password

```bash
# Copy password to clipboard
lock-smith get --id "github" --copy

# Display password in terminal (use with caution)
lock-smith get --id "github" --show
```

### Removing an Entry

```bash
lock-smith remove --id "github"
```

## Security

- **Master Password**: You'll be prompted for a master password that protects your vault
- **Encryption**: All passwords are encrypted using AES-256-GCM before storage
- **Key Derivation**: Master password is processed through Argon2 for secure key generation
- **Local Storage**: Data is stored locally in `~/.lock-smith/vault.enc`
- **Memory Protection**: Sensitive data is protected in memory using the `secrecy` crate

## Commands Reference

| Command | Description | Options |
|---------|-------------|---------|
| `add` | Add or update a password entry | `--id`, `--username`, `--url`, `--description` |
| `get` | Retrieve a password entry | `--id`, `--copy`, `--show` |
| `list` | List all password entries | `--verbose` |
| `remove` | Delete a password entry | `--id` |

## Development

### Prerequisites

- Rust 1.80+ 
- Cargo

### Building

```bash
cargo build
```

### Running Tests

```bash
cargo test
```

### Running in Development

```bash
cargo run -- add --id "test" --username "user"
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security Notice

This software is provided as-is. While it implements industry-standard encryption practices, please ensure you:
- Use a strong master password
- Keep backups of your vault file
- Regularly update the software

For security issues, please create a private issue or contact the maintainer directly.
