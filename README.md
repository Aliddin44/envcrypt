# 🔐 EnvCrypt

Secure AES-256 .env file encryption CLI tool with argon2/scrypt support.

## Features

- 🔒 **AES-256-GCM encryption** - Military-grade security
- 🔑 **Key derivation** - Argon2 or Scrypt algorithms
- 💻 **Cross-platform** - Windows, macOS, Linux
- 🎯 **CLI interface** - Easy to use commands
- 📦 **TypeScript** - Full type safety
- 🚀 **Zero dependencies** - Lightweight package

## Installation

```bash
npm install -g fast-envcrypt
```

## Quick Start

```bash
# Encrypt .env file
envcrypt encrypt .env
#or
npx envcrypt encrypt .env
# Decrypt .env file
envcrypt decrypt .env.enc
#or
npx envcrypt decrypt .env.enc

# Load encrypted env vars into process.env
envcrypt load .env.enc
#or
npx envcrypt load .env.enc
```

## Commands

### Encrypt

```bash
envcrypt encrypt <input> [options]

Options:
  -o, --output <file>     Output file (default: .env.enc)
  -p, --password <pass>   Encryption password
  --algo <algorithm>      argon2 or scrypt (default: argon2)
  --force                 Overwrite existing files
```

### Decrypt

```bash
envcrypt decrypt <input> [options]

Options:
  -o, --output <file>     Output file (default: .env)
  -p, --password <pass>   Decryption password
  --force                 Overwrite existing files
```

### Load

```bash
envcrypt load <input> [options]

Options:
  -p, --password <pass>   Decryption password
```

## Examples

```bash
# Basic encryption
envcrypt encrypt .env
#or
npx envcrypt encrypt .env

# Custom output file
envcrypt encrypt .env -o secrets.enc
#or
npx envcrypt encrypt .env -o secrets.enc

# With password
envcrypt encrypt .env -p mypassword123
#or
envcrypt encrypt .env -p mypassword123

# Using scrypt algorithm
envcrypt encrypt .env --algo scrypt
#or
npx envcrypt encrypt .env --algo scrypt

# Load into environment
envcrypt load .env.enc -p mypassword123
#or
npx envcrypt load .env.enc -p mypassword123

```

## Security

- Uses AES-256-GCM for authenticated encryption
- Supports Argon2 and Scrypt for key derivation
- Passwords are never stored in plain text
- Memory is cleared after operations

## License

MIT © Aliddin44
