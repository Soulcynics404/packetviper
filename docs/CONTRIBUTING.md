# Contributing to PacketViper

Thank you for your interest in contributing! 🐍

## How to Contribute

### Reporting Bugs
1. Open an issue on GitHub
2. Include your OS, Rust version, and network interface type
3. Include the full error output
4. Steps to reproduce

### Feature Requests
Open an issue with the `enhancement` label.

### Pull Requests
1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `cargo test`
5. Build: `cargo build --release`
6. Test manually: `sudo ./target/release/packetviper <interface>`
7. Commit: `git commit -m "feat: description"`
8. Push: `git push origin feature/my-feature`
9. Open a Pull Request

### Commit Convention
- `feat:` — New feature
- `fix:` — Bug fix
- `docs:` — Documentation
- `refactor:` — Code refactoring
- `test:` — Adding tests
- `chore:` — Maintenance

## Development Setup

```bash
# Clone
git clone https://github.com/Soulcynics404/packetviper.git
cd packetviper

# Install dependencies
sudo apt install build-essential libpcap-dev pkg-config

# Build
cargo build

# Run tests
cargo test

# Run
sudo ./target/debug/packetviper wlan0