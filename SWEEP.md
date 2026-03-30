# SWEEP.md - MASQ Node Development Guide

This file contains essential information for AI assistants and developers working on the MASQ Node project, including coding standards, common commands, project structure, and development workflows.

## Table of Contents
- [Project Overview](#project-overview)
- [Common Terminal Commands](#common-terminal-commands)
- [Project Structure](#project-structure)
- [Development Workflow](#development-workflow)
- [Code Style and Standards](#code-style-and-standards)
- [Testing Guidelines](#testing-guidelines)
- [Build and CI/CD](#build-and-cicd)
- [Important Notes](#important-notes)

---

## Project Overview

**MASQ Node** is the foundation of the MASQ Network, an open-source decentralized mesh-network (dMN) written primarily in Rust. It combines the benefits of VPN and Tor technology to create next-generation privacy software.

### Key Technologies
- **Language**: Rust (2021 edition)
- **Build System**: Cargo
- **Testing**: Unit tests, integration tests, multinode integration tests (Docker-based)
- **CI/CD**: GitHub Actions
- **Platforms**: Linux, macOS, Windows (64-bit)

### Repository Structure
The project is organized as a Cargo workspace with multiple crates:
- `node/` - Main MASQ Node implementation
- `masq/` - Command-line user interface
- `masq_lib/` - Shared library code
- `dns_utility/` - DNS configuration utility - deprecated
- `automap/` - Automatic public-IP detection and configuration
- `port_exposer/` - Port exposure utilities for testing only
- `ip_country/` - IP geolocation functionality
- `multinode_integration_tests/` - Docker-based integration tests employing multiple simultaneous Nodes

---

## Common Terminal Commands

### Building and Testing

#### Run All Tests and Checks (Full CI Pipeline)
```bash
ci/all.sh
```
This runs formatting, linting, unit tests, and integration tests for all components. **You will be prompted for your password** during zero-hop integration tests (requires sudo).

#### Run Multinode Integration Tests (Linux only)
```bash
ci/multinode_integration_test.sh
```
Note: These tests only run on Linux and require Docker.

#### Format Code
```bash
ci/format.sh
```
Formats all Rust code using `rustfmt`. This is required before submitting PRs.

#### Run Linting (Clippy)
```bash
cargo clippy -- -D warnings -Anon-snake-case
```
Or for a specific component:
```bash
cd node && ci/lint.sh
```

#### Run Unit Tests
```bash
# For the node component
cd node && ci/unit_tests.sh

# Or manually
cargo test --release --lib --no-fail-fast --features masq_lib/log_recipient_test -- --nocapture --skip _integration
```

#### Run Integration Tests
```bash
cd node && ci/integration_tests.sh
```
Note: Integration tests require sudo privileges on Linux and macOS.

#### Build Release Version
```bash
cargo build --release
```

#### Build Debug Version
```bash
cargo build
```

### Version Management

#### Bump Version
```bash
cd ci && ./bump_version.sh <version>
```
Example:
```bash
cd ci && ./bump_version.sh 6.9.1
```
This updates version numbers in all `Cargo.toml` files and corresponding `Cargo.lock` files.

### Running MASQ Node

#### Start MASQ Daemon (Linux/macOS)
```bash
sudo nohup ./MASQNode --initialization &
```

#### Start MASQ Daemon (Windows)
```bash
start /b MASQNode --initialization
```

#### Start MASQ CLI
```bash
./masq
```

#### Run MASQ Command (Non-interactive)
```bash
./masq setup --log-level debug --clandestine-port 1234
```

#### Shutdown MASQ Node
```bash
./masq shutdown
```

#### Revert DNS Configuration
```bash
sudo ./dns_utility revert
```

### Git Workflow

#### Update Master Branch
```bash
git checkout master
git pull
```

#### Create Feature Branch
```bash
git checkout -b GH-<issue-number>
git push -u origin HEAD
```

#### Merge Master into Feature Branch
```bash
git checkout master
git pull
git checkout -  # Returns to previous branch
git merge master
```

### Docker Commands (for Multinode Tests)

#### View Docker Logs
```bash
multinode_integration_tests/docker_logs.sh
```

#### Dump Docker State
```bash
multinode_integration_tests/docker_dump.sh
```

#### Build Docker Images
```bash
multinode_integration_tests/docker/build.sh
```

---

## Project Structure

### Main Components

#### Node (`node/`)
The core MASQ Node implementation containing:
- `src/accountant/` - Payment and accounting logic
- `src/blockchain/` - Blockchain interaction
- `src/entry_dns/` - Tiny DNS server that returns 'localhost' for any hostname - deprecated
- `src/hopper/` - Message routing
- `src/neighborhood/` - Network topology management
- `src/proxy_client/` - Exit-Node proxy
- `src/proxy_server/` - Originating-Node proxy
- `src/ui_gateway/` - User interface communication
- `src/sub_lib/` - Code shared among accountant, blockchain, hopper, etc.
- `src/test_utils/` - Testing utilities

Each component has its own README.md with detailed documentation.

#### MASQ CLI (`masq/`)
Command-line interface for controlling the MASQ Daemon and Node.

#### DNS Utility (`dns_utility/`) - deprecated
The standard way to add intercept processing to your network data flow is to configure your system network stack to
use an HTTP and/or HTTPS proxy. However, early in the history of Substratum, Justin Tabb made a promise that Node
would be "zero-configuration." This utility, and the code in Node that it supports, were intended to keep that promise.
Essentially, Node contains a tiny DNS server that always returns 'localhost' for any hostname; therefore, when your
browser or other application performs DNS resolution, it will be fooled into routing its traffic through Node, which
is running on `localhost`. This utility wrangles your system DNS settings to point at that tiny DNS server, if you're
going to run Node, or back at your real DNS server if you're not. Since Node is now part of MASQ and no longer part of
Substratum and Justin Tabb is a part of history, the Node now operates as an HTTPS proxy and its `entry_dns` server is
no longer used. However, the code is still available and active and usable, so this utility remains available as well,
although its use is deprecated.

#### Multinode Integration Tests (`multinode_integration_tests/`)
Docker-based integration tests that simulate multi-node networks.

### Configuration Files

#### Cargo.toml
Each component has its own `Cargo.toml` defining dependencies and metadata.

#### config.toml
Runtime configuration file (located in data directory by default).
- Can be specified via `--config-file` parameter or `MASQ_CONFIG_FILE` environment variable
- Uses TOML format with scalar settings
- Example: `clandestine-port = 1234`

---

## Development Workflow

### Setting Up Development Environment

1. **Install Rust toolchain**:
   ```bash
   rustup component add rustfmt
   rustup component add clippy
   ```

2. **Install Docker** (for multinode tests on Linux)

3. **Clone repository and test**:
   ```bash
   git clone <repository-url>
   cd Node
   ci/all.sh
   ```

### Working on an Issue

1. **Select issue** from the [MASQ Node Card Wall](https://github.com/orgs/MASQ-Project/projects/1)
2. **Update master branch**: `git checkout master && git pull`
3. **Create feature branch**: `git checkout -b GH-<issue-number>`
4. **Complete the work** (test-driven development required)
5. **Merge in master regularly**: `git merge master`
6. **Run full test suite**: `ci/all.sh`
7. **Run multinode tests** (Linux only): `ci/multinode_integration_test.sh`
8. **Push changes**: `git push`
9. **Open pull request** on GitHub
10. **Watch GitHub Actions build**
11. **Address reviewer comments**
12. **Wait for QA approval**

### Commit Guidelines

- Commit frequently (commits will be squashed before merging)
- Commit when tests go green
- Commit before trying risky changes
- Write descriptive commit messages for your own reference

---

## Code Style and Standards

### Rust Standards

#### Formatting
- Use `rustfmt` for all code formatting
- Run `ci/format.sh` before committing (non-auto-formatted code will fail CI)
- To skip formatting on specific code: `#[cfg_attr(rustfmt, rustfmt_skip)]`

#### Linting
- All code must pass `clippy` with `-D warnings`
- Non-snake-case warnings are allowed: `-Anon-snake-case`
- Run `cargo clippy -- -D warnings -Anon-snake-case`

#### Compiler Flags
```bash
export RUSTFLAGS="-D warnings -Anon-snake-case"
```

#### Error Handling
- Use `Result` types for fallible operations
- Provide descriptive error messages
- Handle errors appropriately (no `unwrap()` in production code; use `expect()` only, and that sparingly)
- **Important:** Nothing that comes into the system from the network must ever be allowed to cause a panic. All the
standard anti-injection rules apply, but whenever something from the outside generates an error, the error must be
logged and execution must continue. (Sometimes additional action is appropriate, such as banning an evil Node; but
logging the error is the bare minimum.) `eprintln!()` is not logging.

#### Testing
- **Test-Driven Development (TDD) is required**
- All new code must have corresponding tests
- Tests must pass before code review
- Use descriptive test names
- Test both success and failure cases

### Naming Conventions
- Use snake_case for functions and variables
- Use PascalCase for types and traits
- Use SCREAMING_SNAKE_CASE for constants
- All zero-hop integration tests must have names _suffixed_ with `_integration`; otherwise they'll run as unit tests
rather than integration tests.

### Documentation
- Document public APIs with doc comments (`///`)
- Include examples in doc comments where helpful
- Keep README.md files updated for each component

---

## Testing Guidelines

### Test Types

#### Unit Tests
- Located in the same file as the code being tested (in `#[cfg(test)]` modules)
- Test individual functions and methods in isolation
- Run with: `cargo test --lib`
- Should not require sudo or network access

#### Integration Tests
- Test interactions between components
- Starts up a real Node, always in `--neighborhood-mode zero-hop`
- Will require sudo privileges, because a Node has to start with root privileges to open low ports
- Run with: `ci/integration_tests.sh`

#### Multinode Integration Tests
- Docker-based tests simulating multi-node networks
- **Linux only** (do not run on macOS or Windows)
- Require Docker installation
- Run with: `ci/multinode_integration_test.sh`

### Test Execution

#### Run All Tests
```bash
ci/all.sh
```

#### Run Specific Test
```bash
cargo test test_name -- --nocapture
```

#### Run Tests with Backtrace
```bash
RUST_BACKTRACE=full cargo test
```

#### Run Tests in Release Mode
```bash
cargo test --release
```

### Test Features
- Use `--no-fail-fast` to run all tests even if some fail
- Use `--nocapture` to see println! output

---

## Build and CI/CD

### Local Build Process

The `ci/all.sh` script performs the following:
1. Format check and auto-format (`ci/format.sh`)
2. Install git hooks (`install-hooks.sh`)
3. Start sccache server (for faster compilation)
4. Build and test each component:
   - masq_lib
   - node
   - dns_utility
   - masq (CLI)
   - automap
   - ip_country

### GitHub Actions

- Builds run automatically on pull requests
- Unit and single-Node integration tests run on Linux, macOS, and Windows
- Multinode integration tests run on Linux only
- All builds must pass before merging

### Build Artifacts

After successful builds, artifacts are available in:
- `/target/release/` and `/target/debug/` - Executable binaries
  - `MASQNode` (or `MASQNode.exe`) - Node and Daemon
  - `masq` - Command-line interface
  - `dns_utility` - DNS configuration tool
  - `automap` - Firewall penetration test utility: requires special remote setup

### Caching

The project uses `sccache` for faster compilation:
```bash
export SCCACHE_DIR="$HOME/.cargo/sccache"
SCCACHE_IDLE_TIMEOUT=0 sccache --start-server
```

---

## Important Notes

### Platform-Specific Considerations

#### Linux
- Full support for all features
- Multinode integration tests available
- Requires sudo for integration tests
- May need to free port 53: `sudo ci/free-port-53.sh`

#### macOS
- Full support except multinode integration tests
- Requires sudo for integration tests
- May need to adjust file descriptor limits in GitHub Actions

#### Windows
- Use Git Bash for running scripts
- Multinode integration tests not supported
- Some services may need to be stopped (ICS, W3SVC)
- 32-bit Windows not reliably supported (use 64-bit)
- Run as Administrator

### Security Considerations

- **MASQ Node is currently in beta** - not clandestine yet
- Do not use for sensitive traffic
- Traffic cannot be decrypted by attackers but MASQ traffic is identifiable
- Database encryption uses a user-provided password
- Password is never stored on disk
- Forgetting the password means losing all the encrypted content in the database and starting over

### Configuration Priority

Configuration sources in order of priority (highest to lowest):
1. `masq` UI commands
2. Environment variables (prefixed with `MASQ_`)
3. Configuration file (`config.toml`)
4. Defaults

Example:
- CLI, non-interactive mode: `masq setup --clandestine-port 1234`
- Environment: `MASQ_CLANDESTINE_PORT=1234`
- Config file: `clandestine-port = "1234"`

### Daemon vs Node

- **Daemon**: Runs with admin privileges, starts at boot, cannot access network or communicate with Node
- **Node**: Starts with admin privileges, drops privileges after network configuration, handles all network traffic
- UI connects to Daemon first, then is redirected to Node when it first sends the Daemon a Node command

### Error Handling in Browser

#### HTTP Errors
- MASQ Node can impersonate the remote server for HTTP errors
- Errors are clearly marked as coming from MASQ Node rather than the remote server

#### TLS Errors
- In-band error reporting severely limited by TLS protocol; only available for ClientHello
- Friendliest errors are written to the log

### Development Tools

#### Recommended IDE
- JetBrains IntelliJ IDEA with Rust plugin (used by MASQ team)
- Other options: VS Code with rust-analyzer, etc.

#### Required Tools
- Rust toolchain (rustc, cargo, rustfmt, clippy)
- Git
- Docker (for multinode tests on Linux)
- sudo access (for integration tests)

### Useful Links

- [MASQ Node Repository](https://github.com/MASQ-Project/Node)
- [MASQ Node Card Wall](https://github.com/orgs/MASQ-Project/projects/1)
- [GitHub Actions Build Site](https://github.com/MASQ-Project/Node/actions)
- [Knowledge Base](https://docs.masq.ai/masq)
- [Discord Channel](https://discord.gg/masq)
- [Latest Release](https://github.com/MASQ-Project/Node/releases/latest)

---

## Quick Reference

### Most Common Commands

```bash
# Full test suite
ci/all.sh

# Format code
ci/format.sh

# Lint code
cargo clippy -- -D warnings -Anon-snake-case

# Run unit tests
cargo test --release --lib --no-fail-fast

# Build release
cargo build --release

# Start daemon (Linux/macOS)
sudo nohup ./MASQNode --initialization &

# Start CLI
./masq

# Shutdown node
./masq shutdown
```

### Environment Variables

```bash
export RUST_BACKTRACE=full          # Full backtraces on panic
export RUSTFLAGS="-D warnings -Anon-snake-case"  # Compiler flags
export SCCACHE_DIR="$HOME/.cargo/sccache"  # Cache directory
```

### File Locations

- Binaries: `/target/release/` or `/target/debug/`
- Config file: `<data-directory>/config.toml`
- Database: `<data-directory>/`
- Logs: Configured via `--log-level` parameter

---

**Last Updated**: 2026
**Project**: MASQ Node
**License**: GPL-3.0-only
**Copyright**: (c) 2026, MASQ Network
