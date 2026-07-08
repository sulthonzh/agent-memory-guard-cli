# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release with AI agent memory integrity protection
- SHA-256 cryptographic memory state validation
- Automatic backup and restoration capabilities
- Real-time memory monitoring
- Framework integration support (LangChain, LlamaIndex, CrewAI)
- CLI commands: validate, backup, restore, monitor, integrate
- Comprehensive security scoring and issue analysis

### Fixed
- Broken build and test execution (0 tests → 9 tests GREEN)

## [1.0.0] - 2026-06-17

### Added
- Initial stable release
- Memory integrity validation
- Attack detection (injection, anomalies, corruption, tampering)
- Sensitive data pattern scanning
- State change analysis
- Backup rotation and management
- CLI interface with comprehensive commands